//! Schreib-Transaktionen.
//!
//! Eine [`Tx`] hält den Schreib-Lock, arbeitet auf Kopien (Copy-on-Write) der
//! berührten Tabellen und schreibt erst beim `commit` neue Dateien +
//! das Manifest. `rollback`/Drop verwirft alles, ohne dass etwas auf Platte
//! geändert wurde.

use super::*;
use crate::store::WriterGuard;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};

type Maps = HashMap<usize, HashMap<String, usize>>;

pub(crate) struct WorkTable {
    data: Arc<TableData>,
    maps: Option<Maps>,
    next_key: Option<i64>,
    dirty: bool,
}

enum Slot { Dropped, Live(WorkTable) }

enum Backup { Absent, Live(Arc<TableData>, bool) }

struct RefInfo { child: String, ccol: String, pcol: String, on_delete: OnDelete }

/// Eindeutige Spalten, deren leere Werte ("NULL") nicht kollidieren.
fn skips_empty(c: &ColDef) -> bool { !c.key && c.unique }

impl WorkTable {
    fn new(data: Arc<TableData>) -> Self { WorkTable { data, maps: None, next_key: None, dirty: false } }

    fn data_mut(&mut self) -> &mut TableData {
        self.dirty = true;
        self.maps = None;
        self.next_key = None;
        let d = Arc::make_mut(&mut self.data);
        d.touch();
        d
    }

    fn ensure_maps(&mut self) -> Result<&mut Maps> {
        if self.maps.is_none() {
            let schema = &self.data.schema;
            let mut maps: Maps = HashMap::new();
            for ci in unique_cols(schema) {
                let c = &schema[ci];
                let mut m = HashMap::with_capacity(self.data.rows.len());
                for (p, r) in self.data.rows.iter().enumerate() {
                    let raw = cell(r, ci);
                    if raw.is_empty() && skips_empty(c) { continue; }
                    let v = norm_val(c.kind, raw);
                    if m.insert(v.clone(), p).is_some() {
                        return Err(if c.key { DbError::DuplicateKey(v) }
                                   else { DbError::Unique(format!("Spalte '{}' enthält '{v}' doppelt", c.name)) });
                    }
                }
                maps.insert(ci, m);
            }
            self.maps = Some(maps);
        }
        Ok(self.maps.as_mut().expect("maps gesetzt"))
    }

    /// Nimmt die Hash-Maps heraus, lässt `f` Daten **und** Maps gemeinsam ändern
    /// und setzt sie wieder ein (inkrementelle Pflege statt O(n)-Neuaufbau).
    fn with_maps<R>(&mut self, f: impl FnOnce(&mut TableData, &mut Maps) -> R) -> Result<R> {
        let mut maps = std::mem::take(self.ensure_maps()?);
        let prev_next = self.next_key;
        let r = { let d = self.data_mut(); f(d, &mut maps) };
        self.maps = Some(maps);
        self.next_key = prev_next;
        Ok(r)
    }

    fn peek_key(&mut self, ki: usize) -> i64 {
        if self.next_key.is_none() {
            let n = self.data.rows.iter().filter_map(|r| cell(r, ki).parse::<i64>().ok())
                .max().unwrap_or(0).saturating_add(1);
            self.next_key = Some(n);
        }
        self.next_key.unwrap_or(1)
    }
}

struct TxInner {
    store: Arc<Store>,
    guard: Option<WriterGuard>,
    base: store::Manifest,
    work: BTreeMap<String, Slot>,
    user_version: u32,
    finished: bool,
}

/// Schreib-Transaktion. Erzeugen mit [`DBCore::begin`] oder [`DBCore::transaction`].
///
/// Ohne `commit()` wird beim Drop zurückgerollt. Nicht `Sync` (eine Transaktion
/// gehört einem Thread), aber `Send`.
#[must_use = "ohne commit() wird die Transaktion beim Drop zurückgerollt"]
pub struct Tx { inner: RefCell<TxInner> }

impl TxInner {
    fn names(&self) -> BTreeSet<String> {
        let mut s: BTreeSet<String> = self.base.tables.keys().cloned().collect();
        for (n, slot) in &self.work {
            match slot { Slot::Dropped => { s.remove(n); } Slot::Live(_) => { s.insert(n.clone()); } }
        }
        s
    }
    fn exists(&self, name: &str) -> bool {
        match self.work.get(name) {
            Some(Slot::Live(_)) => true,
            Some(Slot::Dropped) => false,
            None => self.base.tables.contains_key(name),
        }
    }

    fn view(&mut self, name: &str) -> Result<Arc<TableData>> {
        if !valid_name(name) { return Err(DbError::InvalidName); }
        match self.work.get(name) {
            Some(Slot::Live(w)) => return Ok(w.data.clone()),
            Some(Slot::Dropped) => return Err(DbError::TableNotFound(name.to_string())),
            None => {}
        }
        let fname = self.base.tables.get(name).ok_or_else(|| DbError::TableNotFound(name.to_string()))?;
        self.store.load_cached(name, fname)
    }

    fn schema_of(&mut self, name: &str) -> Result<Arc<Vec<ColDef>>> {
        match self.work.get(name) {
            Some(Slot::Live(w)) => return Ok(Arc::new(w.data.schema.clone())),
            Some(Slot::Dropped) => return Err(DbError::TableNotFound(name.to_string())),
            None => {}
        }
        let fname = self.base.tables.get(name).ok_or_else(|| DbError::TableNotFound(name.to_string()))?;
        self.store.schema_of(name, fname)
    }

    fn work_mut(&mut self, name: &str) -> Result<&mut WorkTable> {
        if !matches!(self.work.get(name), Some(Slot::Live(_))) {
            if matches!(self.work.get(name), Some(Slot::Dropped)) {
                return Err(DbError::TableNotFound(name.to_string()));
            }
            let data = self.view(name)?;
            self.work.insert(name.to_string(), Slot::Live(WorkTable::new(data)));
        }
        match self.work.get_mut(name) {
            Some(Slot::Live(w)) => Ok(w),
            _ => Err(DbError::TableNotFound(name.to_string())),
        }
    }

    fn backup(&self, name: &str) -> Backup {
        match self.work.get(name) {
            Some(Slot::Live(w)) => Backup::Live(w.data.clone(), w.dirty),
            _ => Backup::Absent,
        }
    }
    fn restore(&mut self, name: &str, b: Backup) {
        match b {
            Backup::Absent => { self.work.remove(name); }
            Backup::Live(d, dirty) => {
                self.work.insert(name.to_string(), Slot::Live(WorkTable { data: d, maps: None, next_key: None, dirty }));
            }
        }
    }

    // ───── Foreign Keys ─────

    fn referencing(&mut self, parent: &str) -> Result<Vec<RefInfo>> {
        let mut out = Vec::new();
        for n in self.names() {
            let schema = self.schema_of(&n)?;
            for c in schema.iter() {
                if let Some(fk) = &c.fk {
                    if fk.table == parent {
                        out.push(RefInfo { child: n.clone(), ccol: c.name.clone(), pcol: fk.column.clone(), on_delete: fk.on_delete });
                    }
                }
            }
        }
        Ok(out)
    }

    fn parent_has(&mut self, ptable: &str, pcol: &str, v: &str) -> Result<bool> {
        if let Some(Slot::Live(w)) = self.work.get_mut(ptable) {
            let ci = w.data.col(pcol).ok_or_else(|| unknown_col(pcol))?;
            let kind = w.data.schema[ci].kind;
            if w.data.schema[ci].is_unique() {
                let maps = w.ensure_maps()?;
                return Ok(maps.get(&ci).map_or(false, |m| m.contains_key(&norm_val(kind, v))));
            }
            return Ok(w.data.rows.iter().any(|r| key_eq(kind, cell(r, ci), v)));
        }
        let d = self.view(ptable)?;
        let ci = d.col(pcol).ok_or_else(|| unknown_col(pcol))?;
        let kind = d.schema[ci].kind;
        if d.schema[ci].is_unique() { Ok(!d.index(ci).get(v).is_empty()) }
        else { Ok(d.rows.iter().any(|r| key_eq(kind, cell(r, ci), v))) }
    }

    fn check_fks(&mut self, table: &str, schema: &[ColDef], row: &[String], only: Option<&[usize]>) -> Result<()> {
        for (i, c) in schema.iter().enumerate() {
            let Some(fk) = &c.fk else { continue };
            if let Some(o) = only { if !o.contains(&i) { continue; } }
            let v = cell(row, i);
            if v.is_empty() { continue; }
            if fk.table == table {
                if let Some(pc) = schema.iter().position(|x| x.name == fk.column) {
                    if key_eq(schema[pc].kind, cell(row, pc), v) { continue; }
                }
            }
            if !self.parent_has(&fk.table, &fk.column, v)? {
                return Err(DbError::ForeignKey(format!(
                    "{table}.{} = '{v}' hat keine Entsprechung in {}.{}", c.name, fk.table, fk.column)));
            }
        }
        Ok(())
    }

    // ───── Zeilen ─────

    fn alloc_key(&mut self, table: &str) -> Result<(String, String)> {
        let d = self.view(table)?;
        let ki = key_index(&d.schema).ok_or_else(|| DbError::SchemaMismatch(
            "put() braucht eine @key-Spalte im Schema".into()))?;
        let name = d.schema[ki].name.clone();
        let generated = match d.schema[ki].kind {
            ColumnKind::Int => self.work_mut(table)?.peek_key(ki).to_string(),
            _ => d.schema[ki].default.clone().ok_or_else(|| DbError::SchemaMismatch(format!(
                "Spalte '{name}' fehlt und kann nicht auto-generiert werden")))?,
        };
        Ok((name, generated))
    }

    /// `upsert = false`: Insert (Duplikate → Fehler); `true`: Upsert per `@key`.
    fn insert_row(&mut self, table: &str, values: Vec<(&str, String)>, upsert: bool) -> Result<String> {
        let schema: Vec<ColDef> = self.view(table)?.schema.clone();
        let ki = key_index(&schema);
        if upsert && ki.is_none() {
            return Err(DbError::SchemaMismatch("put() braucht eine @key-Spalte im Schema".into()));
        }
        let mut vals: Vec<(&str, String)> = values;
        let auto;
        if upsert {
            let kn = ki.map(|k| schema[k].name.clone()).unwrap_or_default();
            if !vals.iter().any(|(k, _)| *k == kn.as_str()) {
                auto = self.alloc_key(table)?;
                vals.push((auto.0.as_str(), auto.1.clone()));
            }
        }
        let row = build_row(&schema, &vals)?;
        check_row_local(&schema, &row)?;
        self.check_fks(table, &schema, &row, None)?;

        // Eindeutigkeit über die Hash-Maps.
        let ucols = unique_cols(&schema);
        let mut replace: Option<usize> = None;
        let mut old_row: Option<Vec<String>> = None;
        {
            let w = self.work_mut(table)?;
            let maps = w.ensure_maps()?;
            if upsert {
                if let Some(k) = ki {
                    replace = maps.get(&k).and_then(|m| m.get(&norm_val(schema[k].kind, &row[k]))).copied();
                }
            }
            for &ci in &ucols {
                let c = &schema[ci];
                if row[ci].is_empty() && skips_empty(c) { continue; }
                if let Some(&p) = maps.get(&ci).and_then(|m| m.get(&norm_val(c.kind, &row[ci]))) {
                    if Some(p) == replace { continue; }
                    return Err(if c.key { DbError::DuplicateKey(row[ci].clone()) }
                               else { DbError::Unique(format!("Spalte '{}' enthält '{}' bereits", c.name, row[ci])) });
                }
            }
            if let Some(p) = replace { old_row = Some(w.data.rows[p].clone()); }
        }
        // Ersetzt ein Upsert eine referenzierte Zeile: referenzierte Werte dürfen sich nicht ändern.
        if let Some(old) = &old_row {
            for r in self.referencing(table)? {
                let Some(pci) = schema.iter().position(|c| c.name == r.pcol) else { continue };
                if cell(old, pci).is_empty() || key_eq(schema[pci].kind, cell(old, pci), &row[pci]) { continue; }
                self.restrict_if_referenced(&r, &norm_val(schema[pci].kind, cell(old, pci)))?;
            }
        }

        let key = ki.map(|k| row[k].clone()).unwrap_or_default();
        let int_key = ki.filter(|&k| schema[k].kind == ColumnKind::Int).and_then(|k| row[k].parse::<i64>().ok());
        let w = self.work_mut(table)?;
        w.with_maps(|d, maps| {
            let pos = match replace {
                Some(p) => {
                    if let Some(old) = &old_row {
                        for &ci in &ucols {
                            if let Some(m) = maps.get_mut(&ci) { m.remove(&norm_val(schema[ci].kind, cell(old, ci))); }
                        }
                    }
                    d.rows[p] = row.clone();
                    p
                }
                None => { d.rows.push(row.clone()); d.rows.len() - 1 }
            };
            for &ci in &ucols {
                if row[ci].is_empty() && skips_empty(&schema[ci]) { continue; }
                maps.entry(ci).or_default().insert(norm_val(schema[ci].kind, &row[ci]), pos);
            }
        })?;
        if let (Some(n), Some(k)) = (w.next_key, int_key) {
            if k >= n { w.next_key = Some(k.saturating_add(1)); }
        }
        Ok(key)
    }

    fn restrict_if_referenced(&mut self, r: &RefInfo, norm_old: &str) -> Result<()> {
        let child = self.view(&r.child)?;
        let cci = child.col(&r.ccol).ok_or_else(|| unknown_col(&r.ccol))?;
        let ck = child.schema[cci].kind;
        if child.rows.iter().any(|row| !cell(row, cci).is_empty() && norm_val(ck, cell(row, cci)) == norm_old) {
            return Err(DbError::ForeignKey(format!(
                "Wert '{norm_old}' wird noch von {}.{} referenziert", r.child, r.ccol)));
        }
        Ok(())
    }

    fn find_key_pos(&mut self, table: &str, key: &str) -> Result<Option<usize>> {
        let no_key = || DbError::SchemaMismatch("Operation per Key braucht eine @key-Spalte im Schema".into());
        if let Some(Slot::Live(w)) = self.work.get_mut(table) {
            let ki = key_index(&w.data.schema).ok_or_else(no_key)?;
            let kind = w.data.schema[ki].kind;
            let maps = w.ensure_maps()?;
            return Ok(maps.get(&ki).and_then(|m| m.get(&norm_val(kind, key))).copied());
        }
        let d = self.view(table)?;
        let ki = key_index(&d.schema).ok_or_else(no_key)?;
        Ok(d.index(ki).get(key).first().copied())
    }

    fn patch_positions(&mut self, table: &str, positions: &[usize], fields: &[(&str, String)]) -> Result<usize> {
        let data = self.view(table)?;
        let schema: Vec<ColDef> = data.schema.clone();
        let mut targets = Vec::with_capacity(fields.len());
        for (k, v) in fields {
            let ci = schema.iter().position(|c| c.name == *k).ok_or_else(|| unknown_col(k))?;
            validate_value(&schema[ci], v)?;
            targets.push(ci);
        }
        if positions.is_empty() { return Ok(0); }
        let mut new_rows: Vec<(usize, Vec<String>)> = Vec::with_capacity(positions.len());
        for &p in positions {
            let old = data.rows.get(p)
                .ok_or_else(|| DbError::RowNotFound(format!("Position {p} in '{table}'")))?;
            let mut r = old.clone();
            r.resize(schema.len(), String::new());
            for (j, (_, v)) in fields.iter().enumerate() { r[targets[j]] = v.clone(); }
            new_rows.push((p, r));
        }
        for (_, r) in &new_rows {
            check_row_local(&schema, r)?;
            self.check_fks(table, &schema, r, Some(&targets))?;
        }
        // Eindeutigkeit der berührten UNIQUE/Key-Spalten.
        let touched: Vec<usize> = unique_cols(&schema).into_iter().filter(|c| targets.contains(c)).collect();
        let mut old_norm: Vec<(usize, usize, String)> = Vec::new(); // (pos, col, norm_old)
        if !touched.is_empty() {
            let patched: HashSet<usize> = positions.iter().copied().collect();
            let w = self.work_mut(table)?;
            let maps = w.ensure_maps()?;
            let mut seen: HashMap<usize, HashSet<String>> = HashMap::new();
            for (p, r) in &new_rows {
                for &ci in &touched {
                    let c = &schema[ci];
                    let dup = |v: &str| if c.key { DbError::DuplicateKey(v.to_string()) }
                        else { DbError::Unique(format!("Spalte '{}' enthält '{v}' bereits", c.name)) };
                    old_norm.push((*p, ci, norm_val(c.kind, cell(&data.rows[*p], ci))));
                    let raw = cell(r, ci);
                    if raw.is_empty() && skips_empty(c) { continue; }
                    let v = norm_val(c.kind, raw);
                    if let Some(&q) = maps.get(&ci).and_then(|m| m.get(&v)) {
                        if !patched.contains(&q) { return Err(dup(&v)); }
                    }
                    if !seen.entry(ci).or_default().insert(v.clone()) { return Err(dup(&v)); }
                }
            }
        }
        // Referenzierte Werte dürfen sich nicht ändern, solange Kinder darauf zeigen.
        for r in self.referencing(table)? {
            let Some(pci) = schema.iter().position(|c| c.name == r.pcol) else { continue };
            if !targets.contains(&pci) { continue; }
            let kind = schema[pci].kind;
            for (p, nr) in &new_rows {
                let old = cell(&data.rows[*p], pci);
                if old.is_empty() || key_eq(kind, old, cell(nr, pci)) { continue; }
                self.restrict_if_referenced(&r, &norm_val(kind, old))?;
            }
        }
        drop(data); // sonst kopiert Arc::make_mut die ganze Tabelle
        let w = self.work_mut(table)?;
        let n = new_rows.len();
        w.with_maps(|d, maps| {
            for (p, ci, old) in &old_norm {
                if let Some(m) = maps.get_mut(ci) { if m.get(old) == Some(p) { m.remove(old); } }
            }
            for (p, r) in new_rows {
                for &ci in &touched {
                    if !(cell(&r, ci).is_empty() && skips_empty(&schema[ci])) {
                        maps.entry(ci).or_default().insert(norm_val(schema[ci].kind, cell(&r, ci)), p);
                    }
                }
                d.rows[p] = r;
            }
        })?;
        Ok(n)
    }

    fn delete_positions(&mut self, table: &str, positions: &[usize]) -> Result<usize> {
        let mut plan: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
        let mut todo: Vec<(String, Vec<usize>)> = vec![(table.to_string(), positions.to_vec())];
        while let Some((t, pos)) = todo.pop() {
            let data = self.view(&t)?;
            let fresh: Vec<usize> = {
                let entry = plan.entry(t.clone()).or_default();
                pos.into_iter().filter(|p| *p < data.rows.len() && entry.insert(*p)).collect()
            };
            if fresh.is_empty() { continue; }
            for r in self.referencing(&t)? {
                let pci = data.col(&r.pcol).ok_or_else(|| unknown_col(&r.pcol))?;
                let child = self.view(&r.child)?;
                let cci = child.col(&r.ccol).ok_or_else(|| unknown_col(&r.ccol))?;
                let ck = child.schema[cci].kind;
                let vals: HashSet<String> = fresh.iter().map(|&p| cell(&data.rows[p], pci))
                    .filter(|v| !v.is_empty()).map(|v| norm_val(ck, v)).collect();
                if vals.is_empty() { continue; }
                let already = plan.get(&r.child);
                let hits: Vec<usize> = child.rows.iter().enumerate()
                    .filter(|(p, row)| {
                        let v = cell(row, cci);
                        !v.is_empty() && vals.contains(&norm_val(ck, v)) && !already.map_or(false, |s| s.contains(p))
                    })
                    .map(|(p, _)| p).collect();
                if hits.is_empty() { continue; }
                match r.on_delete {
                    OnDelete::Restrict => return Err(DbError::ForeignKey(format!(
                        "{} Zeile(n) in {}.{} verweisen auf {t}.{} (ON DELETE RESTRICT)",
                        hits.len(), r.child, r.ccol, r.pcol))),
                    OnDelete::Cascade => todo.push((r.child.clone(), hits)),
                }
            }
        }
        let mut main = 0;
        for (t, set) in plan {
            if set.is_empty() { continue; }
            if t == table { main = set.len(); }
            let w = self.work_mut(&t)?;
            let d = w.data_mut();
            let old = std::mem::take(&mut d.rows);
            d.rows = old.into_iter().enumerate().filter(|(p, _)| !set.contains(p)).map(|(_, r)| r).collect();
        }
        Ok(main)
    }

    // ───── Schema ─────

    fn validate_new_columns(&mut self, name: &str, cols: &[ColDef]) -> Result<()> {
        let mut seen = HashSet::new();
        let mut keys = 0;
        for c in cols {
            if !valid_name(&c.name) { return Err(DbError::InvalidName); }
            if !seen.insert(c.name.clone()) {
                return Err(DbError::SchemaMismatch(format!("doppelte Spalte '{}'", c.name)));
            }
            if c.key { keys += 1; }
            if let Some(d) = &c.default {
                if d.chars().any(|ch| matches!(ch, '\n' | '\r' | ':' | ',')) { return Err(DbError::BadValue(c.name.clone())); }
                validate_value(c, d)?;
            }
            for ck in &c.checks { ck.operands_valid(c)?; }
            if let Some(fk) = &c.fk {
                let pschema: Arc<Vec<ColDef>> = if fk.table == name { Arc::new(cols.to_vec()) }
                    else { self.schema_of(&fk.table).map_err(|_| DbError::SchemaMismatch(format!(
                        "Foreign Key '{}': Tabelle '{}' existiert nicht", c.name, fk.table)))? };
                let p = pschema.iter().find(|p| p.name == fk.column).ok_or_else(|| DbError::SchemaMismatch(format!(
                    "Foreign Key '{}': Spalte '{}.{}' existiert nicht", c.name, fk.table, fk.column)))?;
                if !p.is_unique() {
                    return Err(DbError::SchemaMismatch(format!(
                        "Foreign Key '{}': '{}.{}' muss @key oder UNIQUE sein", c.name, fk.table, fk.column)));
                }
                if p.kind != c.kind {
                    return Err(DbError::SchemaMismatch(format!(
                        "Foreign Key '{}': Typ {} passt nicht zu {}.{} ({})", c.name,
                        c.kind.as_str(), fk.table, fk.column, p.kind.as_str())));
                }
            }
        }
        if keys > 1 { return Err(DbError::SchemaMismatch("mehrere @key-Spalten".into())); }
        Ok(())
    }

    fn create_table(&mut self, name: &str, schema: Schema, if_missing: bool) -> Result<()> {
        if !valid_name(name) { return Err(DbError::InvalidName); }
        if !schema.problems.is_empty() { return Err(DbError::SchemaMismatch(schema.problems.join("; "))); }
        if schema.columns.is_empty() { return Err(DbError::SchemaMismatch("(keine Spalten)".into())); }
        if self.exists(name) {
            return if if_missing { Ok(()) } else { Err(DbError::TableExists(name.to_string())) };
        }
        self.validate_new_columns(name, &schema.columns)?;
        let data = Arc::new(TableData::new(name.to_string(), schema.columns, Vec::new()));
        self.work.insert(name.to_string(), Slot::Live(WorkTable { data, maps: None, next_key: None, dirty: true }));
        Ok(())
    }

    fn drop_table(&mut self, name: &str, if_exists: bool) -> Result<()> {
        if !valid_name(name) { return Err(DbError::InvalidName); }
        if !self.exists(name) {
            return if if_exists { Ok(()) } else { Err(DbError::TableNotFound(name.to_string())) };
        }
        if let Some(r) = self.referencing(name)?.into_iter().find(|r| r.child != name) {
            return Err(DbError::ForeignKey(format!(
                "Tabelle '{name}' wird von {}.{} referenziert", r.child, r.ccol)));
        }
        if self.base.tables.contains_key(name) { self.work.insert(name.to_string(), Slot::Dropped); }
        else { self.work.remove(name); }
        Ok(())
    }

    fn rename_table(&mut self, old: &str, new: &str) -> Result<()> {
        if !valid_name(old) || !valid_name(new) { return Err(DbError::InvalidName); }
        if !self.exists(old) { return Err(DbError::TableNotFound(old.to_string())); }
        if self.exists(new) { return Err(DbError::TableExists(new.to_string())); }
        let refs = self.referencing(old)?;
        let d = self.view(old)?;
        let mut schema = d.schema.clone();
        for c in schema.iter_mut() {
            if let Some(fk) = &mut c.fk { if fk.table == old { fk.table = new.to_string(); } }
        }
        let data = Arc::new(TableData::new(new.to_string(), schema, d.rows.clone()));
        if self.base.tables.contains_key(old) { self.work.insert(old.to_string(), Slot::Dropped); }
        else { self.work.remove(old); }
        self.work.insert(new.to_string(), Slot::Live(WorkTable { data, maps: None, next_key: None, dirty: true }));
        for r in refs.into_iter().filter(|r| r.child != old) {
            let w = self.work_mut(&r.child)?;
            for c in w.data_mut().schema.iter_mut() {
                if let Some(fk) = &mut c.fk { if fk.table == old { fk.table = new.to_string(); } }
            }
        }
        Ok(())
    }

    fn add_field(&mut self, table: &str, col: ColDef) -> Result<()> {
        let d = self.view(table)?;
        if col.key { return Err(DbError::Unsupported("add_field mit @key – Tabelle neu anlegen".into())); }
        let mut all = d.schema.clone();
        all.push(col.clone());
        if d.schema.iter().any(|c| c.name == col.name) {
            return Err(DbError::SchemaMismatch(format!("Spalte '{}' existiert bereits", col.name)));
        }
        self.validate_new_columns(table, &all)?;
        let fill = match (&col.default, d.rows.is_empty()) {
            (Some(v), _) => v.clone(),
            (None, true) => String::new(),
            (None, false) => return Err(DbError::SchemaMismatch(format!(
                "add_field '{}': Default nötig, weil schon {} Zeile(n) existieren", col.name, d.rows.len()))),
        };
        if !d.rows.is_empty() {
            let mut probe = vec![String::new(); all.len()];
            probe[all.len() - 1] = fill.clone();
            let only = [all.len() - 1];
            let last = &all[all.len() - 1];
            if last.not_null && fill.is_empty() { return Err(DbError::NotNull(last.name.clone())); }
            for ck in &last.checks {
                if !(fill.is_empty() && last.kind == ColumnKind::Text) && !ck.holds(last.kind, &fill) {
                    return Err(DbError::CheckFailed(format!("Default '{}' verletzt {}", fill, ck.describe())));
                }
            }
            self.check_fks(table, &all, &probe, Some(&only))?;
            if last.unique && !fill.is_empty() && d.rows.len() > 1 {
                return Err(DbError::Unique(format!("Default '{fill}' würde in '{}' doppelt vorkommen", last.name)));
            }
        }
        let w = self.work_mut(table)?;
        let dm = w.data_mut();
        dm.schema.push(col);
        for r in dm.rows.iter_mut() { r.push(fill.clone()); }
        Ok(())
    }

    fn remove_field(&mut self, table: &str, col: &str) -> Result<()> {
        let d = self.view(table)?;
        let ci = d.col(col).ok_or_else(|| unknown_col(col))?;
        if d.schema.len() == 1 {
            return Err(DbError::SchemaMismatch("die letzte Spalte kann nicht entfernt werden".into()));
        }
        if let Some(r) = self.referencing(table)?.into_iter().find(|r| r.pcol == col) {
            return Err(DbError::ForeignKey(format!("Spalte '{table}.{col}' wird von {}.{} referenziert", r.child, r.ccol)));
        }
        let w = self.work_mut(table)?;
        let dm = w.data_mut();
        dm.schema.remove(ci);
        for r in dm.rows.iter_mut() { if ci < r.len() { r.remove(ci); } }
        Ok(())
    }

    fn rename_field(&mut self, table: &str, old: &str, new: &str) -> Result<()> {
        if !valid_name(new) { return Err(DbError::InvalidName); }
        let d = self.view(table)?;
        let ci = d.col(old).ok_or_else(|| unknown_col(old))?;
        if d.col(new).is_some() { return Err(DbError::SchemaMismatch(format!("Spalte '{new}' existiert bereits"))); }
        let refs = self.referencing(table)?;
        self.work_mut(table)?.data_mut().schema[ci].name = new.to_string();
        for r in refs.into_iter().filter(|r| r.pcol == old) {
            let cname = if r.child == table && r.ccol == old { new.to_string() } else { r.ccol.clone() };
            let w = self.work_mut(&r.child)?;
            for c in w.data_mut().schema.iter_mut() {
                if c.name == cname { if let Some(fk) = &mut c.fk { fk.column = new.to_string(); } }
            }
        }
        Ok(())
    }

    fn set_index(&mut self, table: &str, col: &str, unique: Option<bool>, indexed: bool) -> Result<()> {
        let d = self.view(table)?;
        let ci = d.col(col).ok_or_else(|| unknown_col(col))?;
        if unique == Some(true) && !d.schema[ci].is_unique() {
            let c = &d.schema[ci];
            let mut seen = HashSet::new();
            for r in &d.rows {
                let raw = cell(r, ci);
                if raw.is_empty() { continue; }
                if !seen.insert(norm_val(c.kind, raw)) {
                    return Err(DbError::Unique(format!("Spalte '{col}' enthält Duplikate – UNIQUE nicht möglich")));
                }
            }
        }
        if unique == Some(false) && d.schema[ci].unique {
            if let Some(r) = self.referencing(table)?.into_iter().find(|r| r.pcol == col) {
                return Err(DbError::ForeignKey(format!("'{table}.{col}' wird von {}.{} referenziert", r.child, r.ccol)));
            }
        }
        let w = self.work_mut(table)?;
        let c = &mut w.data_mut().schema[ci];
        if let Some(u) = unique { if !c.key { c.unique = u; } }
        if !c.key { c.indexed = indexed; }
        Ok(())
    }
}

impl Tx {
    pub(crate) fn begin(store: &Arc<Store>) -> Result<Tx> {
        let guard = store.acquire_writer()?;
        let base = store.read_manifest()?;
        let user_version = base.user_version;
        Ok(Tx { inner: RefCell::new(TxInner {
            store: Arc::clone(store), guard: Some(guard), base, work: BTreeMap::new(),
            user_version, finished: false,
        }) })
    }

    fn with<R>(&self, f: impl FnOnce(&mut TxInner) -> Result<R>) -> Result<R> {
        let mut g = self.inner.try_borrow_mut().map_err(|_| DbError::TxState(
            "Transaktion wird gerade benutzt (verschachtelter Aufruf, z. B. in einem Filter?)"))?;
        if g.finished { return Err(DbError::ReadOnly); }
        f(&mut g)
    }

    /// Schließt die Transaktion ab: alle Änderungen werden **atomar** und dauerhaft.
    /// Bei einem Fehler bleibt der alte Stand vollständig erhalten.
    pub fn commit(self) -> DbResult<()> {
        let mut i = self.inner.into_inner();
        if i.finished { return Err(DbError::ReadOnly); }
        i.finished = true;
        let store = Arc::clone(&i.store);
        let changed = i.user_version != i.base.user_version
            || i.work.values().any(|s| match s { Slot::Dropped => true, Slot::Live(w) => w.dirty });
        if !changed { i.guard = None; return Ok(()); }

        let cur = store.read_manifest()?;
        if cur.seq != i.base.seq {
            return Err(DbError::TxState("Datenbank wurde während der Transaktion extern verändert"));
        }
        let seq = cur.seq + 1;
        let mut new = cur;
        new.seq = seq;
        new.user_version = i.user_version;
        let mut written: Vec<String> = Vec::new();
        let mut installs: Vec<(String, String, Arc<TableData>)> = Vec::new();
        let res = (|| -> Result<()> {
            for (name, slot) in &i.work {
                match slot {
                    Slot::Dropped => { new.tables.remove(name); }
                    Slot::Live(w) if w.dirty => {
                        let f = store.write_table_file(name, &w.data.schema, &w.data.rows, seq)?;
                        written.push(f.clone());
                        new.tables.insert(name.clone(), f.clone());
                        installs.push((name.clone(), f, w.data.clone()));
                    }
                    Slot::Live(_) => {}
                }
            }
            store.write_manifest(&new) // ← Commit-Punkt (atomarer rename)
        })();
        if let Err(e) = res {
            for f in &written { let _ = fs::remove_file(store.path(f)); }
            return Err(e);
        }
        // Ab hier ist der Commit gültig; der Rest ist Aufräumen.
        let keep: HashSet<&String> = new.tables.values().collect();
        for f in i.base.tables.values() {
            if !keep.contains(f) { let _ = fs::remove_file(store.path(f)); }
        }
        for (name, slot) in &i.work { if matches!(slot, Slot::Dropped) { store.cache_drop(name); } }
        for (name, f, d) in installs { store.cache_put(&name, &f, d); }
        store.prune_metas(&new);
        i.guard = None;
        Ok(())
    }

    /// Verwirft alle Änderungen (identisch zum Drop ohne `commit`).
    pub fn rollback(self) { drop(self) }

    /// Aktuelle Schema-Versionsnummer (inkl. Änderungen in dieser Transaktion).
    pub fn user_version(&self) -> u32 {
        self.inner.try_borrow().map(|i| i.user_version).unwrap_or(0)
    }
    pub fn set_user_version(&self, v: u32) -> DbResult<()> { self.with(|i| { i.user_version = v; Ok(()) }) }

    /// Abfrage innerhalb der Transaktion (sieht auch die eigenen, noch nicht
    /// committeten Änderungen).
    pub fn table<'a>(&'a self, name: &str) -> Table<'a> { Table::on_tx(self, name) }

    // ───── Zeilen ─────

    pub fn add(&self, table: &str, values: Vec<(&str, String)>) -> DbResult<()> {
        self.with(|i| i.insert_row(table, values, false).map(|_| ()))
    }
    /// Upsert. Liefert den Key.
    pub fn put(&self, table: &str, values: Vec<(&str, String)>) -> DbResult<String> {
        self.with(|i| i.insert_row(table, values, true))
    }
    pub fn update(&self, table: &str, key: &str, values: Vec<(&str, String)>) -> DbResult<()> {
        self.with(|i| {
            let p = i.find_key_pos(table, key)?
                .ok_or_else(|| DbError::RowNotFound(format!("@key='{key}' in '{table}'")))?;
            i.patch_positions(table, &[p], &values).map(|_| ())
        })
    }
    pub fn remove(&self, table: &str, key: &str) -> DbResult<bool> {
        self.with(|i| match i.find_key_pos(table, key)? {
            None => Ok(false),
            Some(p) => i.delete_positions(table, &[p]).map(|_| true),
        })
    }
    /// Viele Upserts; schlägt eine fehl, bleibt die Tabelle in dieser Transaktion unverändert.
    pub fn put_many(&self, table: &str, rows: Vec<Vec<(&str, String)>>) -> DbResult<Vec<String>> {
        self.with(|i| {
            let backup = i.backup(table);
            let mut keys = Vec::with_capacity(rows.len());
            for r in rows {
                match i.insert_row(table, r, true) {
                    Ok(k) => keys.push(k),
                    Err(e) => { i.restore(table, backup); return Err(e); }
                }
            }
            Ok(keys)
        })
    }
    pub fn add_many(&self, table: &str, rows: Vec<Vec<(&str, String)>>) -> DbResult<()> {
        self.with(|i| {
            let backup = i.backup(table);
            for r in rows {
                if let Err(e) = i.insert_row(table, r, false) { i.restore(table, backup); return Err(e); }
            }
            Ok(())
        })
    }
    pub fn get(&self, table: &str, key: &str) -> DbResult<Option<Vec<String>>> {
        self.with(|i| {
            let d = i.view(table)?;
            Ok(i.find_key_pos(table, key)?.map(|p| d.rows[p].clone()))
        })
    }
    pub fn has(&self, table: &str, key: &str) -> DbResult<bool> { Ok(self.get(table, key)?.is_some()) }

    // ───── Schema ─────

    pub fn create_table(&self, name: &str, schema: Schema) -> DbResult<()> {
        self.with(|i| i.create_table(name, schema, false))
    }
    pub fn create_table_if_missing(&self, name: &str, schema: Schema) -> DbResult<()> {
        self.with(|i| i.create_table(name, schema, true))
    }
    pub fn drop_table(&self, name: &str, if_exists: bool) -> DbResult<()> {
        self.with(|i| i.drop_table(name, if_exists))
    }
    pub fn rename_table(&self, old: &str, new: &str) -> DbResult<()> { self.with(|i| i.rename_table(old, new)) }
    pub fn add_field(&self, table: &str, col: ColumnDef) -> DbResult<()> { self.with(|i| i.add_field(table, col)) }
    pub fn remove_field(&self, table: &str, col: &str) -> DbResult<()> { self.with(|i| i.remove_field(table, col)) }
    pub fn rename_field(&self, table: &str, old: &str, new: &str) -> DbResult<()> {
        self.with(|i| i.rename_field(table, old, new))
    }
    pub fn create_index(&self, table: &str, col: &str) -> DbResult<()> {
        self.with(|i| i.set_index(table, col, None, true))
    }
    pub fn create_unique_index(&self, table: &str, col: &str) -> DbResult<()> {
        self.with(|i| i.set_index(table, col, Some(true), true))
    }
    pub fn drop_index(&self, table: &str, col: &str) -> DbResult<()> {
        self.with(|i| i.set_index(table, col, Some(false), false))
    }
    pub fn tables(&self) -> Vec<String> {
        self.inner.try_borrow().map(|i| i.names().into_iter().collect()).unwrap_or_default()
    }

    // ───── Intern für Table/Web ─────

    pub(crate) fn view(&self, name: &str) -> Result<Arc<TableData>> { self.with(|i| i.view(name)) }
    pub(crate) fn patch_at(&self, table: &str, pos: &[usize], fields: &[(&str, String)]) -> Result<usize> {
        self.with(|i| i.patch_positions(table, pos, fields))
    }
    pub(crate) fn delete_at(&self, table: &str, pos: &[usize]) -> Result<usize> {
        self.with(|i| i.delete_positions(table, pos))
    }
    /// Ganze Zeile an Position ersetzen (Web-Editor); prüft alle Constraints.
    pub(crate) fn replace_at(&self, table: &str, pos: usize, row: Vec<String>) -> Result<()> {
        self.with(|i| {
            let d = i.view(table)?;
            let fields: Vec<(&str, String)> = d.schema.iter().zip(row).map(|(c, v)| (c.name.as_str(), v)).collect();
            i.patch_positions(table, &[pos], &fields).map(|_| ())
        })
    }
}
