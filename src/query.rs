//! Query-Builder: Filter, Sortierung, Indizes, Joins, Gruppierung, Mengen,
//! Unterabfragen, lazy Streaming und Mutationen über Abfragen.

use super::*;
use crate::store::Scan;
use std::collections::HashMap;

// ───────────── Lese-Kontext ─────────────

pub(crate) trait Reader {
    fn data(&self, name: &str) -> Result<Arc<TableData>>;
}
impl Reader for Snapshot {
    fn data(&self, name: &str) -> Result<Arc<TableData>> { Snapshot::data(self, name) }
}
impl Reader for Tx {
    fn data(&self, name: &str) -> Result<Arc<TableData>> { self.view(name) }
}

#[derive(Clone, Copy)]
pub(crate) enum Ctx<'a> { Db(&'a DBCore), Snap(&'a Snapshot), Tx(&'a Tx) }

impl<'a> Ctx<'a> {
    fn read<R>(&self, f: &dyn Fn(&dyn Reader) -> Result<R>) -> Result<R> {
        match self {
            Ctx::Db(db) => db.st()?.with_snapshot(|s| f(s)),
            Ctx::Snap(s) => f(*s),
            Ctx::Tx(t) => f(*t),
        }
    }
    fn write<R>(&self, f: impl FnOnce(&Tx) -> Result<R>) -> Result<R> {
        match self {
            Ctx::Db(db) => {
                let tx = Tx::begin(db.st()?)?;
                let r = f(&tx)?;
                tx.commit()?;
                Ok(r)
            }
            Ctx::Tx(t) => f(t),
            Ctx::Snap(_) => Err(DbError::ReadOnly),
        }
    }
}

// ───────────── Bausteine ─────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order { Asc, Desc }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AggFn { Count, CountOf, Sum, Avg, Min, Max }

/// Aggregat für [`Table::agg`].
///
/// ```ignore
/// db.table("posts").group_by(&["author"])
///   .agg(&[Agg::count(), Agg::sum("likes").alias("total")])
/// ```
#[derive(Debug, Clone)]
pub struct Agg { func: AggFn, col: Option<String>, alias: Option<String> }

impl Agg {
    /// Anzahl Zeilen der Gruppe.
    pub fn count() -> Self { Agg { func: AggFn::Count, col: None, alias: None } }
    /// Anzahl nicht-leerer Werte einer Spalte.
    pub fn count_of(col: &str) -> Self { Agg { func: AggFn::CountOf, col: Some(col.into()), alias: None } }
    pub fn sum(col: &str) -> Self { Agg { func: AggFn::Sum, col: Some(col.into()), alias: None } }
    pub fn avg(col: &str) -> Self { Agg { func: AggFn::Avg, col: Some(col.into()), alias: None } }
    pub fn min(col: &str) -> Self { Agg { func: AggFn::Min, col: Some(col.into()), alias: None } }
    pub fn max(col: &str) -> Self { Agg { func: AggFn::Max, col: Some(col.into()), alias: None } }
    /// Name der Ergebnisspalte (Standard: `count`, `sum_likes`, …).
    pub fn alias(mut self, name: &str) -> Self { self.alias = Some(name.into()); self }

    fn out_name(&self) -> String {
        if let Some(a) = &self.alias { return a.clone(); }
        let base = |c: &Option<String>| c.as_deref().unwrap_or("").replace('.', "_");
        match self.func {
            AggFn::Count => "count".into(),
            AggFn::CountOf => format!("count_{}", base(&self.col)),
            AggFn::Sum => format!("sum_{}", base(&self.col)),
            AggFn::Avg => format!("avg_{}", base(&self.col)),
            AggFn::Min => format!("min_{}", base(&self.col)),
            AggFn::Max => format!("max_{}", base(&self.col)),
        }
    }
}

enum Cond<'a> {
    Cmp { col: String, op: CmpOp, val: String },
    Between { col: String, lo: String, hi: String },
    In { col: String, vals: Vec<String> },
    Like { col: String, pat: String },
    Null { col: String, negate: bool },
    InQuery { col: String, sub: Box<Table<'a>>, negate: bool },
}

enum PCond {
    Cmp { ci: usize, kind: ColumnKind, op: CmpOp, val: String },
    Between { ci: usize, kind: ColumnKind, lo: String, hi: String },
    InSet { ci: usize, kind: ColumnKind, set: HashSet<String>, negate: bool },
    Like { ci: usize, pat: String },
    Null { ci: usize, negate: bool },
}

impl PCond {
    fn eval(&self, row: &[String]) -> bool {
        if let PCond::Null { ci, negate } = self {
            return is_null(row, *ci) != *negate;
        }
        if is_null(row, self.col()) { return false; }
        match self {
            PCond::Cmp { ci, kind, op, val } => op.holds(cmp_values(*kind, cell(row, *ci), val)),
            PCond::Between { ci, kind, lo, hi } => {
                let v = cell(row, *ci);
                cmp_values(*kind, v, lo) != Ordering::Less && cmp_values(*kind, v, hi) != Ordering::Greater
            }
            PCond::InSet { ci, kind, set, negate } => set.contains(&norm_val(*kind, cell(row, *ci))) != *negate,
            PCond::Like { ci, pat } => like_match(pat, cell(row, *ci)),
            PCond::Null { .. } => false,
        }
    }
    fn col(&self) -> usize {
        match self { PCond::Cmp { ci, .. } | PCond::Between { ci, .. }
            | PCond::InSet { ci, .. } | PCond::Like { ci, .. } | PCond::Null { ci, .. } => *ci }
    }
}

struct JoinSpec { table: String, left: String, right: String, outer: bool }
struct GroupSpec { keys: Vec<String>, aggs: Vec<Agg> }

enum Src<'a> {
    Base { name: String, joins: Vec<JoinSpec> },
    Derived(Box<Table<'a>>),
    Union(Box<Table<'a>>, Box<Table<'a>>, bool),
}

fn encode_query_value(kind: ColumnKind, value: &str) -> String {
    if kind == ColumnKind::Text && value.starts_with(NULL_CELL) {
        format!("{NULL_CELL}{value}")
    } else {
        value.to_string()
    }
}

pub(crate) struct Rs { pub(crate) schema: Vec<ColDef>, pub(crate) rows: Vec<Vec<String>> }

type RowFn<'a> = Box<dyn Fn(Row<'_>) -> bool + 'a>;

enum Access { Full, Lookup { desc: String, positions: Vec<usize> }, OrderScan { col: usize, desc: bool } }

// ───────────── Table ─────────────

/// Query-Handle. Erzeugen mit `db.table("name")`, `tx.table(..)` oder `snapshot.table(..)`.
///
/// Builder-Methoden konsumieren `self` und geben es zurück – frei verkettbar.
/// Terminal-Methoden führen die Abfrage aus. Jede hat eine `try_*`-Variante mit
/// echtem Fehler. Mutationen (`patch`/`merge`/`delete`/`remove_field`) laufen als
/// eigene Transaktion bzw. in der umgebenden [`Tx`].
///
/// Reihenfolge der Auswertung: Quelle/Join → `where` → `group_by`/`agg` →
/// `having` → `order_by` → `select` → `distinct` → `skip` → `limit`.
pub struct Table<'a> {
    ctx: Ctx<'a>,
    src: Src<'a>,
    select: Option<Vec<String>>,
    conds: Vec<Cond<'a>>,
    filters: Vec<RowFn<'a>>,
    group: Option<GroupSpec>,
    having: Vec<RowFn<'a>>,
    order: Vec<(String, Order)>,
    distinct: bool,
    limit: Option<usize>,
    skip: Option<usize>,
}

impl<'a> Table<'a> {
    fn blank(ctx: Ctx<'a>, src: Src<'a>) -> Self {
        Table { ctx, src, select: None, conds: Vec::new(), filters: Vec::new(), group: None,
                having: Vec::new(), order: Vec::new(), distinct: false, limit: None, skip: None }
    }
    pub(crate) fn on_db(db: &'a DBCore, name: &str) -> Self {
        Self::blank(Ctx::Db(db), Src::Base { name: name.to_string(), joins: Vec::new() })
    }
    pub(crate) fn on_snapshot(s: &'a Snapshot, name: &str) -> Self {
        Self::blank(Ctx::Snap(s), Src::Base { name: name.to_string(), joins: Vec::new() })
    }
    pub(crate) fn on_tx(t: &'a Tx, name: &str) -> Self {
        Self::blank(Ctx::Tx(t), Src::Base { name: name.to_string(), joins: Vec::new() })
    }

    /// Unterabfrage in `FROM`: weitere Bedingungen/Sortierung auf das Ergebnis von `q`.
    pub fn from_query(q: Table<'a>) -> Table<'a> {
        let ctx = q.ctx;
        Self::blank(ctx, Src::Derived(Box::new(q)))
    }

    // ───── Builder ─────

    /// Projektion: nur diese Spalten behalten (in dieser Reihenfolge).
    pub fn select(mut self, cols: &[&str]) -> Self {
        self.select = Some(cols.iter().map(|s| s.to_string()).collect());
        self
    }

    /// WHERE per Closure; mehrere Aufrufe werden mit UND verknüpft. Nutze `with!(r => …)`.
    /// Closures können keinen Index nutzen – für Indizes `where_eq`/`where_in`/… verwenden.
    pub fn filter<F>(mut self, f: F) -> Self
    where F: Fn(Row<'_>) -> bool + 'a {
        self.filters.push(Box::new(f));
        self
    }

    fn cond(mut self, c: Cond<'a>) -> Self { self.conds.push(c); self }
    pub fn where_eq(self, col: &str, v: impl ToString) -> Self {
        self.cond(Cond::Cmp { col: col.into(), op: CmpOp::Eq, val: v.to_string() })
    }
    pub fn where_ne(self, col: &str, v: impl ToString) -> Self {
        self.cond(Cond::Cmp { col: col.into(), op: CmpOp::Ne, val: v.to_string() })
    }
    pub fn where_gt(self, col: &str, v: impl ToString) -> Self {
        self.cond(Cond::Cmp { col: col.into(), op: CmpOp::Gt, val: v.to_string() })
    }
    pub fn where_ge(self, col: &str, v: impl ToString) -> Self {
        self.cond(Cond::Cmp { col: col.into(), op: CmpOp::Ge, val: v.to_string() })
    }
    pub fn where_lt(self, col: &str, v: impl ToString) -> Self {
        self.cond(Cond::Cmp { col: col.into(), op: CmpOp::Lt, val: v.to_string() })
    }
    pub fn where_le(self, col: &str, v: impl ToString) -> Self {
        self.cond(Cond::Cmp { col: col.into(), op: CmpOp::Le, val: v.to_string() })
    }
    pub fn where_between(self, col: &str, lo: impl ToString, hi: impl ToString) -> Self {
        self.cond(Cond::Between { col: col.into(), lo: lo.to_string(), hi: hi.to_string() })
    }
    pub fn where_in<I, S>(self, col: &str, vals: I) -> Self
    where I: IntoIterator<Item = S>, S: ToString {
        self.cond(Cond::In { col: col.into(), vals: vals.into_iter().map(|s| s.to_string()).collect() })
    }
    /// SQL-`LIKE` (`%`, `_`), ohne Groß/Klein.
    pub fn where_like(self, col: &str, pattern: &str) -> Self {
        self.cond(Cond::Like { col: col.into(), pat: pattern.into() })
    }
    /// Match only genuine SQL NULL values.
    pub fn where_null(self, col: &str) -> Self { self.cond(Cond::Null { col: col.into(), negate: false }) }
    /// Exclude genuine SQL NULL values.
    pub fn where_not_null(self, col: &str) -> Self { self.cond(Cond::Null { col: col.into(), negate: true }) }
    /// `col IN (SELECT …)` – die Unterabfrage liefert in ihrer ersten Spalte die Werte.
    pub fn where_in_query(self, col: &str, sub: Table<'a>) -> Self {
        self.cond(Cond::InQuery { col: col.into(), sub: Box::new(sub), negate: false })
    }
    /// `col NOT IN (SELECT …)`.
    pub fn where_not_in_query(self, col: &str, sub: Table<'a>) -> Self {
        self.cond(Cond::InQuery { col: col.into(), sub: Box::new(sub), negate: true })
    }

    fn add_join(mut self, table: &str, left: &str, right: &str, outer: bool) -> Self {
        match &mut self.src {
            Src::Base { joins, .. } => joins.push(JoinSpec {
                table: table.into(), left: left.into(), right: right.into(), outer }),
            _ => {
                // Join auf Union/Derived: als Fehler beim Ausführen melden.
                self.select = self.select.or_else(|| Some(vec!["\u{0}join-unsupported".into()]));
            }
        }
        self
    }
    /// `INNER JOIN table ON <left> = table.<right>`. Spalten heißen danach `tabelle.spalte`;
    /// ansprechbar auch ohne Präfix, wenn eindeutig.
    pub fn join(self, table: &str, left: &str, right: &str) -> Self { self.add_join(table, left, right, false) }
    /// `LEFT JOIN`: Zeilen ohne Treffer bleiben, die rechten Spalten sind dann leer.
    pub fn left_join(self, table: &str, left: &str, right: &str) -> Self { self.add_join(table, left, right, true) }

    /// `GROUP BY`. Danach mit [`Table::agg`] Aggregate hinzufügen (ohne `agg` = distinct Gruppen).
    pub fn group_by(mut self, cols: &[&str]) -> Self {
        let aggs = self.group.take().map(|g| g.aggs).unwrap_or_default();
        self.group = Some(GroupSpec { keys: cols.iter().map(|s| s.to_string()).collect(), aggs });
        self
    }
    /// Aggregate; ohne `group_by` entsteht genau eine Ergebniszeile.
    pub fn agg(mut self, aggs: &[Agg]) -> Self {
        let keys = self.group.take().map(|g| g.keys).unwrap_or_default();
        self.group = Some(GroupSpec { keys, aggs: aggs.to_vec() });
        self
    }
    /// `HAVING`: filtert die gruppierten Zeilen (Spalten: Gruppen + Aggregate).
    pub fn having<F>(mut self, f: F) -> Self
    where F: Fn(Row<'_>) -> bool + 'a {
        self.having.push(Box::new(f));
        self
    }

    pub fn distinct(mut self) -> Self { self.distinct = true; self }

    /// `UNION` (ohne Duplikate). Beide Seiten brauchen gleich viele Spalten.
    pub fn union(self, other: Table<'a>) -> Table<'a> {
        let ctx = self.ctx;
        Self::blank(ctx, Src::Union(Box::new(self), Box::new(other), false))
    }
    /// `UNION ALL` (mit Duplikaten).
    pub fn union_all(self, other: Table<'a>) -> Table<'a> {
        let ctx = self.ctx;
        Self::blank(ctx, Src::Union(Box::new(self), Box::new(other), true))
    }

    /// ORDER BY … (Default: aufsteigend). Ersetzt eine frühere Sortierung.
    pub fn order_by(mut self, col: &str) -> Self {
        self.order = vec![(col.to_string(), Order::Asc)];
        self
    }
    /// Weiteres Sortierkriterium.
    pub fn then_by(mut self, col: &str) -> Self {
        self.order.push((col.to_string(), Order::Asc));
        self
    }
    pub fn desc(mut self) -> Self {
        if let Some((_, d)) = self.order.last_mut() { *d = Order::Desc; }
        self
    }
    pub fn asc(mut self) -> Self {
        if let Some((_, d)) = self.order.last_mut() { *d = Order::Asc; }
        self
    }
    pub fn limit(mut self, n: usize) -> Self { self.limit = Some(n); self }
    pub fn skip(mut self, n: usize) -> Self { self.skip = Some(n); self }
    /// Alias für `skip`.
    pub fn offset(self, n: usize) -> Self { self.skip(n) }

    // ───── Ausführung ─────

    fn is_simple(&self) -> bool {
        self.group.is_none() && !self.distinct && self.having.is_empty()
    }

    fn plain_base(&self) -> Result<&str> {
        match &self.src {
            Src::Base { name, joins } if joins.is_empty() => Ok(name),
            _ => Err(DbError::Unsupported("nur auf einer einfachen Tabelle (ohne Join/Union/Unterabfrage)".into())),
        }
    }

    fn prepare(&self, schema: &[ColDef], rd: &dyn Reader) -> Result<Vec<PCond>> {
        let mut out = Vec::with_capacity(self.conds.len());
        for c in &self.conds {
            out.push(match c {
                Cond::Cmp { col, op, val } => {
                    let ci = resolve_col(schema, col)?;
                    let kind = schema[ci].kind;
                    PCond::Cmp { ci, kind, op: *op, val: encode_query_value(kind, val) }
                }
                Cond::Between { col, lo, hi } => {
                    let ci = resolve_col(schema, col)?;
                    let kind = schema[ci].kind;
                    PCond::Between {
                        ci, kind, lo: encode_query_value(kind, lo), hi: encode_query_value(kind, hi),
                    }
                }
                Cond::In { col, vals } => {
                    let ci = resolve_col(schema, col)?;
                    let kind = schema[ci].kind;
                    PCond::InSet {
                        ci, kind,
                        set: vals.iter().map(|v| norm_val(kind, &encode_query_value(kind, v))).collect(),
                        negate: false,
                    }
                }
                Cond::Like { col, pat } => PCond::Like { ci: resolve_col(schema, col)?, pat: pat.clone() },
                Cond::Null { col, negate } => PCond::Null { ci: resolve_col(schema, col)?, negate: *negate },
                Cond::InQuery { col, sub, negate } => {
                    let ci = resolve_col(schema, col)?;
                    let kind = schema[ci].kind;
                    let rs = sub.exec_with(rd)?;
                    if rs.schema.is_empty() {
                        return Err(DbError::SchemaMismatch("Unterabfrage ohne Spalte".into()));
                    }
                    let set = rs.rows.iter().map(|r| norm_val(kind, cell(r, 0))).collect();
                    PCond::InSet { ci, kind, set, negate: *negate }
                }
            });
        }
        Ok(out)
    }

    fn resolve_order(&self, schema: &[ColDef]) -> Result<Vec<(usize, Order)>> {
        self.order.iter().map(|(c, d)| Ok((resolve_col(schema, c)?, *d))).collect()
    }

    fn plan_access(&self, data: &TableData, pconds: &[PCond], order: &[(usize, Order)]) -> Access {
        let mut best: Option<(String, Vec<usize>)> = None;
        for pc in pconds {
            let ci = pc.col();
            if !data.is_indexed(ci) { continue; }
            let idx = data.index(ci);
            let name = &data.schema[ci].name;
            let found: Option<(String, Vec<usize>)> = match pc {
                PCond::Cmp { op: CmpOp::Eq, val, .. } =>
                    Some((format!("{name}=?"), idx.get(val).to_vec())),
                PCond::Cmp { op: CmpOp::Lt, val, .. } => Some((format!("{name}<?"), idx.range(None, Some((val, false))))),
                PCond::Cmp { op: CmpOp::Le, val, .. } => Some((format!("{name}<=?"), idx.range(None, Some((val, true))))),
                PCond::Cmp { op: CmpOp::Gt, val, .. } => Some((format!("{name}>?"), idx.range(Some((val, false)), None))),
                PCond::Cmp { op: CmpOp::Ge, val, .. } => Some((format!("{name}>=?"), idx.range(Some((val, true)), None))),
                PCond::Between { lo, hi, .. } =>
                    Some((format!("{name} BETWEEN ? AND ?"), idx.range(Some((lo, true)), Some((hi, true))))),
                PCond::InSet { kind, set, negate: false, .. } => {
                    let _ = kind;
                    let mut v: Vec<usize> = set.iter().flat_map(|k| idx.get(k).iter().copied()).collect();
                    v.sort_unstable(); v.dedup();
                    Some((format!("{name} IN (…)"), v))
                }
                _ => None,
            };
            if let Some((d, p)) = found {
                if best.as_ref().map_or(true, |(_, b)| p.len() < b.len()) { best = Some((d, p)); }
            }
        }
        if let Some((desc, positions)) = best { return Access::Lookup { desc, positions }; }
        if order.len() == 1 && data.is_indexed(order[0].0) {
            return Access::OrderScan { col: order[0].0, desc: order[0].1 == Order::Desc };
        }
        Access::Full
    }

    /// Treffer-Positionen: filter → (order → skip → limit, wenn `final_stage`).
    fn positions(
        &self, data: &TableData, pconds: &[PCond], order: &[(usize, Order)],
        skip: Option<usize>, limit: Option<usize>,
    ) -> Result<(Vec<usize>, Access)> {
        let passes = |p: usize| {
            let r = &data.rows[p];
            pconds.iter().all(|c| c.eval(r))
                && self.filters.iter().all(|f| f(Row::new(&data.schema, r)))
        };
        let access = self.plan_access(data, pconds, order);
        let sort = |v: &mut Vec<usize>| {
            if order.is_empty() { return; }
            v.sort_by(|&a, &b| {
                for (ci, dir) in order {
                    let o = cmp_values(data.schema[*ci].kind, cell(&data.rows[a], *ci), cell(&data.rows[b], *ci));
                    let o = if *dir == Order::Desc { o.reverse() } else { o };
                    if o != Ordering::Equal { return o; }
                }
                Ordering::Equal
            });
        };
        let slice = |mut v: Vec<usize>| {
            if let Some(s) = skip { v.drain(..s.min(v.len())); }
            if let Some(l) = limit { v.truncate(l); }
            v
        };
        let out = match &access {
            Access::OrderScan { col, desc } => {
                let idx = data.index(*col);
                let mut out = Vec::new();
                let mut skipped = 0usize;
                let s = skip.unwrap_or(0);
                'outer: for poss in idx.ordered(*desc) {
                    for &p in poss {
                        if !passes(p) { continue; }
                        if skipped < s { skipped += 1; continue; }
                        if limit.map_or(false, |l| out.len() >= l) { break 'outer; }
                        out.push(p);
                    }
                }
                out
            }
            Access::Lookup { positions, .. } => {
                let mut v: Vec<usize> = positions.iter().copied().filter(|&p| passes(p)).collect();
                sort(&mut v);
                slice(v)
            }
            Access::Full => {
                let mut v: Vec<usize> = (0..data.rows.len()).filter(|&p| passes(p)).collect();
                sort(&mut v);
                slice(v)
            }
        };
        Ok((out, access))
    }

    fn project_cols(&self, schema: &[ColDef]) -> Result<Option<(Vec<usize>, Vec<ColDef>)>> {
        let Some(cols) = &self.select else { return Ok(None) };
        if cols.iter().any(|c| c.starts_with('\u{0}')) {
            return Err(DbError::Unsupported("join() ist nur auf einer Tabelle (nicht auf Union/Unterabfrage) möglich".into()));
        }
        let mut keep = Vec::with_capacity(cols.len());
        let mut proj = Vec::with_capacity(cols.len());
        for want in cols {
            let i = resolve_col(schema, want)?;
            keep.push(i);
            proj.push(schema[i].clone());
        }
        Ok(Some((keep, proj)))
    }

    fn run_simple(&self, data: &TableData, pconds: &[PCond]) -> Result<Rs> {
        if let Some(c) = &self.select { if c.iter().any(|c| c.starts_with('\u{0}')) { self.project_cols(&data.schema)?; } }
        let order = self.resolve_order(&data.schema)?;
        let (pos, _) = self.positions(data, pconds, &order, self.skip, self.limit)?;
        match self.project_cols(&data.schema)? {
            None => Ok(Rs { schema: data.schema.clone(), rows: pos.into_iter().map(|p| data.rows[p].clone()).collect() }),
            Some((keep, proj)) => Ok(Rs {
                schema: proj,
                rows: pos.into_iter().map(|p| keep.iter().map(|&c| cell(&data.rows[p], c).to_string()).collect()).collect(),
            }),
        }
    }

    pub(crate) fn exec_with(&self, rd: &dyn Reader) -> Result<Rs> {
        match &self.src {
            Src::Base { name, joins } if joins.is_empty() => {
                let data = rd.data(name)?;
                let pconds = self.prepare(&data.schema, rd)?;
                if self.is_simple() { return self.run_simple(&data, &pconds); }
                let (pos, _) = self.positions(&data, &pconds, &[], None, None)?;
                let rows = pos.into_iter().map(|p| data.rows[p].clone()).collect();
                self.finish(rd, Rs { schema: data.schema.clone(), rows }, false)
            }
            Src::Base { name, joins } => {
                let rs = self.join_rows(rd, name, joins)?;
                self.finish(rd, rs, true)
            }
            Src::Derived(inner) => {
                let rs = inner.exec_with(rd)?;
                self.finish(rd, rs, true)
            }
            Src::Union(a, b, all) => {
                let mut ra = a.exec_with(rd)?;
                let rb = b.exec_with(rd)?;
                if ra.schema.len() != rb.schema.len() {
                    return Err(DbError::SchemaMismatch(format!(
                        "UNION: {} Spalten links, {} rechts", ra.schema.len(), rb.schema.len())));
                }
                ra.rows.extend(rb.rows);
                if !*all {
                    let mut seen = HashSet::new();
                    ra.rows.retain(|r| seen.insert(r.clone()));
                }
                self.finish(rd, ra, true)
            }
        }
    }

    fn join_rows(&self, rd: &dyn Reader, base: &str, joins: &[JoinSpec]) -> Result<Rs> {
        let b = rd.data(base)?;
        let qualify = |t: &str, s: &[ColDef]| -> Vec<ColDef> {
            s.iter().map(|c| { let mut c = c.clone(); c.name = format!("{t}.{}", c.name); c }).collect()
        };
        let mut schema = qualify(base, &b.schema);
        let mut rows: Vec<Vec<String>> = b.rows.clone();
        for j in joins {
            let rt = rd.data(&j.table)?;
            let li = resolve_col(&schema, &j.left)?;
            let rname = j.right.strip_prefix(&format!("{}.", j.table)).unwrap_or(&j.right);
            let ri = rt.col(rname).ok_or_else(|| unknown_col(&j.right))?;
            let (lk, rk) = (schema[li].kind, rt.schema[ri].kind);
            let mut map: HashMap<String, Vec<usize>> = HashMap::with_capacity(rt.rows.len());
            for (p, r) in rt.rows.iter().enumerate() {
                map.entry(norm_val(rk, cell(r, ri))).or_default().push(p);
            }
            let mut out = Vec::with_capacity(rows.len());
            for l in rows {
                match map.get(&norm_val(lk, cell(&l, li))) {
                    Some(ps) => for &p in ps {
                        let mut r = l.clone();
                        r.extend(rt.rows[p].iter().cloned());
                        r.resize(schema.len() + rt.schema.len(), String::new());
                        out.push(r);
                    },
                    None if j.outer => {
                        let mut r = l;
                        r.resize(schema.len() + rt.schema.len(), String::new());
                        out.push(r);
                    }
                    None => {}
                }
            }
            rows = out;
            schema.extend(qualify(&j.table, &rt.schema));
        }
        Ok(Rs { schema, rows })
    }

    /// where (optional) → group → having → order → select → distinct → skip → limit.
    fn finish(&self, rd: &dyn Reader, mut rs: Rs, apply_where: bool) -> Result<Rs> {
        if apply_where {
            let pconds = self.prepare(&rs.schema, rd)?;
            let schema = &rs.schema;
            rs.rows.retain(|r| pconds.iter().all(|c| c.eval(r))
                && self.filters.iter().all(|f| f(Row::new(schema, r))));
        }
        if let Some(g) = &self.group { rs = self.apply_group(rs, g)?; }
        if !self.having.is_empty() {
            let schema = &rs.schema;
            rs.rows.retain(|r| self.having.iter().all(|f| f(Row::new(schema, r))));
        }
        let order = self.resolve_order(&rs.schema)?;
        if !order.is_empty() {
            let schema = &rs.schema;
            rs.rows.sort_by(|a, b| {
                for (ci, dir) in &order {
                    let o = cmp_values(schema[*ci].kind, cell(a, *ci), cell(b, *ci));
                    let o = if *dir == Order::Desc { o.reverse() } else { o };
                    if o != Ordering::Equal { return o; }
                }
                Ordering::Equal
            });
        }
        if let Some((keep, proj)) = self.project_cols(&rs.schema)? {
            rs.rows = rs.rows.into_iter()
                .map(|r| keep.iter().map(|&c| cell(&r, c).to_string()).collect()).collect();
            rs.schema = proj;
        }
        if self.distinct {
            let mut seen = HashSet::new();
            rs.rows.retain(|r| seen.insert(r.clone()));
        }
        if let Some(s) = self.skip { rs.rows.drain(..s.min(rs.rows.len())); }
        if let Some(l) = self.limit { rs.rows.truncate(l); }
        Ok(rs)
    }

    fn apply_group(&self, rs: Rs, g: &GroupSpec) -> Result<Rs> {
        struct Acc { count: i64, nonempty: i64, n_num: i64, sum: f64, sum_i: i128, all_int: bool,
                     min: Option<String>, max: Option<String> }
        let key_idx: Vec<usize> = g.keys.iter().map(|k| resolve_col(&rs.schema, k)).collect::<Result<_>>()?;
        let agg_idx: Vec<Option<usize>> = g.aggs.iter()
            .map(|a| a.col.as_deref().map(|c| resolve_col(&rs.schema, c)).transpose()).collect::<Result<_>>()?;
        let mut index: HashMap<Vec<String>, usize> = HashMap::new();
        let mut groups: Vec<(Vec<String>, Vec<Acc>)> = Vec::new();
        for r in &rs.rows {
            let nk: Vec<String> = key_idx.iter().map(|&i| norm_val(rs.schema[i].kind, cell(r, i))).collect();
            let gi = *index.entry(nk).or_insert_with(|| {
                groups.push((key_idx.iter().map(|&i| cell(r, i).to_string()).collect(),
                    g.aggs.iter().map(|_| Acc { count: 0, nonempty: 0, n_num: 0, sum: 0.0, sum_i: 0,
                        all_int: true, min: None, max: None }).collect()));
                groups.len() - 1
            });
            for (ai, acc) in groups[gi].1.iter_mut().enumerate() {
                acc.count += 1;
                let Some(ci) = agg_idx[ai] else { continue };
                let v = cell(r, ci);
                if v == NULL_CELL { continue; }
                acc.nonempty += 1;
                let kind = rs.schema[ci].kind;
                if let Ok(f) = v.parse::<f64>() {
                    if f.is_finite() { acc.n_num += 1; acc.sum += f; }
                }
                match v.parse::<i128>() { Ok(n) => acc.sum_i += n, Err(_) => acc.all_int = false }
                if acc.min.as_deref().map_or(true, |m| cmp_values(kind, v, m) == Ordering::Less) { acc.min = Some(v.to_string()); }
                if acc.max.as_deref().map_or(true, |m| cmp_values(kind, v, m) == Ordering::Greater) { acc.max = Some(v.to_string()); }
            }
        }
        // Aggregat ohne GROUP BY liefert auch bei leerer Eingabe genau eine Zeile.
        if groups.is_empty() && g.keys.is_empty() {
            groups.push((Vec::new(), g.aggs.iter().map(|_| Acc { count: 0, nonempty: 0, n_num: 0, sum: 0.0,
                sum_i: 0, all_int: true, min: None, max: None }).collect()));
        }
        let mut schema: Vec<ColDef> = key_idx.iter().map(|&i| {
            ColumnDef::new(rs.schema[i].name.clone(), rs.schema[i].kind, None, false)
        }).collect();
        for (ai, a) in g.aggs.iter().enumerate() {
            let src_kind = agg_idx[ai].map(|i| rs.schema[i].kind);
            let kind = match a.func {
                AggFn::Count | AggFn::CountOf => ColumnKind::Int,
                AggFn::Sum if src_kind == Some(ColumnKind::Int) => ColumnKind::Int,
                AggFn::Sum | AggFn::Avg => ColumnKind::Float,
                AggFn::Min | AggFn::Max => src_kind.unwrap_or(ColumnKind::Text),
            };
            schema.push(ColumnDef::new(a.out_name(), kind, None, false));
        }
        let rows = groups.into_iter().map(|(mut keys, accs)| {
            for (ai, a) in g.aggs.iter().enumerate() {
                let acc = &accs[ai];
                let int_col = agg_idx[ai].map(|i| rs.schema[i].kind == ColumnKind::Int).unwrap_or(false);
                keys.push(match a.func {
                    AggFn::Count => acc.count.to_string(),
                    AggFn::CountOf => acc.nonempty.to_string(),
                    AggFn::Sum if int_col && acc.all_int => acc.sum_i.to_string(),
                    AggFn::Sum => acc.sum.to_string(),
                    AggFn::Avg => if acc.n_num == 0 { String::new() } else { (acc.sum / acc.n_num as f64).to_string() },
                    AggFn::Min => acc.min.clone().unwrap_or_default(),
                    AggFn::Max => acc.max.clone().unwrap_or_default(),
                });
            }
            keys
        }).collect();
        Ok(Rs { schema, rows })
    }

    fn execute(&self) -> Result<Rs> { self.ctx.read(&|rd| self.exec_with(rd)) }
    fn run(&self) -> Option<Rs> { report(self.execute()) }

    // ───── Plan ─────

    /// Zeigt, wie die Abfrage ausgeführt wird (Scan, Index, Join, Sortierung …).
    pub fn explain(&self) -> String {
        match self.ctx.read(&|rd| self.explain_with(rd)) {
            Ok(s) => s,
            Err(e) => format!("Fehler: {e}"),
        }
    }

    fn explain_with(&self, rd: &dyn Reader) -> Result<String> {
        let mut lines = Vec::new();
        match &self.src {
            Src::Base { name, joins } => {
                let data = rd.data(name)?;
                if joins.is_empty() {
                    let pconds = self.prepare(&data.schema, rd)?;
                    let order = if self.is_simple() { self.resolve_order(&data.schema)? } else { Vec::new() };
                    let (_, access) = self.positions(&data, &pconds, &order, self.skip, self.limit)?;
                    lines.push(match access {
                        Access::Full => format!("SCAN {name}"),
                        Access::Lookup { desc, .. } => format!("SEARCH {name} USING INDEX {desc}"),
                        Access::OrderScan { col, desc } => format!("SCAN {name} USING INDEX {} ({})",
                            data.schema[col].name, if desc { "absteigend, kein Sortieren" } else { "aufsteigend, kein Sortieren" }),
                    });
                } else {
                    lines.push(format!("SCAN {name}"));
                    for j in joins {
                        lines.push(format!("{} {} (Hash-Join auf {} = {})",
                            if j.outer { "LEFT JOIN" } else { "JOIN" }, j.table, j.left, j.right));
                    }
                }
            }
            Src::Derived(inner) => { lines.push("SUBQUERY".into()); lines.push(inner.explain_with(rd)?.replace('\n', "\n  ")); }
            Src::Union(a, b, all) => {
                lines.push(if *all { "UNION ALL".into() } else { "UNION".into() });
                lines.push(format!("  {}", a.explain_with(rd)?.replace('\n', "\n  ")));
                lines.push(format!("  {}", b.explain_with(rd)?.replace('\n', "\n  ")));
            }
        }
        if let Some(g) = &self.group { lines.push(format!("GROUP BY [{}] mit {} Aggregat(en)", g.keys.join(", "), g.aggs.len())); }
        if !self.having.is_empty() {
            lines.push(format!("HAVING ({} Closure(s))", self.having.len()));
        }
        if self.distinct { lines.push("DISTINCT".into()); }
        if !self.filters.is_empty() {
            lines.push(format!("FILTER ({} Closure(s), kein Index)", self.filters.len()));
        }
        if let Some(l) = self.limit { lines.push(format!("LIMIT {l}")); }
        Ok(lines.join("\n"))
    }

    // ───── Terminal: Daten ─────

    /// Alle Treffer. Bei Fehler: leerer `Vec` (Fehler auf stderr).
    pub fn collect(&self) -> Vec<Vec<String>> { report(self.try_collect()).unwrap_or_default() }
    pub fn try_collect(&self) -> DbResult<Vec<Vec<String>>> {
        let rs = self.execute()?;
        Ok(rs.rows.iter().map(|r| display_row(&rs.schema, r)).collect())
    }

    /// Erste Zeile. Leerer `Vec` = keine Treffer.
    pub fn first(&self) -> Vec<String> { self.try_first().ok().flatten().unwrap_or_default() }
    pub fn try_first(&self) -> DbResult<Option<Vec<String>>> {
        let q = self.shallow_limit(1);
        let rs = q.execute()?;
        Ok(rs.rows.first().map(|r| display_row(&rs.schema, r)))
    }

    /// Erste Zelle der ersten Zeile (SELECT VALUE). `""` = keine Treffer.
    pub fn value(&self) -> String { self.try_value().ok().flatten().unwrap_or_default() }
    pub fn try_value(&self) -> DbResult<Option<String>> {
        Ok(self.try_first()?.and_then(|r| r.into_iter().next()))
    }

    /// Alle Zellen einer Spalte.
    pub fn values(&self, col: &str) -> Vec<String> { report(self.try_values(col)).unwrap_or_default() }
    pub fn try_values(&self, col: &str) -> DbResult<Vec<String>> {
        let rs = self.execute()?;
        let idx = resolve_col(&rs.schema, col)?;
        Ok(rs.rows.iter().map(|r| display_value(cell(r, idx)).to_string()).collect())
    }

    /// Gibt es mindestens einen Treffer?
    pub fn exists(&self) -> bool { self.try_exists().unwrap_or(false) }
    pub fn try_exists(&self) -> DbResult<bool> { Ok(self.try_count_limited(Some(1))? > 0) }

    /// Eigene Typen: siehe [`model!`].
    pub fn collect_as<T: FromRow>(&self) -> Vec<T> { report(self.try_collect_as()).unwrap_or_default() }
    pub fn try_collect_as<T: FromRow>(&self) -> DbResult<Vec<T>> {
        let rs = self.execute()?;
        rs.rows.iter().map(|r| T::from_row(Row::new(&rs.schema, r))).collect()
    }
    pub fn first_as<T: FromRow>(&self) -> Option<T> { report(self.try_first_as()).flatten() }
    pub fn try_first_as<T: FromRow>(&self) -> DbResult<Option<T>> {
        let q = self.shallow_limit(1);
        let rs = q.execute()?;
        rs.rows.first().map(|r| T::from_row(Row::new(&rs.schema, r))).transpose()
    }

    fn shallow_limit(&self, n: usize) -> LimitedView<'_, 'a> { LimitedView { t: self, n, limit: None } }

    // ───── Terminal: Aggregate ─────

    pub fn count(&self) -> usize { report(self.try_count()).unwrap_or(0) }
    pub fn try_count(&self) -> DbResult<usize> { self.try_count_limited(None) }

    fn try_count_limited(&self, cap: Option<usize>) -> Result<usize> {
        if let Src::Base { name, joins } = &self.src {
            if joins.is_empty() && self.is_simple() {
                return self.ctx.read(&|rd| {
                    let data = rd.data(name)?;
                    let pconds = self.prepare(&data.schema, rd)?;
                    let limit = match (self.limit, cap) { (Some(a), Some(b)) => Some(a.min(b)), (a, b) => a.or(b) };
                    let (pos, _) = self.positions(&data, &pconds, &[], self.skip, limit)?;
                    Ok(pos.len())
                });
            }
        }
        Ok(self.execute()?.rows.len())
    }

    /// Summe (nicht-numerische Zellen werden ignoriert). Leer = `0.0`.
    pub fn sum(&self, col: &str) -> f64 { report(self.try_sum(col)).unwrap_or(0.0) }
    pub fn try_sum(&self, col: &str) -> DbResult<f64> { Ok(self.numbers(col)?.iter().sum()) }
    /// Durchschnitt über die numerischen Zellen. Keine Werte = `0.0`.
    pub fn avg(&self, col: &str) -> f64 { report(self.try_avg(col)).flatten().unwrap_or(0.0) }
    /// `Ok(None)` = keine numerischen Werte.
    pub fn try_avg(&self, col: &str) -> DbResult<Option<f64>> {
        let v = self.numbers(col)?;
        Ok(if v.is_empty() { None } else { Some(v.iter().sum::<f64>() / v.len() as f64) })
    }
    /// Kleinster Wert (typgerecht verglichen). Keine Zeilen = `""`.
    pub fn min(&self, col: &str) -> String { report(self.try_min(col)).flatten().unwrap_or_default() }
    pub fn max(&self, col: &str) -> String { report(self.try_max(col)).flatten().unwrap_or_default() }
    pub fn try_min(&self, col: &str) -> DbResult<Option<String>> { self.extreme(col, false) }
    pub fn try_max(&self, col: &str) -> DbResult<Option<String>> { self.extreme(col, true) }

    fn numbers(&self, col: &str) -> Result<Vec<f64>> {
        Ok(self.try_values(col)?.iter().filter_map(|v| v.parse::<f64>().ok()).filter(|f| f.is_finite()).collect())
    }

    fn extreme(&self, col: &str, want_max: bool) -> Result<Option<String>> {
        let rs = self.execute()?;
        let idx = resolve_col(&rs.schema, col)?;
        let kind = rs.schema[idx].kind;
        let vals = rs.rows.iter().map(|r| cell(r, idx)).filter(|v| *v != NULL_CELL);
        let best = if want_max { vals.max_by(|a, b| cmp_values(kind, a, b)) }
                   else { vals.min_by(|a, b| cmp_values(kind, a, b)) };
        Ok(best.map(|v| display_value(v).to_string()))
    }

    // ───── Terminal: Ausgabe ─────

    pub fn print(&self) {
        if let Some(rs) = self.run() { print!("{}", format_terminal(&rs.schema, &rs.rows)); }
    }
    /// HTML-Dokument. Bei Fehler `""`.
    pub fn to_html(&self) -> String {
        let title = match &self.src { Src::Base { name, .. } => name.as_str(), _ => "Abfrage" };
        self.run().map(|r| format_html(title, &r.schema, &r.rows)).unwrap_or_default()
    }
    /// CSV (UTF-8 mit BOM, CRLF). Bei Fehler `""`.
    pub fn to_csv(&self) -> String { self.run().map(|r| format_csv(&r.schema, &r.rows)).unwrap_or_default() }
    /// JSON-Array von Objekten. Bei Fehler `""`.
    pub fn to_json(&self) -> String { self.run().map(|r| format_json(&r.schema, &r.rows)).unwrap_or_default() }

    pub fn export_html(&self, path: impl AsRef<Path>) -> bool {
        let title = match &self.src { Src::Base { name, .. } => name.clone(), _ => "Abfrage".into() };
        self.export(path.as_ref(), |s, r| format_html(&title, s, r))
    }
    pub fn export_csv(&self, path: impl AsRef<Path>) -> bool { self.export(path.as_ref(), |s, r| format_csv(s, r)) }
    pub fn export_json(&self, path: impl AsRef<Path>) -> bool { self.export(path.as_ref(), |s, r| format_json(s, r)) }

    fn export(&self, path: &Path, render: impl Fn(&[ColDef], &[Vec<String>]) -> String) -> bool {
        let Some(rs) = self.run() else { return false };
        match fs::write(path, render(&rs.schema, &rs.rows)) {
            Ok(()) => true,
            Err(e) => { eprintln!("DBCore: I/O-Fehler: {e}"); false }
        }
    }

    // ───── Mutationen ─────

    fn matched(&self, rd: &dyn Reader) -> Result<(String, Vec<usize>)> {
        let name = self.plain_base()?.to_string();
        let data = rd.data(&name)?;
        let pconds = self.prepare(&data.schema, rd)?;
        let order = self.resolve_order(&data.schema)?;
        let (pos, _) = self.positions(&data, &pconds, &order, self.skip, self.limit)?;
        Ok((name, pos))
    }

    /// Löscht alle Treffer (Filter/Order/Skip/Limit werden beachtet), inkl.
    /// `ON DELETE CASCADE`. Liefert die Anzahl gelöschter Zeilen (0 bei Fehler).
    pub fn delete(&self) -> usize { report(self.try_delete()).unwrap_or(0) }
    pub fn try_delete(&self) -> DbResult<usize> {
        self.ctx.write(|tx| {
            let (name, pos) = self.matched(tx)?;
            if pos.is_empty() { return Ok(0); }
            tx.delete_at(&name, &pos)
        })
    }

    /// Alias für `patch`. SQL-Leser kennen MERGE als Synonym.
    pub fn merge(&self, fields: Vec<(&str, String)>) -> usize { self.patch(fields) }

    /// Partielles UPDATE auf allen Treffern. Nur die angegebenen Spalten
    /// werden überschrieben. Liefert die Anzahl geänderter Zeilen (0 bei Fehler).
    pub fn patch(&self, fields: Vec<(&str, String)>) -> usize { report(self.try_patch(fields)).unwrap_or(0) }
    pub fn try_patch(&self, fields: Vec<(&str, String)>) -> DbResult<usize> {
        self.ctx.write(|tx| {
            let (name, pos) = self.matched(tx)?;
            tx.patch_at(&name, &pos, &fields)
        })
    }

    /// Entfernt eine Spalte aus Schema und allen Zeilen. Der `filter`
    /// wird ignoriert. Liefert die Anzahl Zeilen (0 bei Fehler).
    pub fn remove_field(&self, col: &str) -> usize { report(self.try_remove_field(col)).unwrap_or(0) }
    pub fn try_remove_field(&self, col: &str) -> DbResult<usize> {
        let name = self.plain_base()?.to_string();
        self.ctx.write(|tx| {
            let n = tx.view(&name)?.rows.len();
            tx.remove_field(&name, col)?;
            Ok(n)
        })
    }

    // ───── Streaming ─────

    /// Lazy-Iterator mit echtem Fehler pro Zeile. Ohne `order_by`/`group_by`/`distinct`/Join
    /// wird Block für Block von der Platte gelesen (konstanter Speicher). Sonst
    /// wird das Ergebnis berechnet und dann zeilenweise geliefert.
    pub fn stream(self) -> DbResult<RowStream<'a>> {
        let lazy_ok = self.is_simple() && self.order.is_empty()
            && matches!(&self.src, Src::Base { joins, .. } if joins.is_empty())
            && matches!(self.ctx, Ctx::Db(_) | Ctx::Snap(_));
        if !lazy_ok {
            let rs = self.execute()?;
            return Ok(RowStream { inner: StreamInner::Mem(rs.rows.into_iter()) });
        }
        let name = self.plain_base()?.to_string();
        let open = |snap: &Snapshot| -> Result<(Scan, Vec<PCond>)> {
            let scan = snap.store.open_scan(snap, &name)?;
            let pconds = self.prepare(&scan.schema, snap)?;
            Ok((scan, pconds))
        };
        let (scan, pconds) = match self.ctx {
            Ctx::Snap(s) => open(s)?,
            Ctx::Db(db) => {
                let store = db.st()?;
                let mut last = DbError::SnapshotExpired;
                let mut got = None;
                for _ in 0..8 {
                    let snap = store.snapshot()?;
                    match open(&snap) {
                        Err(DbError::SnapshotExpired) => { last = DbError::SnapshotExpired; }
                        other => { got = Some(other?); break; }
                    }
                }
                got.ok_or(last)?
            }
            Ctx::Tx(_) => unreachable!("lazy_ok schließt Tx aus"),
        };
        let proj = self.project_cols(&scan.schema)?;
        let schema = scan.schema.clone();
        Ok(RowStream { inner: StreamInner::Lazy(Box::new(Lazy {
            scan, schema, pconds, filters: self.filters, proj,
            skip: self.skip.unwrap_or(0), limit: self.limit, emitted: 0, failed: false,
        })) })
    }
}

/// Ein `Table` mit überschriebenem Limit (für `first`/`exists`), ohne den Builder zu klonen.
struct LimitedView<'t, 'a> { t: &'t Table<'a>, n: usize, limit: Option<usize> }

impl<'t, 'a> LimitedView<'t, 'a> {
    fn eff_limit(&self) -> Option<usize> {
        Some(self.t.limit.map_or(self.n, |l| l.min(self.n))).or(self.limit)
    }
    fn execute(&self) -> Result<Rs> {
        let lim = self.eff_limit();
        self.t.ctx.read(&|rd| self.t.exec_limited(rd, lim))
    }
}

impl<'a> Table<'a> {
    /// Wie `exec_with`, aber mit anderem Limit (nur für den einfachen Pfad gespart, sonst nachträglich gekappt).
    fn exec_limited(&self, rd: &dyn Reader, limit: Option<usize>) -> Result<Rs> {
        if let Src::Base { name, joins } = &self.src {
            if joins.is_empty() && self.is_simple() {
                let data = rd.data(name)?;
                let pconds = self.prepare(&data.schema, rd)?;
                let order = self.resolve_order(&data.schema)?;
                let (pos, _) = self.positions(&data, &pconds, &order, self.skip, limit)?;
                return Ok(match self.project_cols(&data.schema)? {
                    None => Rs { schema: data.schema.clone(), rows: pos.into_iter().map(|p| data.rows[p].clone()).collect() },
                    Some((keep, proj)) => Rs { schema: proj, rows: pos.into_iter()
                        .map(|p| keep.iter().map(|&c| cell(&data.rows[p], c).to_string()).collect()).collect() },
                });
            }
        }
        let mut rs = self.exec_with(rd)?;
        if let Some(l) = limit { rs.rows.truncate(l); }
        Ok(rs)
    }
}

// ───────────── Streaming-Typen ─────────────

struct Lazy<'a> {
    scan: Scan,
    schema: Vec<ColDef>,
    pconds: Vec<PCond>,
    filters: Vec<RowFn<'a>>,
    proj: Option<(Vec<usize>, Vec<ColDef>)>,
    skip: usize,
    limit: Option<usize>,
    emitted: usize,
    failed: bool,
}

enum StreamInner<'a> {
    Mem(std::vec::IntoIter<Vec<String>>),
    Lazy(Box<Lazy<'a>>),
}

/// Zeilen-Iterator mit Fehlerbehandlung pro Zeile (siehe [`Table::stream`]).
pub struct RowStream<'a> { inner: StreamInner<'a> }

impl<'a> Iterator for RowStream<'a> {
    type Item = DbResult<Vec<String>>;
    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            StreamInner::Mem(it) => it.next().map(|r| Ok(r.iter().map(|v| display_value(v).to_string()).collect())),
            StreamInner::Lazy(l) => {
                if l.failed { return None; }
                loop {
                    if l.limit.map_or(false, |x| l.emitted >= x) { return None; }
                    match l.scan.next_row() {
                        Err(e) => { l.failed = true; return Some(Err(e)); }
                        Ok(None) => return None,
                        Ok(Some(row)) => {
                            let ok = l.pconds.iter().all(|c| c.eval(&row))
                                && l.filters.iter().all(|f| f(Row::new(&l.schema, &row)));
                            if !ok { continue; }
                            if l.skip > 0 { l.skip -= 1; continue; }
                            l.emitted += 1;
                            return Some(Ok(match &l.proj {
                                None => row.iter().map(|v| display_value(v).to_string()).collect(),
                                Some((keep, _)) => keep.iter().map(|&c| display_value(cell(&row, c)).to_string()).collect(),
                            }));
                        }
                    }
                }
            }
        }
    }
}

/// Iterator für `for row in db.table("t") { … }`; Fehler werden auf `stderr` gemeldet
/// und beenden die Iteration.
pub struct Rows<'a>(RowStream<'a>);

impl<'a> Iterator for Rows<'a> {
    type Item = Vec<String>;
    fn next(&mut self) -> Option<Vec<String>> {
        match self.0.next()? {
            Ok(r) => Some(r),
            Err(e) => { eprintln!("DBCore: {e}"); None }
        }
    }
}

impl<'a> IntoIterator for Table<'a> {
    type Item = Vec<String>;
    type IntoIter = Rows<'a>;
    fn into_iter(self) -> Rows<'a> {
        match self.stream() {
            Ok(s) => Rows(s),
            Err(e) => {
                eprintln!("DBCore: {e}");
                Rows(RowStream { inner: StreamInner::Mem(Vec::new().into_iter()) })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexed_order_scan_applies_limit_without_duplicates() {
        let db = DBCore::temp();
        db.create("items", schema! { @key id: i32, rank: i32 }.index(&["rank"]));
        for id in (1..=5).rev() {
            db.add("items", row! { id: id, rank: id });
        }
        assert_eq!(db.table("items").order_by("rank").limit(3).values("rank"), ["1", "2", "3"]);
        assert_eq!(db.table("items").order_by("rank").skip(2).limit(2).values("rank"), ["3", "4"]);
    }
}
