//! Speicherschicht.
//!
//! * **Tabellendatei (v3)**: `DBC3 | prefix(20) | { len:u32 | AEAD-Block }*`.
//!   Block 0 = Kopf (Schema/Constraints), danach Zeilenblöcke. Nonce =
//!   `prefix ‖ Blocknummer`, AAD enthält Tabellenname und „letzter Block“-Flag
//!   (Schutz gegen Umsortieren, Abschneiden, Anhängen, Vertauschen von Tabellen).
//! * **Unveränderlich**: `name.<seq>.tbl` wird nie überschrieben. Gepinnte
//!   Snapshots halten ältere Versionen lesbar; nicht mehr referenzierte
//!   Versionen werden nach Commits eingesammelt.
//! * **Manifest**: verschlüsselte Liste `Tabelle → Datei`. Der atomare
//!   `rename` des Manifests ist der Commit-Punkt.
//! * **MVCC**: Transaktionen lesen parallel aus einem festen Manifest-Snapshot
//!   und prüfen ihren Lese-/Schreibsatz optimistisch beim Commit.
//! * **Locks**: Leser und Transaktionsarbeit brauchen keine; nur Commits
//!   serialisieren sich über ein In-Prozess-Flag und OS-Datei-Lock (`.writer.lock`).

use super::*;
use chacha20poly1305::aead::{rand_core::RngCore, Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, XChaCha20Poly1305, XNonce};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::ops::Bound;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AO};
use std::sync::Mutex;
use std::time::Instant;

const KEY_LEN: usize = 32;
const LEGACY_NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MAGIC_TABLE: &[u8; 4] = b"DBC3";
const MAGIC_MANIFEST: &[u8; 4] = b"DBM1";
const MAGIC_WAL: &[u8; 4] = b"DBW1";
const MAGIC_BACKUP: &[u8; 4] = b"DBB1";
const X_NONCE_LEN: usize = 24;
const PREFIX_LEN: usize = 20;
const ROWS_PER_CHUNK: usize = 1024;
const CHUNK_BYTES: usize = 256 * 1024;
const MAX_CHUNK: usize = 256 * 1024 * 1024;
const MANIFEST: &str = "MANIFEST";
const WAL: &str = "WAL";
const BACKUP: &str = "BACKUP";

// ───────────── Index (im Speicher) ─────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum IKey {
    Int(i128),
    Decimal(String),
    Float(u64),
    Text(String),
}

impl IKey {
    pub(crate) fn of(kind: ColumnKind, v: &str) -> IKey {
        match kind {
            ColumnKind::Int | ColumnKind::Timestamp | ColumnKind::Date | ColumnKind::Time => v
                .parse::<i128>()
                .map(IKey::Int)
                .or_else(|_| v.parse::<u128>().map(|n| IKey::Text(n.to_string())))
                .unwrap_or_else(|_| IKey::Text(v.to_string())),
            ColumnKind::Decimal => decimal_order_key(v)
                .map(IKey::Decimal)
                .unwrap_or_else(|| IKey::Text(v.to_string())),
            ColumnKind::Blob | ColumnKind::Uuid => IKey::Text(v.to_ascii_lowercase()),
            ColumnKind::Float => match v.parse::<f64>() {
                Ok(f) if f.is_finite() => {
                    let b = f.to_bits();
                    IKey::Float(if b >> 63 == 1 { !b } else { b | (1 << 63) })
                }
                _ => IKey::Text(v.to_string()),
            },
            _ => IKey::Text(v.to_string()),
        }
    }
}

pub(crate) struct BIndex {
    map: BTreeMap<IKey, Vec<usize>>,
    kind: ColumnKind,
}

impl BIndex {
    fn build(kind: ColumnKind, rows: &[Vec<String>], ci: usize) -> Self {
        let mut map: BTreeMap<IKey, Vec<usize>> = BTreeMap::new();
        for (p, r) in rows.iter().enumerate() {
            map.entry(IKey::of(kind, cell(r, ci))).or_default().push(p);
        }
        BIndex { map, kind }
    }
    pub(crate) fn get(&self, v: &str) -> &[usize] {
        self.map
            .get(&IKey::of(self.kind, v))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }
    /// Positionen im Bereich (aufsteigend nach Position sortiert).
    pub(crate) fn range(&self, lo: Option<(&str, bool)>, hi: Option<(&str, bool)>) -> Vec<usize> {
        let conv = |b: Option<(&str, bool)>| match b {
            None => Bound::Unbounded,
            Some((v, incl)) => {
                let k = IKey::of(self.kind, v);
                if incl {
                    Bound::Included(k)
                } else {
                    Bound::Excluded(k)
                }
            }
        };
        let (l, h) = (conv(lo), conv(hi));
        // BTreeMap::range paniken bei start > end – vorher prüfen.
        let empty = match (&l, &h) {
            (Bound::Included(a), Bound::Included(b)) => a > b,
            (Bound::Included(a), Bound::Excluded(b)) | (Bound::Excluded(a), Bound::Included(b)) => {
                a >= b
            }
            (Bound::Excluded(a), Bound::Excluded(b)) => a >= b,
            _ => false,
        };
        if empty {
            return Vec::new();
        }
        let mut out: Vec<usize> = self
            .map
            .range((l, h))
            .flat_map(|(_, v)| v.iter().copied())
            .collect();
        out.sort_unstable();
        out
    }
    pub(crate) fn ordered(&self, desc: bool) -> Box<dyn Iterator<Item = &Vec<usize>> + '_> {
        if desc {
            Box::new(self.map.values().rev())
        } else {
            Box::new(self.map.values())
        }
    }
}

// ───────────── Tabellendaten ─────────────

pub(crate) struct TableData {
    pub(crate) name: String,
    pub(crate) schema: Vec<ColDef>,
    pub(crate) rows: Vec<Vec<String>>,
    pub(crate) index_defs: Vec<IndexDefinition>,
    idx: Mutex<HashMap<usize, Arc<BIndex>>>,
    composite_idx: Mutex<HashMap<usize, Arc<CompositeIndex>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IndexTerm {
    Column(String),
    Lower(String),
    Upper(String),
    Length(String),
}

impl IndexTerm {
    pub(crate) fn column(&self) -> &str {
        match self {
            Self::Column(column)
            | Self::Lower(column)
            | Self::Upper(column)
            | Self::Length(column) => column,
        }
    }

    fn value(&self, schema: &[ColDef], row: &[String]) -> Option<(ColumnKind, String)> {
        let ci = schema.iter().position(|c| c.name == self.column())?;
        let raw = cell(row, ci);
        if raw == NULL_CELL {
            return Some((ColumnKind::Null, String::new()));
        }
        Some(match self {
            Self::Column(_) => (schema[ci].kind, raw.to_string()),
            Self::Lower(_) => (ColumnKind::Text, raw.to_lowercase()),
            Self::Upper(_) => (ColumnKind::Text, raw.to_uppercase()),
            Self::Length(_) => (ColumnKind::Int, raw.chars().count().to_string()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IndexDefinition {
    pub(crate) name: String,
    pub(crate) terms: Vec<IndexTerm>,
    pub(crate) included: Vec<String>,
    pub(crate) predicate: Option<crate::IndexPredicate>,
}

pub(crate) struct CompositeIndex {
    map: BTreeMap<Vec<IKey>, Vec<usize>>,
    covering: HashMap<usize, HashMap<String, String>>,
}

impl CompositeIndex {
    fn build(def: &IndexDefinition, schema: &[ColDef], rows: &[Vec<String>]) -> Self {
        let mut map: BTreeMap<Vec<IKey>, Vec<usize>> = BTreeMap::new();
        let mut covering = HashMap::new();
        for (position, row) in rows.iter().enumerate() {
            if !index_predicate_matches(def.predicate.as_ref(), schema, row) {
                continue;
            }
            let mut stored = HashMap::new();
            for term in &def.terms {
                if let IndexTerm::Column(column) = term {
                    if let Some(ci) = schema.iter().position(|col| &col.name == column) {
                        stored.insert(column.clone(), cell(row, ci).to_string());
                    }
                }
            }
            for column in &def.included {
                if let Some(ci) = schema.iter().position(|col| &col.name == column) {
                    stored.insert(column.clone(), cell(row, ci).to_string());
                }
            }
            covering.insert(position, stored);
            let key = def
                .terms
                .iter()
                .filter_map(|term| {
                    term.value(schema, row)
                        .map(|(kind, value)| IKey::of(kind, &value))
                })
                .collect();
            map.entry(key).or_default().push(position);
        }
        CompositeIndex { map, covering }
    }

    pub(crate) fn prefix(&self, key: &[IKey]) -> Vec<usize> {
        self.map
            .range(key.to_vec()..)
            .take_while(|(candidate, _)| candidate.starts_with(key))
            .flat_map(|(_, positions)| positions.iter().copied())
            .collect()
    }

    pub(crate) fn project(
        &self,
        positions: &[usize],
        columns: &[String],
    ) -> Option<HashMap<usize, Vec<String>>> {
        positions
            .iter()
            .map(|position| {
                let values = self.covering.get(position)?;
                let row = columns
                    .iter()
                    .map(|column| values.get(column).cloned())
                    .collect::<Option<Vec<_>>>()?;
                Some((*position, row))
            })
            .collect()
    }
}

fn index_predicate_matches(
    predicate: Option<&crate::IndexPredicate>,
    schema: &[ColDef],
    row: &[String],
) -> bool {
    let Some(predicate) = predicate else {
        return true;
    };
    match predicate {
        crate::IndexPredicate::Equals { column, value } => schema
            .iter()
            .position(|c| &c.name == column)
            .map(|ci| norm_val(schema[ci].kind, cell(row, ci)) == norm_val(schema[ci].kind, value))
            .unwrap_or(false),
        crate::IndexPredicate::IsNotNull(column) => schema
            .iter()
            .position(|c| &c.name == column)
            .map(|ci| cell(row, ci) != NULL_CELL)
            .unwrap_or(false),
    }
}

impl Clone for TableData {
    fn clone(&self) -> Self {
        TableData {
            name: self.name.clone(),
            schema: self.schema.clone(),
            rows: self.rows.clone(),
            index_defs: self.index_defs.clone(),
            idx: Mutex::new(HashMap::new()),
            composite_idx: Mutex::new(HashMap::new()),
        }
    }
}

impl TableData {
    pub(crate) fn new(name: String, schema: Vec<ColDef>, rows: Vec<Vec<String>>) -> Self {
        TableData {
            name,
            schema,
            rows,
            index_defs: Vec::new(),
            idx: Mutex::new(HashMap::new()),
            composite_idx: Mutex::new(HashMap::new()),
        }
    }
    pub(crate) fn with_indexes(mut self, index_defs: Vec<IndexDefinition>) -> Self {
        self.index_defs = index_defs;
        self
    }
    pub(crate) fn col(&self, name: &str) -> Option<usize> {
        self.schema.iter().position(|c| c.name == name)
    }
    pub(crate) fn is_indexed(&self, ci: usize) -> bool {
        self.schema[ci].is_indexed()
    }
    /// Index lazy bauen (pro Tabellenstand einmal) und gemeinsam nutzen.
    pub(crate) fn index(&self, ci: usize) -> Arc<BIndex> {
        let mut g = self.idx.lock().unwrap_or_else(|p| p.into_inner());
        g.entry(ci)
            .or_insert_with(|| Arc::new(BIndex::build(self.schema[ci].kind, &self.rows, ci)))
            .clone()
    }
    pub(crate) fn composite_index(&self, index: usize) -> Arc<CompositeIndex> {
        let mut g = self
            .composite_idx
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        g.entry(index)
            .or_insert_with(|| {
                Arc::new(CompositeIndex::build(
                    &self.index_defs[index],
                    &self.schema,
                    &self.rows,
                ))
            })
            .clone()
    }
    /// Vor jeder Änderung aufrufen: verwirft die gebauten Indizes.
    pub(crate) fn touch(&mut self) {
        self.idx
            .get_mut()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
        self.composite_idx
            .get_mut()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }
}

// ───────────── Manifest ─────────────

#[derive(Debug, Clone, Default)]
pub(crate) struct Manifest {
    pub(crate) seq: u64,
    pub(crate) user_version: u32,
    pub(crate) tables: BTreeMap<String, String>,
}

fn valid_filename(f: &str) -> bool {
    !f.is_empty()
        && f.len() <= 200
        && !f.starts_with('.')
        && !f.contains("..")
        && f.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

impl Manifest {
    fn encode(&self) -> String {
        let mut s = format!(
            "MANIFEST:1\nSEQ:{}\nVERSION:{}\n",
            self.seq, self.user_version
        );
        for (n, f) in &self.tables {
            s.push_str(&format!("T:{n}:{f}\n"));
        }
        s
    }
    fn decode(text: &str) -> Result<Manifest> {
        let mut m = Manifest::default();
        let mut saw_head = false;
        for line in text.lines() {
            if line == "MANIFEST:1" {
                saw_head = true;
            } else if let Some(v) = line.strip_prefix("SEQ:") {
                m.seq = v.parse().map_err(|_| DbError::Corrupt("Manifest: SEQ"))?;
            } else if let Some(v) = line.strip_prefix("VERSION:") {
                m.user_version = v
                    .parse()
                    .map_err(|_| DbError::Corrupt("Manifest: VERSION"))?;
            } else if let Some(v) = line.strip_prefix("T:") {
                let (n, f) = v
                    .split_once(':')
                    .ok_or(DbError::Corrupt("Manifest: Eintrag"))?;
                if !valid_name(n) || !valid_filename(f) {
                    return Err(DbError::Corrupt("Manifest: Name"));
                }
                m.tables.insert(n.to_string(), f.to_string());
            }
        }
        if !saw_head {
            return Err(DbError::Corrupt("Manifest: Kopf fehlt"));
        }
        Ok(m)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackupKind {
    Full,
    Incremental,
}

#[derive(Debug, Clone)]
struct BackupInfo {
    id: String,
    parent: Option<String>,
    kind: BackupKind,
}

impl BackupInfo {
    fn encode(&self) -> String {
        match &self.parent {
            Some(parent) => format!(
                "BACKUP:1\nKIND:INCREMENTAL\nID:{}\nPARENT:{parent}\n",
                self.id
            ),
            None => format!("BACKUP:1\nKIND:FULL\nID:{}\n", self.id),
        }
    }

    fn decode(text: &str) -> Result<Self> {
        let mut lines = text.lines();
        if lines.next() != Some("BACKUP:1") {
            return Err(DbError::Corrupt("Backup-Metadaten: Kopf fehlt"));
        }
        let kind = match lines.next() {
            Some("KIND:FULL") => BackupKind::Full,
            Some("KIND:INCREMENTAL") => BackupKind::Incremental,
            _ => return Err(DbError::Corrupt("Backup-Metadaten: Typ")),
        };
        let id = lines
            .next()
            .and_then(|line| line.strip_prefix("ID:"))
            .filter(|id| valid_backup_id(id))
            .ok_or(DbError::Corrupt("Backup-Metadaten: ID"))?
            .to_string();
        let parent = match (kind, lines.next()) {
            (BackupKind::Full, None) => None,
            (BackupKind::Incremental, Some(line)) => Some(
                line.strip_prefix("PARENT:")
                    .filter(|id| valid_backup_id(id))
                    .ok_or(DbError::Corrupt("Backup-Metadaten: Vorgänger"))?
                    .to_string(),
            ),
            _ => return Err(DbError::Corrupt("Backup-Metadaten: Vorgänger")),
        };
        if lines.next().is_some() {
            return Err(DbError::Corrupt("Backup-Metadaten: zusätzliche Daten"));
        }
        Ok(BackupInfo { id, parent, kind })
    }
}

fn valid_backup_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

fn backup_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct StagingDir {
    path: PathBuf,
    published: bool,
}

impl StagingDir {
    fn create(destination: &Path) -> Result<Self> {
        if destination.exists() {
            return Err(
                io::Error::new(io::ErrorKind::AlreadyExists, "Ziel existiert bereits").into(),
            );
        }
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent)?;
        let name = destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(DbError::InvalidName)?;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..32 {
            let suffix = NEXT.fetch_add(1, AO::Relaxed);
            let path = parent.join(format!(
                ".{name}.dbcore-tmp-{}-{suffix}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    return Ok(Self {
                        path,
                        published: false,
                    })
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "temporäres Zielverzeichnis nicht verfügbar",
        )
        .into())
    }

    fn publish(mut self, destination: &Path) -> Result<()> {
        if destination.exists() {
            return Err(
                io::Error::new(io::ErrorKind::AlreadyExists, "Ziel existiert bereits").into(),
            );
        }
        fs::rename(&self.path, destination)?;
        self.published = true;
        Ok(())
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

// ───────────── Kopf-Text (Schema + Constraints) ─────────────

fn esc_field(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            ':' => o.push_str("\\:"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            c => o.push(c),
        }
    }
    o
}

fn split_fields(s: &str) -> Vec<String> {
    let (mut out, mut cur) = (Vec::new(), String::new());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        match c {
            '\\' => match it.next() {
                Some('n') => cur.push('\n'),
                Some('r') => cur.push('\r'),
                Some(o) => cur.push(o),
                None => cur.push('\\'),
            },
            ':' => out.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// Spaltenzeile `COLS:` (Format unverändert zu v1/v2).
fn schema_line(cols: &[ColDef]) -> String {
    let mut out = String::new();
    for (i, c) in cols.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&c.name);
        out.push(':');
        out.push_str(c.kind.as_str());
        out.push(':');
        out.push(if c.key { 'k' } else { '-' });
        if let Some(d) = &c.default {
            out.push(':');
            out.push_str(d);
        }
    }
    out
}

pub(crate) fn header_text(name: &str, cols: &[ColDef], indexes: &[IndexDefinition]) -> String {
    let mut h = format!("TABLE:{name}\nCOLS:{}\nFORMAT:4\n", schema_line(cols));
    for c in cols {
        if c.not_null {
            h.push_str(&format!("NN:{}\n", esc_field(&c.name)));
        }
        if c.unique && !c.key {
            h.push_str(&format!("UQ:{}\n", esc_field(&c.name)));
        }
        if c.indexed && !c.unique && !c.key {
            h.push_str(&format!("IX:{}\n", esc_field(&c.name)));
        }
        for ck in &c.checks {
            let toks: Vec<String> = ck.encode().iter().map(|t| esc_field(t)).collect();
            h.push_str(&format!("CK:{}:{}\n", esc_field(&c.name), toks.join(":")));
        }
        if let Some(fk) = &c.fk {
            h.push_str(&format!(
                "FK:{}:{}:{}:{}\n",
                esc_field(&c.name),
                esc_field(&fk.table),
                esc_field(&fk.column),
                if fk.on_delete == OnDelete::Cascade {
                    "cascade"
                } else {
                    "restrict"
                }
            ));
        }
    }
    for index in indexes {
        let mut fields = vec![index.name.clone(), index.terms.len().to_string()];
        for term in &index.terms {
            let (kind, column) = match term {
                IndexTerm::Column(c) => ("C", c),
                IndexTerm::Lower(c) => ("L", c),
                IndexTerm::Upper(c) => ("U", c),
                IndexTerm::Length(c) => ("N", c),
            };
            fields.push(kind.into());
            fields.push(column.clone());
        }
        fields.push(index.included.len().to_string());
        fields.extend(index.included.iter().cloned());
        match &index.predicate {
            Some(crate::IndexPredicate::Equals { column, value }) => {
                fields.push("E".into());
                fields.push(column.clone());
                fields.push(value.clone());
            }
            Some(crate::IndexPredicate::IsNotNull(column)) => {
                fields.push("Z".into());
                fields.push(column.clone());
            }
            None => fields.push("-".into()),
        }
        h.push_str("IDF:");
        h.push_str(
            &fields
                .iter()
                .map(|field| esc_field(field))
                .collect::<Vec<_>>()
                .join(":"),
        );
        h.push('\n');
    }
    h
}

pub(crate) fn parse_header(text: &str, name: &str) -> Result<(Vec<ColDef>, Vec<IndexDefinition>)> {
    let cols_line = text
        .lines()
        .find(|l| l.starts_with("COLS:"))
        .ok_or(DbError::Corrupt("Schema fehlt"))?;
    if let Some(t) = text.lines().find(|l| l.starts_with("TABLE:")) {
        if &t[6..] != name {
            return Err(DbError::Corrupt("Tabellenname passt nicht zur Datei"));
        }
    }
    let body = &cols_line[5..];
    let mut cols = Vec::new();
    if !body.is_empty() {
        for s in body.split(',') {
            let mut parts = s.splitn(4, ':');
            let n = parts.next().unwrap_or("").to_string();
            let kind = ColumnKind::from_str(parts.next().unwrap_or("Text"))
                .ok_or(DbError::Corrupt("unbekannter Spaltentyp"))?;
            let key = parts.next().unwrap_or("-") == "k";
            let default = parts.next().map(|s| s.to_string());
            cols.push(ColumnDef::new(n, kind, default, key));
        }
    }
    let mut indexes = Vec::new();
    for line in text.lines() {
        let Some((tag, rest)) = line.split_once(':') else {
            continue;
        };
        if tag == "IDF" {
            let fields = split_fields(rest);
            let mut at = 0;
            let index_name = fields
                .get(at)
                .filter(|name| valid_name(name))
                .ok_or(DbError::Corrupt("Indexdefinition: Name"))?
                .clone();
            at += 1;
            let term_count: usize = fields
                .get(at)
                .ok_or(DbError::Corrupt("Indexdefinition: Terme"))?
                .parse()
                .map_err(|_| DbError::Corrupt("Indexdefinition: Terme"))?;
            at += 1;
            let mut terms = Vec::with_capacity(term_count);
            for _ in 0..term_count {
                let kind = fields
                    .get(at)
                    .ok_or(DbError::Corrupt("Indexdefinition: Ausdruck"))?;
                let column = fields
                    .get(at + 1)
                    .filter(|column| valid_name(column))
                    .ok_or(DbError::Corrupt("Indexdefinition: Spalte"))?
                    .clone();
                terms.push(match kind.as_str() {
                    "C" => IndexTerm::Column(column),
                    "L" => IndexTerm::Lower(column),
                    "U" => IndexTerm::Upper(column),
                    "N" => IndexTerm::Length(column),
                    _ => return Err(DbError::Corrupt("Indexdefinition: Ausdruck")),
                });
                at += 2;
            }
            if terms.is_empty() {
                return Err(DbError::Corrupt("Indexdefinition: keine Terme"));
            }
            let included_count: usize = fields
                .get(at)
                .ok_or(DbError::Corrupt("Indexdefinition: INCLUDE"))?
                .parse()
                .map_err(|_| DbError::Corrupt("Indexdefinition: INCLUDE"))?;
            at += 1;
            let mut included = Vec::with_capacity(included_count);
            for _ in 0..included_count {
                included.push(
                    fields
                        .get(at)
                        .filter(|column| valid_name(column))
                        .ok_or(DbError::Corrupt("Indexdefinition: INCLUDE-Spalte"))?
                        .clone(),
                );
                at += 1;
            }
            let predicate = match fields.get(at).map(String::as_str) {
                Some("-") if at + 1 == fields.len() => None,
                Some("Z") if at + 2 == fields.len() => {
                    Some(crate::IndexPredicate::IsNotNull(fields[at + 1].clone()))
                }
                Some("E") if at + 3 == fields.len() => Some(crate::IndexPredicate::Equals {
                    column: fields[at + 1].clone(),
                    value: fields[at + 2].clone(),
                }),
                _ => return Err(DbError::Corrupt("Indexdefinition: Prädikat")),
            };
            if terms
                .iter()
                .any(|term| !cols.iter().any(|c| c.name == term.column()))
                || included
                    .iter()
                    .any(|column| !cols.iter().any(|c| &c.name == column))
                || predicate
                    .as_ref()
                    .map_or(false, |predicate| match predicate {
                        crate::IndexPredicate::Equals { column, .. }
                        | crate::IndexPredicate::IsNotNull(column) => {
                            !cols.iter().any(|c| &c.name == column)
                        }
                    })
            {
                return Err(DbError::Corrupt("Indexdefinition: unbekannte Spalte"));
            }
            indexes.push(IndexDefinition {
                name: index_name,
                terms,
                included,
                predicate,
            });
            continue;
        }
        if !matches!(tag, "NN" | "UQ" | "IX" | "CK" | "FK") {
            continue;
        }
        let f = split_fields(rest);
        let Some(ci) = f
            .first()
            .and_then(|n| cols.iter().position(|c| &c.name == n))
        else {
            continue;
        };
        match tag {
            "NN" => cols[ci].not_null = true,
            "UQ" => cols[ci].unique = true,
            "IX" => cols[ci].indexed = true,
            "CK" => {
                if let Some(c) = Check::decode(&f[1..]) {
                    cols[ci].checks.push(c);
                }
            }
            "FK" if f.len() >= 4 => {
                cols[ci].fk = Some(ForeignKey {
                    table: f[1].clone(),
                    column: f[2].clone(),
                    on_delete: if f[3] == "cascade" {
                        OnDelete::Cascade
                    } else {
                        OnDelete::Restrict
                    },
                })
            }
            _ => {}
        }
    }
    Ok((cols, indexes))
}

// ───────────── Store ─────────────

pub(crate) struct Store {
    pub(crate) dir: PathBuf,
    x: XChaCha20Poly1305,
    legacy: ChaCha20Poly1305,
    cache: Mutex<HashMap<String, (String, Arc<TableData>)>>,
    metas: Mutex<HashMap<String, Arc<Vec<ColDef>>>>,
    cache_on: AtomicBool,
    sync: AtomicBool,
    busy_ms: AtomicU64,
    writer_busy: AtomicBool,
    temp: bool,
}

impl Drop for Store {
    fn drop(&mut self) {
        if self.temp {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
}

pub(crate) struct WriterGuard {
    store: Arc<Store>,
    file: File,
}

impl Drop for WriterGuard {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
        self.store.writer_busy.store(false, AO::Release);
    }
}

fn load_or_create_key(dir: &Path) -> Result<Key> {
    let path = dir.join(".key");
    let read_existing = |bytes: Vec<u8>| -> Result<Key> {
        if bytes.len() == KEY_LEN {
            Ok(*Key::from_slice(&bytes))
        } else {
            Err(DbError::Corrupt("Schlüsseldatei beschädigt"))
        }
    };
    match fs::read(&path) {
        Ok(bytes) => read_existing(bytes),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let key = ChaCha20Poly1305::generate_key(&mut OsRng);
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            match opts.open(&path) {
                Ok(mut f) => {
                    f.write_all(&key)?;
                    f.sync_all()?;
                    Ok(key)
                }
                // Anderer Prozess war schneller → dessen Schlüssel verwenden.
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    // Der Gewinner schreibt evtl. noch – kurz warten.
                    for _ in 0..50 {
                        let b = fs::read(&path)?;
                        if b.len() == KEY_LEN {
                            return read_existing(b);
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    read_existing(fs::read(&path)?)
                }
                Err(e) => Err(e.into()),
            }
        }
        Err(e) => Err(e.into()),
    }
}

fn chunk_aad(name: &str, last: bool) -> Vec<u8> {
    let mut a = Vec::with_capacity(name.len() + 8);
    a.extend_from_slice(b"DBC3\0");
    a.extend_from_slice(name.as_bytes());
    a.push(0);
    a.push(last as u8);
    a
}

fn chunk_nonce(prefix: &[u8; PREFIX_LEN], idx: u32) -> [u8; X_NONCE_LEN] {
    let mut n = [0u8; X_NONCE_LEN];
    n[..PREFIX_LEN].copy_from_slice(prefix);
    n[PREFIX_LEN..].copy_from_slice(&idx.to_be_bytes());
    n
}

/// Windows meldet kurzzeitige Sperren (Datei wird gerade ersetzt/gelöscht, Virenscanner, …)
/// als „Zugriff verweigert“ (5) bzw. „Sharing-/Lock-Verletzung“ (32/33).
fn transient(e: &io::Error) -> bool {
    cfg!(windows)
        && (e.kind() == io::ErrorKind::PermissionDenied
            || matches!(e.raw_os_error(), Some(5) | Some(32) | Some(33)))
}

/// Datei ist weg *oder* (Windows) im „Löschen ausstehend“-Zustand → Leser nehmen den neuen Stand.
pub(crate) fn vanished(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::NotFound || transient(e)
}

/// Wiederholt eine I/O-Operation bei kurzzeitigen Windows-Sperren (bis ca. 3 s).
fn retry_io<T>(mut f: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let mut i = 0u64;
    loop {
        match f() {
            Err(e) if transient(&e) && i < 150 => {
                std::thread::sleep(Duration::from_millis((1 + i).min(20)));
                i += 1;
            }
            r => return r,
        }
    }
}

pub(crate) fn is_not_found(e: &DbError) -> bool {
    matches!(e, DbError::Io(io) if vanished(io))
}

#[cfg(test)]
pub(crate) fn crash_point(name: &str) {
    if std::env::var("DBCORE_CRASH_AT").as_deref() == Ok(name) {
        std::process::abort();
    }
}

#[cfg(not(test))]
pub(crate) fn crash_point(_: &str) {}

impl Store {
    pub(crate) fn open(dir: PathBuf, temp: bool) -> Result<Arc<Store>> {
        fs::create_dir_all(&dir)?;
        let key = load_or_create_key(&dir)?;
        let store = Arc::new(Store {
            dir,
            x: XChaCha20Poly1305::new(&key),
            legacy: ChaCha20Poly1305::new(&key),
            cache: Mutex::new(HashMap::new()),
            metas: Mutex::new(HashMap::new()),
            cache_on: AtomicBool::new(true),
            sync: AtomicBool::new(true),
            busy_ms: AtomicU64::new(10_000),
            writer_busy: AtomicBool::new(false),
            temp,
        });
        store.maintain()?;
        Ok(store)
    }

    pub(crate) fn set_busy_timeout(&self, d: Duration) {
        self.busy_ms.store(d.as_millis() as u64, AO::Relaxed);
    }
    pub(crate) fn set_sync(&self, on: bool) {
        self.sync.store(on, AO::Relaxed);
    }
    pub(crate) fn set_cache(&self, on: bool) {
        self.cache_on.store(on, AO::Relaxed);
        if !on {
            self.clear_cache();
        }
    }
    pub(crate) fn clear_cache(&self) {
        self.cache.lock().unwrap_or_else(|p| p.into_inner()).clear();
        self.metas.lock().unwrap_or_else(|p| p.into_inner()).clear();
    }
    fn do_sync(&self) -> bool {
        self.sync.load(AO::Relaxed)
    }
    pub(crate) fn path(&self, fname: &str) -> PathBuf {
        self.dir.join(fname)
    }

    pub(crate) fn backup_to(self: &Arc<Self>, destination: &Path) -> Result<()> {
        let snapshot = self.snapshot_pinned()?;
        self.backup_snapshot_to(&snapshot, destination)
    }

    fn backup_snapshot_to(&self, snapshot: &Snapshot, destination: &Path) -> Result<()> {
        let staging = StagingDir::create(destination)?;
        fs::copy(self.dir.join(".key"), staging.path.join(".key"))?;
        self.write_snapshot_manifest(&staging.path, &snapshot.manifest)?;
        for (name, fname) in &snapshot.manifest.tables {
            snapshot.copy_table_file(name, &staging.path.join(fname))?;
        }
        self.write_backup_info(
            &staging.path,
            &BackupInfo {
                id: backup_id(),
                parent: None,
                kind: BackupKind::Full,
            },
        )?;
        staging.publish(destination)
    }

    pub(crate) fn backup_incremental_to(
        self: &Arc<Self>,
        previous: &Path,
        destination: &Path,
    ) -> Result<()> {
        let (previous_store, previous_info) = Self::open_backup(previous)?;
        if fs::read(self.dir.join(".key"))? != fs::read(previous.join(".key"))? {
            return Err(DbError::Crypto(
                "Inkrementelles Backup gehört zu einer anderen Datenbank",
            ));
        }
        let previous_manifest = previous_store.read_manifest()?;
        let snapshot = self.snapshot_pinned()?;
        let staging = StagingDir::create(destination)?;
        fs::copy(self.dir.join(".key"), staging.path.join(".key"))?;
        self.write_snapshot_manifest(&staging.path, &snapshot.manifest)?;
        for (name, fname) in &snapshot.manifest.tables {
            if previous_manifest.tables.get(name) != Some(fname) {
                snapshot.copy_table_file(name, &staging.path.join(fname))?;
            }
        }
        self.write_backup_info(
            &staging.path,
            &BackupInfo {
                id: backup_id(),
                parent: Some(previous_info.id),
                kind: BackupKind::Incremental,
            },
        )?;
        staging.publish(destination)
    }

    fn write_snapshot_manifest(&self, dir: &Path, manifest: &Manifest) -> Result<()> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = self
            .x
            .encrypt(
                &nonce,
                Payload {
                    msg: manifest.encode().as_bytes(),
                    aad: b"DBC3-MANIFEST",
                },
            )
            .map_err(|_| DbError::Crypto("Manifest: Verschlüsselung fehlgeschlagen"))?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(MANIFEST))?;
        file.write_all(MAGIC_MANIFEST)?;
        file.write_all(&nonce)?;
        file.write_all(&ct)?;
        if self.do_sync() {
            file.sync_all()?;
        }
        Ok(())
    }

    fn write_backup_info(&self, dir: &Path, info: &BackupInfo) -> Result<()> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = self
            .x
            .encrypt(
                &nonce,
                Payload {
                    msg: info.encode().as_bytes(),
                    aad: b"DBC3-BACKUP",
                },
            )
            .map_err(|_| DbError::Crypto("Backup-Metadaten: Verschlüsselung fehlgeschlagen"))?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(BACKUP))?;
        file.write_all(MAGIC_BACKUP)?;
        file.write_all(&nonce)?;
        file.write_all(&ct)?;
        if self.do_sync() {
            file.sync_all()?;
        }
        Ok(())
    }

    fn open_backup(path: &Path) -> Result<(Arc<Store>, BackupInfo)> {
        let store = Self::open(path.to_path_buf(), false)?;
        let raw = fs::read(path.join(BACKUP))?;
        if raw.len() < 4 + X_NONCE_LEN + TAG_LEN || &raw[..4] != MAGIC_BACKUP {
            return Err(DbError::Corrupt(
                "Backup-Metadaten beschädigt oder unvollständig",
            ));
        }
        let (nonce, ct) = raw[4..].split_at(X_NONCE_LEN);
        let plain = store
            .x
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: b"DBC3-BACKUP",
                },
            )
            .map_err(|_| DbError::Crypto("Backup-Metadaten: Authentifizierung fehlgeschlagen"))?;
        let text =
            String::from_utf8(plain).map_err(|_| DbError::Corrupt("Backup-Metadaten: UTF-8"))?;
        let info = BackupInfo::decode(&text)?;
        Ok((store, info))
    }

    pub(crate) fn verify_backup(path: &Path) -> Result<Vec<String>> {
        let (store, info) = Self::open_backup(path)?;
        if info.kind != BackupKind::Full {
            return Err(DbError::Unsupported(
                "Ein inkrementelles Backup muss mit seiner Backup-Kette geprüft werden".into(),
            ));
        }
        store.integrity_check()
    }

    pub(crate) fn verify_backup_chain(base: &Path, increments: &[PathBuf]) -> Result<Vec<String>> {
        let temp = std::env::temp_dir().join(format!(
            "dbcore-verify-{}-{}",
            std::process::id(),
            backup_id()
        ));
        let staging = StagingDir::create(&temp)?;
        Self::apply_backup_chain(base, increments, &staging.path)?;
        let store = Self::open(staging.path.clone(), false)?;
        store.integrity_check()
    }

    pub(crate) fn restore_from(
        base: &Path,
        increments: &[PathBuf],
        destination: &Path,
    ) -> Result<()> {
        let staging = StagingDir::create(destination)?;
        Self::apply_backup_chain(base, increments, &staging.path)?;
        let restored = Self::open(staging.path.clone(), false)?;
        let problems = restored.integrity_check()?;
        if !problems.is_empty() {
            return Err(DbError::BackupIntegrity(problems));
        }
        staging.publish(destination)
    }

    fn apply_backup_chain(base: &Path, increments: &[PathBuf], destination: &Path) -> Result<()> {
        let (base_store, base_info) = Self::open_backup(base)?;
        if base_info.kind != BackupKind::Full {
            return Err(DbError::Corrupt(
                "Backup-Kette muss mit einem Vollbackup beginnen",
            ));
        }
        let mut current_manifest = base_store.read_manifest()?;
        fs::copy(base.join(".key"), destination.join(".key"))?;
        fs::copy(base.join(MANIFEST), destination.join(MANIFEST))?;
        for fname in current_manifest.tables.values() {
            fs::copy(base.join(fname), destination.join(fname))?;
        }
        fs::copy(base.join(BACKUP), destination.join(BACKUP))?;
        let mut parent_id = base_info.id;
        for increment in increments {
            let (increment_store, info) = Self::open_backup(increment)?;
            if info.kind != BackupKind::Incremental || info.parent.as_deref() != Some(&parent_id) {
                return Err(DbError::Corrupt(
                    "Inkrementelles Backup passt nicht zur Backup-Kette",
                ));
            }
            if fs::read(base.join(".key"))? != fs::read(increment.join(".key"))? {
                return Err(DbError::Crypto(
                    "Backup-Kette verwendet unterschiedliche Schlüssel",
                ));
            }
            let next_manifest = increment_store.read_manifest()?;
            for (name, fname) in &next_manifest.tables {
                if current_manifest.tables.get(name) != Some(fname) {
                    fs::copy(increment.join(fname), destination.join(fname))?;
                }
            }
            fs::copy(increment.join(MANIFEST), destination.join(MANIFEST))?;
            fs::copy(increment.join(BACKUP), destination.join(BACKUP))?;
            current_manifest = next_manifest;
            parent_id = info.id;
        }
        Ok(())
    }

    /// Entfernt Tabellenversionen, die kein aktuelles Manifest mehr referenziert.
    /// Offene Snapshot-Handles halten Versionen auf Plattformen mit Dateisperren
    /// bis zu einem späteren Lauf dieser Bereinigung am Leben.
    pub(crate) fn gc_versions(&self, manifest: &Manifest) -> Result<()> {
        let referenced: BTreeSet<&str> = manifest.tables.values().map(String::as_str).collect();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let fname = entry.file_name();
            let fname = fname.to_string_lossy();
            if fname.ends_with(".tbl") && !referenced.contains(fname.as_ref()) {
                match fs::remove_file(entry.path()) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound || transient(&e) => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Ok(())
    }

    // ───── Locks ─────

    pub(crate) fn acquire_writer(self: &Arc<Self>) -> Result<WriterGuard> {
        self.acquire_writer_for(Duration::from_millis(self.busy_ms.load(AO::Relaxed)))
    }

    fn acquire_writer_for(self: &Arc<Self>, timeout: Duration) -> Result<WriterGuard> {
        let deadline = Instant::now() + timeout;
        let mut nap = Duration::from_micros(200);
        let step = |nap: &mut Duration| {
            std::thread::sleep(*nap);
            *nap = (*nap * 2).min(Duration::from_millis(20));
        };
        // 1) In-Prozess: nur ein Schreiber-Thread zur Zeit.
        while self
            .writer_busy
            .compare_exchange(false, true, AO::Acquire, AO::Relaxed)
            .is_err()
        {
            if Instant::now() >= deadline {
                return Err(DbError::Busy);
            }
            step(&mut nap);
        }
        // 2) Zwischen Prozessen: OS-Datei-Lock (wird bei Absturz automatisch frei).
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(self.dir.join(".writer.lock"))
        {
            Ok(f) => f,
            Err(e) => {
                self.writer_busy.store(false, AO::Release);
                return Err(e.into());
            }
        };
        loop {
            match fs2::FileExt::try_lock_exclusive(&file) {
                Ok(()) => {
                    return Ok(WriterGuard {
                        store: Arc::clone(self),
                        file,
                    })
                }
                Err(e) => {
                    let contended = e.kind() == io::ErrorKind::WouldBlock
                        || e.raw_os_error() == fs2::lock_contended_error().raw_os_error();
                    if !contended {
                        self.writer_busy.store(false, AO::Release);
                        return Err(e.into());
                    }
                    if Instant::now() >= deadline {
                        self.writer_busy.store(false, AO::Release);
                        return Err(DbError::Busy);
                    }
                    step(&mut nap);
                }
            }
        }
    }

    // ───── Wartung beim Öffnen ─────

    fn maintain(self: &Arc<Self>) -> Result<()> {
        let guard = self.acquire_writer_for(Duration::from_secs(10))?;
        self.maintain_locked()?;
        drop(guard);
        Ok(())
    }

    /// Unter Schreib-Lock: WAL wiederholen, alte `*.db` übernehmen, Crash-Reste löschen.
    fn maintain_locked(self: &Arc<Self>) -> Result<()> {
        self.recover_wal_locked()?;
        let mpath = self.dir.join(MANIFEST);
        let mut m = self.read_manifest()?;
        if !mpath.exists() {
            let mut adopted = false;
            for e in fs::read_dir(&self.dir)?.flatten() {
                let fname = e.file_name().to_string_lossy().to_string();
                if let Some(stem) = fname.strip_suffix(".db") {
                    if valid_name(stem) && e.path().is_file() {
                        m.tables.insert(stem.to_string(), fname.clone());
                        adopted = true;
                    }
                }
            }
            if adopted {
                m.seq = 1;
                self.write_manifest(&m)?;
            }
        }
        let referenced: BTreeSet<&String> = m.tables.values().collect();
        for e in fs::read_dir(&self.dir)?.flatten() {
            let fname = e.file_name().to_string_lossy().to_string();
            if fname.ends_with(".tmp") || (fname.ends_with(".tbl") && !referenced.contains(&fname))
            {
                let _ = fs::remove_file(e.path());
            }
        }
        Ok(())
    }

    // ───── Manifest ─────

    /// Schreibt den Redo-Eintrag, bevor ein Commit im Manifest sichtbar wird.
    pub(crate) fn write_wal(&self, m: &Manifest) -> Result<()> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = self
            .x
            .encrypt(
                &nonce,
                Payload {
                    msg: m.encode().as_bytes(),
                    aad: b"DBC3-WAL",
                },
            )
            .map_err(|_| DbError::Crypto("WAL: Verschlüsselung fehlgeschlagen"))?;
        let tmp = self.dir.join("WAL.tmp");
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(MAGIC_WAL)?;
            f.write_all(&nonce)?;
            f.write_all(&ct)?;
            if self.do_sync() {
                f.sync_all()?;
            }
        }
        retry_io(|| fs::rename(&tmp, self.dir.join(WAL)))?;
        self.sync_dir();
        Ok(())
    }

    /// Spielt ein dauerhaftes WAL genau einmal ein. Muss unter dem Writer-Lock laufen.
    pub(crate) fn recover_wal_locked(self: &Arc<Self>) -> Result<()> {
        let raw = match retry_io(|| fs::read(self.dir.join(WAL))) {
            Ok(raw) => raw,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        if raw.len() < 4 + X_NONCE_LEN + TAG_LEN || &raw[..4] != MAGIC_WAL {
            return Err(DbError::Corrupt("WAL beschädigt oder unvollständig"));
        }
        let (nonce, ct) = raw[4..].split_at(X_NONCE_LEN);
        let plain = self
            .x
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: b"DBC3-WAL",
                },
            )
            .map_err(|_| DbError::Crypto("WAL: Entschlüsselung fehlgeschlagen"))?;
        let text = String::from_utf8(plain).map_err(|_| DbError::Corrupt("WAL: UTF-8"))?;
        let next = Manifest::decode(&text)?;
        let current = self.read_manifest()?;

        if next.seq <= current.seq {
            self.checkpoint_wal()?;
            return Ok(());
        }
        if current.seq.checked_add(1) != Some(next.seq) {
            return Err(DbError::Corrupt("WAL-Sequenz passt nicht zum Manifest"));
        }

        for (name, fname) in &next.tables {
            if current.tables.get(name) != Some(fname) {
                self.read_file(fname, name)?;
            }
        }
        self.write_manifest(&next)?;
        self.checkpoint_wal()
    }

    /// Entfernt ein bereits im Manifest festgeschriebenes WAL (Checkpoint).
    pub(crate) fn checkpoint_wal(&self) -> Result<()> {
        match fs::remove_file(self.dir.join(WAL)) {
            Ok(()) => self.sync_dir(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }

    /// Erstellt einen konsistenten Checkpoint und bereinigt ausstehende WAL-Arbeit.
    pub(crate) fn checkpoint(self: &Arc<Self>) -> Result<()> {
        let _guard = self.acquire_writer()?;
        self.recover_wal_locked()?;
        self.checkpoint_wal()
    }

    pub(crate) fn read_manifest(&self) -> Result<Manifest> {
        let raw = match retry_io(|| fs::read(self.dir.join(MANIFEST))) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Manifest::default()),
            Err(e) => return Err(e.into()),
        };
        if raw.len() < 4 + X_NONCE_LEN + TAG_LEN || &raw[..4] != MAGIC_MANIFEST {
            return Err(DbError::Corrupt("Manifest beschädigt"));
        }
        let (nonce, ct) = raw[4..].split_at(X_NONCE_LEN);
        let plain = self
            .x
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: b"DBC3-MANIFEST",
                },
            )
            .map_err(|_| DbError::Crypto("Manifest: Entschlüsselung fehlgeschlagen"))?;
        let text = String::from_utf8(plain).map_err(|_| DbError::Corrupt("Manifest: UTF-8"))?;
        Manifest::decode(&text)
    }

    pub(crate) fn write_manifest(&self, m: &Manifest) -> Result<()> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = self
            .x
            .encrypt(
                &nonce,
                Payload {
                    msg: m.encode().as_bytes(),
                    aad: b"DBC3-MANIFEST",
                },
            )
            .map_err(|_| DbError::Crypto("Manifest: Verschlüsselung fehlgeschlagen"))?;
        let tmp = self.dir.join("MANIFEST.tmp");
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(MAGIC_MANIFEST)?;
            f.write_all(&nonce)?;
            f.write_all(&ct)?;
            if self.do_sync() {
                f.sync_all()?;
            }
        }
        retry_io(|| fs::rename(&tmp, self.dir.join(MANIFEST)))?;
        self.sync_dir();
        Ok(())
    }

    pub(crate) fn sync_dir(&self) {
        if self.do_sync() {
            if let Ok(f) = File::open(&self.dir) {
                let _ = f.sync_all();
            }
        }
    }

    // ───── Tabellendatei schreiben ─────

    /// Schreibt eine neue, unveränderliche Tabellendatei und liefert ihren Namen.
    pub(crate) fn write_table_file(
        &self,
        name: &str,
        schema: &[ColDef],
        rows: &[Vec<String>],
        indexes: &[IndexDefinition],
        seq: u64,
    ) -> Result<String> {
        let fname = format!("{name}.{seq:016x}.tbl");
        let path = self.dir.join(&fname);
        let mut prefix = [0u8; PREFIX_LEN];
        OsRng.fill_bytes(&mut prefix);
        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        let mut w = BufWriter::with_capacity(128 * 1024, f);
        w.write_all(MAGIC_TABLE)?;
        w.write_all(&prefix)?;
        let mut cw = ChunkWriter {
            x: &self.x,
            w: &mut w,
            name,
            prefix,
            idx: 0,
            pending: None,
        };
        cw.push(header_text(name, schema, indexes).into_bytes())?;
        let mut buf = String::new();
        let mut n = 0usize;
        for r in rows {
            buf.push_str("ROW:");
            for (i, v) in r.iter().enumerate() {
                if i > 0 {
                    buf.push(';');
                }
                escape_cell(v, &mut buf);
            }
            buf.push('\n');
            n += 1;
            if n >= ROWS_PER_CHUNK || buf.len() >= CHUNK_BYTES {
                cw.push(std::mem::take(&mut buf).into_bytes())?;
                n = 0;
            }
        }
        if n > 0 {
            cw.push(buf.into_bytes())?;
        }
        cw.finish()?;
        w.flush()?;
        let f = w.into_inner().map_err(|e| DbError::Io(e.into_error()))?;
        if self.do_sync() {
            f.sync_all()?;
        }
        Ok(fname)
    }

    // ───── Tabellendatei lesen ─────

    fn read_legacy_bytes(&self, raw: &[u8], name: &str) -> Result<TableData> {
        if raw.len() < LEGACY_NONCE_LEN + TAG_LEN {
            return Err(DbError::Corrupt("Datei zu kurz"));
        }
        let (nonce, ct) = raw.split_at(LEGACY_NONCE_LEN);
        let plain = self
            .legacy
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: name.as_bytes(),
                },
            )
            .map_err(|_| DbError::Crypto("Entschlüsselung fehlgeschlagen"))?;
        let text = String::from_utf8(plain).map_err(|_| DbError::Corrupt("kein gültiges UTF-8"))?;
        let (schema, indexes) = parse_header(&text, name)?;
        let (_h, mut rows) = split_rows(&text);
        for r in rows.iter_mut() {
            r.resize(schema.len(), NULL_CELL.to_string());
            for v in r {
                if v.is_empty() {
                    *v = NULL_CELL.to_string();
                }
            }
        }
        Ok(TableData::new(name.to_string(), schema, rows).with_indexes(indexes))
    }

    fn open_chunks(self: &Arc<Self>, br: &mut BufReader<File>, name: &str) -> Result<ChunkReader> {
        let mut magic = [0u8; 4];
        br.read_exact(&mut magic)
            .map_err(|_| DbError::Corrupt("Datei zu kurz"))?;
        if &magic != MAGIC_TABLE {
            return Err(DbError::Corrupt("falsche Kennung"));
        }
        let mut prefix = [0u8; PREFIX_LEN];
        br.read_exact(&mut prefix)
            .map_err(|_| DbError::Corrupt("Datei zu kurz"))?;
        Ok(ChunkReader {
            store: Arc::clone(self),
            name: name.to_string(),
            prefix,
            idx: 0,
            done: false,
        })
    }

    fn read_v3(self: &Arc<Self>, file: File, name: &str) -> Result<TableData> {
        let mut br = BufReader::with_capacity(128 * 1024, file);
        let mut cr = self.open_chunks(&mut br, name)?;
        let head = cr.next(&mut br)?.ok_or(DbError::Corrupt("Kopf fehlt"))?;
        let header = String::from_utf8(head).map_err(|_| DbError::Corrupt("UTF-8"))?;
        let legacy_nulls = !header.lines().any(|l| l == "FORMAT:4");
        let (schema, indexes) = parse_header(&header, name)?;
        let mut rows = Vec::new();
        while let Some(chunk) = cr.next(&mut br)? {
            parse_rows_chunk(&chunk, schema.len(), legacy_nulls, &mut rows)?;
        }
        Ok(TableData::new(name.to_string(), schema, rows).with_indexes(indexes))
    }

    /// Liest und prüft eine komplette Tabellendatei (v3, Fallback v1/v2).
    pub(crate) fn read_file(self: &Arc<Self>, fname: &str, name: &str) -> Result<TableData> {
        self.read_handle(File::open(self.dir.join(fname))?, name)
    }

    /// Wie `read_file`, aber von einem bereits offenen Handle (liest ab Dateianfang).
    pub(crate) fn read_handle(self: &Arc<Self>, mut f: File, name: &str) -> Result<TableData> {
        use std::io::{Seek, SeekFrom};
        f.seek(SeekFrom::Start(0))?;
        let mut magic = [0u8; 4];
        let is_v3 = f.read_exact(&mut magic).is_ok() && &magic == MAGIC_TABLE;
        f.seek(SeekFrom::Start(0))?;
        if is_v3 {
            let dup = f.try_clone()?;
            match self.read_v3(dup, name) {
                Ok(d) => return Ok(d),
                Err(e) => {
                    f.seek(SeekFrom::Start(0))?;
                    let mut raw = Vec::new();
                    f.read_to_end(&mut raw)?;
                    return self.read_legacy_bytes(&raw, name).map_err(|_| e);
                }
            }
        }
        let mut raw = Vec::new();
        f.read_to_end(&mut raw)?;
        self.read_legacy_bytes(&raw, name)
    }

    /// Nur das Schema (erster Block) – für Foreign-Key-Auflösung.
    pub(crate) fn schema_of(self: &Arc<Self>, name: &str, fname: &str) -> Result<Arc<Vec<ColDef>>> {
        if let Some((f, d)) = self
            .cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(name)
        {
            if f == fname {
                return Ok(Arc::new(d.schema.clone()));
            }
        }
        if let Some(m) = self
            .metas
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(fname)
        {
            return Ok(m.clone());
        }
        let path = self.dir.join(fname);
        let mut magic = [0u8; 4];
        let is_v3 = {
            let mut f = File::open(&path)?;
            f.read_exact(&mut magic).is_ok() && &magic == MAGIC_TABLE
        };
        let schema = if is_v3 {
            let mut br = BufReader::new(File::open(&path)?);
            let mut cr = self.open_chunks(&mut br, name)?;
            let head = cr.next_no_last_check(&mut br)?;
            parse_header(
                &String::from_utf8(head).map_err(|_| DbError::Corrupt("UTF-8"))?,
                name,
            )?
            .0
        } else {
            self.read_legacy_bytes(&fs::read(&path)?, name)?.schema
        };
        let arc = Arc::new(schema);
        self.metas
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(fname.to_string(), arc.clone());
        Ok(arc)
    }

    // ───── Cache ─────

    pub(crate) fn load_cached(self: &Arc<Self>, name: &str, fname: &str) -> Result<Arc<TableData>> {
        let on = self.cache_on.load(AO::Relaxed);
        if on {
            if let Some((f, d)) = self
                .cache
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(name)
            {
                if f == fname {
                    return Ok(d.clone());
                }
            }
        }
        let data = Arc::new(self.read_file(fname, name)?);
        if on {
            self.cache_put(name, fname, data.clone());
        }
        Ok(data)
    }

    pub(crate) fn cache_put(&self, name: &str, fname: &str, d: Arc<TableData>) {
        if self.cache_on.load(AO::Relaxed) {
            self.cache
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(name.to_string(), (fname.to_string(), d));
        }
    }
    pub(crate) fn cache_drop(&self, name: &str) {
        self.cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(name);
    }
    pub(crate) fn prune_metas(&self, m: &Manifest) {
        let keep: BTreeSet<&String> = m.tables.values().collect();
        self.metas
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|f, _| keep.contains(f));
    }
    pub(crate) fn cached(&self, name: &str, fname: &str) -> Option<Arc<TableData>> {
        let g = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        g.get(name)
            .filter(|(f, _)| f == fname)
            .map(|(_, d)| d.clone())
    }

    // ───── Snapshots ─────

    /// Leichter Snapshot (nur Manifest). Dateien werden bei Bedarf geöffnet; für
    /// interne, kurze Abfragen mit Wiederholung bei `SnapshotExpired`.
    pub(crate) fn snapshot(self: &Arc<Self>) -> Result<Snapshot> {
        let manifest = self.read_manifest()?;
        Ok(Snapshot {
            store: Arc::clone(self),
            manifest,
            loaded: Mutex::new(HashMap::new()),
            pins: None,
        })
    }

    /// Fester Snapshot: hält alle Tabellendateien offen. Damit bleibt er beliebig
    /// lange gültig, auch wenn Schreiber die Dateien inzwischen ersetzen und löschen.
    pub(crate) fn snapshot_pinned(self: &Arc<Self>) -> Result<Snapshot> {
        'retry: for _ in 0..64 {
            let manifest = self.read_manifest()?;
            let mut pins = HashMap::new();
            for (name, fname) in &manifest.tables {
                match File::open(self.dir.join(fname)) {
                    Ok(f) => {
                        pins.insert(name.clone(), Mutex::new(f));
                    }
                    Err(e) if vanished(&e) => {
                        std::thread::yield_now();
                        continue 'retry;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            return Ok(Snapshot {
                store: Arc::clone(self),
                manifest,
                loaded: Mutex::new(HashMap::new()),
                pins: Some(pins),
            });
        }
        Err(DbError::SnapshotExpired)
    }

    /// Führt `f` auf einem frischen Snapshot aus; bei „Datei inzwischen ersetzt“ erneut.
    pub(crate) fn with_snapshot<R>(
        self: &Arc<Self>,
        f: impl Fn(&Snapshot) -> Result<R>,
    ) -> Result<R> {
        let mut last = DbError::SnapshotExpired;
        for _ in 0..8 {
            let snap = self.snapshot()?;
            match f(&snap) {
                Err(DbError::SnapshotExpired) => {
                    last = DbError::SnapshotExpired;
                    continue;
                }
                other => return other,
            }
        }
        Err(last)
    }

    // ───── Integritätsprüfung ─────

    pub(crate) fn integrity_check(self: &Arc<Self>) -> Result<Vec<String>> {
        let mut problems = Vec::new();
        let m = self.read_manifest()?;
        let mut all: HashMap<String, TableData> = HashMap::new();
        for (name, fname) in &m.tables {
            match self.read_file(fname, name) {
                Ok(d) => {
                    all.insert(name.clone(), d);
                }
                Err(e) => problems.push(format!("Tabelle '{name}' ({fname}): {e}")),
            }
        }
        for (name, d) in &all {
            let mut seen: Vec<(usize, HashSet<String>)> = unique_cols(&d.schema)
                .into_iter()
                .map(|c| (c, HashSet::new()))
                .collect();
            for (rn, r) in d.rows.iter().enumerate() {
                for (i, c) in d.schema.iter().enumerate() {
                    if !is_null(r, i) {
                        if let Err(e) = validate_value(c, cell(r, i)) {
                            problems.push(format!("{name}[{rn}]: {e}"));
                        }
                    }
                }
                if let Err(e) = check_row_local(&d.schema, r) {
                    problems.push(format!("{name}[{rn}]: {e}"));
                }
                for (ci, set) in seen.iter_mut() {
                    let c = &d.schema[*ci];
                    let raw = cell(r, *ci);
                    if raw == NULL_CELL && !c.key && c.unique {
                        continue;
                    }
                    let v = norm_val(c.kind, raw);
                    if !set.insert(v.clone()) {
                        problems.push(format!(
                            "{name}[{rn}]: doppelter Wert '{v}' in eindeutiger Spalte '{}'",
                            c.name
                        ));
                    }
                }
                for (i, c) in d.schema.iter().enumerate() {
                    let Some(fk) = &c.fk else { continue };
                    let v = cell(r, i);
                    if v == NULL_CELL {
                        continue;
                    }
                    let ok = all
                        .get(&fk.table)
                        .and_then(|p| p.col(&fk.column).map(|pc| (p, pc)))
                        .map(|(p, pc)| {
                            let k = p.schema[pc].kind;
                            p.rows.iter().any(|pr| key_eq(k, cell(pr, pc), v))
                        })
                        .unwrap_or(false);
                    if !ok {
                        problems.push(format!(
                            "{name}[{rn}]: Foreign Key '{}'='{v}' zeigt ins Leere ({}.{})",
                            c.name, fk.table, fk.column
                        ));
                    }
                }
            }
        }
        // Verwaiste Dateien sind kein Fehler, aber erwähnenswert.
        Ok(problems)
    }
}

// ───────────── Blockweises Schreiben/Lesen ─────────────

struct ChunkWriter<'a, W: Write> {
    x: &'a XChaCha20Poly1305,
    w: &'a mut W,
    name: &'a str,
    prefix: [u8; PREFIX_LEN],
    idx: u32,
    pending: Option<Vec<u8>>,
}

impl<'a, W: Write> ChunkWriter<'a, W> {
    fn push(&mut self, plain: Vec<u8>) -> Result<()> {
        if let Some(prev) = self.pending.replace(plain) {
            self.emit(&prev, false)?;
        }
        Ok(())
    }
    fn finish(&mut self) -> Result<()> {
        let last = self.pending.take().ok_or(DbError::Corrupt("leere Datei"))?;
        self.emit(&last, true)
    }
    fn emit(&mut self, plain: &[u8], last: bool) -> Result<()> {
        let nonce = chunk_nonce(&self.prefix, self.idx);
        let ct = self
            .x
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plain,
                    aad: &chunk_aad(self.name, last),
                },
            )
            .map_err(|_| DbError::Crypto("Verschlüsselung fehlgeschlagen"))?;
        self.w.write_all(&(ct.len() as u32).to_le_bytes())?;
        self.w.write_all(&ct)?;
        self.idx = self
            .idx
            .checked_add(1)
            .ok_or(DbError::Corrupt("zu viele Blöcke"))?;
        Ok(())
    }
}

pub(crate) struct ChunkReader {
    store: Arc<Store>,
    name: String,
    prefix: [u8; PREFIX_LEN],
    idx: u32,
    done: bool,
}

impl ChunkReader {
    fn read_ct(&self, br: &mut BufReader<File>) -> Result<Vec<u8>> {
        let mut lenb = [0u8; 4];
        br.read_exact(&mut lenb)
            .map_err(|_| DbError::Corrupt("Datei abgeschnitten"))?;
        let len = u32::from_le_bytes(lenb) as usize;
        if len < TAG_LEN || len > MAX_CHUNK {
            return Err(DbError::Corrupt("ungültige Blockgröße"));
        }
        let mut ct = vec![0u8; len];
        br.read_exact(&mut ct)
            .map_err(|_| DbError::Corrupt("Datei abgeschnitten"))?;
        Ok(ct)
    }

    fn open_block(&self, ct: &[u8], last: bool) -> Result<Vec<u8>> {
        let nonce = chunk_nonce(&self.prefix, self.idx);
        self.store
            .x
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: ct,
                    aad: &chunk_aad(&self.name, last),
                },
            )
            .map_err(|_| {
                DbError::Crypto("Entschlüsselung fehlgeschlagen (Datei verändert oder beschädigt)")
            })
    }

    /// Nächster Block; `None` nach dem letzten. Erkennt Abschneiden/Anhängen über das Last-Flag.
    pub(crate) fn next(&mut self, br: &mut BufReader<File>) -> Result<Option<Vec<u8>>> {
        if self.done {
            return Ok(None);
        }
        let ct = self.read_ct(br)?;
        let last = br.fill_buf()?.is_empty();
        let pt = self.open_block(&ct, last)?;
        self.idx = self
            .idx
            .checked_add(1)
            .ok_or(DbError::Corrupt("zu viele Blöcke"))?;
        if last {
            self.done = true;
        }
        Ok(Some(pt))
    }

    /// Nur Block 0 lesen (Kopf), ohne den Rest der Datei zu prüfen.
    fn next_no_last_check(&mut self, br: &mut BufReader<File>) -> Result<Vec<u8>> {
        let ct = self.read_ct(br)?;
        let last = br.fill_buf()?.is_empty();
        self.open_block(&ct, last)
    }
}

fn parse_rows_chunk(
    chunk: &[u8],
    ncols: usize,
    legacy_nulls: bool,
    out: &mut Vec<Vec<String>>,
) -> Result<()> {
    let text = std::str::from_utf8(chunk).map_err(|_| DbError::Corrupt("kein gültiges UTF-8"))?;
    for line in text.split('\n') {
        if let Some(rest) = line.strip_prefix("ROW:") {
            let mut r = split_cells_v2(rest);
            r.resize(ncols, NULL_CELL.to_string());
            if legacy_nulls {
                for v in &mut r {
                    if v.is_empty() {
                        *v = NULL_CELL.to_string();
                    }
                }
            }
            out.push(r);
        }
    }
    Ok(())
}

// ───────────── Streaming-Scan ─────────────

pub(crate) enum ScanSrc {
    Mem(Arc<TableData>, usize),
    File {
        br: BufReader<File>,
        cr: ChunkReader,
        buf: VecDeque<Vec<String>>,
        legacy_nulls: bool,
    },
}

pub(crate) struct Scan {
    pub(crate) schema: Vec<ColDef>,
    src: ScanSrc,
}

impl Scan {
    pub(crate) fn next_row(&mut self) -> Result<Option<Vec<String>>> {
        match &mut self.src {
            ScanSrc::Mem(d, pos) => {
                let r = d.rows.get(*pos).cloned();
                if r.is_some() {
                    *pos += 1;
                }
                Ok(r)
            }
            ScanSrc::File {
                br,
                cr,
                buf,
                legacy_nulls,
            } => loop {
                if let Some(r) = buf.pop_front() {
                    return Ok(Some(r));
                }
                match cr.next(br)? {
                    None => return Ok(None),
                    Some(chunk) => {
                        let mut v = Vec::new();
                        parse_rows_chunk(&chunk, self.schema.len(), *legacy_nulls, &mut v)?;
                        buf.extend(v);
                    }
                }
            },
        }
    }
}

impl Store {
    /// Öffnet einen blockweisen Scan. Ist die Tabelle im Cache, wird von dort gelesen.
    pub(crate) fn open_scan(self: &Arc<Self>, snap: &Snapshot, name: &str) -> Result<Scan> {
        let fname = snap
            .manifest
            .tables
            .get(name)
            .ok_or_else(|| DbError::TableNotFound(name.to_string()))?;
        if snap.pins.is_some() {
            let d = snap.data(name)?;
            return Ok(Scan {
                schema: d.schema.clone(),
                src: ScanSrc::Mem(d, 0),
            });
        }
        if let Some(d) = self.cached(name, fname) {
            return Ok(Scan {
                schema: d.schema.clone(),
                src: ScanSrc::Mem(d, 0),
            });
        }
        let path = self.dir.join(fname);
        let mut magic = [0u8; 4];
        let is_v3 = {
            let mut f = File::open(&path).map_err(|e| snap_err(e))?;
            f.read_exact(&mut magic).is_ok() && &magic == MAGIC_TABLE
        };
        if !is_v3 {
            let d = Arc::new(self.read_file(fname, name)?);
            return Ok(Scan {
                schema: d.schema.clone(),
                src: ScanSrc::Mem(d, 0),
            });
        }
        let mut br =
            BufReader::with_capacity(128 * 1024, File::open(&path).map_err(|e| snap_err(e))?);
        let mut cr = self.open_chunks(&mut br, name)?;
        let head = cr.next(&mut br)?.ok_or(DbError::Corrupt("Kopf fehlt"))?;
        let header = String::from_utf8(head).map_err(|_| DbError::Corrupt("UTF-8"))?;
        let legacy_nulls = !header.lines().any(|l| l == "FORMAT:4");
        let (schema, _) = parse_header(&header, name)?;
        Ok(Scan {
            schema,
            src: ScanSrc::File {
                br,
                cr,
                buf: VecDeque::new(),
                legacy_nulls,
            },
        })
    }
}

fn snap_err(e: io::Error) -> DbError {
    if vanished(&e) {
        DbError::SnapshotExpired
    } else {
        DbError::Io(e)
    }
}

// ───────────── Snapshot ─────────────

/// Fester, konsistenter Lese-Stand der ganzen Datenbank.
///
/// Alle Abfragen über denselben Snapshot sehen exakt denselben Stand – auch
/// über mehrere Tabellen – egal, was Schreiber inzwischen committen. Ein mit
/// [`DBCore::snapshot`] erzeugter Snapshot hält seine Dateien offen und bleibt
/// deshalb beliebig lange gültig (kostet nur einen Datei-Handle pro Tabelle,
/// bis er gedroppt wird).
pub struct Snapshot {
    pub(crate) store: Arc<Store>,
    pub(crate) manifest: Manifest,
    loaded: Mutex<HashMap<String, Arc<TableData>>>,
    pins: Option<HashMap<String, Mutex<File>>>,
}

impl Snapshot {
    fn copy_table_file(&self, table: &str, destination: &Path) -> Result<()> {
        let pin = self
            .pins
            .as_ref()
            .and_then(|pins| pins.get(table))
            .ok_or(DbError::SnapshotExpired)?;
        let mut source = pin.lock().unwrap_or_else(|p| p.into_inner());
        source.seek(SeekFrom::Start(0))?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)?;
        std::io::copy(&mut *source, &mut output)?;
        if self.store.do_sync() {
            output.sync_all()?;
        }
        Ok(())
    }

    pub fn tables(&self) -> Vec<String> {
        self.manifest.tables.keys().cloned().collect()
    }
    pub fn has_table(&self, t: &str) -> bool {
        self.manifest.tables.contains_key(t)
    }
    pub fn user_version(&self) -> u32 {
        self.manifest.user_version
    }

    /// Abfrage auf diesem Snapshot.
    pub fn table<'a>(&'a self, name: &str) -> Table<'a> {
        Table::on_snapshot(self, name)
    }

    /// Erstellt ein konsistentes Online-Backup genau dieses Snapshots.
    pub fn backup_to(&self, destination: impl AsRef<Path>) -> DbResult<()> {
        self.store.backup_snapshot_to(self, destination.as_ref())
    }

    pub(crate) fn schema(&self, name: &str) -> Result<Arc<Vec<ColDef>>> {
        if !valid_name(name) {
            return Err(DbError::InvalidName);
        }
        if let Some(d) = self
            .loaded
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(name)
        {
            return Ok(Arc::new(d.schema.clone()));
        }
        let fname = self
            .manifest
            .tables
            .get(name)
            .ok_or_else(|| DbError::TableNotFound(name.to_string()))?;
        if let Some(data) = self.store.cached(name, fname) {
            return Ok(Arc::new(data.schema.clone()));
        }
        if let Some(schema) = self
            .store
            .metas
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(fname)
        {
            return Ok(schema.clone());
        }
        if let Some(pin) = self.pins.as_ref().and_then(|pins| pins.get(name)) {
            let file = pin.lock().unwrap_or_else(|p| p.into_inner());
            let mut reader = BufReader::new(file.try_clone()?);
            let mut chunks = self.store.open_chunks(&mut reader, name)?;
            let header = chunks.next_no_last_check(&mut reader)?;
            let (schema, _) = parse_header(
                &String::from_utf8(header).map_err(|_| DbError::Corrupt("UTF-8"))?,
                name,
            )?;
            let schema = Arc::new(schema);
            self.store
                .metas
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(fname.clone(), schema.clone());
            return Ok(schema);
        }
        self.store.schema_of(name, fname)
    }

    pub(crate) fn data(&self, name: &str) -> Result<Arc<TableData>> {
        if !valid_name(name) {
            return Err(DbError::InvalidName);
        }
        if let Some(d) = self
            .loaded
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(name)
        {
            return Ok(d.clone());
        }
        let fname = self
            .manifest
            .tables
            .get(name)
            .ok_or_else(|| DbError::TableNotFound(name.to_string()))?;
        let d = match self.pins.as_ref().and_then(|p| p.get(name)) {
            Some(pin) => match self.store.cached(name, fname) {
                Some(d) => d,
                None => {
                    // Gepinnt: aus dem offenen Handle lesen, nie aus dem (evtl. gelöschten) Pfad.
                    let f = pin.lock().unwrap_or_else(|p| p.into_inner());
                    let d = Arc::new(self.store.read_handle(f.try_clone()?, name)?);
                    self.store.cache_put(name, fname, d.clone());
                    d
                }
            },
            None => self.store.load_cached(name, fname).map_err(|e| {
                if is_not_found(&e) {
                    DbError::SnapshotExpired
                } else {
                    e
                }
            })?,
        };
        self.loaded
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(name.to_string(), d.clone());
        Ok(d)
    }

    pub(crate) fn get_row(&self, table: &str, key: &str) -> Result<Option<Vec<String>>> {
        let d = self.data(table)?;
        let ki = key_index(&d.schema).ok_or_else(|| {
            DbError::SchemaMismatch("get() braucht eine @key-Spalte im Schema".into())
        })?;
        let idx = d.index(ki);
        Ok(idx.get(key).first().map(|&p| d.rows[p].clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn test_dir(tag: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("dbcore-wal-{tag}-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn crash_child() {
        let Ok(dir) = std::env::var("DBCORE_CRASH_PATH") else {
            return;
        };
        let db = crate::DBCore::try_at(dir).unwrap();
        db.transaction(|tx| {
            tx.add("items", crate::row! { id: 2, value: "after" })?;
            Ok(())
        })
        .unwrap();
        panic!("crash injection point was not reached");
    }

    #[test]
    fn process_kill_recovers_each_commit_boundary() {
        for (stage, expected_rows) in [("after_tables", 1), ("after_wal", 2), ("after_manifest", 2)]
        {
            let dir = test_dir(stage);
            {
                let db = crate::DBCore::try_at(&dir).unwrap();
                db.create("items", crate::schema! { @key id: i32, value: String });
                db.add("items", crate::row! { id: 1, value: "before" });
            }

            let status = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("store::tests::crash_child")
                .arg("--nocapture")
                .env("DBCORE_CRASH_PATH", &dir)
                .env("DBCORE_CRASH_AT", stage)
                .status()
                .unwrap();
            assert!(!status.success(), "child should terminate at {stage}");

            let recovered = crate::DBCore::try_at(&dir).unwrap();
            assert_eq!(recovered.table("items").try_count().unwrap(), expected_rows);
            assert!(
                !dir.join(WAL).exists(),
                "WAL should be checkpointed after {stage}"
            );
            drop(recovered);
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn truncated_wal_is_reported_on_open() {
        let dir = test_dir("torn");
        let db = crate::DBCore::try_at(&dir).unwrap();
        let store = db.st().unwrap().clone();
        let mut next = store.read_manifest().unwrap();
        next.seq = 1;
        store.write_wal(&next).unwrap();
        let raw = fs::read(dir.join(WAL)).unwrap();
        fs::write(dir.join(WAL), &raw[..raw.len() - 1]).unwrap();
        drop(store);
        drop(db);

        assert!(matches!(
            crate::DBCore::try_at(&dir),
            Err(DbError::Crypto(_))
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn explicit_checkpoint_succeeds_without_pending_wal() {
        let dir = test_dir("checkpoint");
        let db = crate::DBCore::try_at(&dir).unwrap();
        db.checkpoint().unwrap();
        assert!(!db.path().join(WAL).exists());
        drop(db);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn committed_table_streams_without_cache() {
        let dir = test_dir("stream");
        let db = crate::DBCore::try_at(&dir).unwrap();
        db.set_sync(false);
        db.create("items", crate::schema! { @key id: i32, value: i32 });
        assert!(db.add_many(
            "items",
            (0..30_000)
                .map(|id| crate::row! { id: id, value: id % 10 })
                .collect()
        ));
        db.set_cache(false);
        assert_eq!(db.table("items").stream().unwrap().take(3).count(), 3);
        drop(db);
        fs::remove_dir_all(dir).unwrap();
    }
}
