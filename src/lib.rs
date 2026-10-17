//! # DBCore – eingebettete, verschlüsselte Datenbank mit Query-Builder
//!
//! Kleine Rust-Datenbank ohne SQL-Parser: Schema per Makro, Abfragen per
//! Builder, alles auf Platte mit ChaCha20-Poly1305 verschlüsselt und
//! authentifiziert. Seit Version 0.2 mit Transaktionen, Crash-Sicherheit,
//! Multi-Thread/Multi-Prozess-Zugriff, Indizes, Constraints und Joins.
//!
//! ## Schnellstart
//! ```no_run
//! use dbcore::{DBCore, schema, row, with};
//!
//! let db = DBCore::new("HI");                      // ./dbcore_data/HI
//! db.create_if_missing("users", schema! {
//!     @key id: i32,
//!     name: String,
//!     views: i64 = 0,
//! });
//! db.put("users", row! { id: 1, name: "Alice", views: 5 });
//! db.table("users")
//!     .filter(with!(r => r.get::<i64>("views").unwrap_or(0) > 0))
//!     .order_by("views").desc()
//!     .print();
//! ```
//!
//! Native parameter values preserve the difference between `NULL` and an
//! empty string:
//! ```no_run
//! use dbcore::{DBCore, Value, params, schema};
//! let db = DBCore::temp();
//! db.create("notes", schema! { @key id: i32, body: Option<String> });
//! db.try_add_values("notes", params! { id: 1, body: Value::Null }).unwrap();
//! assert_eq!(db.try_get_value("notes", "1", "body").unwrap(), Some(Value::Null));
//! ```
//! `Timestamp` zählt Mikrosekunden seit Unix-Epoch, `Date` Tage seit
//! 1970-01-01 und `Time` Mikrosekunden seit Mitternacht. `Decimal` speichert
//! einen exakten Koeffizienten mit separater Skala; `Json` wird syntaktisch
//! validiert und `Blob` als Bytes behandelt.
//!
//! Konstruktoren: [`DBCore::new`] (Name oder Pfad), [`DBCore::at`],
//! [`DBCore::under`], [`DBCore::temp`] (Wegwerf-DB für Tests) und die
//! `try_*`-Varianten mit echtem `Result`.
//!
//! ## 1. Transaktionen (ACID)
//! * **Atomar**: [`DBCore::begin`] / [`Tx::commit`] / [`Tx::rollback`] oder
//!   komfortabel [`DBCore::transaction`] (Commit bei `Ok`, Rollback bei `Err`
//!   oder Panic). Ein Commit über mehrere Tabellen ist *ein* atomarer Schritt.
//! * **Konsistent**: Constraints (Typ, `NOT NULL`, `UNIQUE`, `CHECK`,
//!   Foreign Keys) werden bei jeder Änderung geprüft, jede Anweisung ist
//!   für sich atomar.
//! * **Isoliert**: Leser und Schreiber arbeiten parallel auf unveränderlichen,
//!   gepinnten Snapshots. Beim Commit werden alle gelesenen und geänderten
//!   Tabellen optimistisch geprüft; widersprüchliche Änderungen liefern
//!   [`DbError::WriteConflict`] statt fremde Writes zu überschreiben.
//! * **Dauerhaft**: `fsync` von Datei *und* Verzeichnis (abschaltbar mit
//!   [`DBCore::set_sync`]).
//!
//! ```no_run
//! # use dbcore::{DBCore, row};
//! # let db = DBCore::temp();
//! db.transaction(|tx| {
//!     tx.update("accounts", "1", row! { balance: 90 })?;
//!     tx.update("accounts", "2", row! { balance: 110 })?;
//!     Ok(())                       // beides oder nichts
//! }).unwrap();
//! ```
//!
//! ## 2. Crash-Sicherheit
//! Jede Tabelle ist eine *unveränderliche* Datei (`name.<seq>.tbl`); ein
//! Commit schreibt neue Dateien, sichert den verschlüsselten Redo-Eintrag im
//! `WAL` und schaltet ihn danach mit **einem** atomaren `rename` der
//! `MANIFEST`-Datei scharf. Beim Öffnen wird ein vorhandenes WAL geprüft und
//! nötigenfalls wiederholt; nach dem Commit wird es automatisch checkpointed.
//! [`DBCore::checkpoint`] kann einen Checkpoint explizit erzwingen. Stirbt der
//! Prozess vor dem WAL, bleibt der alte Stand erhalten; ein abgerissenes oder
//! manipuliertes WAL wird als Fehler gemeldet. Jeder Block und das WAL sind
//! AEAD-authentifiziert (Schutz auch gegen Abschneiden/Umsortieren).
//! Nicht mehr referenzierte Tabellenversionen werden nach Commits eingesammelt;
//! offene Snapshots bleiben durch ihre Datei-Handles weiterhin lesbar.
//! Beschädigungen werden als [`DbError::Crypto`]/[`DbError::Corrupt`] gemeldet,
//! nie still geschluckt.
//! [`DBCore::integrity_check`] prüft die ganze Datenbank.
//!
//! ## 3. Nebenläufigkeit
//! * [`DBCore`] ist `Clone + Send + Sync` – einfach pro Thread klonen.
//! * **Beliebig viele Leser gleichzeitig** (Threads *und* Prozesse), ohne
//!   Sperren und ohne von Schreibern blockiert zu werden.
//! * **Mehrere Schreiber gleichzeitig**: Transaktionen starten ohne
//!   Schreib-Lock und bereiten Änderungen parallel vor. Nur der Commit wird
//!   kurz per Datei-Lock serialisiert. Änderungen an gelesenen/geänderten
//!   Tabellen seit dem Snapshot führen zu [`DbError::WriteConflict`];
//!   unabhängige Tabellen können parallel geändert werden. Wer beim Commit
//!   zu lange auf den Lock wartet, bekommt [`DbError::Busy`] (Standard 10 s,
//!   [`DBCore::set_busy_timeout`]).
//! * [`DBCore::snapshot`] liefert einen festen Stand über mehrere Tabellen.
//!
//! **Wichtig:** Innerhalb von `transaction(|tx| …)` immer `tx.…` benutzen,
//! nicht `db.…`: ein Aufruf über `db` läuft in einer unabhängigen Transaktion
//! und kann einen Konflikt mit der äußeren Transaktion auslösen.
//!
//! ## 4. Fehlerbehandlung
//! Alle Operationen haben eine `try_*`-Variante mit `Result<_, DbError>`.
//! Die Kurzformen ohne `try_` melden Fehler auf `stderr` und liefern einen
//! neutralen Wert (`false`, `0`, `""`, leerer `Vec`); sie paniken nie.
//! Für „leer“ vs. „Fehler“ gibt es `Option`-Varianten (`try_avg`, `try_min`, …).
//!
//! ## 5. Indizes
//! `db.create_index("users", "name")`, `create_unique_index`, `drop_index`.
//! Der Planer nutzt Indizes (und den `@key`) für `where_eq`, `where_in`,
//! Bereichs-Bedingungen und `order_by … limit`. `table.explain()` zeigt den Plan.
//! Hinweis: Der Index lebt im Speicher pro Tabellenstand (Aufbau einmalig
//! O(n log n) nach jeder Änderung); die Definition ist persistent.
//!
//! ## 6. Constraints
//! ```no_run
//! # use dbcore::*;
//! # let db = DBCore::temp();
//! db.create("posts", schema! { @key id: i32, title: String, author: i32, likes: i64 = 0 }
//!     .not_null(&["title"])
//!     .check("likes", Check::ge(0))
//!     .references("author", "users", "id", OnDelete::Cascade));
//! ```
//! `NOT NULL` weist den expliziten [`Value::Null`] zurück. Ein leerer Textwert
//! bleibt davon unterschieden; nullable Schemafelder können mit `Option<T>`
//! abgebildet werden.
//!
//! ## 7. Typen
//! * Beim Schreiben wird jeder Wert gegen den Spaltentyp geprüft.
//! * Zugriff nach Spaltenname: `r["name"]`, `r.get::<i64>("views")?`
//!   (im Filter via [`with!`]; die Position `r[2]` geht weiterhin).
//! * Eigene Structs mit [`model!`] ([`FromRow`] + [`Model`]):
//!   `db.table("users").try_collect_as::<User>()`.
//!
//! ## 8. Joins, Gruppierung, Mengen
//! `join` / `left_join`, `group_by` + [`Agg`], `having`, `distinct`, `union`,
//! `union_all`, Unterabfragen (`where_in_query`, `Table::from_query`).
//!
//! ## 9. Migrationen
//! `add_field`, `rename_field`, `remove_field`, `rename_table`,
//! `user_version` / `set_user_version` und [`DBCore::migrate`].
//!
//! ## 10. Lazy Iteration und Batches
//! `for row in db.table("t")` und [`Table::stream`] lesen Block für Block von
//! der Platte (ohne Sortierung/Gruppierung ohne Gesamtladen).
//! `put_many` / `add_many` schreiben beliebig viele Zeilen in **einem**
//! Commit (typisch 100× schneller als einzelne `put`).
//!
//! ## Opt-in via Import
//! * `use dbcore::interface;` – `db.open_interface(8080)` (Web-UI, blockiert)
//! * `use dbcore::csv;` / `html` / `json` – `db.to_csv(..)`, `db.export_csv(..)`
//!
//! ## Dateiformat / Migration alter Daten
//! Bestehende `*.db`-Dateien (v1/v2) werden beim ersten Öffnen automatisch
//! übernommen und beim nächsten Schreiben ins neue Format überführt.

use std::cmp::Ordering;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::ops::Index;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use std::{error, fmt};

mod format;
mod query;
mod store;
mod tx;
mod web;

pub(crate) use format::*;
pub(crate) use store::{Store, TableData};

pub use query::{Agg, Order, RowStream, Rows, Table};
pub use store::Snapshot;
pub use tx::Tx;

pub(crate) const BASE_DIR: &str = "dbcore_data";
/// Dateiformat der alten Tabellen (v2): Zellen werden escaped.
pub(crate) const FORMAT_LINE: &str = "FORMAT:2";

// ───────────── Spaltentypen ─────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnKind {
    Null,
    Int,
    Float,
    Text,
    Bool,
    Blob,
    Timestamp,
    Date,
    Time,
    Uuid,
    Json,
    Decimal,
}

impl ColumnKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ColumnKind::Null => "Null",
            ColumnKind::Int => "Int",
            ColumnKind::Float => "Float",
            ColumnKind::Text => "Text",
            ColumnKind::Bool => "Bool",
            ColumnKind::Blob => "Blob",
            ColumnKind::Timestamp => "Timestamp",
            ColumnKind::Date => "Date",
            ColumnKind::Time => "Time",
            ColumnKind::Uuid => "Uuid",
            ColumnKind::Json => "Json",
            ColumnKind::Decimal => "Decimal",
        }
    }
    pub(crate) fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "Null" => ColumnKind::Null,
            "Int" => ColumnKind::Int,
            "Float" => ColumnKind::Float,
            "Text" => ColumnKind::Text,
            "Bool" => ColumnKind::Bool,
            "Blob" => ColumnKind::Blob,
            "Timestamp" => ColumnKind::Timestamp,
            "Date" => ColumnKind::Date,
            "Time" => ColumnKind::Time,
            "Uuid" => ColumnKind::Uuid,
            "Json" => ColumnKind::Json,
            "Decimal" => ColumnKind::Decimal,
            _ => return None,
        })
    }
}

/// Natively typed value accepted by the typed parameter APIs.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Int(i128),
    Float(f64),
    Text(String),
    Bool(bool),
    Blob(Vec<u8>),
    Timestamp(i64),
    Date(i32),
    Time(i64),
    Uuid([u8; 16]),
    Json(String),
    Decimal { coefficient: i128, scale: u32 },
}

impl Value {
    pub fn kind(&self) -> ColumnKind {
        match self {
            Value::Null => ColumnKind::Null,
            Value::Int(_) => ColumnKind::Int,
            Value::Float(_) => ColumnKind::Float,
            Value::Text(_) => ColumnKind::Text,
            Value::Bool(_) => ColumnKind::Bool,
            Value::Blob(_) => ColumnKind::Blob,
            Value::Timestamp(_) => ColumnKind::Timestamp,
            Value::Date(_) => ColumnKind::Date,
            Value::Time(_) => ColumnKind::Time,
            Value::Uuid(_) => ColumnKind::Uuid,
            Value::Json(_) => ColumnKind::Json,
            Value::Decimal { .. } => ColumnKind::Decimal,
        }
    }

    fn as_input(&self) -> String {
        match self {
            Value::Null => NULL_CELL.to_string(),
            Value::Int(v) => v.to_string(),
            Value::Float(v) => v.to_string(),
            Value::Text(v) | Value::Json(v) => v.clone(),
            Value::Bool(v) => v.to_string(),
            Value::Blob(v) => hex_encode(v),
            Value::Timestamp(v) | Value::Time(v) => v.to_string(),
            Value::Date(v) => v.to_string(),
            Value::Uuid(v) => format_uuid(v),
            Value::Decimal { coefficient, scale } => decimal_text(*coefficient, *scale),
        }
    }
}

macro_rules! value_from {
    ($($ty:ty => $variant:ident),* $(,)?) => {$(
        impl From<$ty> for Value {
            fn from(value: $ty) -> Self { Value::$variant(value.into()) }
        }
    )*};
}
value_from! {
    i8 => Int, i16 => Int, i32 => Int, i64 => Int, i128 => Int,
    u8 => Int, u16 => Int, u32 => Int, u64 => Int,
    f32 => Float, f64 => Float,
    bool => Bool,
    String => Text,
    Vec<u8> => Blob,
}
impl From<isize> for Value {
    fn from(v: isize) -> Self {
        Value::Int(v as i128)
    }
}
impl From<usize> for Value {
    fn from(v: usize) -> Self {
        Value::Int(v as i128)
    }
}
impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::Text(v.to_string())
    }
}
impl From<&String> for Value {
    fn from(v: &String) -> Self {
        Value::Text(v.clone())
    }
}
impl From<&[u8]> for Value {
    fn from(v: &[u8]) -> Self {
        Value::Blob(v.to_vec())
    }
}
impl From<&Vec<u8>> for Value {
    fn from(v: &Vec<u8>) -> Self {
        Value::Blob(v.clone())
    }
}

macro_rules! value_from_ref {
    ($($ty:ty),* $(,)?) => {$(
        impl From<&$ty> for Value {
            fn from(v: &$ty) -> Self { Value::from(*v) }
        }
    )*};
}
value_from_ref!(i8, i16, i32, i64, i128, u8, u16, u32, u64, f32, f64, bool);
impl From<&isize> for Value {
    fn from(v: &isize) -> Self {
        Value::from(*v)
    }
}
impl From<&usize> for Value {
    fn from(v: &usize) -> Self {
        Value::from(*v)
    }
}
impl<T: Clone + Into<Value>> From<&Option<T>> for Value {
    fn from(v: &Option<T>) -> Self {
        v.as_ref().cloned().map(Into::into).unwrap_or(Value::Null)
    }
}
impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(v: Option<T>) -> Self {
        v.map(Into::into).unwrap_or(Value::Null)
    }
}
impl From<Blob> for Value {
    fn from(v: Blob) -> Self {
        Value::Blob(v.0)
    }
}
impl From<&Blob> for Value {
    fn from(v: &Blob) -> Self {
        Value::Blob(v.0.clone())
    }
}
impl From<Timestamp> for Value {
    fn from(v: Timestamp) -> Self {
        Value::Timestamp(v.0)
    }
}
impl From<Date> for Value {
    fn from(v: Date) -> Self {
        Value::Date(v.0)
    }
}
impl From<Time> for Value {
    fn from(v: Time) -> Self {
        Value::Time(v.0)
    }
}
impl From<Uuid> for Value {
    fn from(v: Uuid) -> Self {
        Value::Uuid(v.0)
    }
}
impl From<Json> for Value {
    fn from(v: Json) -> Self {
        Value::Json(v.0)
    }
}
impl From<&Json> for Value {
    fn from(v: &Json) -> Self {
        Value::Json(v.0.clone())
    }
}
impl From<Decimal> for Value {
    fn from(v: Decimal) -> Self {
        Value::Decimal {
            coefficient: v.coefficient,
            scale: v.scale,
        }
    }
}

const NULL_CELL: &str = "\u{0}";
const TEXT_ESCAPE: &str = "\u{0}\u{0}";

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn format_uuid(bytes: &[u8; 16]) -> String {
    let hex = hex_encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn decimal_text(coefficient: i128, scale: u32) -> String {
    if scale > 38 {
        return String::new();
    }
    let negative = coefficient < 0;
    let digits = coefficient.unsigned_abs().to_string();
    let scale = scale as usize;
    let mut out = if scale == 0 {
        digits
    } else if digits.len() <= scale {
        format!("0.{}{}", "0".repeat(scale - digits.len()), digits)
    } else {
        format!(
            "{}.{}",
            &digits[..digits.len() - scale],
            &digits[digits.len() - scale..]
        )
    };
    if negative {
        out.insert(0, '-');
    }
    out
}

/// Binary value marker type for [`schema!`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blob(pub Vec<u8>);
/// Unix-epoch timestamp in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp(pub i64);
/// Calendar day count relative to 1970-01-01.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Date(pub i32);
/// Microseconds since midnight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Time(pub i64);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uuid(pub [u8; 16]);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Json(pub String);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decimal {
    pub coefficient: i128,
    pub scale: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Null;

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if matches!(self, Value::Null) {
            f.write_str("NULL")
        } else {
            f.write_str(&self.as_input())
        }
    }
}

impl fmt::Display for Blob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex_encode(&self.0))
    }
}
impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format_uuid(&self.0))
    }
}
impl fmt::Display for Json {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl fmt::Display for Decimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&decimal_text(self.coefficient, self.scale))
    }
}

// ───────────── Constraints ─────────────

/// Vergleichsoperator für [`Check`] und die `where_*`-Bedingungen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl CmpOp {
    pub(crate) fn code(self) -> &'static str {
        match self {
            CmpOp::Eq => "eq",
            CmpOp::Ne => "ne",
            CmpOp::Lt => "lt",
            CmpOp::Le => "le",
            CmpOp::Gt => "gt",
            CmpOp::Ge => "ge",
        }
    }
    pub(crate) fn from_code(s: &str) -> Option<Self> {
        Some(match s {
            "eq" => CmpOp::Eq,
            "ne" => CmpOp::Ne,
            "lt" => CmpOp::Lt,
            "le" => CmpOp::Le,
            "gt" => CmpOp::Gt,
            "ge" => CmpOp::Ge,
            _ => return None,
        })
    }
    pub(crate) fn symbol(self) -> &'static str {
        match self {
            CmpOp::Eq => "=",
            CmpOp::Ne => "!=",
            CmpOp::Lt => "<",
            CmpOp::Le => "<=",
            CmpOp::Gt => ">",
            CmpOp::Ge => ">=",
        }
    }
    pub(crate) fn holds(self, o: Ordering) -> bool {
        match self {
            CmpOp::Eq => o == Ordering::Equal,
            CmpOp::Ne => o != Ordering::Equal,
            CmpOp::Lt => o == Ordering::Less,
            CmpOp::Le => o != Ordering::Greater,
            CmpOp::Gt => o == Ordering::Greater,
            CmpOp::Ge => o != Ordering::Less,
        }
    }
}

/// `CHECK`-Bedingung einer Spalte. Wird bei jedem Schreiben geprüft und
/// zusammen mit dem Schema gespeichert.
///
/// ```
/// use dbcore::Check;
/// let _ = Check::ge(0);              // views >= 0
/// let _ = Check::between(1, 5);      // 1..=5
/// let _ = Check::one_of(["a", "b"]); // Aufzählung
/// let _ = Check::len(1, 50);         // Textlänge in Zeichen
/// let _ = Check::like("%@%");        // SQL-LIKE (% und _), ohne Groß/Klein
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum Check {
    Cmp(CmpOp, String),
    Between(String, String),
    OneOf(Vec<String>),
    Len { min: usize, max: usize },
    Like(String),
}

impl Check {
    pub fn eq(v: impl ToString) -> Self {
        Check::Cmp(CmpOp::Eq, v.to_string())
    }
    pub fn ne(v: impl ToString) -> Self {
        Check::Cmp(CmpOp::Ne, v.to_string())
    }
    pub fn lt(v: impl ToString) -> Self {
        Check::Cmp(CmpOp::Lt, v.to_string())
    }
    pub fn le(v: impl ToString) -> Self {
        Check::Cmp(CmpOp::Le, v.to_string())
    }
    pub fn gt(v: impl ToString) -> Self {
        Check::Cmp(CmpOp::Gt, v.to_string())
    }
    pub fn ge(v: impl ToString) -> Self {
        Check::Cmp(CmpOp::Ge, v.to_string())
    }
    pub fn between(lo: impl ToString, hi: impl ToString) -> Self {
        Check::Between(lo.to_string(), hi.to_string())
    }
    pub fn one_of<I, S>(items: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: ToString,
    {
        Check::OneOf(items.into_iter().map(|s| s.to_string()).collect())
    }
    pub fn len(min: usize, max: usize) -> Self {
        Check::Len { min, max }
    }
    pub fn like(pattern: impl ToString) -> Self {
        Check::Like(pattern.to_string())
    }

    pub(crate) fn holds(&self, kind: ColumnKind, v: &str) -> bool {
        match self {
            Check::Cmp(op, rhs) => op.holds(cmp_values(kind, v, rhs)),
            Check::Between(lo, hi) => {
                cmp_values(kind, v, lo) != Ordering::Less
                    && cmp_values(kind, v, hi) != Ordering::Greater
            }
            Check::OneOf(items) => items
                .iter()
                .any(|i| cmp_values(kind, v, i) == Ordering::Equal),
            Check::Len { min, max } => {
                let n = v.chars().count();
                n >= *min && n <= *max
            }
            Check::Like(p) => like_match(p, v),
        }
    }

    pub(crate) fn describe(&self) -> String {
        match self {
            Check::Cmp(op, v) => format!("{} {v}", op.symbol()),
            Check::Between(a, b) => format!("zwischen {a} und {b}"),
            Check::OneOf(i) => format!("eines von [{}]", i.join(", ")),
            Check::Len { min, max } => format!("Länge {min}..={max}"),
            Check::Like(p) => format!("LIKE '{p}'"),
        }
    }

    /// Prüft, ob die Bedingung zum Spaltentyp passt (z. B. keine Text-Grenze bei `Int`).
    pub(crate) fn operands_valid(&self, c: &ColumnDef) -> Result<()> {
        let probe = |v: &str| validate_value(c, v);
        match self {
            Check::Cmp(_, v) => probe(v),
            Check::Between(a, b) => probe(a).and_then(|_| probe(b)),
            Check::OneOf(items) => items.iter().try_for_each(|i| probe(i)),
            _ => Ok(()),
        }
    }

    pub(crate) fn encode(&self) -> Vec<String> {
        match self {
            Check::Cmp(op, v) => vec!["cmp".into(), op.code().into(), v.clone()],
            Check::Between(a, b) => vec!["between".into(), a.clone(), b.clone()],
            Check::OneOf(i) => {
                let mut t = vec!["in".to_string()];
                t.extend(i.iter().cloned());
                t
            }
            Check::Len { min, max } => vec!["len".into(), min.to_string(), max.to_string()],
            Check::Like(p) => vec!["like".into(), p.clone()],
        }
    }

    pub(crate) fn decode(t: &[String]) -> Option<Self> {
        let tag = t.first()?.as_str();
        Some(match tag {
            "cmp" => Check::Cmp(CmpOp::from_code(t.get(1)?)?, t.get(2)?.clone()),
            "between" => Check::Between(t.get(1)?.clone(), t.get(2)?.clone()),
            "in" => Check::OneOf(t[1..].to_vec()),
            "len" => Check::Len {
                min: t.get(1)?.parse().ok()?,
                max: t.get(2)?.parse().ok()?,
            },
            "like" => Check::Like(t.get(1)?.clone()),
            _ => return None,
        })
    }
}

/// SQL-`LIKE` (`%` = beliebig viele Zeichen, `_` = genau eins), ASCII-case-insensitive.
pub(crate) fn like_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().map(|c| c.to_ascii_lowercase()).collect();
    let t: Vec<char> = text.chars().map(|c| c.to_ascii_lowercase()).collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '_' || (p[pi] != '%' && p[pi] == t[ti])) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '%' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '%' {
        pi += 1;
    }
    pi == p.len()
}

/// Verhalten beim Löschen der referenzierten Zeile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnDelete {
    /// Löschen wird abgelehnt, solange Kinder existieren (Standard).
    Restrict,
    /// Kinder werden mitgelöscht (rekursiv).
    Cascade,
}

/// Fremdschlüssel: Spalte verweist auf `table.column` (muss `@key` oder `UNIQUE` sein).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignKey {
    pub table: String,
    pub column: String,
    pub on_delete: OnDelete,
}

// ───────────── Column ─────────────

#[derive(Debug, Clone)]
pub struct ColumnDef {
    pub(crate) name: String,
    pub(crate) kind: ColumnKind,
    pub(crate) default: Option<String>,
    pub(crate) key: bool,
    pub(crate) not_null: bool,
    pub(crate) unique: bool,
    pub(crate) indexed: bool,
    pub(crate) checks: Vec<Check>,
    pub(crate) fk: Option<ForeignKey>,
}

/// Interner Alias.
pub(crate) type ColDef = ColumnDef;

impl ColumnDef {
    pub fn new(
        name: impl Into<String>,
        kind: ColumnKind,
        default: Option<String>,
        key: bool,
    ) -> Self {
        ColumnDef {
            name: name.into(),
            kind,
            default,
            key,
            not_null: false,
            unique: false,
            indexed: false,
            checks: Vec::new(),
            fk: None,
        }
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn kind(&self) -> ColumnKind {
        self.kind
    }
    pub fn default_value(&self) -> Option<&str> {
        self.default.as_deref().filter(|v| *v != NULL_CELL)
    }
    pub fn is_key(&self) -> bool {
        self.key
    }
    pub fn is_not_null(&self) -> bool {
        self.not_null
    }
    pub fn is_unique(&self) -> bool {
        self.unique || self.key
    }
    pub fn is_indexed(&self) -> bool {
        self.indexed || self.unique || self.key
    }
    pub fn checks(&self) -> &[Check] {
        &self.checks
    }
    pub fn foreign_key(&self) -> Option<&ForeignKey> {
        self.fk.as_ref()
    }

    /// Builder: Spalte darf nicht leer sein.
    pub fn not_null(mut self) -> Self {
        self.not_null = true;
        self
    }
    pub fn unique(mut self) -> Self {
        self.unique = true;
        self
    }
    pub fn indexed(mut self) -> Self {
        self.indexed = true;
        self
    }
    pub fn with_check(mut self, c: Check) -> Self {
        self.checks.push(c);
        self
    }
    pub fn with_reference(
        mut self,
        table: impl Into<String>,
        column: impl Into<String>,
        on_delete: OnDelete,
    ) -> Self {
        self.fk = Some(ForeignKey {
            table: table.into(),
            column: column.into(),
            on_delete,
        });
        self
    }
}

pub trait ColumnType {
    fn kind() -> ColumnKind;
    fn nullable() -> bool { false }
}

macro_rules! impl_column_type {
    ($($t:ty => $k:ident),* $(,)?) => {
        $( impl ColumnType for $t { fn kind() -> ColumnKind { ColumnKind::$k } } )*
    };
}
impl_column_type! {
    String => Text, &str => Text,
    i8 => Int, i16 => Int, i32 => Int, i64 => Int, isize => Int,
    u8 => Int, u16 => Int, u32 => Int, u64 => Int, usize => Int,
    f32 => Float, f64 => Float,
    bool => Bool,
    Blob => Blob, Timestamp => Timestamp, Date => Date, Time => Time,
    Uuid => Uuid, Json => Json, Decimal => Decimal, Null => Null,
}
impl<T: ColumnType> ColumnType for Option<T> {
    fn kind() -> ColumnKind {
        T::kind()
    }
    fn nullable() -> bool { true }
}

// ───────────── Schema ─────────────

/// Tabellenschema. Erzeugen mit [`schema!`], verfeinern mit den Builder-Methoden.
#[derive(Debug, Clone)]
pub struct Schema {
    pub(crate) columns: Vec<ColumnDef>,
    pub(crate) problems: Vec<String>,
}

impl Schema {
    pub fn new(columns: Vec<ColumnDef>) -> Self {
        Schema {
            columns,
            problems: Vec::new(),
        }
    }
    pub fn columns(&self) -> &[ColumnDef] {
        &self.columns
    }

    fn on<F: FnOnce(&mut ColumnDef)>(mut self, col: &str, f: F) -> Self {
        match self.columns.iter_mut().find(|c| c.name == col) {
            Some(c) => f(c),
            None => self.problems.push(format!("unbekannte Spalte '{col}'")),
        }
        self
    }

    /// Spalten dürfen nicht leer sein.
    pub fn not_null(mut self, cols: &[&str]) -> Self {
        for c in cols {
            self = self.on(c, |c| c.not_null = true);
        }
        self
    }
    /// `UNIQUE` (erzeugt zugleich einen Index).
    pub fn unique(mut self, cols: &[&str]) -> Self {
        for c in cols {
            self = self.on(c, |c| c.unique = true);
        }
        self
    }
    /// Sekundärer Index (nicht eindeutig).
    pub fn index(mut self, cols: &[&str]) -> Self {
        for c in cols {
            self = self.on(c, |c| c.indexed = true);
        }
        self
    }
    /// `CHECK`-Bedingung für eine Spalte (mehrfach aufrufbar).
    pub fn check(self, col: &str, check: Check) -> Self {
        self.on(col, |c| c.checks.push(check))
    }
    /// Foreign Key: `col` verweist auf `table.column`.
    pub fn references(self, col: &str, table: &str, column: &str, on_delete: OnDelete) -> Self {
        let (t, cc) = (table.to_string(), column.to_string());
        self.on(col, |c| {
            c.fk = Some(ForeignKey {
                table: t,
                column: cc,
                on_delete,
            })
        })
    }
}

/// ```ignore
/// schema! { @key id: i32, name: String, views: i64 = 0 }
/// ```
#[macro_export]
macro_rules! schema {
    (
        $(
            $(@ $key_marker:ident)?
            $name:ident : $ty:ty
            $(= $default:expr)?
        ),* $(,)?
    ) => {
        $crate::Schema::new(::std::vec![
            $(
                $crate::ColumnDef::new(
                    ::std::stringify!($name),
                    <$ty as $crate::ColumnType>::kind(),
                    {
                        #[allow(unused_mut)]
                        let mut d: ::std::option::Option<::std::string::String> =
                            ::std::option::Option::None;
                        $(
                            d = ::std::option::Option::Some(
                                ::std::format!("{}", $default)
                            );
                        )?
                        if d.is_none() && <$ty as $crate::ColumnType>::nullable() {
                            d = ::std::option::Option::Some(::std::string::String::from("\0"));
                        }
                        d
                    },
                    $crate::__dbcore_is_key_marker!($( $key_marker )?),
                )
            ),*
        ])
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __dbcore_is_key_marker {
    (key) => {
        true
    };
    () => {
        false
    };
}

/// `row! { id: 1, name: "Alice" }` → `Vec<(&str, String)>`.
#[macro_export]
macro_rules! row {
    (
        $($name:ident : $val:expr),* $(,)?
    ) => {
        ::std::vec![
            $(
                (::std::stringify!($name), ::std::format!("{}", $val))
            ),*
        ]
    };
}

/// `params! { id: 1, note: Value::Null }` creates native, typed parameters.
#[macro_export]
macro_rules! params {
    ($($name:ident : $val:expr),* $(,)?) => {
        ::std::vec![
            $(
                (::std::stringify!($name), $crate::Value::from($val))
            ),*
        ]
    };
}

/// Erzeugt eine Filter-Closure; `r` ist eine [`Row`] mit Zugriff nach Position
/// (`r[2]`) **und** Name (`r["views"]`, `r.get::<i64>("views")`).
///
/// ```ignore
/// db.table("users").filter(with!(r => r["name"] == "Alice")).print();
/// db.table("users").filter(with!(r => r.get::<i64>("views").unwrap_or(0) > 0)).print();
/// ```
#[macro_export]
macro_rules! with {
    ($var:ident => $cond:expr) => {
        |$var: $crate::Row<'_>| $cond
    };
}

/// Löscht alle Zeilen, für die der Ausdruck `true` ergibt. Liefert die Anzahl.
///
/// ```ignore
/// let n = remove_if!(db, "users", r => r[1].starts_with('A'));
/// ```
#[macro_export]
macro_rules! remove_if {
    ($db:expr, $table:expr, $var:ident => $cond:expr) => {
        $db.table($table).filter($crate::with!($var => $cond)).delete()
    };
}

/// Definiert ein Struct samt Schema und Zeilen-Konvertierung (ersetzt `#[derive]`).
///
/// ```
/// dbcore::model! {
///     #[derive(Debug, Clone, PartialEq)]
///     pub struct User {
///         @key id: i32,
///         name: String,
///         views: i64 = 0,
///     }
/// }
/// let db = dbcore::DBCore::temp();
/// db.create_model::<User>("users");
/// db.put_model("users", &User { id: 1, name: "Alice".into(), views: 3 });
/// let all: Vec<User> = db.table("users").collect_as();
/// assert_eq!(all[0].name, "Alice");
/// ```
#[macro_export]
macro_rules! model {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $(
                $(@ $km:ident)?
                $f:ident : $t:ty
                $(= $d:expr)?
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis struct $name { $( pub $f: $t ),* }

        impl $crate::FromRow for $name {
            fn from_row(row: $crate::Row<'_>) -> $crate::DbResult<Self> {
                ::std::result::Result::Ok($name {
                    $( $f: row.get::<$t>(::std::stringify!($f))? ),*
                })
            }
        }

        impl $crate::Model for $name {
            fn schema() -> $crate::Schema {
                $crate::schema! { $( $(@ $km)? $f : $t $(= $d)? ),* }
            }
            fn to_values(&self) -> ::std::vec::Vec<(&'static str, ::std::string::String)> {
                ::std::vec![
                    $(
                        (
                            ::std::stringify!($f),
                            ::std::string::ToString::to_string(&$crate::Value::from(&self.$f)),
                        )
                    ),*
                ]
            }
            fn to_typed_values(&self) -> ::std::vec::Vec<(&'static str, $crate::Value)> {
                ::std::vec![
                    $(
                        (::std::stringify!($f), $crate::Value::from(&self.$f))
                    ),*
                ]
            }
        }
    };
}

// ───────────── Fehler ─────────────

#[derive(Debug)]
#[non_exhaustive]
pub enum DbError {
    Io(io::Error),
    Crypto(&'static str),
    Corrupt(&'static str),
    InvalidName,
    TableExists(String),
    TableNotFound(String),
    RowNotFound(String),
    Closed,
    SchemaMismatch(String),
    TypeMismatch(String),
    DuplicateKey(String),
    BadValue(String),
    /// Schreib-Lock beim Commit nicht rechtzeitig erhalten.
    Busy,
    /// Eine gelesene oder geänderte Tabelle hat sich seit Transaktionsbeginn geändert.
    WriteConflict(String),
    /// `NOT NULL` verletzt.
    NotNull(String),
    /// `UNIQUE` verletzt.
    Unique(String),
    /// `CHECK` verletzt.
    CheckFailed(String),
    /// Foreign-Key-Verstoß.
    ForeignKey(String),
    /// Schreiben auf einem Snapshot / mit beendeter Transaktion.
    ReadOnly,
    /// Ein Snapshot ist veraltet (Datei wurde inzwischen ersetzt).
    SnapshotExpired,
    /// Transaktion wird gerade benutzt (Re-Entrancy) oder ist beendet.
    TxState(&'static str),
    /// Funktion für diese Abfrageform nicht verfügbar.
    Unsupported(String),
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbError::Io(e) => write!(f, "I/O-Fehler: {e}"),
            DbError::Crypto(m) => write!(f, "Krypto-Fehler: {m}"),
            DbError::Corrupt(m) => write!(f, "Beschädigte Datei: {m}"),
            DbError::InvalidName => write!(f, "Ungültiger Name (erlaubt: a-z A-Z 0-9 _ -)"),
            DbError::TableExists(n) => write!(f, "Tabelle '{n}' existiert bereits"),
            DbError::TableNotFound(n) => write!(f, "Tabelle '{n}' nicht gefunden"),
            DbError::RowNotFound(m) => write!(f, "Zeile nicht gefunden: {m}"),
            DbError::Closed => write!(f, "Datenbank ist nicht geöffnet"),
            DbError::SchemaMismatch(n) => write!(f, "Schema-Verstoß: {n}"),
            DbError::TypeMismatch(n) => write!(f, "Typfehler: {n}"),
            DbError::DuplicateKey(k) => write!(f, "Schlüssel '{k}' existiert bereits"),
            DbError::BadValue(n) => write!(
                f,
                "Default von '{n}' enthält unerlaubte Zeichen (: , Zeilenumbruch)"
            ),
            DbError::Busy => write!(f, "Datenbank ist beschäftigt (Schreib-Lock-Timeout)"),
            DbError::WriteConflict(t) => write!(
                f,
                "Schreibkonflikt: '{t}' wurde seit Transaktionsbeginn geändert"
            ),
            DbError::NotNull(c) => {
                write!(f, "NOT NULL verletzt: Spalte '{c}' darf nicht leer sein")
            }
            DbError::Unique(m) => write!(f, "UNIQUE verletzt: {m}"),
            DbError::CheckFailed(m) => write!(f, "CHECK verletzt: {m}"),
            DbError::ForeignKey(m) => write!(f, "Foreign-Key-Verstoß: {m}"),
            DbError::ReadOnly => write!(f, "Nur lesbar (Snapshot oder beendete Transaktion)"),
            DbError::SnapshotExpired => write!(f, "Snapshot veraltet – bitte neuen Snapshot holen"),
            DbError::TxState(m) => write!(f, "Transaktionsfehler: {m}"),
            DbError::Unsupported(m) => write!(f, "Nicht unterstützt: {m}"),
        }
    }
}

impl error::Error for DbError {}
impl From<io::Error> for DbError {
    fn from(e: io::Error) -> Self {
        DbError::Io(e)
    }
}

pub(crate) type Result<T> = std::result::Result<T, DbError>;
/// Öffentlicher Ergebnistyp der Bibliothek.
pub type DbResult<T> = std::result::Result<T, DbError>;

/// Fehler auf stderr drucken, Ergebnis als `Option` weiterreichen.
pub(crate) fn report<T>(r: Result<T>) -> Option<T> {
    match r {
        Ok(v) => Some(v),
        Err(e) => {
            eprintln!("DBCore: {e}");
            None
        }
    }
}

// ───────────── Helpers ─────────────

pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn looks_like_path(s: &str) -> bool {
    !s.is_empty()
        && (s.contains('/') || s.contains('\\') || s.starts_with('.') || Path::new(s).is_absolute())
}

/// Zelle `i` einer Zeile; fehlende Zelle = "".
pub(crate) fn cell(row: &[String], i: usize) -> &str {
    row.get(i).map(String::as_str).unwrap_or("")
}

pub(crate) fn is_null(row: &[String], i: usize) -> bool {
    cell(row, i) == NULL_CELL
}

pub(crate) fn display_value(raw: &str) -> &str {
    if raw == NULL_CELL {
        ""
    } else if raw.starts_with(TEXT_ESCAPE) {
        &raw[1..]
    } else {
        raw
    }
}

pub(crate) fn display_row(schema: &[ColDef], row: &[String]) -> Vec<String> {
    schema
        .iter()
        .enumerate()
        .map(|(i, _)| display_value(cell(row, i)).to_string())
        .collect()
}

fn valid_uuid(s: &str) -> bool {
    let bytes: String = s.chars().filter(|&c| c != '-').collect();
    s.len() == 36
        && s.as_bytes().get(8) == Some(&b'-')
        && s.as_bytes().get(13) == Some(&b'-')
        && s.as_bytes().get(18) == Some(&b'-')
        && s.as_bytes().get(23) == Some(&b'-')
        && bytes.len() == 32
        && bytes.bytes().all(|b| b.is_ascii_hexdigit())
}

fn parse_uuid(s: &str) -> Option<[u8; 16]> {
    if !valid_uuid(s) {
        return None;
    }
    let hex: String = s.chars().filter(|&c| c != '-').collect();
    let bytes = hex_decode(&hex)?;
    bytes.try_into().ok()
}

fn valid_decimal(s: &str) -> bool {
    let unsigned = s
        .strip_prefix('-')
        .or_else(|| s.strip_prefix('+'))
        .unwrap_or(s);
    let mut parts = unsigned.split('.');
    let whole = parts.next().unwrap_or("");
    let fraction = parts.next();
    !whole.is_empty()
        && whole.len() <= 39
        && whole.bytes().all(|b| b.is_ascii_digit())
        && fraction.map_or(true, |p| {
            p.len() <= 38 && !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())
        })
        && parts.next().is_none()
}

pub(crate) fn canonical_decimal(s: &str) -> Option<String> {
    if !valid_decimal(s) || parse_decimal(s).is_none() {
        return None;
    }
    let negative = s.starts_with('-');
    let unsigned = s
        .strip_prefix('-')
        .or_else(|| s.strip_prefix('+'))
        .unwrap_or(s);
    let (whole, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    let whole = whole.trim_start_matches('0');
    let whole = if whole.is_empty() { "0" } else { whole };
    let fraction = fraction.trim_end_matches('0');
    let zero = whole == "0" && fraction.is_empty();
    Some(format!(
        "{}{}{}{}",
        if negative && !zero { "-" } else { "" },
        whole,
        if fraction.is_empty() { "" } else { "." },
        fraction
    ))
}

pub(crate) fn decimal_order_key(s: &str) -> Option<String> {
    let canonical = canonical_decimal(s)?;
    let negative = canonical.starts_with('-');
    let unsigned = canonical.strip_prefix('-').unwrap_or(&canonical);
    let (whole, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    let len = whole.len();
    let mut out = String::with_capacity(80);
    out.push(if negative { '0' } else { '1' });
    if negative {
        out.push(char::from(b'9' - (len as u8 / 10)));
        out.push(char::from(b'9' - (len as u8 % 10)));
        out.extend(whole.bytes().map(|b| char::from(b'9' - (b - b'0'))));
        out.extend(fraction.bytes().map(|b| char::from(b'9' - (b - b'0'))));
        out.extend(std::iter::repeat('9').take(38usize.saturating_sub(fraction.len())));
    } else {
        out.push(char::from(b'0' + (len as u8 / 10)));
        out.push(char::from(b'0' + (len as u8 % 10)));
        out.push_str(whole);
        out.extend(fraction.bytes().map(char::from));
        out.extend(std::iter::repeat('0').take(38usize.saturating_sub(fraction.len())));
    }
    Some(out)
}

fn parse_decimal(s: &str) -> Option<(i128, u32)> {
    if !valid_decimal(s) {
        return None;
    }
    let negative = s.starts_with('-');
    let unsigned = s
        .strip_prefix('-')
        .or_else(|| s.strip_prefix('+'))
        .unwrap_or(s);
    let mut parts = unsigned.split('.');
    let whole = parts.next()?;
    let fraction = parts.next().unwrap_or("");
    let digits = format!("{whole}{fraction}");
    let magnitude = digits.parse::<i128>().ok()?;
    let coefficient = if negative {
        magnitude.checked_neg()?
    } else {
        magnitude
    };
    Some((coefficient, u32::try_from(fraction.len()).ok()?))
}

fn typed_values<'a>(
    schema: &[ColDef],
    values: Vec<(&'a str, Value)>,
) -> Result<Vec<(&'a str, String)>> {
    values
        .into_iter()
        .map(|(name, value)| {
            let col = schema
                .iter()
                .find(|c| c.name == name)
                .ok_or_else(|| unknown_col(name))?;
            if !matches!(&value, Value::Null) && value.kind() != col.kind {
                return Err(DbError::TypeMismatch(format!(
                    "Spalte '{}' erwartet {}, bekam {}",
                    col.name,
                    col.kind.as_str(),
                    value.kind().as_str()
                )));
            }
            let raw = value.as_input();
            let raw = if matches!(&value, Value::Text(_)) && raw.starts_with(NULL_CELL) {
                format!("{NULL_CELL}{raw}")
            } else {
                raw
            };
            if !matches!(&value, Value::Null) {
                validate_value(col, &raw)?;
            }
            Ok((name, raw))
        })
        .collect()
}

pub(crate) fn escape_text_fields<'a>(
    schema: &[ColDef],
    values: Vec<(&'a str, String)>,
) -> Vec<(&'a str, String)> {
    values
        .into_iter()
        .map(|(name, mut value)| {
            if schema
                .iter()
                .any(|c| c.name == name && c.kind == ColumnKind::Text)
                && value != NULL_CELL
                && value.starts_with(NULL_CELL)
            {
                value.insert(0, '\0');
            }
            (name, value)
        })
        .collect()
}

pub(crate) fn unknown_col(c: &str) -> DbError {
    DbError::SchemaMismatch(format!("unbekannte Spalte '{c}'"))
}

pub(crate) fn key_index(schema: &[ColDef]) -> Option<usize> {
    schema.iter().position(|c| c.key)
}

/// Spalten, die eindeutig sein müssen (`@key` + `UNIQUE`).
pub(crate) fn unique_cols(schema: &[ColDef]) -> Vec<usize> {
    schema
        .iter()
        .enumerate()
        .filter(|(_, c)| c.key || c.unique)
        .map(|(i, _)| i)
        .collect()
}

/// Kanonische Form für Vergleiche/Hash-Keys ("01" == "1", "1.0" == "1").
pub(crate) fn norm_val(kind: ColumnKind, v: &str) -> String {
    match kind {
        ColumnKind::Int | ColumnKind::Timestamp | ColumnKind::Date | ColumnKind::Time => v
            .parse::<i128>()
            .map(|n| n.to_string())
            .or_else(|_| v.parse::<u128>().map(|n| n.to_string()))
            .unwrap_or_else(|_| v.to_string()),
        ColumnKind::Float => match v.parse::<f64>() {
            Ok(f) if f.is_finite() => f.to_string(),
            _ => v.to_string(),
        },
        ColumnKind::Decimal => canonical_decimal(v).unwrap_or_else(|| v.to_string()),
        ColumnKind::Blob | ColumnKind::Uuid => v.to_ascii_lowercase(),
        _ => v.to_string(),
    }
}

pub(crate) fn key_eq(kind: ColumnKind, a: &str, b: &str) -> bool {
    a == b || norm_val(kind, a) == norm_val(kind, b)
}

/// Prüft den Wert gegen den Spaltentyp.
pub(crate) fn validate_value(c: &ColDef, v: &str) -> Result<()> {
    let ok = match c.kind {
        ColumnKind::Null => false,
        ColumnKind::Int => v.parse::<i128>().is_ok() || v.parse::<u128>().is_ok(),
        ColumnKind::Float => v.parse::<f64>().map(|f| f.is_finite()).unwrap_or(false),
        ColumnKind::Bool => v == "true" || v == "false",
        ColumnKind::Text => true,
        ColumnKind::Blob => hex_decode(v).is_some(),
        ColumnKind::Timestamp => v.parse::<i64>().is_ok(),
        ColumnKind::Date => v.parse::<i32>().is_ok(),
        ColumnKind::Time => v
            .parse::<i64>()
            .map(|n| (0..86_400_000_000).contains(&n))
            .unwrap_or(false),
        ColumnKind::Uuid => valid_uuid(v),
        ColumnKind::Json => serde_json::from_str::<serde_json::Value>(v).is_ok(),
        ColumnKind::Decimal => parse_decimal(v).is_some(),
    };
    if ok {
        Ok(())
    } else {
        Err(DbError::TypeMismatch(format!(
            "Spalte '{}' erwartet {}, bekam '{}'",
            c.name,
            c.kind.as_str(),
            v
        )))
    }
}

/// Lokale Constraints einer Zeile: `NOT NULL` und `CHECK` (Typ separat).
pub(crate) fn check_row_local(schema: &[ColDef], row: &[String]) -> Result<()> {
    for (i, c) in schema.iter().enumerate() {
        let v = cell(row, i);
        let null = is_null(row, i);
        if (c.not_null || c.key) && null {
            return Err(DbError::NotNull(c.name.clone()));
        }
        if null {
            continue;
        }
        for ck in &c.checks {
            if !ck.holds(c.kind, v) {
                return Err(DbError::CheckFailed(format!(
                    "Spalte '{}' = '{}' muss {} sein",
                    c.name,
                    v,
                    ck.describe()
                )));
            }
        }
    }
    Ok(())
}

/// Totale Ordnung: parsebare Zahlen vor Unparsebarem, sonst Text.
pub(crate) fn cmp_values(kind: ColumnKind, a: &str, b: &str) -> Ordering {
    match kind {
        ColumnKind::Int | ColumnKind::Timestamp | ColumnKind::Date | ColumnKind::Time => {
            match (a.parse::<i128>().ok(), b.parse::<i128>().ok()) {
                (Some(x), Some(y)) => x.cmp(&y),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => a.cmp(b),
            }
        }
        ColumnKind::Float => match (a.parse::<f64>().ok(), b.parse::<f64>().ok()) {
            (Some(x), Some(y)) => x.total_cmp(&y),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => a.cmp(b),
        },
        ColumnKind::Decimal => match (decimal_order_key(a), decimal_order_key(b)) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => a.cmp(b),
        },
        _ => a.cmp(b),
    }
}

/// Spalte per Name finden: exakt, `tabelle.spalte` (einfache Tabelle)
/// oder eindeutiges Suffix `.spalte` (Join-Ergebnis).
pub(crate) fn find_col(schema: &[ColDef], name: &str) -> Option<usize> {
    if let Some(i) = schema.iter().position(|c| c.name == name) {
        return Some(i);
    }
    if let Some((_, rest)) = name.split_once('.') {
        if let Some(i) = schema.iter().position(|c| c.name == rest) {
            return Some(i);
        }
        return None;
    }
    let suffix = format!(".{name}");
    let mut hits = schema
        .iter()
        .enumerate()
        .filter(|(_, c)| c.name.ends_with(&suffix));
    match (hits.next(), hits.next()) {
        (Some((i, _)), None) => Some(i),
        _ => None,
    }
}

pub(crate) fn resolve_col(schema: &[ColDef], name: &str) -> Result<usize> {
    find_col(schema, name).ok_or_else(|| {
        let ambiguous = !name.contains('.')
            && schema
                .iter()
                .filter(|c| c.name.ends_with(&format!(".{name}")))
                .count()
                > 1;
        if ambiguous {
            DbError::SchemaMismatch(format!(
                "Spalte '{name}' ist mehrdeutig – 'tabelle.{name}' verwenden"
            ))
        } else {
            unknown_col(name)
        }
    })
}

pub(crate) fn build_row(schema: &[ColDef], values: &[(&str, String)]) -> Result<Vec<String>> {
    for (k, _) in values {
        if !schema.iter().any(|c| c.name == *k) {
            return Err(unknown_col(k));
        }
    }
    let mut row = Vec::with_capacity(schema.len());
    for c in schema {
        let mut v = match values.iter().find(|p| p.0 == c.name.as_str()) {
            Some(p) => p.1.clone(),
            None => c
                .default
                .clone()
                .ok_or_else(|| DbError::SchemaMismatch(format!("Spalte '{}' fehlt", c.name)))?,
        };
        if v == NULL_CELL {
            if c.not_null || c.key {
                return Err(DbError::NotNull(c.name.clone()));
            }
        } else {
            validate_value(c, &v)?;
            if c.kind == ColumnKind::Text && v.starts_with(NULL_CELL) && !v.starts_with(TEXT_ESCAPE)
            {
                v.insert(0, '\0');
            }
        }
        row.push(v);
    }
    Ok(row)
}

// ───────────── Row: Zugriff nach Name und Typ ─────────────

static EMPTY: String = String::new();

/// Eine Ergebniszeile mit Schema. Zugriff nach Position (`r[2]`), Name
/// (`r["views"]`) oder typisiert (`r.get::<i64>("views")`).
#[derive(Clone)]
pub struct Row<'a> {
    pub(crate) schema: &'a [ColDef],
    cells: Vec<String>,
    raw: Vec<String>,
}

impl<'a> Row<'a> {
    pub(crate) fn new(schema: &'a [ColDef], raw: &[String]) -> Self {
        Row {
            schema,
            cells: raw.iter().map(|v| display_value(v).to_string()).collect(),
            raw: raw.to_vec(),
        }
    }
    pub fn len(&self) -> usize {
        self.cells.len()
    }
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }
    pub fn cells(&self) -> &[String] {
        &self.cells
    }
    pub fn iter(&self) -> std::slice::Iter<'_, String> {
        self.cells.iter()
    }
    pub fn columns(&self) -> impl Iterator<Item = &'a str> {
        self.schema.iter().map(|c| c.name.as_str())
    }

    /// Rohtext einer Spalte (`None` = Spalte existiert nicht).
    pub fn str(&self, col: &str) -> Option<&str> {
        find_col(self.schema, col).and_then(|i| self.cells.get(i).map(String::as_str))
    }

    /// Typisierter Zugriff nach Name.
    pub fn get<T: FromCell>(&self, col: &str) -> DbResult<T> {
        let i = find_col(self.schema, col).ok_or_else(|| unknown_col(col))?;
        self.get_at(i)
    }

    /// Typisierter Zugriff nach Position.
    pub fn get_at<T: FromCell>(&self, i: usize) -> DbResult<T> {
        let raw = cell(&self.raw, i);
        T::from_cell(raw).map_err(|why| {
            DbError::TypeMismatch(format!(
                "Spalte '{}': '{}' {}",
                self.schema.get(i).map(|c| c.name.as_str()).unwrap_or("?"),
                raw,
                why
            ))
        })
    }

    /// Read a cell as its native database value, preserving SQL NULL.
    pub fn get_value(&self, col: &str) -> DbResult<Value> {
        let i = find_col(self.schema, col).ok_or_else(|| unknown_col(col))?;
        self.get_value_at(i)
    }

    /// Read a cell by position as its native database value.
    pub fn get_value_at(&self, i: usize) -> DbResult<Value> {
        let Some(c) = self.schema.get(i) else {
            return Err(DbError::SchemaMismatch(format!(
                "Spalte an Position {i} existiert nicht"
            )));
        };
        let raw = cell(&self.raw, i);
        if raw == NULL_CELL {
            return Ok(Value::Null);
        }
        let value = match c.kind {
            ColumnKind::Null => Value::Null,
            ColumnKind::Int => Value::Int(
                raw.parse()
                    .map_err(|_| DbError::TypeMismatch(format!("'{}' ist kein Int", raw)))?,
            ),
            ColumnKind::Float => Value::Float(
                raw.parse()
                    .map_err(|_| DbError::TypeMismatch(format!("'{}' ist kein Float", raw)))?,
            ),
            ColumnKind::Text => Value::Text(display_value(raw).to_string()),
            ColumnKind::Bool => Value::Bool(
                raw.parse()
                    .map_err(|_| DbError::TypeMismatch(format!("'{}' ist kein Bool", raw)))?,
            ),
            ColumnKind::Blob => Value::Blob(
                hex_decode(raw).ok_or_else(|| DbError::TypeMismatch("ungültiges Blob".into()))?,
            ),
            ColumnKind::Timestamp => Value::Timestamp(
                raw.parse()
                    .map_err(|_| DbError::TypeMismatch("ungültiger Timestamp".into()))?,
            ),
            ColumnKind::Date => Value::Date(
                raw.parse()
                    .map_err(|_| DbError::TypeMismatch("ungültiges Date".into()))?,
            ),
            ColumnKind::Time => Value::Time(
                raw.parse()
                    .map_err(|_| DbError::TypeMismatch("ungültige Time".into()))?,
            ),
            ColumnKind::Uuid => Value::Uuid(
                parse_uuid(raw).ok_or_else(|| DbError::TypeMismatch("ungültige UUID".into()))?,
            ),
            ColumnKind::Json => Value::Json(raw.to_string()),
            ColumnKind::Decimal => {
                let (coefficient, scale) = parse_decimal(raw)
                    .ok_or_else(|| DbError::TypeMismatch("ungültiger Decimal".into()))?;
                Value::Decimal { coefficient, scale }
            }
        };
        Ok(value)
    }
}

impl<'a> Index<usize> for Row<'a> {
    type Output = String;
    fn index(&self, i: usize) -> &String {
        self.cells.get(i).unwrap_or(&EMPTY)
    }
}

impl<'a, 'b> Index<&'b str> for Row<'a> {
    type Output = String;
    /// Unbekannte Spalte → leerer Text (plus Warnung auf stderr).
    fn index(&self, col: &'b str) -> &String {
        match find_col(self.schema, col) {
            Some(i) => self.cells.get(i).unwrap_or(&EMPTY),
            None => {
                eprintln!("DBCore: {}", unknown_col(col));
                &EMPTY
            }
        }
    }
}

impl fmt::Debug for Row<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut m = f.debug_map();
        for (i, c) in self.schema.iter().enumerate() {
            m.entry(&c.name, self.cells.get(i).unwrap_or(&EMPTY));
        }
        m.finish()
    }
}

/// Zelle → Rust-Typ.
pub trait FromCell: Sized {
    fn from_cell(s: &str) -> std::result::Result<Self, String>;
}

macro_rules! impl_from_cell {
    ($($t:ty => $what:expr),* $(,)?) => {$(
        impl FromCell for $t {
            fn from_cell(s: &str) -> std::result::Result<Self, String> {
                s.parse::<$t>().map_err(|_| format!("ist kein {}", $what))
            }
        }
    )*};
}
impl_from_cell! {
    i8 => "i8", i16 => "i16", i32 => "i32", i64 => "i64", isize => "isize", i128 => "i128",
    u8 => "u8", u16 => "u16", u32 => "u32", u64 => "u64", usize => "usize",
    f32 => "f32", f64 => "f64", bool => "bool",
}
impl FromCell for String {
    fn from_cell(s: &str) -> std::result::Result<Self, String> {
        Ok(display_value(s).to_string())
    }
}
impl FromCell for Blob {
    fn from_cell(s: &str) -> std::result::Result<Self, String> {
        hex_decode(s)
            .map(Blob)
            .ok_or_else(|| "ist kein Blob".into())
    }
}
impl FromCell for Timestamp {
    fn from_cell(s: &str) -> std::result::Result<Self, String> {
        s.parse()
            .map(Timestamp)
            .map_err(|_| "ist kein Timestamp".into())
    }
}
impl FromCell for Date {
    fn from_cell(s: &str) -> std::result::Result<Self, String> {
        s.parse().map(Date).map_err(|_| "ist kein Date".into())
    }
}
impl FromCell for Time {
    fn from_cell(s: &str) -> std::result::Result<Self, String> {
        s.parse().map(Time).map_err(|_| "ist keine Time".into())
    }
}
impl FromCell for Uuid {
    fn from_cell(s: &str) -> std::result::Result<Self, String> {
        parse_uuid(s)
            .map(Uuid)
            .ok_or_else(|| "ist keine UUID".into())
    }
}
impl FromCell for Json {
    fn from_cell(s: &str) -> std::result::Result<Self, String> {
        serde_json::from_str::<serde_json::Value>(s).map_err(|_| "ist kein JSON".to_string())?;
        Ok(Json(s.to_string()))
    }
}
impl FromCell for Decimal {
    fn from_cell(s: &str) -> std::result::Result<Self, String> {
        parse_decimal(s)
            .map(|(coefficient, scale)| Decimal { coefficient, scale })
            .ok_or_else(|| "ist kein Decimal".into())
    }
}
impl<T: FromCell> FromCell for Option<T> {
    fn from_cell(s: &str) -> std::result::Result<Self, String> {
        if s == NULL_CELL {
            Ok(None)
        } else {
            T::from_cell(s).map(Some)
        }
    }
}

/// Zeile → eigener Typ (siehe [`model!`]).
pub trait FromRow: Sized {
    fn from_row(row: Row<'_>) -> DbResult<Self>;
}

/// Struct mit Schema und Werten (siehe [`model!`]).
pub trait Model: FromRow {
    fn schema() -> Schema;
    fn to_values(&self) -> Vec<(&'static str, String)>;
    fn to_typed_values(&self) -> Vec<(&'static str, Value)> {
        self.to_values()
            .into_iter()
            .map(|(name, value)| (name, Value::Text(value)))
            .collect()
    }
}

// ───────────── DBCore ─────────────

/// Datenbank-Handle. Billig zu klonen (`Arc`), `Send + Sync`.
#[derive(Clone)]
pub struct DBCore {
    pub(crate) dir: PathBuf,
    pub(crate) store: Option<Arc<Store>>,
}

impl fmt::Debug for DBCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DBCore")
            .field("dir", &self.dir)
            .field("key", &"<verborgen>")
            .field("open", &self.store.is_some())
            .finish()
    }
}

/// Migrationsschritt für [`DBCore::migrate`]: `(Zielversion, Funktion)`.
pub type Migration = (u32, fn(&Tx) -> DbResult<()>);

impl DBCore {
    // ───── Konstruktoren ─────

    /// Name (`"HI"` → `./dbcore_data/HI`) oder Pfad (`"./db"`, `"/abs"`).
    /// Fehler werden auf `stderr` gemeldet; die DB ist dann „geschlossen“.
    pub fn new(name: &str) -> Self {
        let dir = Self::dir_for(name);
        Self::or_closed(dir.clone(), Self::try_new(name))
    }
    pub fn at(path: impl AsRef<Path>) -> Self {
        let dir = path.as_ref().to_path_buf();
        Self::or_closed(dir.clone(), Self::try_at(&dir))
    }
    pub fn under(base: impl AsRef<Path>, name: &str) -> Self {
        let dir = base.as_ref().join(name);
        Self::or_closed(dir.clone(), Self::try_at(&dir))
    }
    /// Wegwerf-Datenbank in einem temporären Verzeichnis (für Tests/Prototypen);
    /// wird beim Löschen des letzten Handles entfernt.
    pub fn temp() -> Self {
        match Self::try_temp() {
            Ok(db) => db,
            Err(e) => {
                eprintln!("DBCore: {e}");
                DBCore {
                    dir: PathBuf::new(),
                    store: None,
                }
            }
        }
    }

    fn or_closed(dir: PathBuf, r: Result<DBCore>) -> DBCore {
        match r {
            Ok(db) => db,
            Err(e) => {
                eprintln!("DBCore: {e}");
                DBCore { dir, store: None }
            }
        }
    }

    fn dir_for(input: &str) -> PathBuf {
        if input.is_empty() {
            PathBuf::from(BASE_DIR)
        } else if looks_like_path(input) {
            PathBuf::from(input)
        } else {
            Path::new(BASE_DIR).join(input)
        }
    }

    pub fn try_new(input: &str) -> DbResult<Self> {
        if !input.is_empty() && !looks_like_path(input) && !valid_name(input) {
            return Err(DbError::InvalidName);
        }
        Self::try_at(&Self::dir_for(input))
    }
    pub fn try_at(dir: impl AsRef<Path>) -> DbResult<Self> {
        let dir = dir.as_ref().to_path_buf();
        let store = Store::open(dir.clone(), false)?;
        Ok(DBCore {
            dir,
            store: Some(store),
        })
    }
    pub fn try_under(base: impl AsRef<Path>, name: &str) -> DbResult<Self> {
        if !valid_name(name) {
            return Err(DbError::InvalidName);
        }
        Self::try_at(base.as_ref().join(name))
    }
    pub fn try_temp() -> DbResult<Self> {
        use std::sync::atomic::{AtomicU64, Ordering as AO};
        static N: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "dbcore-{}-{nanos}-{}",
            std::process::id(),
            N.fetch_add(1, AO::Relaxed)
        ));
        let store = Store::open(dir.clone(), true)?;
        Ok(DBCore {
            dir,
            store: Some(store),
        })
    }

    /// Verzeichnis der Datenbank.
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// `true`, wenn die Datenbank geöffnet (Schlüssel geladen) ist.
    pub fn is_open(&self) -> bool {
        self.store.is_some()
    }

    pub(crate) fn st(&self) -> Result<&Arc<Store>> {
        self.store.as_ref().ok_or(DbError::Closed)
    }

    // ───── Einstellungen ─────

    /// Maximale Wartezeit auf den Schreib-Lock (Standard 10 s).
    pub fn set_busy_timeout(&self, d: Duration) {
        if let Ok(s) = self.st() {
            s.set_busy_timeout(d);
        }
    }
    /// `false` = kein `fsync` (schneller, aber nicht stromausfallsicher).
    pub fn set_sync(&self, on: bool) {
        if let Ok(s) = self.st() {
            s.set_sync(on);
        }
    }
    /// Tabellen-Cache an/aus (Standard an). Aus = geringster Speicherbedarf.
    pub fn set_cache(&self, on: bool) {
        if let Ok(s) = self.st() {
            s.set_cache(on);
        }
    }
    pub fn clear_cache(&self) {
        if let Ok(s) = self.st() {
            s.clear_cache();
        }
    }

    /// Spielt ein ausstehendes WAL ein und checkpointed es unter dem Schreib-Lock.
    pub fn checkpoint(&self) -> DbResult<()> {
        self.st()?.checkpoint()
    }

    // ───── Transaktionen & Snapshots ─────

    /// Startet eine Schreib-Transaktion auf einem festen Snapshot.
    /// Der Schreib-Lock wird erst beim Commit angefordert. Ohne [`Tx::commit`]
    /// wird beim Drop zurückgerollt.
    pub fn begin(&self) -> DbResult<Tx> {
        Tx::begin(self.st()?)
    }

    /// Führt `f` in einer Transaktion aus: `Ok` → Commit, `Err`/Panic → Rollback.
    pub fn transaction<R>(&self, f: impl FnOnce(&Tx) -> DbResult<R>) -> DbResult<R> {
        let tx = self.begin()?;
        let r = f(&tx)?;
        tx.commit()?;
        Ok(r)
    }

    /// Fester, konsistenter Lese-Stand über alle Tabellen. Bleibt gültig, egal
    /// wie viele Commits andere Schreiber inzwischen machen.
    pub fn snapshot(&self) -> DbResult<Snapshot> {
        self.st()?.snapshot_pinned()
    }

    // ───── Tabellen ─────

    pub fn create(&self, name: &str, schema: Schema) -> bool {
        report(self.try_create(name, schema)).is_some()
    }
    pub fn create_if_missing(&self, name: &str, schema: Schema) -> bool {
        report(self.try_create_if_missing(name, schema)).is_some()
    }
    pub fn delete_table(&self, table: &str) -> bool {
        report(self.try_delete_table(table, false)).is_some()
    }
    pub fn delete_table_if_exists(&self, table: &str) -> bool {
        report(self.try_delete_table(table, true)).is_some()
    }
    /// Alter, missverständlicher Name – identisch zu `delete_table_if_exists`.
    pub fn delete_table_if_not_missing(&self, table: &str) -> bool {
        self.delete_table_if_exists(table)
    }

    /// Namen aller Tabellen, alphabetisch.
    pub fn tables(&self) -> Vec<String> {
        report(self.try_tables()).unwrap_or_default()
    }
    pub fn try_tables(&self) -> DbResult<Vec<String>> {
        Ok(self.st()?.snapshot()?.tables())
    }
    pub fn has_table(&self, table: &str) -> bool {
        valid_name(table) && report(self.try_has_table(table)).unwrap_or(false)
    }
    pub fn try_has_table(&self, table: &str) -> DbResult<bool> {
        Ok(self.st()?.snapshot()?.has_table(table))
    }

    pub fn try_create(&self, name: &str, schema: Schema) -> DbResult<()> {
        self.transaction(|tx| tx.create_table(name, schema))
    }
    pub fn try_create_if_missing(&self, name: &str, schema: Schema) -> DbResult<()> {
        self.transaction(|tx| tx.create_table_if_missing(name, schema))
    }
    pub fn try_delete_table(&self, table: &str, if_exists: bool) -> DbResult<()> {
        self.transaction(|tx| tx.drop_table(table, if_exists))
    }

    // ───── Zeilen schreiben ─────

    /// Fügt eine Zeile ein. Doppelte Keys werden abgelehnt. `true` = ok.
    pub fn add(&self, table: &str, values: Vec<(&str, String)>) -> bool {
        report(self.try_add(table, values)).is_some()
    }
    /// Upsert. Liefert den **Key** der geschriebenen Zeile (bei Int-Key ggf.
    /// automatisch vergeben) – oder `""` bei Fehler.
    pub fn put(&self, table: &str, values: Vec<(&str, String)>) -> String {
        report(self.try_put(table, values)).unwrap_or_default()
    }
    /// Partielles Update per Key. `true` = Zeile gefunden und geändert.
    pub fn update(&self, table: &str, key: &str, values: Vec<(&str, String)>) -> bool {
        report(self.try_update(table, key, values)).is_some()
    }
    /// Löscht per Key (inkl. `ON DELETE CASCADE`). `true` = es gab die Zeile.
    pub fn remove(&self, table: &str, key: &str) -> bool {
        report(self.try_remove(table, key)).unwrap_or(false)
    }
    /// Viele Upserts in **einem** Commit (alles oder nichts). Liefert die Keys;
    /// bei Fehler leer und nichts geschrieben.
    pub fn put_many(&self, table: &str, rows: Vec<Vec<(&str, String)>>) -> Vec<String> {
        report(self.try_put_many(table, rows)).unwrap_or_default()
    }
    /// Viele Inserts in **einem** Commit (alles oder nichts). `true` = ok.
    pub fn add_many(&self, table: &str, rows: Vec<Vec<(&str, String)>>) -> bool {
        report(self.try_add_many(table, rows)).is_some()
    }

    pub fn try_add(&self, table: &str, values: Vec<(&str, String)>) -> DbResult<()> {
        self.transaction(|tx| tx.add(table, values))
    }
    pub fn try_put(&self, table: &str, values: Vec<(&str, String)>) -> DbResult<String> {
        self.transaction(|tx| tx.put(table, values))
    }
    pub fn try_update(&self, table: &str, key: &str, values: Vec<(&str, String)>) -> DbResult<()> {
        self.transaction(|tx| tx.update(table, key, values))
    }
    /// Insert with native, type-checked parameter values (including real NULL).
    pub fn try_add_values(&self, table: &str, values: Vec<(&str, Value)>) -> DbResult<()> {
        self.transaction(|tx| tx.add_values(table, values))
    }
    /// Upsert with native, type-checked parameter values.
    pub fn try_put_values(&self, table: &str, values: Vec<(&str, Value)>) -> DbResult<String> {
        self.transaction(|tx| tx.put_values(table, values))
    }
    /// Partial update with native, type-checked parameter values.
    pub fn try_update_values(
        &self,
        table: &str,
        key: &str,
        values: Vec<(&str, Value)>,
    ) -> DbResult<()> {
        self.transaction(|tx| tx.update_values(table, key, values))
    }
    /// `Ok(true)` = entfernt, `Ok(false)` = Key nicht vorhanden.
    pub fn try_remove(&self, table: &str, key: &str) -> DbResult<bool> {
        self.transaction(|tx| tx.remove(table, key))
    }
    pub fn try_put_many(
        &self,
        table: &str,
        rows: Vec<Vec<(&str, String)>>,
    ) -> DbResult<Vec<String>> {
        self.transaction(|tx| tx.put_many(table, rows))
    }
    pub fn try_add_many(&self, table: &str, rows: Vec<Vec<(&str, String)>>) -> DbResult<()> {
        self.transaction(|tx| tx.add_many(table, rows))
    }

    // ───── Zeilen lesen (Kurzformen, ungefiltert) ─────

    pub fn print(&self, table: &str) {
        self.table(table).print()
    }
    pub fn count(&self, table: &str) -> usize {
        self.table(table).count()
    }
    pub fn try_count(&self, table: &str) -> DbResult<usize> {
        self.table(table).try_count()
    }
    pub fn all(&self, table: &str) -> Vec<Vec<String>> {
        self.table(table).collect()
    }
    pub fn try_all(&self, table: &str) -> DbResult<Vec<Vec<String>>> {
        self.table(table).try_collect()
    }

    /// Zeile per Key. Leerer `Vec` = nicht gefunden (oder Fehler).
    /// Mit `has()` / `try_get()` lässt sich das unterscheiden.
    pub fn get(&self, table: &str, key: &str) -> Vec<String> {
        report(self.try_get(table, key))
            .flatten()
            .unwrap_or_default()
    }
    pub fn has(&self, table: &str, key: &str) -> bool {
        report(self.try_get(table, key)).flatten().is_some()
    }
    pub fn try_get(&self, table: &str, key: &str) -> DbResult<Option<Vec<String>>> {
        self.st()?.with_snapshot(|s| {
            let Some(row) = s.get_row(table, key)? else {
                return Ok(None);
            };
            let schema = s.schema(table)?;
            Ok(Some(display_row(&schema, &row)))
        })
    }
    /// Fetch a single value without collapsing NULL into an empty string.
    pub fn try_get_value(&self, table: &str, key: &str, col: &str) -> DbResult<Option<Value>> {
        self.st()?.with_snapshot(|s| {
            let Some(raw) = s.get_row(table, key)? else {
                return Ok(None);
            };
            let schema = s.schema(table)?;
            Row::new(&schema, &raw).get_value(col).map(Some)
        })
    }

    // ───── Query-Handle ─────

    /// Einstieg in den Query-Builder.
    ///
    /// ```ignore
    /// db.table("users").filter(with!(r => r[2] == "0")).order_by("name").print();
    /// ```
    pub fn table<'a>(&'a self, name: &str) -> Table<'a> {
        Table::on_db(self, name)
    }

    // ───── Schema-Änderungen (Migrationen) ─────

    pub fn create_index(&self, table: &str, col: &str) -> bool {
        report(self.try_create_index(table, col)).is_some()
    }
    pub fn try_create_index(&self, table: &str, col: &str) -> DbResult<()> {
        self.transaction(|tx| tx.create_index(table, col))
    }
    pub fn create_unique_index(&self, table: &str, col: &str) -> bool {
        report(self.try_create_unique_index(table, col)).is_some()
    }
    pub fn try_create_unique_index(&self, table: &str, col: &str) -> DbResult<()> {
        self.transaction(|tx| tx.create_unique_index(table, col))
    }
    pub fn drop_index(&self, table: &str, col: &str) -> bool {
        report(self.try_drop_index(table, col)).is_some()
    }
    pub fn try_drop_index(&self, table: &str, col: &str) -> DbResult<()> {
        self.transaction(|tx| tx.drop_index(table, col))
    }
    /// Spalten mit Index (inkl. `@key` und `UNIQUE`).
    pub fn indexes(&self, table: &str) -> Vec<String> {
        report(self.try_indexes(table)).unwrap_or_default()
    }
    pub fn try_indexes(&self, table: &str) -> DbResult<Vec<String>> {
        self.st()?.with_snapshot(|s| {
            let d = s.data(table)?;
            Ok(d.schema
                .iter()
                .filter(|c| c.is_indexed())
                .map(|c| c.name.clone())
                .collect())
        })
    }

    /// Neue Spalte; bestehende Zeilen bekommen den Default (Pflicht, wenn Zeilen existieren).
    pub fn add_field(&self, table: &str, col: ColumnDef) -> bool {
        report(self.try_add_field(table, col)).is_some()
    }
    pub fn try_add_field(&self, table: &str, col: ColumnDef) -> DbResult<()> {
        self.transaction(|tx| tx.add_field(table, col))
    }
    pub fn rename_field(&self, table: &str, old: &str, new: &str) -> bool {
        report(self.try_rename_field(table, old, new)).is_some()
    }
    pub fn try_rename_field(&self, table: &str, old: &str, new: &str) -> DbResult<()> {
        self.transaction(|tx| tx.rename_field(table, old, new))
    }
    pub fn remove_field(&self, table: &str, col: &str) -> bool {
        report(self.try_remove_field(table, col)).is_some()
    }
    pub fn try_remove_field(&self, table: &str, col: &str) -> DbResult<()> {
        self.transaction(|tx| tx.remove_field(table, col))
    }
    pub fn rename_table(&self, old: &str, new: &str) -> bool {
        report(self.try_rename_table(old, new)).is_some()
    }
    pub fn try_rename_table(&self, old: &str, new: &str) -> DbResult<()> {
        self.transaction(|tx| tx.rename_table(old, new))
    }

    /// Schema-Versionsnummer der Datenbank (Start: 0).
    pub fn user_version(&self) -> u32 {
        report(self.try_user_version()).unwrap_or(0)
    }
    pub fn try_user_version(&self) -> DbResult<u32> {
        Ok(self.st()?.snapshot()?.user_version())
    }
    pub fn set_user_version(&self, v: u32) -> bool {
        report(self.transaction(|tx| tx.set_user_version(v))).is_some()
    }

    /// Führt alle Schritte mit Version > aktueller `user_version` der Reihe nach aus –
    /// jeder Schritt atomar *zusammen* mit dem Hochsetzen der Version.
    /// Mehrfaches Aufrufen ist harmlos (idempotent).
    ///
    /// ```no_run
    /// # use dbcore::*;
    /// # let db = DBCore::temp();
    /// db.migrate(&[
    ///     (1, |tx| tx.create_table_if_missing("users", schema!{ @key id: i32, name: String })),
    ///     (2, |tx| tx.add_field("users", ColumnDef::new("email", ColumnKind::Text, Some("".into()), false))),
    /// ]).unwrap();
    /// ```
    pub fn migrate(&self, steps: &[Migration]) -> DbResult<u32> {
        let mut steps: Vec<&Migration> = steps.iter().collect();
        steps.sort_by_key(|s| s.0);
        for (v, f) in steps {
            self.transaction(|tx| {
                if tx.user_version() >= *v {
                    return Ok(());
                }
                f(tx)?;
                tx.set_user_version(*v)
            })?;
        }
        self.try_user_version()
    }

    // ───── Eigene Structs ─────

    pub fn create_model<M: Model>(&self, table: &str) -> bool {
        report(self.try_create_model::<M>(table)).is_some()
    }
    pub fn try_create_model<M: Model>(&self, table: &str) -> DbResult<()> {
        self.try_create_if_missing(table, M::schema())
    }
    pub fn put_model<M: Model>(&self, table: &str, m: &M) -> String {
        report(self.try_put_model(table, m)).unwrap_or_default()
    }
    pub fn try_put_model<M: Model>(&self, table: &str, m: &M) -> DbResult<String> {
        self.try_put_values(table, m.to_typed_values())
    }

    // ───── Wartung ─────

    /// Prüft die ganze Datenbank: Entschlüsselung/Authentizität aller Blöcke,
    /// Typen, `NOT NULL`, `CHECK`, `UNIQUE`/Key-Duplikate und Foreign Keys.
    /// Leerer `Vec` = alles in Ordnung.
    pub fn integrity_check(&self) -> Vec<String> {
        match self.st().and_then(|s| s.integrity_check()) {
            Ok(v) => v,
            Err(e) => vec![e.to_string()],
        }
    }
}

// ───────────── Opt-in Traits ─────────────

#[allow(non_camel_case_types)]
pub trait interface {
    /// Startet einen blockierenden HTTP-Server auf `127.0.0.1:<port>`.
    /// Druckt **nichts** – die Ausgabe liegt beim Aufrufer.
    fn open_interface(&self, port: u16);
}

#[allow(non_camel_case_types)]
pub trait csv {
    fn to_csv(&self, table: &str) -> String;
    fn export_csv(&self, table: &str, path: impl AsRef<Path>) -> bool;
}

#[allow(non_camel_case_types)]
pub trait html {
    fn to_html(&self, table: &str) -> String;
    fn export_html(&self, table: &str, path: impl AsRef<Path>) -> bool;
}

#[allow(non_camel_case_types)]
pub trait json {
    fn to_json(&self, table: &str) -> String;
    fn export_json(&self, table: &str, path: impl AsRef<Path>) -> bool;
}

impl interface for DBCore {
    fn open_interface(&self, port: u16) {
        web::serve(self, port);
    }
}

impl csv for DBCore {
    fn to_csv(&self, table: &str) -> String {
        self.table(table).to_csv()
    }
    fn export_csv(&self, table: &str, path: impl AsRef<Path>) -> bool {
        self.table(table).export_csv(path)
    }
}

impl html for DBCore {
    fn to_html(&self, table: &str) -> String {
        self.table(table).to_html()
    }
    fn export_html(&self, table: &str, path: impl AsRef<Path>) -> bool {
        self.table(table).export_html(path)
    }
}

impl json for DBCore {
    fn to_json(&self, table: &str) -> String {
        self.table(table).to_json()
    }
    fn export_json(&self, table: &str, path: impl AsRef<Path>) -> bool {
        self.table(table).export_json(path)
    }
}

#[allow(dead_code)]
fn _assert_send_sync() {
    fn is<T: Send + Sync>() {}
    is::<DBCore>();
    is::<Snapshot>();
    fn send<T: Send>() {}
    send::<Tx>();
}

#[allow(dead_code)]
type _Unused = HashSet<()>;
#[allow(unused_imports)]
use fs as _fs;

#[cfg(test)]
mod value_tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    model! {
        #[derive(Debug, Clone, PartialEq)]
        struct OptionalModel {
            @key id: i32,
            value: Option<String>,
        }
    }

    fn temp_path() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("dbcore-values-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn typed_values_null_empty_and_native_types_round_trip() {
        let dir = temp_path();
        let db = DBCore::try_at(&dir).unwrap();
        db.set_sync(false);
        db.try_create(
            "values",
            schema! {
                @key id: i32,
                empty: String,
                nullable: Option<String>,
                blob: Blob,
                timestamp: Timestamp,
                date: Date,
                time: Time,
                uuid: Uuid,
                doc: Json,
                amount: Decimal,
            },
        )
        .unwrap();
        let uuid = [0x12; 16];
        db.try_add_values(
            "values",
            params! {
                id: 1,
                empty: "",
                nullable: Value::Null,
                blob: Blob(vec![0, 1, 254, 255]),
                timestamp: Timestamp(1_700_000_000_000_000),
                date: Date(20_000),
                time: Time(45_000_000),
                uuid: Uuid(uuid),
                doc: Json("{\"ok\":true}".to_string()),
                amount: Decimal { coefficient: -12345, scale: 2 },
            },
        )
        .unwrap();

        assert_eq!(db.table("values").where_null("nullable").count(), 1);
        assert_eq!(db.table("values").where_not_null("empty").count(), 1);
        assert_eq!(
            db.try_get_value("values", "1", "nullable").unwrap(),
            Some(Value::Null)
        );
        assert_eq!(
            db.try_get_value("values", "1", "empty").unwrap(),
            Some(Value::Text(String::new()))
        );
        assert_eq!(
            db.try_get_value("values", "1", "blob").unwrap(),
            Some(Value::Blob(vec![0, 1, 254, 255]))
        );
        assert_eq!(
            db.try_get_value("values", "1", "uuid").unwrap(),
            Some(Value::Uuid(uuid))
        );
        assert_eq!(
            db.try_get_value("values", "1", "timestamp").unwrap(),
            Some(Value::Timestamp(1_700_000_000_000_000))
        );
        assert_eq!(
            db.try_get_value("values", "1", "date").unwrap(),
            Some(Value::Date(20_000))
        );
        assert_eq!(
            db.try_get_value("values", "1", "time").unwrap(),
            Some(Value::Time(45_000_000))
        );
        assert_eq!(
            db.try_get_value("values", "1", "doc").unwrap(),
            Some(Value::Json("{\"ok\":true}".to_string()))
        );
        assert_eq!(
            db.try_get_value("values", "1", "amount").unwrap(),
            Some(Value::Decimal {
                coefficient: -12345,
                scale: 2
            })
        );
        assert!(db.integrity_check().is_empty());
        drop(db);

        let reopened = DBCore::try_at(&dir).unwrap();
        assert_eq!(
            reopened.try_get_value("values", "1", "nullable").unwrap(),
            Some(Value::Null)
        );
        assert_eq!(reopened.table("values").where_null("nullable").count(), 1);
        drop(reopened);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn typed_parameters_reject_wrong_types_and_preserve_nul_text() {
        let db = DBCore::temp();
        db.try_create("items", schema! { @key id: i32, value: String })
            .unwrap();
        assert!(matches!(
            db.try_add_values("items", params! { id: 1, value: Value::Int(7) }),
            Err(DbError::TypeMismatch(_))
        ));
        db.try_add_values("items", params! { id: 1, value: "\0text" })
            .unwrap();
        assert_eq!(
            db.try_get_value("items", "1", "value").unwrap(),
            Some(Value::Text("\0text".to_string()))
        );
        assert_eq!(db.table("items").where_eq("value", "\0text").count(), 1);
    }

    #[test]
    fn nullable_unique_values_and_decimal_ordering_are_native() {
        let db = DBCore::temp();
        db.try_create(
            "unique_items",
            schema! { @key id: i32, value: Option<String> }.unique(&["value"]),
        )
        .unwrap();
        db.try_add_values("unique_items", params! { id: 1, value: Value::Null })
            .unwrap();
        db.try_add_values("unique_items", params! { id: 2, value: Value::Null })
            .unwrap();
        db.try_add_values("unique_items", params! { id: 3, value: "" })
            .unwrap();
        assert!(matches!(
            db.try_add_values("unique_items", params! { id: 4, value: "" }),
            Err(DbError::Unique(_))
        ));
        assert_eq!(db.table("unique_items").where_null("value").count(), 2);
        assert_eq!(db.table("unique_items").where_eq("value", "").count(), 1);

        db.try_create("decimals", schema! { @key id: i32, value: Decimal })
            .unwrap();
        for (id, coefficient, scale) in [(1, 22, 1), (2, -11, 1), (3, -2, 0), (4, 5, 1)] {
            db.try_add_values(
                "decimals",
                params! {
                    id: id, value: Decimal { coefficient, scale }
                },
            )
            .unwrap();
        }
        assert_eq!(
            db.table("decimals").order_by("value").values("value"),
            ["-2", "-1.1", "0.5", "2.2"]
        );
    }

    #[test]
    fn model_option_fields_keep_null_separate_from_empty_text() {
        let db = DBCore::temp();
        db.try_create_model::<OptionalModel>("models").unwrap();
        db.try_put_model("models", &OptionalModel { id: 1, value: None }).unwrap();
        db.try_put_model("models", &OptionalModel { id: 2, value: Some(String::new()) })
            .unwrap();
        assert_eq!(db.try_get_value("models", "1", "value").unwrap(), Some(Value::Null));
        assert_eq!(
            db.try_get_value("models", "2", "value").unwrap(),
            Some(Value::Text(String::new()))
        );
        let rows: Vec<OptionalModel> = db.table("models").collect_as();
        assert_eq!(rows[0].value, None);
        assert_eq!(rows[1].value.as_deref(), Some(""));
    }
}
