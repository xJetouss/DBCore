//! HTTP-Server + Web-UI. Wird nur über den `interface`-Trait sichtbar.
//!
//! Routen:
//!   GET  /                           – Index
//! `GET  /t/<name>` – Tabelle (?q=,?sort=,?dir=,?page=)
//! `GET  /t/<name>/new` – Insert-Formular
//! `GET  /t/<name>/new_put` – Upsert-Formular
//! `GET  /t/<name>/edit/<idx>` – Edit-Formular
//! `GET  /t/<name>/export.csv|json|html`
//! `POST /t/<name>/add`
//! `POST /t/<name>/put`
//! `POST /t/<name>/update/<idx>`
//! `POST /t/<name>/delete/<idx>`
//!
//! Sicherheit: nur `127.0.0.1`; `Host`-Header wird geprüft (DNS-Rebinding),
//! bei POST zusätzlich `Origin` (CSRF). Jede Verbindung läuft in einem eigenen
//! Thread mit Timeout. Die Datenbank ist selbst thread-sicher: Leser blockieren
//! nie, Schreiber werden von der Engine serialisiert.
//!
//! Zeilen werden über `<idx>.<fingerabdruck>` adressiert. Hat ein anderer
//! Schreiber die Zeile inzwischen geändert oder verschoben, wird die Aktion
//! abgelehnt statt die falsche Zeile zu treffen.

use super::*;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

const MAX_REQUEST: u64 = 1_048_576; // 1 MiB Kopf + Body
const IO_TIMEOUT: Duration = Duration::from_secs(5);

type Resp = (u16, &'static str, String, Option<String>);

// ───────────── Public entry ─────────────

pub(super) fn serve(db: &DBCore, port: u16) {
    let addr = format!("127.0.0.1:{port}");
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => { eprintln!("DBCore: bind {addr}: {e}"); return; }
    };
    // Kein println! hier – der Aufrufer entscheidet, was (oder ob) er druckt.
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let db = db.clone(); // billig (Arc)
                std::thread::spawn(move || { let _ = handle(&db, s, port); });
            }
            Err(e) => eprintln!("DBCore: accept: {e}"),
        }
    }
}

// ───────────── HTTP ─────────────

struct Request {
    method: String,
    path: String,
    host: String,
    origin: Option<String>,
    query: Vec<(String, String)>,
    form: Vec<(String, String)>,
}

impl Request {
    fn q(&self, key: &str) -> Option<&str> {
        self.query.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }
}

fn host_ok(req: &Request, port: u16) -> bool {
    let h = req.host.to_ascii_lowercase();
    h == format!("127.0.0.1:{port}") || h == format!("localhost:{port}")
}

fn origin_ok(req: &Request, port: u16) -> bool {
    match req.origin.as_deref() {
        None => true, // kein Browser-Formular (z. B. curl)
        Some(o) => {
            let o = o.to_ascii_lowercase();
            o == format!("http://127.0.0.1:{port}") || o == format!("http://localhost:{port}")
        }
    }
}

fn handle(db: &DBCore, mut stream: TcpStream, port: u16) -> io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let req = match read_request(&mut stream) {
        Ok(r) => r,
        Err(_) => return Ok(()),
    };
    let resp: Resp = if !host_ok(&req, port) {
        (403, "text/plain", "Forbidden: unerwarteter Host".to_string(), None)
    } else if req.method == "POST" && !origin_ok(&req, port) {
        (403, "text/plain", "Forbidden: fremder Origin".to_string(), None)
    } else {
        route(db, &req)
    };
    let (status, ctype, body, extra) = resp;
    send(&mut stream, status, ctype, &body, extra.as_deref())
}

fn not_found(msg: &str) -> Resp {
    (404, "text/html", render_error(msg), None)
}

fn page(r: Result<String>) -> Resp {
    match r {
        Ok(h)  => (200, "text/html", h, None),
        Err(e) => not_found(&e.to_string()),
    }
}

fn redirect(table: &str, kind: &str, msg: &str) -> Resp {
    (303, "text/plain", String::new(),
     Some(format!("Location: /t/{table}?{}", qs(&[(kind, msg)]))))
}

fn flash(table: &str, ok_msg: &str, r: Result<()>) -> Resp {
    match r {
        Ok(())  => redirect(table, "msg", ok_msg),
        Err(e)  => redirect(table, "err", &e.to_string()),
    }
}

fn download(db: &DBCore, name: &str, ext: &str, ctype: &'static str) -> Resp {
    match read_table(db, name) {
        Ok((sc, rows)) => {
            let body = match ext {
                "csv"  => format_csv(&sc, &rows),
                "json" => format_json(&sc, &rows),
                _      => format_html(name, &sc, &rows),
            };
            (200, ctype, body, Some(format!(
                "Content-Disposition: attachment; filename=\"{name}.{ext}\""
            )))
        }
        Err(e) => (404, "text/plain", e.to_string(), None),
    }
}

/// Tabelle als `(Schema, Zeilen)` – ein konsistenter Snapshot.
fn read_table(db: &DBCore, name: &str) -> Result<(Vec<ColDef>, Vec<Vec<String>>)> {
    db.st()?.with_snapshot(|s| {
        let d = s.data(name)?;
        Ok((d.schema.clone(), d.rows.clone()))
    })
}

fn row_hash(row: &[String]) -> u32 {
    let mut h = DefaultHasher::new();
    row.hash(&mut h);
    h.finish() as u32
}

/// `<idx>.<fingerabdruck>` – siehe Modul-Doku.
fn row_token(idx: usize, row: &[String]) -> String {
    format!("{idx}.{:08x}", row_hash(row))
}

fn parse_token(arg: &str) -> Result<(usize, u32)> {
    let bad = || DbError::RowNotFound(format!("Zeilen-Adresse '{arg}'"));
    let (i, h) = arg.split_once('.').ok_or_else(bad)?;
    Ok((i.parse().map_err(|_| bad())?, u32::from_str_radix(h, 16).map_err(|_| bad())?))
}

const STALE: &str = "Die Zeile wurde inzwischen von jemand anderem geändert oder gelöscht – bitte Seite neu laden";

fn check_row(table: &str, rows: &[Vec<String>], idx: usize, hash: u32) -> Result<()> {
    let row = rows.get(idx).ok_or_else(|| DbError::RowNotFound(format!("Index {idx} in '{table}'")))?;
    if row_hash(row) != hash { return Err(DbError::RowNotFound(STALE.into())); }
    Ok(())
}

fn route(db: &DBCore, req: &Request) -> Resp {
    let p = req.path.as_str();

    if req.method == "GET" && p == "/" {
        return (200, "text/html", render_index(db), None);
    }

    if let Some(rest) = p.strip_prefix("/t/") {
        let mut it = rest.splitn(3, '/');
        let name = it.next().unwrap_or("");
        let action = it.next().unwrap_or("");
        let arg = it.next().unwrap_or("");
        if !valid_name(name) {
            return not_found("Ungültiger Tabellenname");
        }

        return match (req.method.as_str(), action) {
            ("GET", "")        => page(render_table(db, name, req)),
            ("GET", "new")     => page(render_form(db, name, Form::Add, None)),
            ("GET", "new_put") => page(render_form(db, name, Form::Put, None)),
            ("GET", "edit")    => page(
                parse_token(arg).and_then(|(i, h)| {
                    let (_, rows) = read_table(db, name)?;
                    check_row(name, &rows, i, h)?;
                    render_form(db, name, Form::Edit, Some(i))
                })
            ),
            ("GET", "export.csv")  => download(db, name, "csv", "text/csv"),
            ("GET", "export.json") => download(db, name, "json", "application/json"),
            ("GET", "export.html") => download(db, name, "html", "text/html"),

            ("POST", "add") => flash(name, "Hinzugefügt",
                read_table(db, name).and_then(|(sc, _)|
                    db.try_add(name, form_values(&sc, &req.form, true)))),
            ("POST", "put") => flash(name, "Gespeichert",
                read_table(db, name).and_then(|(sc, _)|
                    db.try_put(name, form_values(&sc, &req.form, true)).map(|_| ()))),
            ("POST", "update") => flash(name, "Aktualisiert",
                parse_token(arg).and_then(|(i, h)| update_row(db, name, i, h, &req.form))),
            ("POST", "delete") => flash(name, "Gelöscht",
                parse_token(arg).and_then(|(i, h)| delete_row(db, name, i, h))),
            _ => not_found("Nicht gefunden"),
        };
    }
    not_found("Nicht gefunden")
}

/// Formulardaten → `(Spalte, Wert)`.
///
/// `drop_empty` (Add/Put): leere Felder für `@key`- und Default-Spalten
/// werden weggelassen, damit Auto-Key bzw. Default greifen – sonst würde
/// ein leeres Key-Feld als `""` gespeichert.
fn form_values<'a>(
    schema: &[ColDef],
    form: &'a [(String, String)],
    drop_empty: bool,
) -> Vec<(&'a str, String)> {
    form.iter()
        .filter(|(k, v)| {
            if !drop_empty || !v.is_empty() { return true; }
            match schema.iter().find(|c| c.name == *k) {
                Some(c) => !(c.key || c.default.is_some()),
                None => true,
            }
        })
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect()
}

/// Ersetzt die Zeile atomar – aber nur, wenn sie noch unverändert ist.
fn update_row(db: &DBCore, table: &str, idx: usize, hash: u32, form: &[(String, String)]) -> Result<()> {
    db.transaction(|tx| {
        let d = tx.view(table)?;
        check_row(table, &d.rows, idx, hash)?;
        let row = build_row(&d.schema, &form_values(&d.schema, form, false))?;
        tx.replace_at(table, idx, row)
    })
}

fn delete_row(db: &DBCore, table: &str, idx: usize, hash: u32) -> Result<()> {
    db.transaction(|tx| {
        let d = tx.view(table)?;
        check_row(table, &d.rows, idx, hash)?;
        tx.delete_at(table, &[idx]).map(|_| ())
    })
}

fn read_request(stream: &mut TcpStream) -> io::Result<Request> {
    // `take` begrenzt Kopf + Body insgesamt – kein unbegrenztes Einlesen.
    let mut reader = BufReader::new(stream.try_clone()?.take(MAX_REQUEST));
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path_q = parts.next().unwrap_or("/").to_string();

    let mut content_length: usize = 0;
    let mut host = String::new();
    let mut origin: Option<String> = None;
    loop {
        let mut h = String::new();
        reader.read_line(&mut h)?;
        if h == "\r\n" || h == "\n" || h.is_empty() { break; }
        if let Some((k, v)) = h.split_once(':') {
            let v = v.trim();
            match k.trim().to_ascii_lowercase().as_str() {
                "content-length" => content_length = v.parse().unwrap_or(0),
                "host"           => host = v.to_string(),
                "origin"         => origin = Some(v.to_string()),
                _ => {}
            }
        }
    }
    if content_length as u64 >= MAX_REQUEST {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Body zu groß"));
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 { reader.read_exact(&mut body)?; }

    let (path, query_str) = match path_q.split_once('?') {
        Some((p, q)) => (p.to_string(), q),
        None => (path_q, ""),
    };
    let query = parse_kv(query_str);
    let form  = parse_kv(&String::from_utf8_lossy(&body));

    Ok(Request { method, path, host, origin, query, form })
}

fn send(
    stream: &mut TcpStream,
    status: u16,
    ctype: &str,
    body: &str,
    extra: Option<&str>,
) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        303 => "See Other",
        403 => "Forbidden",
        404 => "Not Found",
        _   => "OK",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {ctype}; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         X-Frame-Options: DENY\r\n\
         X-Content-Type-Options: nosniff\r\n",
        body.as_bytes().len()
    );
    if let Some(e) = extra {
        head.push_str(e);
        head.push_str("\r\n");
    }
    head.push_str("Connection: close\r\n\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

// ───────────── URL / Form ─────────────

fn parse_kv(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for pair in s.split('&') {
        if pair.is_empty() { continue; }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.push((url_decode(k), url_decode(v)));
    }
    out
}

fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => { out.push(b' '); i += 1; }
            b'%' if i + 2 < b.len() => {
                match (hex(b[i+1]), hex(b[i+2])) {
                    (Some(h), Some(l)) => { out.push(h*16 + l); i += 3; }
                    _ => { out.push(b'%'); i += 1; }
                }
            }
            c => { out.push(c); i += 1; }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' =>
                out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn qs(params: &[(&str, &str)]) -> String {
    params.iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

// ───────────── Layout ─────────────

fn list_tables(db: &DBCore) -> Vec<(String, usize)> {
    db.tables().into_iter()
        .map(|t| {
            let n = db.try_count(&t).unwrap_or(0);
            (t, n)
        })
        .collect()
}

fn render_error(msg: &str) -> String {
    format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Fehler</title>\
         <style>{STYLE}</style></head><body>\
         <div style=\"max-width:640px;margin:4rem auto;padding:2rem\">\
         <h1 style=\"color:var(--danger)\">Fehler</h1>\
         <p>{}</p>\
         <p><a class=\"btn\" href=\"/\">← zur Startseite</a></p>\
         </div></body></html>",
        html_escape(msg)
    )
}

fn shell(title: &str, active: Option<&str>, db: &DBCore, body: &str) -> String {
    let tables = list_tables(db);
    let sidebar = render_sidebar(&tables, active);
    format!(
        "<!DOCTYPE html><html lang=\"de\"><head>\
         <meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{title}</title>\
         <style>{STYLE}</style></head><body>\
         <header class=\"top\">\
           <a class=\"brand\" href=\"/\"><span class=\"dot\"></span>DBCore</a>\
           <span class=\"path\">{dir}</span>\
           <span class=\"grow\"></span>\
           <button class=\"ghost\" type=\"button\" data-theme-toggle title=\"Theme wechseln\">◐</button>\
         </header>\
         <div class=\"layout\">{sidebar}\
           <main class=\"main\">{body}</main>\
         </div>\
         <script>{SCRIPT}</script></body></html>",
        title = html_escape(title),
        dir = html_escape(&db.dir.display().to_string()),
        sidebar = sidebar,
        body = body,
        STYLE = STYLE,
        SCRIPT = SCRIPT,
    )
}

fn render_sidebar(tables: &[(String, usize)], active: Option<&str>) -> String {
    let mut b = String::new();
    b.push_str("<aside class=\"side\">");
    b.push_str("<div class=\"side-search\">\
                <input id=\"tablefilter\" type=\"text\" placeholder=\"Tabellen filtern…\" \
                oninput=\"filterTables(this.value)\" autocomplete=\"off\"></div>");
    b.push_str("<ul class=\"side-list\" id=\"tablelist\">");
    if tables.is_empty() {
        b.push_str("<li class=\"empty-row\">Keine Tabellen</li>");
    }
    for (name, count) in tables {
        let cls = if Some(name.as_str()) == active { " class=\"active\"" } else { "" };
        b.push_str(&format!(
            "<li data-name=\"{0}\"><a href=\"/t/{0}\"{1}>\
             <span class=\"tname\">{0}</span>\
             <span class=\"tcount\">{2}</span></a></li>",
            html_escape(name), cls, count
        ));
    }
    b.push_str("</ul></aside>");
    b.push_str("<script>function filterTables(v){v=v.toLowerCase();\
        document.querySelectorAll('#tablelist li').forEach(function(li){\
        var n=(li.dataset.name||'').toLowerCase();\
        li.style.display=n.indexOf(v)<0?'none':'';});}</script>");
    b
}

fn render_index(db: &DBCore) -> String {
    let tables = list_tables(db);
    let total_rows: usize = tables.iter().map(|(_, c)| c).sum();
    let mut b = String::new();
    b.push_str("<h1 class=\"title\">Übersicht</h1>");
    b.push_str("<p class=\"sub\">Verzeichnis <code>");
    b.push_str(&html_escape(&db.dir.display().to_string()));
    b.push_str("</code></p>");

    b.push_str("<div class=\"stats\">");
    b.push_str(&format!(
        "<div class=\"stat\"><div class=\"v\">{}</div><div class=\"l\">Tabellen</div></div>",
        tables.len()
    ));
    b.push_str(&format!(
        "<div class=\"stat\"><div class=\"v\">{}</div><div class=\"l\">Zeilen gesamt</div></div>",
        total_rows
    ));
    b.push_str("</div>");

    if tables.is_empty() {
        b.push_str("<div class=\"empty\"><div class=\"empty-icon\">◌</div>\
                    <div>Noch keine Tabellen</div>\
                    <div class=\"muted\" style=\"font-size:.88em;margin-top:.3rem\">\
                    Lege eine Tabelle mit <code>db.create(…)</code> an.</div></div>");
    } else {
        b.push_str("<div class=\"table-wrap\"><table class=\"data\"><thead><tr>\
                    <th>Tabelle</th>\
                    <th style=\"width:100px;text-align:right\">Zeilen</th>\
                    <th class=\"th-action\"></th></tr></thead><tbody>");
        for (name, count) in &tables {
            b.push_str(&format!(
                "<tr data-href=\"/t/{0}\">\
                 <td><a class=\"tlink\" href=\"/t/{0}\">{0}</a></td>\
                 <td class=\"mono\" style=\"text-align:right\">{1}</td>\
                 <td class=\"actions\"><a class=\"btn small\" href=\"/t/{0}\">öffnen</a></td>\
                 </tr>",
                html_escape(name), count
            ));
        }
        b.push_str("</tbody></table></div>");
    }
    shell("DBCore", None, db, &b)
}

// ───────────── Table page ─────────────

fn render_table(db: &DBCore, name: &str, req: &Request) -> Result<String> {
    let (schema, all_rows) = read_table(db, name)?;
    let total_all = all_rows.len();

    let q = req.q("q").unwrap_or("").to_string();
    let sort = req.q("sort").map(String::from).filter(|s| !s.is_empty());
    let dir = req.q("dir").unwrap_or("asc").to_string();
    let page: usize = req.q("page")
        .and_then(|p| p.parse().ok())
        .filter(|&p| p >= 1)
        .unwrap_or(1);

    // Jede Zeile trägt ihren ORIGINAL-Index. Edit/Delete adressieren darüber –
    // der Listen-Index würde bei aktiver Suche/Sortierung die falsche Zeile treffen.
    let mut rows: Vec<(usize, Vec<String>)> = all_rows.into_iter().enumerate().collect();

    // Filter
    if !q.is_empty() {
        let ql = q.to_lowercase();
        rows.retain(|(_, r)| r.iter().any(|v| v.to_lowercase().contains(&ql)));
    }

    // Sort
    if let Some(col) = &sort {
        if let Some(idx) = schema.iter().position(|c| &c.name == col) {
            let kind = schema[idx].kind;
            rows.sort_by(|a, b| {
                let ord = cmp_values(kind, cell(&a.1, idx), cell(&b.1, idx));
                if dir == "desc" { ord.reverse() } else { ord }
            });
        }
    }

    let total_filtered = rows.len();
    let per_page = 25usize;
    let total_pages = (total_filtered + per_page - 1) / per_page;
    let page = page.min(total_pages.max(1));
    let start = (page - 1) * per_page;
    let end = (start + per_page).min(total_filtered);
    let page_rows = &rows[start..end];

    let mut b = String::new();

    // Breadcrumb
    b.push_str(&format!(
        "<div class=\"crumbs\"><a href=\"/\">Start</a> <span class=\"sep\">/</span> \
         <span class=\"cur\">{}</span></div>",
        html_escape(name)
    ));

    // Title + Action-Bar
    b.push_str("<div class=\"page-head\">");
    b.push_str(&format!("<h1 class=\"title\">{}</h1>", html_escape(name)));
    b.push_str("<div class=\"page-actions\">");
    b.push_str(&format!("<a class=\"btn primary\" href=\"/t/{}/new\">+ Neu</a>",
                        html_escape(name)));
    b.push_str(&format!("<a class=\"btn\" href=\"/t/{}/new_put\">↑ Upsert</a>",
                        html_escape(name)));
    b.push_str(&format!(
        "<details class=\"dd\"><summary class=\"btn\">↓ Export</summary>\
         <div class=\"dd-menu\">\
           <a href=\"/t/{0}/export.csv\">CSV</a>\
           <a href=\"/t/{0}/export.json\">JSON</a>\
           <a href=\"/t/{0}/export.html\">HTML</a>\
         </div></details>",
        html_escape(name)
    ));
    b.push_str("</div></div>");

    // Toast (Erfolg / Fehler)
    if let Some(msg) = req.q("msg") {
        b.push_str(&format!(
            "<div class=\"toast\" id=\"toast\">{}</div>", html_escape(msg)
        ));
    }
    if let Some(msg) = req.q("err") {
        b.push_str(&format!(
            "<div class=\"toast err\" id=\"toast\">{}</div>", html_escape(msg)
        ));
    }

    // Stats
    b.push_str("<div class=\"stats\">");
    b.push_str(&format!(
        "<div class=\"stat\"><div class=\"v\">{}{}</div><div class=\"l\">Zeilen</div></div>",
        total_filtered,
        if total_filtered != total_all {
            format!(" <span class=\"muted\" style=\"font-size:.8em\">/ {}</span>", total_all)
        } else { String::new() }
    ));
    b.push_str(&format!(
        "<div class=\"stat\"><div class=\"v\">{}</div><div class=\"l\">Spalten</div></div>",
        schema.len()
    ));
    if let Some(k) = schema.iter().find(|c| c.key) {
        b.push_str(&format!(
            "<div class=\"stat\"><div class=\"v mono\">{}</div><div class=\"l\">Key</div></div>",
            html_escape(&k.name)
        ));
    }
    b.push_str("</div>");

    // Search
    let clear = if q.is_empty() { String::new() } else {
        format!("<a class=\"btn ghost small\" href=\"/t/{}\" title=\"Filter entfernen\">×</a>",
                html_escape(name))
    };
    b.push_str(&format!(
        "<form class=\"searchbar\" method=\"GET\" action=\"/t/{0}\">\
         <input type=\"hidden\" name=\"sort\" value=\"{1}\">\
         <input type=\"hidden\" name=\"dir\" value=\"{2}\">\
         <input type=\"text\" name=\"q\" placeholder=\"In Tabelle suchen…\" \
                value=\"{3}\" id=\"q\" autocomplete=\"off\">\
         <button class=\"btn\" type=\"submit\">Suchen</button>\
         {4}</form>",
        html_escape(name),
        html_escape(sort.as_deref().unwrap_or("")),
        html_escape(&dir),
        html_escape(&q),
        clear
    ));

    // Table
    if schema.is_empty() {
        b.push_str("<div class=\"empty\"><div class=\"empty-icon\">◌</div>Kein Schema</div>");
    } else {
        b.push_str("<div class=\"table-wrap\"><table class=\"data\"><thead><tr>");
        for c in &schema {
            let is_sorted = sort.as_deref() == Some(c.name.as_str());
            let arrow = if is_sorted {
                if dir == "desc" { " ↓" } else { " ↑" }
            } else { "" };
            let next_dir = if is_sorted && dir == "asc" { "desc" } else { "asc" };
            let href = format!(
                "/t/{}?{}", name,
                qs(&[("sort", &c.name), ("dir", next_dir), ("q", &q)])
            );
            let cls = if c.key { " class=\"key\"" } else { "" };
            b.push_str(&format!(
                "<th{}><a href=\"{}\">{}{}</a></th>",
                cls, html_escape(&href), html_escape(&c.name), arrow
            ));
        }
        b.push_str("<th class=\"th-action\"></th></tr></thead><tbody>");

        if page_rows.is_empty() {
            let msg = if q.is_empty() { "Noch keine Einträge." } else { "Keine Treffer." };
            b.push_str(&format!(
                "<tr><td class=\"empty-row\" colspan=\"{}\">{}</td></tr>",
                schema.len() + 1, msg
            ));
        } else {
            for (idx, r) in page_rows {
                let tok = row_token(*idx, r);
                b.push_str(&format!(
                    "<tr data-href=\"/t/{0}/edit/{1}\">",
                    html_escape(name), tok
                ));
                for i in 0..schema.len() {
                    let v = cell(r, i);
                    if v.is_empty() {
                        b.push_str("<td class=\"mono empty-val\">—</td>");
                    } else {
                        b.push_str(&format!("<td class=\"mono\">{}</td>", html_escape(v)));
                    }
                }
                b.push_str(&format!(
                    "<td class=\"actions\">\
                     <a class=\"btn small ghost icon\" href=\"/t/{0}/edit/{1}\" \
                        title=\"Bearbeiten\">{SVG_EDIT}</a>\
                     <form method=\"POST\" action=\"/t/{0}/delete/{1}\" \
                           data-confirm=\"Zeile wirklich löschen?\">\
                     <button class=\"btn small ghost danger icon\" type=\"submit\" \
                             title=\"Löschen\">{SVG_DELETE}</button>\
                     </form></td></tr>",
                    html_escape(name), tok,
                    SVG_EDIT = SVG_EDIT, SVG_DELETE = SVG_DELETE,
                ));
            }
        }
        b.push_str("</tbody></table></div>");
    }

    // Pagination
    if total_pages > 1 {
        b.push_str("<div class=\"pagination\">");
        let link = |p: usize, label: &str, current: bool| {
            if current {
                format!("<span class=\"page current\">{}</span>", label)
            } else {
                let href = format!(
                    "/t/{}?{}", name,
                    qs(&[
                        ("sort", sort.as_deref().unwrap_or("")),
                        ("dir", &dir),
                        ("q", &q),
                        ("page", &p.to_string()),
                    ])
                );
                format!("<a class=\"page\" href=\"{}\">{}</a>", html_escape(&href), label)
            }
        };
        if page > 1 { b.push_str(&link(page - 1, "‹", false)); }
        let (lo, hi) = (page.saturating_sub(2).max(1), (page + 2).min(total_pages));
        if lo > 1 {
            b.push_str(&link(1, "1", page == 1));
            if lo > 2 { b.push_str("<span class=\"dots\">…</span>"); }
        }
        for p in lo..=hi { b.push_str(&link(p, &p.to_string(), p == page)); }
        if hi < total_pages {
            if hi + 1 < total_pages { b.push_str("<span class=\"dots\">…</span>"); }
            b.push_str(&link(total_pages, &total_pages.to_string(), page == total_pages));
        }
        if page < total_pages { b.push_str(&link(page + 1, "›", false)); }
        b.push_str(&format!(
            "<span class=\"muted pginfo\">Seite {} / {} · {} Einträge</span>",
            page, total_pages, total_filtered
        ));
        b.push_str("</div>");
    }

    Ok(shell(name, Some(name), db, &b))
}

// ───────────── Icons (SVG, rendern überall gleich) ─────────────

const SVG_EDIT: &str = "<svg viewBox=\"0 0 16 16\" fill=\"none\" stroke=\"currentColor\" \
    stroke-width=\"1.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\">\
    <path d=\"M11.5 2.5l2 2L5 13l-2.5.5.5-2.5 8.5-8.5z\"/></svg>";

const SVG_DELETE: &str = "<svg viewBox=\"0 0 16 16\" fill=\"none\" stroke=\"currentColor\" \
    stroke-width=\"1.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\">\
    <path d=\"M3 4h10M6.5 4V2.5h3V4M5 4l.5 9h5L11 4\"/></svg>";

// ───────────── Form ─────────────

#[derive(Clone, Copy)]
enum Form { Add, Put, Edit }

fn render_form(db: &DBCore, name: &str, mode: Form, idx: Option<usize>) -> Result<String> {
    let (schema, rows) = read_table(db, name)?;
    // Edit mit ungültigem Index darf NICHT still ein leeres Formular zeigen –
    // das würde beim Speichern Zeile 0 überschreiben.
    let existing: Option<&Vec<String>> = match mode {
        Form::Edit => {
            let i = idx.ok_or_else(|| DbError::RowNotFound("kein Index".into()))?;
            Some(rows.get(i).ok_or_else(||
                DbError::RowNotFound(format!("Index {i} in '{name}'")))?)
        }
        _ => None,
    };

    let (title, action, submit, hint) = match mode {
        Form::Add  => (format!("Neue Zeile – {name}"),
                       format!("/t/{name}/add"), "Hinzufügen", None),
        Form::Put  => (format!("Upsert – {name}"),
                       format!("/t/{name}/put"), "Speichern",
                       Some("Mit @key-Wert wird eine existierende Zeile ersetzt. \
                             Bleibt er leer, wird er automatisch vergeben (Int-Key) \
                             oder der Default genutzt.")),
        Form::Edit => (format!("Bearbeiten – {name}"),
                       format!("/t/{name}/update/{}", match (idx, existing) {
                           (Some(i), Some(r)) => row_token(i, r),
                           _ => "0.0".to_string(),
                       }), "Speichern", None),
    };

    let mut b = String::new();
    b.push_str(&format!(
        "<div class=\"crumbs\"><a href=\"/\">Start</a> <span class=\"sep\">/</span> \
         <a href=\"/t/{0}\">{0}</a> <span class=\"sep\">/</span> \
         <span class=\"cur\">{1}</span></div>",
        html_escape(name), html_escape(&title)
    ));
    b.push_str(&format!("<h1 class=\"title\">{}</h1>", html_escape(&title)));
    if let Some(h) = hint {
        b.push_str(&format!("<p class=\"sub\">{}</p>", html_escape(h)));
    }

    b.push_str(&format!(
        "<form class=\"card\" method=\"POST\" action=\"{}\">",
        html_escape(&action)
    ));
    for (i, c) in schema.iter().enumerate() {
        let current = match existing {
            Some(r) => cell(r, i).to_string(),
            None => c.default.clone().unwrap_or_default(),
        };
        let kind = match c.kind {
            ColumnKind::Int   => "Ganzzahl",
            ColumnKind::Float => "Kommazahl",
            ColumnKind::Bool  => "true/false",
            ColumnKind::Text  => "Text",
        };
        let key_marker = if c.key { "<span class=\"keymark\">@key</span>" } else { "" };
        let default_hint = c.default.as_ref()
            .map(|d| format!(" · Default <code>{}</code>", html_escape(d)))
            .unwrap_or_default();
        let placeholder = match (&c.default, c.key, mode) {
            (Some(d), _, _)          => d.clone(),
            (None, true, Form::Put)  => "automatisch".to_string(),
            _                        => String::new(),
        };
        b.push_str(&format!(
            "<label class=\"field\">\
             <span class=\"flabel\">\
               <span class=\"fname\">{}</span>{}\
               <span class=\"fmeta\">{} {}</span>\
             </span>\
             <input type=\"text\" name=\"{}\" value=\"{}\" \
                    placeholder=\"{}\" autocomplete=\"off\" spellcheck=\"false\">\
             </label>",
            html_escape(&c.name), key_marker,
            kind, default_hint,
            html_escape(&c.name),
            html_escape(&current),
            html_escape(&placeholder)
        ));
    }
    b.push_str("<div class=\"form-actions\">");
    b.push_str(&format!("<button class=\"btn primary\" type=\"submit\">{}</button>",
                        html_escape(submit)));
    b.push_str(&format!("<a class=\"btn\" href=\"/t/{}\">Abbrechen</a>",
                        html_escape(name)));
    b.push_str("</div></form>");

    Ok(shell(&title, Some(name), db, &b))
}

// ───────────── CSS ─────────────

const STYLE: &str = r#"
*,*::before,*::after{box-sizing:border-box}
:root{
  --bg:#ffffff;
  --surface:#ffffff;
  --surface-2:#f9fafb;
  --hover:#f3f4f6;
  --border:#e5e7eb;
  --border-strong:#d1d5db;
  --fg:#111827;
  --fg-2:#374151;
  --muted:#6b7280;
  --muted-2:#9ca3af;
  --accent:#2563eb;
  --accent-hover:#1d4ed8;
  --accent-fg:#ffffff;
  --accent-soft:#eff6ff;
  --danger:#dc2626;
  --danger-bg:#fef2f2;
  --success:#059669;
  --success-bg:#ecfdf5;
  --radius:6px;
  --radius-lg:8px;
  --shadow-sm:0 1px 2px rgba(0,0,0,.04);
  --shadow:0 1px 3px rgba(0,0,0,.06),0 1px 2px rgba(0,0,0,.04);
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
}
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
    --bg:#0a0a0a;
    --surface:#141414;
    --surface-2:#1c1c1c;
    --hover:#1f1f1f;
    --border:#262626;
    --border-strong:#3f3f46;
    --fg:#f5f5f5;
    --fg-2:#d4d4d8;
    --muted:#a1a1aa;
    --muted-2:#71717a;
    --accent:#3b82f6;
    --accent-hover:#60a5fa;
    --accent-fg:#ffffff;
    --accent-soft:#172554;
    --danger:#f87171;
    --danger-bg:#2a0e0e;
    --success:#34d399;
    --success-bg:#052e1c;
    --shadow-sm:0 1px 2px rgba(0,0,0,.5);
    --shadow:0 1px 3px rgba(0,0,0,.6);
  }
}
:root[data-theme="dark"]{
  --bg:#0a0a0a;
  --surface:#141414;
  --surface-2:#1c1c1c;
  --hover:#1f1f1f;
  --border:#262626;
  --border-strong:#3f3f46;
  --fg:#f5f5f5;
  --fg-2:#d4d4d8;
  --muted:#a1a1aa;
  --muted-2:#71717a;
  --accent:#3b82f6;
  --accent-hover:#60a5fa;
  --accent-fg:#ffffff;
  --accent-soft:#172554;
  --danger:#f87171;
  --danger-bg:#2a0e0e;
  --success:#34d399;
  --success-bg:#052e1c;
  --shadow-sm:0 1px 2px rgba(0,0,0,.5);
  --shadow:0 1px 3px rgba(0,0,0,.6);
}
html,body{margin:0;padding:0}
body{
  background:var(--bg);color:var(--fg);
  font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased;
}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
code,.mono{font-family:var(--mono);font-size:.92em}
code{background:var(--surface-2);padding:.05em .35em;border-radius:4px}

/* Topbar */
header.top{
  height:52px;display:flex;align-items:center;gap:1rem;
  padding:0 1.25rem;background:var(--surface);
  border-bottom:1px solid var(--border);
  position:sticky;top:0;z-index:30;
}
header.top .brand{
  display:inline-flex;align-items:center;gap:.5rem;
  font-weight:600;color:var(--fg);letter-spacing:-.01em;font-size:.95rem;
}
header.top .brand:hover{text-decoration:none}
header.top .brand .dot{
  width:8px;height:8px;border-radius:2px;background:var(--accent);
}
header.top .path{color:var(--muted);font-family:var(--mono);font-size:.8rem}
header.top .grow{flex:1}
header.top .ghost{
  background:transparent;border:1px solid transparent;color:var(--muted);
  cursor:pointer;padding:.35rem .55rem;border-radius:var(--radius);
  font:inherit;font-size:1rem;line-height:1;
}
header.top .ghost:hover{background:var(--hover);color:var(--fg)}

/* Layout */
.layout{display:grid;grid-template-columns:240px 1fr;min-height:calc(100vh - 52px)}
@media (max-width:800px){
  .layout{grid-template-columns:1fr}
}
aside.side{
  border-right:1px solid var(--border);background:var(--surface);
  padding:1rem .75rem;overflow-y:auto;
  position:sticky;top:52px;height:calc(100vh - 52px);
}
@media (max-width:800px){
  aside.side{
    position:static;height:auto;max-height:40vh;
    border-right:none;border-bottom:1px solid var(--border);
  }
}
.side-search{margin-bottom:.5rem}
.side-search input{
  width:100%;padding:.4rem .6rem;border-radius:var(--radius);
  border:1px solid var(--border);background:var(--bg);color:var(--fg);
  font:inherit;font-size:.85em;transition:border-color .1s;
}
.side-search input:focus{outline:none;border-color:var(--accent)}
.side-list{list-style:none;margin:0;padding:0}
.side-list li{margin:1px 0}
.side-list li.empty-row{color:var(--muted);font-size:.85em;padding:.5rem}
.side-list a{
  display:flex;justify-content:space-between;align-items:center;
  gap:.5rem;padding:.35rem .55rem;border-radius:var(--radius);
  color:var(--fg);font-size:.9em;transition:background .08s;
}
.side-list a:hover{background:var(--hover);text-decoration:none}
.side-list a.active{background:var(--accent);color:var(--accent-fg)}
.side-list a.active .tcount{background:rgba(255,255,255,.2);color:inherit}
.side-list .tname{
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  font-family:var(--mono);font-size:.92em;
}
.side-list .tcount{
  font-size:.72em;background:var(--surface-2);color:var(--muted);
  padding:.05rem .4rem;border-radius:999px;font-variant-numeric:tabular-nums;
}

/* Main */
main.main{padding:1.5rem 2rem 4rem;max-width:1280px;margin:0 auto}
@media (max-width:640px){main.main{padding:1rem}}

.crumbs{color:var(--muted);font-size:.85em;margin-bottom:.5rem}
.crumbs .sep{margin:0 .3rem;color:var(--muted-2)}
.crumbs .cur{color:var(--fg);font-family:var(--mono)}

.title{font-size:1.25rem;font-weight:600;margin:0 0 .15rem;letter-spacing:-.01em}
.sub{color:var(--muted);margin:0 0 1rem;font-size:.9em}

.page-head{
  display:flex;align-items:center;justify-content:space-between;
  gap:1rem;flex-wrap:wrap;margin-bottom:1rem;
}
.page-actions{display:flex;gap:.4rem;flex-wrap:wrap;align-items:center}

/* Buttons */
.btn{
  display:inline-flex;align-items:center;gap:.35rem;
  padding:.4rem .75rem;border-radius:var(--radius);
  font:inherit;font-size:.88em;font-weight:500;line-height:1.2;
  border:1px solid var(--border-strong);
  background:var(--surface);color:var(--fg);
  cursor:pointer;text-decoration:none;
  transition:background .1s,border-color .1s,color .1s;
  white-space:nowrap;
}
.btn:hover{background:var(--hover);text-decoration:none}
.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-fg)}
.btn.primary:hover{background:var(--accent-hover);border-color:var(--accent-hover)}
.btn.ghost{border-color:transparent;background:transparent;color:var(--muted)}
.btn.ghost:hover{background:var(--hover);color:var(--fg)}
.btn.small{padding:.2rem .5rem;font-size:.85em}
.btn.icon{padding:0;width:26px;height:26px;justify-content:center;flex-shrink:0}
.btn.icon svg{width:14px;height:14px;display:block}
.btn.danger{color:var(--danger)}
.btn.danger:hover{background:var(--danger-bg);color:var(--danger)}

/* Dropdown */
.dd{position:relative;display:inline-block}
.dd>summary{list-style:none;cursor:pointer}
.dd>summary::-webkit-details-marker{display:none}
.dd[open]>summary{background:var(--hover)}
.dd-menu{
  position:absolute;top:100%;right:0;margin-top:.25rem;
  background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);box-shadow:var(--shadow);min-width:130px;
  z-index:10;padding:.25rem;
}
.dd-menu a{
  display:block;padding:.35rem .6rem;border-radius:4px;
  color:var(--fg);font-size:.88em;
}
.dd-menu a:hover{background:var(--hover);text-decoration:none}

/* Stats */
.stats{display:flex;gap:.6rem;flex-wrap:wrap;margin-bottom:1rem}
.stat{
  background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);padding:.55rem .85rem;
  min-width:90px;box-shadow:var(--shadow-sm);
}
.stat .v{
  font-size:1.05em;font-weight:600;font-variant-numeric:tabular-nums;
  line-height:1.2;color:var(--fg);
}
.stat .v.mono{font-family:var(--mono);font-size:.95em}
.stat .l{
  font-size:.7em;color:var(--muted);text-transform:uppercase;
  letter-spacing:.05em;margin-top:.15rem;
}

/* Search bar */
.searchbar{
  display:flex;gap:.4rem;align-items:center;
  margin-bottom:1rem;flex-wrap:wrap;
}
.searchbar input[type=text]{
  padding:.45rem .7rem;border-radius:var(--radius);
  border:1px solid var(--border);background:var(--surface);color:var(--fg);
  font:inherit;font-size:.9em;min-width:220px;flex:1;max-width:400px;
  transition:border-color .1s;
}
.searchbar input[type=text]:focus{outline:none;border-color:var(--accent)}

/* Table */
.table-wrap{
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:var(--radius-lg);
  /* overflow:clip clippt ohne Scroll-Container zu erzeugen –
     so bleibt position:sticky im thead erhalten. */
  overflow:clip;
}
table.data{
  width:100%;
  border-collapse:separate;
  border-spacing:0;
  font-size:.9em;
}
table.data th,table.data td{
  padding:.55rem .85rem;
  text-align:left;
  vertical-align:middle;
  border-bottom:1px solid var(--border);
}
table.data thead th{
  background:var(--surface-2);
  font-size:.72em;font-weight:600;color:var(--muted);
  text-transform:uppercase;letter-spacing:.06em;
  white-space:nowrap;
  position:sticky;
  top:52px;
  z-index:5;
  border-bottom:1px solid var(--border);
}
table.data thead th a{
  color:inherit;display:inline-flex;align-items:center;gap:.25rem;
}
table.data thead th a:hover{color:var(--fg);text-decoration:none}
table.data thead th.key a::after{
  content:"@key";
  font-size:.82em;color:var(--accent);font-weight:600;
  background:var(--accent-soft);
  padding:.05em .35em;border-radius:3px;letter-spacing:.02em;
  margin-left:.3em;
}
table.data thead th.th-action{width:1px;padding:.4rem .6rem}
table.data tbody tr{transition:background .08s}
table.data tbody tr[data-href]{cursor:pointer}
table.data tbody tr:hover{background:var(--hover)}
table.data tbody tr:last-child td{border-bottom:none}
table.data td.mono{font-family:var(--mono);font-size:.92em}
table.data td.empty-val{color:var(--muted-2);font-style:italic}
table.data td.empty-row{
  text-align:center;color:var(--muted);padding:2rem;font-style:italic;
}
table.data td.actions{
  width:1px;white-space:nowrap;padding:.35rem .5rem;
  text-align:right;
}
table.data td.actions form{display:inline;margin:0}
table.data td.actions .btn{margin-left:.15rem}
.tlink{font-family:var(--mono);font-weight:500}

/* Pagination */
.pagination{
  display:flex;gap:.25rem;align-items:center;
  margin-top:1rem;flex-wrap:wrap;
}
.page{
  display:inline-flex;align-items:center;justify-content:center;
  min-width:30px;height:30px;padding:0 .5rem;
  border-radius:var(--radius);border:1px solid var(--border);
  background:var(--surface);color:var(--fg);
  font-size:.85em;font-variant-numeric:tabular-nums;
  transition:background .08s;
}
.page:hover{background:var(--hover);text-decoration:none}
.page.current{
  background:var(--accent);border-color:var(--accent);
  color:var(--accent-fg);font-weight:600;
}
.dots{color:var(--muted);padding:0 .25rem}
.pginfo{margin-left:.5rem;font-size:.82em}

/* Form */
.card{
  background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius-lg);padding:1.25rem;
  box-shadow:var(--shadow-sm);max-width:560px;
}
.field{display:block;margin-bottom:.85rem}
.flabel{
  display:flex;align-items:baseline;gap:.4rem;flex-wrap:wrap;
  margin-bottom:.3rem;font-size:.85em;
}
.fname{font-weight:600;font-family:var(--mono)}
.keymark{
  font-size:.72em;background:var(--accent-soft);color:var(--accent);
  padding:.05em .4em;border-radius:3px;font-weight:600;
}
.fmeta{color:var(--muted);font-size:.85em;font-weight:400}
.card input[type=text]{
  width:100%;padding:.5rem .7rem;border-radius:var(--radius);
  border:1px solid var(--border);background:var(--surface);color:var(--fg);
  font:inherit;font-family:var(--mono);font-size:.9em;
  transition:border-color .1s,box-shadow .1s;
}
.card input[type=text]:focus{
  outline:none;border-color:var(--accent);
  box-shadow:0 0 0 3px var(--accent-soft);
}
.form-actions{
  display:flex;gap:.5rem;margin-top:1rem;
  padding-top:1rem;border-top:1px solid var(--border);
}

/* Toast */
.toast{
  display:inline-block;padding:.5rem .9rem;border-radius:var(--radius);
  background:var(--success-bg);color:var(--success);
  border:1px solid color-mix(in srgb,var(--success) 25%,transparent);
  font-size:.88em;margin-bottom:1rem;
}
.toast.err{
  background:var(--danger-bg);color:var(--danger);
  border-color:color-mix(in srgb,var(--danger) 25%,transparent);
}

/* Empty */
.empty{
  text-align:center;color:var(--muted);padding:3rem 1rem;
  background:var(--surface);border:1px dashed var(--border);
  border-radius:var(--radius-lg);
}
.empty-icon{font-size:1.75rem;color:var(--muted-2);margin-bottom:.5rem}
.muted{color:var(--muted)}
"#;

// ───────────── JS ─────────────

const SCRIPT: &str = r#"
(function(){
  var root=document.documentElement;
  // localStorage kann (Privatmodus, Policies) werfen.
  function lsGet(k){try{return localStorage.getItem(k)}catch(e){return null}}
  function lsSet(k,v){try{localStorage.setItem(k,v)}catch(e){}}
  var stored=lsGet('dbcore-theme');
  if(stored)root.setAttribute('data-theme',stored);

  // Theme toggle
  document.addEventListener('click',function(e){
    var t=e.target.closest('[data-theme-toggle]');
    if(!t)return;
    var cur=root.getAttribute('data-theme')
      || (matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');
    var next=cur==='dark'?'light':'dark';
    root.setAttribute('data-theme',next);
    lsSet('dbcore-theme',next);
  });

  // Clickable rows
  document.addEventListener('click',function(e){
    var row=e.target.closest('tr[data-href]');
    if(!row)return;
    if(e.target.closest('a, button, form, input, select, summary'))return;
    location.href=row.dataset.href;
  });

  // Confirm on forms
  document.addEventListener('submit',function(e){
    var f=e.target;
    if(f.matches('form[data-confirm]')){
      if(!confirm(f.dataset.confirm))e.preventDefault();
    }
  });

  // Close dropdown on outside click
  document.addEventListener('click',function(e){
    document.querySelectorAll('details.dd[open]').forEach(function(d){
      if(!d.contains(e.target))d.removeAttribute('open');
    });
  });

  // Keyboard: "/" fokussiert Suche, Esc blurrt
  document.addEventListener('keydown',function(e){
    if(e.key==='/'&&!/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)){
      var q=document.getElementById('q');
      if(q){e.preventDefault();q.focus();q.select();}
    }
    if(e.key==='Escape'&&document.activeElement&&document.activeElement.id==='q'){
      document.activeElement.blur();
    }
  });

  // Erfolgs-Toast ausblenden; Fehler bleiben stehen.
  var t=document.getElementById('toast');
  if(t&&!t.classList.contains('err')){
    setTimeout(function(){
      t.style.transition='opacity .4s';
      t.style.opacity='0';
      setTimeout(function(){t.remove()},400);
    },2500);
  }
})();
"#;