//! Datei- und Ausgabeformate: Zeilen-Kodierung, Terminal, CSV, JSON, HTML.
use super::*;

pub(crate) fn escape_cell(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ';'  => out.push_str("\\;"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c    => out.push(c),
        }
    }
}

pub(crate) fn split_cells_v2(s: &str) -> Vec<String> {
    let mut cells = Vec::new();
    let mut cur = String::new();
    let mut it = s.chars();
    while let Some(c) = it.next() {
        match c {
            '\\' => match it.next() {
                Some('n') => cur.push('\n'),
                Some('r') => cur.push('\r'),
                Some(o)   => cur.push(o),
                None      => cur.push('\\'),
            },
            ';' => cells.push(std::mem::take(&mut cur)),
            c   => cur.push(c),
        }
    }
    cells.push(cur);
    cells
}

pub(crate) fn split_rows(text: &str) -> (String, Vec<Vec<String>>) {
    let v2 = text.lines().any(|l| l == FORMAT_LINE);
    let mut header = String::with_capacity(text.len().min(256));
    let mut rows = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("ROW:") {
            rows.push(if v2 {
                split_cells_v2(rest)
            } else {
                rest.split(';').map(String::from).collect()
            });
        } else {
            header.push_str(line);
            header.push('\n');
        }
    }
    (header, rows)
}

// ───────────── Terminal ─────────────
pub(crate) fn format_terminal(schema: &[ColDef], rows: &[Vec<String>]) -> String {
    let cols = schema.len();
    if cols == 0 { return String::from("(leer)\n"); }
    let labels: Vec<String> = schema.iter()
        .map(|c| if c.key { format!("{}*", c.name) } else { c.name.clone() })
        .collect();
    let mut widths = vec![0usize; cols];
    for (i, label) in labels.iter().enumerate() {
        widths[i] = label.chars().count();
    }
    for r in rows {
        for i in 0..cols {
            let len = cell(r, i).chars().count();
            if len > widths[i] { widths[i] = len; }
        }
    }
    let sep = |l: &str, m: &str, r: &str| {
        let mut s = String::new();
        s.push_str(l);
        for (i, w) in widths.iter().enumerate() {
            if i > 0 { s.push_str(m); }
            for _ in 0..(w + 2) { s.push('─'); }
        }
        s.push_str(r);
        s
    };
    let mut out = String::new();
    out.push_str(&sep("┌", "┬", "┐")); out.push('\n');
    out.push('│');
    for (i, label) in labels.iter().enumerate() {
        out.push_str(&format!(" {:width$} │", label, width = widths[i]));
    }
    out.push('\n');
    out.push_str(&sep("├", "┼", "┤")); out.push('\n');
    for r in rows {
        out.push('│');
        for i in 0..cols {
            // Zeilenumbrüche/Tabs würden das Raster zerstören.
            let v = cell(r, i).replace(['\n', '\r', '\t'], " ");
            out.push_str(&format!(" {:width$} │", v, width = widths[i]));
        }
        out.push('\n');
    }
    out.push_str(&sep("└", "┴", "┘")); out.push('\n');
    out
}

// ───────────── CSV-Format ─────────────

pub(crate) fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

pub(crate) fn format_csv(schema: &[ColDef], rows: &[Vec<String>]) -> String {
    let est = 3 + schema.len() * 12
        + rows.iter().map(|r| r.len() * 12 + 2).sum::<usize>();
    let mut out = String::with_capacity(est);
    out.push('\u{FEFF}');
    for (i, c) in schema.iter().enumerate() {
        if i > 0 { out.push(','); }
        out.push_str(&csv_escape(&c.name));
    }
    out.push_str("\r\n");
    for r in rows {
        for i in 0..schema.len() {
            if i > 0 { out.push(','); }
            out.push_str(&csv_escape(cell(r, i)));
        }
        out.push_str("\r\n");
    }
    out
}

// ───────────── JSON-Format ─────────────

pub(crate) fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"'  => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub(crate) fn json_value(c: &ColDef, v: &str) -> String {
    let quoted = || format!("\"{}\"", json_escape(v));
    match c.kind {
        // `parse::<f64>` akzeptiert auch "NaN"/"inf" – das ist kein gültiges JSON.
        ColumnKind::Int => v.parse::<i64>().map(|n| n.to_string()).unwrap_or_else(|_| quoted()),
        ColumnKind::Float => match v.parse::<f64>() {
            Ok(f) if f.is_finite() => f.to_string(),
            _ => quoted(),
        },
        ColumnKind::Bool if v == "true" || v == "false" => v.to_string(),
        _ => quoted(),
    }
}

pub(crate) fn format_json(schema: &[ColDef], rows: &[Vec<String>]) -> String {
    let mut out = String::from("[\n");
    for (ri, r) in rows.iter().enumerate() {
        out.push_str("  {");
        for (i, c) in schema.iter().enumerate() {
            if i > 0 { out.push(','); }
            out.push_str(&format!(
                "\n    \"{}\": {}", json_escape(&c.name), json_value(c, cell(r, i))
            ));
        }
        out.push_str("\n  }");
        if ri + 1 < rows.len() { out.push(','); }
        out.push('\n');
    }
    out.push_str("]\n");
    out
}

// ───────────── HTML-Format ─────────────

pub(crate) fn html_escape(s: &str) -> String {
    if !s.bytes().any(|b| matches!(b, b'&' | b'<' | b'>' | b'"' | b'\'')) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&'  => out.push_str("&amp;"),
            '<'  => out.push_str("&lt;"),
            '>'  => out.push_str("&gt;"),
            '"'  => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _    => out.push(c),
        }
    }
    out
}

pub(crate) fn format_html(title: &str, schema: &[ColDef], rows: &[Vec<String>]) -> String {
    let est = 1_500 + (schema.len() + rows.len() * schema.len()) * 32;
    let mut out = String::with_capacity(est);

    out.push_str("<!DOCTYPE html>\n<html lang=\"de\">\n<head>\n");
    out.push_str("<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n");
    out.push_str("<title>");
    out.push_str(&html_escape(title));
    out.push_str("</title>\n<style>");
    out.push_str(HTML_EXPORT_STYLE);
    out.push_str("</style>\n</head>\n<body>\n");

    out.push_str("<header><h1>");
    out.push_str(&html_escape(title));
    out.push_str("</h1><p class=\"meta\">");
    out.push_str(&schema.len().to_string());
    out.push_str(" Spalten · ");
    out.push_str(&rows.len().to_string());
    out.push_str(" Zeilen</p></header>\n<table>\n<thead>\n<tr>\n");

    for c in schema {
        let cls = if c.key { " class=\"key\"" } else { "" };
        out.push_str("<th");
        out.push_str(cls);
        out.push('>');
        out.push_str(&html_escape(&c.name));
        out.push_str("</th>\n");
    }
    out.push_str("</tr>\n</thead>\n<tbody>\n");
    for r in rows {
        out.push_str("<tr>");
        for i in 0..schema.len() {
            let v = cell(r, i);
            if v.is_empty() {
                out.push_str("<td class=\"empty\">—</td>");
            } else {
                out.push_str("<td>");
                out.push_str(&html_escape(v));
                out.push_str("</td>");
            }
        }
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody>\n</table>\n</body>\n</html>\n");
    out
}

pub(crate) const HTML_EXPORT_STYLE: &str = "\
*,*::before,*::after{box-sizing:border-box}\
:root{color-scheme:light;\
--bg:#fff;--fg:#111827;--muted:#6b7280;--muted-2:#9ca3af;\
--border:#e5e7eb;--surface-2:#f9fafb;\
--accent:#2563eb;--accent-soft:#eff6ff;\
--mono:ui-monospace,SFMono-Regular,\"SF Mono\",Menlo,Consolas,monospace;}\
html,body{margin:0;padding:0;background:var(--bg);color:var(--fg)}\
body{font:14px/1.5 system-ui,-apple-system,\"Segoe UI\",Roboto,sans-serif;\
-webkit-font-smoothing:antialiased;padding:2rem 1.25rem 4rem;\
max-width:1200px;margin:0 auto}\
header{margin-bottom:1.25rem;padding-bottom:1rem;border-bottom:1px solid var(--border)}\
header h1{margin:0 0 .25rem;font-size:1.4rem;font-weight:600;letter-spacing:-.01em}\
header .meta{margin:0;color:var(--muted);font-size:.85em;font-variant-numeric:tabular-nums}\
table{width:100%;border-collapse:separate;border-spacing:0;font-size:.9em;\
background:#fff;border:1px solid var(--border);border-radius:8px;overflow:hidden}\
th,td{padding:.55rem .85rem;text-align:left;vertical-align:middle;\
border-bottom:1px solid var(--border)}\
thead th{background:var(--surface-2);font-size:.72em;font-weight:600;color:var(--muted);\
text-transform:uppercase;letter-spacing:.06em;white-space:nowrap}\
thead th.key::after{content:\"@key\";margin-left:.35em;font-size:.85em;color:var(--accent);\
background:var(--accent-soft);padding:.05em .35em;border-radius:3px;\
letter-spacing:.02em;font-weight:600}\
tbody tr:last-child td{border-bottom:none}\
tbody tr:hover{background:var(--surface-2)}\
td{font-family:var(--mono);font-size:.95em}\
td.empty{color:var(--muted-2);font-style:italic;font-family:inherit}\
@media print{body{padding:0;max-width:none;font-size:11pt}\
table{border-radius:0;border-color:#ccc}\
thead{display:table-header-group}tr{page-break-inside:avoid}}\
";
