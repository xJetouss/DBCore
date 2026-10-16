//! Demo aller DBCore-Features. Keine `|r|`-Closures – nur `with!`.

use dbcore::{DBCore, schema, row, with, remove_if, model, interface, csv, html, json,
             Check, OnDelete, Agg, ColumnDef, ColumnKind, Migration};

fn main() {
    // ── 1. Konstruktor-Varianten ──────────────────────────────
    let db = DBCore::new("HI");                 // ./dbcore_data/HI
    // let db = DBCore::new("./mydb");          // ./mydb
    // let db = DBCore::new("/tmp/mydb");       // absoluter Pfad
    // let db = DBCore::at("./data/hi");        // explizit
    // let db = DBCore::under("./data", "hi");  // ./data/hi

    // ── 2. Tabellen anlegen (idempotent) ──────────────────────
    db.create_if_missing("users", schema! {
        @key id: i32,
        name: String,
        views: i64 = 0,
    });
    db.create_if_missing("posts", schema! {
        @key id: i32,
        title: String,
        author: String,
        likes: i64 = 0,
    });

    // ── 3. Insert / Upsert ────────────────────────────────────
    db.put("users", row! { id: 1, name: "Alice", views: 5 });
    db.put("users", row! { id: 2, name: "Bob"   });
    db.put("users", row! { id: 3, name: "Carol", views: 10 });
    db.put("users", row! { id: 4, name: "Alice", views: 2 });
    db.add("users", row! { id: 5, name: "Dave",  views: 0 });

    // put() liefert den Key – auch wenn er automatisch vergeben wurde.
    let eve = db.put("users", row! { name: "Eve; die \"Zweite\"" }); // Sonderzeichen sind ok
    println!("Eve hat den Key {eve}");

    db.put("posts", row! { id: 1, title: "Hallo",    author: "Alice", likes: 3 });
    db.put("posts", row! { id: 2, title: "Rust 101", author: "Bob",   likes: 7 });

    // ── 4. Update (Patch per @key) ────────────────────────────
    db.update("users", "1", row! { views: 7 });          // name bleibt
    db.update("users", "2", row! { name: "Bobby" });

    // ── 5. Remove per @key (true = es gab die Zeile) ──────────
    let removed = db.remove("users", "5");
    println!("Dave entfernt: {removed}");
    db.remove("users", &eve);

    // ── 6. Remove_if (Makro, kein `|r|`) – liefert die Anzahl ─
    let n_gone = remove_if!(db, "users", r => r[1] == "nonexistent");
    println!("remove_if hat {n_gone} Zeilen gelöscht");

    // ── 7. Query-Builder ──────────────────────────────────────
    println!("\n== Alle User ==");
    db.table("users").order_by("id").print();

    println!("\n== Users mit views > 0, sortiert views desc, Top 2 ==");
    db.table("users")
        .filter(with!(r => r[2].parse::<i64>().unwrap_or(0) > 0))
        .order_by("views").desc()
        .limit(2)
        .print();

    println!("\n== Nur Spalte `name`, ohne erste Zeile ==");
    db.table("users")
        .select(&["name"])
        .order_by("id")
        .skip(1)
        .print();

    // ── 8. Aggregate (echte Werte, kein Option) ───────────────
    let n    = db.table("users").count();
    let sum  = db.table("users").sum("views");
    let avg  = db.table("users").avg("views");
    let minv = db.table("users").min("views");
    let maxv = db.table("users").max("views");
    println!("\ncount={n}  sum={sum}  avg={avg:.2}  min={minv}  max={maxv}");

    // ── 9. VALUE / VALUES / FIRST ─────────────────────────────
    let first_name = db.table("users").order_by("id").select(&["name"]).value();
    let all_names  = db.table("users").order_by("id").values("name");
    let first_row  = db.table("users").order_by("id").first();
    println!("\nerster Name: {first_name}");
    println!("alle Namen:  {all_names:?}");
    println!("erste Zeile: {first_row:?}");
    println!("Gibt es Carol? {}", db.table("users").filter(with!(r => r[1] == "Carol")).exists());
    println!("Zeile 3:     {:?}  (has: {})", db.get("users", "3"), db.has("users", "3"));

    // ── 10. Iteration ─────────────────────────────────────────
    println!("\n== for-Loop über Query ==");
    for row in db.table("users").order_by("id") {
        println!("  {} → {}", row[0], row[1]);
    }

    // ── 11. PATCH / MERGE über Query ──────────────────────────
    let patched = db.table("users")
        .filter(with!(r => r[1] == "Alice"))
        .patch(row! { views: 42 });
    println!("\n{patched} Alice-Zeilen gepatcht");

    db.table("users")
        .filter(with!(r => r[1] == "Bobby"))
        .merge(row! { views: 1 });

    // ── 12. Print / Export ───────────────────────────────────
    println!("\n== Stand nach Patch ==");
    db.table("users").order_by("id").print();

    db.table("users").export_csv("users_export.csv");
    db.table("users").export_html("users_export.html");
    db.export_csv("users", "users_full.csv");      // via `csv`-Trait
    db.export_html("users", "users_full.html");    // via `html`-Trait
    db.export_json("users", "users_full.json");    // via `json`-Trait

    let csv_str = db.table("users").to_csv();
    println!("\nCSV ({} Bytes):", csv_str.len());
    println!("{csv_str}");

    // ── 13. DELETE über Query ─────────────────────────────────
    let deleted = db.table("users")
        .filter(with!(r => r[2] == "1"))
        .delete();
    println!("{deleted} Zeile(n) gelöscht (views==1)");

    // ── 14. remove_field ──────────────────────────────────────
    // db.table("users").remove_field("views");

    // ── 15. Tabelle löschen ──────────────────────────────────
    db.delete_table_if_exists("posts");

    // ═════════════════ NEU in 0.2 ═════════════════════════════════

    // ── 16. Transaktionen: alles oder nichts ──────────────────
    db.create_if_missing("accounts", schema! { @key id: i32, owner: String, balance: i64 = 0 }
        .check("balance", Check::ge(0)));                     // CHECK-Constraint
    db.put("accounts", row! { id: 1, owner: "Alice", balance: 100 });
    db.put("accounts", row! { id: 2, owner: "Bob",   balance: 50 });

    let transfer = db.transaction(|tx| {
        tx.update("accounts", "1", row! { balance: 30 })?;   // 70 abbuchen …
        tx.update("accounts", "2", row! { balance: 120 })?;  // … 70 gutschreiben
        tx.update("accounts", "1", row! { balance: -5 })?;   // ✗ CHECK verletzt → ALLES zurück
        Ok(())
    });
    println!("\nÜberweisung: {:?}", transfer.map_err(|e| e.to_string()));
    println!("Alice hat weiter {} (Rollback)", db.get("accounts", "1")[2]);

    // ── 17. Constraints + Foreign Key mit CASCADE ─────────────
    db.create_if_missing("authors", schema! { @key id: i32, name: String, email: String = "" }
        .not_null(&["name"]).unique(&["email"]));
    db.create_if_missing("articles", schema! { @key id: i32, title: String, author: i32, likes: i64 = 0 }
        .index(&["author"])                                   // Sekundärindex
        .references("author", "authors", "id", OnDelete::Cascade));
    db.put("authors", row! { id: 1, name: "Alice", email: "a@x.de" });
    db.put("authors", row! { id: 2, name: "Bob",   email: "b@x.de" });
    println!("doppelte E-Mail: {:?}", db.try_add("authors", row! { id: 3, name: "X", email: "a@x.de" }).map_err(|e| e.to_string()));
    println!("Post ohne Autor:  {:?}", db.try_add("articles", row! { id: 1, title: "?", author: 99 }).map_err(|e| e.to_string()));

    // ── 18. Batch: tausende Zeilen in EINEM Commit ────────────
    let rows = (1..=1000).map(|i| row! { id: i, title: format!("Artikel {i}"), author: 1 + i % 2, likes: i % 17 }).collect();
    println!("put_many → {} Zeilen", db.put_many("articles", rows).len());

    // ── 19. Joins, GROUP BY, HAVING ───────────────────────────
    println!("\n== Likes pro Autor (JOIN + GROUP BY + HAVING) ==");
    db.table("articles")
        .join("authors", "author", "id")
        .group_by(&["authors.name"])
        .agg(&[Agg::count().alias("artikel"), Agg::sum("likes").alias("likes_gesamt"), Agg::avg("likes")])
        .having(with!(r => r.get::<i64>("artikel").unwrap_or(0) > 10))
        .order_by("likes_gesamt").desc()
        .print();

    // Unterabfrage: Autoren, die etwas mit > 15 Likes geschrieben haben
    let stars = db.table("authors")
        .where_in_query("id", db.table("articles").where_gt("likes", 15).select(&["author"]))
        .values("name");
    println!("Autoren mit Hit-Artikel: {stars:?}");

    // ── 20. Indizes: der Plan zeigt, ob einer genutzt wird ────
    println!("\nPlan 1: {}", db.table("articles").where_eq("author", 2).explain());
    println!("Plan 2: {}", db.table("articles").filter(with!(r => r["author"] == "2")).explain());
    println!("Plan 3: {}", db.table("articles").order_by("id").desc().limit(3).explain());

    // ── 21. Typisierter Zugriff nach Spaltenname + eigene Structs
    model! {
        #[derive(Debug)]
        pub struct Author { @key id: i32, name: String, email: String = "" }
    }
    let authors: Vec<Author> = db.table("authors").order_by("id").collect_as();
    println!("\nals Structs: {authors:?}");

    // ── 22. Lazy-Iteration: Block für Block von der Platte ────
    let mut big = 0;
    for row in db.table("articles").where_ge("likes", 15) { big += row.len().min(1); }
    println!("{big} Artikel mit ≥ 15 Likes (gestreamt)");

    // ── 23. Konsistenter Snapshot + Migration ─────────────────
    let snap = db.snapshot().expect("snapshot");
    db.put("accounts", row! { id: 3, owner: "Neu", balance: 1 });
    println!("Snapshot sieht {} Konten, live sind es {}", snap.table("accounts").count(), db.count("accounts"));

    let steps: &[Migration] = &[
        (1, |tx| tx.add_field("accounts", ColumnDef::new("currency", ColumnKind::Text, Some("EUR".into()), false))),
    ];
    println!("Schema-Version jetzt: {}", db.migrate(steps).unwrap());
    println!("Integritätsprüfung: {:?}", db.integrity_check());

    // ── 24. Web-Interface (blockiert; Ausgabe macht der Aufrufer) ──
    // println!("Server läuft: http://127.0.0.1:8080");
    db.open_interface(8080);
}