//! Selbsttest für ALLE DBCore-Features.
//!
//!   cargo run --release                 → alle Tests, ✔/✘ je Test, Exit-Code 1 bei Fehlern
//!   cargo run --release -- crash        → nur die Crash-/Multi-Prozess-Tests
//!   cargo run --release -- web          → Web-Interface mit Beispieldaten (http://127.0.0.1:8080)
//!   cargo run --example demo            → die ursprüngliche Feature-Demo
//!
//! Interne Modi (werden von den Prozess-Tests selbst gestartet):
//!   `selftest --child DIR N`            → Zähler-Worker (N=0: endlos)

use dbcore::*;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// ───────────── Mini-Testrunner ─────────────

/// Meldungen *aller* Panics (auch aus Hilfs-Threads) – sonst sieht man bei
/// `join().unwrap()` nur ein nichtssagendes `Any { .. }`.
static PANICS: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct Runner { ok: usize, failed: Vec<String> }

impl Runner {
    fn run(&mut self, name: &str, f: impl FnOnce()) {
        let t = Instant::now();
        PANICS.lock().unwrap_or_else(|p| p.into_inner()).clear();
        match catch_unwind(AssertUnwindSafe(f)) {
            Ok(()) => { self.ok += 1; println!("  ✔ {name:<58} {:>8.1?}", t.elapsed()); }
            Err(e) => {
                let msg = e.downcast_ref::<String>().cloned()
                    .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
                println!("  ✘ {name:<58} {msg}");
                for m in PANICS.lock().unwrap_or_else(|p| p.into_inner()).iter().take(4) {
                    println!("      ↳ {}", m.replace('\n', " "));
                }
                self.failed.push(name.to_string());
            }
        }
    }
}

fn db() -> DBCore { let d = DBCore::temp(); d.set_sync(false); d }
fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("dbcore-self-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}
fn users(d: &DBCore) { d.create("users", schema! { @key id: i32, name: String, views: i64 = 0 }); }

fn blog(d: &DBCore) {
    d.create("users", schema! { @key id: i32, name: String, age: i64 = 0 });
    d.create("posts", schema! { @key id: i32, title: String, author: String, likes: i64 = 0 });
    for (i, (n, a)) in [("Alice", 30), ("Bob", 25), ("Carol", 41), ("Dave", 25)].iter().enumerate() {
        d.put("users", row! { id: i + 1, name: n, age: a });
    }
    for (t, a, l) in [("Hallo", "Alice", 3), ("Rust 101", "Bob", 7), ("Mehr", "Alice", 10), ("Waise", "Nobody", 1), ("Zwei", "Bob", 2)] {
        d.put("posts", row! { title: t, author: a, likes: l });
    }
}

model! {
    #[derive(Debug, Clone, PartialEq)]
    pub struct User { @key id: i32, name: String, views: i64 = 0 }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--child") => return child(&args[1], args[2].parse().unwrap_or(0)),
        Some("web") => return web(),
        _ => {}
    }
    // Panic-Meldungen sammeln statt drucken; der Runner zeigt sie bei einem Fehlschlag.
    std::panic::set_hook(Box::new(|info| {
        PANICS.lock().unwrap_or_else(|p| p.into_inner()).push(info.to_string());
    }));
    let only_crash = args.first().map(String::as_str) == Some("crash");
    let mut r = Runner { ok: 0, failed: vec![] };
    let t0 = Instant::now();

    if !only_crash {
        println!("\n▌ Grundlagen & Typen");
        r.run("CRUD, Sonderzeichen, Upsert liefert Key", || {
            let d = db(); users(&d);
            assert!(d.add("users", row! { id: 1, name: "Alice", views: 5 }));
            assert!(!d.add("users", row! { id: 1, name: "Dup" }), "Duplikat");
            assert_eq!(d.put("users", row! { name: "Eve; die \"Zweite\"\nZeile2" }), "2");
            assert_eq!(d.get("users", "2")[1], "Eve; die \"Zweite\"\nZeile2");
            assert!(d.update("users", "1", row! { views: 7 }));
            assert!(d.remove("users", "2") && !d.remove("users", "2"));
            assert_eq!(d.count("users"), 1);
        });
        r.run("Typprüfung beim Schreiben", || {
            let d = db(); users(&d);
            assert!(matches!(d.try_add("users", row! { id: "abc", name: "x" }), Err(DbError::TypeMismatch(_))));
            assert!(matches!(d.try_add("users", row! { id: 1, nope: "x" }), Err(DbError::SchemaMismatch(_))));
            assert_eq!(d.count("users"), 0);
        });
        r.run("Zugriff nach Name, typisiert und nach Position", || {
            let d = db(); users(&d);
            d.put("users", row! { id: 1, name: "Alice", views: 5 });
            d.put("users", row! { id: 2, name: "Bob", views: 0 });
            assert_eq!(d.table("users").filter(with!(r => r.get::<i64>("views").unwrap_or(0) > 0)).count(), 1);
            assert_eq!(d.table("users").filter(with!(r => r["name"] == "Bob")).count(), 1);
            assert_eq!(d.table("users").filter(with!(r => r[1] == "Bob")).count(), 1);
        });
        r.run("model!: eigene Structs", || {
            let d = db();
            assert!(d.create_model::<User>("users"));
            d.put_model("users", &User { id: 1, name: "A".into(), views: 3 });
            let all: Vec<User> = d.table("users").collect_as();
            assert_eq!(all[0], User { id: 1, name: "A".into(), views: 3 });
        });
        r.run("Fehler statt Panic: unbekannte Tabelle/Spalte", || {
            let d = db(); users(&d);
            assert!(matches!(d.table("nope").try_count(), Err(DbError::TableNotFound(_))));
            assert!(matches!(d.table("users").where_eq("zzz", 1).try_count(), Err(DbError::SchemaMismatch(_))));
            assert_eq!(d.table("users").try_avg("views").unwrap(), None, "leer → None statt 0");
        });

        println!("\n▌ 1 Transaktionen");
        r.run("Commit, Rollback bei Err, Rollback bei Drop", || {
            let d = db(); users(&d);
            d.put("users", row! { id: 1, name: "A", views: 100 });
            d.put("users", row! { id: 2, name: "B", views: 0 });
            d.transaction(|tx| {
                tx.update("users", "1", row! { views: 90 })?;
                tx.update("users", "2", row! { views: 10 })?;
                assert_eq!(tx.get("users", "1")?.unwrap()[2], "90");
                Ok(())
            }).unwrap();
            let res: DbResult<()> = d.transaction(|tx| {
                tx.update("users", "1", row! { views: 0 })?;
                tx.add("users", row! { id: 3, name: "C" })?;
                Err(DbError::TxState("absichtlich"))
            });
            assert!(res.is_err());
            assert_eq!(d.get("users", "1")[2], "90");
            { let tx = d.begin().unwrap(); tx.add("users", row! { id: 9, name: "Z" }).unwrap(); }
            assert!(!d.has("users", "9"));
        });
        r.run("Mehrere Tabellen + DDL atomar", || {
            let d = db(); users(&d);
            let res: DbResult<()> = d.transaction(|tx| {
                tx.create_table("logs", schema! { @key id: i32, msg: String })?;
                tx.put("logs", row! { msg: "hi" })?;
                tx.drop_table("users", false)?;
                Err(DbError::TxState("boom"))
            });
            assert!(res.is_err() && !d.has_table("logs") && d.has_table("users"));
        });
        r.run("Panic in Transaktion → Rollback, Lock wieder frei", || {
            let d = db(); users(&d);
            let d2 = d.clone();
            let h = thread::spawn(move || { let _ = d2.transaction(|tx| -> DbResult<()> {
                tx.add("users", row! { id: 1, name: "A" })?; panic!("kaputt"); }); });
            assert!(h.join().is_err());
            assert_eq!(d.count("users"), 0);
            assert!(d.add("users", row! { id: 1, name: "ok" }));
        });
        r.run("db.* innerhalb einer Tx → Busy statt Hänger", || {
            let d = db(); users(&d);
            d.set_busy_timeout(Duration::from_millis(200));
            assert!(matches!(d.transaction(|_| d.try_add("users", row! { id: 1, name: "x" })), Err(DbError::Busy)));
        });

        println!("\n▌ 10 Batch (put_many / add_many)");
        r.run("20 000 Zeilen in einem Commit, alles-oder-nichts", || {
            let d = db(); users(&d);
            let rows: Vec<_> = (0..20_000).map(|i| row! { id: i, name: format!("n{i}"), views: i % 7 }).collect();
            let t = Instant::now();
            assert_eq!(d.put_many("users", rows).len(), 20_000);
            assert!(t.elapsed().as_secs() < 20);
            let mut bad: Vec<_> = (100_000..100_010).map(|i| row! { id: i, name: "ok" }).collect();
            bad.push(row! { id: 100_011, name: "x", views: "kaputt" });
            assert!(d.try_put_many("users", bad).is_err());
            assert_eq!(d.count("users"), 20_000);
            assert!(!d.add_many("users", vec![row! { id: 500_000, name: "a" }, row! { id: 500_000, name: "b" }]));
            assert!(!d.has("users", "500000"));
        });

        println!("\n▌ 6 Constraints");
        fn shop(d: &DBCore) {
            d.create("users", schema! { @key id: i32, name: String, email: String = "" }
                .not_null(&["name"]).unique(&["email"]).check("name", Check::len(2, 20)));
            d.create("posts", schema! { @key id: i32, title: String, author: i32, likes: i64 = 0 }
                .check("likes", Check::ge(0)).index(&["author"])
                .references("author", "users", "id", OnDelete::Cascade));
            d.create("notes", schema! { @key id: i32, post: i32 }
                .references("post", "posts", "id", OnDelete::Restrict));
        }
        r.run("NOT NULL, UNIQUE, CHECK", || {
            let d = db(); shop(&d);
            assert!(matches!(d.try_add("users", row! { id: 1, name: "" }), Err(DbError::NotNull(_))));
            assert!(matches!(d.try_add("users", row! { id: 1, name: "A" }), Err(DbError::CheckFailed(_))));
            d.add("users", row! { id: 1, name: "Alice", email: "a@x.de" });
            assert!(matches!(d.try_add("users", row! { id: 2, name: "Bob", email: "a@x.de" }), Err(DbError::Unique(_))));
            assert!(d.add("users", row! { id: 3, name: "Carl" }) && d.add("users", row! { id: 4, name: "Dora" }), "leer ≠ Duplikat");
            d.add("users", row! { id: 5, name: "Erik", email: "e@x.de" });
            assert!(matches!(d.try_update("users", "5", row! { email: "a@x.de" }), Err(DbError::Unique(_))));
            assert_eq!(d.get("users", "5")[2], "e@x.de");
        });
        r.run("Foreign Keys: RESTRICT, CASCADE, Parent-Schutz", || {
            let d = db(); shop(&d);
            d.add("users", row! { id: 1, name: "Alice" }); d.add("users", row! { id: 2, name: "Bob" });
            assert!(matches!(d.try_add("posts", row! { id: 1, title: "x", author: 99 }), Err(DbError::ForeignKey(_))));
            d.add("posts", row! { id: 1, title: "p1", author: 1 }); d.add("posts", row! { id: 2, title: "p2", author: 1 });
            d.add("posts", row! { id: 3, title: "p3", author: 2 });
            d.add("notes", row! { id: 1, post: 3 });
            assert!(matches!(d.try_remove("users", "2"), Err(DbError::ForeignKey(_))), "Kaskade stößt auf RESTRICT");
            assert!(d.has("users", "2") && d.has("posts", "3"), "nichts halb gelöscht");
            assert!(d.remove("users", "1"));
            assert_eq!(d.count("posts"), 1);
            assert!(matches!(d.try_update("users", "2", row! { id: 22 }), Err(DbError::ForeignKey(_))));
            assert!(matches!(d.try_delete_table("users", false), Err(DbError::ForeignKey(_))));
            d.remove("notes", "1");
            assert!(d.remove("users", "2") && d.count("posts") == 0);
            assert!(d.integrity_check().is_empty());
        });

        println!("\n▌ 5 Indizes & Planer");
        r.run("Index wird genutzt, Ergebnis == Vollscan (4000 Zeilen)", || {
            let d = db();
            d.create("t", schema! { @key id: i32, grp: i32, code: String, score: f64 }
                .index(&["grp"]).unique(&["code"]).index(&["score"]));
            assert!(d.add_many("t", (0..4000).map(|i| row! { id: i, grp: i % 50,
                code: format!("c{:05}", (i * 7919) % 100_003), score: (i % 97) as f64 / 4.0 }).collect()));
            assert!(d.table("t").where_eq("grp", 3).explain().contains("USING INDEX grp"));
            assert!(d.table("t").where_between("score", 1, 3).explain().contains("INDEX score"));
            assert!(d.table("t").order_by("score").limit(5).explain().contains("kein Sortieren"));
            assert!(d.table("t").filter(with!(r => r[1] == "3")).explain().starts_with("SCAN t"));
            assert_eq!(d.table("t").where_eq("grp", 3).collect(), d.table("t").filter(with!(r => r["grp"] == "3")).collect());
            assert_eq!(d.table("t").where_in("grp", [1, 2, 49]).collect(),
                       d.table("t").filter(with!(r => ["1","2","49"].contains(&r["grp"].as_str()))).collect());
            assert_eq!(d.table("t").where_gt("score", 20).collect(),
                       d.table("t").filter(with!(r => r.get::<f64>("score").unwrap() > 20.0)).collect());
            assert_eq!(d.table("t").where_between("id", 100, 120).count(), 21);
            let a = d.table("t").where_gt("id", 5).order_by("score").desc().limit(7).values("score");
            let b = d.table("t").filter(with!(r => r.get::<i32>("id").unwrap() > 5)).order_by("score").desc().limit(7).values("score");
            assert_eq!(a, b);
        });
        r.run("Index anlegen/droppen, UNIQUE auf Bestand, persistent", || {
            let d = db();
            d.create("t", schema! { @key id: i32, a: String, b: String });
            d.add("t", row! { id: 1, a: "x", b: "p" }); d.add("t", row! { id: 2, a: "x", b: "q" });
            assert!(!d.create_unique_index("t", "a") && d.create_unique_index("t", "b"));
            assert!(matches!(d.try_add("t", row! { id: 3, a: "z", b: "p" }), Err(DbError::Unique(_))));
            assert!(d.create_index("t", "a") && d.drop_index("t", "b"));
            let d2 = DBCore::at(d.path());
            assert!(d2.indexes("t").contains(&"a".to_string()));
        });

        println!("\n▌ 8 Joins, Gruppierung, Mengen");
        r.run("INNER/LEFT JOIN, Mehrfach-Join, Mehrdeutigkeit", || {
            let d = db(); blog(&d);
            assert_eq!(d.table("posts").join("users", "author", "name").count(), 4);
            let l = d.table("posts").left_join("users", "author", "name").where_eq("title", "Waise")
                .select(&["posts.title", "users.name"]).collect();
            assert_eq!(l, vec![vec!["Waise".to_string(), String::new()]]);
            assert_eq!(d.table("posts").join("users", "author", "name").where_ge("users.age", 30).where_gt("likes", 5).count(), 1);
            assert!(matches!(d.table("posts").join("users", "author", "name").select(&["id"]).try_collect(), Err(DbError::SchemaMismatch(_))));
            d.create("tags", schema! { @key id: i32, post: i32, tag: String });
            d.add("tags", row! { id: 1, post: 1, tag: "intro" }); d.add("tags", row! { id: 2, post: 2, tag: "rust" });
            let t = d.table("posts").join("users", "author", "name").join("tags", "posts.id", "post")
                .select(&["title", "name", "tag"]).order_by("tag").collect();
            assert_eq!(t, [["Hallo", "Alice", "intro"], ["Rust 101", "Bob", "rust"]]);
        });
        r.run("GROUP BY, HAVING, Aggregate (auch auf leerer Menge)", || {
            let d = db(); blog(&d);
            let g = d.table("posts").group_by(&["author"])
                .agg(&[Agg::count(), Agg::sum("likes").alias("total"), Agg::avg("likes"), Agg::min("likes"), Agg::max("likes")])
                .order_by("total").desc().collect();
            assert_eq!(g[0], ["Alice", "2", "13", "6.5", "3", "10"]);
            let h = d.table("posts").group_by(&["author"]).agg(&[Agg::count().alias("n")])
                .having(with!(r => r.get::<i64>("n").unwrap() >= 2)).order_by("author").values("author");
            assert_eq!(h, ["Alice", "Bob"]);
            assert_eq!(d.table("posts").where_gt("likes", 1000).agg(&[Agg::count(), Agg::sum("likes"), Agg::max("likes")]).collect(), [["0", "0", ""]]);
        });
        r.run("DISTINCT, UNION, UNION ALL, IN/NOT IN (Unterabfrage), FROM-Subquery", || {
            let d = db(); blog(&d);
            assert_eq!(d.table("users").select(&["age"]).distinct().order_by("age").values("age"), ["25", "30", "41"]);
            assert_eq!(d.table("users").select(&["name"]).union(d.table("posts").select(&["author"])).count(), 5);
            assert_eq!(d.table("users").select(&["name"]).union_all(d.table("posts").select(&["author"])).count(), 9);
            assert_eq!(d.table("users").where_in_query("name", d.table("posts").select(&["author"])).order_by("id").values("name"), ["Alice", "Bob"]);
            assert_eq!(d.table("users").where_not_in_query("name", d.table("posts").select(&["author"])).order_by("id").values("name"), ["Carol", "Dave"]);
            assert_eq!(Table::from_query(d.table("posts").group_by(&["author"]).agg(&[Agg::sum("likes").alias("total")]))
                .where_gt("total", 10).values("author"), ["Alice"]);
        });
        r.run("Queries in Tx sehen eigene Writes; Snapshot bleibt stabil", || {
            let d = db(); blog(&d);
            let snap = d.snapshot().unwrap();
            d.transaction(|tx| {
                tx.add("users", row! { id: 10, name: "Zoe", age: 99 })?;
                assert_eq!(tx.table("users").count(), 5);
                assert_eq!(tx.table("users").where_eq("name", "Zoe").patch(row! { age: 100 }), 1);
                assert_eq!(tx.table("users").where_eq("age", 100).delete(), 1);
                Ok(())
            }).unwrap();
            d.add("users", row! { id: 11, name: "Neu" });
            assert_eq!(snap.table("users").count(), 4);
            assert_eq!(d.count("users"), 5);
            assert!(matches!(snap.table("users").try_patch(row! { age: 1 }), Err(DbError::ReadOnly)));
        });

        println!("\n▌ 10 Lazy-Iteration");
        r.run("stream() == collect(), frühes Abbrechen, Fallback bei order_by", || {
            let d = db();
            d.create("big", schema! { @key id: i32, v: i32 });
            assert!(d.add_many("big", (0..30_000).map(|i| row! { id: i, v: i % 10 }).collect()));
            d.set_cache(false); // echtes Block-für-Block-Lesen von der Platte
            let eager = d.table("big").filter(with!(r => r["v"] == "3")).skip(5).limit(100).collect();
            let lazy: Vec<_> = d.table("big").filter(with!(r => r["v"] == "3")).skip(5).limit(100).stream().unwrap().map(|r| r.unwrap()).collect();
            assert_eq!(eager, lazy);
            assert_eq!(d.table("big").where_eq("v", 7).into_iter().count(), 3000);
            assert_eq!(d.table("big").stream().unwrap().take(3).count(), 3);
            assert_eq!(d.table("big").order_by("id").desc().stream().unwrap().next().unwrap().unwrap()[0], "29999");
        });

        println!("\n▌ 9 Migrationen");
        r.run("add/rename/remove field, rename table, FK wird nachgeführt", || {
            let d = db();
            d.create("users", schema! { @key id: i32, name: String });
            d.add("users", row! { id: 1, name: "A" });
            d.create("posts", schema! { @key id: i32, author: i32 }.references("author", "users", "id", OnDelete::Restrict));
            d.add("posts", row! { id: 1, author: 1 });
            assert!(!d.add_field("users", ColumnDef::new("email", ColumnKind::Text, None, false)), "Default nötig");
            assert!(d.add_field("users", ColumnDef::new("email", ColumnKind::Text, Some("n/a".into()), false)));
            assert!(d.rename_field("users", "id", "uid"));
            assert!(d.add("posts", row! { id: 2, author: 1 }) && !d.add("posts", row! { id: 3, author: 5 }));
            assert!(d.rename_table("users", "people") && d.has_table("people") && !d.has_table("users"));
            assert!(d.add("posts", row! { id: 3, author: 1 }) && !d.add("posts", row! { id: 4, author: 9 }));
            assert!(!d.remove_field("people", "uid") && !d.delete_table("people"), "referenziert → geschützt");
            assert!(d.remove_field("people", "email"));
            assert_eq!(d.get("people", "1"), ["1", "A"]);
            assert!(d.integrity_check().is_empty());
        });
        r.run("migrate(): versioniert, idempotent, atomar", || {
            let d = db();
            let steps: &[Migration] = &[
                (1, |tx| tx.create_table("t", schema! { @key id: i32, a: String })),
                (2, |tx| { tx.put("t", row! { id: 1, a: "x" })?; tx.add_field("t", ColumnDef::new("b", ColumnKind::Int, Some("7".into()), false)) }),
            ];
            assert_eq!(d.migrate(steps).unwrap(), 2);
            assert_eq!(d.migrate(steps).unwrap(), 2);
            let bad: Vec<Migration> = steps.iter().copied().chain([(3u32, (|tx: &Tx| {
                tx.add_field("t", ColumnDef::new("c", ColumnKind::Text, Some("z".into()), false))?;
                tx.put("t", row! { id: 2, a: "y", b: "kein-int" }).map(|_| ())
            }) as fn(&Tx) -> DbResult<()>)]).collect();
            assert!(d.migrate(&bad).is_err());
            assert_eq!(d.user_version(), 2);
            assert_eq!(d.get("t", "1"), ["1", "x", "7"], "Spalte c darf nicht existieren");
        });

        println!("\n▌ Export-Sicherheit");
        r.run("HTML/CSV/JSON escapen gefährliche Inhalte", || {
            let d = db();
            d.create("x", schema! { @key id: i32, v: String });
            d.add("x", row! { id: 1, v: "<script>alert(1)</script>" });
            d.add("x", row! { id: 2, v: "a;b,\"c\"" });
            let html = d.table("x").to_html();
            assert!(!html.contains("<script>alert") && html.contains("&lt;script&gt;"));
            assert!(d.table("x").to_csv().contains("\"a;b,\"\"c\"\"\""));
            assert!(d.table("x").to_json().contains("\\\"c\\\""));
        });

        println!("\n▌ 2 Crash-Sicherheit & Manipulationserkennung");
        r.run("Reste eines abgestürzten Commits werden ignoriert + aufgeräumt", || {
            let dir = tmpdir("leftover");
            { let d = DBCore::at(&dir); users(&d); d.put("users", row! { id: 1, name: "A" }); }
            let any = tbl_files(&dir).remove(0);
            let bytes = std::fs::read(&any).unwrap();
            std::fs::write(dir.join("users.00000000000000ff.tbl"), &bytes[..bytes.len() / 2]).unwrap();
            std::fs::write(dir.join("MANIFEST.tmp"), b"muell").unwrap();
            { let d = DBCore::at(&dir); assert_eq!(d.get("users", "1")[1], "A"); assert!(d.add("users", row! { id: 2, name: "B" })); }
            assert!(!dir.join("users.00000000000000ff.tbl").exists() && !dir.join("MANIFEST.tmp").exists());
            let _ = std::fs::remove_dir_all(&dir);
        });
        r.run("Bitflip / Abschneiden / Anhängen / Vertauschen / Manifest", || {
            let dir = tmpdir("tamper");
            let make = || {
                let _ = std::fs::remove_dir_all(&dir);
                let d = DBCore::at(&dir); d.set_sync(false); users(&d);
                assert!(d.add_many("users", (0..3000).map(|i| row! { id: i, name: format!("n{i}") }).collect()));
                d
            };
            let users_file = || tbl_files(&dir).into_iter().find(|p| p.to_string_lossy().contains("users")).unwrap();
            let d = make(); let f = users_file(); let mut b = std::fs::read(&f).unwrap();
            let m = b.len() / 2; b[m] ^= 1; std::fs::write(&f, &b).unwrap(); d.clear_cache();
            assert!(matches!(d.table("users").try_count(), Err(DbError::Crypto(_))), "Bitflip");
            assert!(!d.integrity_check().is_empty());

            let d = make(); let f = users_file(); let b = std::fs::read(&f).unwrap();
            let (mut off, mut ends) = (24usize, vec![]);
            while off < b.len() { off += 4 + u32::from_le_bytes(b[off..off + 4].try_into().unwrap()) as usize; ends.push(off); }
            std::fs::write(&f, &b[..ends[ends.len() - 2]]).unwrap(); d.clear_cache();
            assert!(d.table("users").try_count().is_err(), "Abschneiden an Blockgrenze");

            let d = make(); let f = users_file(); let mut b = std::fs::read(&f).unwrap();
            let l0 = u32::from_le_bytes(b[24..28].try_into().unwrap()) as usize;
            let s = 24 + 4 + l0; let l1 = u32::from_le_bytes(b[s..s + 4].try_into().unwrap()) as usize;
            let dup = b[s..s + 4 + l1].to_vec(); b.extend_from_slice(&dup); std::fs::write(&f, &b).unwrap(); d.clear_cache();
            assert!(d.table("users").try_count().is_err(), "Anhängen");

            let d = make(); d.create("other", schema! { @key id: i32, name: String }); d.add("other", row! { id: 1, name: "x" });
            let other = tbl_files(&dir).into_iter().find(|p| p.to_string_lossy().contains("other")).unwrap();
            std::fs::copy(&other, users_file()).unwrap(); d.clear_cache();
            assert!(d.table("users").try_count().is_err(), "Tabellen vertauscht");

            let d = make(); let mp = dir.join("MANIFEST"); let mut m = std::fs::read(&mp).unwrap();
            let last = m.len() - 1; m[last] ^= 1; std::fs::write(&mp, &m).unwrap();
            assert!(d.try_tables().is_err(), "Manifest");
            let _ = std::fs::remove_dir_all(&dir);
        });
        r.run("Falscher Schlüssel → Fehler, kein Panic", || {
            let dir = tmpdir("key");
            { let d = DBCore::at(&dir); users(&d); d.put("users", row! { id: 1, name: "A" }); }
            std::fs::write(dir.join(".key"), [7u8; 32]).unwrap();
            let d = DBCore::at(&dir);
            assert!(d.try_tables().is_err() && d.count("users") == 0);
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    println!("\n▌ 3 Concurrency (Threads)");
    if !only_crash {
        r.run("8 Schreiber-Threads × 40 Read-Modify-Write: nichts geht verloren", || {
            let d = db();
            d.create("c", schema! { @key id: i32, n: i64 = 0 });
            d.put("c", row! { id: 1, n: 0 });
            let hs: Vec<_> = (0..8).map(|_| { let d = d.clone(); thread::spawn(move || for _ in 0..40 {
                d.transaction(|tx| { let n: i64 = tx.get("c", "1")?.unwrap()[1].parse().unwrap(); tx.update("c", "1", row! { n: n + 1 }) }).unwrap();
            }) }).collect();
            for h in hs { h.join().unwrap(); }
            assert_eq!(d.get("c", "1")[1], "320");
        });
        r.run("Leser sehen nie einen halben Commit (Kontostand-Summe konstant)", || {
            let d = db();
            d.create("acc", schema! { @key id: i32, bal: i64 });
            d.put("acc", row! { id: 1, bal: 500 }); d.put("acc", row! { id: 2, bal: 500 });
            let stop = Arc::new(AtomicBool::new(false));
            let writers: Vec<_> = (0..3).map(|w| { let d = d.clone(); thread::spawn(move || for i in 0..60 {
                let amt = (w * 7 + i) % 13;
                d.transaction(|tx| {
                    let a: i64 = tx.get("acc", "1")?.unwrap()[1].parse().unwrap();
                    let b: i64 = tx.get("acc", "2")?.unwrap()[1].parse().unwrap();
                    tx.update("acc", "1", row! { bal: a - amt })?; tx.update("acc", "2", row! { bal: b + amt })
                }).unwrap();
            }) }).collect();
            let readers: Vec<_> = (0..4).map(|_| { let (d, stop) = (d.clone(), stop.clone()); thread::spawn(move || {
                let mut n = 0;
                while !stop.load(Ordering::Relaxed) { let s = d.snapshot().expect("snapshot"); let sum = s.table("acc").try_sum("bal").expect("sum");
                    assert_eq!(sum, 1000.0, "Summe muss konstant sein"); n += 1; }
                n
            }) }).collect();
            for w in writers { w.join().unwrap(); }
            stop.store(true, Ordering::Relaxed);
            let n: i32 = readers.into_iter().map(|r| r.join().unwrap()).sum();
            assert!(n > 0);
        });
        r.run("Leser werden von offener Schreib-Transaktion nicht blockiert", || {
            let d = db(); users(&d); d.put("users", row! { id: 1, name: "A" });
            let tx = d.begin().unwrap(); tx.add("users", row! { id: 2, name: "B" }).unwrap();
            let hs: Vec<_> = (0..8).map(|_| { let d = d.clone(); thread::spawn(move || d.count("users")) }).collect();
            for h in hs { assert_eq!(h.join().unwrap(), 1); }
            tx.commit().unwrap();
            assert_eq!(d.count("users"), 2);
        });
        r.run("Zwei getrennte Handles auf demselben Verzeichnis", || {
            let dir = tmpdir("two");
            let a = DBCore::at(&dir); a.set_sync(false);
            a.create("c", schema! { @key id: i32, n: i64 = 0 }); a.put("c", row! { id: 1, n: 0 });
            let b = DBCore::at(&dir); b.set_sync(false);
            let inc = |d: DBCore| thread::spawn(move || for _ in 0..50 {
                d.transaction(|tx| { let n: i64 = tx.get("c", "1")?.unwrap()[1].parse().unwrap(); tx.update("c", "1", row! { n: n + 1 }) }).unwrap(); });
            let (t1, t2) = (inc(a.clone()), inc(b.clone()));
            t1.join().unwrap(); t2.join().unwrap();
            assert_eq!(a.get("c", "1")[1], "100");
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    println!("\n▌ 3+2 Mehrere Prozesse & kill -9");
    r.run("3 Prozesse + Eltern schreiben gleichzeitig, nichts geht verloren", || {
        let (dir, d) = counter_db("multiproc");
        let mut kids: Vec<_> = (0..3).map(|_| spawn_child(&dir, 40)).collect();
        for _ in 0..40 { d.transaction(|tx| { let c: i64 = tx.get("c", "1")?.unwrap()[1].parse().unwrap(); tx.update("c", "1", row! { n: c + 1 }) }).unwrap(); }
        for k in &mut kids { assert!(k.wait().unwrap().success()); }
        assert_eq!(d.get("c", "1")[1], "160");
        assert!(d.integrity_check().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    });
    r.run("6× SIGKILL mitten in Commits → DB bleibt konsistent", || {
        let (dir, _d) = counter_db("kill9");
        let mut last = 0i64;
        for round in 0..6u64 {
            let mut k = spawn_child(&dir, 0);
            thread::sleep(Duration::from_millis(250 + round * 40));
            k.kill().unwrap(); k.wait().unwrap();
            let d2 = DBCore::at(&dir); // neu öffnen = Recovery
            let problems = d2.integrity_check();
            assert!(problems.is_empty(), "Runde {round}: {problems:?}");
            let n: i64 = d2.get("c", "1")[1].parse().unwrap();
            assert!(n >= last, "Zähler darf nie zurückgehen");
            assert_eq!(d2.table("log").max("c").parse::<i64>().unwrap_or(0), n, "c und log gehören zu EINEM Commit");
            last = n;
        }
        assert!(last > 0);
        let _ = std::fs::remove_dir_all(&dir);
    });

    let _ = std::panic::take_hook();
    println!("\n──────────────────────────────────────────────────────────────");
    println!("  {} bestanden, {} fehlgeschlagen   ({:.1?})", r.ok, r.failed.len(), t0.elapsed());
    if !r.failed.is_empty() {
        for f in &r.failed { println!("    ✘ {f}"); }
        std::process::exit(1);
    }
    println!("  Alles grün ✔");
}

// ───────────── Hilfen für Prozess-Tests ─────────────

fn tbl_files(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir).unwrap().flatten().map(|e| e.path())
        .filter(|p| p.extension().map_or(false, |e| e == "tbl")).collect()
}

fn counter_db(tag: &str) -> (PathBuf, DBCore) {
    let dir = tmpdir(tag);
    let d = DBCore::at(&dir); d.set_sync(false);
    d.create("c", schema! { @key id: i32, n: i64 = 0 });
    d.create("log", schema! { @key who: u32, c: i64 });
    d.put("c", row! { id: 1, n: 0 });
    (dir, d)
}

fn spawn_child(dir: &Path, n: usize) -> std::process::Child {
    std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--child", &dir.to_string_lossy(), &n.to_string()])
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .spawn().unwrap()
}

/// Worker: erhöht den Zähler in EINER Transaktion gemeinsam mit einem Log-Eintrag.
fn child(dir: &str, n: usize) {
    let d = DBCore::at(dir); d.set_sync(false);
    let mut i = 0;
    while n == 0 || i < n {
        d.transaction(|tx| {
            let c: i64 = tx.get("c", "1")?.unwrap()[1].parse().unwrap();
            tx.put("c", row! { id: 1, n: c + 1 })?;
            tx.put("log", row! { who: std::process::id(), c: c + 1 }).map(|_| ())
        }).unwrap();
        i += 1;
    }
}

fn web() {
    let d = DBCore::new("selftest-web");
    d.create_if_missing("users", schema! { @key id: i32, name: String, views: i64 = 0 });
    d.put("users", row! { id: 1, name: "Alice", views: 5 });
    d.put("users", row! { id: 2, name: "<b>Bob</b>", views: 0 });
    println!("Web-Interface: http://127.0.0.1:8080   (Strg+C beendet)");
    d.open_interface(8080);
}
