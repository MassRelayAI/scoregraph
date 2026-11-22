//! End-to-end tests of the `scoregraph` binary on the example ruleset and the adapter fixtures. Every refusal is red-proved:
//! each test shows the command going red on a broken input and green on the honest one.
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_scoregraph"));
    for v in ["POSTHOG_HOST", "POSTHOG_PROJECT_ID", "POSTHOG_PERSONAL_API_KEY", "SCOREGRAPH_REDACT_SALT"] {
        c.env_remove(v);
    }
    c
}

fn run(args: &[&str]) -> (i32, String) {
    let o: Output = bin().args(args).output().unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    (o.status.code().unwrap_or(-1), text)
}

fn s(p: &Path) -> String {
    p.display().to_string()
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let t = to.join(e.file_name());
        if e.path().is_dir() {
            copy_dir(&e.path(), &t);
        } else {
            std::fs::copy(e.path(), t).unwrap();
        }
    }
}

/// A scratch folder holding a copy of the example ruleset and a fresh ledger with base (a1) and head (b2) ingested.
struct World {
    _d: tempfile::TempDir,
    root: PathBuf,
    rules: PathBuf,
    db: PathBuf,
}

fn world() -> World {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().to_path_buf();
    let rules = root.join("rules-base");
    copy_dir(&repo().join("rulesets/example"), &rules);
    let db = root.join("ledger.db");
    let obs = rules.join("observations");
    let (c, t) = run(&["ingest", "--db", &s(&db), "--rules", &s(&rules), &s(&obs.join("base-a1.jsonl")), &s(&obs.join("head-b2.jsonl"))]);
    assert_eq!(c, 0, "{t}");
    World { _d: d, root, rules, db }
}

fn edit_rule(dir: &Path, id: &str, f: impl FnOnce(&mut Value)) {
    let p = dir.join("rules").join(format!("{id}.json"));
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
    f(&mut v);
    std::fs::write(&p, serde_json::to_string_pretty(&v).unwrap()).unwrap();
}

#[test]
fn selftest_passes_on_the_example_and_refuses_a_hollow_rule() {
    let (c, t) = run(&["selftest", "--rules", &s(&repo().join("rulesets/example"))]);
    assert_eq!(c, 0, "{t}");
    assert!(t.contains("7 active rules"), "{t}");
    let w = world();
    edit_rule(&w.rules, "quality.headers.csp", |v| v["check"] = json!({"any": [{"fact": "headers", "op": "exists"}]}));
    let (c, t) = run(&["selftest", "--rules", &s(&w.rules)]);
    assert_eq!(c, 1, "{t}");
    assert!(t.contains("BROKEN quality.headers.csp@1") && t.contains("REFUSED"), "{t}");
    // a broken ruleset also refuses ingest and score
    let (c, _) = run(&["score", "--db", &s(&w.db), "--rules", &s(&w.rules), "--product", "example-web", "--version", "a1"]);
    assert_eq!(c, 1);
}

#[test]
fn score_with_claims_reports_proven_and_overclaims() {
    let w = world();
    let claims = repo().join("adapters/comparegraph-export/fixtures/export");
    let (c, t) = run(&["score", "--db", &s(&w.db), "--rules", &s(&w.rules), "--product", "example-web", "--version", "a1", "--claims", &s(&claims), "--claims-repo", "example-web", "--json"]);
    assert_eq!(c, 0, "{t}");
    let v: Value = serde_json::from_str(&t).unwrap();
    assert_eq!(v["claims"]["proven"], json!(["export.csv"]));
    assert_eq!(v["claims"]["overclaims"], json!(["share.link"]), "claimed partial, the proof fails");
    assert_eq!(v["claims"]["features"], 4);
    assert_eq!(v["rules"]["feature.share.link"]["letter"], "fail");
    assert_eq!(v["coverage"], 1.0);
    // zero observations is red, never green
    let (c, t) = run(&["score", "--db", &s(&w.db), "--rules", &s(&w.rules), "--product", "example-web", "--version", "zz"]);
    assert_eq!(c, 1, "{t}");
    assert!(t.contains("zero observations"));
}

#[test]
fn an_observation_whose_outcome_disagrees_with_its_facts_is_refused() {
    let w = world();
    let p = w.root.join("lie.jsonl");
    std::fs::write(&p, serde_json::to_string(&json!({"schema": "observation/1", "product": "example-web", "version": "c3",
        "rule": {"id": "ui.target.min-size", "version": 1}, "context": {}, "facts": {"target": {"min_px": 20}}, "outcome": "pass",
        "probe": {"id": "p", "version": "1"}})).unwrap()).unwrap();
    let (c, t) = run(&["ingest", "--db", &s(&w.db), "--rules", &s(&w.rules), &s(&p)]);
    assert_eq!(c, 1, "{t}");
    assert!(t.contains("the probe says pass but its facts give fail"), "{t}");
}

#[test]
fn gate_exit_codes() {
    let w = world();
    let g = |base: &str, head: &str, head_rules: &Path| run(&["gate", "--db", &s(&w.db), "--product", "example-web", "--base", base, "--head", head, "--base-rules", &s(&w.rules), "--head-rules", &s(head_rules)]);
    // 0: the same version against itself
    let (c, t) = g("a1", "a1", &w.rules);
    assert_eq!(c, 0, "{t}");
    // 10: ui.target.min-size (blocking) passed on a1 and is partial on b2
    let (c, t) = g("a1", "b2", &w.rules);
    assert_eq!(c, 10, "{t}");
    assert!(t.contains("rule ui.target.min-size was pass on a1 and is partial on b2 (closes feedback fb-example-0001)"), "{t}");
    // 12: a head that skipped the sign-up flow
    let skipped: String = std::fs::read_to_string(w.rules.join("observations/base-a1.jsonl")).unwrap().lines()
        .filter(|l| !l.contains("flow.signup")).map(|l| l.replace("\"a1\"", "\"c3\"") + "\n").collect();
    std::fs::write(w.root.join("c3.jsonl"), skipped).unwrap();
    assert_eq!(run(&["ingest", "--db", &s(&w.db), "--rules", &s(&w.rules), &s(&w.root.join("c3.jsonl"))]).0, 0);
    let (c, t) = g("a1", "c3", &w.rules);
    assert_eq!(c, 12, "{t}");
    // 13: the head loosens the rule it regressed on, with no decision on the base
    let head = w.root.join("rules-head");
    copy_dir(&w.rules, &head);
    edit_rule(&head, "ui.target.min-size", |v| {
        v["version"] = json!(2);
        v["check"]["value"] = json!(32);
        v["red"] = json!({"facts": {"target": {"min_px": 31}}});
    });
    let (c, t) = g("a1", "b2", &head);
    assert_eq!(c, 13, "{t}");
    assert!(t.contains("check-loosened without a decision record"), "{t}");
    // the regression is still named under the base ruleset
    assert!(t.contains("was pass on a1 and is partial on b2"), "{t}");
    // with a loosen decision already on the base, the gaming reason goes; the base-ruleset regression still blocks (10)
    let (c, t) = run(&["decision", "add", "--db", &s(&w.db), "--rules", &s(&w.rules), "--id", "d-0001", "--rule", "ui.target.min-size",
        "--action", "loosen", "--from-version", "1", "--to-version", "2", "--why", "the platform guideline is 32 px for dense tables", "--by", "maintainer"]);
    assert_eq!(c, 0, "{t}");
    edit_rule(&head, "ui.target.min-size", |v| v["decision"] = json!("d-0001"));
    std::fs::copy(w.rules.join("decisions.jsonl"), head.join("decisions.jsonl")).unwrap();
    let (c, t) = g("a1", "b2", &head);
    assert_eq!(c, 10, "{t}");
    assert!(!t.contains("check-loosened"), "{t}");
}

#[test]
fn the_ledger_refuses_an_edited_row_and_the_anchor_refuses_rewritten_history() {
    let w = world();
    for v in ["a1", "b2"] {
        let (c, t) = run(&["score", "--db", &s(&w.db), "--rules", &s(&w.rules), "--product", "example-web", "--version", v, "--append", "--at", "2026-01-01T00:00:00Z"]);
        assert_eq!(c, 0, "{t}");
    }
    let committed = w.root.join("scores-committed.jsonl");
    assert_eq!(run(&["ledger", "export", "--db", &s(&w.db), "--out", &s(&committed)]).0, 0);
    let (c, t) = run(&["score", "--db", &s(&w.db), "--rules", &s(&w.rules), "--product", "example-web", "--version", "a1", "--append", "--at", "2026-01-02T00:00:00Z"]);
    assert_eq!(c, 0, "{t}");
    let current = w.root.join("scores.jsonl");
    assert_eq!(run(&["ledger", "export", "--db", &s(&w.db), "--out", &s(&current)]).0, 0);
    let (c, t) = run(&["ledger", "anchor", "--committed", &s(&committed), "--current", &s(&current)]);
    assert_eq!(c, 0, "{t}");
    assert!(t.contains("committed 2 rows are a prefix of the current 3"), "{t}");
    // red: the current copy with its first line edited
    let edited = std::fs::read_to_string(&current).unwrap().replacen("\"version\":\"a1\"", "\"version\":\"a9\"", 1);
    std::fs::write(w.root.join("edited.jsonl"), edited).unwrap();
    let (c, t) = run(&["ledger", "anchor", "--committed", &s(&committed), "--current", &s(&w.root.join("edited.jsonl"))]);
    assert_eq!(c, 1, "{t}");
    // the SQLite chain: UPDATE is refused by the trigger; an edit behind the trigger's back is found by verify and blocks writes
    let conn = rusqlite::Connection::open(&w.db).unwrap();
    assert!(conn.execute("UPDATE entries SET body = '{}' WHERE seq = 3", []).is_err());
    conn.execute_batch("DROP TRIGGER entries_no_update; UPDATE entries SET body = replace(body, '\"min_px\":48', '\"min_px\":49') WHERE seq = 1;").unwrap();
    drop(conn);
    let (c, t) = run(&["ledger", "verify", "--db", &s(&w.db)]);
    assert_eq!(c, 1, "{t}");
    assert!(t.contains("chain broken at seq 1"), "{t}");
    let (c, _) = run(&["score", "--db", &s(&w.db), "--rules", &s(&w.rules), "--product", "example-web", "--version", "a1"]);
    assert_eq!(c, 1, "scoring reads a broken ledger: refused");
    let (c, _) = run(&["gate", "--db", &s(&w.db), "--product", "example-web", "--base", "a1", "--head", "a1", "--base-rules", &s(&w.rules)]);
    assert_eq!(c, 1);
}

#[test]
fn a_truncated_ledger_is_refused_against_its_committed_head() {
    let w = world();
    let head = w.root.join("ledger-head.json");
    let (c, t) = run(&["ledger", "head", "--db", &s(&w.db), "--out", &s(&head)]);
    assert_eq!(c, 0, "{t}");
    assert_eq!(run(&["ledger", "verify", "--db", &s(&w.db), "--anchor", &s(&head)]).0, 0);
    let conn = rusqlite::Connection::open(&w.db).unwrap();
    conn.execute_batch("DROP TRIGGER entries_no_delete; DELETE FROM entries WHERE seq = (SELECT MAX(seq) FROM entries);").unwrap();
    drop(conn);
    // the cut chain still verifies by itself...
    assert_eq!(run(&["ledger", "verify", "--db", &s(&w.db)]).0, 0);
    // ...but not against the committed head, and neither does the gate
    let (c, t) = run(&["ledger", "verify", "--db", &s(&w.db), "--anchor", &s(&head)]);
    assert_eq!(c, 1, "{t}");
    assert!(t.contains("truncated"), "{t}");
    let (c, t) = run(&["gate", "--db", &s(&w.db), "--product", "example-web", "--base", "a1", "--head", "a1", "--base-rules", &s(&w.rules), "--anchor", &s(&head)]);
    assert_eq!(c, 1, "{t}");
}

#[test]
fn feedback_becomes_a_rule_only_when_it_is_red_today() {
    let w = world();
    let fb = w.root.join("fb.jsonl");
    let (c, t) = run(&["adapter", "run", "intake", "--in", &s(&repo().join("adapters/intake/fixtures/intake.jsonl")), "--out", &s(&fb)]);
    assert_eq!(c, 0, "{t}");
    assert!(!std::fs::read_to_string(&fb).unwrap().contains("@example.org"));
    assert_eq!(run(&["feedback", "add", "--db", &s(&w.db), &s(&fb)]).0, 0);
    let id = std::fs::read_to_string(&fb).unwrap().lines().next().map(|l| serde_json::from_str::<Value>(l).unwrap()["id"].as_str().unwrap().to_string()).unwrap();
    let draft = w.root.join("draft.json");
    let (c, t) = run(&["rule", "draft", "--db", &s(&w.db), "--feedback", &id, "--id", "flow.checkout.pay-button-works", "--owner", "flows/checkout", "--out", &s(&draft)]);
    assert_eq!(c, 0, "{t}");
    // red: the unfilled draft fails its own self-test
    let accept = |v: &str| run(&["rule", "accept", "--db", &s(&w.db), "--rules", &s(&w.rules), "--draft", &s(&draft), "--product", "example-web", "--version", v]);
    let (c, t) = accept("a1");
    assert_eq!(c, 1, "{t}");
    assert!(t.contains("self-test failed"));
    let mut d: Value = serde_json::from_str(&std::fs::read_to_string(&draft).unwrap()).unwrap();
    d["check"] = json!({"fact": "checkout.pay_click_navigates", "op": "eq", "value": true});
    d["red"] = json!({"facts": {"checkout": {"pay_click_navigates": false}}});
    d["green"] = json!({"facts": {"checkout": {"pay_click_navigates": true}}});
    std::fs::write(&draft, serde_json::to_string_pretty(&d).unwrap()).unwrap();
    // red: nothing observed yet
    let (c, t) = accept("a1");
    assert_eq!(c, 1, "{t}");
    assert!(t.contains("probe the product first"), "{t}");
    let probe = |v: &str, ok: bool| {
        let p = w.root.join(format!("pay-{v}.jsonl"));
        std::fs::write(&p, serde_json::to_string(&json!({"schema": "observation/1", "product": "example-web", "version": v,
            "rule": {"id": "flow.checkout.pay-button-works", "version": 1}, "context": {"viewport": "390"},
            "facts": {"checkout": {"pay_click_navigates": ok}}, "probe": {"id": "example-probe", "version": "0.1"}})).unwrap()).unwrap();
        assert_eq!(run(&["ingest", "--db", &s(&w.db), "--rules", &s(&w.rules), &s(&p)]).0, 0);
    };
    // red: the product already passes on b2 -> not-reproduced, recorded on the feedback
    probe("b2", true);
    let (c, t) = accept("b2");
    assert_eq!(c, 1, "{t}");
    assert!(t.contains("not-reproduced"), "{t}");
    let (_, list) = run(&["feedback", "list", "--db", &s(&w.db)]);
    assert!(list.contains("not-reproduced"), "{list}");
    // green: red on a1 -> accepted, written to the ruleset, feedback red-proven
    probe("a1", false);
    let (c, t) = accept("a1");
    assert_eq!(c, 0, "{t}");
    assert!(w.rules.join("rules/flow.checkout.pay-button-works.json").is_file());
    let (_, list) = run(&["feedback", "list", "--db", &s(&w.db)]);
    assert!(list.contains("red-proven"), "{list}");
    // retire needs a decision
    let (c, t) = run(&["rule", "retire", "--db", &s(&w.db), "--rules", &s(&w.rules), "--id", "flow.checkout.pay-button-works", "--decision", "d-9"]);
    assert_eq!(c, 1, "{t}");
    assert_eq!(run(&["ledger", "verify", "--db", &s(&w.db)]).0, 0);
}

#[test]
fn feedback_with_pii_is_refused_on_ingest() {
    let w = world();
    let p = w.root.join("raw.jsonl");
    std::fs::write(&p, serde_json::to_string(&json!({"schema": "feedback/1", "id": "fb-1", "product": "example-web", "source": "customer",
        "received_at": "2026-01-01", "text": "call me on +1 415 555 0100", "status": "new"})).unwrap()).unwrap();
    let (c, t) = run(&["feedback", "add", "--db", &s(&w.db), &s(&p)]);
    assert_eq!(c, 1, "{t}");
    assert!(t.contains("holds phone") && !t.contains("555 0100"), "{t}");
}

#[test]
fn adapters_are_inert_until_configured_and_dry_runs_write_nothing() {
    let (c, t) = run(&["adapter", "plan", "posthog-surveys"]);
    assert_eq!(c, 0, "{t}");
    assert!(t.contains("inert until configured") && t.contains("POSTHOG_PERSONAL_API_KEY"), "{t}");
    let o = bin().args(["adapter", "plan", "posthog-surveys"]).env("POSTHOG_HOST", "https://ph.example.com").env("POSTHOG_PROJECT_ID", "42")
        .env("POSTHOG_PERSONAL_API_KEY", "phx_not_a_real_key_000").output().unwrap();
    let t = String::from_utf8_lossy(&o.stdout);
    assert!(t.contains("\"configured\": true") && t.contains("https://ph.example.com/api/projects/42/query/"), "{t}");
    assert!(!t.contains("phx_not_a_real_key"), "a key value is never printed: {t}");
    for (name, input, extra) in [
        ("play-reviews", "adapters/play-reviews/fixtures/reviews-week-1.json", vec!["--product", "example-app"]),
        ("appstore-reviews", "adapters/appstore-reviews/fixtures/customer-reviews-page.json", vec!["--product", "example-app"]),
        ("tickets", "adapters/tickets/fixtures/helpdesk-export.json", vec!["--product", "example-web"]),
        ("posthog-surveys", "adapters/posthog/fixtures/survey-query-response.json", vec!["--product", "example-web"]),
        ("posthog-funnel", "adapters/posthog/fixtures/funnel-query-response.json", vec!["--product", "example-web", "--version", "a1", "--rule", "flow.signup.funnel", "--funnel", "signup"]),
        ("gatetrain-stamp", "adapters/gatetrain-stamp/fixtures", vec!["--product", "example-web", "--rule", "quality.chain.green"]),
    ] {
        let d = tempfile::tempdir().unwrap();
        let out = d.path().join("out.jsonl");
        let mut args = vec!["adapter", "run", name, "--in"];
        let inp = s(&repo().join(input));
        args.push(&inp);
        args.extend(extra.iter().copied());
        let so = s(&out);
        let mut dry = args.clone();
        dry.push("--dry-run");
        let (c, t) = run(&dry);
        assert_eq!(c, 0, "{name}: {t}");
        assert!(t.contains("\"dry_run\": true") && !out.exists(), "{name}: {t}");
        args.extend(["--out", &so]);
        let (c, t) = run(&args);
        assert_eq!(c, 0, "{name}: {t}");
        assert!(!std::fs::read_to_string(&out).unwrap().is_empty(), "{name}");
    }
    let (c, t) = run(&["adapter", "run", "comparegraph-export", "--in", &s(&repo().join("adapters/comparegraph-export/fixtures/export")), "--claims-repo", "example-web"]);
    assert_eq!(c, 0, "{t}");
    assert!(t.contains("\"share.link\": \"partial\""), "{t}");
}

#[test]
fn the_privacy_check_is_clean_here_and_red_on_a_private_word() {
    let (c, t) = run(&["privacy-check", "--root", &s(&repo())]);
    assert_eq!(c, 0, "{t}");
    // red: a throwaway repository with this repository's deny-list and one deny-listed word (assembled at run time)
    let d = tempfile::tempdir().unwrap();
    assert!(Command::new("git").args(["init", "-q"]).arg(d.path()).status().unwrap().success());
    std::fs::copy(repo().join(".privacy-denylist"), d.path().join(".privacy-denylist")).unwrap();
    let word = ["o", "n", "y", "x"].concat();
    std::fs::write(d.path().join("notes.md"), format!("deploy to {word} tonight\n")).unwrap();
    let (c, t) = run(&["privacy-check", "--root", &s(d.path())]);
    assert_eq!(c, 1, "{t}");
    assert!(t.contains("notes.md:1 (deny-listed word)") && !t.contains(&word), "{t}");
}
