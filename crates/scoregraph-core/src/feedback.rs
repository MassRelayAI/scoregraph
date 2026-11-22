//! Feedback becomes permanent rules, red first.
//!
//! ```text
//! feedback add -> rule draft -> (probe observes the product) -> rule accept: RED on the named product version, or refused
//!              -> fix -> green -> the gate blocks any regression for good
//! ```
//! - `add` refuses a record that still holds an email or a phone number (the second scan; the first is the adapter's redaction).
//! - `accept` refuses a rule whose self-test fails, a rule that passes on the product today (`not-reproduced`, recorded on the
//!   feedback), a rule with no observation to judge by, and a new version that loosens the old one without a decision.
//! - `retire` needs a decision record in the ruleset; the rule file stays, state `retired`.
//!
//! Feedback records are never edited: every status change is a `feedback-event` row on the chain.
use crate::ledger::Ledger;
use crate::model::{Decision, DecisionAction, Feedback, FeedbackStatus, Outcome, Rule, RuleState};
use crate::redact;
use crate::ruleset::{is_looser, resolve_fixture, self_test_rule, Ruleset};
use crate::util::canonical;
use crate::{invalid, refused, Result};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Default, Serialize, PartialEq)]
pub struct AddReport {
    pub added: Vec<String>,
    pub already_stored: Vec<String>,
}

/// Validate, scan and store feedback records. A PII hit refuses the whole batch (nothing is written).
pub fn add(ledger: &mut Ledger, records: &[Value], dry_run: bool) -> Result<AddReport> {
    let mut parsed = vec![];
    for v in records {
        let f = Feedback::from_value(v)?;
        let mut hits: Vec<&str> = redact::scan(&f.text);
        for l in &f.links {
            hits.extend(redact::scan(l));
        }
        if !hits.is_empty() {
            hits.sort();
            hits.dedup();
            return refused(format!("feedback {}: holds {} after redaction; redact at the edge (scoregraph adapter ...) and retry", f.id, hits.join(" and ")));
        }
        parsed.push((f, v.clone()));
    }
    let stored: std::collections::BTreeSet<String> = ledger.entries("feedback", None)?.into_iter().map(|e| e.key).collect();
    let mut rep = AddReport::default();
    let mut recs = vec![];
    for (f, v) in parsed {
        if stored.contains(&f.id) || rep.added.contains(&f.id) {
            rep.already_stored.push(f.id);
            continue;
        }
        rep.added.push(f.id.clone());
        recs.push(("feedback", f.id, v));
    }
    if !dry_run && !recs.is_empty() {
        ledger.append_many(&recs)?;
    }
    Ok(rep)
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FeedbackState {
    pub id: String,
    pub product: String,
    pub source: String,
    pub text: String,
    pub status: String,
    pub rules: Vec<String>,
    pub history: Vec<Value>,
}

/// Every feedback record with its current status (the record's own, then each event in chain order).
pub fn states(ledger: &Ledger) -> Result<BTreeMap<String, FeedbackState>> {
    let mut out = BTreeMap::new();
    for e in ledger.entries("feedback", None)? {
        let f = Feedback::from_value(&e.body)?;
        out.insert(
            f.id.clone(),
            FeedbackState {
                id: f.id.clone(),
                product: f.product.clone(),
                source: serde_json::to_value(f.source)?.as_str().unwrap_or("").into(),
                text: f.text.clone(),
                status: f.status.as_str().into(),
                rules: f.rules.clone(),
                history: vec![],
            },
        );
    }
    for e in ledger.entries("feedback-event", None)? {
        if let Some(s) = out.get_mut(&e.key) {
            if let Some(st) = e.body["status"].as_str() {
                s.status = st.into();
            }
            if let Some(r) = e.body["rule"].as_str() {
                if !s.rules.iter().any(|x| x == r) {
                    s.rules.push(r.into());
                }
            }
            s.history.push(e.body);
        }
    }
    Ok(out)
}

pub fn event(ledger: &mut Ledger, id: &str, status: FeedbackStatus, rule: Option<&str>, note: &str, at: &str) -> Result<i64> {
    let mut b = json!({"feedback": id, "status": status.as_str(), "note": note, "at": at});
    if let Some(r) = rule {
        b["rule"] = json!(r);
    }
    ledger.append("feedback-event", id, &b)
}

/// A rule skeleton for a feedback record. The check and fixtures are placeholders a person or a model fills in; `accept` will
/// refuse it until they are real (its self-test fails as written).
pub fn draft(ledger: &mut Ledger, feedback_id: &str, rule_id: &str, owner: &str, at: &str) -> Result<Value> {
    let st = states(ledger)?;
    let Some(f) = st.get(feedback_id) else { return invalid(format!("no feedback {feedback_id} in the ledger")) };
    let family = rule_id.split('.').next().unwrap_or("");
    let kind = if family == "judged" { "judged" } else { "deterministic" };
    let d = json!({
        "schema": "rule/1", "id": rule_id, "version": 1, "title": format!("from feedback {feedback_id}: {}", f.text.chars().take(80).collect::<String>()),
        "family": family, "kind": kind, "mode": "advisory", "weight": 1,
        "check": {"fact": "todo.fact", "op": "eq", "value": true},
        "red": {"facts": {}}, "green": {"facts": {}},
        "owner": owner, "source_feedback": [feedback_id], "state": "draft",
    });
    Rule::from_value(&d)?;
    event(ledger, feedback_id, FeedbackStatus::RuleDrafted, Some(rule_id), "rule drafted", at)?;
    Ok(d)
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Accepted {
    pub rule: String,
    pub version: u32,
    pub red_on: String,
    pub failing: usize,
    pub measured: usize,
    pub path: String,
}

/// Accept a draft into the ruleset: self-test, then RED on `product@version`, then written to `rules/<id>.json`.
pub fn accept(ledger: &mut Ledger, ruleset_dir: &Path, draft: &Value, product: &str, version: &str, at: &str) -> Result<Accepted> {
    let mut v = draft.clone();
    v["state"] = json!("active");
    let rule = Rule::from_value(&v)?;
    let rs = Ruleset::load(ruleset_dir)?;
    let fx = (resolve_fixture(ruleset_dir, &rule.red, &rule.id)?, resolve_fixture(ruleset_dir, &rule.green, &rule.id)?);
    let t = self_test_rule(&rule, &fx);
    if !t.ok {
        return refused(format!("rule {}: self-test failed (red fixture gave {}, green gave {}); a rule must fail its red fixture and pass its green one",
            rule.id, t.red.as_str(), t.green.as_str()));
    }
    let fb = states(ledger)?;
    for f in &rule.source_feedback {
        if !fb.contains_key(f) {
            return refused(format!("rule {}: source feedback {f} is not in the ledger", rule.id));
        }
    }
    if let Some(old) = rs.rules.get(&rule.id) {
        if rule.version <= old.version {
            return refused(format!("rule {}: version {} is not above the ruleset's {}", rule.id, rule.version, old.version));
        }
        let (or, og) = &rs.fixtures[&rule.id];
        let observed: Vec<_> = ledger.observations(product, version)?.into_iter().filter(|o| o.rule.id == rule.id).filter_map(|o| o.facts).collect();
        let mut probes: Vec<&serde_json::Map<String, Value>> = vec![or, og, &fx.0, &fx.1];
        probes.extend(observed.iter());
        let allowed = rule.decision.as_ref().and_then(|d| rs.decision(d)).is_some_and(|d| d.rule == rule.id && d.action == DecisionAction::Loosen);
        if is_looser(old, &rule, &probes) && !allowed {
            return refused(format!("rule {}: version {} lets through what version {} held back (a loosening); it needs a loosen decision", rule.id, rule.version, old.version));
        }
    }
    let obs: Vec<_> = ledger.observations(product, version)?.into_iter().filter(|o| o.rule.id == rule.id).collect();
    let outs: Vec<Outcome> = obs.iter().map(|o| o.outcome_under(&rule)).filter(|o| o.value().is_some()).collect();
    if outs.is_empty() {
        return refused(format!("rule {}: no measured observation of it on {product}@{version} ({} stored); probe the product first, then accept", rule.id, obs.len()));
    }
    let failing = outs.iter().filter(|o| **o != Outcome::Pass).count();
    if failing == 0 {
        for f in &rule.source_feedback {
            event(ledger, f, FeedbackStatus::NotReproduced, Some(&rule.id), &format!("rule passes on {product}@{version}: sharpen it"), at)?;
        }
        return refused(format!("rule {}: passes on {product}@{version} ({} observations): not-reproduced; a rule is accepted only when it is red on the product today", rule.id, outs.len()));
    }
    let path = ruleset_dir.join("rules").join(format!("{}.json", rule.id));
    std::fs::write(&path, serde_json::to_string_pretty(&rule)? + "\n")?;
    ledger.append("rule-event", &rule.id, &json!({"event": "accepted", "rule": rule.id, "version": rule.version,
        "red_on": format!("{product}@{version}"), "failing": failing, "measured": outs.len(), "rule_digest": crate::util::sha256_hex(canonical(&serde_json::to_value(&rule)?).as_bytes()), "at": at}))?;
    for f in &rule.source_feedback {
        event(ledger, f, FeedbackStatus::RedProven, Some(&rule.id), &format!("red on {product}@{version}"), at)?;
    }
    Ok(Accepted { rule: rule.id, version: rule.version, red_on: format!("{product}@{version}"), failing, measured: outs.len(), path: path.display().to_string() })
}

/// Append a decision record to the ruleset's `decisions.jsonl` and the ledger.
pub fn add_decision(ledger: &mut Ledger, ruleset_dir: &Path, d: &Value) -> Result<Decision> {
    let dec = Decision::from_value(d)?;
    let rs = Ruleset::load(ruleset_dir)?;
    if rs.decision(&dec.id).is_some() {
        return refused(format!("decision {} already exists; decisions are never rewritten", dec.id));
    }
    let path = ruleset_dir.join("decisions.jsonl");
    let mut text = if path.is_file() { std::fs::read_to_string(&path)? } else { String::new() };
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&canonical(&serde_json::to_value(&dec)?));
    text.push('\n');
    std::fs::write(&path, text)?;
    ledger.append("decision", &dec.id, &serde_json::to_value(&dec)?)?;
    Ok(dec)
}

/// Retire a rule: only with a retire decision for it in the ruleset. The file stays, with state `retired`.
pub fn retire(ledger: &mut Ledger, ruleset_dir: &Path, rule_id: &str, decision: &str, at: &str) -> Result<()> {
    let rs = Ruleset::load(ruleset_dir)?;
    let Some(r) = rs.rules.get(rule_id) else { return invalid(format!("no rule {rule_id}")) };
    let ok = rs.decision(decision).is_some_and(|d| d.rule == rule_id && d.action == DecisionAction::Retire);
    if !ok {
        return refused(format!("rule {rule_id}: retiring needs a retire decision for this rule in decisions.jsonl (got `{decision}`)"));
    }
    let mut r = r.clone();
    r.state = RuleState::Retired;
    r.decision = Some(decision.into());
    std::fs::write(ruleset_dir.join("rules").join(format!("{rule_id}.json")), serde_json::to_string_pretty(&r)? + "\n")?;
    ledger.append("rule-event", rule_id, &json!({"event": "retired", "rule": rule_id, "version": r.version, "decision": decision, "at": at}))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ruleset::testkit::{decision, rule, write};

    fn fb(id: &str, text: &str) -> Value {
        json!({"schema": "feedback/1", "id": id, "product": "example-app", "source": "tester", "received_at": "2026-01-01", "text": text, "status": "new"})
    }

    fn obs(ledger: &mut Ledger, rule: &str, x: i64) {
        let o = json!({"schema": "observation/1", "product": "example-app", "version": "a1", "rule": {"id": rule, "version": 1},
            "context": {}, "facts": {"x": x}, "probe": {"id": "p", "version": "1"}});
        ledger.append("observation", "example-app@a1", &o).unwrap();
    }

    fn real_draft(ledger: &mut Ledger, id: &str) -> Value {
        let mut d = draft(ledger, "fb-1", id, "screens/answer", "t").unwrap();
        d["check"] = json!({"fact": "x", "op": "ge", "value": 20});
        d["red"] = json!({"facts": {"x": 10}});
        d["green"] = json!({"facts": {"x": 24}});
        d
    }

    #[test]
    fn feedback_with_pii_is_refused_and_nothing_is_written() {
        let mut l = Ledger::in_memory().unwrap();
        let e = add(&mut l, &[fb("fb-1", "fine"), fb("fb-2", "mail me at a@example.com")], false).unwrap_err().to_string();
        assert!(e.contains("fb-2") && e.contains("email") && !e.contains("a@example.com"), "{e}");
        assert!(l.entries("feedback", None).unwrap().is_empty());
        let r = add(&mut l, &[fb("fb-1", "fine"), fb("fb-1", "fine")], false).unwrap();
        assert_eq!((r.added.len(), r.already_stored.len()), (1, 1));
        assert_eq!(add(&mut l, &[fb("fb-1", "fine")], false).unwrap().already_stored, vec!["fb-1"]);
    }

    #[test]
    fn a_rule_that_passes_on_the_product_today_is_refused_as_not_reproduced() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), &[rule("ui.other", "ui", 1, "warn")], &[]);
        let mut l = Ledger::in_memory().unwrap();
        add(&mut l, &[fb("fb-1", "answer buttons are too small")], false).unwrap();
        let dr = real_draft(&mut l, "ui.target.answer");
        // no observation yet: refused, probe first
        assert!(accept(&mut l, d.path(), &dr, "example-app", "a1", "t").unwrap_err().to_string().contains("probe the product first"));
        // the product already passes: refused, and the feedback says not-reproduced
        obs(&mut l, "ui.target.answer", 30);
        assert!(accept(&mut l, d.path(), &dr, "example-app", "a1", "t").unwrap_err().to_string().contains("not-reproduced"));
        assert_eq!(states(&l).unwrap()["fb-1"].status, "not-reproduced");
        assert!(!d.path().join("rules/ui.target.answer.json").exists());
        // red today: accepted, written, feedback red-proven
        obs(&mut l, "ui.target.answer", 12);
        let a = accept(&mut l, d.path(), &dr, "example-app", "a1", "t").unwrap();
        assert_eq!((a.failing, a.measured), (1, 2));
        assert_eq!(states(&l).unwrap()["fb-1"].status, "red-proven");
        let rs = Ruleset::load(d.path()).unwrap();
        assert_eq!(rs.rules["ui.target.answer"].state, RuleState::Active);
        assert!(rs.require_self_test().is_ok());
        assert_eq!(l.verify().unwrap(), l.conn().query_row("SELECT COUNT(*) FROM entries", [], |r| r.get::<_, i64>(0)).unwrap());
    }

    #[test]
    fn an_unfilled_draft_fails_its_self_test() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), &[rule("ui.other", "ui", 1, "warn")], &[]);
        let mut l = Ledger::in_memory().unwrap();
        add(&mut l, &[fb("fb-1", "x")], false).unwrap();
        let dr = draft(&mut l, "fb-1", "ui.y", "o", "t").unwrap();
        assert!(accept(&mut l, d.path(), &dr, "example-app", "a1", "t").unwrap_err().to_string().contains("self-test failed"));
    }

    #[test]
    fn a_new_version_that_loosens_needs_a_decision_and_retire_needs_one_too() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), &[rule("ui.target.answer", "ui", 20, "blocking")], &[]);
        let mut l = Ledger::in_memory().unwrap();
        add(&mut l, &[fb("fb-1", "x")], false).unwrap();
        obs(&mut l, "ui.target.answer", 5);
        let mut v2 = rule("ui.target.answer", "ui", 8, "blocking");
        v2["version"] = json!(2);
        assert!(accept(&mut l, d.path(), &v2, "example-app", "a1", "t").unwrap_err().to_string().contains("loosening"));
        assert!(retire(&mut l, d.path(), "ui.target.answer", "d-1", "t").unwrap_err().to_string().contains("needs a retire decision"));
        add_decision(&mut l, d.path(), &decision("d-1", "ui.target.answer", "retire")).unwrap();
        assert!(add_decision(&mut l, d.path(), &decision("d-1", "ui.target.answer", "retire")).is_err(), "a decision id is written once");
        retire(&mut l, d.path(), "ui.target.answer", "d-1", "t").unwrap();
        assert_eq!(Ruleset::load(d.path()).unwrap().rules["ui.target.answer"].state, RuleState::Retired);
    }
}
