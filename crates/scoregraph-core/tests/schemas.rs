//! The JSON Schema files under `schemas/` and the Rust formats must agree: same title, same required fields, same enums.
use scoregraph_core::adapters::intake;
use scoregraph_core::model::*;
use serde_json::Value;
use std::path::Path;

fn schema(name: &str) -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas").join(name);
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect()
}

fn same(a: Vec<String>, b: &[&str]) {
    let mut a = a;
    let mut b: Vec<String> = b.iter().map(|s| s.to_string()).collect();
    a.sort();
    b.sort();
    assert_eq!(a, b);
}

#[test]
fn titles_and_required_fields_match_the_code() {
    for (file, title, req) in [
        ("observation-1.schema.json", OBSERVATION_V1, &OBSERVATION_REQUIRED[..]),
        ("rule-1.schema.json", RULE_V1, &RULE_REQUIRED[..]),
        ("feedback-1.schema.json", FEEDBACK_V1, &FEEDBACK_REQUIRED[..]),
        ("decision-1.schema.json", DECISION_V1, &DECISION_REQUIRED[..]),
        ("score-1.schema.json", SCORE_V1, &SCORE_REQUIRED[..]),
        ("intake-1.schema.json", intake::INTAKE_V1, &intake::REQUIRED[..]),
    ] {
        let s = schema(file);
        assert_eq!(s["title"], title, "{file}");
        assert_eq!(s["properties"]["schema"]["const"], title, "{file}");
        same(strs(&s["required"]), req);
    }
    let keys: Vec<String> = schema("intake-1.schema.json")["properties"].as_object().unwrap().keys().cloned().collect();
    same(keys, &intake::FIELDS);
}

#[test]
fn enums_match_the_code() {
    let ser = |v: Vec<Value>| v.into_iter().map(|x| x.as_str().unwrap().to_string()).collect::<Vec<_>>();
    let o = schema("observation-1.schema.json");
    let outcomes = [Outcome::Pass, Outcome::Partial, Outcome::Fail, Outcome::Unmeasured, Outcome::Blocked].map(|x| serde_json::to_value(x).unwrap());
    assert_eq!(strs(&o["properties"]["outcome"]["enum"]), ser(outcomes.to_vec()));
    let r = schema("rule-1.schema.json");
    assert_eq!(strs(&r["properties"]["family"]["enum"]), Family::ALL.iter().map(|f| f.as_str().to_string()).collect::<Vec<_>>());
    assert_eq!(
        strs(&r["$defs"]["check"]["oneOf"][3]["properties"]["op"]["enum"]),
        scoregraph_core::check::OPS.iter().map(|s| s.to_string()).collect::<Vec<_>>()
    );
    let f = schema("feedback-1.schema.json");
    for s in strs(&f["properties"]["status"]["enum"]) {
        let st: FeedbackStatus = serde_json::from_value(Value::String(s.clone())).unwrap_or_else(|_| panic!("status {s}"));
        assert_eq!(st.as_str(), s);
    }
    for s in strs(&f["properties"]["source"]["enum"]) {
        serde_json::from_value::<Source>(Value::String(s.clone())).unwrap_or_else(|_| panic!("source {s}"));
    }
}

#[test]
fn every_example_rule_validates_against_the_rust_format() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rulesets/example/rules");
    let mut n = 0;
    for e in std::fs::read_dir(dir).unwrap() {
        let v: Value = serde_json::from_str(&std::fs::read_to_string(e.unwrap().path()).unwrap()).unwrap();
        Rule::from_value(&v).unwrap();
        n += 1;
    }
    assert!(n >= 5);
}
