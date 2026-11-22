//! A ruleset directory:
//!
//! ```text
//! <dir>/rules/<rule id>.json     one rule/1 per file
//! <dir>/fixtures/...             fixture files a rule names by relative path
//! <dir>/decisions.jsonl          decision/1 lines (the only way to loosen or retire a rule)
//! <dir>/profile.json             optional: family weights and gate policy
//! ```
//! Every command that scores or gates first runs [`self_test`]: each active rule must FAIL its red fixture and PASS its green one.
//! A rule that does not is `broken` and the run refuses ("a guard never seen to fail is not known to work").
use crate::model::{Decision, DecisionAction, Family, FixtureRef, Mode, Outcome, Rule, RuleState};
use crate::util::{canonical, read_jsonl, sha256_hex};
use crate::{invalid, refused, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Gate policy of one family: a drop beyond noise blocks or warns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DropPolicy {
    #[default]
    Block,
    Warn,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// `W_f` per family; a family not named weighs 1.
    #[serde(default)]
    pub family_weights: BTreeMap<String, f64>,
    /// Per family: what a drop beyond noise does (default block).
    #[serde(default)]
    pub family_drop: BTreeMap<String, DropPolicy>,
    /// Subtracted from the product score per overclaim (default 0: overclaims are reported, not folded in).
    #[serde(default)]
    pub overclaim_penalty: f64,
}

impl Profile {
    pub fn weight(&self, f: Family) -> f64 {
        self.family_weights.get(f.as_str()).copied().unwrap_or(1.0)
    }
    pub fn drop_policy(&self, f: Family) -> DropPolicy {
        self.family_drop.get(f.as_str()).copied().unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
pub struct Ruleset {
    pub dir: PathBuf,
    /// Every rule file, by id (active, draft and retired).
    pub rules: BTreeMap<String, Rule>,
    /// Resolved fixtures per rule id: (red facts, green facts).
    pub fixtures: BTreeMap<String, (Map<String, Value>, Map<String, Value>)>,
    pub decisions: Vec<Decision>,
    pub profile: Profile,
}

/// One rule's self-test.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SelfTest {
    pub rule: String,
    pub version: u32,
    pub red: Outcome,
    pub green: Outcome,
    pub ok: bool,
}

pub fn resolve_fixture(dir: &Path, f: &FixtureRef, rule: &str) -> Result<Map<String, Value>> {
    match f {
        FixtureRef::Inline { facts } => Ok(facts.clone()),
        FixtureRef::Path(p) => {
            if p.contains("..") || Path::new(p).is_absolute() {
                return invalid(format!("rule {rule}: fixture path `{p}` must stay inside the ruleset"));
            }
            let path = dir.join(p);
            let text = std::fs::read_to_string(&path).map_err(|e| crate::Error::Invalid(format!("rule {rule}: fixture {p}: {e}")))?;
            let v: Value = serde_json::from_str(&text).map_err(|e| crate::Error::Invalid(format!("rule {rule}: fixture {p}: {e}")))?;
            match v.get("facts").and_then(Value::as_object) {
                Some(m) => Ok(m.clone()),
                None => invalid(format!("rule {rule}: fixture {p} needs a `facts` object")),
            }
        }
    }
}

impl Ruleset {
    pub fn load(dir: &Path) -> Result<Ruleset> {
        let rdir = dir.join("rules");
        if !rdir.is_dir() {
            return invalid(format!("{}: no rules/ folder", dir.display()));
        }
        let mut paths: Vec<PathBuf> = std::fs::read_dir(&rdir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        paths.sort();
        let mut rules = BTreeMap::new();
        let mut fixtures = BTreeMap::new();
        for p in paths {
            let v: Value = serde_json::from_str(&std::fs::read_to_string(&p)?)
                .map_err(|e| crate::Error::Invalid(format!("{}: {e}", p.display())))?;
            let r = Rule::from_value(&v).map_err(|e| crate::Error::Invalid(format!("{}: {e}", p.display())))?;
            if p.file_stem().and_then(|s| s.to_str()) != Some(r.id.as_str()) {
                return invalid(format!("{}: file name must be `{}.json`", p.display(), r.id));
            }
            let red = resolve_fixture(dir, &r.red, &r.id)?;
            let green = resolve_fixture(dir, &r.green, &r.id)?;
            fixtures.insert(r.id.clone(), (red, green));
            rules.insert(r.id.clone(), r);
        }
        let dpath = dir.join("decisions.jsonl");
        let mut decisions = vec![];
        if dpath.is_file() {
            for v in read_jsonl(&dpath)? {
                decisions.push(Decision::from_value(&v)?);
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for d in &decisions {
            if !seen.insert(d.id.clone()) {
                return invalid(format!("decisions.jsonl: decision id {} appears twice", d.id));
            }
        }
        let ppath = dir.join("profile.json");
        let profile = if ppath.is_file() {
            serde_json::from_str(&std::fs::read_to_string(&ppath)?).map_err(|e| crate::Error::Invalid(format!("profile.json: {e}")))?
        } else {
            Profile::default()
        };
        Ok(Ruleset { dir: dir.to_path_buf(), rules, fixtures, decisions, profile })
    }

    /// Rules that score: state active.
    pub fn active(&self) -> impl Iterator<Item = &Rule> {
        self.rules.values().filter(|r| r.state == RuleState::Active)
    }

    pub fn decision(&self, id: &str) -> Option<&Decision> {
        self.decisions.iter().find(|d| d.id == id)
    }

    /// The digest of everything that decides a score: every rule (any state), its resolved fixtures, decisions and profile.
    pub fn digest(&self) -> String {
        let rules: Vec<Value> = self
            .rules
            .values()
            .map(|r| {
                let (red, green) = &self.fixtures[&r.id];
                json!({"rule": serde_json::to_value(r).unwrap_or(Value::Null), "red": red, "green": green})
            })
            .collect();
        let body = json!({
            "rules": rules,
            "decisions": self.decisions.iter().map(|d| serde_json::to_value(d).unwrap_or(Value::Null)).collect::<Vec<_>>(),
            "profile": serde_json::to_value(&self.profile).unwrap_or(Value::Null),
        });
        sha256_hex(canonical(&body).as_bytes())
    }

    /// The self-test of every active rule.
    pub fn self_test(&self) -> Vec<SelfTest> {
        self.active().map(|r| self_test_rule(r, &self.fixtures[&r.id])).collect()
    }

    /// Run the self-test and refuse when any rule is broken or when there is no active rule at all.
    pub fn require_self_test(&self) -> Result<Vec<SelfTest>> {
        let t = self.self_test();
        if t.is_empty() {
            return refused(format!("{}: no active rule; a suite of zero rules proves nothing", self.dir.display()));
        }
        let broken: Vec<String> = t
            .iter()
            .filter(|x| !x.ok)
            .map(|x| format!("{}@{} (red fixture gave {}, green gave {})", x.rule, x.version, x.red.as_str(), x.green.as_str()))
            .collect();
        if broken.is_empty() {
            Ok(t)
        } else {
            refused(format!("self-test: broken rule(s), a rule must fail its red fixture and pass its green one: {}", broken.join("; ")))
        }
    }
}

pub fn self_test_rule(r: &Rule, fx: &(Map<String, Value>, Map<String, Value>)) -> SelfTest {
    let red = r.eval(&fx.0);
    let green = r.eval(&fx.1);
    SelfTest { rule: r.id.clone(), version: r.version, red, green, ok: red == Outcome::Fail && green == Outcome::Pass }
}

/// One finding of the anti-gaming diff between a trusted base ruleset and a head ruleset.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Loosening {
    pub rule: String,
    /// removed | retired | check-loosened | weight-lowered | mode-lowered | changed-without-version
    pub what: String,
    /// The decision that allows it, when one is on the base.
    pub decision: Option<String>,
    pub allowed: bool,
}

/// Compare a head ruleset with its trusted base. A loosening is allowed only by a decision that is ALREADY in the base's
/// `decisions.jsonl` (a head cannot approve its own loosening) and names this rule with a matching action.
pub fn loosenings(base: &Ruleset, head: &Ruleset) -> Vec<Loosening> {
    let mut out = vec![];
    let allowed_by = |rule: &str, d: Option<&String>, action: DecisionAction| -> (Option<String>, bool) {
        match d {
            Some(id) => {
                let ok = base.decision(id).is_some_and(|x| x.rule == rule && x.action == action);
                (Some(id.clone()), ok)
            }
            None => (None, false),
        }
    };
    for b in base.active() {
        let push = |out: &mut Vec<Loosening>, what: &str, (decision, allowed): (Option<String>, bool)| {
            out.push(Loosening { rule: b.id.clone(), what: what.into(), decision, allowed });
        };
        let Some(h) = head.rules.get(&b.id) else {
            // a removed file has no `decision` field: the base must hold a retire decision for it
            let d = base.decisions.iter().find(|d| d.rule == b.id && d.action == DecisionAction::Retire).map(|d| d.id.clone());
            let allowed = d.is_some();
            out.push(Loosening { rule: b.id.clone(), what: "removed".into(), decision: d, allowed });
            continue;
        };
        if h.state != RuleState::Active {
            push(&mut out, "retired", allowed_by(&b.id, h.decision.as_ref(), DecisionAction::Retire));
            continue;
        }
        let same_text = serde_json::to_value(b).ok() == serde_json::to_value(h).ok() && base.fixtures.get(&b.id) == head.fixtures.get(&b.id);
        if same_text {
            continue;
        }
        if h.version == b.version {
            out.push(Loosening { rule: b.id.clone(), what: "changed-without-version".into(), decision: None, allowed: false });
            continue;
        }
        // the easy direction, measured: the head rule lets the base rule's red fixture through
        let base_red = &base.fixtures[&b.id].0;
        if h.eval(base_red) != Outcome::Fail {
            push(&mut out, "check-loosened", allowed_by(&b.id, h.decision.as_ref(), DecisionAction::Loosen));
        }
        if h.weight < b.weight {
            push(&mut out, "weight-lowered", allowed_by(&b.id, h.decision.as_ref(), DecisionAction::Loosen));
        }
        if h.mode < b.mode {
            push(&mut out, "mode-lowered", allowed_by(&b.id, h.decision.as_ref(), DecisionAction::Loosen));
        }
    }
    out
}

/// Mode of a rule id in whichever ruleset has it, preferring the stricter one.
pub fn strictest_mode(base: &Ruleset, head: &Ruleset, id: &str) -> Option<Mode> {
    match (base.rules.get(id).map(|r| r.mode), head.rules.get(id).map(|r| r.mode)) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}

#[cfg(test)]
pub(crate) mod testkit {
    use super::*;

    /// Write a ruleset folder: rules as JSON values, decisions as JSON values.
    pub fn write(dir: &Path, rules: &[Value], decisions: &[Value]) {
        let r = dir.join("rules");
        std::fs::create_dir_all(&r).unwrap();
        for e in std::fs::read_dir(&r).unwrap() {
            std::fs::remove_file(e.unwrap().path()).unwrap();
        }
        for v in rules {
            let id = v["id"].as_str().unwrap();
            std::fs::write(r.join(format!("{id}.json")), serde_json::to_string_pretty(v).unwrap()).unwrap();
        }
        let d: String = decisions.iter().map(|d| canonical(d) + "\n").collect();
        std::fs::write(dir.join("decisions.jsonl"), d).unwrap();
    }

    pub fn rule(id: &str, family: &str, min: i64, mode: &str) -> Value {
        json!({"schema": "rule/1", "id": id, "version": 1, "title": "t", "family": family, "kind": "deterministic", "mode": mode,
               "weight": 1, "check": {"fact": "x", "op": "ge", "value": min}, "red": {"facts": {"x": min - 1}},
               "green": {"facts": {"x": min}}, "owner": "o"})
    }

    pub fn decision(id: &str, rule: &str, action: &str) -> Value {
        json!({"schema": "decision/1", "id": id, "rule": rule, "action": action, "why": "w", "decided_by": "maintainer", "decided_at": "2026-01-01"})
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;

    #[test]
    fn a_rule_that_passes_its_red_fixture_is_broken_and_the_run_refuses() {
        let d = tempfile::tempdir().unwrap();
        let mut hollow = rule("ui.a", "ui", 44, "blocking");
        // a check hollowed out to always pass: `exists` holds for the red fixture too
        hollow["check"] = json!({"fact": "x", "op": "exists"});
        write(d.path(), &[rule("ui.b", "ui", 10, "warn"), hollow], &[]);
        let rs = Ruleset::load(d.path()).unwrap();
        let err = rs.require_self_test().unwrap_err().to_string();
        assert!(err.contains("ui.a@1") && err.contains("red fixture gave pass"), "{err}");
        assert!(!err.contains("ui.b"));
        // green: the honest rule set passes its self-test
        write(d.path(), &[rule("ui.b", "ui", 10, "warn")], &[]);
        assert_eq!(Ruleset::load(d.path()).unwrap().require_self_test().unwrap().len(), 1);
    }

    #[test]
    fn a_rule_that_fails_its_green_fixture_or_is_unmeasured_on_red_is_broken() {
        let d = tempfile::tempdir().unwrap();
        let mut r = rule("ui.a", "ui", 44, "warn");
        r["green"] = json!({"facts": {"x": 1}});
        write(d.path(), &[r.clone()], &[]);
        assert!(Ruleset::load(d.path()).unwrap().require_self_test().is_err());
        r["green"] = json!({"facts": {"x": 50}});
        r["red"] = json!({"facts": {}});
        write(d.path(), &[r], &[]);
        assert!(Ruleset::load(d.path()).unwrap().require_self_test().unwrap_err().to_string().contains("red fixture gave unmeasured"));
    }

    #[test]
    fn zero_rules_is_red() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), &[], &[]);
        assert!(Ruleset::load(d.path()).unwrap().require_self_test().unwrap_err().to_string().contains("zero rules"));
    }

    #[test]
    fn fixture_files_resolve_and_may_not_escape() {
        let d = tempfile::tempdir().unwrap();
        let mut r = rule("ui.a", "ui", 44, "warn");
        r["red"] = json!("fixtures/a.red.json");
        std::fs::create_dir_all(d.path().join("fixtures")).unwrap();
        std::fs::write(d.path().join("fixtures/a.red.json"), r#"{"facts": {"x": 3}}"#).unwrap();
        write(d.path(), &[r.clone()], &[]);
        assert!(Ruleset::load(d.path()).unwrap().require_self_test().is_ok());
        r["red"] = json!("../outside.json");
        write(d.path(), &[r], &[]);
        assert!(Ruleset::load(d.path()).unwrap_err().to_string().contains("inside the ruleset"));
    }

    #[test]
    fn the_digest_moves_with_any_rule_or_fixture_change() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), &[rule("ui.a", "ui", 44, "warn")], &[]);
        let a = Ruleset::load(d.path()).unwrap().digest();
        write(d.path(), &[rule("ui.a", "ui", 45, "warn")], &[]);
        let b = Ruleset::load(d.path()).unwrap().digest();
        assert_ne!(a, b);
        write(d.path(), &[rule("ui.a", "ui", 44, "warn")], &[]);
        assert_eq!(Ruleset::load(d.path()).unwrap().digest(), a);
    }

    fn diff(base_rules: &[Value], base_dec: &[Value], head_rules: &[Value], head_dec: &[Value]) -> Vec<Loosening> {
        let (b, h) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        write(b.path(), base_rules, base_dec);
        write(h.path(), head_rules, head_dec);
        loosenings(&Ruleset::load(b.path()).unwrap(), &Ruleset::load(h.path()).unwrap())
    }

    #[test]
    fn loosening_a_threshold_needs_a_decision_already_on_the_base() {
        let base = rule("ui.a", "ui", 44, "blocking");
        let mut loose = rule("ui.a", "ui", 30, "blocking");
        loose["version"] = json!(2);
        // red: loosened, no decision
        let l = diff(&[base.clone()], &[], &[loose.clone()], &[]);
        assert_eq!((l[0].what.as_str(), l[0].allowed), ("check-loosened", false));
        // red: the head adds its own decision; it is not on the base, so it does not count
        loose["decision"] = json!("d-1");
        let l = diff(&[base.clone()], &[], &[loose.clone()], &[decision("d-1", "ui.a", "loosen")]);
        assert!(!l[0].allowed);
        // red: a decision on the base for another rule does not count
        let l = diff(&[base.clone()], &[decision("d-1", "ui.b", "loosen")], &[loose.clone()], &[]);
        assert!(!l[0].allowed);
        // green: the decision is on the base and names this rule
        let l = diff(&[base.clone()], &[decision("d-1", "ui.a", "loosen")], &[loose], &[]);
        assert!(l[0].allowed);
        // tightening needs nothing
        let mut tight = rule("ui.a", "ui", 48, "blocking");
        tight["version"] = json!(2);
        assert!(diff(&[base], &[], &[tight], &[]).is_empty());
    }

    #[test]
    fn retiring_removing_and_silent_edits_are_caught() {
        let base = rule("ui.a", "ui", 44, "blocking");
        let l = diff(&[base.clone()], &[], &[], &[]);
        assert_eq!((l[0].what.as_str(), l[0].allowed), ("removed", false));
        let l = diff(&[base.clone()], &[decision("d-2", "ui.a", "retire")], &[], &[]);
        assert!(l[0].allowed);
        let mut ret = base.clone();
        ret["state"] = json!("retired");
        ret["decision"] = json!("d-2");
        assert!(!diff(&[base.clone()], &[], &[ret.clone()], &[])[0].allowed);
        assert!(diff(&[base.clone()], &[decision("d-2", "ui.a", "retire")], &[ret], &[])[0].allowed);
        let mut silent = base.clone();
        silent["weight"] = json!(5);
        assert_eq!(diff(&[base.clone()], &[], &[silent], &[])[0].what, "changed-without-version");
        let mut down = base.clone();
        down["version"] = json!(2);
        down["mode"] = json!("advisory");
        down["weight"] = json!(0.5);
        let l = diff(&[base], &[], &[down], &[]);
        let whats: Vec<&str> = l.iter().map(|x| x.what.as_str()).collect();
        assert_eq!(whats, vec!["weight-lowered", "mode-lowered"]);
    }
}
