//! The record formats. Each carries its version in a `schema` field (`observation/1`, `rule/1`, ...). The JSON Schema files under
//! `schemas/` describe the same shapes; a test keeps their `required` lists equal to the constants here.
use crate::check;
use crate::{invalid, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::sync::OnceLock;

pub const OBSERVATION_V1: &str = "observation/1";
pub const RULE_V1: &str = "rule/1";
pub const FEEDBACK_V1: &str = "feedback/1";
pub const DECISION_V1: &str = "decision/1";
pub const SCORE_V1: &str = "score/1";

pub const OBSERVATION_REQUIRED: [&str; 6] = ["schema", "product", "version", "rule", "context", "probe"];
pub const RULE_REQUIRED: [&str; 12] = ["schema", "id", "version", "title", "family", "kind", "mode", "weight", "check", "red", "green", "owner"];
pub const FEEDBACK_REQUIRED: [&str; 7] = ["schema", "id", "product", "source", "received_at", "text", "status"];
pub const DECISION_REQUIRED: [&str; 7] = ["schema", "id", "rule", "action", "why", "decided_by", "decided_at"];
pub const SCORE_REQUIRED: [&str; 8] = ["schema", "product", "version", "ruleset_digest", "at", "product_score", "families", "rules"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Pass,
    Partial,
    Fail,
    Unmeasured,
    Blocked,
}

impl Outcome {
    /// pass 1, partial 0.5, fail 0; unmeasured and blocked are not measured.
    pub fn value(self) -> Option<f64> {
        match self {
            Outcome::Pass => Some(1.0),
            Outcome::Partial => Some(0.5),
            Outcome::Fail => Some(0.0),
            Outcome::Unmeasured | Outcome::Blocked => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Pass => "pass",
            Outcome::Partial => "partial",
            Outcome::Fail => "fail",
            Outcome::Unmeasured => "unmeasured",
            Outcome::Blocked => "blocked",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Feature,
    Ui,
    Nav,
    Flow,
    Quality,
    Judged,
}

impl Family {
    pub const ALL: [Family; 6] = [Family::Feature, Family::Ui, Family::Nav, Family::Flow, Family::Quality, Family::Judged];
    pub fn as_str(self) -> &'static str {
        match self {
            Family::Feature => "feature",
            Family::Ui => "ui",
            Family::Nav => "nav",
            Family::Flow => "flow",
            Family::Quality => "quality",
            Family::Judged => "judged",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Deterministic,
    Judged,
}

/// How much a rule may decide. Ordered: advisory < warn < blocking. Moving down needs a decision record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Advisory,
    Warn,
    Blocking,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleState {
    #[default]
    Active,
    Draft,
    Retired,
}

/// A fixture: inline facts (`{"facts": {...}}`) or a path to such a file, relative to the ruleset directory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FixtureRef {
    Path(String),
    Inline { facts: Map<String, Value> },
}

/// `rule/1`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub schema: String,
    /// `<family>.<name>[.<name>...]`, lowercase.
    pub id: String,
    /// Starts at 1; any change to the check, weight, mode or fixtures is a new version.
    pub version: u32,
    pub title: String,
    pub family: Family,
    pub kind: Kind,
    pub mode: Mode,
    pub weight: f64,
    pub check: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial: Option<Value>,
    pub red: FixtureRef,
    pub green: FixtureRef,
    /// A screen, module or team that answers for the rule.
    pub owner: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_feedback: Vec<String>,
    /// CompareGraph feature ids this rule proves.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    #[serde(default)]
    pub state: RuleState,
    /// The decision record that allowed a retirement or a loosening.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
    /// For a judged rule: digest of prompt, model id, reference set and rubric.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judge_digest: Option<String>,
}

fn id_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[a-z][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)+$").unwrap())
}

impl Rule {
    pub fn from_value(v: &Value) -> Result<Rule> {
        require(v, &RULE_REQUIRED, "rule")?;
        let r: Rule = serde_json::from_value(v.clone()).map_err(|e| crate::Error::Invalid(format!("rule: {e}")))?;
        r.validate()?;
        Ok(r)
    }

    pub fn validate(&self) -> Result<()> {
        let id = &self.id;
        if self.schema != RULE_V1 {
            return invalid(format!("rule {id}: schema must be `{RULE_V1}`"));
        }
        if !id_re().is_match(id) {
            return invalid(format!("rule {id}: id must be `<family>.<name>`, lowercase, dot separated"));
        }
        if id.split('.').next() != Some(self.family.as_str()) {
            return invalid(format!("rule {id}: id must start with its family `{}.`", self.family.as_str()));
        }
        if self.version == 0 {
            return invalid(format!("rule {id}: version starts at 1"));
        }
        if !(self.weight.is_finite() && self.weight > 0.0) {
            return invalid(format!("rule {id}: weight must be a positive number"));
        }
        if (self.family == Family::Judged) != (self.kind == Kind::Judged) {
            return invalid(format!("rule {id}: kind `judged` belongs to family `judged` and only there"));
        }
        if self.kind == Kind::Judged && self.mode == Mode::Blocking && self.decision.is_none() {
            return invalid(format!("rule {id}: a judged rule blocks nothing until a decision promotes it (set `decision`)"));
        }
        if self.title.trim().is_empty() || self.owner.trim().is_empty() {
            return invalid(format!("rule {id}: title and owner are required"));
        }
        if self.state == RuleState::Retired && self.decision.is_none() {
            return invalid(format!("rule {id}: a retired rule names the decision that retired it"));
        }
        check::validate(&self.check).map_err(|e| crate::Error::Invalid(format!("rule {id}: check: {e}")))?;
        if let Some(p) = &self.partial {
            check::validate(p).map_err(|e| crate::Error::Invalid(format!("rule {id}: partial: {e}")))?;
        }
        Ok(())
    }

    /// The outcome of this rule over facts: check true = pass; false = partial when `partial` holds, else fail; unknown = unmeasured.
    pub fn eval(&self, facts: &Map<String, Value>) -> Outcome {
        match check::eval(&self.check, facts) {
            check::Tri::True => Outcome::Pass,
            check::Tri::Unknown => Outcome::Unmeasured,
            check::Tri::False => match self.partial.as_ref().map(|p| check::eval(p, facts)) {
                Some(check::Tri::True) => Outcome::Partial,
                _ => Outcome::Fail,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleRef {
    pub id: String,
    pub version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeRef {
    pub id: String,
    pub version: String,
}

/// `observation/1`: what a probe saw for one rule in one context of one product version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub schema: String,
    pub product: String,
    /// A commit sha, an image digest, a clone sha or a capture date.
    pub version: String,
    pub rule: RuleRef,
    /// viewport, role, locale, host class...; observations are compared only within one context.
    pub context: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    /// Facts the rule's check is evaluated over. When present the engine computes the outcome itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facts: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    pub probe: ProbeRef,
    /// A gatetrain-style stamp: sha-256 of the stamp file's bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stamp: Option<String>,
    /// The repeat this observation belongs to (several runs of one version give the noise band).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    /// How many assertions the probe made; fewer on head than on base is reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertions: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judge_digest: Option<String>,
}

impl Observation {
    pub fn from_value(v: &Value) -> Result<Observation> {
        require(v, &OBSERVATION_REQUIRED, "observation")?;
        let o: Observation = serde_json::from_value(v.clone()).map_err(|e| crate::Error::Invalid(format!("observation: {e}")))?;
        if o.schema != OBSERVATION_V1 {
            return invalid(format!("observation: schema must be `{OBSERVATION_V1}`"));
        }
        if o.product.trim().is_empty() || o.version.trim().is_empty() {
            return invalid("observation: product and version are required");
        }
        if o.outcome.is_none() && o.facts.is_none() {
            return invalid(format!("observation of {}: needs `outcome` or `facts`", o.rule.id));
        }
        Ok(o)
    }

    /// The context as one stable string key.
    pub fn context_key(&self) -> String {
        self.context.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(";")
    }

    /// The outcome under `rule`: facts are evaluated by the rule itself; a bare outcome counts only for the same rule version.
    pub fn outcome_under(&self, rule: &Rule) -> Outcome {
        if let Some(f) = &self.facts {
            let computed = rule.eval(f);
            // a probe's own outcome never overrides the engine's evaluation; blocked is the one thing facts cannot say
            if self.outcome == Some(Outcome::Blocked) {
                return Outcome::Blocked;
            }
            return computed;
        }
        match self.outcome {
            Some(o) if self.rule.version == rule.version => o,
            Some(Outcome::Blocked) => Outcome::Blocked,
            _ => Outcome::Unmeasured,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Founder,
    Review,
    Tester,
    Customer,
    Store,
    Ticket,
    Analytics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FeedbackStatus {
    New,
    Covered,
    RuleDrafted,
    RedProven,
    Fixed,
    Closed,
    NotReproduced,
    Declined,
}

impl FeedbackStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            FeedbackStatus::New => "new",
            FeedbackStatus::Covered => "covered",
            FeedbackStatus::RuleDrafted => "rule-drafted",
            FeedbackStatus::RedProven => "red-proven",
            FeedbackStatus::Fixed => "fixed",
            FeedbackStatus::Closed => "closed",
            FeedbackStatus::NotReproduced => "not-reproduced",
            FeedbackStatus::Declined => "declined",
        }
    }
}

/// `feedback/1`: one complaint or request, redacted before it got here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Feedback {
    pub schema: String,
    /// Opaque; the product maps it back to a person, this repository never does.
    pub id: String,
    pub product: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_version: Option<String>,
    pub source: Source,
    pub received_at: String,
    /// Redacted text: emails, phone numbers and known names are hashed placeholders.
    pub text: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub context: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rating: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reporter_class: Option<String>,
    #[serde(default = "one")]
    pub reporter_count: u32,
    pub status: FeedbackStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction: Option<Value>,
}

fn one() -> u32 {
    1
}

impl Feedback {
    pub fn from_value(v: &Value) -> Result<Feedback> {
        require(v, &FEEDBACK_REQUIRED, "feedback")?;
        let f: Feedback = serde_json::from_value(v.clone()).map_err(|e| crate::Error::Invalid(format!("feedback: {e}")))?;
        if f.schema != FEEDBACK_V1 {
            return invalid(format!("feedback: schema must be `{FEEDBACK_V1}`"));
        }
        if f.id.trim().is_empty() || f.product.trim().is_empty() {
            return invalid("feedback: id and product are required");
        }
        Ok(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DecisionAction {
    /// The rule may be retired.
    Retire,
    /// The rule may be loosened (a check that lets its old red fixture through, a lower weight, a lower mode).
    Loosen,
    /// A judged rule may block.
    Promote,
}

/// `decision/1`: the only thing that lets a rule be loosened or retired.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub schema: String,
    pub id: String,
    pub rule: String,
    pub action: DecisionAction,
    pub why: String,
    pub decided_by: String,
    pub decided_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<String>,
}

impl Decision {
    pub fn from_value(v: &Value) -> Result<Decision> {
        require(v, &DECISION_REQUIRED, "decision")?;
        let d: Decision = serde_json::from_value(v.clone()).map_err(|e| crate::Error::Invalid(format!("decision: {e}")))?;
        if d.schema != DECISION_V1 {
            return invalid(format!("decision: schema must be `{DECISION_V1}`"));
        }
        if d.why.trim().is_empty() {
            return invalid(format!("decision {}: `why` is required", d.id));
        }
        Ok(d)
    }
}

/// The fields a format requires must be present (a clearer error than serde's first missing field).
pub fn require(v: &Value, fields: &[&str], what: &str) -> Result<()> {
    let Some(o) = v.as_object() else { return invalid(format!("{what}: a JSON object is required")) };
    let missing: Vec<&str> = fields.iter().copied().filter(|f| !o.contains_key(*f)).collect();
    if missing.is_empty() {
        Ok(())
    } else {
        invalid(format!("{what}: missing {}", missing.join(", ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    pub fn rule_json() -> Value {
        json!({"schema": "rule/1", "id": "ui.target.min-size", "version": 1, "title": "t", "family": "ui", "kind": "deterministic",
               "mode": "blocking", "weight": 3, "check": {"fact": "min_px", "op": "ge", "value": 44},
               "red": {"facts": {"min_px": 30}}, "green": {"facts": {"min_px": 48}}, "owner": "screens/home"})
    }

    #[test]
    fn a_rule_parses_and_bad_rules_are_refused() {
        let r = Rule::from_value(&rule_json()).unwrap();
        assert_eq!(r.eval(json!({"min_px": 50}).as_object().unwrap()), Outcome::Pass);
        assert_eq!(r.eval(json!({}).as_object().unwrap()), Outcome::Unmeasured);
        for (k, v) in [("id", json!("nav.x")), ("id", json!("UI.x")), ("weight", json!(0)), ("version", json!(0)), ("kind", json!("judged")), ("schema", json!("rule/2"))] {
            let mut j = rule_json();
            j[k] = v;
            assert!(Rule::from_value(&j).is_err(), "{k}");
        }
        let mut j = rule_json();
        j.as_object_mut().unwrap().remove("red");
        assert!(Rule::from_value(&j).unwrap_err().to_string().contains("missing red"));
        let mut j = rule_json();
        j["state"] = json!("retired");
        assert!(Rule::from_value(&j).unwrap_err().to_string().contains("decision"));
    }

    #[test]
    fn a_bare_outcome_counts_only_for_its_rule_version() {
        let r = Rule::from_value(&rule_json()).unwrap();
        let mut o = Observation::from_value(&json!({"schema": "observation/1", "product": "example-web", "version": "a1",
            "rule": {"id": "ui.target.min-size", "version": 1}, "context": {"viewport": "390"}, "outcome": "pass",
            "probe": {"id": "web", "version": "0.1"}})).unwrap();
        assert_eq!(o.outcome_under(&r), Outcome::Pass);
        o.rule.version = 2;
        assert_eq!(o.outcome_under(&r), Outcome::Unmeasured);
        o.facts = Some(json!({"min_px": 10}).as_object().unwrap().clone());
        assert_eq!(o.outcome_under(&r), Outcome::Fail, "facts are evaluated by the rule, the probe's outcome does not override");
        assert!(Observation::from_value(&json!({"schema": "observation/1", "product": "p", "version": "v",
            "rule": {"id": "ui.a", "version": 1}, "context": {}, "probe": {"id": "x", "version": "1"}})).is_err());
    }
}
