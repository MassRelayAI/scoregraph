//! The score of one product version under one ruleset.
//!
//! ```text
//! s(observation)  = pass 1 · partial 0.5 · fail 0 ; unmeasured and blocked are not measured
//! rule score      = mean over contexts of the median over repeats (runs)        band = max over contexts of (max - min)
//! family_score    = Σ w·s / Σ w            over measured rules
//! family_floor    = Σ w·s / Σ w            over applicable rules, unmeasured counted as 0
//! coverage        = measured rules / applicable rules
//! family band     = sqrt(Σ (w·band)²) / Σ w over measured rules (each rule band capped at `max_rule_band`, default 0.5)
//! product_score   = Σ W_f·family_score / Σ W_f over measured families          (same for floor and band)
//! proven_pct      = claimed features (has|partial) with a passing proof / features
//! overclaims      = claimed has|partial, a proof was measured, and it is not a pass
//! ```
//! Penalties are separate lines (`net = product_score - overclaim_penalty·overclaims`), never folded in silently.
use crate::adapters::comparegraph::Claims;
use crate::model::{Family, Observation, Outcome, Rule, SCORE_V1};
use crate::refused;
use crate::ruleset::Ruleset;
use crate::util::round6;
use crate::Result;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RuleScore {
    pub v: u32,
    pub family: Family,
    pub mode: crate::model::Mode,
    /// pass | partial | fail | unmeasured | blocked
    pub letter: String,
    pub score: Option<f64>,
    pub band: f64,
    pub contexts: usize,
    pub assertions: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FamilyScore {
    pub score: Option<f64>,
    pub floor: f64,
    pub coverage: f64,
    pub band: f64,
    pub measured: usize,
    pub applicable: usize,
    pub weight: f64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
pub struct ClaimAudit {
    pub features: usize,
    pub proven_pct: f64,
    pub proven: Vec<String>,
    pub overclaims: Vec<String>,
    pub unproven: Vec<String>,
    pub underclaims: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Score {
    pub schema: String,
    pub product: String,
    pub version: String,
    pub ruleset_digest: String,
    pub at: String,
    pub product_score: Option<f64>,
    pub product_floor: f64,
    pub product_band: f64,
    pub coverage: f64,
    pub net: Option<f64>,
    pub families: BTreeMap<String, FamilyScore>,
    pub rules: BTreeMap<String, RuleScore>,
    pub counts: BTreeMap<String, u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<ClaimAudit>,
    pub stamps: Vec<String>,
}

impl Score {
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

/// Which stamps count as proof. `None` = stamps are not required.
pub struct StampPolicy<'a> {
    /// Digests of stamp files that were verified (see `adapters::gatetrain`), with the commit each one proves.
    pub verified: &'a BTreeMap<String, String>,
}

pub struct Input<'a> {
    pub ruleset: &'a Ruleset,
    pub product: &'a str,
    pub version: &'a str,
    pub observations: &'a [Observation],
    pub claims: Option<(&'a Claims, &'a str)>,
    pub stamps: Option<StampPolicy<'a>>,
    pub at: String,
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.total_cmp(b));
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

fn letter(s: Option<f64>, all_blocked: bool) -> &'static str {
    match s {
        None if all_blocked => "blocked",
        None => "unmeasured",
        Some(x) if x >= 1.0 => "pass",
        Some(x) if x <= 0.0 => "fail",
        Some(_) => "partial",
    }
}

/// Score one rule over the observations that name it.
fn score_rule(rule: &Rule, obs: &[&Observation], stamps: &Option<StampPolicy>, version: &str, cap: f64, counts: &mut BTreeMap<String, u64>) -> RuleScore {
    let mut by_ctx: BTreeMap<String, Vec<Option<f64>>> = BTreeMap::new();
    let mut blocked = 0usize;
    let mut assertions = 0u64;
    for o in obs {
        let mut out = o.outcome_under(rule);
        if let Some(p) = stamps {
            let proven = o.stamp.as_ref().and_then(|d| p.verified.get(d)).is_some_and(|sha| sha == version);
            if !proven && out.value().is_some() {
                *counts.entry("unproven".into()).or_default() += 1;
                out = Outcome::Unmeasured;
            }
        }
        if out == Outcome::Blocked {
            blocked += 1;
        }
        *counts.entry(out.as_str().into()).or_default() += 1;
        assertions += u64::from(o.assertions.unwrap_or(0));
        by_ctx.entry(o.context_key()).or_default().push(out.value());
    }
    let mut ctx_scores = vec![];
    let mut band = 0.0f64;
    for vals in by_ctx.values() {
        let m: Vec<f64> = vals.iter().flatten().copied().collect();
        if m.is_empty() {
            continue;
        }
        let (lo, hi) = m.iter().fold((f64::MAX, f64::MIN), |(a, b), &x| (a.min(x), b.max(x)));
        band = band.max(hi - lo);
        ctx_scores.push(median(m));
    }
    let score = if ctx_scores.is_empty() { None } else { Some(round6(ctx_scores.iter().sum::<f64>() / ctx_scores.len() as f64)) };
    let all_blocked = score.is_none() && blocked > 0 && blocked == obs.len();
    RuleScore {
        v: rule.version,
        family: rule.family,
        mode: rule.mode,
        letter: letter(score, all_blocked).into(),
        score,
        // a rule's band is capped: no amount of repeat spread makes a rule's drop invisible
        band: round6(band.min(cap)),
        contexts: by_ctx.len(),
        assertions,
    }
}

pub fn score(inp: &Input) -> Result<Score> {
    let rs = inp.ruleset;
    rs.require_self_test()?;
    let mine: Vec<&Observation> = inp.observations.iter().filter(|o| o.product == inp.product && o.version == inp.version).collect();
    if mine.is_empty() {
        return refused(format!("no observation of {}@{}: a run over zero observations is red, never green", inp.product, inp.version));
    }
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut rules = BTreeMap::new();
    for r in rs.active() {
        let obs: Vec<&Observation> = mine.iter().copied().filter(|o| o.rule.id == r.id).collect();
        rules.insert(r.id.clone(), score_rule(r, &obs, &inp.stamps, inp.version, rs.profile.max_rule_band(), &mut counts));
    }
    let known: BTreeSet<&str> = rs.rules.keys().map(String::as_str).collect();
    let stray = mine.iter().filter(|o| !known.contains(o.rule.id.as_str())).count();
    counts.insert("observations".into(), mine.len() as u64);
    counts.insert("unknown_rule".into(), stray as u64);
    counts.insert("rules".into(), rules.len() as u64);
    let measured_rules = rules.values().filter(|r| r.score.is_some()).count();
    counts.insert("rules_measured".into(), measured_rules as u64);
    if measured_rules == 0 {
        return refused(format!("{}@{}: no rule was measured ({} observations); zero measured is red, never green", inp.product, inp.version, mine.len()));
    }

    let mut families = BTreeMap::new();
    for f in Family::ALL {
        let rf: Vec<(&Rule, &RuleScore)> = rs.active().filter(|r| r.family == f).map(|r| (r, &rules[&r.id])).collect();
        if rf.is_empty() {
            continue;
        }
        let w_all: f64 = rf.iter().map(|(r, _)| r.weight).sum();
        let meas: Vec<&(&Rule, &RuleScore)> = rf.iter().filter(|(_, s)| s.score.is_some()).collect();
        let w_m: f64 = meas.iter().map(|(r, _)| r.weight).sum();
        let sum: f64 = meas.iter().map(|(r, s)| r.weight * s.score.unwrap_or(0.0)).sum();
        let band = if w_m > 0.0 { meas.iter().map(|(r, s)| (r.weight * s.band).powi(2)).sum::<f64>().sqrt() / w_m } else { 0.0 };
        families.insert(
            f.as_str().to_string(),
            FamilyScore {
                score: if w_m > 0.0 { Some(round6(sum / w_m)) } else { None },
                floor: round6(sum / w_all),
                coverage: round6(meas.len() as f64 / rf.len() as f64),
                band: round6(band),
                measured: meas.len(),
                applicable: rf.len(),
                weight: rs.profile.weight(f),
            },
        );
    }
    let mf: Vec<&FamilyScore> = families.values().filter(|f| f.score.is_some()).collect();
    let wsum: f64 = mf.iter().map(|f| f.weight).sum();
    let product_score = if wsum > 0.0 { Some(round6(mf.iter().map(|f| f.weight * f.score.unwrap_or(0.0)).sum::<f64>() / wsum)) } else { None };
    let wall: f64 = families.values().map(|f| f.weight).sum();
    let product_floor = round6(families.values().map(|f| f.weight * f.floor).sum::<f64>() / wall.max(f64::MIN_POSITIVE));
    let product_band = if wsum > 0.0 { round6(mf.iter().map(|f| (f.weight * f.band).powi(2)).sum::<f64>().sqrt() / wsum) } else { 0.0 };
    let coverage = round6(measured_rules as f64 / rules.len() as f64);

    let claims = inp.claims.map(|(c, repo)| audit_claims(c, repo, rs, &rules));
    let net = product_score.map(|s| round6(s - rs.profile.overclaim_penalty * claims.as_ref().map_or(0, |c| c.overclaims.len()) as f64));
    let mut stamps: Vec<String> = mine.iter().filter_map(|o| o.stamp.clone()).collect::<BTreeSet<_>>().into_iter().collect();
    stamps.sort();
    Ok(Score {
        schema: SCORE_V1.into(),
        product: inp.product.into(),
        version: inp.version.into(),
        ruleset_digest: rs.digest(),
        at: inp.at.clone(),
        product_score,
        product_floor,
        product_band,
        coverage,
        net,
        families,
        rules,
        counts,
        claims,
        stamps,
    })
}

/// Join CompareGraph claims with proofs. A feature's proof is the best measured score of the rules that name it.
pub fn audit_claims(c: &Claims, repo: &str, rs: &Ruleset, rules: &BTreeMap<String, RuleScore>) -> ClaimAudit {
    let mut proof: BTreeMap<&str, f64> = BTreeMap::new();
    for r in rs.active() {
        if let Some(s) = rules.get(&r.id).and_then(|x| x.score) {
            for f in &r.features {
                let e = proof.entry(f.as_str()).or_insert(s);
                *e = e.max(s);
            }
        }
    }
    let verdicts = c.latest_for(repo);
    let mut features: BTreeSet<String> = c.features_of(repo);
    features.extend(verdicts.keys().cloned());
    let mut a = ClaimAudit { features: features.len(), ..Default::default() };
    for f in &features {
        let claimed = verdicts.get(f).is_some_and(|v| v == "has" || v == "partial");
        match (claimed, proof.get(f.as_str())) {
            (true, Some(s)) if *s >= 1.0 => a.proven.push(f.clone()),
            (true, Some(_)) => a.overclaims.push(f.clone()),
            (true, None) => a.unproven.push(f.clone()),
            (false, Some(s)) if *s >= 1.0 => a.underclaims.push(f.clone()),
            _ => {}
        }
    }
    a.proven_pct = if a.features == 0 { 0.0 } else { round6(a.proven.len() as f64 / a.features as f64) };
    a
}

/// One line per family plus the product, for a terminal.
pub fn render(s: &Score) -> String {
    let pct = |x: Option<f64>| x.map_or("  n/a".to_string(), |v| format!("{:5.1}", v * 100.0));
    let mut out = format!(
        "{}@{}  score {}  floor {}  coverage {}  band ±{:.1}  ruleset {}\n",
        s.product,
        s.version,
        pct(s.product_score),
        pct(Some(s.product_floor)),
        pct(Some(s.coverage)),
        s.product_band * 100.0,
        &s.ruleset_digest[..12]
    );
    for (name, f) in &s.families {
        out += &format!("  {name:<8} {}  floor {}  coverage {}/{}  band ±{:.1}\n", pct(f.score), pct(Some(f.floor)), f.measured, f.applicable, f.band * 100.0);
    }
    if let Some(c) = &s.claims {
        out += &format!(
            "  claims   proven {}/{} ({:.1}%)  overclaims {}  unproven {}  underclaims {}\n",
            c.proven.len(),
            c.features,
            c.proven_pct * 100.0,
            c.overclaims.len(),
            c.unproven.len(),
            c.underclaims.len()
        );
    }
    let moved: Vec<String> = s.rules.iter().filter(|(_, r)| r.letter != "pass").take(10).map(|(id, r)| format!("{id}={}", r.letter)).collect();
    if !moved.is_empty() {
        out += &format!("  not passing: {}\n", moved.join(" "));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ruleset::testkit::{rule, write};
    use serde_json::json;

    fn obs(rule: &str, v: &str, x: i64, ctx: &str, run: &str) -> Observation {
        Observation::from_value(&json!({"schema": "observation/1", "product": "example-web", "version": v,
            "rule": {"id": rule, "version": 1}, "context": {"viewport": ctx}, "facts": {"x": x}, "run": run,
            "probe": {"id": "web", "version": "0.1"}}))
        .unwrap()
    }

    fn rs(rules: &[Value]) -> (tempfile::TempDir, Ruleset) {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), rules, &[]);
        let r = Ruleset::load(d.path()).unwrap();
        (d, r)
    }

    fn run(r: &Ruleset, o: &[Observation]) -> Result<Score> {
        score(&Input { ruleset: r, product: "example-web", version: "a1", observations: o, claims: None, stamps: None, at: "t".into() })
    }

    #[test]
    fn weighted_family_score_floor_and_coverage() {
        let mut heavy = rule("ui.b", "ui", 10, "warn");
        heavy["weight"] = json!(3);
        let (_d, r) = rs(&[rule("ui.a", "ui", 10, "warn"), heavy, rule("ui.c", "ui", 10, "warn"), rule("nav.a", "nav", 1, "warn")]);
        // ui.a pass (w1), ui.b fail (w3), ui.c unmeasured, nav.a pass
        let s = run(&r, &[obs("ui.a", "a1", 12, "1440", "1"), obs("ui.b", "a1", 2, "1440", "1"), obs("nav.a", "a1", 1, "1440", "1")]).unwrap();
        let ui = &s.families["ui"];
        assert_eq!(ui.score, Some(0.25));
        assert_eq!(ui.floor, 0.2);
        assert_eq!((ui.measured, ui.applicable), (2, 3));
        assert_eq!(s.product_score, Some(0.625));
        assert_eq!(s.coverage, 0.75);
        assert_eq!(s.rules["ui.c"].letter, "unmeasured");
    }

    #[test]
    fn repeats_give_a_median_and_a_noise_band() {
        let (_d, r) = rs(&[rule("quality.a", "quality", 10, "warn")]);
        let o = [obs("quality.a", "a1", 12, "x", "1"), obs("quality.a", "a1", 2, "x", "2"), obs("quality.a", "a1", 12, "x", "3")];
        let s = run(&r, &o).unwrap();
        assert_eq!(s.rules["quality.a"].score, Some(1.0));
        assert_eq!(s.rules["quality.a"].band, 0.5, "a spread of 1 is capped at the default 0.5");
        assert_eq!(s.product_band, 0.5);
        // deterministic and repeated identically: band 0
        let s = run(&r, &[obs("quality.a", "a1", 12, "x", "1"), obs("quality.a", "a1", 12, "x", "2")]).unwrap();
        assert_eq!(s.product_band, 0.0);
    }

    #[test]
    fn zero_observations_and_zero_measured_are_red() {
        let (_d, r) = rs(&[rule("ui.a", "ui", 10, "warn")]);
        assert!(run(&r, &[]).unwrap_err().to_string().contains("zero observations"));
        assert!(run(&r, &[obs("ui.zz", "a1", 1, "x", "1")]).unwrap_err().to_string().contains("no rule was measured"));
    }

    #[test]
    fn an_unstamped_observation_cannot_raise_a_score() {
        let (_d, r) = rs(&[rule("ui.a", "ui", 10, "warn"), rule("ui.b", "ui", 10, "warn")]);
        let mut good = obs("ui.a", "a1", 12, "x", "1");
        good.stamp = Some("d1".into());
        let mut wrong_commit = obs("ui.b", "a1", 12, "x", "1");
        wrong_commit.stamp = Some("d2".into());
        let verified: BTreeMap<String, String> = [("d1".to_string(), "a1".to_string()), ("d2".to_string(), "zz".to_string())].into();
        let s = score(&Input { ruleset: &r, product: "example-web", version: "a1", observations: &[good, wrong_commit], claims: None,
            stamps: Some(StampPolicy { verified: &verified }), at: "t".into() }).unwrap();
        assert_eq!(s.rules["ui.a"].letter, "pass");
        assert_eq!(s.rules["ui.b"].letter, "unmeasured");
        assert_eq!(s.counts["unproven"], 1);
    }
}
