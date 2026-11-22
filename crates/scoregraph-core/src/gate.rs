//! The gatekeeper: does head lower the product's score beyond measured noise?
//!
//! Head is scored under the BASE ruleset, and also under its own when the rulesets differ (a chain-linked index: each pair is
//! compared under one digest, never across digests). The gate takes the worse of the two, so a head that edits rules and code
//! together cannot buy a pass with the rule edit. A loosened or retired rule needs a decision already on the base.
//!
//! Exit codes (one per run; every reason is printed):
//!
//! | code | meaning |
//! |---|---|
//! | 0 | nothing blocks (warnings may be printed) |
//! | 1 | refused: a broken rule, a broken ledger, zero observations |
//! | 2 | usage or format error |
//! | 10 | a blocking rule that passed on base fails on head |
//! | 11 | the product score, or a family set to block, dropped beyond its noise band |
//! | 12 | coverage dropped (a skipped check is not a pass) |
//! | 13 | a rule was loosened, retired or removed without a decision on the base |
//!
//! When several reasons block, the code is the first of 13, 10, 12, 11 (a skipped check explains a drop, so it is named first).
use crate::model::{Mode, Observation};
use crate::ruleset::{loosenings, strictest_mode, DropPolicy, Ruleset};
use crate::score::{score, Input, Score};
use crate::Result;
use serde::Serialize;

pub const EXIT_OK: i32 = 0;
pub const EXIT_REFUSED: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_BLOCKING_RULE: i32 = 10;
pub const EXIT_SCORE_DROP: i32 = 11;
pub const EXIT_COVERAGE_DROP: i32 = 12;
pub const EXIT_GAMING: i32 = 13;
// a skipped check explains a score drop, so coverage is named before the drop
const PRIORITY: [i32; 4] = [EXIT_GAMING, EXIT_BLOCKING_RULE, EXIT_COVERAGE_DROP, EXIT_SCORE_DROP];
const EPS: f64 = 1e-9;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Reason {
    pub code: i32,
    /// block | warn
    pub level: String,
    /// The ruleset digest the comparison ran under (`-` for the ruleset diff).
    pub under: String,
    pub what: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub product: String,
    pub base: String,
    pub head: String,
    pub base_digest: String,
    pub head_digest: String,
    pub reasons: Vec<Reason>,
    pub exit: i32,
    /// (base score, head score) under each digest compared.
    pub pairs: Vec<(String, Option<f64>, Option<f64>)>,
}

pub struct GateInput<'a> {
    pub product: &'a str,
    pub base: &'a str,
    pub head: &'a str,
    pub base_rules: &'a Ruleset,
    pub head_rules: &'a Ruleset,
    pub base_obs: &'a [Observation],
    pub head_obs: &'a [Observation],
}

fn sc(rs: &Ruleset, product: &str, version: &str, obs: &[Observation]) -> Result<Score> {
    score(&Input { ruleset: rs, product, version, observations: obs, claims: None, stamps: None, at: String::new() })
}

fn block(code: i32, under: &str, what: String) -> Reason {
    Reason { code, level: "block".into(), under: under.into(), what }
}

fn warn(code: i32, under: &str, what: String) -> Reason {
    Reason { code, level: "warn".into(), under: under.into(), what }
}

/// Compare base and head under one ruleset.
fn compare(b: &Score, h: &Score, g: &GateInput, policy_rules: &Ruleset) -> Vec<Reason> {
    let under = &b.ruleset_digest[..12];
    let mut out = vec![];
    for (id, br) in &b.rules {
        let Some(hr) = h.rules.get(id) else { continue };
        let mode = strictest_mode(g.base_rules, g.head_rules, id).unwrap_or(br.mode);
        if br.letter == "pass" && (hr.letter == "fail" || hr.letter == "partial") {
            let fb = policy_rules.rules.get(id).map(|r| r.source_feedback.join(",")).unwrap_or_default();
            let closes = if fb.is_empty() { String::new() } else { format!(" (closes feedback {fb})") };
            let msg = format!("rule {id} was pass on {} and is {} on {}{closes}", g.base, hr.letter, g.head);
            out.push(if mode == Mode::Blocking { block(EXIT_BLOCKING_RULE, under, msg) } else { warn(EXIT_BLOCKING_RULE, under, msg) });
        }
        if br.score.is_some() && hr.score.is_none() {
            out.push(block(EXIT_COVERAGE_DROP, under, format!("rule {id} was measured on {} and is {} on {}", g.base, hr.letter, g.head)));
        }
        if br.assertions > 0 && hr.assertions < br.assertions {
            out.push(warn(EXIT_COVERAGE_DROP, under, format!("rule {id}: {} assertions on head, {} on base", hr.assertions, br.assertions)));
        }
    }
    // noise is the BASE's measured band only: the head is the thing under test and cannot widen its own tolerance
    if let (Some(bs), Some(hs)) = (b.product_score, h.product_score) {
        let noise = b.product_band;
        if bs - hs > noise + EPS {
            out.push(block(EXIT_SCORE_DROP, under, format!("product score {:.1} -> {:.1}, beyond noise ±{:.1}", bs * 100.0, hs * 100.0, noise * 100.0)));
        }
    }
    for (name, bf) in &b.families {
        let Some(hf) = h.families.get(name) else { continue };
        if let (Some(bs), Some(hs)) = (bf.score, hf.score) {
            let noise = bf.band;
            if bs - hs > noise + EPS {
                let fam = crate::model::Family::ALL.into_iter().find(|f| f.as_str() == name);
                let policy = fam.map(|f| g.base_rules.profile.drop_policy(f)).unwrap_or_default();
                let msg = format!("family {name} {:.1} -> {:.1}, beyond noise ±{:.1}", bs * 100.0, hs * 100.0, noise * 100.0);
                out.push(if policy == DropPolicy::Block { block(EXIT_SCORE_DROP, under, msg) } else { warn(EXIT_SCORE_DROP, under, msg) });
            }
        }
    }
    if h.coverage + EPS < b.coverage {
        out.push(block(EXIT_COVERAGE_DROP, under, format!("coverage {:.1}% -> {:.1}%", b.coverage * 100.0, h.coverage * 100.0)));
    }
    out
}

pub fn gate(g: &GateInput) -> Result<Report> {
    // both rulesets must pass their self-test; a broken head rule refuses the whole gate
    g.base_rules.require_self_test()?;
    g.head_rules.require_self_test()?;
    let bd = g.base_rules.digest();
    let hd = g.head_rules.digest();
    let mut reasons = vec![];
    let mut observed: std::collections::BTreeMap<String, Vec<serde_json::Map<String, serde_json::Value>>> = Default::default();
    for o in g.base_obs.iter().chain(g.head_obs) {
        if let Some(f) = &o.facts {
            observed.entry(o.rule.id.clone()).or_default().push(f.clone());
        }
    }
    for l in loosenings(g.base_rules, g.head_rules, &observed) {
        if !l.allowed {
            let d = l.decision.map(|d| format!(" (decision {d} is not on the base for this rule)")).unwrap_or_else(|| " without a decision record".into());
            reasons.push(block(EXIT_GAMING, "-", format!("rule {} {}{d}", l.rule, l.what)));
        }
    }
    let mut pairs = vec![];
    let b_b = sc(g.base_rules, g.product, g.base, g.base_obs)?;
    let h_b = sc(g.base_rules, g.product, g.head, g.head_obs)?;
    pairs.push((bd.clone(), b_b.product_score, h_b.product_score));
    reasons.extend(compare(&b_b, &h_b, g, g.base_rules));
    if hd != bd {
        let h_h = sc(g.head_rules, g.product, g.head, g.head_obs)?;
        match sc(g.head_rules, g.product, g.base, g.base_obs) {
            Ok(b_h) => {
                pairs.push((hd.clone(), b_h.product_score, h_h.product_score));
                reasons.extend(compare(&b_h, &h_h, g, g.head_rules));
            }
            Err(e) => reasons.push(warn(EXIT_OK, &hd[..12], format!("base cannot be scored under the head ruleset: {e}"))),
        }
    }
    reasons.dedup();
    let blocking: Vec<i32> = reasons.iter().filter(|r| r.level == "block").map(|r| r.code).collect();
    let exit = PRIORITY.into_iter().find(|c| blocking.contains(c)).unwrap_or(EXIT_OK);
    Ok(Report { product: g.product.into(), base: g.base.into(), head: g.head.into(), base_digest: bd, head_digest: hd, reasons, exit, pairs })
}

pub fn render(r: &Report) -> String {
    let mut out = format!("gate {} {} -> {}\n", r.product, r.base, r.head);
    for (d, b, h) in &r.pairs {
        let p = |x: &Option<f64>| x.map_or("n/a".into(), |v| format!("{:.1}", v * 100.0));
        out += &format!("  under {}: base {} head {}\n", &d[..12], p(b), p(h));
    }
    for x in &r.reasons {
        out += &format!("  {} [{}] {}\n", x.level.to_uppercase(), x.code, x.what);
    }
    out += &format!("GATE_EXIT {}\n", r.exit);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ruleset::testkit::{decision, rule, write};
    use serde_json::{json, Value};

    fn o(rule: &str, v: &str, x: i64) -> Observation {
        Observation::from_value(&json!({"schema": "observation/1", "product": "example-web", "version": v,
            "rule": {"id": rule, "version": 1}, "context": {"viewport": "1440"}, "facts": {"x": x}, "probe": {"id": "web", "version": "0.1"}}))
        .unwrap()
    }

    struct Fx {
        _b: tempfile::TempDir,
        _h: tempfile::TempDir,
        base: Ruleset,
        head: Ruleset,
    }

    fn fx(base: &[Value], bdec: &[Value], head: &[Value]) -> Fx {
        let (b, h) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        write(b.path(), base, bdec);
        write(h.path(), head, bdec);
        let (base, head) = (Ruleset::load(b.path()).unwrap(), Ruleset::load(h.path()).unwrap());
        Fx { _b: b, _h: h, base, head }
    }

    fn run(f: &Fx, bo: &[Observation], ho: &[Observation]) -> Report {
        gate(&GateInput { product: "example-web", base: "a1", head: "b2", base_rules: &f.base, head_rules: &f.head, base_obs: bo, head_obs: ho }).unwrap()
    }

    fn rules3() -> Vec<Value> {
        vec![rule("ui.a", "ui", 10, "blocking"), rule("ui.b", "ui", 10, "advisory"), rule("nav.a", "nav", 10, "warn")]
    }

    #[test]
    fn no_change_passes() {
        let f = fx(&rules3(), &[], &rules3());
        let obs = |v| vec![o("ui.a", v, 12), o("ui.b", v, 12), o("nav.a", v, 12)];
        assert_eq!(run(&f, &obs("a1"), &obs("b2")).exit, EXIT_OK);
    }

    #[test]
    fn a_blocking_rule_regression_exits_10() {
        let f = fx(&rules3(), &[], &rules3());
        let r = run(&f, &[o("ui.a", "a1", 12), o("nav.a", "a1", 12)], &[o("ui.a", "b2", 1), o("nav.a", "b2", 12)]);
        assert_eq!(r.exit, EXIT_BLOCKING_RULE, "{}", render(&r));
        // an advisory rule regressing only warns about itself (the score drop still blocks: 11)
        let r = run(&f, &[o("ui.b", "a1", 12), o("nav.a", "a1", 12)], &[o("ui.b", "b2", 1), o("nav.a", "b2", 12)]);
        assert_eq!(r.exit, EXIT_SCORE_DROP, "{}", render(&r));
        assert!(r.reasons.iter().any(|x| x.code == EXIT_BLOCKING_RULE && x.level == "warn"));
    }

    #[test]
    fn a_drop_within_noise_passes_and_beyond_noise_exits_11() {
        let rs = vec![rule("quality.a", "quality", 10, "warn"), rule("quality.b", "quality", 10, "warn")];
        let f = fx(&rs, &[], &rs);
        let mut noisy_base = vec![o("quality.a", "a1", 12), o("quality.b", "a1", 12)];
        let mut r2 = o("quality.a", "a1", 1);
        r2.run = Some("2".into());
        noisy_base.push(r2);
        let mut r3 = o("quality.a", "a1", 12);
        r3.run = Some("3".into());
        noisy_base.push(r3);
        // base quality.a: repeats 1,0,1 -> median 1, band 1 capped at 0.5 -> family band 0.25.
        // head quality.a repeats 1,0 -> median 0.5: family 1.0 -> 0.75, a drop of 0.25, within the base band
        let mut h2 = o("quality.a", "b2", 1);
        h2.run = Some("2".into());
        let r = run(&f, &noisy_base, &[o("quality.a", "b2", 12), h2, o("quality.b", "b2", 12)]);
        assert_eq!(r.exit, EXIT_OK, "{}", render(&r));
        // a full fail on head is beyond it
        let r = run(&f, &noisy_base, &[o("quality.a", "b2", 1), o("quality.b", "b2", 12)]);
        assert_eq!(r.exit, EXIT_SCORE_DROP, "{}", render(&r));
        // the same drop with no measured noise blocks
        let r = run(&f, &[o("quality.a", "a1", 12), o("quality.b", "a1", 12)], &[o("quality.a", "b2", 1), o("quality.b", "b2", 12)]);
        assert_eq!(r.exit, EXIT_SCORE_DROP, "{}", render(&r));
    }

    #[test]
    fn a_head_that_inflates_its_own_noise_cannot_mask_a_drop() {
        let rs = vec![rule("quality.a", "quality", 10, "warn"), rule("quality.b", "quality", 10, "warn")];
        let f = fx(&rs, &[], &rs);
        let base = [o("quality.a", "a1", 12), o("quality.b", "a1", 12)];
        // head repeats quality.a as fail, pass, fail: median fail, and a self-made band of 1
        let mut head = vec![o("quality.b", "b2", 12)];
        for (i, x) in [1, 12, 1].iter().enumerate() {
            let mut h = o("quality.a", "b2", *x);
            h.run = Some(format!("{i}"));
            head.push(h);
        }
        let r = run(&f, &base, &head);
        assert_eq!(r.exit, EXIT_SCORE_DROP, "{}", render(&r));
    }

    #[test]
    fn a_skipped_check_exits_12() {
        let f = fx(&rules3(), &[], &rules3());
        let r = run(&f, &[o("ui.b", "a1", 12), o("nav.a", "a1", 12)], &[o("nav.a", "b2", 12)]);
        assert_eq!(r.exit, EXIT_COVERAGE_DROP, "{}", render(&r));
    }

    #[test]
    fn a_head_that_loosens_its_own_rule_is_scored_under_the_base_rules_too_and_exits_13() {
        let base = vec![rule("ui.a", "ui", 10, "blocking"), rule("nav.a", "nav", 10, "warn")];
        let mut loose = rule("ui.a", "ui", 1, "blocking");
        loose["version"] = json!(2);
        let head = vec![loose.clone(), rule("nav.a", "nav", 10, "warn")];
        let f = fx(&base, &[], &head);
        // head's code regressed (x=2) and its rule was loosened to let x=2 pass
        let bo = [o("ui.a", "a1", 12), o("nav.a", "a1", 12)];
        let ho = [o("ui.a", "b2", 2), o("nav.a", "b2", 12)];
        let r = run(&f, &bo, &ho);
        assert_eq!(r.exit, EXIT_GAMING, "{}", render(&r));
        // and under the base ruleset the regression is visible as well
        assert!(r.reasons.iter().any(|x| x.code == EXIT_BLOCKING_RULE && x.under == f.base.digest()[..12]), "{}", render(&r));
        // with a decision already on the base, the loosening is allowed; the regression under base rules still blocks
        loose["decision"] = json!("d-7");
        let f = fx(&base, &[decision("d-7", "ui.a", "loosen")], &[loose, rule("nav.a", "nav", 10, "warn")]);
        let r = run(&f, &bo, &ho);
        assert_eq!(r.exit, EXIT_BLOCKING_RULE, "{}", render(&r));
    }

    #[test]
    fn a_head_with_a_broken_rule_is_refused() {
        let mut hollow = rule("ui.a", "ui", 10, "blocking");
        hollow["version"] = json!(2);
        hollow["check"] = json!({"fact": "x", "op": "exists"});
        let f = fx(&rules3(), &[], &[hollow]);
        let e = gate(&GateInput { product: "example-web", base: "a1", head: "b2", base_rules: &f.base, head_rules: &f.head,
            base_obs: &[o("ui.a", "a1", 12)], head_obs: &[o("ui.a", "b2", 12)] }).unwrap_err();
        assert!(e.to_string().contains("self-test"));
    }
}
