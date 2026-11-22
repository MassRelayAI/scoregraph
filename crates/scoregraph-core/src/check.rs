//! The check language: a rule's `check` (and optional `partial`) is a small JSON predicate evaluated over facts.
//!
//! ```json
//! {"all": [ {"fact": "flow.signup.completed", "op": "eq", "value": true},
//!           {"not": {"fact": "nav.dead_links", "op": "gt", "value": 0}} ]}
//! ```
//! Forms: `{"all": [..]}`, `{"any": [..]}`, `{"not": c}`, and a comparison `{"fact": <dotted path>, "op": <op>, "value": <json>}`.
//! Ops: `eq ne lt le gt ge in contains exists absent`. A comparison on a fact that is not there is **unknown** (except `exists` and
//! `absent`), so a missing fact makes an observation `unmeasured`, never a silent pass or fail.
use crate::{invalid, Result};
use serde_json::{Map, Value};

/// Three-valued truth: a predicate over a missing fact is `Unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tri {
    True,
    False,
    Unknown,
}

pub const OPS: [&str; 10] = ["eq", "ne", "lt", "le", "gt", "ge", "in", "contains", "exists", "absent"];

/// Validate the shape of a check; the error names the first bad node.
pub fn validate(c: &Value) -> Result<()> {
    let Some(o) = c.as_object() else { return invalid("a check is a JSON object") };
    if let Some(a) = o.get("all").or_else(|| o.get("any")) {
        if o.len() != 1 {
            return invalid("`all` / `any` stand alone in their object");
        }
        let Some(items) = a.as_array() else { return invalid("`all` / `any` take an array") };
        if items.is_empty() {
            return invalid("`all` / `any` need at least one check");
        }
        return items.iter().try_for_each(validate);
    }
    if let Some(n) = o.get("not") {
        if o.len() != 1 {
            return invalid("`not` stands alone in its object");
        }
        return validate(n);
    }
    let Some(fact) = o.get("fact").and_then(Value::as_str) else { return invalid("a comparison needs a string `fact`") };
    if fact.is_empty() {
        return invalid("`fact` is empty");
    }
    let Some(op) = o.get("op").and_then(Value::as_str) else { return invalid(format!("comparison on `{fact}` needs an `op`")) };
    if !OPS.contains(&op) {
        return invalid(format!("unknown op `{op}` (ops: {})", OPS.join(" ")));
    }
    let needs_value = !matches!(op, "exists" | "absent");
    if needs_value != o.contains_key("value") {
        return invalid(format!("op `{op}` {} a `value`", if needs_value { "needs" } else { "takes no" }));
    }
    if op == "in" && !o["value"].is_array() {
        return invalid("op `in` takes an array `value`");
    }
    if matches!(op, "lt" | "le" | "gt" | "ge") && !o["value"].is_number() {
        return invalid(format!("op `{op}` takes a number `value`"));
    }
    for k in o.keys() {
        if !matches!(k.as_str(), "fact" | "op" | "value") {
            return invalid(format!("unknown key `{k}` in a comparison"));
        }
    }
    Ok(())
}

/// A fact by dotted path: an exact top-level key first, then nested objects.
pub fn lookup<'a>(facts: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    if let Some(v) = facts.get(path) {
        return Some(v);
    }
    let mut cur: Option<&Value> = None;
    for (i, part) in path.split('.').enumerate() {
        cur = if i == 0 { facts.get(part) } else { cur?.as_object()?.get(part) };
        cur?;
    }
    cur
}

/// Evaluate a validated check over facts.
pub fn eval(c: &Value, facts: &Map<String, Value>) -> Tri {
    let o = match c.as_object() {
        Some(o) => o,
        None => return Tri::Unknown,
    };
    if let Some(items) = o.get("all").and_then(Value::as_array) {
        let r: Vec<Tri> = items.iter().map(|x| eval(x, facts)).collect();
        return if r.contains(&Tri::False) {
            Tri::False
        } else if r.contains(&Tri::Unknown) {
            Tri::Unknown
        } else {
            Tri::True
        };
    }
    if let Some(items) = o.get("any").and_then(Value::as_array) {
        let r: Vec<Tri> = items.iter().map(|x| eval(x, facts)).collect();
        return if r.contains(&Tri::True) {
            Tri::True
        } else if r.contains(&Tri::Unknown) {
            Tri::Unknown
        } else {
            Tri::False
        };
    }
    if let Some(n) = o.get("not") {
        return match eval(n, facts) {
            Tri::True => Tri::False,
            Tri::False => Tri::True,
            Tri::Unknown => Tri::Unknown,
        };
    }
    let fact = o.get("fact").and_then(Value::as_str).unwrap_or("");
    let op = o.get("op").and_then(Value::as_str).unwrap_or("");
    let got = lookup(facts, fact);
    match op {
        "exists" => return tri(got.is_some_and(|v| !v.is_null())),
        "absent" => return tri(got.is_none_or(Value::is_null)),
        _ => {}
    }
    let Some(got) = got.filter(|v| !v.is_null()) else { return Tri::Unknown };
    let want = o.get("value").unwrap_or(&Value::Null);
    match op {
        "eq" => tri(same(got, want)),
        "ne" => tri(!same(got, want)),
        "in" => tri(want.as_array().is_some_and(|a| a.iter().any(|w| same(got, w)))),
        "contains" => match got {
            Value::Array(a) => tri(a.iter().any(|x| same(x, want))),
            Value::String(s) => want.as_str().map_or(Tri::Unknown, |w| tri(s.contains(w))),
            _ => Tri::Unknown,
        },
        _ => match (got.as_f64(), want.as_f64()) {
            (Some(g), Some(w)) => tri(match op {
                "lt" => g < w,
                "le" => g <= w,
                "gt" => g > w,
                _ => g >= w,
            }),
            _ => Tri::Unknown,
        },
    }
}

fn tri(b: bool) -> Tri {
    if b {
        Tri::True
    } else {
        Tri::False
    }
}

/// Equality where 2 and 2.0 are the same number.
fn same(a: &Value, b: &Value) -> bool {
    match (a.as_f64(), b.as_f64()) {
        (Some(x), Some(y)) if a.is_number() && b.is_number() => x == y,
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn f(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn comparisons_and_missing_facts() {
        let facts = f(json!({"target": {"min_px": 40}, "dead": 0, "tags": ["a", "b"], "t": "hello"}));
        assert_eq!(eval(&json!({"fact": "target.min_px", "op": "ge", "value": 44}), &facts), Tri::False);
        assert_eq!(eval(&json!({"fact": "target.min_px", "op": "ge", "value": 40.0}), &facts), Tri::True);
        assert_eq!(eval(&json!({"fact": "dead", "op": "eq", "value": 0}), &facts), Tri::True);
        assert_eq!(eval(&json!({"fact": "tags", "op": "contains", "value": "b"}), &facts), Tri::True);
        assert_eq!(eval(&json!({"fact": "t", "op": "contains", "value": "ell"}), &facts), Tri::True);
        assert_eq!(eval(&json!({"fact": "t", "op": "in", "value": ["x", "hello"]}), &facts), Tri::True);
        assert_eq!(eval(&json!({"fact": "nope", "op": "eq", "value": 1}), &facts), Tri::Unknown);
        assert_eq!(eval(&json!({"fact": "nope", "op": "absent"}), &facts), Tri::True);
        assert_eq!(eval(&json!({"fact": "dead", "op": "exists"}), &facts), Tri::True);
    }

    #[test]
    fn all_any_not_are_three_valued() {
        let facts = f(json!({"a": 1}));
        let t = json!({"fact": "a", "op": "eq", "value": 1});
        let fl = json!({"fact": "a", "op": "eq", "value": 2});
        let u = json!({"fact": "zz", "op": "eq", "value": 1});
        assert_eq!(eval(&json!({"all": [t, u]}), &facts), Tri::Unknown);
        assert_eq!(eval(&json!({"all": [fl, u]}), &facts), Tri::False);
        assert_eq!(eval(&json!({"any": [t, u]}), &facts), Tri::True);
        assert_eq!(eval(&json!({"any": [fl, u]}), &facts), Tri::Unknown);
        assert_eq!(eval(&json!({"not": u}), &facts), Tri::Unknown);
        assert_eq!(eval(&json!({"not": fl}), &facts), Tri::True);
    }

    #[test]
    fn bad_shapes_are_refused() {
        for bad in [
            json!(1),
            json!({"all": []}),
            json!({"fact": "a", "op": "zz", "value": 1}),
            json!({"fact": "a", "op": "ge", "value": "x"}),
            json!({"fact": "a", "op": "exists", "value": 1}),
            json!({"fact": "a", "op": "eq"}),
            json!({"fact": "a", "op": "in", "value": 1}),
            json!({"fact": "a", "op": "eq", "value": 1, "extra": 2}),
            json!({"not": {"fact": "a", "op": "eq", "value": 1}, "all": []}),
        ] {
            assert!(validate(&bad).is_err(), "{bad}");
        }
        assert!(validate(&json!({"all": [{"fact": "a", "op": "exists"}, {"not": {"fact": "b", "op": "lt", "value": 3}}]})).is_ok());
    }
}
