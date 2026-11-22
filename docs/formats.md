# Formats

Every record is JSON and names its format and version in a `schema` field. A new incompatible version gets a new name (`rule/2`); readers
refuse a version they do not know. JSON Schema files are in [`schemas/`](../schemas/); a test keeps their required fields and enums equal
to the code.

| format | file | what |
|---|---|---|
| `observation/1` | [observation-1.schema.json](../schemas/observation-1.schema.json) | what a probe saw for one rule, in one context, of one product version |
| `rule/1` | [rule-1.schema.json](../schemas/rule-1.schema.json) | a versioned executable rule with a red and a green fixture |
| `feedback/1` | [feedback-1.schema.json](../schemas/feedback-1.schema.json) | one redacted complaint or request |
| `decision/1` | [decision-1.schema.json](../schemas/decision-1.schema.json) | permission to loosen, retire or promote a rule |
| `score/1` | [score-1.schema.json](../schemas/score-1.schema.json) | one product version under one ruleset digest |
| `intake/1` | [intake-1.schema.json](../schemas/intake-1.schema.json) | what a product's own feedback door exports |

## observation/1

```json
{"schema": "observation/1", "product": "example-web", "version": "a1b2c3d", "rule": {"id": "ui.target.min-size", "version": 1},
 "context": {"viewport": "390"}, "facts": {"target": {"min_px": 36}}, "evidence": ["facts/a1b2c3d/home-390.json"],
 "probe": {"id": "web-facts", "version": "0.1.0"}, "stamp": "<sha-256 of a stamp file>", "run": "1", "assertions": 12}
```

- `facts` or `outcome` (`pass | partial | fail | unmeasured | blocked`) is required. With facts, the engine evaluates the rule; a bare
  outcome counts only for the same rule version AND with a non-empty `evidence` or a `stamp` (otherwise it is `unmeasured`: a claim,
  not a measurement). `blocked` (the probe could not reach the thing) is never overridden.
- `run` groups repeats of one version: the median is the rule's score in that context, the spread its noise band.
- `stamp` is the sha-256 of a gatetrain stamp file; with `score --stamps` an observation without a verified stamp of its own version is
  `unproven`.

## rule/1

```json
{"schema": "rule/1", "id": "ui.target.min-size", "version": 1, "title": "every tap target is at least 44 px on its short side",
 "family": "ui", "kind": "deterministic", "mode": "blocking", "weight": 3,
 "check": {"fact": "target.min_px", "op": "ge", "value": 44},
 "red": "fixtures/ui.target.min-size.red.json", "green": {"facts": {"target": {"min_px": 48}}},
 "owner": "screens/home", "source_feedback": ["fb-example-0001"], "features": []}
```

- `id` = `<family>.<name>[.<name>]`, lowercase; it must start with its family. One file per rule: `rules/<id>.json`.
- `kind` is `judged` exactly when `family` is `judged`; a judged rule may be `blocking` only with a `decision`.
- `mode`: `advisory < warn < blocking`. Moving down is a loosening.
- `red` / `green`: inline `{"facts": {...}}` or a path inside the ruleset to a file holding that.
- `partial` (optional): a second check; when `check` is false and `partial` true the outcome is `partial`.
- `features`: CompareGraph feature ids this rule proves.
- `state`: `active` (default), `draft`, `retired` (needs `decision`).
- Any change to check, weight, mode or fixtures is a new `version`. A changed rule with the same version is refused by the gate.

### The check language

| form | meaning |
|---|---|
| `{"fact": "a.b", "op": "ge", "value": 44}` | a comparison on a fact by dotted path (an exact top-level key wins) |
| `{"all": [c, ...]}` | every check holds |
| `{"any": [c, ...]}` | at least one holds |
| `{"not": c}` | the check does not hold |

Ops: `eq ne lt le gt ge in contains exists absent`. `lt le gt ge` take a number, `in` an array, `exists` and `absent` no value. Logic is
three-valued: a comparison on a missing fact is **unknown**, which makes the outcome `unmeasured` (never a silent pass or fail). `all` is
false if any part is false, else unknown if any is unknown; `any` is true if any part is true, else unknown if any is unknown.

### The self-test

Each active rule must give `fail` on its red fixture and `pass` on its green one. `unmeasured` on red is broken too (the red fixture must
actually exercise the check). Any broken rule refuses `selftest`, `ingest`, `score` and `gate`.

## feedback/1

```json
{"schema": "feedback/1", "id": "fb-intake-abcdefghijkl", "product": "example-web", "source": "customer", "received_at": "2026-01-10T09:00:00Z",
 "text": "The pay button does nothing. Reply to [email:kdmgbpac]", "status": "new", "surface": "checkout",
 "context": {"viewport": "390"}, "rating": 2, "reporter_class": "customer", "reporter_count": 1,
 "redaction": {"scanner": "scoregraph-redact/1", "salted": true, "removed": {"email": 1}}}
```

- `source`: `founder | review | tester | customer | store | ticket | analytics`.
- `status`: `new | covered | rule-drafted | red-proven | fixed | closed | not-reproduced | declined`. A stored record is never edited;
  status changes are `feedback-event` rows on the ledger chain.
- `feedback add` refuses the whole batch when any record still holds an email or a phone number in `text` or `links`.

## decision/1

```json
{"schema": "decision/1", "id": "d-0001", "rule": "ui.target.min-size", "action": "loosen",
 "why": "the platform guideline is 32 px for dense tables", "decided_by": "maintainer", "decided_at": "2026-01-12T00:00:00Z"}
```

`action`: `retire | loosen | promote`. Decisions live in `<ruleset>/decisions.jsonl` (written once, never rewritten) and on the ledger.
For the gate, a decision counts only when it is already in the **base** ruleset, and it binds:

- a `loosen` of a rule names `from_version` and `to_version`, and allows exactly that step (a decision for 1 -> 3 does not allow 1 -> 2);
- a `retire` may name `from_version`; if it does, it must match;
- a `loosen` of the profile (`"rule": "profile"`) names `profile_digest`, the sha-256 of the canonical head profile it allows.

## score/1

```json
{"schema": "score/1", "product": "example-web", "version": "a1", "ruleset_digest": "<64 hex>", "at": "2026-01-01T00:00:00Z",
 "product_score": 0.93, "product_floor": 0.93, "product_band": 0.0, "coverage": 1.0, "net": 0.93,
 "families": {"ui": {"score": 1.0, "floor": 1.0, "coverage": 1.0, "band": 0.0, "measured": 1, "applicable": 1, "weight": 1.0}},
 "rules": {"ui.target.min-size": {"v": 1, "family": "ui", "mode": "blocking", "letter": "pass", "score": 1.0, "band": 0.0, "contexts": 2, "assertions": 0}},
 "counts": {"observations": 10, "pass": 9, "fail": 1}, "claims": {"features": 4, "proven_pct": 0.25, "proven": ["export.csv"],
 "overclaims": ["share.link"], "unproven": [], "underclaims": []}, "stamps": []}
```

Scores are fractions 0..1 rounded to six decimals; `null` means nothing in it was measured.

## intake/1

What a product's feedback door exports for the `intake` adapter. Required: `schema`, `product`, `submitted_at`, `text`. Optional:
`product_version`, `surface`, `rating`, `source` (`customer` default, `tester`, `founder`), `reporter_class`, `context` (strings),
`links`, `client_ref` (the product's own opaque id). **No other field is accepted**: a door that sends an email, a name or a device id is
refused, not filtered.

## The ledger

`ledger/schema.sql`: one table `entries (seq, kind, key, body, prev, hash, chain_v)`; `kind` is `observation | score | feedback |
feedback-event | rule-event | decision | chain-seal`; `body` is canonical JSON (sorted keys, no whitespace); `prev` of row 1 is 64 zeros.

- **Chain v2** (every row written now): `hash = sha256_hex(canonical(["scoregraph-chain/2", seq, kind, key, prev, body]))`, so re-keying a
  row to another product version, changing its kind or its seq breaks the chain as surely as editing its body.
- **Chain v1** (older ledgers): `hash = sha256_hex(prev || body)`. Opening one adds the `chain_v` column (existing rows are v1); the first
  write appends a `chain-seal` row whose `v1_digest` covers every v1 row's (seq, kind, key, hash), so their keys are protected from then on.
  No v1 row may follow a v2 row.
- Triggers refuse UPDATE and DELETE. Every write first recomputes the chain and refuses a broken one.
- **Head anchor.** A cut tail (or a cut and re-forged one) still chains by itself. `ledger head --out ledger-head.json` writes
  `{"schema": "ledger-head/1", "seq": n, "hash": h}`; commit it on the trusted branch, then `ledger verify --anchor ledger-head.json` (or
  `--anchor-ref origin/main:ledger-head.json`), `score --anchor` and `gate --anchor` refuse a ledger that no longer holds row `n` with hash
  `h` (`truncated` or `rewritten`). Rows after the anchor are only as safe as the next anchor you commit.

`scores.jsonl` (`ledger export`): one score row per line in chain order, each with `prev` = sha-256 of the previous line's bytes.
`ledger anchor --committed-ref origin/main:scores.jsonl --current scores.jsonl` refuses unless both chains verify and the committed lines
are a byte-for-byte prefix of the current ones.

## Exit codes

| code | meaning |
|---|---|
| 0 | ok |
| 1 | refused: broken rule, broken chain, zero observations, a non-red rule, a missing decision, PII in feedback, a privacy hit |
| 2 | usage or format error |
| 10 | gate: a blocking rule regressed |
| 11 | gate: a score dropped beyond its noise band |
| 12 | gate: coverage dropped |
| 13 | gate: a rule was loosened, retired or removed without a decision on the base |

When several gate reasons block, the code is the first of 13, 10, 12, 11.
