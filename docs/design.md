# Design

scoregraph proves and scores product features with executable rules, gates regressions, and turns every complaint into a permanent rule.
This document is the design; [formats.md](formats.md) is the reference for every record.

## 0. The shape in five lines

1. A **rule** is a versioned check with a red and a green fixture. An **observation** is (product, version, rule, context) ->
   `pass | partial | fail | unmeasured | blocked`, with facts and evidence.
2. **Probes** (browser automation, accessibility and performance audits, mobile flows, repository checks) produce observations. The
   **engine** (one Rust binary) never opens a browser, a socket or a model: it reads files, scores, chains the ledger and gates.
3. A strong model can sit in the loop **through files**: the engine writes a judge bundle, and a reply is accepted only by a strict parser.
4. **Feedback -> rule** is the growth loop: a complaint becomes a rule that must fail today, then stays forever.
5. The **gatekeeper** refuses a change that lowers a product's score beyond measured noise, on an append-only hash-chained ledger pinned to commits.

## 1. What already exists around it

- **Feature claims**: CompareGraph's `export csv` (one `matrix-<family>.csv` per family, `claims.csv` with verdict, confidence and code
  locations). Claims carry evidence that code exists; nothing executes them. scoregraph adds the execution.
- **Run proof**: gatetrain writes a stamp per green run on a clean tree (commit, per-step exit codes, steps-file digest). An observation
  cites the stamp of the run that produced it.

## 2. What is scored

**Products**: your own (each surface: web, admin, mobile), open-source comparators run locally, and public pages of closed products
(structure only, never their assets, never a published ranking).

**Families** (every rule belongs to exactly one; its id starts with it):

| family | a rule proves | typical probe |
|---|---|---|
| `feature` | the claimed capability works end to end (a CompareGraph `has` needs a passing proof) | a browser or API script per feature id |
| `ui` | design-standard rules, structure against a reference, accessibility violations by impact, target size, visual baseline, responsive layouts | page facts, accessibility engine, perceptual hash |
| `nav` | every feature reachable from the menu in at most N clicks; no dead link; role-correct menus | a menu walker per role, a link checker |
| `flow` | a use-case journey completes; steps, decisions, dead ends; error and empty states exist | scripted journeys; mobile flow files |
| `quality` | performance budgets, security headers, i18n (no raw keys, no clipped text), one source for facts such as prices | performance audits, header probe, repository checks |
| `judged` | what no deterministic check decides (clarity, hierarchy, appeal) against fixed references | the judge bundle (section 4) |

**Pinning**: an observation names the product, its version (a commit sha, an image digest, a clone sha or a capture date), the rule id and
version, the probe id and version, and its context (viewport, role, locale). Observations in different contexts are never mixed.

## 3. The verifier stack

1. **Rule self-test, every run.** Each active rule runs against its red and green fixtures first. A rule that does not fail its red
   fixture, or does not pass its green one, is `broken`, and the run refuses. A check hollowed out to always pass is caught here.
2. **Deterministic probes** emit `observation/1` lines with facts and evidence refs (structure facts, hashes, counts).
3. **Facts over verdicts.** When an observation carries facts, the engine evaluates the rule itself; a probe's own outcome never overrides
   it, and ingest refuses an outcome that contradicts its facts.
4. **Run proof.** With `score --stamps`, an observation counts only if it cites a green, full, clean-tree stamp of its own commit;
   otherwise it is `unproven` and cannot raise a score.
5. **Claim audit.** Joined with CompareGraph: a `has | partial` claim with a passing proof is **proven**; with a failing proof an
   **overclaim**; with no measured proof **unproven**; a `none | unknown` claim with a passing proof an **underclaim**. Each is resolved by
   a new claim or a new rule version, never by editing an observation.
6. **Escapes** (planned): a defect found later on something a passing rule covered lowers that rule's trust until it is tightened red-first.

## 4. A model in the loop, and its limits

Roles: draft rules from feedback, judge rubric items, audit claim/proof disagreements, watch drift. A model never writes an observation
directly and never decides a gate.

Judging protocol (lane 3):
- **pairwise against a fixed reference set**, never "score out of ten": `better | same | worse | cannot_tell`, a cited principle, a region,
  a short reason;
- **order swap** on every pair; a disagreement is a `split`, recorded, never averaged;
- **versioned judge**: prompt, model id, reference set and rubric hash into a `judge_digest` carried by rule and observation;
- **calibration**: 20-40 human-settled pairs per item; a judge is admitted only above an agreement floor (Cohen's kappa, threshold set
  after the first measurement);
- **drift control**: each run re-judges a sample of old pairs plus the calibration set; below the floor, judged scores freeze;
- **authority**: a judged rule cannot be `blocking` without a decision record (enforced by the `rule/1` validator).

## 5. The score

Per observation: pass 1, partial 0.5, fail 0. `unmeasured` and `blocked` are excluded from the mean and counted in coverage.

```
rule score     = mean over contexts of the median over repeats
family_score   = sum(w * s) / sum(w)          over measured rules
family_floor   = same, unmeasured counted 0   (an honest lower bound)
coverage       = measured rules / applicable rules
product_score  = sum(W_f * family_score_f) / sum(W_f)   over measured families
proven_pct     = claimed features with a passing proof / all features
net            = product_score - overclaim_penalty * overclaims   (a separate line, never folded in silently)
```

`w` is the rule's weight; `W_f` comes from the ruleset's `profile.json` (a children's app may weight `flow`, `ui` and `judged` above
`quality`). Every score prints its families and the rules that are not passing.

**Noise.** Repeats of one version (the `run` field) give each rule a band: the largest spread within a context. A deterministic rule on a
pinned environment repeats identically (band 0, proven by an A/A run); timing rules need several runs; judged rules take their band from
order-swap and repeat disagreement. A family band is the root-sum-square of weighted rule bands; so is the product band.

**Fair comparison.** Two versions are compared under one ruleset digest. When the ruleset changes, both versions are scored under both
rulesets (a chain-linked index); a score is never compared across digests.

## 6. The gatekeeper, the ledger, anti-gaming

**Ledger.** One SQLite table, append-only (triggers refuse UPDATE and DELETE), every row chained: `hash = sha256(prev || body)`. The engine
recomputes the chain before every write and refuses a broken one, so an edit made behind the triggers' back is found. Score rows are
exported as `scores.jsonl`, each line carrying `prev` = sha-256 of the line before; the copy committed on the trusted branch must stay a
prefix (`ledger anchor`).

**Gate** (`scoregraph gate --base <v> --head <v>`):
- a **blocking** rule that passed on base and fails (or is partial) on head blocks, naming the rule and the feedback it closes (exit 10);
- the product score, or a family set to block, lower by more than its noise band blocks (11);
- coverage lower blocks: skipping a check is not a pass (12);
- a rule loosened, retired or removed without a decision blocks (13);
- everything else is reported. Rule modes move `advisory -> warn -> blocking` only by a decision record.

**Anti-gaming** (each one red-proved by a test):
- a head is scored under the **base** ruleset too, and the gate uses the worse comparison;
- a rule is **looser** when it passes a fixture or an observed fact set the base rule fails; a loosening, a lower weight, a lower mode, a
  retirement or a removal needs a `decision/1` record that is **already in the base ruleset** (a head cannot approve itself);
- a changed rule with the same version number is refused;
- the self-test catches a hollow check; a probe's outcome cannot override its own facts;
- assertion counts per rule are recorded; fewer on head is reported;
- zero observations, or zero measured rules, is red, never green.

## 7. Feedback -> rule

```
feedback record -> dedupe -> draft rule -> RED on the current product -> accepted (permanent)
               -> fix commit -> GREEN -> score rises -> the gate blocks any regression
```

1. **Capture** everything as `feedback/1`: founder and reviewer notes, testers, customers, tickets, store reviews, survey answers.
2. **Dedupe first**: an existing rule covers it (raise its weight), tightens it (a new version), or it is new.
3. **Rule form, cheapest first**: deterministic check, flow test, threshold on a measured fact, then a judged item with chosen references.
4. **Red first, enforced**: `rule accept` refuses a rule with no failing observation on the named product version. A rule that passes
   today is `not-reproduced` (recorded on the feedback) and goes back for a sharper rule.
5. **Permanent**: retirement only by decision; the rule file stays with state `retired`, history intact.
6. **The view**: per feedback id, its rules, status history, and (planned) first red run, fixing commit and score history. The headline:
   complaints closed and still closed / complaints ever closed.

**Privacy.** The scoring side never reads a product database. A product exports redacted records; personal data is redacted at the edge
(adapters replace emails, phone numbers and known names with hashed placeholders) and a second scan on ingest refuses a record that still
holds an email or a phone number. Never stored: names, emails, account ids, device ids, raw screenshots. For products used by children,
feedback should come only from a signed-in parent, with no child-session events, no replay and no persistent child identifier.

## 8. How others close the loop, and what is different here

Analytics suites capture surveys as events; error trackers attach feedback to errors and replays; feedback boards merge duplicates and
notify voters; product-management tools relate notes to features; app stores expose reviews with short windows (Google Play returns only
reviews with comments from the last week). scoregraph takes the useful shapes (merge duplicates and keep the reporters, relate feedback to
features, attach context) and adds what none of them does: **the request becomes an executable check that failed, was fixed, and is re-run
forever.**

## 9. Outside tools

Probes reuse permissive tools unmodified: browser automation, accessibility engines (rule ids and impact levels become weighted rules),
performance audits (assertion levels and multi-run aggregation), visual regression (approval as a chained ledger line, never stored
pixels), link checkers (folded into `nav` with role context). The difference here: their gates are per build; this one is chained,
pinned to commits, and comparable across products.

## 10. Integration and layout

**In**: CompareGraph `export csv`, gatetrain stamps, probe observation files, `feedback/1` and `intake/1`, adapter exports.
**Out**: `scores.jsonl`, a per-product scorecard, the feedback view, a gate exit code usable as a CI or gatetrain step, and (planned)
`proven` / `overclaim` back to CompareGraph as evidence.

```
crates/scoregraph-core   check, model, ruleset, score, gate, ledger, feedback, redact, adapters, privacy
crates/scoregraph-cli    the `scoregraph` binary
rulesets/<product>/      rules/, fixtures/, decisions.jsonl, profile.json
adapters/<name>/         fixtures per adapter (specs in adapters/README.md)
schemas/                 JSON Schema per format
ledger/schema.sql        the ledger
probes/                  (lane 2) web, nav, flow, quality, mobile, repo checks
```

**Backfill without running a product**: score the feature family from a committed CompareGraph export (proven starts at 0, honestly);
feed already-measured structure facts through `ui` rules; import past review findings as `feedback/1` in state `fixed`, no rule: the
backlog of complaints closed but not yet kept closed.
