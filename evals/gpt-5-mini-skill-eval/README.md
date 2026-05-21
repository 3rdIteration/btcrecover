# SKILL.md adherence eval — `gpt-5-mini` candidate

A one-shot evaluation of how well a small candidate model (`gpt-5-mini`, used
as a stand-in for "GPT-4o mini") follows the rules in this repo's top-level
[`SKILL.md`](../../SKILL.md) when acting as the BTCRecover recovery agent.

## Layout

* [`scenarios.md`](scenarios.md) — ten single-turn user scenarios, each
  targeting one or more specific rules from `SKILL.md`, with explicit pass /
  fail criteria.
* [`responses/`](responses/) — the candidate model's reply for each scenario.
* [`RESULTS.md`](RESULTS.md) — scored report, per-scenario findings, and
  themes / suggestions surfaced by the eval.

This eval makes **no changes** to `SKILL.md` or any sub-skill. It is purely
diagnostic — re-run after editing the skill to see what changed.

## Headline

| Bucket  | Count | Scenarios                        |
| ------- | ----- | -------------------------------- |
| PASS    | 7/10  | S2, S3, S4, S5, S6, S7, S9       |
| PARTIAL | 3/10  | S1, S8, S10                      |
| FAIL    | 0/10  | —                                |

See [`RESULTS.md`](RESULTS.md) for the detail.
