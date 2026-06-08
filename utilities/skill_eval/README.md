# Skill evaluation harness

A self-contained harness for evaluating the BTCRecover **skill files** (the
`SKILL.md` documents under `/SKILL.md` and `/skills/`) against a panel of LLMs.
Each scenario plays out a multi-turn conversation between a *candidate* model
(driving the skills) and one or more *judge* models that score the transcript
against a per-scenario rubric. Runs can execute as plain **chat** (no tools) or
inside a **docker** sandbox where the candidate can actually run commands.

Everything needed to run the harness lives in this folder. Run all commands
**from the repository root** so the relative skill paths resolve.

## Contents

| File | What it is |
|------|------------|
| `skill_eval_harness.py` | Core engine. Runs one runner mode (chat *or* docker) per invocation. |
| `skill_eval_runner.py` | Thin wrapper that reads a suite config's `test_modes` and invokes the harness once per mode (e.g. docker **and** chat back-to-back). |
| `run_eval_suite.py` | Driver for running one or more suite configs across all of their `test_modes`. |
| `redact_skill_eval_results.py` | Post-hoc privacy pass over result JSON (strips API keys, hashes local URLs/paths). The live harness already redacts at write time. |
| `scenarios.json` | The default scenario set (rubrics + opening user messages). A JSON list. |
| `focused_scenarios.json` | A smaller subset for quick iteration. |
| `example_suite.json` | A sanitized, runnable suite config. API keys are `REDACTED` and model hosts point at localhost — fill in your own before running. |
| `example_prompts.md` | Notes / example prompts used while authoring scenarios. |

> **Note:** `utilities/net_check.py` is **not** part of this folder. It is a
> connectivity check that the skills themselves instruct agents to run (it is
> referenced by `SKILL.md` and the scenarios), so it stays at
> `utilities/net_check.py` as a real product utility.

## Requirements

- Python 3 (standard library only; the harness talks to OpenAI-compatible
  endpoints over HTTP).
- **Docker** — only for `docker` runner mode (the candidate runs commands in an
  `ubuntu:24.04` sandbox). Not needed for `chat` mode.
- API access to your candidate/judge models via any OpenAI-compatible endpoint
  (DeepSeek, a local LM Studio / llama.cpp server, etc.). Put real keys in your
  own copy of a suite config — never commit them.

## Quick start

1. Copy the example config and add your endpoints/keys:

   ```bash
   cp utilities/skill_eval/example_suite.json my_suite.json
   # edit my_suite.json: set base_url / api_key, enable the runs you want
   ```

2. Run it (chat + docker per the config's `test_modes`):

   ```bash
   python utilities/skill_eval/run_eval_suite.py my_suite.json
   ```

   Or drive the core harness directly for a single mode / single scenario:

   ```bash
   # list available scenarios
   python utilities/skill_eval/skill_eval_harness.py --list-scenarios

   # one scenario, chat mode
   python utilities/skill_eval/skill_eval_harness.py \
       --suite-config my_suite.json \
       --runner chat \
       --scenario bip38_password_recovery
   ```

Results are written to `utilities/skill_eval/results/` by default
(`--output-dir` to change; the default is gitignored). One JSON file is written
per scenario/trial with the transcript, per-rubric scores, `violation_tags`,
and token usage.

## Suite config shape

A suite config has a `shared` block (defaults applied to every run) and a
`runs` list (one entry per candidate model). Key fields:

- `scenarios` — path to the scenario file (defaults to this folder's
  `scenarios.json`).
- `output_dir` — where result JSON is written.
- `test_modes` — `["docker"]`, `["chat"]`, or `["chat", "docker"]`.
- `skills` / `skill_mode` / `skill_allocation_mode` — which `SKILL.md` files are
  exposed and whether they are all preloaded (`static`) or revealed
  progressively as the conversation routes (`progressive`).
- `judges` — the scoring panel (one or more can be `lead`); supports per-run
  overrides inside a `runs[].judges` block.

See `example_suite.json` for a complete, commented-by-example layout. Most
harness defaults can also be overridden on the CLI — run
`python utilities/skill_eval/skill_eval_harness.py --help` for the full list.

## Redaction

The harness redacts secrets and local host/path details at write time. To
re-process older result files (e.g. before sharing them):

```bash
python utilities/skill_eval/redact_skill_eval_results.py --results-dir utilities/skill_eval/results
```
