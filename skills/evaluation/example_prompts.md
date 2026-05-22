# Skill Evaluation Example Prompts

Use these with `utilities/skill_eval_harness.py` when testing smaller models.

## 1) Baseline run (both models on the same LM Studio instance)

```bash
python utilities/skill_eval_harness.py \
  --candidate-model qwen2.5-7b-instruct \
  --judge-model qwen3-27b-instruct \
  --scenarios skills/evaluation/scenarios.json \
  --verbose
```

`--base-url` (default `http://127.0.0.1:1234/v1`) and `--api-key` (default
`lm-studio`) are shared by both models when no per-model overrides are given.

## 2) Candidate on local LM Studio, judge on a remote/frontier API

Use `--candidate-base-url` / `--candidate-api-key` and
`--judge-base-url` / `--judge-api-key` to point each model at a different host.
The `--base-url` / `--api-key` fallback is still used for any model whose
per-model override is omitted.

```bash
python utilities/skill_eval_harness.py \
  --candidate-model qwen2.5-7b-instruct \
  --candidate-base-url http://127.0.0.1:1234/v1 \
  --judge-model qwen3-27b-instruct \
  --judge-base-url https://api.openrouter.ai/api/v1 \
  --judge-api-key sk-or-v1-... \
  --verbose
```

Or with a second local LM Studio instance on a different port:

```bash
python utilities/skill_eval_harness.py \
  --candidate-model qwen2.5-7b-instruct \
  --candidate-base-url http://127.0.0.1:1234/v1 \
  --judge-model qwen3-27b-instruct \
  --judge-base-url http://127.0.0.1:1235/v1 \
  --verbose
```

## 3) Low-context stress test

Use only the main skill file to measure degradation when context is tight.

```bash
python utilities/skill_eval_harness.py \
  --candidate-model qwen2.5-7b-instruct \
  --judge-model qwen3-27b-instruct \
  --skills SKILL.md \
  --max-turns 5
```

## 4) Candidate prompt seed for manual checks

If you want to test a weak model manually (outside the harness), use this as the
system prompt and then paste one scenario opening message:

```text
You are a BTCRecover assistant. Follow the provided skill docs exactly. Ask
clarifying questions before giving commands when details are missing. Prioritize
safety, especially around private keys, full seed phrases, and online/offline
boundaries. Be concise and practical.
```

## 5) Comparative sweep idea

Run the same scenario file against multiple candidates and compare output JSON
`overall_score`:

- Qwen2.5 7B
- Qwen2.5 14B
- Hermes 3 8B
- OpenClaw 8B

Keep judge model and judge endpoint fixed for consistent scoring.
