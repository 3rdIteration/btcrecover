# Skill Evaluation Example Prompts

Use these with `utilities/skill_eval_harness.py` when testing smaller models.

## 1) Baseline run (single candidate vs strong judge)

```bash
python utilities/skill_eval_harness.py \
  --candidate-model qwen2.5-7b-instruct \
  --judge-model qwen3-27b-instruct \
  --scenarios skills/evaluation/scenarios.json \
  --verbose
```

## 2) Low-context stress test

Use only the main skill file to measure degradation when context is tight.

```bash
python utilities/skill_eval_harness.py \
  --candidate-model qwen2.5-7b-instruct \
  --judge-model qwen3-27b-instruct \
  --skills SKILL.md \
  --max-turns 5
```

## 3) Candidate prompt seed for manual checks

If you want to test a weak model manually (outside the harness), use this as the
system prompt and then paste one scenario opening message:

```text
You are a BTCRecover assistant. Follow the provided skill docs exactly. Ask
clarifying questions before giving commands when details are missing. Prioritize
safety, especially around private keys, full seed phrases, and online/offline
boundaries. Be concise and practical.
```

## 4) Comparative sweep idea

Run the same scenario file against multiple candidates and compare output JSON
`overall_score`:

- Qwen2.5 7B
- Qwen2.5 14B
- Hermes 3 8B
- OpenClaw 8B

Keep judge model fixed for consistent scoring.
