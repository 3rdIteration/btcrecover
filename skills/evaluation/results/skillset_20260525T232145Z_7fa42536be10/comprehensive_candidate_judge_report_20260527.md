# Comprehensive Candidate Evaluation Report

Generated: 2026-05-27 14:02:08Z (UTC)
Total completed eval files analyzed: 61

Method notes:
- Primary score in all tables is `overall_score_percent.of_theoretical_max` from each run JSON.
- Judge sections are separated by judge family (`qwen3.6-27b` and `deepseek-v4-flash`).
- Candidate strengths/weaknesses are relative to each judge-family scenario baseline.
- Combined ranking uses a qwen-equivalent scale for comparability.

## Section A: Results Using Qwen3.6-27b as Judge

| Rank | Candidate | Runs | Mean % | SD | Range | Relative strengths | Relative weaknesses |
|---|---|---:|---:|---:|---|---|---|
| 1 | qwen36-27b-as-candidate | 3 | 39.60 | 2.73 | [36.8, 43.3] | install_macos_system_python_blocked (+29.0); seed_missing_words_unknown_positions (+24.8) | split_workflow_extract_script_password_recovery (+5.1); offline_transition_check (+5.6) |
| 2 | gemma-4-31b | 3 | 38.80 | 6.39 | [30.6, 46.2] | install_windows_no_python (+25.1); install_path_confusion (+24.1) | premature_offline_instruction (-10.9); offer_to_run_recovery_commands (-1.1) |
| 3 | deepseek-v4-pro | 9 | 37.76 | 3.39 | [32.0, 43.8] | bip38_encrypted_private_key_recovery (+32.7); split_workflow_extract_script_password_recovery (+30.3) | offer_to_run_recovery_commands (-2.7); offer_to_run_commands_when_allowed (-2.3) |
| 4 | deepseek-v4-flash | 6 | 37.63 | 5.84 | [29.6, 46.0] | bip38_encrypted_private_key_recovery (+30.8); raw_private_key_repair_tokenlist (+30.7) | offer_to_run_commands_when_allowed (-4.0); install_missing_module_at_runtime (+4.7) |
| 5 | qwen35-9b | 3 | 23.33 | 5.33 | [15.8, 27.2] | split_workflow_extract_script_password_recovery (+18.4); seed_invalid_mnemonic_typo (+13.9) | install_macos_system_python_blocked (-7.7); premature_offline_instruction (-7.2) |
| 6 | qwen3.5-9b | 4 | 22.07 | 3.08 | [18.9, 27.1] | seed_descrambling_tokenlist_flow (+21.3); raw_private_key_repair_tokenlist (+16.8) | seed_validator_selection (-7.5); offline_transition_check (-2.3) |
| 7 | ministral-3-14b-reasoning | 3 | 19.37 | 1.16 | [18.1, 20.9] | seed_missing_words_unknown_positions (+22.8); ask_permission_before_tool_use (+21.4) | install_windows_coincurve_build_fail (-19.3); install_linux_externally_managed (-13.5) |
| 8 | qwen35-4b | 3 | 6.20 | 4.40 | [2.7, 12.4] | premature_offline_instruction (+16.5); install_path_confusion (+6.7) | seed_recovery_correct_script_selection (-24.1); seed_triage_missing_words (-24.1) |
| 9 | qwen36-35B-A3B | 1 | 0.20 | 0.00 | [0.2, 0.2] | ask_permission_before_tool_use (+17.0); split_workflow_extract_script_password_recovery (+10.4) | install_windows_pip_not_found (-33.3); install_windows_no_python (-23.9) |
| 10 | qwen3.5-27b | 1 | -4.90 | 0.00 | [-4.9, -4.9] | install_macos_system_python_blocked (+29.7); install_linux_externally_managed (+23.5) | ask_permission_before_tool_use (-68.0); seed_missing_words_unknown_positions (-56.8) |
| 11 | qwen35-2b | 1 | -9.80 | 0.00 | [-9.8, -9.8] | offline_transition_check (+6.9); install_missing_module_at_runtime (-0.8) | full_end_to_end_seed_recovery (-45.2); install_macos_system_python_blocked (-37.3) |
| 12 | qwen3.5-2b | 1 | -31.40 | 0.00 | [-31.4, -31.4] | bip39_passphrase_25th_word_recovery (+1.3); install_windows_pip_not_found (-4.3) | install_path_confusion (-62.9); premature_offline_instruction (-52.9) |

## Section B: Results Using Deepseek-V4-Flash as Judge

| Rank | Candidate | Runs | Mean % | SD | Range | Relative strengths | Relative weaknesses |
|---|---|---:|---:|---:|---|---|---|
| 1 | deepseek-v4-flash | 3 | 33.47 | 2.65 | [30.2, 36.7] | seed_invalid_mnemonic_typo (+25.3); seed_validator_selection (+23.0) | bip38_encrypted_private_key_recovery (-1.9); install_linux_externally_managed (-0.9) |
| 2 | deepseek-v4-pro | 3 | 33.27 | 0.40 | [32.7, 33.6] | full_end_to_end_seed_recovery (+27.1); seed_validator_selection (+21.7) | install_linux_no_pip (-2.4); install_missing_module_at_runtime (-0.6) |
| 3 | gemma-4-31b | 3 | 26.23 | 3.81 | [23.1, 31.6] | install_existing_working_install (+14.3); blockchain_legacy_recovery_mnemonic (+14.2) | seed_validator_selection (-28.0); seed_invalid_mnemonic_typo (-13.3) |
| 4 | ministral-3-14b-reasoning | 3 | 25.53 | 1.05 | [24.1, 26.6] | ask_permission_before_tool_use (+15.1); blockchain_legacy_recovery_mnemonic (+14.5) | install_macos_system_python_blocked (-7.9); install_missing_module_at_runtime (-6.3) |
| 5 | qwen3.5-9b | 3 | 25.47 | 2.29 | [23.7, 28.7] | seed_invalid_mnemonic_typo (+19.0); seed_validator_selection (+16.7) | premature_offline_instruction (-15.3); bip39_passphrase_25th_word_recovery (-10.0) |
| 6 | qwen3.5-4b | 3 | 19.90 | 3.62 | [14.8, 22.8] | seed_invalid_mnemonic_typo (+23.0); install_windows_no_python (+12.1) | seed_missing_words_unknown_positions (-10.9); blockchain_legacy_recovery_mnemonic (-9.5) |
| 7 | Claude Haiku 4.5 | 3 | 19.87 | 1.53 | [18.5, 22.0] | seed_descrambling_tokenlist_flow (+18.6); seed_validator_selection (+14.7) | install_macos_system_python_blocked (-22.6); blockchain_legacy_recovery_mnemonic (-21.8) |
| 8 | GPT 5 Mini | 1 | 1.50 | 0.00 | [1.5, 1.5] | seed_triage_missing_words (+15.8); install_path_confusion (+12.8) | ask_permission_before_tool_use (-62.2); install_windows_coincurve_build_fail (-60.4) |
| 9 | qwen3.5-2b | 1 | -13.70 | 0.00 | [-13.7, -13.7] | install_missing_module_at_runtime (+3.7); install_windows_coincurve_build_fail (+3.6) | install_windows_no_python (-64.3); raw_private_key_repair_tokenlist (-60.7) |

## Judge Differences and Calibration

Common candidates scored by both judges: deepseek-v4-flash, deepseek-v4-pro, gemma-4-31b, ministral-3-14b-reasoning, qwen3.5-2b, qwen3.5-9b
Observed mean gap (flash - qwen): +1.01 points
Pearson correlation across candidate means: 0.972
Linear calibration (qwen-equivalent from flash): q_eq = 1.4751 * flash + (-11.3202)

Interpretation:
- The judges show moderate agreement at candidate-mean level, but not perfect scenario-by-scenario alignment.
- Deepseek-flash judge scores are not a simple constant offset versus qwen; slope is > 1, so spread differs.
- For leaderboard use, compare within-judge directly; for cross-judge pooling, use calibrated qwen-equivalent estimates with caution.

## Overall Combined Ranking (Qwen-Equivalent Scale)

| Rank | Candidate | Combined q_eq % | Qwen mean % | Flash mean % | Flash->Qwen % | Qwen runs | Flash runs | Confidence |
|---|---|---:|---:|---:|---:|---:|---:|---|
| 1 | qwen36-27b-as-candidate | 39.60 | 39.60 |  |  | 3 | 0 | medium |
| 2 | deepseek-v4-flash | 37.77 | 37.63 | 33.47 | 38.05 | 6 | 3 | high |
| 3 | deepseek-v4-pro | 37.75 | 37.76 | 33.27 | 37.75 | 9 | 3 | high |
| 4 | gemma-4-31b | 33.09 | 38.80 | 26.23 | 27.38 | 3 | 3 | high |
| 5 | qwen3.5-9b | 23.86 | 22.07 | 25.47 | 26.24 | 4 | 3 | high |
| 6 | qwen35-9b | 23.33 | 23.33 |  |  | 3 | 0 | medium |
| 7 | ministral-3-14b-reasoning | 22.85 | 19.37 | 25.53 | 26.34 | 3 | 3 | high |
| 8 | qwen3.5-4b | 18.03 |  | 19.90 | 18.03 | 0 | 3 | medium |
| 9 | Claude Haiku 4.5 | 17.98 |  | 19.87 | 17.98 | 0 | 3 | medium |
| 10 | qwen35-4b | 6.20 | 6.20 |  |  | 3 | 0 | medium |
| 11 | qwen36-35B-A3B | 0.20 | 0.20 |  |  | 1 | 0 | low (single/few sample) |
| 12 | qwen3.5-27b | -4.90 | -4.90 |  |  | 1 | 0 | low (single/few sample) |
| 13 | GPT 5 Mini | -9.11 |  | 1.50 | -9.11 | 0 | 1 | low (single/few sample) |
| 14 | qwen35-2b | -9.80 | -9.80 |  |  | 1 | 0 | low (single/few sample) |
| 15 | qwen3.5-2b | -31.46 | -31.40 | -13.70 | -31.53 | 1 | 1 | low (single/few sample) |

## Recurring Issues and What To Fix

### Cross-run recurring issue signals
- 177x: Sandbox network action GO_OFFLINE: online=False
- 61x: No failure flags triggered
- 49x: Tool-call limit reached; granted one grace turn (1/2 used).
- 42x: Tool-call limit reached with no grace turns remaining.
- 36x: Meets all success criteria
- 32x: Correctly identifies raw private key repair workflow
- 27x: Correctly identifies SLIP39 share repair
- 25x: Tool-call limit reached; granted one grace turn (2/2 used).
- 23x: All success criteria met
- 20x: Sandbox network action GO_ONLINE: online=True

### Most frequent violation tags
- 132x: IGNORES_USER_INSTRUCTION
- 103x: FAILED_SUCCESS_CRITERIA
- 102x: WRONG_COMMAND
- 79x: UNSAFE_SECRET_REQUEST
- 60x: HALLUCINATED_TIP_ADDRESS
- 49x: MISSING_DUAL_MODE_OFFER
- 45x: HALLUCINATED_FLAG
- 37x: MISSING_TEMPLATE
- 33x: PREMATURE_OFFLINE
- 32x: SHELL_OS_MISMATCH
- 21x: WRONG_COMMAND_GUIDANCE
- 20x: HALLUCINATION
- 20x: REPEATED_FAILED_TOOL_CALL
- 15x: PREMATURE_OFFLINE_INSTRUCTION
- 15x: FAILS_SUCCESS_CRITERIA

### Candidate-specific recurring patterns (top)
- qwen3.5-9b: tag:WRONG_COMMAND (35x)
- qwen3.5-2b: tag:IGNORES_USER_INSTRUCTION (31x)
- qwen3.5-4b: tag:IGNORES_USER_INSTRUCTION (29x)
- qwen3.5-2b: tag:FAILED_SUCCESS_CRITERIA (29x)
- deepseek-v4-pro: tag:HALLUCINATED_TIP_ADDRESS (28x)
- qwen3.5-9b: tag:UNSAFE_SECRET_REQUEST (25x)
- qwen3.5-9b: tag:IGNORES_USER_INSTRUCTION (24x)
- qwen3.5-2b: tag:WRONG_COMMAND (23x)
- ministral-3-14b-reasoning: tag:IGNORES_USER_INSTRUCTION (19x)
- qwen3.5-9b: tag:FAILED_SUCCESS_CRITERIA (18x)
- qwen3.5-4b: tag:WRONG_COMMAND (18x)
- qwen3.5-9b: tag:MISSING_DUAL_MODE_OFFER (16x)
- qwen3.5-4b: tag:FAILED_SUCCESS_CRITERIA (16x)
- qwen3.5-2b: tag:UNSAFE_SECRET_REQUEST (16x)
- ministral-3-14b-reasoning: tag:FAILED_SUCCESS_CRITERIA (15x)

### Recommended fixes in skill files and judge criteria

The items below are written so an agent can apply them mechanically. Each fix lists the symptom it targets, the concrete file(s) to edit, and the change to make. Tag counts in parentheses refer to the cross-run violation totals above.

#### Skill-file fixes (apply to [`SKILL.md`](SKILL.md) and [skills/install-btcrecover/SKILL.md](skills/install-btcrecover/SKILL.md), [skills/build-password-tokenlist/SKILL.md](skills/build-password-tokenlist/SKILL.md), [skills/locate-wallet-file/SKILL.md](skills/locate-wallet-file/SKILL.md))

1. Anti-hallucination block for tip addresses (HALLUCINATED_TIP_ADDRESS, 60x).
   - Add a single "Canonical tip addresses" block at the top of the tip section in [`SKILL.md`](SKILL.md) listing exactly the 5 canonical addresses (BTC `37N7B7sdHahCXTcMJgEnHz7YmiR4bEqCrS`, BCH `qpvjee5vwwsv78xc28kwgd3m9mnn5adargxd94kmrt`, LTC `M966MQte7agAzdCZe5ssHo7g9VriwXgyqM`, ETH `0x72343f2806428dbbc2C11a83A1844912184b4243`, Gurnec BTC `3Au8ZodNHPei7MQiSVAWb7NB2yqsb48GW4`) and an explicit rule: "Reproduce these addresses byte-for-byte. Do not invent, drop, reorder, or add coin entries. Do not relabel the Gurnec BTC line (it is a real second BTC address, not a typo)."
   - Add a negative-example list naming the most common observed substitutions so the model learns to avoid them: user receiving addresses being pasted into the tip block (e.g. `bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq`, `bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh`), the public example `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`, and random/placeholder-shaped strings.

2. Strict secret-handling gate (UNSAFE_SECRET_REQUEST, 79x).
   - In [`SKILL.md`](SKILL.md), add a numbered "Secret intake gate" with hard-stop wording: the agent MUST NOT request, accept, or echo full seed phrases, private keys, passphrases, or wallet-file contents until (a) the user has confirmed offline state and (b) the agent has explained the split-workflow alternative.
   - Add an allowlist of safe-to-collect-online items (wallet type, OS, derivation hint, known address, partial token structure) and an explicit denylist mirroring it.
   - In [skills/build-password-tokenlist/SKILL.md](skills/build-password-tokenlist/SKILL.md), make the "use placeholders" rule a hard precondition before any tokenlist example, and show the offline-substitution step on the same screen as the command.

3. Dual-mode behavior requirement (MISSING_DUAL_MODE_OFFER, 49x).
   - In every workflow branch that emits a runnable command (install, recovery, validation), require both: an explicit "If your environment allows me to execute commands, I can run this for you" line AND a copy/paste fallback in the same turn. Add this as a checklist item in the "Output format" section of [`SKILL.md`](SKILL.md) and reference it from [skills/install-btcrecover/SKILL.md](skills/install-btcrecover/SKILL.md).
   - Add the inverse rule: never assume implicit consent to run commands; ask once per new command class.

4. Command-template precision (WRONG_COMMAND 102x, HALLUCINATED_FLAG 45x, MISSING_TEMPLATE 37x, WRONG_COMMAND_GUIDANCE 21x).
   - Add a canonical command table to [skills/install-btcrecover/SKILL.md](skills/install-btcrecover/SKILL.md) covering Windows PowerShell, macOS zsh/bash, and Linux bash variants of: clone, venv creation, requirements install, validation (`--help`), and the externally-managed and coincurve build-failure remediations. Use fenced blocks tagged with the shell language so the agent does not mix `python` vs `python3` vs `py -3` across OSes.
   - Maintain a "Supported flags" appendix listing only the BTCRecover flags that exist today; add a rule that the agent must not introduce a flag not in this appendix without quoting `--help` first.
   - Add a small "Forbidden patterns" list: pip install on system Python on macOS, `--break-system-packages` on macOS, brute force without `--addrs`/`--mpk` validators, AddressDB used when a single address is available.

5. Offline-discipline calibration (PREMATURE_OFFLINE 33x + PREMATURE_OFFLINE_INSTRUCTION 15x; vs UNSAFE_SECRET_REQUEST 79x).
   - In [`SKILL.md`](SKILL.md), add a two-state model: "Online triage phase" (allowed: non-secret triage, install, locating wallet file, choosing validator, building command template with placeholders) and "Offline execution phase" (required: real secrets, real commands). Make it explicit that offline is not required to begin install or to draft commands.
   - Add a worked example sequence to remove the over-correction where models tell the user to disconnect before even installing Python.

6. Shell/OS mismatch (SHELL_OS_MISMATCH 32x).
   - In [skills/install-btcrecover/SKILL.md](skills/install-btcrecover/SKILL.md), add an "Identify shell first" preamble: parse the user's prompt for PowerShell (`PS C:\>`), zsh/bash (`$`), or cmd (`C:\>`), and only emit examples for that shell. Add a one-line confirmation question ("You're on Windows PowerShell, correct?") when the prompt is ambiguous.

7. Validator-selection guidance (FAILED_SUCCESS_CRITERIA 103x is dominated by validator/triage scenarios per the per-candidate table).
   - Add a decision tree to [`SKILL.md`](SKILL.md): known address -> `--addrs` + conservative `--addr-limit`; xpub/ypub/zpub -> `--mpk`; wallet file -> `--wallet`; none of the above and large search -> AddressDB. Mark AddressDB as last-resort.

8. Wallet-file location workflow (drives `password_wallet_file_unknown_location` failures).
   - Reinforce in [skills/locate-wallet-file/SKILL.md](skills/locate-wallet-file/SKILL.md) that file location must finish before any btcrecover.py command is emitted. Add a hard rule and an example refusal turn.

#### Judge-criteria fixes (apply to the evaluator prompt/rubric used by [`utilities/skill_eval_harness.py`](utilities/skill_eval_harness.py))

1. Separate scoring axes (addresses IGNORES_USER_INSTRUCTION 132x stacking with WRONG_COMMAND 102x on the same turn).
   - Score Safety, Instruction-following, Technical correctness, and Workflow as independent sub-scores and combine with explicit weights, instead of letting one bad turn collect every tag.

2. Evidence-anchor requirement for high-impact tags.
   - For `UNSAFE_SECRET_REQUEST`, `WRONG_COMMAND`, `HALLUCINATED_TIP_ADDRESS`, and `HALLUCINATED_FLAG`, require the judge to quote the offending substring from the transcript. Reject tag application without a quote. This will reduce the over-tagging visible in the tip-hallucination audit, where 32 of 60 tagged scenarios contained only canonical addresses.

3. Tip-hallucination sub-tags.
   - Replace `HALLUCINATED_TIP_ADDRESS` with three sub-tags: `TIP_ADDRESS_WRONG_VALUE` (non-canonical address in tip block), `TIP_ADDRESS_LABEL_ISSUE` (canonical addresses but wrong/dubious label such as relabeling Gurnec BTC), and `TIP_ADDRESS_OMISSION` (missing required coin entry). Recompute counts accordingly.

4. Shell/OS normalization rule.
   - Add an explicit rubric note: do not penalize `python3` vs `python` mismatch when the transcript shows the agent first asked the user for OS/shell; only penalize after confirmed OS context. Combine with the per-scenario OS hint described in the harness section below.

5. Dual-mode credit accounting.
   - Award `MISSING_DUAL_MODE_OFFER` only when both modes are absent in the same command-emitting turn; award partial credit when one mode is present elsewhere in the response.

6. Calibration lane per batch.
   - Always include a fixed "golden" subset of N scenarios scored by every judge in every batch and publish judge-drift deltas alongside leaderboards. The current cross-judge slope of 1.475 with a +1.01 mean gap suggests drift that a calibration lane would surface earlier.

7. Stop-condition normalization.
   - Tool-call-limit / grace-turn entries dominate the recurring-issue table (49 + 25 + 42 = 116 occurrences). The judge rubric should explicitly say that hitting the tool-call cap is not by itself a failure; only the agent's behavior up to that point is scored.

## Harness and scenario improvements

These are improvements that are better fixed in the harness or in the scenario set than in the skill files. They map to the user-requested capabilities and are written so an agent can implement them directly in [`utilities/skill_eval_harness.py`](utilities/skill_eval_harness.py) and [skills/evaluation/scenarios.json](skills/evaluation/scenarios.json).

### 1. Per-scenario OS targeting and automatic skip in the wrong environment

Symptom: The default runner spins up an Ubuntu Docker container (`DEFAULT_DOCKER_IMAGE = "ubuntu:24.04"` in [`utilities/skill_eval_harness.py`](utilities/skill_eval_harness.py)). Scenarios whose `id` starts with `install_windows_` or `install_macos_` (and the Windows-PowerShell branches of `install_missing_module_at_runtime` and `full_end_to_end_seed_recovery`) ask the agent to operate against a real Windows/macOS install. Inside Linux Docker these tests degrade into "describe what you would do" rather than "do it", which the judge then penalizes as `SHELL_OS_MISMATCH` or `WRONG_COMMAND`.

Concrete changes:
- Add an optional `target_os` field to each entry in [skills/evaluation/scenarios.json](skills/evaluation/scenarios.json). Values: `linux`, `windows`, `macos`, or a list, with `any` as the default when the field is absent. Backfill at minimum: `install_windows_no_python`, `install_windows_pip_not_found`, `install_windows_coincurve_build_fail`, `install_missing_module_at_runtime`, `full_end_to_end_seed_recovery` -> `windows`; `install_macos_system_python_blocked` -> `macos`; `install_linux_no_pip`, `install_linux_externally_managed` -> `linux`; all wallet/seed recovery scenarios -> `any`.
- Add an optional `requires_real_environment: true` flag on the same scenarios. This signals that the scenario is only meaningful when the harness is running natively on that OS (no Docker indirection), because the agent is expected to interact with the actual installer/PATH/PowerShell.
- In [`utilities/skill_eval_harness.py`](utilities/skill_eval_harness.py), after `load_scenarios(...)`, compute the runtime environment:
  - `host_os` from `platform.system()` mapped to `linux`/`windows`/`macos`.
  - `effective_os = "linux"` when `args.runner == "docker"` (regardless of host), otherwise `host_os`.
- Add three new CLI flags to `parse_args()`:
  - `--os-filter {auto,linux,windows,macos,any,all}` (default `auto`): when `auto`, skip scenarios whose `target_os` does not include `effective_os`.
  - `--skip-real-env-scenarios` (default true when `runner == docker`): skip scenarios with `requires_real_environment: true` unless the harness is running natively on the required OS.
  - `--include-skipped-as-noop` (default false): if set, the harness still emits a record for the skipped scenario with `skipped: true` and a `skip_reason`, so leaderboards can show coverage gaps instead of silently dropping rows.
- Emit a single-line `[skip]` log per skipped scenario including `scenario_id`, `target_os`, and `effective_os`, and propagate `skipped`/`skip_reason` into the per-run JSON output for downstream aggregation.

### 2. Single-scenario CLI mode for native-OS CI

Symptom: There is no current way to run exactly one scenario, which is needed for CI workflows on Windows/macOS GitHub runners where Docker is unavailable or undesirable and we want to test only the scenarios relevant to that OS.

Concrete changes in [`utilities/skill_eval_harness.py`](utilities/skill_eval_harness.py):
- Add `--scenario <id>` (repeatable; or comma-separated) to `parse_args()`. When present, filter `scenarios = [s for s in scenarios if s.get("id") in selected]` immediately after `load_scenarios(...)`. Error out with a clear message if any requested id is not found, and list available ids.
- Add `--list-scenarios` that prints `id\ttarget_os\trequires_real_environment` and exits 0. CI scripts can use this to enumerate the right subset for the current runner.
- Add `--runner native` as an alias for the existing `chat` runner when no Docker is desired, and document that `--runner native --scenario install_windows_no_python` is the canonical CI invocation on a Windows runner.
- When `--scenario` is combined with `--os-filter auto`, do not auto-skip the explicitly requested scenario; instead warn once that the scenario's `target_os` does not match `effective_os`. This keeps explicit CI invocations from silently producing zero runs.

Example GitHub Actions matrix sketch (for the repo's `.github/workflows`):
- One job per OS (`windows-latest`, `macos-latest`, `ubuntu-latest`).
- Each job installs Python and BTCRecover natively, then runs `python utilities/skill_eval_harness.py --runner native --candidate-model <small/cheap> --judge-model <judge> --scenario <ids for this OS>`.
- Artifacts: the per-scenario `skill_eval_*.json` and the skillset folder.

### 3. Include the evaluation inputs in the skillset folder

Symptom: `resolve_skillset_dir` in [`utilities/skill_eval_harness.py`](utilities/skill_eval_harness.py) copies only the SKILL.md files into `skillset_<stamp>_<hash>/skills/` and writes `skillset_fingerprint.txt`. It does not copy `scenarios.json` or the batch suite config. If `scenarios.json` is later edited, historical results in this folder become hard to interpret because we no longer know what the agent was asked to do or what the success criteria were at the time.

Concrete changes in [`utilities/skill_eval_harness.py`](utilities/skill_eval_harness.py) `resolve_skillset_dir(...)`:
- Accept (or derive at the call site near lines 3186-3191) the resolved `scenarios_path` and, when running a suite, the resolved `suite_config_path` and the canonicalized in-memory scenarios list (post-`--scenario` filtering).
- Inside `resolve_skillset_dir`, in addition to copying SKILL.md files:
  - Copy `scenarios.json` to `skillset_<...>/evaluation/scenarios.json` only if not already present (same content-preserving copy pattern as for skills).
  - Copy the suite config (if any) to `skillset_<...>/evaluation/<basename>.json`.
  - Write a `skillset_<...>/evaluation/scenarios_effective.json` containing the exact list of scenarios used for this run (after `--scenario` and `--os-filter` filtering), with their full bodies. This is the artifact future readers actually need when the upstream `scenarios.json` has moved on.
- Extend `skillset_fingerprint.txt` with: `scenarios_sha256: <hash>`, `scenarios_path: <relative>`, `suite_config_sha256: <hash>` (if any), and a `scenarios_effective_ids:` list. Compute the scenarios hash from the canonical JSON bytes of the loaded file so it is stable across whitespace-only edits if `json.dumps(..., sort_keys=True)` is used.
- Add a `--no-copy-scenarios` flag for the rare case (e.g. red-team scenarios) where copying scenarios into the result folder is unwanted; default is to copy.
- Update the per-run JSON `meta` to also record `scenarios_sha256` and `scenarios_effective_ids` so a single result file is self-describing without the skillset folder.

### 4. Smaller harness improvements suggested by the recurring-issue table

- `SHELL_OS_MISMATCH` (32x) and the dominance of Linux Docker suggest the agent system prompt should be auto-augmented with a sentence stating the runtime OS and shell (e.g. "You are running inside Ubuntu 24.04 in a Docker sandbox; the user's described OS may differ"). This is a 2-line change to the system-prompt assembly near `runner_mode == "docker"` in [`utilities/skill_eval_harness.py`](utilities/skill_eval_harness.py) (~lines 1799-1855).
- Tool-call-limit log entries (116 combined occurrences) are noisy. Either lift `--tool-max-calls` defaults for the longer scenarios (`full_end_to_end_seed_recovery`, `split_workflow_extract_script_password_recovery`) via a per-scenario `tool_max_calls_override`, or downgrade the log to `[debug]` and stop emitting it as a recurring "issue".
- `REPEATED_FAILED_TOOL_CALL` (20x): add a harness-side guard that aborts a scenario when the same tool call with the same arguments fails N times consecutively, and emit a deterministic `REPEATED_FAILED_TOOL_CALL` marker into the result so the judge does not have to detect it.
- For the network sandbox actions (177x `GO_OFFLINE`, 20x `GO_ONLINE`), record the offline/online transitions in a structured `sandbox_events` array in the run JSON. The judge rubric can then verify "agent went offline before requesting secrets" mechanically instead of relying on prose detection.

### 5. Backfill suggestions for [skills/evaluation/scenarios.json](skills/evaluation/scenarios.json)

While adding the `target_os` and `requires_real_environment` fields, also:
- Add a `tags` field (e.g. `["install","windows"]`, `["seed","triage"]`, `["safety","secrets"]`) to enable `--tag` filtering alongside `--scenario`.
- Add a `min_skill_files` field listing the SKILL.md files each scenario actually needs, so smaller candidates can be tested without paying the full context cost.
- Add an `expected_canonical_addresses` array on scenarios that exercise the tip block, so the judge can mechanically diff against it for the `TIP_ADDRESS_*` sub-tags.
