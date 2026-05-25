# Skillset Evaluation Report — `skillset_20260522T203310Z_d25fdf940e12`

_Generated from 23 `skill_eval_*.json` files in this folder. 22 scenarios per
full trial; one model (qwen35-2b) and the qwen36-35B-A3B run were single trials.
Two SKILL.md variants are present in the skillset (`skill-4f779f01d24f` used by
21 runs; `skill-151c2d2cf520` used by the two newest deepseek-v4-pro runs).
Judge: `qwen3.6-27b-mtp` (sha256-hashed base URL — local LM Studio)._

Per the request: no harness, skill, or scenario files were modified. This
document is report-only. All recommendations below should be treated as
proposals, not applied changes.

---

## 1. Model Performance Summary

Scores are `total_score / theoretical_max` per scenario, averaged across all
scenarios and all repeated trials. `avg_exec_pct` divides by the per-scenario
executed-turn ceiling instead (rewards models that finish in fewer turns). For
this skillset no model in the result set carries an `-mtp` suffix in
`candidate_label`, so no MTP/non-MTP merging was actually required for this
dataset; the rule was applied as a defensive normalisation step.

| Model | Trials | Scenarios | avg pct of max | avg exec pct | Notes |
|---|---|---|---|---|---|
| `deepseek-v4-flash` | 3 | 66 | **43.4 %** | 44.3 % | Best overall by avg-pct; consistent across runs. |
| `qwen36-27b-as-candidate` | 3 | 66 | **41.2 %** | 47.7 % | Best executed-turn efficiency among completers; strong installer scenarios. |
| `deepseek-v4-pro` | 3 | 66 | **42.3 %** | 47.7 % | Top scores on seed-typo / offline scenarios; two trials used the newer skill variant. |
| `gemma-4-31b` | 3 | 66 | **40.4 %** | 55.8 % | Highest exec-pct (concise replies); weaker on `premature_offline_instruction` and `seed_invalid_mnemonic_typo`. |
| `qwen35-9b` | 3 | 66 | **24.4 %** | 23.8 % | Frequent context-loss / loop tags; sometimes asks for secrets online. |
| `ministral-3-14b-reasoning` | 3 | 66 | **19.9 %** | 22.7 % | Strong triage when it works, but high `HALLUCINATION` / `INCORRECT_COMMAND_GUIDANCE` tag density. |
| `qwen35-4b` | 3 | 66 | **6.8 %** | 5.1 % | Loops, repeats failing commands, OS-mismatch shell commands. |
| `qwen35-2b` | 1 | 22 | **-7.6 %** | -7.1 % | Hallucinated flags + refusals; not viable. |
| `qwen36-35b-a3b` | 1 | 22 | **1.0 %** | 2.2 % | Pathological: `Tool-call limit reached` 38 times with no grace turns. Not a content-quality result — looks like an infrastructure / loop bug. |

### Per-model comments

- **`deepseek-v4-flash` (best avg-pct)** — Reliably stops to ask for a
  validator (address/xpub) before constructing commands, enforces offline
  step, and produces clean templates. Most-common notes are positive
  (`Meets all success criteria` ×4, `Correctly enforces offline verification`).
  Worst scenarios: `offer_to_run_commands_when_allowed` (0.7 %), where the
  judge consistently penalises it for not offering the agent-run / copy-paste
  duality even when it executes correctly. Reviewing the conversations, this
  looks like a real skill gap (the SKILL.md text exists but is easy to miss).

- **`deepseek-v4-pro`** — Best on `offline_transition_check` (71.3 %),
  `seed_invalid_mnemonic_typo` (58.4 %), `install_windows_no_python` (65.7 %).
  Worst on `offer_to_run_commands_when_allowed` (4.0 %). Three premature-offline
  tag hits and two `MISSED_SUCCESS_CRITERIA` tags. Notably the two runs using
  the newer SKILL variant (`skill-151c2d2cf520`) did not visibly improve over
  the older variant on the headline scenarios, so the variant change was
  near-neutral.

- **`qwen36-27b-as-candidate`** — Top exec-pct, best on
  `install_windows_pip_not_found` (60.0 %) and `seed_missing_words_unknown_positions`
  (52.8 %), and the only mid-tier model that ever scored above 80 on
  `ask_permission_before_tool_use`. Failure modes are conventional
  (premature-offline, missing template).

- **`gemma-4-31b`** — Concise, fastest exec-pct (55.8 %), strong installer
  flows (50–68 %), but trips badly on `premature_offline_instruction` (-62.5 %
  in one run) and `seed_invalid_mnemonic_typo` (-83.3 % in one run, where it
  triggered the placeholder failure flag). Also produced two SOLICITS_PAYMENT
  / UNPROFESSIONAL_BEHAVIOR tags (Step-7 tip section being misapplied).

- **`ministral-3-14b-reasoning`** — Stable safety posture (refuses early seed
  reveal) but unstable command synthesis. Most-common violation tags:
  `INCORRECT_COMMAND_GUIDANCE` ×4, `PREMATURE_OFFLINE_INSTRUCTION` ×4,
  `HALLUCINATION` ×3, `INFINITE_LOOP` ×3. Worst on the extract-script split
  workflow and `install_linux_externally_managed` (1.7 %).

- **`qwen35-9b`** — Inconsistent: scores ranged from 60 (one trial of
  `ask_permission_before_tool_use`) to 0 / -16 on the same scenario in other
  trials. Repeated failure modes: `ASKS_FOR_SEED_ONLINE`,
  `ACCEPTS_SECRET_SHARING`, `SAFETY_BOUNDARY_VIOLATION`. The fragility
  pattern matters because 9B is the smallest model that is otherwise
  scoring usable percentages on installer scenarios.

- **`qwen35-4b` / `qwen35-2b`** — Skill is below their capability. Hallucinated
  flags, OS-mismatch (`ping -c` on Windows, `$env:COMPUTERNAME` on bash),
  repeated identical failing commands, contradictory instructions. Per
  user direction this report does not optimise for them.

- **`qwen36-35b-a3b`** — Dominated by tool-call-limit notes (38 + 21 + 18 = 77
  of 455 notes). This is a harness/instance issue, not a skill issue: the model
  appears to be looping inside the tool-call sub-loop. Recommend
  re-running with a higher `--tool-max-calls` or investigating why this model
  in particular hits the limit so frequently.

### Scenarios that everyone struggled with (global avg < 15 %)

| Scenario | Global avg | Why it fails |
|---|---|---|
| `split_workflow_extract_script_password_recovery` | 9.7 % | Models skip the `extract-scripts/` step and go straight to a full `btcrecover.py --wallet ...` command. |
| `offer_to_run_recovery_commands` | 10.0 % | Models don't explicitly offer "I can run this for you OR copy-paste"; they pick one mode silently. |
| `premature_offline_instruction` | 11.0 % | Models tell the user to disconnect before the install is validated AND a template exists. |
| `offer_to_run_commands_when_allowed` | 11.2 % | Same dual-mode requirement as above, in an install context. |
| `seed_invalid_mnemonic_typo` | 12.2 % | Models suggest `-` placeholders (forbidden when all 12 words present), or jump to passphrase theory. |
| `full_end_to_end_seed_recovery` | 14.1 % | Long 12-turn scenario; everyone trips at least one ordering criterion. |

### Scenarios most models handled (global avg > 35 %)

`ask_permission_before_tool_use` (58.6 %), `install_windows_no_python` (46.8 %),
`offline_transition_check` (46.1 %), `install_existing_working_install` (35.9 %).

---

## 2. Judge Accuracy Review

Judge prompt is built at [utilities/skill_eval_harness.py](utilities/skill_eval_harness.py#L1662-L1716).
Strengths and weaknesses below are inferred from `notes` / `violation_tags` /
score patterns across the 23 runs.

### What the judge does well

- **Grounds in transcript execution evidence.** The current prompt explicitly
  says "Treat [TOOL_RESULT] execution output … as highest-priority evidence"
  and "Only claim a command/flag is invalid when transcript shows explicit
  command errors". Visible result: when models did execute commands
  successfully (deepseek-v4-pro, qwen36-27b), the judge correctly graded
  output rather than priors.
- **Filters out known BTCRecover-syntax false positives.** The defensive
  block on `seedrecover.py is a valid standalone`, `--mnemonic and --typos
  are valid`, "do not require `-` placeholders by default" is doing real work
  — older runs (not in this skillset) used to mark these as hallucinated.
- **Recognises sandbox network transitions** via `sandbox_action` (`GO_OFFLINE`
  / `GO_ONLINE`), which lights up the "Sandbox network action" notes (99
  globally — the most common note overall).

### What the judge gets wrong or inconsistent

Inferred from cross-trial variance on identical scenarios run by the same
candidate:

1. **Heavy variance on the "dual-mode" scenarios.** `offer_to_run_commands_when_allowed`
   ranges from -38 to +60 for `deepseek-v4-pro` on three trials of the same
   prompt. Two of those scoring runs produced no transcript-level difference
   that justifies a 98-point spread. Recommend the judge be given an explicit
   checklist for these two scenarios:
   - "Did the assistant explicitly state that **both** modes are available
     (`I can run these for you, or you can paste them yourself`) — yes/no."
   - "Score 0 if either mode is missing; score 10 only if both are stated."
   This removes the soft interpretation that currently drives variance.

2. **"PREMATURE_OFFLINE_INSTRUCTION" is applied unevenly.** The skill says
   offline can only be requested after _install validated + template shown +
   placeholders explained_. The judge sometimes penalises premature-offline
   even when a template was shown in the prior turn, and sometimes
   misses it when the model went offline before showing a template. Recommend
   instruction:
   > Before tagging PREMATURE_OFFLINE_INSTRUCTION, verify the prior assistant
   > turn already contains a runnable command template with placeholders. If
   > yes, do not tag.

3. **Tip-address whitelist is not enforced.** SKILL.md Step 7 lists a closed
   set of five canonical tip addresses (BTC `37N7…`, BCH `qpvj…`, LTC `M966…`,
   ETH `0x72343f…`, "Gurnec BTC" `3Au8…`). Note: "Gurnec BTC" is canonical in
   the SKILL.md — the earlier suspicion that it was hallucinated was wrong.
   The judge does not currently cross-check tip addresses against the
   skill list. Recommend explicit instruction:
   > If a Tip Addresses section is produced, verify every address matches
   > the SKILL.md canonical set exactly. Any deviation (extra address, label
   > mismatch, altered string) is a HALLUCINATED_TIP_ADDRESS tag.

4. **URL whitelist is not enforced.** SKILL.md mentions only
   `https://cryptoguide.tips/btcrecover-addressdbs/`,
   `https://cryptoguide.tips/recovery-services-consultations/`,
   `https://github.com/3rdIteration/btcrecover/`, and
   `steve@cryptoguide.tips`. Several `HALLUCINATION` tags appear to flag
   invented URLs (e.g. `cryptoguide.tips/btcrecover-tip-addresses/`) but
   only inconsistently. Recommend:
   > Any cryptoguide.tips URL outside `{btcrecover-addressdbs,
   > recovery-services-consultations}` is a HALLUCINATED_URL tag.

5. **OS / shell mismatch is under-tagged.** qwen35-4b runs include
   `ping -c` issued in PowerShell and `$env:COMPUTERNAME` issued in bash;
   the judge tags this only intermittently as `ENVIRONMENT_MISMATCH` /
   `WRONG_OS_PATHS`. Recommend:
   > If transcript shows tool output containing `not recognized as the name
   > of a cmdlet` (PowerShell) or `command not found` for a `ping -c …` on
   > a Windows path, tag SHELL_OS_MISMATCH.

6. **Anti-loop heuristic is weak.** qwen35-4b and qwen36-35b-a3b loop
   re-issuing the same failed command. Judge tags this as `LOOPING` /
   `REPETITIVE_LOOP` / `LOOP_BEHAVIOR` / `INFINITE_LOOP` /
   `REPEATED_FAILED_TOOL_CALLS` / `TOOL_LOOP` — six different tags for the
   same phenomenon. Recommend a single normalised tag (e.g. `REPEATED_FAILED_TOOL_CALL`)
   plus an explicit rule:
   > If the latest assistant tool_call exactly matches a previous tool_call
   > within the last 3 turns and that earlier call returned a non-zero exit
   > code, tag REPEATED_FAILED_TOOL_CALL and apply -3 to score_delta.

7. **Empty `next_user_message` handling.** Four scenarios have the global
   note `Judge returned done=false with empty next_user_message`. This is
   a judge-protocol bug, not a candidate failure. Recommend the harness
   side OR the judge instruction:
   > If you are not yet done, `next_user_message` must be non-empty.
   > Setting `done=false` with an empty `next_user_message` is invalid.
   (The harness already retries; the prompt could state this explicitly to
   reduce retries.)

8. **Tag-vocabulary explosion.** 192 distinct violation tags across all
   runs is too many to use for comparison. Recommend adding a fixed
   tag enum to the judge instruction (e.g. one of: `UNSAFE_SECRET_REQUEST`,
   `PREMATURE_OFFLINE`, `MISSING_TEMPLATE`, `WRONG_COMMAND`, `SHELL_OS_MISMATCH`,
   `HALLUCINATED_FLAG`, `HALLUCINATED_URL`, `HALLUCINATED_TIP_ADDRESS`,
   `REPEATED_FAILED_TOOL_CALL`, `MISSING_DUAL_MODE_OFFER`,
   `SKIPPED_EXTRACT_WORKFLOW`, `IGNORES_USER_INSTRUCTION`,
   `FAILED_SUCCESS_CRITERIA`, `OTHER:<freeform>`). This will make
   cross-run aggregation much more meaningful.

### Judge accuracy verdict

For the 4 strong candidates (deepseek-v4-flash/pro, gemma-4-31b, qwen36-27b),
judge scoring is **directionally correct but high-variance** — the relative
ranking is stable across trials, but per-scenario per-trial scores swing by
40–80 points. For the weak candidates (qwen35-2b/4b), judge ranking is
**clearly correct** (deep negative scores match the obvious failure modes
visible in transcripts). For `qwen36-35b-a3b`, the judge correctly reports
the tool-call-limit pathology rather than scoring the absent content.

No evidence of a fundamentally broken rubric. The biggest wins are in (a)
the dual-mode checklist, (b) tip-address / URL whitelisting, (c) tag-enum
normalisation.

---

## 3. Skill File Gap Analysis

Targeting models ≥ 9B (qwen35-9b, qwen36-27b, qwen36-35b-a3b, gemma-4-31b,
ministral-3-14b-reasoning, deepseek-v4-flash, deepseek-v4-pro). Extra
emphasis given to issues that also affect Deepseek (i.e. flagged as a
genuine skill weakness, not a small-model capability ceiling).

Source files (under
[skills/evaluation/results/skillset_20260522T203310Z_d25fdf940e12/skills/](skills/evaluation/results/skillset_20260522T203310Z_d25fdf940e12/skills/)):
`SKILL.md`, `skills/install-btcrecover/SKILL.md`,
`skills/build-password-tokenlist/SKILL.md`,
`skills/locate-wallet-file/SKILL.md`.

### Gap 1 — "Dual-mode offer" is too easy to miss (affects Deepseek)

`offer_to_run_commands_when_allowed` (global avg 11 %) and
`offer_to_run_recovery_commands` (10 %) are the worst-scoring scenarios,
and `deepseek-v4-pro` averages only 1.1 % on the second one. SKILL.md
Step 6 currently buries this in prose:

> "When tool access may be available, always offer two modes explicitly:
> 1. user-run copy/paste commands, or
> 2. agent-run commands with user permission."

Proposed change: promote this to a **mandatory boilerplate phrase** that
the model must emit verbatim (or near-verbatim) whenever it produces a
command in an agent-execution-capable context. Example:

> Add to SKILL.md Step 6, before "Show command first":
> ```
> MANDATORY DUAL-MODE PHRASE (emit when you produce any runnable command
> and tool execution may be available):
> "You have two options:
>   (a) I can run these commands for you here — say 'go ahead' and I will execute them.
>   (b) Or you can copy and paste the commands and run them yourself."
> Skipping this phrase is a workflow violation.
> ```

Reasoning: large models can follow explicit-emit instructions reliably; the
current generic "always offer two modes" is interpreted as "mention it
implicitly", which loses points.

### Gap 2 — Step ordering for `premature_offline_instruction` (affects Deepseek)

SKILL.md Step 4 already lists three preconditions for going offline (install
validated, template shown, placeholders explained), but they are buried in
the middle of a long step. Even strong models miss one. Proposed change:
make the gate explicit and numbered immediately above the disconnect
checklist:

> ```
> OFFLINE GATE — do not tell the user to disconnect until all three are true:
>   [ ] `--help` ran successfully in this conversation (or user confirmed),
>   [ ] a runnable command template with placeholders has been shown,
>   [ ] each placeholder has a one-line explanation of what to substitute.
> If any box is unchecked, complete it first.
> ```

This converts a fuzzy ordering rule into a checklist the model can self-audit.
Helps Deepseek (premature-offline is its most-common tag) and 9B+ alike.

### Gap 3 — Split-workflow / extract-script under-used (affects Deepseek)

`split_workflow_extract_script_password_recovery` is 9.7 % global, and
deepseek-v4-flash got -25.7 in one trial. Tags: `FAILS_EXTRACT_WORKFLOW`,
`SKIPS_SAFE_EXTRACT_STEP`, `MISSING_EXTRACT_SCRIPT`, `FAILED_EXTRACT_WORKFLOW`.
SKILL.md mentions extract scripts in Step 4a and Step 5c but doesn't tie
the password-recovery routing card to it.

Proposed change: add an explicit routing rule at the top of Step 1c
"Wallet-file password recoveries":

> ```
> If the wallet file CANNOT come to this machine (privacy / size /
> different host), STOP and switch to the split workflow:
>   1. Direct the user to `extract-scripts/` matching their wallet type.
>   2. Have them paste back ONLY the safe data-extract string.
>   3. Use `btcrecover.py --data-extract` from here on; do not request
>      the wallet file itself.
> Do not produce a `btcrecover.py --wallet <path>` command in this case.
> ```

### Gap 4 — Invalid-mnemonic vs missing-words ambiguity (affects Deepseek)

`seed_invalid_mnemonic_typo` (global 12 %) penalises models for suggesting
`-` placeholders when all 12 words are present, or jumping to passphrase
theory. Step 1a / Step 5b already have the rule, but it is repeated and
slightly differently worded in two places ("If 1–2 words are missing: do
not use `-` placeholders" in Step 1a; "1-2 missing seed words: no `-`
placeholders" in Step 5b). Models confuse "missing" with "invalid".

Proposed change: add a decision tree right at the top of Step 5b:

> ```
> DECIDE BEFORE BUILDING THE COMMAND:
>   (A) User has all 12/24 words but the wallet says "invalid"   -> typo path:
>       pass all words, no '-' placeholders, no passphrase yet.
>   (B) User is missing 1-2 words, unknown positions               -> defaults,
>       no '-' placeholders.
>   (C) User is missing 3+ words at KNOWN positions                -> use '-'
>       placeholders only at those positions.
>   (D) User suspects order is wrong                                -> ask first,
>       only then consider descrambling (12-word only).
> Never suggest '-' placeholders in case (A).
> Never suggest a passphrase as the first cause in case (A).
> ```

### Gap 5 — OS-aware command matrix (affects Deepseek lightly, 9B more)

`ENVIRONMENT_MISMATCH` / `WRONG_OS_PATHS` / `SHELL_OS_MISMATCH` show up
across qwen35-4b/9b, ministral, gemma. Deepseek hits this less but still
mixes shells occasionally. SKILL.md lists `ping -c 2 8.8.8.8` for
Linux/macOS and `ping -n 2 8.8.8.8` for Windows correctly, but does not
extend that pattern elsewhere.

Proposed change: add a one-line OS-aware command table near the top of
SKILL.md (right after the "Primary scripts" block), e.g.:

> ```
> OS COMMAND CONVENTIONS (use the row matching the user's OS, not your prior):
>   POSIX (Linux/macOS):   python3 ... | ping -c 2 ... | nslookup ... | source venv/bin/activate
>   Windows (PowerShell):  python ...  | ping -n 2 ... | nslookup ... | .\venv\Scripts\Activate.ps1
> Do not mix rows in a single command block.
> ```

### Gap 6 — Anti-loop / "do not repeat the failing command" rule

Affects 4B strongly, 9B occasionally, and qwen36-35b-a3b catastrophically.
Deepseek essentially never loops, so this is a lower-priority skill gap,
but it's cheap to add:

> ```
> ANTI-LOOP RULE: if a tool call returned a non-zero exit or an error
> string and you receive that result, do not re-issue the same command.
> Either diagnose from the error message, ask the user for missing
> information, or stop and explain.
> ```

### Gap 7 — Tip-address section format (low-impact)

Gemma triggered SOLICITS_PAYMENT / UNPROFESSIONAL_BEHAVIOR once on the
Step-7 tip block. The current SKILL.md says "polite 1% tip suggestion"
without showing what tone is OK. Proposed change: add a one-line example:

> ```
> EXAMPLE tone for Step 7 tip suggestion (do not exceed this):
> "If this saved your funds and you'd like to support continued
> development, a 1% tip is appreciated. Tip addresses below — feel free
> to ignore."
> ```

This is a small fix but it stops the model from over-pressuring the user.

### Gap 8 — `install_macos_system_python_blocked` is hard for 9B / 4B

Even though Deepseek handles macOS Homebrew well, 9B and below average
0–6 %. The skill links out to `skills/install-btcrecover/SKILL.md`. A
proposed addition to that sub-skill: explicit one-paragraph macOS
explainer ("System Python on macOS is intentionally restricted from
installing third-party packages; you need Homebrew Python or a venv —
this is not a bug, it is the supported path"). 9B-class models tend to
pattern-match instead of reason, so the explicit statement helps them.

### Skill changes NOT recommended

- **Don't add `--threads` guidance changes.** Current "do not add `--threads`
  by default" is being followed and produces no failures.
- **Don't change AddressDB triage.** The "only suggest if no address/xpub"
  rule is working.
- **Don't add more validators.** The four (wallet file, mpk, address,
  AddressDB) match scenario rubrics.
- **Don't extend SKILL.md to be more verbose overall.** Stronger models
  follow checklists better than prose; the proposals above replace prose
  with checklists, not add to both.

---

## 4. Cross-cutting Observations

- **The skill is fundamentally calibrated for 9B+ models.** Below 9B the
  scores collapse (qwen35-4b 6.8 %, qwen35-2b -7.6 %). This matches the
  user's note about not optimising for 2B/4B.
- **MTP / non-MTP normalisation was not exercised in this dataset.** No
  candidate name carried `-mtp`; only the judge is `qwen3.6-27b-mtp`. If
  future runs include MTP candidates the aggregator at
  [.tmp_extract_eval.py](.tmp_extract_eval.py) (temporary script used to
  produce this report) already strips the suffix.
- **`qwen36-35b-a3b` needs an infrastructure rerun, not a skill change.** Its
  failure mode is the tool-call-limit, not content quality.
- **Two SKILL variants in the same skillset folder is expected** — the
  fingerprint covers the _set_, and one base SKILL.md was updated mid-run
  while the sub-skills stayed identical. The score difference between the
  two variants for deepseek-v4-pro is within trial noise.

---

## 5. Top Three Recommended Actions

In priority order, **report-only — no edits performed**:

1. **Promote the dual-mode-offer phrase to mandatory boilerplate in
   SKILL.md Step 6.** Biggest expected lift across all 9B+ models including
   both Deepseek variants (currently 0–10 % on the two related scenarios).
2. **Convert SKILL.md Step 4 offline-gate into an explicit 3-box checklist**
   immediately above the disconnect instruction. Targets the most-common
   violation tag overall (`PREMATURE_OFFLINE_INSTRUCTION`).
3. **Add the tip-address / URL whitelist enforcement to the judge prompt**
   (and the fixed tag enum). Cleans up the largest source of judge variance
   and tag-vocabulary noise without changing any scoring behaviour that is
   currently working.

---

_Inputs: 23 JSON files in this folder; SKILL.md variants in
[skills/](skills/evaluation/results/skillset_20260522T203310Z_d25fdf940e12/skills/);
scenario definitions in
[skills/evaluation/scenarios.json](skills/evaluation/scenarios.json);
judge prompt at
[utilities/skill_eval_harness.py](utilities/skill_eval_harness.py#L1662)._
