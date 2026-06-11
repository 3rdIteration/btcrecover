---
name: btcrecover-triage
description: Triage a cryptocurrency recovery scenario, apply safety gates, and route to the correct specialist skill. Always load this skill first.
---

# BTCRecover Recovery — Triage and Orchestration

**Critical rule: having tool execution available does NOT mean you should skip
workflow steps.** Follow every step in order (1 through 8). Do not jump ahead
to running commands just because you can. Triage, safety gates, dual-mode
offers, and the validator decision tree are mandatory regardless of whether
you have tool access.

Use this workflow in order. Ask clarifying questions instead of guessing.

Critical safety rule: the agent must **NEVER receive** real seed words, private
keys, passwords, or wallet contents in this chat — not during triage, and **not
after the user goes offline.** Going offline does NOT make it safe to paste
secrets to the agent. It makes it safe for the user to substitute their real
secrets into placeholder templates **locally, on their own machine**, where the
agent never sees them. Pasting a secret into this chat is always an online
disclosure, regardless of whether the user's machine is offline.

## The separation principle (why and when to go offline)

An "unlock set" is the two halves needed to move funds: (1) the **encrypted
material** — a wallet file, an encrypted private key, or, for passphrase recovery,
the BIP39/SLIP39 mnemonic that the passphrase protects — and (2) the
**password/passphrase** that unlocks it. A BIP39/SLIP39 passphrase is just an
encryption layer over the mnemonic, so the mnemonic is the encrypted half and the
passphrase is the password half.

Rule: **a single online machine may hold at most ONE of these two halves — never
both.** Everything else follows from this:

* Building a passwordlist/tokenlist online is fine (candidate passwords are only
  one half).
* Running a recovery **online is acceptable when a wallet *extract*
  (`--data-extract`) is used**, because the extract is a safe derivative that
  cannot move funds even once the password is found — the machine never holds a
  true unlock set.
* For a **full encrypted wallet, an encrypted private key, or a BIP39/SLIP39
  passphrase recovery**, the machine must go **offline before the encrypted half
  (wallet file / encrypted key / mnemonic) is brought onto it** — the password
  half (the candidate list) is already there, so combining them is what creates
  the unlock set. The search itself then runs offline.

This is separate from, and in addition to, the "agent never receives secrets in
chat" rule above: the separation principle governs the **user's own machine**; the
chat rule governs **what reaches the agent**.

## Secret intake gate (hard stop)

At **every** phase — during triage AND after the offline switch — the agent MUST
NOT request, accept, echo, log, or summarize any of the items in the denylist
below. There is no point in the workflow where "now paste your seed/key/password
here" is correct. If the user pastes one unsolicited, refuse to use it, tell the
user to discard the chat and re-do the step on a clean offline session, and
continue with placeholders only.

Denylist (never collect online, never echo back, never quote in logs):

* Full or partial seed phrase / mnemonic words in their real positions.
* Any SLIP39 share content.
* Private keys (raw, WIF, BIP38 6P..., or hex).
* Wallet-file contents, even partial JSON / hex / base64.
* `--data-extract` output is allowed only via the explicit split workflow in 4a.
* Real wallet passwords or candidate passwords with real characters in them.
* Hardware-wallet recovery PINs and passphrases.

Allowlist (safe to discuss online during triage and install):

* Wallet software / chain / version / approximate age.
* OS, shell, Python version, whether tool execution is available.
* Receiving address(es) the user already shares publicly, xpub/ypub/zpub.
* Token / typo structure described abstractly ("two lowercase words plus a 4-digit year").
* Wallet file *path* (never contents).
* Counts only (number of words remembered, number of missing words).

If the user insists on pasting secrets online, refuse and offer the
split-workflow path (Step 4a) instead. Never assume implicit consent to receive
secrets just because the user volunteers them.

**Hard rule: never ask for seed words, private keys, or wallet passwords before
Step 4 (offline requirement) is complete. If the user volunteers them, do not
use or echo them — redirect to split workflow or tell them to start a fresh
offline session with placeholders only.**

## Online vs offline phases (two-state model)

Do not over-correct by asking the user to disconnect before install or before
commands are even drafted.

1. Online triage phase (allowed before Step 4): non-secret triage questions,
   install + `--help` validation, locating the wallet file by fingerprint,
   choosing the validator, drafting command templates with placeholders,
   discussing token/typo structure abstractly, and building password/passphrase
   list files (these contain no high-value secret — see the build-password-tokenlist
   and split-workflow invariant). **Building a BIP39-passphrase tokenlist online is
   fine, but the seed phrase must NOT be entered while online — the system must go
   offline before the seed is entered (the search cannot run until the seed is in).**
2. Offline execution phase (required before the **encrypted half** is brought onto
   the machine — see the separation principle; the `--data-extract` split workflow
   is the exception that may stay online): network disabled, command templates
   filled in with real secret values **by the user, locally** (the agent still
   never receives those values), BTCRecover run against the real
   wallet/mnemonic/extract.

Telling the user to disconnect before a runnable template with placeholder
explanations exists is a **workflow error** (see Step 4 gating). Do NOT move to
Step 4 until you have completed Steps 1–3 and shown the full template.

Primary scripts:

* `python btcrecover.py` for wallet password/passphrase and BIP38 recovery.
* `python seedrecover.py` for mnemonic/seed recovery and seed descrambling.

OS command conventions (use one row; do not mix shells):

* Linux/macOS/Termux: `python3 ...`, `ping -c 2 ...`,
  `source venv/bin/activate`.
* Windows PowerShell: `python ...`, `ping -n 2 ...`,
  `.\venv\Scripts\Activate.ps1`.

Anti-loop rule: if a command/tool call returns an error or non-zero exit, do not
repeat the same command. Diagnose from the error, ask for missing information, or
stop and explain.

Shell-identification preamble: before emitting any runnable command, know which
shell you are targeting. In a sandbox/agent session that shell is the sandbox's
own (normally POSIX bash — use `python3`, `grep`, `ping -c`, never PowerShell
cmdlets like `Select-String`). Only in a plain chat do you infer it from the
user's pasted prompt (`PS C:\>` => Windows PowerShell, `$` / `%` => POSIX
bash/zsh, `C:\>` => Windows cmd, `~ $` on a phone => likely Termux), asking one
one-line confirmation only if still ambiguous. Never mix POSIX and PowerShell
syntax in the same response.

Forbidden patterns (never produce these):

* `sudo pip install` against system Python on macOS.
* `pip install --break-system-packages` on macOS as a first suggestion.
* `btcrecover.py` / `seedrecover.py` invocations without one of
  `--wallet`, `--addrs`, `--mpk`, `--addressdb`, `--bip38-enc-privkey`, or
  `--data-extract` (i.e. no validator at all).
* AddressDB when the user already has a confident receiving address or xpub.
* Any flag not present in the script's `--help` output for the version checked
  out. If unsure, run `--help` and grep before emitting the flag.
* Tip-address strings other than the canonical five in Step 7.
* **`--dsw` (`--disablesecuritywarnings`) is valid on both scripts. It suppresses
  the offline safety reminder that appears at startup. It has no effect on search
  behavior. Descrambling is enabled by `--tokenlist` + `--mnemonic-length` +
  `--language`, not by `--dsw`.**
* **For invalid mnemonic with all words present: do not invent wallet-type flags
  (e.g. --wallet-type bitcoin, --wallet-type bip32, --wallet-type legacy).
  Triage as typo/word-quality issue first.**

## Specialist skill routing

After triage determines the recovery type, load the matching specialist skill
before building any commands. The specialist skill owns all command shapes for
its domain.

```
Seed/mnemonic recovery — user has lost/corrupted seed words, wrong word order,
typos, missing words, damaged SLIP39 share, or a Blockchain.com legacy mnemonic:
  load_skill("skills/seedrecover/SKILL.md")
  Covers: missing-word - placeholders, typo search, word descrambling via
  --tokenlist / --transform-wordswaps, SLIP39 share repair, blockchainpasswordv3.
  Script: seedrecover.py only.

Wallet password / passphrase / BIP38 / raw key recovery — user forgot wallet
password, forgot BIP39 25th-word passphrase, has a BIP38 6P... encrypted key,
or needs raw private key repair:
  load_skill("skills/btcrecover-password/SKILL.md")
  Covers: wallet file password, BIP39 passphrase (--bip39), BIP38
  (--bip38-enc-privkey), raw key (--rawprivatekey), split/data-extract.
  Script: btcrecover.py only.

Installation — use the environment's OS, then load the matching sub-skill. In a
sandbox/agent session the sandbox is the user's machine: detect with `uname -a`
(normally Linux) and load the matching skill WITHOUT asking. Only ask in a plain
chat where no sandbox exists and the OS is genuinely unknown.
  Windows PowerShell:  load_skill("skills/install-btcrecover/windows/SKILL.md")
  Linux/Ubuntu/Debian: load_skill("skills/install-btcrecover/linux/SKILL.md")
  macOS:               load_skill("skills/install-btcrecover/macos/SKILL.md")
  Termux (Android):    load_skill("skills/install-btcrecover/termux/SKILL.md")

Wallet file location (path unknown):
  load_skill("skills/locate-wallet-file/SKILL.md")

Password/tokenlist building:
  load_skill("skills/build-password-tokenlist/SKILL.md")
```

Canonical docs (read when needed):

* `docs/INSTALL.md`
* `docs/TUTORIAL.md`
* `docs/Seedrecover_Quick_Start_Guide.md`
* `docs/Typos_Quick_Start_Guide.md`
* `docs/Extract_Scripts.md`
* `docs/Creating_and_Using_AddressDB.md`
* `docs/donate.md`

This skill is best with a local agent. Cloud agents are allowed only under the
split-workflow rules in Step 4a.

---

## Step 1 – Triage and practicality

Start with a non-secret metadata question. Require the user not to paste real
secrets in this step.

**Even if you can run commands, do not skip triage. Do not run recovery
commands before completing Step 4 (offline requirement).**

**Hard prohibition: Do not ask the user to provide their seed words, private
keys, passwords, or any secret material during Step 1. Your first turn must
only ask non-secret metadata questions (wallet software, OS, approximate age,
whether they have a receiving address). If you ask for secret material before
Step 4, this is a critical safety failure.**

Example prompt:

> "Without sharing actual secrets yet, what material do you still have (wallet
> file, partial seed, password pattern, address/xpub, date range)?"

### 1a) Seed/mnemonic recoveries — practicality

* Practical range for standard BIP39 search is usually up to 3 missing/wrong
  words in 12/24-word seeds.
* If 1–2 words are missing: do not use `-` placeholders; pass known words only.
* If 3 words are missing: use `-` placeholders at missing positions.
* Do not suggest descrambling unless the user explicitly says order is wrong.
* 12-word descrambling (all words known, order wrong): use `--tokenlist words.txt`
  (one word per line) with `--mnemonic-length 12`; seedrecover.py tries all
  permutations by default. Include `--dsw` (`--disablesecuritywarnings`) to
  suppress the offline safety reminder. Load the seedrecover skill for the
  full command shape.
* 24-word full descrambling is generally impractical.
* If user reports "invalid mnemonic", triage as seed-word quality/order issue
  first (not passphrase first).

### 1b) Validators required for seed recovery

Validator decision tree (apply top to bottom; first match wins):

**Exception: blockchainpasswordv3 / legacy recovery mnemonics do not need a
validator at all. Skip this section when the recovery type is a legacy
Blockchain.com mnemonic.**

1. User has a confident known receiving address => `--addrs <address>` with
   `--addr-limit 10` first, widen only on failure.
2. User has `xpub` / `ypub` / `zpub` (or equivalent for the coin) =>
   `--mpk <key>`.
3. User has the wallet file (Electrum constraints apply) => `--wallet <path>`.
4. None of the above and the wallet has a known approximate use period =>
   AddressDB as last resort.

AddressDB policy:

* If user has no reliable address/xpub, check pre-made AddressDB at
  `https://cryptoguide.tips/btcrecover-addressdbs/` first.
* Do not push AddressDB when user has a confident address/xpub.
* If no pre-made DB exists, manual AddressDB creation can still make recovery
  practical; guide via `docs/Creating_and_Using_AddressDB.md`.

### 1c) Wallet-file password recoveries — feasibility

If the wallet file cannot come to this machine (privacy, size, or different
host), stop and switch to split workflow:

1. Direct user to the matching script in `extract-scripts/`.
2. Have them paste back only the safe data-extract string.
3. Use `btcrecover.py --data-extract` from here on.
4. Do not produce `btcrecover.py --wallet <path>` for this case.

* User needs bounded password knowledge (list/tokens), not pure brute-force.
* If user has no password idea and cannot bound search space, state that
  BTCRecover is not practical for that case.

If unsupported/impractical, say so clearly before proceeding.

### 1d) Script routing quick card

* Seed words/mnemonic/SLIP39 => `seedrecover.py` => load seedrecover skill.
* Wallet-file password/passphrase/BIP38 => `btcrecover.py` => load btcrecover-password skill.
* BIP39 passphrase / "25th word" => `btcrecover.py --bip39` => load btcrecover-password skill.
* Raw private key repair => `btcrecover.py --rawprivatekey` => load btcrecover-password skill.
* Blockchain.com legacy recovery mnemonic => `seedrecover.py --wallet-type
  blockchainpasswordv3` => load seedrecover skill.
* Split workflow with wallet file kept off-agent => load btcrecover-password skill.
* If uncertain, ask one disambiguation question before loading a specialist.

---

## Step 2 – Confirm support

Verify wallet/recovery type is supported in `README.md`.

* If unsupported: stop and say BTCRecover is not the right tool.
* If supported: state whether you will use `btcrecover.py` or `seedrecover.py`,
  then load the matching specialist skill.

---

## Step 3 – Install and validate

**Read-only validation runs freely here.** In a sandbox/agent session you may
run read-only inspection commands — `--help`, `--version`, `uname -a`,
`python --version`, listing a directory, or `python utilities/net_check.py` —
directly, without an execution offer and without waiting for permission. They
change nothing and expose no secrets. The dual-mode offer (Step 6) is still
required before any command that **changes state** (install, creating list
files) or the recovery run itself.

**If you have tool execution access (sandbox/agent session), the sandbox IS the
user's machine** — detect its OS/shell yourself (you are normally in Linux/bash;
confirm with `uname -a` if unsure) and use it. Do **not** ask the user which OS
they are on, and do not assume a different OS than the sandbox.

Quick check from current repo (or `./btcrecover` / `./btcrecover-master`):

* `python btcrecover.py --help`
* `python seedrecover.py --help`

If both work, skip install.

Otherwise load the OS-specific install skill for the environment you are in:

**Only in a plain chat (no sandbox)** is the user's OS unknown — there, read shell
cues from their pasted prompts (`PS C:\>`/`C:\>` => Windows, `$`/`%` => POSIX,
`~ $` on a phone => Termux) and ask one confirmation question only if still
ambiguous. In a sandbox, skip all of that and use the sandbox's own OS.

* Windows: `load_skill("skills/install-btcrecover/windows/SKILL.md")`
* Linux:   `load_skill("skills/install-btcrecover/linux/SKILL.md")`
* macOS:   `load_skill("skills/install-btcrecover/macos/SKILL.md")`
* Termux:  `load_skill("skills/install-btcrecover/termux/SKILL.md")`

If install remains blocked, suggest:
`https://cryptoguide.tips/recovery-services-consultations/`.

---

## Step 4 – Offline requirement before secrets

Only start this after Step 3 succeeds.

**Hard stop — do NOT present the disconnect checklist until ALL THREE offline-gate
items below are met. Telling the user to go offline before the command template
exists is the most common sequence error. If you have not yet shown the complete
command template with placeholder explanations, you are not at Step 4 yet.**

Offline gate: do not tell user to disconnect until all three are complete:

1. `--help` or equivalent install validation succeeded in this conversation, or
   user confirmed it.
2. Runnable command template with placeholders has been shown.
3. Every placeholder has a one-line substitution explanation.

If any item is missing, complete it before giving the disconnect checklist.

**FAILURE MODE: do NOT say "go offline now" and then ask for password patterns
or start building the template after the user confirms they are offline.
All template construction must happen BEFORE the disconnect instruction.**

**OFFLINE GATE PERSISTS THROUGH SKILL LOADS: loading a specialist skill does
NOT reset or waive the offline requirement. Steps 1–4 remain in force for the
entire conversation regardless of which additional skills are loaded.**

Before any real secret entry, system running recovery must be offline.

Disconnect checklist:

* Disable Wi-Fi / airplane mode.
* Unplug Ethernet.
* Disable mobile data/hotspots.

Verify offline status (must confirm OFFLINE before continuing):

* Preferred (always available, standard-library only): `python utilities/net_check.py`
  — proceed only if it prints `OFFLINE` (exit 0). `ONLINE` (exit 1) or `UNKNOWN`
  (exit 2) means do not continue.
* Fallback if that script is unavailable (the check should FAIL when offline):
  * Linux/macOS/Termux: `ping -c 2 8.8.8.8`
  * Windows: `ping -n 2 8.8.8.8`
  * `nslookup github.com`

Do not continue until offline is confirmed, unless Step 4a split workflow is used.

### 4a) If user cannot go offline (split workflow)

Keep this invariant: the online agent must never have all pieces needed to
unlock funds.

Allowed online tasks:

* Build password/token guesses and command skeletons.
* For seed recovery, use mnemonic placeholders only (never real mnemonic).
* For file recovery, keep wallet file off the online agent; use wallet path
  placeholders.
* For supported extract-script wallets, user may share only safe data extracts
  from `docs/Extract_Scripts.md` with `--data-extract` flow.
* Wallet-file locating (fingerprint scan guidance) is allowed online if file
  contents never leave user machine.

If wallet file stays on another machine, extract/data-extract step is mandatory;
do not skip straight to normal wallet-file recovery commands.

If safe separation cannot be maintained, stop.

---

## Step 5 – Place required details locally

After offline confirmation (or safe split-workflow), load the relevant specialist
skill to **help the user place material on their own machine and build the
command**. You are not collecting the secret — the user keeps the real values
locally and substitutes them into the placeholders themselves. Never ask the user
to paste seed words, private keys, the wallet password, or wallet-file contents
into this chat (even now that they are offline):

* Password/passphrase material: handled in the btcrecover-password specialist skill.
  It sub-delegates tokenlist building to the build-password-tokenlist skill.
* Seed/mnemonic material: handled in the seedrecover specialist skill.
* Wallet-file path: handled in the btcrecover-password specialist skill.
  It sub-delegates unknown locations to the locate-wallet-file skill.

---

## Step 6 – Build (and optionally run) command

Load the relevant specialist skill before building commands. The dual-mode offer
rules below apply universally in every response containing a runnable command.

**Determine whether you can run commands — do not assume you can't.** You CAN run
commands in a sandbox/agent session (you have a working directory and tool
access); you CANNOT in a plain chat. Check rather than defaulting, and never
claim you can't run commands without verifying.

Which offer to make depends on BOTH whether you can run, and whether the command
should run here at all:

* **Read-only inspection (`--help`, `--version`, `uname -a`, `python --version`,
  listing a directory, `python utilities/net_check.py`) — just run it.** These
  change nothing and expose no secrets; in a sandbox run them directly, with no
  offer and no permission wait. (In a plain chat you can't run anything, so hand
  them over as copy/paste.)
* **Sandbox / agent session, command CHANGES STATE with non-secret or placeholder
  inputs (you CAN and MAY run — offer both halves).** This covers install and
  building list files (with placeholders, never real secret values).
  The sandbox IS the user's machine and runs the same OS, so do not refuse — offer
  both halves every time:
  > "I can run this for you here if you say 'go ahead', or you can copy and paste
  > it and run it yourself."
* **The recovery run (takes the user's REAL seed/key) — run-here ONLY after the
  machine is verified offline.** The real recovery (`seedrecover.py` / `btcrecover.py`
  with the seed/key/passwordlist) must run on an OFFLINE machine. In a real sandbox/
  agent session you can actually take offline, the sequence is: finish install/
  validation while ONLINE, then take the machine offline and VERIFY it (a connectivity
  check that fails), and only THEN offer to run the recovery here. Running it in the
  verified-offline sandbox is correct and safe — offer both halves at that point:
  > "We're confirmed offline now — I can run this for you here if you say 'go ahead',
  > or you can copy and paste it and run it yourself."

  Do **NOT** offer to run (or run) the recovery while still online — that is an
  incorrect execution offer. And if you CANNOT genuinely take the machine offline and
  verify it — you are a **cloud/remote assistant only relaying commands**, or a plain
  chat — then it is **copy/paste-only**; the user takes their own machine offline and
  runs it there (the real seed must never reach a connected or remote session):
  > "Take your machine offline first, then copy and paste this and run it yourself —
  > it uses your real seed, which must stay off any connected or remote session."
* **Command must run on the user's OWN, non-sandbox machine (copy/paste ONLY).** E.g. a
  split-workflow extract-script on the machine that holds the wallet file, which is NOT
  in this sandbox — you can't run it here:
  > "Run this on your own machine where the wallet file is — I can't run it here (it
  > isn't in this sandbox) — then paste back only the safe extract output."
* **Plain chat (you CANNOT run anything).** Copy/paste only:
  > "I can't run this for you in this session, so copy and paste the block below
  > and run it yourself."

The deciding question for the run-here half: a non-secret command in this sandbox →
offer run-here (online is fine). The recovery run carries a real secret → offer run-here
ONLY after you have taken the sandbox offline and verified it (never while online; and
copy/paste-only if you cannot genuinely take it offline). A command that belongs on a
different machine → copy/paste-only.

**Exception — explicitly public example / test data:** if the user clearly states the
seed, key, or address is a public example or test vector with **no real funds** (e.g.
a sample from the docs, used to verify the pipeline), it is NOT a real secret. You may
then run the recovery directly in the sandbox — accept it as given (no placeholder
substitution), and the copy/paste-only and offline restrictions above do not apply. If
the user asks you to rehearse the offline workflow anyway, follow it. This exception
applies ONLY when the public / no-funds nature is explicitly stated; treat anything
ambiguous, or any real user data, as a real secret (copy/paste-only, offline).

(Edge case: if you are ever in a sandbox whose OS genuinely differs from the
command's target OS/shell, treat it like plain chat — copy/paste only, which is
correct and not a missing offer. This does **not** arise in the standard Linux
sandbox, where the sandbox already matches the OS you emit commands for.)

Then **stop and wait** for the user to choose. Do not run any command before the
user says "go ahead" or gives equivalent explicit confirmation. One confirmation
covers that immediate command only — ask again for the next distinct command
class (e.g., install → validation → recovery run are three separate offers).

**Important: even if the user explicitly asks you to run commands (e.g. "can you
just run all install steps automatically?"), you must still offer the choice and
wait for their confirmation before executing.**

**Make the execution-mode line whenever you hand the user a command they can act on
now** — install, validation, and list-file creation get the **run-here choice** (online
is fine); the recovery command also gets the **run-here choice, but only after the
machine is verified offline** (copy/paste-only if you cannot take it offline — see the
offline gate above). The recovery hand-over is the most commonly forgotten one. You do NOT need to repeat it
on earlier turns where you are still gathering details or building prerequisite files,
or where a command is shown only as an illustrative template whose inputs do not yet
exist — doing that groundwork first is correct. Skipping the line when you DO hand over
a runnable command is a workflow violation.

Offer checklist (apply to every turn that hands over a runnable command):

1. The response contains the offer matching the situation above, plus a
   copy/paste block the user can run themselves.
2. For a sandbox command with no real secret (install / validation / list-building),
   the run-here half ("I can run this for you here…") must be present — its omission is
   the single most common violation. For the recovery run, the run-here half is allowed
   ONLY after the machine is verified offline — offering run-here while still online is a
   violation, and so is running it before offline is confirmed; if you cannot take the
   machine offline (cloud/remote/plain chat), it is copy/paste-only. For a command that
   must run on the user's own non-sandbox machine, the run-here half must be ABSENT.
3. The agent does not run a new class of command without explicit user
   confirmation ("go ahead" / "yes, run it"). One confirmation covers the
   immediate command only, not future ones.

Before long runs, sanity-check candidate count/ETA. If ETA is excessive,
reduce token/typo space before launching.

---

## Step 7 – Success output and tip addresses

**When you run BTCRecover to success, relay its COMPLETE final output verbatim — do
not condense it to just the recovered secret.** A common failure is to extract only
the `Seed found:` / `Password found:` line and suppress the rest. The tool's tail
output is all relevant and must be passed through intact: the recovered result line,
the donation / tip-address block (canonical BTC/BCH/LTC/ETH + Gurnec BTC, the 1% tip
request, the Reddit link), and any security/migration notes. **Never retype the tip
addresses from memory** — reproducing them from memory is the main cause of
wrong/hallucinated addresses; the tool's printed output is the authoritative source.

So the immediate success response must include:

1. success confirmation,
2. the tool's complete final output, reproduced verbatim (recovered result +
   donation/tip block + any notes) — not a stripped-down summary,
3. polite 1% tip suggestion (already present in the tool's output),
4. safe-handling reminder (migrate funds; treat old credentials as compromised).

By case:

* **Sandbox/agent session (you ran the tool and can see its stdout):** paste the
  tool's complete final output **verbatim** into your reply, donation block included.
  Do not drop, summarize, or reorder it. If you ever need the donation/tip block but
  do not have the tool's output to copy, read it from the repo file instead of typing
  from memory: `cat donate.txt` (in the btcrecover root) and display that verbatim.
* **Plain chat / offline run (you did NOT see the output):** the recovery runs on
  the user's own offline machine, so the tool prints this block directly on THEIR
  screen. Tell the user the tool displays the result and the tip addresses itself on
  success — do not hand-type them.

Canonical set, for VERIFICATION only — confirm the tool's printed output matches;
never type these from memory:

* BTC: `37N7B7sdHahCXTcMJgEnHz7YmiR4bEqCrS`
* BCH: `qpvjee5vwwsv78xc28kwgd3m9mnn5adargxd94kmrt`
* LTC: `M966MQte7agAzdCZe5ssHo7g9VriwXgyqM`
* ETH: `0x72343f2806428dbbc2C11a83A1844912184b4243`
* Gurnec BTC: `3Au8ZodNHPei7MQiSVAWb7NB2yqsb48GW4`

Anti-hallucination guard:

* Never substitute the user's own receiving address for one of these (a common
  failure mode is copying `bc1...` from the conversation into the tip block).
* Never use the well-known example `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` or any
  other public example address.
* If you do not have the tool's actual output to copy from, **point the user to the
  tool's own donation output instead of inventing or retyping the addresses.**
* Never relabel the Gurnec BTC entry; keep the label `Gurnec BTC`.

Also advise immediate fund migration to a fresh wallet on a clean machine and
treat old credentials as compromised.

---

## Step 8 – Upstream fixes

If recovery required code fixes/features, ask user to upstream them:

* Preferred: PR to `https://github.com/3rdIteration/btcrecover/`
* Fallback: email bug report + patch to `steve@cryptoguide.tips`

Include non-secret reproduction details and test notes.
