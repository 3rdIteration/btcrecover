---
name: btcrecover-recovery
description: Help a user safely attempt cryptocurrency wallet recovery with BTCRecover (btcrecover.py for password/passphrase/BIP38 and seedrecover.py for seed/mnemonic/SLIP39). Use for triage, practicality checks, install handoff, offline safety, data collection, command construction, and post-success guidance.
---

# BTCRecover Assisted Recovery Skill

Use this workflow in order. Ask clarifying questions instead of guessing.

Critical safety rule: never ask for real seed words, private keys, passwords, or
wallet contents until Step 4 (offline checks) is complete.

Primary scripts:

* `python btcrecover.py` for wallet password/passphrase and BIP38 recovery.
* `python seedrecover.py` for mnemonic/seed recovery and seed descrambling.

Script routing quick card:

* Seed words/mnemonic/SLIP39 => `seedrecover.py`.
* Wallet-file password/passphrase/BIP38 => `btcrecover.py`.
* Split workflow with wallet file kept off-agent => extract script +
  `btcrecover.py --data-extract`.
* If uncertain, ask one disambiguation question before building commands.

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

Example prompt:

> "Without sharing actual secrets yet, what material do you still have (wallet
> file, partial seed, password pattern, address/xpub, date range)?"

### 1a) Seed/mnemonic recoveries

* Practical range for standard BIP39 search is usually up to 3 missing/wrong
  words in 12/24-word seeds.
* If 1–2 words are missing: do not use `-` placeholders; pass known words only.
* If 3 words are missing: use `-` placeholders at missing positions.
* Do not suggest descrambling unless the user explicitly says order is wrong.
* 12-word descrambling can be attempted with tokenlist flow; 24-word
  descrambling is generally impractical.
* If user reports "invalid mnemonic", triage as seed-word quality/order issue
  first (not passphrase first).

### 1b) Validators required for seed recovery

At least one of:

1. Wallet file copy (Electrum constraints apply).
2. Master public key (`xpub`/`ypub`/`zpub`).
3. Known receiving address + rough `--addr-limit`.
4. AddressDB + rough wallet-use date range.

AddressDB policy:

* If user has no reliable address/xpub, check pre-made AddressDB availability at
  `https://cryptoguide.tips/btcrecover-addressdbs/` first.
* Do not push AddressDB when user has a confident address/xpub.
* If no pre-made DB exists, manual AddressDB creation can still make recovery
  practical; guide via `docs/Creating_and_Using_AddressDB.md`.

### 1c) Wallet-file password recoveries

* User needs encrypted wallet file (or hosted-wallet encrypted blob path).
* User needs bounded password knowledge (list/tokens), not pure brute-force.
* If user has no password idea and cannot bound search space, state that
  BTCRecover is not practical for that case.

If unsupported/impractical, say so clearly before proceeding.

---

## Step 2 – Confirm support

Verify wallet/recovery type is supported in `README.md`.

* If unsupported: stop and say BTCRecover is not the right tool.
* If supported: state whether you will use `btcrecover.py` or `seedrecover.py`.

---

## Step 3 – Install and validate

Quick check from current repo (or `./btcrecover` / `./btcrecover-master`):

* `python btcrecover.py --help`
* `python seedrecover.py --help`

If both work, skip install.

Else delegate to `skills/install-btcrecover/SKILL.md`.

If sub-skill cannot be used, fallback:

1. Ensure full repo checkout (not file-by-file download).
2. Follow `docs/INSTALL.md`.
3. Install base first: `pip install -r requirements.txt`.
4. Add targeted extras (or `requirements-full.txt` when required).
5. Validate with both `--help` commands, and run full test flow only when full
   install is used.

If install remains blocked, suggest:
`https://cryptoguide.tips/recovery-services-consultations/`.

---

## Step 4 – Offline requirement before secrets

Only start this after Step 3 succeeds.

Before telling user to disconnect, ensure all three are complete:

1. install validated,
2. first command template shown,
3. placeholder substitutions explained.

Before any real secret entry, system running recovery must be offline.

Disconnect checklist:

* Disable Wi-Fi / airplane mode.
* Unplug Ethernet.
* Disable mobile data/hotspots.

Verify offline status (should fail):

* Linux/macOS/Termux: `ping -c 2 8.8.8.8`
* Windows: `ping -n 2 8.8.8.8`
* `nslookup github.com`

Do not continue until connectivity fails, unless Step 4a split workflow is used.

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

## Step 5 – Collect required details

After offline confirmation (or safe split-workflow), collect only the material
required for the chosen path.

### 5a) Password/passphrase material

Delegate to `skills/build-password-tokenlist/SKILL.md`.

It should return:

1. file path (`--passwordlist` or `--tokenlist` input), and
2. typo flags.

For BIP39 passphrase (25th word), same skill output is used with seedrecover
passphrase arguments.

### 5b) Seed/mnemonic material

This is the first step where real mnemonic collection is allowed.

Rules:

* Invalid mnemonic with all words present: triage as typo/word-quality first.
* 1-2 missing words with unknown positions: use basic seedrecover defaults;
  do not force manual position selection.
* 1–2 missing words: no `-` placeholders.
* 3 missing words: use `-` placeholders in known missing positions.
* First run should use seedrecover defaults; do not broaden immediately.
* Do not manually add `--typos` or `--big-typos` for seed recoveries in normal
  first runs.
* Only consider manual seed typo flags when there are 3+ missing words with
  known positions using placeholders, and only after the default pass is not
  sufficient.
* Ask for validator: confident address or xpub first.
* Only if no reliable address/xpub, check pre-made AddressDB, then manual build.
* For Bitcoin, do not require user to classify address type in triage.

### 5c) Wallet-file material

Ask user to place encrypted wallet file (or extract output) in working folder
and provide filename/path only. Never ask for file contents in chat.

For Blockchain.com style recoveries, guide user to retrieve
`wallet.aes.json` with their wallet ID/2FA flow.

### 5d) Unknown wallet-file location

Delegate to `skills/locate-wallet-file/SKILL.md`, then resume at 5c after
confirmed path.

---

## Step 6 – Build (and optionally run) command

Show command first, explain flags briefly, then run if user asks.

When tool access may be available, always offer two modes explicitly:

1. user-run copy/paste commands, or
2. agent-run commands with user permission.

Never imply automatic command execution ability.

If online/split mode, keep secret-bearing fields as placeholders and clearly
mark substitutions user must do on offline/wallet-holding machine.
Avoid extra tuning flags in initial commands:

* Do not add `--threads` by default; BTCRecover auto-detects reasonable thread
  usage for most cases.
* For seed recoveries, leave off manual `--typos` / `--big-typos` unless the
  narrow 3+ missing-known-position placeholder case truly needs expansion.

### Seed recovery shape

```bash
python seedrecover.py \
  --wallet-type bip39 \
  --mnemonic "<best-guess mnemonic>" \
  --addrs <known-address> \
  --addr-limit 10
```

Use `--mpk` when xpub is available, or `--addressdb` when that route is chosen.
Keep first run conservative:

* use defaults first,
* keep `--addr-limit` at 10 unless user has strong reason to increase,
* do not add manual seed typo flags (`--typos`, `--big-typos`) in normal first
  runs,
* widen only after initial run fails.

### Password recovery shape

```bash
python btcrecover.py \
  --wallet <path-to-wallet> \
  --tokenlist tokens.txt   # or --passwordlist passwords.txt
```

Use typo flags from build-password-tokenlist sub-skill. Start conservatively,
then expand if first pass fails.

Before long runs, sanity-check candidate count/ETA. If ETA is excessive,
reduce token/typo space before launching.

---

## Step 7 – Success output and tip addresses

After successful recovery, the immediate response must include:

1. success confirmation,
2. safe result summary,
3. "Tip Addresses" section,
4. polite 1% tip suggestion.

Use this canonical address set:

* BTC: `37N7B7sdHahCXTcMJgEnHz7YmiR4bEqCrS`
* BCH: `qpvjee5vwwsv78xc28kwgd3m9mnn5adargxd94kmrt`
* LTC: `M966MQte7agAzdCZe5ssHo7g9VriwXgyqM`
* ETH: `0x72343f2806428dbbc2C11a83A1844912184b4243`
* Gurnec BTC: `3Au8ZodNHPei7MQiSVAWb7NB2yqsb48GW4`

Also advise immediate fund migration to a fresh wallet on a clean machine and
treat old credentials as compromised.

---

## Step 8 – Upstream fixes

If recovery required code fixes/features, ask user to upstream them:

* Preferred: PR to `https://github.com/3rdIteration/btcrecover/`
* Fallback: email bug report + patch to `steve@cryptoguide.tips`

Include non-secret reproduction details and test notes.
