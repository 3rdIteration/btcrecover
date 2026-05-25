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

OS command conventions (use one row; do not mix shells):

* Linux/macOS/Termux: `python3 ...`, `ping -c 2 ...`,
  `source venv/bin/activate`.
* Windows PowerShell: `python ...`, `ping -n 2 ...`,
  `.\venv\Scripts\Activate.ps1`.

Anti-loop rule: if a command/tool call returns an error or non-zero exit, do not
repeat the same command. Diagnose from the error, ask for missing information, or
stop and explain.

Script routing quick card:

* Seed words/mnemonic/SLIP39 => `seedrecover.py`.
* Wallet-file password/passphrase/BIP38 => `btcrecover.py`.
* BIP39 passphrase / "25th word" => `btcrecover.py --bip39` with
  `--mnemonic`, `--passwordlist` or `--tokenlist`, and validator.
* Raw private key repair => `btcrecover.py --rawprivatekey`; use guesses in a
  tokenlist/passwordlist plus address or AddressDB.
* Blockchain.com legacy recovery mnemonic => `seedrecover.py --wallet-type
  blockchainpasswordv3`; it is not a BIP39 wallet seed.
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
* 12-word descrambling can be attempted with `--dsw` tokenlist flow.
* 24-word full descrambling is generally impractical; only consider token/group
  flows when the user knows ordered word groups or strong anchors.
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

If the wallet file cannot come to this machine (privacy, size, or different
host), stop and switch to split workflow:

1. Direct user to the matching script in `extract-scripts/`.
2. Have them paste back only the safe data-extract string.
3. Use `btcrecover.py --data-extract` from here on.
4. Do not produce `btcrecover.py --wallet <path>` for this case.

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

Offline gate: do not tell user to disconnect until all three are complete:

1. `--help` or equivalent install validation succeeded in this conversation, or
   user confirmed it.
2. Runnable command template with placeholders has been shown.
3. Every placeholder has a one-line substitution explanation.

If any item is missing, complete it before giving the disconnect checklist.

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

For BIP39 passphrase/25th-word recovery: build the passwordlist or tokenlist
here, then use `btcrecover.py --bip39` with the mnemonic, validator, and
passwordlist/tokenlist. Do not route BIP39 passphrase recovery to
`seedrecover.py`.

### 5b) Seed/mnemonic material

This is the first step where real mnemonic collection is allowed.

Decide before building the command:

1. All 12/24 words present but wallet says "invalid": typo path. Pass all
   words, no `-` placeholders, no passphrase theory first.
2. 1-2 missing words, unknown positions: use basic seedrecover defaults, no `-`
   placeholders.
3. 3+ missing words at known positions: use `-` placeholders only at those
   positions.
4. Suspected wrong order: ask first; only then consider descrambling (12-word
   only).

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

Mandatory dual-mode phrase when producing any runnable command and tool
execution may be available:

> "You have two options: (a) I can run these commands for you here if you say
> 'go ahead', or (b) you can copy and paste them and run them yourself."

Skipping this offer is a workflow violation. Never imply automatic command
execution ability or consent.

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

Special command shapes from usage examples:

* BIP39 passphrase:
  `python btcrecover.py --bip39 --mnemonic "<seed>" --addrs <address> --addr-limit 10 --passwordlist passwords.txt`
* BIP38:
  `python btcrecover.py --bip38-enc-privkey <encrypted-key> --passwordlist passwords.txt`
* Raw private key repair:
  `python btcrecover.py --rawprivatekey --addrs <address> --wallet-type <coin> --tokenlist keys.txt`
* Descrambling:
  `python seedrecover.py --dsw --mnemonic-length 12 --tokenlist words.txt --addrs <address> --wallet-type bip39`
* SLIP39 share repair:
  `python seedrecover.py --slip39 --mnemonic "<damaged share>"`
* Blockchain.com legacy recovery mnemonic:
  `python seedrecover.py --wallet-type blockchainpasswordv3 --mnemonic "<legacy words>" --mnemonic-length <count>`

Before long runs, sanity-check candidate count/ETA. If ETA is excessive,
reduce token/typo space before launching.

---

## Step 7 – Success output and tip addresses

After successful recovery, the immediate response must include:

1. success confirmation,
2. safe result summary,
3. "Tip Addresses" section,
4. polite 1% tip suggestion.

Example tone: "If this saved your funds and you'd like to support continued
development, a 1% tip is appreciated. Tip addresses below — feel free to
ignore."

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
