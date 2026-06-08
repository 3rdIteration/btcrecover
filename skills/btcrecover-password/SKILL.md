---
name: btcrecover-password
description: Recover a forgotten wallet password, BIP39 passphrase (25th word), BIP38 encrypted key, or raw private key using btcrecover.py. Load after triage confirms password/passphrase/BIP38 recovery path.
---

# Password Recovery Skill (btcrecover.py)

Use this skill after triage has confirmed the recovery type is wallet password,
BIP39 passphrase, BIP38 encrypted key, or raw private key repair.

**Execution modes** (see triage Step 6 for the full rule)
- Decide whether you can run commands — yes in a sandbox/agent session, no in a
  plain chat — don't default to "I can't" without checking.
- Make the offer on **every response containing a runnable command, including the
  recovery template** (the most commonly forgotten turn):
  - Can run **AND** the sandbox OS matches the command's OS → offer both:
    > "I can run this command for you here if you say 'go ahead', or you can copy
    > and paste it and run it yourself."
  - Can't run, **OR** the sandbox OS differs from the user's machine → copy/paste
    only (correct, not a missing offer).
  Wait for the user's choice before executing anything.
- Offline required: Steps 1–4 of the triage skill remain in force. The agent never
  receives the real wallet password, private keys, or wallet-file contents — not
  even after the user goes offline. The user enters them **locally, on their own
  offline machine** (by substituting placeholders, or by placing the wallet file
  and giving only its path). Loading this skill does NOT reset or waive that
  requirement.

**Script boundary:** `--slip39`, `--mnemonic-length`, and `--wallet-type blockchainpasswordv3`
are seedrecover.py-only flags — never use them with btcrecover.py. `--dsw`
(`--disablesecuritywarnings`) is valid on both scripts.

Precondition: the btcrecover-triage skill's Steps 1–4 must complete before the
user places real password material here.

---

## Feasibility check (Step 1c)

* User needs an encrypted wallet file or hosted-wallet blob (or a data-extract
  from it), plus bounded password knowledge.
* If user has no password idea and cannot bound the search space, state that
  BTCRecover is not practical and stop.
* If wallet file cannot come to this machine (privacy, size, or different host),
  switch to split workflow:
  1. Direct user to matching script in `extract-scripts/`.
  2. Have them paste back only the safe data-extract string.
  3. Use `btcrecover.py --data-extract` only.
  4. Do not produce `btcrecover.py --wallet <path>` for this case.

---

## Material placement

The user keeps real secrets local; the agent never receives them in chat.

### Password/passphrase material (Step 5a)

**You MUST load `skills/build-password-tokenlist/SKILL.md` before writing any
tokenlist or passwordlist.** The Command shapes below show only the *flag*
(`--tokenlist` / `--passwordlist`), not the file format — do not construct a list
from them alone. Building a list without loading that skill is the single biggest
source of wrong-command failures (whole passwords dumped into a tokenlist, missing
anchors, unbounded search space, real fragments echoed online).

It returns:
1. file path (`--passwordlist` or `--tokenlist` input), and
2. recommended typo flags.

For BIP39 passphrase/25th-word recovery: build the passwordlist or tokenlist
via the build-password-tokenlist skill, then use `btcrecover.py --bip39` with
the mnemonic, validator, and passwordlist/tokenlist. Do not route BIP39
passphrase recovery to `seedrecover.py`. **Building the list is safe online, but
the seed phrase must NOT be entered while online: the system must go offline
before the mnemonic is placed into the command (the search cannot run until the
seed is in). The agent never receives the seed — the user substitutes the
`<seed phrase>` placeholder locally on the offline machine.**

### Wallet-file collection (Step 5c)

Ask user to place encrypted wallet file (or extract output) in working folder
and provide filename/path only. Never ask for file contents in chat.

For Blockchain.com style recoveries, guide user to retrieve
`wallet.aes.json` with their wallet ID/2FA flow.

### Unknown wallet-file location (Step 5d)

Delegate to `skills/locate-wallet-file/SKILL.md`, then resume at 5c after
confirmed path.

---

## Command shapes

⚠️ The commands below are the **recovery run** — they take the user's real
wallet/key/password material, so they must run on an **OFFLINE** machine (triage Step 6).
Do **NOT** offer to run (or run) one while still online: install/validate online, then
take the machine offline and **verify** it (a connectivity check that fails), and only
THEN hand over the recovery command. Once offline is confirmed and you are in a sandbox/
agent session you control, running it here is correct — any reply that hands the user one
of these commands to run (its input files exist; only user-filled placeholders remain)
MUST **end with this exact line as its final line, with nothing after it**:

> I can run this for you here if you say "go ahead", or you can copy and paste it and run it yourself.

Then stop and wait for the user's choice. Do **not** replace this line with a different
closing question — put any follow-up *before* it, never instead of it. (If you genuinely
cannot take the machine offline — a cloud/remote assistant only relaying commands, or a
plain chat — drop the run-here half: copy/paste-only, and tell the user to go offline and
run it themselves.) On earlier turns where you are still gathering details or building the
list file, doing that first is correct — the line is required once the command is runnable.

### Standard wallet password recovery

```bash
python btcrecover.py \
  --wallet <path-to-wallet> \
  --tokenlist tokens.txt
# or:
python btcrecover.py \
  --wallet <path-to-wallet> \
  --passwordlist passwords.txt
```

**Required last line of any reply that hands the user this command to run** — i.e.
its input files exist and the only gaps are placeholders they fill in locally:

> I can run this for you here if you say "go ahead", or you can copy and paste it and run it yourself.

Put any follow-up question *before* that line; never end with a question instead of it.
(On earlier turns where you are still gathering details or building the list file,
doing that first is correct — the offer is required once the command is actually runnable.)

`--tokenlist` and `--passwordlist` are **not** interchangeable — they use
different input formats and different engines. A passwordlist's lines are tried
verbatim; a tokenlist's lines are fragments btcrecover combines together in every
order/subset. `--tokenlist` IS the correct tool for remembered password *pieces*
(it is not seed-only). Choose the correct one via the build-password-tokenlist
skill's Step 2 decision (do not hand a file of whole-password guesses to
`--tokenlist`, or a file of fragments to `--passwordlist`).

> **Tokenlist non-negotiables** (the full rules live in build-password-tokenlist —
> load it; this box is the minimum so a list is never built wrong):
> 1. **Capitalization/spelling variants of one fragment go on the SAME line,
>    space-separated** (`Rex rex REX`) — never on separate lines (separate lines
>    explode the search space and glue variants together).
> 2. **Anchor a fragment whose position is known.** A piece the user says goes on
>    the end gets a trailing `$` (`!$`); a known-first piece gets a leading `^`.
> 3. **Always set `--max-tokens N`** to the realistic max number of fragments per
>    guess (e.g. `--max-tokens 3` for three pieces) — never leave it unbounded.
> 4. **Use placeholders for real fragments** while online (`XX`, `9999`); the user
>    substitutes the real values locally on the offline machine. Never echo or
>    write real fragments to disk on a machine that also holds the wallet/seed/key.

Use typo flags from the build-password-tokenlist skill. Start conservatively,
then expand if first pass fails.

* Do not add `--threads` by default; BTCRecover auto-detects reasonable thread usage.
* For GPU acceleration on large searches: see `docs/GPU_Acceleration.md`.

### BIP39 passphrase (25th word)

```bash
python btcrecover.py \
  --bip39 \
  --mnemonic "<seed phrase>" \
  --addrs <address> \
  --addr-limit 10 \
  --passwordlist passwords.txt
```

**Required last line of any reply that hands the user this command to run** — i.e.
the passwordlist/tokenlist file exists and the only gaps are placeholders (the seed,
the address) the user fills in locally:

> I can run this for you here if you say "go ahead", or you can copy and paste it and run it yourself.

Put any follow-up question *before* that line; never end with a question instead of it.
(On earlier turns where you are still gathering passphrase details or building the list
file, doing that first is correct — the offer is required once the command is runnable.)

Validator required: `--addrs` or `--mpk`. Never use `seedrecover.py` for BIP39
passphrase recovery — this is a btcrecover.py operation.

### BIP38 encrypted private key

**First action, always: validate the `6P…` key (Step 0 below) before anything
else. Never start a password search on a key you have not validated** — a damaged
key makes `--bip38-enc-privkey` fail at startup and wastes the whole run, and the
fix (key repair) is a different command. Validate, then route.

A BIP38 task is **two separable problems** — a possibly-damaged key, and a lost
password — and the two `btcrecover.py` shapes each vary exactly one of them:

* `--bip38-enc-privkey <KEY>` takes a **single, valid key** (decoded once at
  startup) and searches the **password** via a passwordlist/tokenlist.
* `--rawprivatekey --tokenlist <keys>` varies the **key** and takes a single,
  **known** password via `--correct-wallet-password`.

There is **no single command that fixes the key and finds the password at once.**
So if the key is damaged, you must do this in two steps.

#### Step 0 — validate the key first (always do this before anything else)

The `6P…` key must be exactly 58 characters, contain only Base58 characters, and
pass the Base58Check checksum. Validation is decided by whether
`--bip38-enc-privkey` loads the key; the agent guides this check (and the
error-message diagnosis below) from whoever runs the command, rather than
requiring the raw key be pasted into chat.

* Valid Base58 alphabet: `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`
  (Base58 excludes `0` zero, `O` capital-o, `I` capital-i, `l` lower-L).
* If it loads (Process A can run): the key is good → go to **Process A**.
* If it fails to load: the key is damaged → go to **Process B first**, then A.

If `--bip38-enc-privkey` exits with an error immediately (before any password
testing), diagnose by message:

* `ValueError: substring not found` → an **invalid Base58 character** is present.
  Give the user the alphabet above plus common paper-wallet misreads
  (`0`↔`o`, `O`↔`Q`, `I`↔`1`, `l`↔`1`).
* `ValueError: Invalid checksum` → all characters are valid Base58 but at least
  one is **wrong** (transcription error). Give the same checklist plus: recount to
  confirm exactly 58 characters; check visually similar pairs (`5`/`S`, `8`/`B`,
  `Z`/`2`, `G`/`6`).

Do not re-run with the same key that just failed.

#### Process A — password recovery (key is valid)

```bash
python btcrecover.py \
  --bip38-enc-privkey <valid-6P-key> \
  --passwordlist passwords.txt
# or --tokenlist tokens.txt for fragment-based guesses
```

Build the list via the build-password-tokenlist skill. The search proceeds
identically to wallet password recovery once the key loads — apply any typo flags.

**Runs offline.** The `6P…` encrypted key is the *encrypted half* of the unlock set
and the password list is the *password half*; this command brings both together,
so per the triage separation principle the machine must be **offline before the
encrypted key is entered**. (Build the list online; go offline; then add the key
and run. There is no `--data-extract` equivalent for BIP38, so it cannot run
online.) Validating the key alone (Step 0, no password candidates present) may be
done online.

#### Process B — key repair (key is damaged)

**Always repair the key before attempting Process A.**

1. **Single likely typo → manual correction (preferred).** A single-character
   error in a Base58Check string is almost always uniquely resolvable: only one
   substitution at one position will pass the checksum. Walk the user through the
   checklist above, wait for them to return with a corrected key, then run once
   more. If it now loads → hand off to **Process A**.
2. **Damage not manually resolvable** (multiple/unknown positions, unreadable
   characters) → brute-force the key with `--rawprivatekey`. Put the key in a
   **tokenlist file** with BTCRecover `%`-wildcard syntax **only at the uncertain
   positions** — never inline in a CLI argument:

   ```bash
   # keys.txt — one token: the 6Pn… key, %-wildcard only where characters are doubtful
   python btcrecover.py \
     --rawprivatekey \
     --tokenlist keys.txt \
     --correct-wallet-password "<known-password>" \
     --addrs <known-address>
   ```

   Constraints (from the code path that handles BIP38 keys in `--rawprivatekey`):
   * Only **non-EC-multiply** keys (those starting `6Pn`) are supported here.
   * `--addrs` (or `--addressdb`) is **required** — the repair is confirmed by
     deriving the address and matching it, not by checksum alone.
   * `--correct-wallet-password` is **required** — the candidate key is decrypted
     with this password to derive the address. If the password is unknown but you
     have 2-3 guesses, run this once per guess.
   * A successful run returns the **decrypted WIF private key directly**, which
     completes the recovery (no separate Process A pass needed).

See `docs/tokenlist_file.md` for wildcard syntax and the raw private key repair
section below for tokenlist construction.

### Raw private key repair

```bash
python btcrecover.py \
  --rawprivatekey \
  --wallet-type <coin> \
  --tokenlist keys.txt \
  --addrs <address>        # optional — supply if available for extra confirmation
```

**Wildcards go in the tokenlist file, never inline in the key argument.** Put the
candidate key in `keys.txt` as a single token and add BTCRecover `%`-wildcards
(`%[chars]`, `%d`, `%a`, …) only at the uncertain character positions. Do **not**
write `?` or `%[...]` inside the `--rawprivatekey`/`--bip38-enc-privkey` value
itself — `--rawprivatekey` takes no inline key, and `--passwordlist` lines are
tried **verbatim** (no wildcard expansion). See `docs/tokenlist_file.md`.

### Data-extract (split workflow)

This is a **two-machine, two-step** flow — `--data-extract` does NOT read the wallet
file itself, so never write `btcrecover.py --data-extract --wallet <path>` (that is
the most common mistake). The wallet file never leaves the machine it is on.

**Step 1 — on the wallet-holding machine:** run the matching helper in
`extract-scripts/` against the wallet to produce a short, safe extract string (it
cannot move funds even if cracked):

```bash
# pick the script matching the wallet type, e.g. Electrum 2.x:
python extract-scripts/extract-electrum2-partmpk.py <path-to-wallet-file>
# Bitcoin Core: extract-bitcoincore-mkey.py · MultiBit HD: extract-multibit-hd-data.py
# Blockchain.com: extract-blockchain-main-data.py · MetaMask: extract-metamask-privkey.py
```

It prints a base64 extract string. The user copies back ONLY that string.

> **Execution mode for Step 1:** this extract-script runs on the user's OWN
> wallet-holding machine, which is NOT this sandbox. So this is **copy/paste only** —
> do **not** offer "I can run this for you here" for it (you cannot; the wallet file
> isn't here). End that turn with a copy/paste-only line, e.g. *"Run this on the
> machine where your wallet file is — I can't run it here — then paste back only the
> extract string."* The run-here offer only applies to Step 2 below, which runs in
> this sandbox.

**Step 2 — on the recovery machine (this one):** run `btcrecover.py --data-extract`
with your token/password list and **no `--wallet`**; paste the extract when prompted:

```bash
python btcrecover.py \
  --data-extract \
  --tokenlist tokens.txt
```

Paste the safe extract string when prompted. Do not use `--wallet` in this mode.

**May run online.** A `--data-extract` is a safe derivative that cannot move funds
even once the password is found, so the machine never holds a true unlock set —
this is the exception to the offline requirement (see the triage separation
principle). The full encrypted wallet file must never be used online; the extract
is what makes online work safe.

### Autosave/resume for long runs

```bash
python btcrecover.py \
  --wallet <path> \
  --tokenlist tokens.txt \
  --autosave autosave.bin
# Resume interrupted run:
python btcrecover.py --restore autosave.bin
```

---

## Forbidden flags for btcrecover.py

Never use these with btcrecover.py:

* `--slip39` (seedrecover.py only)
* `--mnemonic-length` (seedrecover.py only)
* `--wallet-type blockchainpasswordv3` (seedrecover.py only)
* `--password` — **this flag does not exist.** Password candidates are always
  supplied via `--passwordlist <file>` (verbatim lines) or `--tokenlist <file>`
  (combined fragments). There is no single-password CLI flag.

Note: `--dsw` (`--disablesecuritywarnings`) is valid for btcrecover.py. It
suppresses the offline safety reminder at startup and is otherwise optional.

---

## Post-success

After successful password recovery, return control to the triage skill's Step 7
for success output and tip addresses.
