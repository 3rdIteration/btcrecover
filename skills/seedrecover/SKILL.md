---
name: seedrecover
description: Recover a lost or corrupted seed phrase, mnemonic, or SLIP39 share using seedrecover.py. Covers missing words, typos, descrambling, SLIP39, and Blockchain.com legacy mnemonics. Load after triage confirms seed/mnemonic recovery path.
---

# Seed Recovery Skill (seedrecover.py)

Use this skill after triage has confirmed the recovery type is seed/mnemonic/SLIP39.

**Execution modes** (see triage Step 6 for the full rule)
- Decide whether you can run commands — yes in a sandbox/agent session, no in a
  plain chat — don't default to "I can't" without checking.
- Make the offer on **every response containing a runnable command, including the
  recovery template** (the most commonly forgotten turn):
  - **Sandbox / agent session (you CAN run)** — the sandbox is the user's machine,
    so always offer both:
    > "I can run this command for you here if you say 'go ahead', or you can copy
    > and paste it and run it yourself."
  - **Plain chat (you CANNOT run)** → copy/paste only (correct, not a missing offer).
  Wait for the user's choice before executing anything.
- Offline required: Steps 1–4 of the triage skill remain in force. The agent never
  receives real seed words, mnemonic material, or private keys — not even after the
  user goes offline. The user enters them into the command **locally, on their own
  offline machine**, by substituting the placeholders. Loading this skill does NOT
  reset or waive that requirement.

**Script boundary:** `--mnemonic-length`, `--slip39`, and `--wallet-type blockchainpasswordv3`
are seedrecover.py-only flags. `--dsw` (`--disablesecuritywarnings`) exists in both scripts;
it suppresses the offline safety reminder. It has no effect on search behavior.
Do not mix other flags between the two scripts.

Precondition: the btcrecover-triage skill's Steps 1–4 (secret intake gate and
offline gate) must complete before the user places real mnemonic material here.

Ordering: if the user has just cloned/installed, first confirm the script runs
(`python seedrecover.py --help`) and hand over the command template with
placeholders **before** telling them to go offline. Never give the offline/disconnect
checklist until install is validated and the template is delivered.

---

## Material placement (Step 5b)

This is the first step where the **user** enters real mnemonic material — and only
on their own offline machine, by substituting the placeholders in the command
template. The agent never sees the words: do not ask the user to paste their seed
phrase into the chat, even now that they are offline. Build the template with
`<word1 … wordN>` placeholders and tell the user to replace them locally.

Decide before building the command:

1. All 12/24 words present but wallet says "invalid": typo path. Pass all
   words, no `-` placeholders, no passphrase theory first.
2. 1–2 missing OR wrong words: **no `-` placeholders, and you do NOT need to know
   the positions.** seedrecover.py automatically searches inserting/replacing up to
   two words on its own. For missing words, pass only the words you have (a short
   mnemonic) and let it insert; for wrong/typo'd words, pass all the words and let
   it substitute. Do not ask the user which positions are affected — it is
   unnecessary for ≤2 and adds no value.
3. **Exactly 3 missing words at known positions:** use `-` placeholders at those
   three positions. This is the one case where placeholders earn their keep — the
   automatic up-to-two search no longer covers it, and pinning the three known
   positions keeps the search tractable. (4+ missing words is generally impractical
   without strong extra constraints.)
4. Suspected wrong order: ask first; only then consider descrambling (12-word only).

Rules:

* Invalid mnemonic with all words present: triage as typo/word-quality first.
* 1–2 missing or wrong words: **never** use `-` placeholders and do not ask for
  positions — seedrecover handles up to two automatically, position unknown is fine.
* Exactly 3 missing words with known positions: use `-` placeholders to mark those
  three positions (this is what makes 3 feasible).
* First run should use seedrecover defaults; do not broaden immediately.
* Do not manually add `--typos` or `--big-typos` in normal first runs.
* Only consider manual seed typo flags when there are 3 missing words with
  known positions using placeholders, and only after the default pass is not
  sufficient.
* Ask for validator: confident address or xpub first.
* Only if no reliable address/xpub, check pre-made AddressDB, then manual build.
* For Bitcoin, do not require user to classify address type in triage.
* **When building command templates with --mnemonic, example words must match
  the user's actual word count. If the user has 17 words, use "word1 word2 ...
  word17" or `<17 words here>` — never a mismatched count.**

---

## Command shapes

⚠️ The seedrecover commands below are the **recovery run** — they take the user's real
seed, so they must run on an **OFFLINE** machine (triage Step 6). Do **NOT** offer to
run (or run) one while still online: install/validate online, then take the machine
offline and **verify** it (a connectivity check that fails), and only THEN hand over the
recovery command. Once offline is confirmed and you are in a sandbox/agent session you
control, running it here is correct — any reply that hands the user one of these commands
to run MUST **end with this exact line as its final line, with nothing after it**:

> I can run this for you here if you say "go ahead", or you can copy and paste it and run it yourself.

Then stop and wait for the user's choice. Do **not** replace this line with a different
closing question — put any follow-up *before* it, never instead of it. (If you genuinely
cannot take the machine offline — a cloud/remote assistant only relaying commands, or a
plain chat — drop the run-here half: copy/paste-only, and tell the user to go offline and
run it themselves.) On earlier turns where you are still gathering details, doing that
first is correct — the line is required once the command is runnable.

### Standard seed recovery

```bash
python seedrecover.py \
  --wallet-type bip39 \
  --mnemonic "<best-guess mnemonic>" \
  --addrs <known-address> \
  --addr-limit 10
```

Use `--mpk <key>` when xpub/ypub/zpub is available.
Use `--addressdb <path>` when AddressDB route is chosen.

Keep first run conservative:

* use defaults first,
* keep `--addr-limit` at 10 unless user has strong reason to increase,
* do not add manual `--typos` or `--big-typos` in first run,
* widen only after initial run fails.

### BIP39 with 3 missing words at known positions

Placeholders are for the **3-missing-words** case only. Mark each known-missing
position with `-` (this example: positions 3, 5 and 8 of a 12-word seed):

```bash
python seedrecover.py \
  --wallet-type bip39 \
  --mnemonic "word1 word2 - word4 - word6 word7 - word9 word10 word11 word12" \
  --addrs <address> \
  --addr-limit 10
```

Use `-` placeholders ONLY for this 3-missing-words case. For **1–2 missing or wrong
words, omit `-` entirely** — known or unknown position makes no difference, because
seedrecover automatically searches inserting/replacing up to two words. Adding
placeholders (or asking the user for positions) when ≤2 are missing is unnecessary.

### Descrambling (12-word only, when user says order is wrong)

Descrambling works by providing all words as a tokenlist; seedrecover.py tries
every permutation by default. `--dsw` (`--disablesecuritywarnings`) suppresses
the offline safety reminder — it does NOT activate descrambling; the tokenlist
+ no `--keep-tokens-order` is what enables it.

Create `words.txt` with one word per line (all known words, any order):

```bash
python seedrecover.py \
  --wallet-type bip39 \
  --mnemonic-length 12 \
  --tokenlist words.txt \
  --addrs <address> \
  --addr-limit 10 \
  --dsw
```

For partial order (user knows some pairs are swapped, not full reorder), prefer
`--transform-wordswaps 2` instead of a full tokenlist permutation.

See `docs/BIP39_descrambling_seedlists.md` and
`docs/Usage_Examples/2020-05-02_Descrambling_a_12_word_seed/`.

24-word full descrambling is generally impractical; only consider token/group
flows when the user knows ordered word groups or strong anchors.

### SLIP39 share repair

```bash
python seedrecover.py \
  --slip39 \
  --mnemonic "<damaged share>"
```

SLIP39 support needs the `shamir-mnemonic` package. If `--slip39` errors with a
missing dependency, install it first (in the sandbox/venv):
`python -m pip install shamir-mnemonic` (it is also included in
`requirements-full.txt`), then re-run. Repair the damaged share only — do not ask
for the full quorum of real shares in chat.

### Blockchain.com legacy recovery mnemonic

```bash
python seedrecover.py \
  --wallet-type blockchainpasswordv3 \
  --mnemonic "<legacy words>" \
  --mnemonic-length <count>
```

**This recovery type does NOT need an address/xpub/AddressDB validator** —
it validates by checksum and password match. Always include `--mnemonic-length`
matching the user's word count. If the user has no wallet file, no address, and
no xpub, proceed anyway — blockchainpasswordv3 does not require any of them.

---

## Forbidden flags for seedrecover.py

Never use these with seedrecover.py (they belong to btcrecover.py):

* `--wallet <path>`
* `--bip38-enc-privkey`
* `--data-extract`
* `--tokenlist` (allowed for descrambling only; not for standard seed recovery)

---

## Post-success

After successful seed recovery, return control to the triage skill's Step 7
for success output and tip addresses.
