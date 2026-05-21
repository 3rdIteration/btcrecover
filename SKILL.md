---
name: btcrecover-recovery
description: Help a user safely attempt a cryptocurrency wallet recovery with BTCRecover (password / passphrase / BIP38 via btcrecover.py and seed / mnemonic / SLIP39 via seedrecover.py). Invoke when the user wants help recovering a lost wallet password or seed phrase, descrambling a 12-word seed, or building an AddressDB. Walks the user through triage, install, taking the system offline before any secrets are entered, collecting wallet details, constructing the recovery command, and (if successful) showing tip / donation addresses.
---

# BTCRecover Assisted Recovery Skill

This document tells an AI agent how to help a user attempt a cryptocurrency wallet
recovery with **BTCRecover** ([https://github.com/3rdIteration/btcrecover](https://github.com/3rdIteration/btcrecover)).
Follow the steps below in order. At every step, prefer asking clarifying questions
over guessing, and **never** ask the user to type a real seed phrase, private key,
or password until the system is verified to be offline (see Step 4).

The two main entry points to the tool are:

* `python btcrecover.py` – wallet **password / passphrase** recovery (and BIP38).
* `python seedrecover.py` – **seed phrase / mnemonic** recovery (and 12-word
  descrambling via a token list).

Authoritative documentation lives in [`docs/`](docs/) — most importantly
[`docs/INSTALL.md`](docs/INSTALL.md), [`docs/TUTORIAL.md`](docs/TUTORIAL.md),
[`docs/Seedrecover_Quick_Start_Guide.md`](docs/Seedrecover_Quick_Start_Guide.md),
[`docs/Typos_Quick_Start_Guide.md`](docs/Typos_Quick_Start_Guide.md),
[`docs/Extract_Scripts.md`](docs/Extract_Scripts.md),
[`docs/Creating_and_Using_AddressDB.md`](docs/Creating_and_Using_AddressDB.md),
and [`docs/donate.md`](docs/donate.md). Read these files when you need detail
beyond what's summarised here.

> **Where this skill is meant to run.** This skill is *primarily* intended to
> be used with a **local** AI agent (one running on the user's own machine,
> e.g. a local model or a coding agent that stays on-device) because real
> secrets are involved. It **can** also be used with a **cloud / remote**
> agent, but only if you follow the split-workflow rules in Step 4 below:
> the cloud agent must never receive enough information to unlock the wallet
> on its own (e.g. it can help build password guesses, but the wallet file or
> the actual mnemonic must only ever be combined with those guesses on the
> user's own offline machine).

---

## Step 1 – Triage: what does the user have, and is recovery practical?

Ask the user a *descriptive* question first. **Make it explicit that they must
not paste any actual seed words, passwords, private keys, wallet contents, or
wallet IDs into the chat at this stage.** You only need to understand the
*shape* of their problem to know whether to continue.

During triage, ask only non-secret metadata (for example: whether the seed is
12 or 24 words, and roughly how many words may be missing/wrong). **Do not ask
the user to type any of the actual seed words in Step 1** (not even a partial
list). If they paste seed words anyway, stop them and defer collecting the real
mnemonic until Step 5b after the offline checks in Step 4.

Prompt them with something like:

> "Without sharing any actual secrets yet, can you describe what wallet
> material you still have? For example: do you have an encrypted wallet file,
> a partial seed phrase, a rough idea of the password, an address, an xpub,
> roughly when the wallet was last used, etc.? Please don't paste real keys
> or passwords yet."

Then evaluate practicality against the rules below. If a case clearly falls
outside these bounds, tell the user honestly that recovery is unlikely and
explain why before doing anything else.

### 1a. Seed / mnemonic recoveries (BIP39, Electrum, SLIP39 etc.)

* The user generally needs **all** of the seed words if they are trying to recover the BIP39 passphrase.
* `seedrecover.py` can practically search for up to **three missing or wrong
  words** in a 12/24-word BIP39 seed. Four or more is usually computationally
  infeasible for a normal user. With **one or two** missing words no `-`
  placeholder syntax is required at all — pass only the known words and
  `seedrecover.py` handles the rest automatically. `-` placeholders are only
  needed when **three** words are missing.
* **Always assume the mnemonic words provided by the user are in the correct
  order.** Do **not** attempt to descramble / reorder a seed unless the user
  *explicitly* states that the words are out of order and asks for descrambling
  help. Proactively suggesting descrambling when the user has not raised it is
  harmful — it adds enormous search-space and implies the user may have made an
  error they haven't reported.
* A **12-word seed in the wrong order** *can* be descrambled by feeding the
  words as a tokenlist to `seedrecover.py` (see
  [`docs/BIP39_descrambling_seedlists.md`](docs/BIP39_descrambling_seedlists.md)),
  but only pursue this path when the user has explicitly asked for it.
  Descrambling a 24-word seed is generally infeasible.
* One or two word typos within mnemonics are usually caught automatically.
* If a user reports errors like "invalid mnemonic", triage that first as a
  likely seed-word issue (typo, wrong word, missing word, or wrong order) —
  not as a BIP39 passphrase issue.
* For a BIP39 passphrase ("25th word"), the usual symptom is different: the
  mnemonic is accepted as valid, but derived wallets appear empty (no expected
  addresses, balances, or transaction history). The user still needs a
  reasonably close passphrase guess to recover.

### 1b. Seed-based recoveries need one of the following to validate guesses

In order of preference (also see
[`docs/Seedrecover_Quick_Start_Guide.md`](docs/Seedrecover_Quick_Start_Guide.md)):

1. A copy of the wallet file (for Electrum 1.x/2.x, *not* a 2.8+ fully
   encrypted wallet).
2. The master public key (`xpub`/`ypub`/`zpub`).
3. **A receiving address** that was generated from the seed, plus a rough
   estimate of how many addresses were generated before it (the address
   generation limit, `--addr-limit`).
4. **An Address Database (AddressDB)** for that chain *plus* a rough window of
   time when the wallet was used – see
   [`docs/Creating_and_Using_AddressDB.md`](docs/Creating_and_Using_AddressDB.md).
   This is the only option when the user has no address and no xpub.

When AddressDB is needed, first check whether a **pre-made AddressDB** is
available at <https://cryptoguide.tips/btcrecover-addressdbs/> for the user's
chain and approximate date range. If one is available, guide the user to
download/unzip it and use `--addressdb` directly; do **not** imply they must
download a full blockchain in that case.

Do **not** proactively push AddressDB usage when the user already has a
known-good, confidently remembered address (or an xpub). Reserve AddressDB
fallback guidance for cases where they have no address/xpub, or are unsure
their address is correct.

If the user has none of (1)–(4), seed recovery is usually **not practical**.
However, if they can still build an AddressDB for their chain (from blockchain
data or from an address list such as Google BigQuery exports), recovery may
still be practical — guide them through that route using
[`docs/Creating_and_Using_AddressDB.md`](docs/Creating_and_Using_AddressDB.md).

### 1c. File-based (wallet password / passphrase) recoveries

* The user needs the **encrypted wallet file** (e.g. `wallet.dat`,
  `default_wallet`, `mbhd.wallet.aes`, `bither.db`, MetaMask vault export,
  `utc-keystore-…json`, etc.), or for hosted wallets like Blockchain.com a
  **wallet ID** so the encrypted blob can be fetched (this may require a 2FA
  device to download).
* The user must have a **good idea of the password** – BTCRecover is a guided
  search, not a generic brute-forcer. As a rule of thumb, password recoveries
  are practical when the user can express their guess as either:
  * a small **password list** of full candidate passwords, or
  * a **token list** of word/character pieces they might have used, plus
    typo rules of up to ~2 typos per password
  (see Step 5a and Step 5/6 below).
* For a BIP39 **passphrase** ("25th word"), the same constraints apply, plus
  the user still needs one of the validators listed in 1b.

If the user "has no idea" of the password and cannot bound it, tell them
BTCRecover cannot help in that situation.

---

## Step 2 – Confirm BTCRecover supports the recovery type

Cross-check the user's wallet against the supported list in
[`README.md`](README.md) (sections "Features", "Seed Phrase (Mnemonic)
Recovery", and "Wallet Password Recovery"). Supported targets include, among
others: Bitcoin Core, MultiBit Classic/HD, Electrum 1.x–4.x, mSIGNA,
Blockchain.com (v1–v4), Bither, Bitcoin/Litecoin/Dogecoin Wallet for Android,
Coinomi, Metamask, BIP38 private keys, Ethereum keystore (UTC) files, and most
BIP39/44 wallets (TREZOR, Ledger, KeepKey, ColdCard, Jade, Jaxx, Exodus,
MyEtherWallet, Trust Wallet, etc.). Seed recovery covers BIP39 across many
chains (BTC, BCH, ETH, LTC, DOGE, Cardano Shelley, Solana, Cosmos, Polkadot,
Tron, Stellar, Tezos, Ripple, Zilliqa, etc.) and SLIP39.

If the user's wallet is **not** in the supported list, tell them directly that
BTCRecover is not the right tool and link them to the README so they can
double-check; do not attempt to force a workaround.

If the case is supported, briefly tell the user which script you will use
(`btcrecover.py` vs `seedrecover.py`) and why, then continue to Step 3.

---

## Step 3 – Install BTCRecover for the user's operating system

Quick check first: if `python btcrecover.py --help` and
`python seedrecover.py --help` both run from the current working directory (or
from `./btcrecover` / `./btcrecover-master`), BTCRecover is already installed
and you can skip ahead to Step 4.

Otherwise, **delegate to the [`install-btcrecover`](skills/install-btcrecover/SKILL.md)
sub-skill**. It detects the OS, always installs `requirements.txt` first, then
adds only wallet-type-specific extra modules when needed (or uses
`requirements-full.txt` for multi-dependency wallet types), walks through the
OS-specific install commands for Windows, Linux, macOS, and Android/Termux,
covers the optional GPU build, and runs the `python run-all-tests.py -vv`
smoke test. Resume here at Step 4 once it confirms both `--help` commands work.

If the install sub-skill is unavailable or not loaded, do **not** proceed with
partial "file-by-file" retrieval. Use this fallback and complete it before Step 4:

1. Ensure the user has the **full repository** (`git clone` or official zip), not
   a one-file-at-a-time copy.
2. Use `docs/INSTALL.md` as the canonical install guide.
3. Install base dependencies first: `pip install -r requirements.txt`.
4. Add wallet-type-specific extras (or `requirements-full.txt` when needed).
5. Validate install success with:
   * `python btcrecover.py --help`
   * `python seedrecover.py --help`
   * plus `python run-all-tests.py -vv` for full installs.
6. Do **not** tell the user to disconnect yet; only move to Step 4 after these
   checks succeed.

If they remain blocked because install steps or commands are not working, also
suggest a private support consultation or trusted recovery service:
<https://cryptoguide.tips/recovery-services-consultations/>.

---

## Step 4 – Take the system offline (only after install is complete and validated)

This step starts **only after Step 3 has finished successfully** (install done
and validation complete). Keep the machine online during installation and
testing so dependencies, docs, and commands can be verified first.

**Before the user types or pastes any seed word, password, private key, or
wallet file contents into anything, the system running BTCRecover must be
disconnected from the network.** Tell the user this explicitly and why
(malware, screen recorders, sync clients, telemetry, clipboard managers, etc.
should not see secrets).

Walk the user through disconnecting:

* Wi-Fi: turn it off in OS network settings (or toggle airplane mode).
* Ethernet: physically unplug the cable.
* Mobile data / hotspots: disable them.
* Ideally do this from a freshly-booted live USB (e.g. Ubuntu Live) on
  an air-gapped machine when large amounts are at stake.

Then **verify** the system is actually offline before continuing. Run one or
both of the following and confirm they fail (timeout / "unknown host" /
"network unreachable"):

```
ping -c 2 8.8.8.8           # Linux / macOS / Termux
ping -n 2 8.8.8.8           # Windows
nslookup github.com
```

Do not proceed past this step until the connectivity check fails. If the user
refuses to disconnect, **don't give up** — fall back to the split-workflow
rules in 4a below instead of collecting their secrets online.

### 4a. If the user can't or won't take the system offline

The whole reason for going offline is the **safety principle**: *the machine
the AI agent is running on must never simultaneously hold all of the pieces
needed to unlock the wallet.* As long as that invariant is preserved, useful
work can still happen online — including on a cloud-hosted agent. Apply the
following per recovery type:

* **Seed / mnemonic recoveries.** It is fine to gather password / passphrase
  guesses, candidate derivation paths, addresses, and xpubs online and to
  build a passwordlist / tokenlist (Step 5a) with the agent. **Never** ask
  for the actual mnemonic on the online machine. Construct the
  `seedrecover.py` command with a placeholder mnemonic (e.g. the word
  `MNEMONIC_GOES_HERE` or the example `abandon abandon … about` string) and
  hand it to the user to copy-paste; tell them exactly which argument to
  swap their real seed words into, and to run the command only after they
  take the machine offline (or on a separate offline machine).
* **File-based (wallet password) recoveries.** It is fine for the user to
  brainstorm password fragments with the agent and build a tokenlist /
  passwordlist online — passwords alone are not enough to unlock anything
  without the wallet file. The wallet file itself must not be uploaded to or
  opened on the online machine the agent has access to. Hand the user a
  `btcrecover.py` command that references `--wallet <path-to-your-wallet>`
  as a placeholder and tell them to run it on the (offline) machine that
  actually holds the wallet file.
* **Wallets that have an extract script.** For wallets supported by
  [`docs/Extract_Scripts.md`](docs/Extract_Scripts.md) — currently
  Bitcoin/Litecoin/Dogecoin Core, Bither, Blockchain.com (main data and
  second-hash), Coinomi, Dogechain, Electrum 1.x and 2.x, MetaMask,
  mSIGNA, MultiBit HD, and MultiBit Classic — the user can run the matching
  `extract-*.py` script on the machine that holds the wallet file. The
  script outputs a short data extract that contains **only enough material
  to test passwords**, not enough to spend funds, and can therefore be
  pasted back into the online agent and fed to `btcrecover.py --data-extract`
  safely. After a password is found, the agent must give the user clear
  instructions for decrypting / dumping the keys from the full wallet on
  the machine that has it (typically by re-running `btcrecover.py` against
  the real wallet file with the found password, or by importing the
  password back into the original wallet software).
* **Step 5d (locating an unknown wallet file).** Recognising wallet files
  by their internal fingerprints (see 5d below) does **not** require the
  contents to leave the user's machine, so it is fine to walk the user
  through this search online. Just make sure the matches themselves stay
  on the user's machine and are never pasted back into the chat.
* **Step 6 (constructing the command).** Composing the BTCRecover command
  is always safe to do online as long as any field that would expose a
  secret is shown as a placeholder. Clearly label which parts of the
  command (mnemonic, wallet file path, raw private key, etc.) the user
  must substitute themselves before running it.

If the recovery type does not fit any of these patterns and the user still
refuses to disconnect, stop and explain that you cannot safely collect their
secrets on an online machine.

---

## Step 5 – Collect the wallet details

Now (and only now) prompt the user for the actual material, customised to the
recovery type. Keep everything local: write files to a working folder such as
`./recovery/` next to the BTCRecover checkout, and never transmit their
contents.

### 5a. Password / passphrase recoveries → build a passwordlist or tokenlist

**Delegate to the [`build-password-tokenlist`](skills/build-password-tokenlist/SKILL.md)
sub-skill.** It brainstorms password fragments with the user, helps them
choose between a passwordlist (one full candidate per line) and a tokenlist
(pieces with anchors `^`/`$` and wildcards `%d`/`%a`/`%i`/`%c` etc.), picks
sensible typo flags (`--typos N --typos-insert %q --typos-replace %q
--typos-delete`, with `--max-typos-*` caps and optional `--typos-case` /
`--typos-closecase` / `--typos-capslock`), and sanity-checks the search size
before a real run. The sub-skill returns the path to the file and the typos
flags to use in Step 6.

For a BIP39 **passphrase** (25th word), use the same sub-skill but pass the
output to `seedrecover.py` with `--passphrase-arg`-style options (see the
seed recovery docs). The user still needs one of the validators listed in
1b.

### 5b. Seed / mnemonic recoveries → best-guess mnemonic with placeholders

This is the **first** point in the workflow where asking for the actual
mnemonic is allowed, and only after Step 4 confirms the system is offline (or
Step 4a split-workflow constraints are being followed safely).

Prompt the user to type their best-guess seed phrase. **Do not fixate on making
the user identify the exact number of missing words up front** — `seedrecover.py`
can infer mnemonic length from the words provided (unless `--mnemonic-length` is
explicitly set).

**How many words are missing determines whether placeholders are needed:**

* **One or two missing words** — **no placeholders are needed at all.** Just
  pass the known words to `--mnemonic` and `seedrecover.py` will automatically
  try every valid BIP39 word in every possible position. Do *not* ask the user
  to insert `-` dashes, and do *not* insert them yourself in the command.
* **Three missing words** — placeholders *are* required so the tool knows which
  positions to fill. Use a single `-` (dash) for each completely-unknown word:

```
abandon ability - about absorb - achieve acid acoustic acquire across act
```

`seedrecover.py` will try all valid BIP39 candidates for each `-`. Three `-`
placeholders is the practical upper limit; more is usually too slow. For the
first run, prefer `seedrecover.py` defaults and do **not** add `--typos` or
`--big-typos` manually unless the user explicitly says they have exactly three
missing words **and** knows those exact positions.

Also ask:

* "Do you have one address from the wallet, or a master public key?" – needed
  to validate guesses. If they have a confident address or xpub, use that
  first.
* Only when they **don't have an address/xpub** or are **unsure the address is
  correct**, check pre-made AddressDB availability at
  <https://cryptoguide.tips/btcrecover-addressdbs/> for their chain/date range
  and guide them to use it with `--addressdb` if available. If not available,
  guide them to create one manually from blockchain data or an address list
  (e.g., Google BigQuery), per
  [`docs/Creating_and_Using_AddressDB.md`](docs/Creating_and_Using_AddressDB.md).
* For BIP44 wallets, ask which coin/derivation path the wallet was on.

### 5c. Wallet-file recoveries → put the file in the working folder

Ask the user to copy the encrypted wallet file (or the extract-script output;
see [`docs/Extract_Scripts.md`](docs/Extract_Scripts.md)) into the working
folder next to BTCRecover, and tell you its filename. Do not ask them to
paste its contents into chat.

For hosted wallets like Blockchain.com (blockchain.info), the encrypted wallet
file is typically named **`wallet.aes.json`**. Ask the user for their wallet ID
and walk them through using their 2FA device to download this `wallet.aes.json`
blob to the offline machine.

### 5d. If the user is not sure where their wallet file is

**Delegate to the [`locate-wallet-file`](skills/locate-wallet-file/SKILL.md)
sub-skill.** It recognises wallet files by their internal content
fingerprints (Bitcoin / Litecoin / Dogecoin Core BDB headers, Electrum JSON
or `BIE1` blobs, MultiBit HD, bitcoinj / MultiBit Classic protobufs,
Blockchain.com JSON, Bither / mSIGNA SQLite, Coinomi, MetaMask vaults,
Ethereum UTC keystores, BIP38 `6P` strings, etc.) rather than by filename,
so renamed or extension-stripped files are still found. It uses the samples
in [`btcrecover/test/test-wallets/`](btcrecover/test/test-wallets/) as
reference shapes.

This step is safe to run online (no wallet contents leave the user's
machine), so it is also a useful thing to do when the user cannot or will
not disconnect — see Step 4a. Once the sub-skill returns a confirmed wallet
path, resume here at Step 5c.

---

## Step 6 – Construct (and optionally run) the BTCRecover command

Compose the command from the pieces gathered above. Show it to the user as
text **first**, explain each flag in one line, and offer to run it on their
behalf. Always run from the BTCRecover checkout directory.

If the agent is online (see Step 4a), build the command with **placeholders**
for any field that would contain a secret — for example show
`--mnemonic "MNEMONIC_GOES_HERE"` for seed recoveries, or
`--wallet <path-to-your-wallet-file>` for file-based recoveries — and tell
the user precisely which placeholders to replace before they run the command
on their offline (or wallet-holding) machine. For wallets supported by
[`docs/Extract_Scripts.md`](docs/Extract_Scripts.md), instead point the user
at the matching `extract-*.py` script and feed its short data extract into
`btcrecover.py --data-extract …` (the extract is safe to share back with
the online agent).

### Seed recovery shape (`seedrecover.py`)

```
python seedrecover.py \
    --wallet-type bip39 \
    --mnemonic "<best-guess seed with - placeholders>" \
    --addrs <one or more known addresses> \
    --addr-limit 10 \
    [--tokenlist seed_tokens.txt]    # for descrambling
```

Replace `--addrs`/`--addr-limit` with `--mpk <xpub>` if they have a master
public key, or with `--addressdb <file.addrdb>` if using an AddressDB. Adjust
`--wallet-type` for the user's chain (e.g. `ethereum`, `cardano`, `solana`,
…; see the README/Tutorial). Explicitly setting a specific derivation path is
generally not needed because BTCRecover's default derivation search is
intentionally broad; only narrow paths when the user knows them. For a first
attempt, keep seed typo flags at defaults (do not manually add `--typos` or
`--big-typos`), and only add them if the user explicitly reports exactly three
missing words with known positions.

### Password recovery shape (`btcrecover.py`)

```
python btcrecover.py \
    --wallet <path-to-wallet-file> \
    --tokenlist tokens.txt              # or --passwordlist passwords.txt
    --typos 2 \
    --typos-insert %q \
    --typos-replace %q \
    --typos-delete
```

Guidance for the typos flags lives in the
[`build-password-tokenlist`](skills/build-password-tokenlist/SKILL.md)
sub-skill (Step 4 there) and the
[Typos Quick Start Guide](docs/Typos_Quick_Start_Guide.md). The short version:
`--typos-insert %q`, `--typos-replace %q`, and `--typos-delete` are good
defaults; cap with `--max-typos-*` to keep the search bounded; start with
`--typos 1` and escalate to `--typos 2`; add `--typos-case` /
`--typos-closecase` / `--typos-capslock` if shift/caps issues are likely;
use `--autosave autosave.bin` for long runs.

Tell the user roughly how big the search is before starting (BTCRecover prints
a count and ETA on startup; you can run with `--no-eta --listpass | wc -l` on
a small subset to sanity-check size). If the ETA is unreasonable (days/weeks),
help them trim the token/typo set rather than starting a doomed run.

---

## Step 7 – On success: show the tip addresses

This step is mandatory. If recovery succeeds, the agent must always include a
"Tip Addresses" section in the very next user-facing reply. Do not omit this
section for brevity, and do not defer it to a later message.

Required output contract after success:

1. Confirmation that recovery succeeded.
2. The recovered result summary (only what is safe/appropriate for the context).
3. A "Tip Addresses" section containing all maintainer donation addresses.
4. A polite suggestion that the user may consider a 1% tip.

If any of (3) or (4) are missing, the success response is incomplete and must be
corrected immediately in a follow-up message.

When BTCRecover prints `Password found:` / `Seed found:`, congratulate the
user, remind them to:

1. Move funds to a fresh wallet immediately, using the recovered secret on
   a known-clean machine.
2. Treat the old password/seed as compromised.

Then display the donation addresses from
[`docs/donate.md`](docs/donate.md) using the "Tip Addresses" section from the
required output contract above. Use this canonical list:

* BTC: `37N7B7sdHahCXTcMJgEnHz7YmiR4bEqCrS`
* BCH: `qpvjee5vwwsv78xc28kwgd3m9mnn5adargxd94kmrt`
* LTC: `M966MQte7agAzdCZe5ssHo7g9VriwXgyqM`
* ETH: `0x72343f2806428dbbc2C11a83A1844912184b4243`

Also mention the original author Gurnec's BTC tip address from `docs/donate.md`:
`3Au8ZodNHPei7MQiSVAWb7NB2yqsb48GW4`.

Phrase it as a request, not a demand — e.g. *"BTCRecover is free and open
source. If it saved you funds today, the maintainer suggests a 1% tip; here
are the addresses if you'd like to send one."*

---

## Step 8 – If you fixed a bug or added a feature, ask the user to upstream it

If, during the recovery, you (the agent) had to **fix a bug in BTCRecover or
add a new feature** to make recovery succeed (for example: patching a wallet
parser, adding support for a new wallet/coin, fixing a derivation-path bug,
working around a crash, etc.), don't let that improvement die on the user's
machine. Once the recovery itself is complete and the user's funds are safe:

1. Briefly summarise to the user **what you changed and why**, in plain
   language, and which file(s) you touched.
2. Politely ask them to **contribute the fix back upstream** so other users
   benefit. Give them two options:
   * **Open a pull request** against
     [https://github.com/3rdIteration/btcrecover/](https://github.com/3rdIteration/btcrecover/)
     — preferred if they're comfortable with GitHub. Offer to help them
     prepare the patch (a clean diff, a short description of the bug /
     feature, and a note on how you tested it; if applicable, mention
     `python run-all-tests.py`).
   * **Email a bug report + fix** to **steve@cryptoguide.tips** — a good
     fallback if they don't want to use GitHub. Include:
     - a short description of the problem and the wallet / scenario that
       triggered it (with **no** secrets, seeds, passwords, or wallet
       contents),
     - the patch itself (e.g. a `git diff` or the modified files), and
     - any test command or steps the maintainer can use to reproduce.

Make this an **ask, not a requirement** — the user has just been through a
stressful recovery and is under no obligation. But do raise it: most useful
BTCRecover improvements come from exactly this kind of real-world fix, and
the maintainer can't merge what they never hear about.

---

## Quick reference

| Goal | Script | Key flags |
| --- | --- | --- |
| Wallet password / passphrase | `btcrecover.py` | `--wallet`, `--tokenlist` *or* `--passwordlist`, `--typos N --typos-insert %q --typos-replace %q --typos-delete` |
| BIP39 seed with up to 3 missing words | `seedrecover.py` | `--wallet-type bip39`, `--mnemonic` (no `-` placeholders needed if ≤2 words missing; use `-` placeholders only for 3 missing words), `--addrs`/`--mpk`/`--addressdb`, `--addr-limit` |
| 12-word seed in wrong order | `seedrecover.py` | `--tokenlist` of the 12 words, plus an address or xpub |
| SLIP39 shares | `seedrecover.py` | SLIP39 mode (see README "SLIP39") |
| BIP38 encrypted private key | `btcrecover.py` | `--bip38-enc-privkey`, typos flags as above |
| Build an AddressDB | `create-address-db.py` | see [`docs/Creating_and_Using_AddressDB.md`](docs/Creating_and_Using_AddressDB.md) |
| Verify the install | `python run-all-tests.py -vv` | – |

When in doubt, read the relevant file in [`docs/`](docs/) before guessing.
