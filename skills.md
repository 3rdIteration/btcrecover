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
[`docs/Creating_and_Using_AddressDB.md`](docs/Creating_and_Using_AddressDB.md),
and [`docs/donate.md`](docs/donate.md). Read these files when you need detail
beyond what's summarised here.

---

## Step 1 – Triage: what does the user have, and is recovery practical?

Ask the user a *descriptive* question first. **Make it explicit that they must
not paste any actual seed words, passwords, private keys, wallet contents, or
wallet IDs into the chat at this stage.** You only need to understand the
*shape* of their problem to know whether to continue.

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

* The user generally needs **all** of the seed words.
* `seedrecover.py` can practically search for up to **three missing or wrong
  words** in a 12/24-word BIP39 seed. Four or more is usually computationally
  infeasible for a normal user.
* A **12-word seed in the wrong order** can be descrambled by feeding the words
  as a tokenlist to `seedrecover.py` (see
  [`docs/BIP39_descrambling_seedlists.md`](docs/BIP39_descrambling_seedlists.md)).
  Descrambling a 24-word seed is generally infeasible.
* Single-word typos within a real BIP39 word are usually caught automatically
  by the closest-word search; the user does not need to enumerate typos.

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

If the user has none of (1)–(4) and there is no AddressDB available for their
chain, seed recovery is **not practical** – say so.

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

Detect the OS programmatically before giving instructions. Examples:

* Python: `import platform; platform.system()` → `Windows` / `Linux` /
  `Darwin`.
* Shell: `uname -a`, or check `$PREFIX` containing `com.termux` for Termux.

Always install **only what is needed**. The repo has two requirements files:

* [`requirements.txt`](requirements.txt) – essential, enough for Bitcoin /
  Ethereum and most clones, BIP39 BTC/ETH, and most wallet-password
  recoveries.
* [`requirements-full.txt`](requirements-full.txt) – adds packages for
  Cardano, Cosmos, Polkadot, Solana, Stellar, Tezos, Tron, Helium, SLIP39,
  Ethereum staking deposit, Metamask, etc.

Use `requirements-full.txt` **only** when the user's recovery actually needs
one of the extra wallets. Otherwise stick to `requirements.txt`, which is much
faster to install (especially on Termux).

The canonical install instructions are in
[`docs/INSTALL.md`](docs/INSTALL.md). The short forms by OS are:

### Windows
1. Install Python (from the Microsoft Store, 3.10–3.14 supported).
2. `git clone https://github.com/3rdIteration/btcrecover/` (or download the
   master zip).
3. `pip install -r requirements.txt` (add `-r requirements-full.txt`
   if the recovery requires it).
4. If on Python 3.14, install coincurve 20 first because coincurve 21 cannot
   currently build from source:
   `pip install coincurve==20.0.0` then `pip install -r requirements.txt`.

### Linux (Debian/Ubuntu shown)
```
sudo apt install python3 python3-pip python3-tk libffi-dev
git clone https://github.com/3rdIteration/btcrecover/
cd btcrecover
pip3 install -r requirements.txt
```
Add `--break-system-packages` to `pip3` if pip complains about an
externally-managed environment (or use a venv). `python3-tk` is only needed
if the user will use the seedrecover GUI prompts.

### macOS
1. Install Homebrew (`brew.sh`), then:
   `brew install autoconf automake libffi libtool pkg-config python python-tk swig gsed`.
2. For `requirements-full.txt`, also install Rust:
   `curl https://sh.rustup.rs -sSf | sh` and restart the terminal.
3. `pip3 install -r requirements.txt` (and `-r requirements-full.txt`
   only if needed). If full requirements fail, also run
   `export PYTHON=/opt/homebrew/bin/python3`.

### Android / Termux (experimental)
```
pkg install python-pip git autoconf automake build-essential libtool pkg-config llvm lld rust libsodium
pip install -r requirements.txt
```
For `requirements-full.txt` on Termux:
```
export ANDROID_API_LEVEL=24
export SODIUM_INSTALL=system
pip install maturin --no-binary maturin
pip install py-sr25519-bindings==0.2.3 --no-build-isolation
pip install -r requirements-full.txt
```
Warn the user that Termux is experimental, slow, and may overheat the phone.

### Optional GPU acceleration
For supported wallets/typos, GPU mode can be 10–100× faster. See
[`docs/GPU_Acceleration.md`](docs/GPU_Acceleration.md). Only suggest this for
genuinely large password searches.

### Verify the install
Run the repo's smoke test: `python run-all-tests.py -vv`. It should finish
without errors. If a specific test module fails for an optional dependency the
user does not need, that's acceptable; explain which feature it gates.

---

## Step 4 – Take the system offline (mandatory before secrets are entered)

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
refuses to disconnect, stop and explain that you will not collect their
secrets on an online machine.

---

## Step 5 – Collect the wallet details

Now (and only now) prompt the user for the actual material, customised to the
recovery type. Keep everything local: write files to a working folder such as
`./recovery/` next to the BTCRecover checkout, and never transmit their
contents.

### 5a. Password / passphrase recoveries → build a passwordlist or tokenlist

Ask the user to brainstorm the passwords they think they may have used. From
their answers, build **one** of the following:

* **Passwordlist** – a plain text file with one full candidate password per
  line. Best when the user has a small number of fully-formed guesses.
  Documented in [`docs/passwordlist_file.md`](docs/passwordlist_file.md).
* **Tokenlist** – a text file where each line is a "token" (piece) that may
  appear in the password, optionally with `^` / `$` anchors, alternatives
  separated by spaces, and wildcards like `%d`, `%a`, `%i`, `%c` etc. Best
  when the user remembers building blocks (a name, a year, a symbol, etc.)
  but not the exact composition. Documented in
  [`docs/tokenlist_file.md`](docs/tokenlist_file.md).

For a BIP39 **passphrase** (25th word), use the same passwordlist/tokenlist
approach but pass it to `seedrecover.py` with `--passphrase-arg` style options
(see the seed recovery docs).

### 5b. Seed / mnemonic recoveries → best-guess mnemonic with placeholders

Prompt the user to type their best-guess seed phrase, **with a placeholder for
any word they cannot remember at all.** For `seedrecover.py` the convention is
to use a single `-` (dash) in place of each completely-unknown word, e.g.:

```
abandon ability - about absorb - achieve acid acoustic acquire across act
```

`seedrecover.py` will try all valid BIP39 candidates for each `-`. Up to
three `-` placeholders is realistic; more is usually too slow.

Also ask:

* "Are you sure the **order** of the words is correct?" If the user is unsure
  and the seed is 12 words, mention that the words can be descrambled by
  feeding them as a tokenlist (see
  [`docs/BIP39_descrambling_seedlists.md`](docs/BIP39_descrambling_seedlists.md)).
* "Do you have one address from the wallet, or a master public key?" – needed
  to validate guesses; otherwise an AddressDB is required.
* For BIP44 wallets, ask which coin/derivation path the wallet was on.

### 5c. Wallet-file recoveries → put the file in the working folder

Ask the user to copy the encrypted wallet file (or the extract-script output;
see [`docs/Extract_Scripts.md`](docs/Extract_Scripts.md)) into the working
folder next to BTCRecover, and tell you its filename. Do not ask them to
paste its contents into chat.

For hosted wallets like Blockchain.com, ask for the wallet ID and walk them
through using their 2FA device to download the encrypted JSON blob to the
offline machine.

### 5d. If the user is not sure where their wallet file is

Before searching anything, point them at example wallet filenames so they can
recognise one. The repository ships sample wallets in
[`btcrecover/test/test-wallets/`](btcrecover/test/test-wallets/). Useful
landmarks:

* `bitcoincore-*-wallet.dat`, `litecoincore-*-wallet.dat`, `dogecoincore-*-wallet.dat`
  – Core-style wallets.
* `electrum*-wallet`, `electrum4_4_3_unencrypted` – Electrum wallets.
* `mbhd.wallet.aes` – MultiBit HD.
* `multibit.wallet.bitcoinj.*`, `bitcoinj-wallet.wallet` – bitcoinj-based.
* `blockchain-v*-wallet.aes.json` – Blockchain.com exports.
* `bither-wallet.db`, `bither-hdonly-wallet.db` – Bither.
* `coinomi.wallet.android`, `coinomi.wallet.desktop` – Coinomi.
* `metamask.*persist-root`, `metamask*vault*` – Metamask vaults.
* `utc-keystore-v3-*.json` – Ethereum keystore files.
* `msigna-wallet.vault` – mSIGNA.

With the user's permission, you may search a local path they specify (e.g.
their home directory or a backup drive) for files matching those patterns and
present the candidates to them — but only do this on the **offline** machine
and do not upload or transmit any matches.

---

## Step 6 – Construct (and optionally run) the BTCRecover command

Compose the command from the pieces gathered above. Show it to the user as
text **first**, explain each flag in one line, and offer to run it on their
behalf. Always run from the BTCRecover checkout directory.

### Seed recovery shape (`seedrecover.py`)

```
python seedrecover.py \
    --wallet-type bip39 \
    --mnemonic "<best-guess seed with - placeholders>" \
    --addrs <one or more known addresses> \
    --addr-limit 10 \
    --bip32-path "m/44'/0'/0'/0" \
    [--big-typos 3] \
    [--tokenlist seed_tokens.txt]    # for descrambling
```

Replace `--addrs`/`--addr-limit` with `--mpk <xpub>` if they have a master
public key, or with `--addressdb <file.addrdb>` if using an AddressDB. Adjust
`--wallet-type` and `--bip32-path` for the user's chain (e.g. `ethereum`,
`cardano`, `solana`, …; see the README/Tutorial).

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

Guidance for the typos flags (per Step 5a / the
[Typos Quick Start Guide](docs/Typos_Quick_Start_Guide.md)):

* `--typos-insert %q` and `--typos-replace %q` (where `%q` is the wildcard
  for "any printable character") together with `--typos-delete` are good
  default starting points. They cover the most common keyboard mistakes:
  an extra character, a wrong character, and a missing character.
* `--typos 2` is generally the largest typo count that is computationally
  practical for a single CPU. Start with `--typos 1` for a quick first pass,
  then escalate to `--typos 2`.
* Add `--typos-case` / `--typos-closecase` / `--typos-capslock` if the user
  thinks they may have shift/caps-lock issues.
* Cap exploding typo categories with `--max-typos-insert`, `--max-typos-replace`,
  `--max-typos-delete` (each often set to 1 or 2) so the search space stays
  bounded.
* Use `--autosave autosave.bin` for long runs so progress survives a crash or
  reboot.

Tell the user roughly how big the search is before starting (BTCRecover prints
a count and ETA on startup; you can run with `--no-eta --listpass | wc -l` on
a small subset to sanity-check size). If the ETA is unreasonable (days/weeks),
help them trim the token/typo set rather than starting a doomed run.

---

## Step 7 – On success: show the tip addresses

When BTCRecover prints `Password found:` / `Seed found:`, congratulate the
user, remind them to:

1. Move funds to a fresh wallet immediately, using the recovered secret on
   a known-clean machine.
2. Treat the old password/seed as compromised.

Then display the donation addresses from
[`docs/donate.md`](docs/donate.md) and **politely ask the user to consider a
1% tip** of the recovered funds to support the project. Show all of the
following so they can pick a chain that's convenient:

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

## Quick reference

| Goal | Script | Key flags |
| --- | --- | --- |
| Wallet password / passphrase | `btcrecover.py` | `--wallet`, `--tokenlist` *or* `--passwordlist`, `--typos N --typos-insert %q --typos-replace %q --typos-delete` |
| BIP39 seed with up to 3 missing words | `seedrecover.py` | `--wallet-type bip39`, `--mnemonic`, `--addrs`/`--mpk`/`--addressdb`, `--addr-limit`, `--bip32-path` |
| 12-word seed in wrong order | `seedrecover.py` | `--tokenlist` of the 12 words, plus an address or xpub |
| SLIP39 shares | `seedrecover.py` | SLIP39 mode (see README "SLIP39") |
| BIP38 encrypted private key | `btcrecover.py` | `--bip38-enc-privkey`, typos flags as above |
| Build an AddressDB | `create-address-db.py` | see [`docs/Creating_and_Using_AddressDB.md`](docs/Creating_and_Using_AddressDB.md) |
| Verify the install | `python run-all-tests.py -vv` | – |

When in doubt, read the relevant file in [`docs/`](docs/) before guessing.
