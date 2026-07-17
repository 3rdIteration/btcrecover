---
name: install-btcrecover-macos
description: Install BTCRecover on macOS using Homebrew Python and a virtual environment, with Apple Silicon (M1/M2/M3) and Rust prerequisite notes.
---

# Install BTCRecover — macOS

Primary docs: `docs/INSTALL.md`.

System Python on macOS is intentionally restricted from installing third-party
packages. Use Homebrew Python or a virtual environment — this is not a
BTCRecover bug.

## Step 0 – Safety and execution mode

**OS confirmation:** If running in a sandbox/docker environment, the container OS
is Linux — the user's machine is macOS. Confirm with the user before proceeding
that they are installing on their own macOS machine.

**Execution mode (see triage Step 6):** decide whether you can run commands — yes
in a sandbox/agent session, no in a plain chat — don't default to "I can't"
without checking. Offer on every response that contains a runnable command:

* Can run **AND** the sandbox is macOS (matches these commands) → offer both:
  > "I can run these for you here if you say 'go ahead', or you can copy and paste
  > them and run them yourself."
* Can't run, **OR** the sandbox is Linux/Windows while the user is on macOS (these
  commands would fail if run here) → copy/paste only — this is correct, not a
  missing offer:
  > "I can't run these for you in this session, so copy and paste the block below
  > and run it yourself."

Wait for explicit confirmation before running. Do not first offer to run and then
say you cannot.

`--break-system-packages` is NOT a first suggestion on macOS; use a venv.

## Step 1 – Check for existing install

```bash
python3 btcrecover.py --help
python3 seedrecover.py --help
```

If both work, skip install. Also check `./btcrecover/` and `./btcrecover-master/`.

## Step 2 – Install

> **Use Python 3.13 if you can.** Python 3.10–3.13 ship pre-built `coincurve`
> wheels (fastest backend). Python 3.14+ has no coincurve wheel — see the
> Windows skill Step 3 / `docs/INSTALL.md` for the `wallycore` fallback.

```bash
# Prereqs (Homebrew Python required; do not use system Python for packages)
brew install python git

# Clone
git clone https://github.com/3rdIteration/btcrecover.git
cd btcrecover

# Virtual environment (REQUIRED on macOS)
python3 -m venv venv
source venv/bin/activate

# Base requirements
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

# Validate
python3 btcrecover.py --help
python3 seedrecover.py --help
```

## Step 3 – Apple Silicon (M1/M2/M3) notes

Most packages build fine via Homebrew Python on Apple Silicon. If a
requirements-full install fails due to missing Rust (for cryptography/pynacl
source builds):

```bash
brew install rust
python3 -m pip install -r requirements-full.txt
```

## Step 4 – Targeted extras (add only what the wallet type needs)

After base install, add extras only when needed:

* SLIP39: `pip install "shamir-mnemonic[cli]"`
* BIP38/block.io: `pip install ecdsa`
* Ethereum UTC/JSON keystore: `pip install eth-keyfile`
* Groestlcoin BIP39: `pip install groestlcoin-hash`
* Cosmos/Polkadot/Solana/Tezos/Tron/Avalanche/Secret/Elrond:
  `pip install py-crypto-hd-wallet`

Use `requirements-full.txt` for multi-package installs or unclear wallet type.

> **Python 3.14 note:** `requirements-full.txt` cannot be installed on Python
> 3.14 because `bip-utils` (and dependents) hard-require `coincurve`, which has
> no 3.14 wheel yet. Install the base `requirements.txt` (which falls back to
> `wallycore` for secp256k1) and add HD-wallet extras only once coincurve ships
> a 3.14 wheel. See `docs/INSTALL.md` ("Python 3.14 and coincurve").

## Step 5 – Validate

```bash
python3 btcrecover.py --help
python3 seedrecover.py --help
```

For full feature validation: `python3 run-all-tests.py -vv`

### Runtime ImportError fix

If base install succeeded but a wallet command fails with `ModuleNotFoundError`,
identify the missing module from the traceback, map it to Step 4 extras, and
install only that module. Do not reinstall everything.

## Step 6 – If still blocked

`https://cryptoguide.tips/recovery-services-consultations/`

## Done criteria

Report: full validation succeeded (`run-all-tests.py -vv`), or selective
validation succeeded (`--help` commands + matching usage example).
