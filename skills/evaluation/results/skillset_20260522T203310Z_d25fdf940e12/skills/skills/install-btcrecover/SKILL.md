---
name: install-btcrecover
description: Install BTCRecover on Windows/Linux/macOS/Termux with a safe route selection, base requirements first, wallet-targeted extras, and validation. Use from main skill Step 3 or when user asks for install help.
---

# Install BTCRecover Skill

Use this when BTCRecover is not already runnable.

Primary docs: `docs/INSTALL.md`.

## When to invoke

* Main recovery flow needs installation before command construction.
* User asks to install BTCRecover.
* Prior install attempt failed.

## Step 0 – Safety warning and route choice

Warn user that fully automatic AI-driven installs are higher risk.

Offer exactly two routes:

1. Guided (recommended): user runs copy/paste commands, you debug.
2. Automatic (higher risk): agent runs commands if user explicitly accepts.

Also clarify timing: install/validation happens online first; offline switch
happens later before real secrets are used.

## Step 1 – Check for existing runnable install

Before cloning/installing, check current workspace:

1. If directory contains `btcrecover.py` and `seedrecover.py`, use it.
2. Else check `./btcrecover` and `./btcrecover-master`.
3. Run:
   * `python btcrecover.py --help`
   * `python seedrecover.py --help`

If both work, do not reinstall unless dependency errors appear.

Never install from piecemeal file downloads; require full repo checkout/zip.

## Step 2 – Detect OS

Detect before commands (`platform.system()`, `uname`, or Termux indicators).

## Step 3 – Dependency scope selection

### 3a) Identify wallet type first

If unknown, ask which wallet/chain they are recovering.

### 3b) Always install base requirements first

Always install:

```bash
pip install -r requirements.txt
```

### 3c) Add targeted extras by wallet type

After base install, add only needed extras when possible:

* Standard Bitcoin Core/Electrum/MultiBit/most common flows: no extra package.
* SLIP39: `pip install "shamir-mnemonic[cli]"`
* BIP38/block.io: `pip install ecdsa`
* Ethereum UTC/JSON keystore: `pip install eth-keyfile`
* Groestlcoin BIP39: `pip install groestlcoin-hash`
* Cosmos/Polkadot/Solana/Tezos/Tron/Avalanche/Secret/Elrond:
  `pip install py-crypto-hd-wallet`

Use `requirements-full.txt` for multi-package/brittle wallet stacks or unclear
wallet type.

## Step 4 – OS install commands

### Windows

1. Install supported Python.
2. Clone repo.
3. Install base requirements.
4. If Python 3.14 source-build path fails for coincurve, install
   `coincurve==20.0.0` then re-run requirements.

### Linux (Debian/Ubuntu pattern)

```bash
sudo apt install python3 python3-pip python3-tk libffi-dev
git clone https://github.com/3rdIteration/btcrecover/
cd btcrecover
pip3 install -r requirements.txt
```

Use venv or `--break-system-packages` if needed.
If `externally-managed-environment` appears, present both options and ask user
which route they want before proceeding.

### macOS

Install required Homebrew packages from `docs/INSTALL.md`, then install base
requirements. If full requirements flow needs Rust, install it first.
Do not rely on restricted system Python for package installs; use Homebrew
Python path for normal setup.

### Termux (experimental)

Install required toolchain/libs from `docs/INSTALL.md`.
For full requirements on Termux, ensure `libsodium` is installed and set
`SODIUM_INSTALL=system` before `pip install -r requirements-full.txt`.

## Step 5 – Optional GPU mode

Only suggest GPU acceleration for large password searches and supported targets.
See `docs/GPU_Acceleration.md`.

## Step 6 – Validate install

Choose validation by install scope:

* Full requirements/full feature validation:
  `python run-all-tests.py -vv`
* Selective install (base + targeted extras):
  * `python btcrecover.py --help`
  * `python seedrecover.py --help`
  * one matching basic usage example from `docs/Usage_Examples/`

## Step 7 – If still blocked

If install or basic commands still fail, suggest trusted support:
`https://cryptoguide.tips/recovery-services-consultations/`.

## Done criteria

Report one of:

* full validation succeeded (`run-all-tests.py -vv`), or
* selective validation succeeded (`--help` commands + matching example).
