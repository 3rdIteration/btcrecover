---
name: install-btcrecover-windows
description: Install BTCRecover on Windows (PowerShell) including Python setup, pip, virtual environment, and coincurve build-failure workaround.
---

# Install BTCRecover — Windows (PowerShell)

Primary docs: `docs/INSTALL.md`.

## Step 0 – Safety and execution mode

**Execution mode (see triage Step 6):** decide whether you can run commands — yes
in a sandbox/agent session, no in a plain chat — don't default to "I can't"
without checking. Offer on every response that contains a runnable command:

* Can run **AND** the sandbox OS is Windows (matches these PowerShell commands) →
  offer both:
  > "I can run these for you here if you say 'go ahead', or you can copy and paste
  > them and run them yourself."
* Can't run, **OR** the sandbox is Linux/macOS while the user is on Windows (these
  PowerShell commands would fail if run here) → copy/paste only — this is correct,
  not a missing offer:
  > "I can't run these for you in this session, so copy and paste the block below
  > and run it yourself."

Wait for explicit confirmation before running. Do not first offer to run and then
say you cannot.

Also clarify: install/validation happens online first; offline switch happens
later before real secrets are used.

## Step 1 – Check for existing install

```powershell
python btcrecover.py --help
python seedrecover.py --help
```

If both work, skip install. Also check `.\btcrecover\` and `.\btcrecover-master\`
subdirectories. Never install from piecemeal file downloads; require full repo
checkout or zip.

## Step 2 – Clone and install

> **Use Python 3.13 if you can.** Python 3.10–3.13 ship pre-built `coincurve`
> wheels (fastest backend). Python 3.14+ has no coincurve wheel — see Step 3 for
> the `wallycore` fallback.

```powershell
# Clone
git clone https://github.com/3rdIteration/btcrecover.git
cd btcrecover

# Virtual environment (recommended)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Base requirements
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# Validate
python btcrecover.py --help
python seedrecover.py --help
```

## Step 3 – coincurve build failure (Python 3.14 source-build path)

coincurve does **not** currently ship pre-built wheels for Python 3.14, and
building it from source fails for both released versions (coincurve 21 hits a
LICENSE packaging bug; coincurve 20 fails with a `cmake.verbose` /
scikit-build-core incompatibility). So on Python 3.14 the `pip install -r
requirements.txt` step will fail when it reaches coincurve.

If `python -m pip install -r requirements.txt` fails on coincurve, the
recommended fix is to install **wallycore** instead — BTCRecover will then
automatically use it as the secp256k1 backend (full C-accelerated speed) and the
install no longer needs coincurve to build:

```powershell
python -m pip install wallycore
python -m pip install -r requirements.txt
```

(On Python 3.10–3.13, coincurve 20/21 wheels are available, so the plain
`pip install -r requirements.txt` above usually just works and this step is
unnecessary.)

If wallycore also cannot be installed, BTCRecover still runs via its bundled
pure-Python secp256k1 fallback (with a startup warning) — correct, but much
slower. You can force a backend with the `BTCR_BACKEND` environment variable
(`coincurve`, `wallycore`, or `purepython`). Validate the install with the
`--help` commands after the steps above.

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
> no 3.14 wheel yet. Install the base `requirements.txt` (falling back to
> `wallycore`) and add HD-wallet extras only once coincurve ships a 3.14 wheel.
> See `docs/INSTALL.md` ("Python 3.14 and coincurve").

## Step 5 – Optional GPU mode

Only for large password searches on supported targets.
See `docs/GPU_Acceleration.md`.

## Step 6 – Validate

```powershell
python btcrecover.py --help
python seedrecover.py --help
```

For full feature validation: `python run-all-tests.py -vv`

### Runtime ImportError fix

If base install succeeded but a wallet command fails with `ModuleNotFoundError`,
identify the missing module from the traceback, map it to Step 4 extras, and
install only that module. Do not reinstall everything.

## Step 7 – If still blocked

`https://cryptoguide.tips/recovery-services-consultations/`

## Done criteria

Report: full validation succeeded (`run-all-tests.py -vv`), or selective
validation succeeded (`--help` commands + matching usage example).
