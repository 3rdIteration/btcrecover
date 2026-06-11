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

If `python -m pip install -r requirements.txt` fails on coincurve (a wall of C/C++
errors ending in "Microsoft Visual C++ 14.0 or greater is required" / "Failed to
build coincurve"), the **first and usually only fix** is to pin coincurve to a
version with a prebuilt wheel, which skips the compile entirely:

```powershell
python -m pip install coincurve==20.0.0
python -m pip install -r requirements.txt
```

Do this BEFORE suggesting anything heavier. The build error itself tells the user to
install Visual C++ Build Tools — mention that (and downgrading Python) only as a
fallback if the pin above does not work, NOT as the first step. If a user asks
specifically whether a coincurve version works on Windows, the answer is yes:
`coincurve==20.0.0`. After it succeeds, validate with the `--help` commands.

## Step 4 – Targeted extras (add only what the wallet type needs)

After base install, add extras only when needed:

* SLIP39: `pip install "shamir-mnemonic[cli]"`
* BIP38/block.io: `pip install ecdsa`
* Ethereum UTC/JSON keystore: `pip install eth-keyfile`
* Groestlcoin BIP39: `pip install groestlcoin-hash`
* Cosmos/Polkadot/Solana/Tezos/Tron/Avalanche/Secret/Elrond:
  `pip install py-crypto-hd-wallet`

Use `requirements-full.txt` for multi-package installs or unclear wallet type.

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
