---
name: install-btcrecover-linux
description: Install BTCRecover on Linux/Debian/Ubuntu including Python, pip, virtual environment, and externally-managed-environment workaround options.
---

# Install BTCRecover — Linux (Debian/Ubuntu)

Primary docs: `docs/INSTALL.md`.

## Step 0 – Safety and execution mode

**OS confirmation:** If running in a sandbox/docker environment, confirm the user
actually wants Linux installation (sandbox is always Linux, but user may be on
Windows or macOS — check the conversation context).

**Execution mode (see triage Step 6):** decide whether you can run commands — yes
in a sandbox/agent session, no in a plain chat — don't default to "I can't"
without checking. Offer on every response that contains a runnable command:

* Can run **AND** the sandbox is Linux (matches these commands) → offer both:
  > "I can run these for you here if you say 'go ahead', or you can copy and paste
  > them and run them yourself."
* Can't run, **OR** the sandbox OS differs from the user's machine → copy/paste
  only — this is correct, not a missing offer:
  > "I can't run these for you in this session, so copy and paste the block below
  > and run it yourself."

Wait for explicit confirmation before running. Do not first offer to run and then
say you cannot.

## Step 1 – Check for existing install

```bash
python3 btcrecover.py --help
python3 seedrecover.py --help
```

If both work, skip install. Also check `./btcrecover/` and `./btcrecover-master/`.
Never install from piecemeal file downloads; require full repo checkout or zip.

## Step 2 – Install

> **Use Python 3.13 if you can.** Python 3.10–3.13 ship pre-built `coincurve`
> wheels (fastest backend). Python 3.14+ has no coincurve wheel — see the
> Windows skill Step 3 / `docs/INSTALL.md` for the `wallycore` fallback.

Hand over this block whole — do not drop packages from the apt line or skip the
validation. `python3-tk` (seedrecover's GUI prompts) and `libffi-dev` (builds
native deps) are REQUIRED, not optional; do not tell the user to omit them. The
two `--help` lines are the mandatory install validation — always end with them.

```bash
# Prereqs (install all of these — python3-tk and libffi-dev are required)
sudo apt update
sudo apt install -y python3 python3-pip python3-venv python3-tk libffi-dev git

# Clone
git clone https://github.com/3rdIteration/btcrecover.git
cd btcrecover

# Virtual environment (preferred; avoids externally-managed-environment error)
python3 -m venv venv
source venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

# Validate (mandatory — confirms the install actually works)
python3 btcrecover.py --help
python3 seedrecover.py --help
```

## Step 3 – externally-managed-environment error

If the user explicitly rejects a venv and hits this error, present both options
and ask which they want before proceeding:

1. Recommended: create the venv (commands in Step 2 above).
2. Bypass: `python3 -m pip install --break-system-packages -r requirements.txt`
   (acknowledge the risk to system packages).

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

## Step 5 – Optional GPU mode (CUDA/OpenCL)

Only for large password searches on supported targets.
See `docs/GPU_Acceleration.md`.

## Step 6 – Validate

```bash
python3 btcrecover.py --help
python3 seedrecover.py --help
```

For full feature validation: `python3 run-all-tests.py -vv`

### Runtime ImportError fix

If base install succeeded but a wallet command fails with `ModuleNotFoundError`,
identify the missing module from the traceback, map it to Step 4 extras, and
install only that module. Do not reinstall everything.

## Step 7 – If still blocked

`https://cryptoguide.tips/recovery-services-consultations/`

## Done criteria

Report: full validation succeeded (`run-all-tests.py -vv`), or selective
validation succeeded (`--help` commands + matching usage example).
