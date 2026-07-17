---
name: install-btcrecover-termux
description: Install BTCRecover on Android via Termux, including pkg prerequisites, libsodium setup, and known Android limitations (no GPU acceleration).
---

# Install BTCRecover — Termux (Android)

Primary docs: `docs/INSTALL.md`.

Termux support is experimental. GPU acceleration is not available on Android.
Large searches will be slow due to mobile CPU constraints.

## Step 0 – Safety and execution mode

**Execution mode (see triage Step 6):** decide whether you can run commands — yes
in a sandbox/agent session, no in a plain chat — don't default to "I can't"
without checking. Offer on every response that contains a runnable command:

* Can run **AND** the sandbox is the user's Termux/Android shell → offer both:
  > "I can run these for you here if you say 'go ahead', or you can copy and paste
  > them and run them yourself."
* Can't run, **OR** the sandbox OS differs from the user's phone → copy/paste only
  — this is correct, not a missing offer:
  > "I can't run these for you in this session, so copy and paste the block below
  > and run it yourself."

Wait for explicit confirmation before running. Do not first offer to run and then
say you cannot.

## Step 1 – Storage permission

```bash
termux-setup-storage
```

## Step 2 – Install prerequisites

```bash
pkg update
pkg install -y python git libsodium libffi clang
```

## Step 3 – Clone and install

```bash
git clone https://github.com/3rdIteration/btcrecover.git
cd btcrecover

pip install --upgrade pip
pip install -r requirements.txt

# Validate
python btcrecover.py --help
python seedrecover.py --help
```

## Step 4 – Full requirements (when targeted extras are not sufficient)

**Avoid `requirements-full.txt` on Termux.** Its `bip-utils` package
hard-requires `coincurve`, which cannot be installed on Android/aarch64 (see the
backend note below), so the full requirements will fail to install. Install the
base `requirements.txt` and add targeted extras (Step 5) only.

If you do attempt the full requirements, ensure libsodium is installed and set
the environment variable before installing, and build maturin from source first
(the pre-built maturin wheel does not work on Termux):

```bash
export ANDROID_API_LEVEL=24
export SODIUM_INSTALL=system
pip install maturin --no-binary maturin
pip install py-sr25519-bindings==0.2.3 --no-build-isolation
pip install -r requirements-full.txt
```

## Step 5 – Targeted extras

For specific wallet types not covered by base requirements:

* SLIP39: `pip install "shamir-mnemonic[cli]"`
* BIP38/block.io: `pip install ecdsa`
* Ethereum UTC/JSON keystore: `pip install eth-keyfile`

## Step 6 – Known limitations

* GPU acceleration not available on Android.
* **coincurve does not work on Termux at all** — even when built from source,
  `import coincurve` fails with `cannot locate symbol "_Py_NoneStruct"`
  (ofek/coincurve#189). `wallycore` also has no aarch64 wheel. So BTCRecover runs
  on the **bundled pure-Python** secp256k1 backend, which is correct but ~100×
  slower for public-key derivation.
* `requirements-full.txt` cannot install on Termux because `bip-utils` needs
  coincurve — stick to the base requirements + targeted extras.
* Large password/seed searches will be significantly slower than on a desktop
  (slow CPU **and** the pure-Python backend).

## Step 7 – Validate

```bash
python btcrecover.py --help
python seedrecover.py --help
```

## Step 8 – If still blocked

`https://cryptoguide.tips/recovery-services-consultations/`

## Done criteria

Report: selective validation succeeded (`--help` commands + matching usage example).
Full test suite (`run-all-tests.py -vv`) may not complete successfully on Android
due to platform limitations.
