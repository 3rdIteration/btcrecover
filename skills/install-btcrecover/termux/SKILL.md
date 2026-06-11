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

For wallets requiring `requirements-full.txt`, ensure libsodium is installed
and set the environment variable before installing:

```bash
SODIUM_INSTALL=system pip install -r requirements-full.txt
```

## Step 5 – Targeted extras

For specific wallet types not covered by base requirements:

* SLIP39: `pip install "shamir-mnemonic[cli]"`
* BIP38/block.io: `pip install ecdsa`
* Ethereum UTC/JSON keystore: `pip install eth-keyfile`

## Step 6 – Known limitations

* GPU acceleration not available on Android.
* Some cryptographic packages may fail to build from source; try targeted extras
  before falling back to requirements-full.txt.
* Large password/seed searches will be significantly slower than on a desktop.

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
