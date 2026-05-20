---
name: install-btcrecover
description: Install BTCRecover on the user's machine (Windows, Linux, macOS, or Android/Termux), always installing base requirements first and then adding wallet-type-specific extras (or full requirements when needed), plus optional GPU acceleration. Detects the OS, checks whether BTCRecover is already runnable, and only installs what is needed. Invoke from the main BTCRecover recovery skill (Step 3) or any time a user needs BTCRecover installed before doing anything else.
---

# Install BTCRecover Skill

This skill installs BTCRecover ([https://github.com/3rdIteration/btcrecover](https://github.com/3rdIteration/btcrecover))
on the user's machine and verifies it can run. It is a sub-skill of the main
BTCRecover recovery skill ([`SKILL.md`](../../SKILL.md), Step 3) and can also
be used standalone.

The canonical install instructions live in
[`docs/INSTALL.md`](../../docs/INSTALL.md). Read it when you need detail
beyond what's summarised here.

---

## When to invoke

* The main BTCRecover skill is about to construct a `btcrecover.py` or
  `seedrecover.py` command and needs the tool to be installed.
* The user explicitly asks how to install BTCRecover.
* A previous install attempt failed and the user needs help debugging it.

## Step 0 – Safety warning + choose install route

Before running any installation steps, clearly warn the user:

* Letting an AI install BTCRecover entirely on its own is **very dangerous**,
  especially on an everyday/personal PC.
* Automatic installs can execute commands the user does not fully review.
* Encourage an offline/dedicated machine for wallet-recovery work whenever
  possible.
* Clarify timing: installation, dependency downloads, and validation commands
  are done while online first; the offline/disconnect step comes later in the
  main skill right before any real secrets are entered.

Then offer exactly two routes and let the user choose:

1. **Guided route (recommended):**
   * Walk through the official docs in [`docs/INSTALL.md`](../../docs/INSTALL.md).
   * Provide commands for the user to copy/paste manually.
   * Help debug any command failures step-by-step.
2. **Automatic route (higher risk):**
   * The AI executes install commands for them.
   * Use only if they explicitly accept the risk.

## Step 1 – Check whether BTCRecover is already installed

Before telling the user to clone/install anything, check whether BTCRecover
is already present and runnable in the current workspace:

1. **If the current directory already looks like BTCRecover** (it contains
   `btcrecover.py` and `seedrecover.py`), use it directly.
2. **If not**, check for sibling folders named `btcrecover` or
   `btcrecover-master` in the current working directory and `cd` into
   whichever exists.
3. **Quick-run check using the basic usage entry points:**
   * `python btcrecover.py --help`
   * `python seedrecover.py --help`

   If both commands show usage/help text, BTCRecover is installed enough to
   proceed; **do not reclone or reinstall** unless the user hits dependency
   errors.
4. If neither the current directory nor `./btcrecover` / `./btcrecover-master`
   is usable, continue with a fresh install below.

## Step 2 – Detect the OS

Detect the OS programmatically before giving instructions. Examples:

* Python: `import platform; platform.system()` → `Windows` / `Linux` /
  `Darwin`.
* Shell: `uname -a`, or check `$PREFIX` containing `com.termux` for Termux.

## Step 3 – Choose dependency scope from wallet type (targeted mode)

### 3a) Identify wallet type before installing extras

Use the wallet type already collected in the main skill Step 1 triage when
available.
If it is not already known, ask now before installing anything beyond base:

* "What wallet type / chain are you recovering (for example: Bitcoin Core,
  Electrum, BIP38 key, Ethereum keystore, SLIP39, Cardano, Solana, etc.)?"

### 3b) Always install base requirements first

Install [`requirements.txt`](../../requirements.txt) for **every** recovery.
It is always required.

### 3c) After base install, add only the extra module(s) needed for that wallet

Prefer targeted installs (one package at a time) when possible.
This mapping is based on [`docs/INSTALL.md`](../../docs/INSTALL.md) ("Wallet
Python Package Requirements") and BTCRecover runtime dependency checks in
[`btcrecover/btcrseed.py`](../../btcrecover/btcrseed.py) /
[`btcrecover/btcrpass.py`](../../btcrecover/btcrpass.py). Keep this section in
sync with those files when wallet dependency checks change.

* **Bitcoin Core / Electrum / MultiBit / Blockchain.com / most standard BTC/ETH password recoveries** → no extra install after `requirements.txt`
* **SLIP39 share recovery** → `pip install "shamir-mnemonic[cli]"`
* **BIP38 / block.io** → `pip install ecdsa`
* **Ethereum UTC/JSON keystore file recovery** → `pip install eth-keyfile`
* **Groestlcoin BIP39 recovery** → `pip install groestlcoin-hash`
* **Cosmos / Polkadot / Solana / Tezos / Tron / Avalanche / Secret Network / Elrond** → `pip install py-crypto-hd-wallet`

Note: for `shamir-mnemonic[cli]`, quote the package spec in shells like
`bash`/`zsh` that glob `[]`; Windows CMD/PowerShell usually do not require
quotes.

Use [`requirements-full.txt`](../../requirements-full.txt) when the recovery
needs multiple coupled extras or build-sensitive packages (for example:
Cardano, Helium, Ethereum validator seed recovery, MetaMask/BitGo paths), or
when the wallet type is unclear and targeted installs are likely to miss
dependencies.

Here, "multiple coupled extras" means wallet types that depend on several
inter-related packages that are commonly installed together, not just one
standalone module.

## Step 4 – Install for the user's OS

### Windows

1. Install Python (from the Microsoft Store, 3.10–3.14 supported).
2. `git clone https://github.com/3rdIteration/btcrecover/` (or download the
   master zip).
3. `pip install -r requirements.txt` (always).
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
2. If you plan to use `requirements-full.txt`, also install Rust:
   `curl https://sh.rustup.rs -sSf | sh` and restart the terminal.
3. `pip3 install -r requirements.txt` (always). If full requirements are
   needed and fail, also run
   `export PYTHON=/opt/homebrew/bin/python3`.

### Android / Termux (experimental)

```
pkg install python-pip git autoconf automake build-essential libtool pkg-config llvm lld rust libsodium
pip install -r requirements.txt
```

If `requirements-full.txt` is needed on Termux:

```
export ANDROID_API_LEVEL=24
export SODIUM_INSTALL=system
pip install maturin --no-binary maturin
pip install py-sr25519-bindings==0.2.3 --no-build-isolation
pip install -r requirements-full.txt
```

Warn the user that Termux is experimental, slow, and may overheat the
phone.

After base install, run the targeted extra package install chosen in Step 3c.
Only use the full requirements flow above when Step 3c calls for
`requirements-full.txt`.

## Step 5 – Optional GPU acceleration

For supported wallets/typos, GPU mode can be 10–100× faster. See
[`docs/GPU_Acceleration.md`](../../docs/GPU_Acceleration.md). Only suggest
this for genuinely large password searches.

## Step 6 – Verify the install

Choose the validation method based on what was installed:

* **If `requirements-full.txt` was installed** (or the user explicitly wants to
  validate the full feature set), run the repo's smoke test:
  `python run-all-tests.py -vv`. It should finish without errors. If a
  specific test module fails for an optional dependency the user does not
  need, explain which feature it gates.
* **If only `requirements.txt` plus one/few targeted extras were installed**,
  do **not** require the full smoke test. Instead, validate with:
  * `python btcrecover.py --help`
  * `python seedrecover.py --help`
  * one relevant command from the basic usage examples in
    [`docs/Usage_Examples/`](../../docs/Usage_Examples/) that matches the
    user's recovery type

For selective installs, pick the example that exercises the feature they
actually need (for example a BIP38 example for `ecdsa`, an Ethereum keystore
example for `eth-keyfile`, or a SLIP39 example for `shamir-mnemonic`).

## Step 7 – If install or commands still fail

If the user is still blocked because install steps or basic commands (like
`python btcrecover.py --help` / `python seedrecover.py --help`) are not
working, suggest a private support consultation or trusted recovery service:

<https://cryptoguide.tips/recovery-services-consultations/>

## When you're done

Confirm to the user (or to the caller) that the chosen validation succeeded:

* for full installs, `python run-all-tests.py -vv` completed successfully; or
* for selective installs, `btcrecover.py --help` / `seedrecover.py --help`
  worked and the matching basic usage example ran successfully.

If invoked from the main BTCRecover skill, control then continues at Step 4
(take the system offline).
