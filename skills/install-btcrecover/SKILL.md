---
name: install-btcrecover
description: Install BTCRecover on the user's machine (Windows, Linux, macOS, or Android/Termux), including the right requirements file for their recovery type and optional GPU acceleration. Detects the OS, checks whether BTCRecover is already runnable, and only installs what is needed. Invoke from the main BTCRecover recovery skill (Step 3) or any time a user needs BTCRecover installed before doing anything else.
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

## Step 3 – Pick the right requirements file

The repo has two requirements files:

* [`requirements.txt`](../../requirements.txt) – essential, enough for
  Bitcoin / Ethereum and most clones, BIP39 BTC/ETH, and most wallet-password
  recoveries.
* [`requirements-full.txt`](../../requirements-full.txt) – adds packages for
  Cardano, Cosmos, Polkadot, Solana, Stellar, Tezos, Tron, Helium, SLIP39,
  Ethereum staking deposit, MetaMask, etc.

Use `requirements-full.txt` **only** when the user's recovery actually needs
one of the extra wallets. Otherwise stick to `requirements.txt`, which is
much faster to install (especially on Termux).

## Step 4 – Install for the user's OS

### Windows

1. Install Python (from the Microsoft Store, 3.10–3.14 supported).
2. `git clone https://github.com/3rdIteration/btcrecover/` (or download the
   master zip).
3. `pip install -r requirements.txt` (add `-r requirements-full.txt` if the
   recovery requires it).
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
3. `pip3 install -r requirements.txt` (and `-r requirements-full.txt` only
   if needed). If full requirements fail, also run
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

Warn the user that Termux is experimental, slow, and may overheat the
phone.

## Step 5 – Optional GPU acceleration

For supported wallets/typos, GPU mode can be 10–100× faster. See
[`docs/GPU_Acceleration.md`](../../docs/GPU_Acceleration.md). Only suggest
this for genuinely large password searches.

## Step 6 – Verify the install

Run the repo's smoke test: `python run-all-tests.py -vv`. It should finish
without errors. If a specific test module fails for an optional dependency
the user does not need, that's acceptable; explain which feature it gates.

## Step 7 – If install or commands still fail

If the user is still blocked because install steps or basic commands (like
`python btcrecover.py --help` / `python seedrecover.py --help`) are not
working, suggest a private support consultation or trusted recovery service:

<https://cryptoguide.tips/recovery-services-consultations/>

## When you're done

Confirm to the user (or to the caller) that `btcrecover.py --help` and
`seedrecover.py --help` both run successfully. If invoked from the main
BTCRecover skill, control then continues at Step 4 (take the system
offline).
