---
name: install-btcrecover
description: Routes to the OS-specific BTCRecover installation skill. Detect the OS first, then load the matching sub-skill.
---

# Install BTCRecover — OS Router

**There is no PyPI package — never `pip install btcrecover`.** BTCRecover is
installed by cloning/downloading the full repository
(`git clone https://github.com/3rdIteration/btcrecover.git`) and then installing
its `requirements.txt` into a virtual environment. Never install from piecemeal
file downloads.

**Recommended Python version: 3.13.** Python 3.10–3.13 ship pre-built `coincurve`
wheels, so the default install uses the fastest secp256k1 backend. Python 3.14
and later (e.g. 3.15) currently have **no** `coincurve` wheel, so the default
install cannot use coincurve there — you must install `wallycore` or accept the
slower pure-Python fallback, and `requirements-full.txt` won't install until a
coincurve wheel exists. See `docs/INSTALL.md` ("Recommended Python version" and
"Python 3.14 and coincurve").

**Pick the OS from the environment you are actually in — do not ask when you can
tell.**

* **Sandbox / agent session:** the sandbox IS the user's machine. Detect its OS and
  load the matching sub-skill WITHOUT asking. It is normally Linux:
  ```bash
  uname -a
  cat /etc/os-release   # e.g. Ubuntu -> load the linux sub-skill
  ```
* **Plain chat (no sandbox):** the OS is whatever the user describes. Read shell cues
  from their pasted prompt (below) and load the matching sub-skill; ask one short
  confirmation question only if it is still ambiguous.

Load the matching sub-skill:

* Windows PowerShell: `load_skill("skills/install-btcrecover/windows/SKILL.md")`
* Linux/Ubuntu/Debian: `load_skill("skills/install-btcrecover/linux/SKILL.md")`
* macOS: `load_skill("skills/install-btcrecover/macos/SKILL.md")`
* Termux (Android): `load_skill("skills/install-btcrecover/termux/SKILL.md")`

Shell identification cues (from prompt or user description):

* `PS C:\>` or `C:\>` => Windows; use PowerShell skill.
* `$` / `%` with POSIX paths, `apt`/`apt-get` available => Linux.
* `brew` available or `/opt/homebrew` path => macOS.
* `pkg` available or `~ $` on phone => Termux.
