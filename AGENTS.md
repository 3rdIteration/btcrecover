# Repository Instructions

## Code Quality
- Ensure that all code changes conform to PEP 8 guidelines, including converting any tab-based indentation to spaces.

## Required Tests
- Always run `python run-all-tests.py` before completing work on this repository.

## WalletFinder Exclusion List
- `walletfinder.py` skips the repository's own test wallets and example seed/key files (so `python walletfinder.py --folder .` stays clean) using the path substrings in [`walletfinder-exclusionlist.txt`](walletfinder-exclusionlist.txt).
- If you **add, remove, or rename repo files** that contain example seeds, private keys, or wallet files (e.g. under `docs/`, `lib/`, `btcrecover/test/`), regenerate the list so a repo scan still reports zero matches:
  ```
  python walletfinder.py --update-exclusions
  ```
  This rescans the repo and unions any newly-matching files into the exclusion list (existing/hand-added entries are preserved). Commit the updated `walletfinder-exclusionlist.txt`.

## AI-Assisted Recovery Skill
- If you are an AI agent helping a user **recover a wallet** with BTCRecover (rather than making code changes), follow the workflow in [`SKILL.md`](SKILL.md) at the repository root.
- For installation guidance on where to drop `SKILL.md` for Claude Code, GitHub Copilot, ChatGPT or Cline, see [`docs/AI_Assisted_Recovery.md`](docs/AI_Assisted_Recovery.md).

