---
name: locate-wallet-file
description: Locate encrypted wallet files by content fingerprints (not filename), returning candidate paths without exposing wallet contents.
---

# Locate Wallet File Skill

Use this when the user cannot find wallet files or suspects renamed files.

Safety: scanning can be guided online as long as file contents are not pasted
into chat and never leave the user's machine.

**Execution mode (see triage Step 6):** before any local scan, decide whether you
can run commands — yes in a sandbox/agent session, no in a plain chat — don't
default to "I can't" without checking. Offer on every response that contains a
runnable scan command:

* Can run **AND** the sandbox OS matches the user's machine → offer both:
  > "I can run the scan commands for you here if you say 'go ahead', or you can
  > copy and paste them and run them yourself."
* Can't run, **OR** the sandbox OS differs from the user's machine → copy/paste
  only — this is correct, not a missing offer:
  > "I can't run these for you in this session, so copy and paste the block below
  > and run it yourself."

Do not first offer to run commands and then later say you cannot.

Use OS-matching commands only (POSIX paths for Linux/macOS/Termux; PowerShell
paths and syntax for Windows). If a scan command fails, do not repeat it
unchanged; diagnose the error or narrow the scan path.

## When to invoke

* User does not know wallet location.
* User has backup folders/drives and wants wallet detection.
* User has ambiguous file names/extensions.

## Required user input

1. Path(s) to scan (do not default to full filesystem).
2. Suspected wallet software/chain if known.
3. Permission to read files in those paths.

Hard rule: do not emit any `btcrecover.py` or `seedrecover.py` command for a
wallet-file path until this skill has returned a confirmed file path. If the
user asks for the recovery command first, stop and complete the locate step.
If no candidate is found, do not invent a placeholder `--wallet` path; report
the locations scanned and the next places to try.

## Fingerprint-first identification

Do not rely on filenames. Use internal signatures validated against samples in
`btcrecover/test/test-wallets/`.

Core fingerprints to check:

* Core wallets (BTC/LTC/DOGE): Berkeley DB signatures and key markers.
* Electrum: JSON wallets or encrypted `BIE1` prefix.
* MultiBit HD: `mbhd.wallet.aes` binary patterns.
* bitcoinj/MultiBit Classic: protobuf headers.
* Blockchain.com: JSON containing `version`, `pbkdf2_iterations`, `payload`
  (often filename `wallet.aes.json`).
* Bither / mSIGNA: SQLite header then wallet-specific table names.
* MetaMask vault: JSON with `data`, `iv`, `salt`.
* Ethereum UTC keystore: version 3 JSON with `crypto` fields.
* BIP38 key material: text beginning with `6P`.

## Search workflow

1. Confirm scan paths and execution mode (agent-run vs user-run commands).
2. Combine filename hints and content fingerprint checks.
3. Return candidate paths plus matched fingerprint type.
4. Never print wallet contents in chat.
5. Ask user to confirm which candidate is the target wallet.

## Done criteria

Return confirmed wallet file path.
If split workflow is in use, next step is extract-script/data-extract guidance,
not wallet file sharing.
If none matched, report scanned paths and suggest likely additional locations
(cloud sync, phone backups, external drives, exported keystore folders).
