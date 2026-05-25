---
name: locate-wallet-file
description: Locate encrypted wallet files by content fingerprints (not filename), returning candidate paths without exposing wallet contents.
---

# Locate Wallet File Skill

Use this when the user cannot find wallet files or suspects renamed files.

Safety: scanning can be guided online as long as file contents are not pasted
into chat and never leave the user's machine.

Before any local scan, explicitly offer both modes:

> "You have two options: (a) I can run the scan commands for you here if you
> say 'go ahead', or (b) you can copy and paste them and run them yourself."

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
