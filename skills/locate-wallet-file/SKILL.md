---
name: locate-wallet-file
description: Locate encrypted wallet files by content fingerprints (not filename), returning candidate paths without exposing wallet contents.
---

# Locate Wallet File Skill

Use this when the user cannot find wallet files or suspects renamed files.

Safety: scanning can be guided online as long as file contents are not pasted
into chat and never leave the user's machine.

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

## Search workflow

1. Confirm scan paths with user (do not default to full filesystem).
2. Run `python walletfinder.py --folder <path>` for wallet detection, or add
   `--mnemonic-mode` if searching for seed phrases instead.
3. Use `--depth N` to limit recursion when the target path is large; start with
   depth 1–2 and increase only if no candidates are found.
4. Return candidate paths plus matched wallet type from walletfinder output.
5. Never print wallet contents in chat.
6. Ask user to confirm which candidate is the target wallet.

If a scan fails, diagnose the error (permissions, path, depth) or narrow the
scan path rather than repeating the same command unchanged.

## Done criteria

Return confirmed wallet file path.
If split workflow is in use, next step is extract-script/data-extract guidance,
not wallet file sharing.
If none matched, report scanned paths and suggest likely additional locations
(cloud sync, phone backups, external drives, exported keystore folders).
