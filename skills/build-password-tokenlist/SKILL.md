---
name: build-password-tokenlist
description: Build a BTCRecover passwordlist or tokenlist with practical typo settings and search-space sanity checks for password/passphrase recovery.
---

# Build Password / Tokenlist Skill

Use this for:

* `btcrecover.py` password/passphrase recovery (including BIP38).
* `btcrecover.py --bip39` BIP39 passphrase (25th-word) recovery.

Docs:

* `docs/passwordlist_file.md`
* `docs/tokenlist_file.md`
* `docs/Typos_Quick_Start_Guide.md`

Safety: password fragments alone are generally safe to work with online if the
wallet file/mnemonic remains separate.

If creating or validating list files with tool access, explicitly offer both
modes:

> "You have two options: (a) I can create/check the tokenlist for you here if
> you say 'go ahead', or (b) you can copy and paste the content and commands
> yourself."

Do not run file-writing commands without permission. If a command fails, do not
repeat it unchanged; diagnose or ask for the missing detail.

## Step 1 – Gather candidate clues

Ask for likely patterns:

* names/phrases/places/dates,
* number/symbol habits,
* capitalization/leetspeak habits,
* expected length/policy constraints,
* for BIP39 passphrase: word-like phrase vs random string.

## Step 2 – Choose list type

* Passwordlist: full candidates, one per line; best when user has concrete
  guesses.
* Tokenlist: fragments + structure; best when user remembers building blocks.

## Step 3 – If tokenlist, apply structure features

Use concise syntax reminders:

* alternatives on same line (`a b c`),
* anchors (`^token`, `token$`, `^2^token`),
* common wildcards (`%d`, `%a`, `%A`, `%i`, `%c`, `%s`).

Point to docs for advanced wildcard syntax.

## Step 4 – Choose typo policy

Conservative defaults:

* start with `--typos 1`, then widen to `--typos 2` if needed,
* use `--typos-insert %q --typos-replace %q --typos-delete`,
* cap expansions with `--max-typos-*` (often 1 each),
* add case flags only when capitalization uncertainty is likely,
* use `--autosave autosave.bin` for long runs.

## Step 5 – Sanity-check search size

Before full run, check candidate volume/ETA.
If too large, trim low-probability tokens and/or typo breadth.

## Done criteria

Return:

1. path to passwordlist/tokenlist file,
2. recommended typo flags.

If called from main skill, hand output to Step 6 command construction.
