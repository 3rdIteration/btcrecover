---
name: build-password-tokenlist
description: Help a user build a passwordlist or tokenlist (and choose typo rules) for BTCRecover password / passphrase recovery. Walks the user through brainstorming password fragments, choosing between a passwordlist and a tokenlist, using anchors (^/$) and wildcards (%d, %a, %i, %c), and picking typo flags (--typos-insert, --typos-replace, --typos-delete, --typos-case, etc.) with sensible defaults. Invoke from the main BTCRecover recovery skill (Step 5a) for `btcrecover.py` password recovery or `seedrecover.py` BIP39 passphrase recovery.
---

# Build Password / Tokenlist Skill

This skill helps an AI agent build the candidate-password input file that
BTCRecover uses to test guesses. It is a sub-skill of the main BTCRecover
recovery skill ([`SKILL.md`](../../SKILL.md), Step 5a) and can also be used
standalone.

It applies to:

* `btcrecover.py` — wallet **password / passphrase** recovery (and BIP38).
* `seedrecover.py --passphrase-arg …` — BIP39 **passphrase** ("25th word")
  recovery.

Authoritative docs:

* [`docs/passwordlist_file.md`](../../docs/passwordlist_file.md)
* [`docs/tokenlist_file.md`](../../docs/tokenlist_file.md)
* [`docs/Typos_Quick_Start_Guide.md`](../../docs/Typos_Quick_Start_Guide.md)

> **Safety.** Password fragments alone are not enough to unlock a wallet
> without the wallet file or mnemonic, so this skill is safe to run online
> (e.g. on a cloud agent) even when the rest of the recovery is split
> across machines (see Step 4a of the main `SKILL.md`).

---

## Step 1 – Brainstorm with the user

Ask the user what they think they may have used. Useful prompts:

* Names, nicknames, pets, family, places, dates significant to them.
* Years, birthdates, anniversaries, phone numbers (or fragments).
* Symbols and punctuation they tend to use (`!`, `@`, `#`, `_`, `-`, `.`,
  `$`, etc.).
* Capitalisation habits (always-lowercase, TitleCase, leetspeak, etc.).
* Length they usually use, and any required-character policies the wallet
  might have enforced.
* For BIP39 passphrases, ask whether the user remembers it being a single
  word, a phrase, or random characters.

## Step 2 – Choose passwordlist vs tokenlist

Build **one** of the following:

* **Passwordlist** — a plain text file with **one full candidate password
  per line**. Best when the user has a small number of fully-formed
  guesses. Documented in
  [`docs/passwordlist_file.md`](../../docs/passwordlist_file.md).
* **Tokenlist** — a text file where each line is a "token" (piece) that may
  appear in the password, optionally with anchors and wildcards. Best when
  the user remembers building blocks (a name, a year, a symbol, etc.) but
  not the exact composition. Documented in
  [`docs/tokenlist_file.md`](../../docs/tokenlist_file.md).

Guidance:

* If the user can list ≲ a few hundred specific full passwords → passwordlist.
* If the user remembers fragments and how they tend to combine them →
  tokenlist (much more powerful, but the search space grows fast).

## Step 3 – Tokenlist anchors and wildcards (only when building a tokenlist)

* **Alternatives on one line** are separated by spaces — any of them may
  appear at that position. Example: `summer winter spring autumn`.
* **Positional anchors:**
  * `^token` — token must appear at the **start** of the password.
  * `token$` — token must appear at the **end** of the password.
  * `^2^token` — token must appear at position 2.
* **Wildcards** (placed inside a token, e.g. `mydog%d%d`):
  * `%d` — any digit `0-9`.
  * `%a` — any lowercase letter `a-z`.
  * `%A` — any uppercase letter `A-Z`.
  * `%i` — any letter, case-insensitive.
  * `%c` — any printable character.
  * `%s` — any whitespace character.

See [`docs/tokenlist_file.md`](../../docs/tokenlist_file.md) for the full
syntax (including `%[abc]` custom sets, repeat counts like `%2d`, and the
`+` "must appear" marker).

## Step 4 – Pick typo rules

Typos let BTCRecover mutate each candidate before testing it. Per the
[Typos Quick Start Guide](../../docs/Typos_Quick_Start_Guide.md):

* `--typos-insert %q` and `--typos-replace %q` (where `%q` is the wildcard
  for "any printable character") together with `--typos-delete` are good
  default starting points. They cover the three most common keyboard
  mistakes: an extra character, a wrong character, and a missing character.
* `--typos N` caps the total typos per candidate. `--typos 2` is generally
  the largest count that is computationally practical on a single CPU.
  Start with `--typos 1` for a quick first pass, then escalate to
  `--typos 2`.
* Add `--typos-case` / `--typos-closecase` / `--typos-capslock` if the user
  thinks they may have shift / caps-lock issues.
* Cap exploding typo categories with `--max-typos-insert`,
  `--max-typos-replace`, `--max-typos-delete` (each often set to 1 or 2) so
  the search space stays bounded.
* Use `--autosave autosave.bin` for long runs so progress survives a crash
  or reboot.

## Step 5 – Sanity-check the search size

Before kicking off a real run, estimate the search size:

* BTCRecover prints a candidate count and ETA on startup — let the user see
  it.
* For a quick offline estimate, run on a small subset with
  `--no-eta --listpass | wc -l` to count candidates.

If the ETA is unreasonable (days/weeks), help the user **trim** the
token/typo set rather than starting a doomed run. Typical trim moves:

* Remove low-probability tokens.
* Tighten `--typos N` from 2 to 1.
* Cap `--max-typos-insert`, `--max-typos-replace`, `--max-typos-delete`.
* Drop `--typos-case` if capitalisation is well-known.

## When you're done

Hand the caller (or the user) two things:

1. The path to the passwordlist or tokenlist file.
2. The typos flags you recommend, e.g.:

   ```
   --typos 2 --typos-insert %q --typos-replace %q --typos-delete \
       --max-typos-insert 1 --max-typos-replace 1 --max-typos-delete 1
   ```

If invoked from the main BTCRecover skill, control then continues at Step 6
("Construct (and optionally run) the BTCRecover command"). For a BIP39
passphrase, the same file is passed to `seedrecover.py` via its
`--passphrase-arg`-style options.
