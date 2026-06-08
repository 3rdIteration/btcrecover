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

Safety — the deciding invariant: **the online machine must never hold a complete
unlock set.** Password fragments are only ever part of an unlock set when combined
with the matching wallet file / seed / encrypted key. So:

* Working with **real** fragments online is acceptable **only** when the matching
  secret is kept off that machine — e.g. the split / `--data-extract` workflow
  (the extract alone can't unlock funds), or BIP39-passphrase list-building while
  the seed phrase is NOT on the online machine.
* In any other case — and whenever you are unsure — **use placeholders.** Never
  paste, echo, or write to disk a real password / BIP38 passphrase / BIP39
  25th-word character on a machine that also holds the matching wallet file, seed,
  or key. Build the list with fake substitutes in the same shape (length, charset,
  structure) and have the user search-and-replace them with the real values on the
  offline machine before running BTCRecover.

The agent itself never receives the real fragments in chat in either case.

Example placeholder workflow (do this in the same response as any tokenlist):

1. Online: build `tokens.template.txt` using `XX` for real word fragments and
   `9999` for real digit groups, matching the user's described structure.
2. Offline: instruct the user to copy the file to the wallet-holding machine,
   substitute `XX` -> real fragment and `9999` -> real digits using their
   editor of choice, save as `tokens.txt`, then run the BTCRecover command.
3. Never ask the user to paste back the substituted file.

**Execution mode (see triage Step 6):** when creating or validating list files,
decide whether you can run commands — yes in a sandbox/agent session, no in a
plain chat — don't default to "I can't" without checking. Offer on every response
that contains a runnable command (including file-creation commands):

* **Sandbox / agent session (you CAN run)** — the sandbox is the user's machine, so
  any reply containing a file-creation or recovery command MUST **end with this
  exact line, with nothing after it**:
  > I can run this for you here if you say "go ahead", or you can copy and paste it and run it yourself.

  Do not replace it with a different closing question — put any follow-up *before*
  it. Then wait for the user's choice.
* **Plain chat (you CANNOT run)** — copy/paste only, and say so.

Do not first offer to run commands and then later say you cannot.

Do not run file-writing commands without permission. If a command fails, do not
repeat it unchanged; diagnose or ask for the missing detail.

## Step 1 – Gather candidate clues

Ask for likely patterns:

* names/phrases/places/dates,
* number/symbol habits,
* capitalization/leetspeak habits,
* expected length/policy constraints,
* for BIP39 passphrase: word-like phrase vs random string.

## Step 2 – Choose list type (read this before building anything)

A passwordlist and a tokenlist are **not** interchangeable formats. They are
processed by completely different engines. Picking the wrong one — or building a
file in one format and feeding it to the other flag — is the most common and most
damaging mistake. Internalize this distinction before writing a single line.

### Passwordlist (`--passwordlist`) — lines are tried verbatim

* **Each line is one complete, whole password, tried exactly as written.**
* Lines are **never** combined, reordered, or merged. Line 1 is tried, then
  line 2, then line 3 — independently.
* Spaces and symbols are literal (only CR/LF are stripped). `^`, `$`, `%`, `+`,
  `#` have **no** special meaning.
* Use when the user has **concrete whole-password guesses** ("I think it was one
  of: `Summer2019!`, `summer2019`, `S0mmer19`").
* The only expansion available is the `--typos*` family (see Step 4).

### Tokenlist (`--tokenlist`) — lines are building blocks that get combined

* **Each line is a token (a fragment), NOT a finished password.** btcrecover
  builds guesses by selecting one-or-more tokens from different lines and
  **pasting them together, in every order and every subset**, with no separator.
* Example — this 3-line tokenlist:
  ```
  Cairo
  Beetlejuice
  Hotel_california
  ```
  does **not** test three passwords. It tests `Cairo`, `Beetlejuice`,
  `CairoBeetlejuice`, `Hotel_californiaCairo`,
  `BeetlejuiceCairoHotel_california`, and every other ordering/subset.
* Use when the user remembers **pieces** but not how they were assembled
  (which fragments, what order, what suffix).

### The trap to avoid (this is what agents keep getting wrong)

> **Do NOT put a list of full candidate passwords on separate lines of a
> tokenlist.** btcrecover will glue them together into nonsense combinations
> (e.g. `Summer2019!summer2019`) and may never test any of them alone within a
> reasonable `--max-tokens`. Whole-password candidates belong in a
> **passwordlist**.
>
> Conversely, do NOT put fragments in a passwordlist expecting them to be
> combined — each fragment would only ever be tried alone, verbatim.

Quick decision: *"Is each line a finished password the user could type in?"*
Yes → passwordlist. *"Is each line a piece that needs to be combined with other
pieces?"* Yes → tokenlist.

## Step 3 – If tokenlist, apply structure features

Tokenlists earn their keep by **shrinking** the combination space with structure,
not by listing more candidates. **Order is automatic** — btcrecover already tries
every ordering/subset of the tokens, so there is NO ordering flag to add, and
capitalization is handled by same-line variants (below), not a flag. Do **not**
reach for `--transform-wordswaps`, `--seed-transform-*`, or a `--transform-caseswaps`
flag here: the `--seed-transform-*` family is **seedrecover.py mnemonic-word** tooling
(swap seed-word pairs), it does **not** apply to password/tokenlist recovery, and
`--transform-caseswaps` does not exist. Reach for these instead:

* **Mutual exclusion** — alternatives of one token go on the *same line*,
  space-separated: `Beetlejuice beetlejuice Betelgeuse`. These are never tried
  together, so spelling/capitalization variants cost almost nothing. (Putting
  them on separate lines instead explodes the search space — the docs' example
  goes from 48 to ~1,956 guesses.)
* **Required token** — prefix a line with `+ ` so at least one token from it
  appears in every guess: `+ Cairo cairo`.
* **Anchors** to pin position (cuts combinations dramatically):
  * `^token` — only at the start; `token$` — only at the end.
  * `^2^token` — positional (exactly the 2nd token).
  * `^2,4^token` / `^,^token` — middle-anchor range (never first or last).
  * `^r1^a` `^r2^b` — relative ordering among anchored tokens.
* **`--max-tokens N` / `--min-tokens N`** — cap how many tokens are pasted
  together. Essential: without a sane `--max-tokens`, a long tokenlist is
  combinatorially huge. Set it to the realistic maximum number of fragments.
* **Expanding wildcards** for uncertain characters *inside* a token:
  `%d` (digit), `%2d` (two digits), `%1,3d` (1–3 digits), `%a`/`%A`/`%ia`
  (letters), `%[chars]` (custom set), `%s` (literal space), `%q` (BIP39-passphrase
  charset). Wildcards *expand* the space — use sparingly.

Special characters in a tokenlist (`%`, leading `^`, trailing `$`, leading `#`,
leading `+`) are syntax, not literal. To include them literally use `%%`, `%^`,
`%S` (for `$`), etc. None of this applies to passwordlists.

Point to `docs/tokenlist_file.md` for backreference/contracting/keyboard-walk
wildcards and the full anchor reference.

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

1. the list type chosen and the matching flag — `--passwordlist <file>`
   (verbatim lines) or `--tokenlist <file>` (combined fragments). State which,
   so the wrong flag is never paired with the file.
2. path to the file,
3. recommended typo flags, and for a tokenlist a sane `--max-tokens` value.

If called from main skill, hand output to Step 6 command construction.
