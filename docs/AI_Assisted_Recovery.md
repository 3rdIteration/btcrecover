# AI-Assisted Recovery (using `SKILL.md`)

## Two ways to use AI for recovery help

There are two approaches:

1. Use a normal chat bot that helps you follow the documentation.
2. Use an AI CLI (coding) tool that can run commands, including BTCRecover installation and execution.

For a chat bot, you can simply prompt with:
**"Can you help me recover a wallet using https://github.com/3rdIteration/btcrecover/blob/master/SKILL.md"**

Or if you ave downloaded and unzipped BTCRecover, you can select the folder using something like Claude and prompt:
**"Can you help me recover a wallet using the Skill.md from this repository**

BTCRecover ships with a [`SKILL.md`](https://github.com/3rdIteration/btcrecover/blob/master/SKILL.md)
file at the root of the repository. It is a structured prompt that teaches an
AI coding agent how to triage a wallet-recovery situation, install BTCRecover,
take the user's system offline, collect wallet material, build a
`btcrecover.py` / `seedrecover.py` command, and finish up — all while avoiding
the common ways a user can leak their secrets to an online machine.

This page tells you **where to put `SKILL.md`** for the four AI agents the
skill has been tested against (and a generic fallback for anything else), and
gives the safety rules you should keep in mind no matter which agent you use.

> ⚠️ **Important — read this before you start.**
> AI agents will happily ask for your seed phrase, password, or wallet file.
> Never paste a real secret into a chat with a hosted / cloud agent. The
> `SKILL.md` workflow is *primarily* intended for a **local** agent (one
> running on your own machine), and *secondarily* for cloud agents under the
> split-workflow rules described in Step 4 of `SKILL.md`. If you're using a
> cloud agent (ChatGPT, Claude on the web, GitHub Copilot chat, etc.) make
> sure the agent only ever sees half the puzzle — for example password
> guesses, not the wallet file; or password guesses, not the mnemonic.

---

## Quick start (any agent)

1. Clone or download this repository so you have a local copy of
   [`SKILL.md`](https://github.com/3rdIteration/btcrecover/blob/master/SKILL.md)
   **and the [`skills/`](https://github.com/3rdIteration/btcrecover/tree/master/skills)
   directory** next to it. The main `SKILL.md` dispatches to sub-skills
   under `skills/` for installation, building a passwordlist / tokenlist,
   and locating a wallet file on disk — they must be installed together.
2. Drop `SKILL.md` (and the `skills/` directory) into the location your AI
   agent looks at (see per-agent instructions below).
3. Start a new chat / session and ask the agent something like
   *"Use the BTCRecover recovery skill to help me recover my wallet."* The
   agent will then follow the workflow in `SKILL.md` and walk you through
   triage, install, going offline, building a command, and running it.

If you have already downloaded the BTCRecover repository, you can simply open
it in Claude Desktop, Claude Code, or VS Code + Cline and prompt with:
*"I want to recover a wallet, can you use the SKILL.md in this repo to help
me?"*.

If your agent isn't listed below, the universal fallback is: open a fresh
chat, paste the **contents** of `SKILL.md` as the first message (or as a
system / custom-instructions message if the product supports it), then
describe your situation.

---

## Tested models

### Tested local-model combinations (VS Code + Cline)

* `qwen/qwen3.6-27b` (Usable on 24 GB+ GPU like a 3090, 4090 or 5090)
* `qwen/qwen3.5-9b` (Usable on CPU or 8 GB GPU like a 3070 with 35,000 context)
* `qwen/qwen3.5-4b` (Usable on just about any modern system, even without a GPU)

All three work well with the skills and with running local commands. The 27b model
is **much** better overall, 9b is pretty good and 4b also works but will struggle to work out anything complex. 

### Local LLM Settings to watch:
* Set context length to something like 35,000 regardless of model. (You generally set this in your LMStudio or Ollama)
* If you are using Cline, then enabling "Use Compact Prompt" will help it work **much better** as the default prompt include a bunch of stuff we don't need that just fills up the limited context of our local LLM. (Particularly noticable on less capable models and systems)

### Cloud Models (Claude Desktop or Claude Code)

* Claude Sonnet 4.6
* Claude Haiku 4.5

Both work fine. Opus will have no problem at all but you shouldn't need that
level of reasoning.

---

## Use with less capable agents (e.g. smaller 9b models)

Some smaller models struggle when asked to do the full multi-step recovery
workflow in one go. Instead, run recovery as a sequence of short, explicit
requests and only ask for one skill at a time.

Recommended pattern:

1. Keep each prompt narrow (one outcome only).
2. Wait for output, confirm it looks correct, then send the next prompt.
3. Explicitly name the skill you want used (`install-btcrecover`,
   `build-password-tokenlist`, `locate-wallet-file`).
4. Do not mix online brainstorming with offline secret-entry steps in the same
   prompt.
5. For first-run command building, ask the agent not to over-specify tuning
   flags (`--threads`, seed `--typos` / `--big-typos`) unless there is a clear
   case requiring them.

Example prompt sequence:

* **Main skill kickoff (triage only):**
  *"Use `SKILL.md`, run Step 1 triage only, and stop after you summarize what
  recovery path I should use."*
* **Install skill only:**
  *"Use the `install-btcrecover` skill only. Detect my OS, check if BTCRecover
  is already runnable, and then give me only the exact next install commands."*
* **Wallet file location skill only (if needed):**
  *"Use the `locate-wallet-file` skill only. Help me scan these folders and
  return candidate wallet paths with matched fingerprint type, without printing
  file contents."*
* **Password/tokenlist skill only:**
  *"Use the `build-password-tokenlist` skill only. Help me create a tokenlist
  from my remembered fragments and propose conservative typo flags for a first
  run."*
* **Command build only (main skill step):**
  *"Return to `SKILL.md` and do only Step 6: build the exact
  `btcrecover.py`/`seedrecover.py` command with placeholders, keep defaults,
  and do not add `--threads` or seed `--typos` / `--big-typos` unless I
  explicitly ask for expansion, then stop."*
* **Execution only (offline machine):**
  *"Now do only the run/monitor step with the command we already built; do not
  redesign the tokenlist unless the run fails quickly."*

This staged approach usually improves reliability with lower-capability models
and makes it easier for you to verify each step before continuing.

---

## Claude Code (Anthropic's terminal coding agent)

[Claude Code](https://docs.claude.com/en/docs/claude-code) automatically
discovers project-level instructions from a `CLAUDE.md` file in the working
directory, and discovers reusable "skills" from a `.claude/skills/` folder.

Recommended setup:

* **Project-scoped (preferred for one-off use):** From inside your local
  BTCRecover checkout, just start Claude Code with `claude` — it will pick
  up `SKILL.md` from the project root because the file is referenced from
  `AGENTS.md` / `README.md`. You can also explicitly tell Claude
  *"Follow `SKILL.md` in this repo"*.
* **User-scoped (so the skill is available in any directory):** copy
  `SKILL.md` to `~/.claude/skills/btcrecover-recovery/SKILL.md` (create the
  directory if it doesn't exist), and copy each sub-skill under the
  repository's `skills/` directory to its own folder under
  `~/.claude/skills/` (e.g. `~/.claude/skills/install-btcrecover/SKILL.md`,
  `~/.claude/skills/build-password-tokenlist/SKILL.md`,
  `~/.claude/skills/locate-wallet-file/SKILL.md`). Claude Code will then
  offer the BTCRecover recovery skill from any project and the sub-skills
  will be discoverable by name when the main skill delegates to them.

When recovery involves real secrets, run Claude Code on the offline machine
(or on a separate machine from the wallet file — see Step 4 / 4a in
`SKILL.md`).

---

## GitHub Copilot (VS Code / JetBrains / Visual Studio)

GitHub Copilot picks up repo-specific instructions from
`.github/copilot-instructions.md` and from `AGENTS.md` at the repo root.

Recommended setup:

* Open your local BTCRecover checkout in VS Code (or your supported IDE)
  with GitHub Copilot Chat enabled.
* `AGENTS.md` already points Copilot at `SKILL.md` — open Copilot Chat and
  ask it *"Help me run a BTCRecover recovery using `SKILL.md`."*
* If you want the skill available in **every** repo you open, copy
  `SKILL.md` into your user-level Copilot custom instructions
  (Settings → Copilot → "Custom instructions") or into
  `.github/copilot-instructions.md` of the project you typically work in.

Treat Copilot Chat as an **online** agent (it talks to GitHub's servers).
Follow the Step 4a split-workflow rules in `SKILL.md`: brainstorm passwords
and build the command with Copilot online, then swap the mnemonic / wallet
file in on your offline machine.

---

## ChatGPT (OpenAI, web or desktop app)

ChatGPT doesn't read files from your disk automatically, so you load
`SKILL.md` into the conversation instead.

Two good options:

* **Custom GPT (recommended if you'll use this more than once).** Create a
  new GPT in *Explore GPTs → Create*. In the *Instructions* box, paste the
  full contents of `SKILL.md`. Optionally upload the BTCRecover repository
  (or just the `docs/` folder) as a Knowledge file so the GPT can reference
  the linked documents. Use that GPT whenever you do a recovery.
* **One-off chat.** Start a new conversation, paste the contents of
  `SKILL.md` as the first message, then describe your situation.

ChatGPT is a **cloud agent**. Do not paste your real seed phrase, real
password, or wallet-file contents into the chat. Use it to draft your
passwordlist / tokenlist and the suggested command (with placeholders), then
run the command on your offline machine. For wallets supported by the
[extract scripts](Extract_Scripts.md), you can run the extract script on
the wallet-holding machine and paste the safe "data extract" back into the
chat — that extract is designed to be safe to share.

---

## Cline (VS Code AI agent)

[Cline](https://cline.bot/) reads project-level instructions from a
`.clinerules` file at the root of the workspace and a global rules file in
your home directory.

Recommended setup:

* **Per-project:** open your local BTCRecover checkout in VS Code with the
  Cline extension installed. Cline will see `AGENTS.md` and `SKILL.md`
  automatically. Start a task with *"Follow `SKILL.md` to help me recover
  my wallet."*
* **Global:** copy `SKILL.md` to `~/.clinerules` (macOS/Linux) or
  `%USERPROFILE%\.clinerules` (Windows) so the skill applies in every
  workspace. You can also keep both — project rules override global rules
  for the project you're in.

Cline can run locally against your own model (e.g. via Ollama or LM Studio),
which is the safest option for recovery work. If you're pointing Cline at a
hosted model, treat it like ChatGPT above and stick to the split-workflow.

---

## Any other agent (generic instructions)

Most AI assistants will accept `SKILL.md` either as a "system prompt",
"custom instructions", "project rules", or simply by pasting it as the first
message in a fresh chat. The key requirements are:

1. The agent sees `SKILL.md` **before** you describe your situation.
2. The agent has access to a terminal where it can run `git`, `python`,
   `btcrecover.py`, and `seedrecover.py` (or it gives you commands to run
   yourself).
3. You can identify whether the agent is local or cloud-hosted, so you can
   apply the right safety rules from Step 4 / 4a of `SKILL.md`.

## Contributing fixes back

If the AI agent had to **fix a bug** in BTCRecover or **add a new feature**
during your recovery (for example to support a wallet variant that wasn't
quite handled correctly), please consider sending that improvement back so
other users benefit:

* Preferred: open a pull request against
  [https://github.com/3rdIteration/btcrecover/](https://github.com/3rdIteration/btcrecover/).
* Or: email a short bug report **with the fix attached** (e.g. a `git diff`
  or the modified files, plus reproduction steps that contain **no**
  secrets) to **steve@cryptoguide.tips**.

Step 8 of [`SKILL.md`](https://github.com/3rdIteration/btcrecover/blob/master/SKILL.md)
asks the agent to prompt you about this once your funds are safe.

## See also

* [`SKILL.md`](https://github.com/3rdIteration/btcrecover/blob/master/SKILL.md) — the actual skill the agent follows.
* [`skills/`](https://github.com/3rdIteration/btcrecover/tree/master/skills) — sub-skills the main `SKILL.md` delegates to (install, build passwordlist/tokenlist, locate wallet file).
* [`AGENTS.md`](https://github.com/3rdIteration/btcrecover/blob/master/AGENTS.md) — repository-wide guardrails AI agents must respect.
* [Installing BTCRecover](INSTALL.md)
* [Seed Recovery Quickstart](Seedrecover_Quick_Start_Guide.md)
* [Password Recovery Quickstart](TUTORIAL.md)
* [Trustless (or Cloud) Recovery – Creating Wallet Extracts](Extract_Scripts.md)
* [Extracting Private Keys from Wallet Files (Decrypt & Dump)](Decrypting_dumping_walletfiles.md)
