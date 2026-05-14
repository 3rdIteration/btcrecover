# AI-Assisted Recovery (using `skills.md`)

BTCRecover ships with a [`skills.md`](https://github.com/3rdIteration/btcrecover/blob/master/skills.md)
file at the root of the repository. It is a structured prompt that teaches an
AI coding agent how to triage a wallet-recovery situation, install BTCRecover,
take the user's system offline, collect wallet material, build a
`btcrecover.py` / `seedrecover.py` command, and finish up — all while avoiding
the common ways a user can leak their secrets to an online machine.

This page tells you **where to put `skills.md`** for the four AI agents the
skill has been tested against (and a generic fallback for anything else), and
gives the safety rules you should keep in mind no matter which agent you use.

> ⚠️ **Important — read this before you start.**
> AI agents will happily ask for your seed phrase, password, or wallet file.
> Never paste a real secret into a chat with a hosted / cloud agent. The
> `skills.md` workflow is *primarily* intended for a **local** agent (one
> running on your own machine), and *secondarily* for cloud agents under the
> split-workflow rules described in Step 4 of `skills.md`. If you're using a
> cloud agent (ChatGPT, Claude on the web, GitHub Copilot chat, etc.) make
> sure the agent only ever sees half the puzzle — for example password
> guesses, not the wallet file; or password guesses, not the mnemonic.

---

## Quick start (any agent)

1. Clone or download this repository so you have a local copy of
   [`skills.md`](https://github.com/3rdIteration/btcrecover/blob/master/skills.md).
2. Drop `skills.md` into the location your AI agent looks at (see per-agent
   instructions below).
3. Start a new chat / session and ask the agent something like
   *"Use the BTCRecover recovery skill to help me recover my wallet."* The
   agent will then follow the workflow in `skills.md` and walk you through
   triage, install, going offline, building a command, and running it.

If your agent isn't listed below, the universal fallback is: open a fresh
chat, paste the **contents** of `skills.md` as the first message (or as a
system / custom-instructions message if the product supports it), then
describe your situation.

---

## Claude Code (Anthropic's terminal coding agent)

[Claude Code](https://docs.claude.com/en/docs/claude-code) automatically
discovers project-level instructions from a `CLAUDE.md` file in the working
directory, and discovers reusable "skills" from a `.claude/skills/` folder.

Recommended setup:

* **Project-scoped (preferred for one-off use):** From inside your local
  BTCRecover checkout, just start Claude Code with `claude` — it will pick
  up `skills.md` from the project root because the file is referenced from
  `AGENTS.md` / `README.md`. You can also explicitly tell Claude
  *"Follow `skills.md` in this repo"*.
* **User-scoped (so the skill is available in any directory):** copy
  `skills.md` to `~/.claude/skills/btcrecover-recovery/SKILL.md` (create the
  directory if it doesn't exist). Claude Code will then offer the BTCRecover
  recovery skill from any project.

When recovery involves real secrets, run Claude Code on the offline machine
(or on a separate machine from the wallet file — see Step 4 / 4a in
`skills.md`).

---

## GitHub Copilot (VS Code / JetBrains / Visual Studio)

GitHub Copilot picks up repo-specific instructions from
`.github/copilot-instructions.md` and from `AGENTS.md` at the repo root.

Recommended setup:

* Open your local BTCRecover checkout in VS Code (or your supported IDE)
  with GitHub Copilot Chat enabled.
* `AGENTS.md` already points Copilot at `skills.md` — open Copilot Chat and
  ask it *"Help me run a BTCRecover recovery using `skills.md`."*
* If you want the skill available in **every** repo you open, copy
  `skills.md` into your user-level Copilot custom instructions
  (Settings → Copilot → "Custom instructions") or into
  `.github/copilot-instructions.md` of the project you typically work in.

Treat Copilot Chat as an **online** agent (it talks to GitHub's servers).
Follow the Step 4a split-workflow rules in `skills.md`: brainstorm passwords
and build the command with Copilot online, then swap the mnemonic / wallet
file in on your offline machine.

---

## ChatGPT (OpenAI, web or desktop app)

ChatGPT doesn't read files from your disk automatically, so you load
`skills.md` into the conversation instead.

Two good options:

* **Custom GPT (recommended if you'll use this more than once).** Create a
  new GPT in *Explore GPTs → Create*. In the *Instructions* box, paste the
  full contents of `skills.md`. Optionally upload the BTCRecover repository
  (or just the `docs/` folder) as a Knowledge file so the GPT can reference
  the linked documents. Use that GPT whenever you do a recovery.
* **One-off chat.** Start a new conversation, paste the contents of
  `skills.md` as the first message, then describe your situation.

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
  Cline extension installed. Cline will see `AGENTS.md` and `skills.md`
  automatically. Start a task with *"Follow `skills.md` to help me recover
  my wallet."*
* **Global:** copy `skills.md` to `~/.clinerules` (macOS/Linux) or
  `%USERPROFILE%\.clinerules` (Windows) so the skill applies in every
  workspace. You can also keep both — project rules override global rules
  for the project you're in.

Cline can run locally against your own model (e.g. via Ollama or LM Studio),
which is the safest option for recovery work. If you're pointing Cline at a
hosted model, treat it like ChatGPT above and stick to the split-workflow.

---

## Any other agent (generic instructions)

Most AI assistants will accept `skills.md` either as a "system prompt",
"custom instructions", "project rules", or simply by pasting it as the first
message in a fresh chat. The key requirements are:

1. The agent sees `skills.md` **before** you describe your situation.
2. The agent has access to a terminal where it can run `git`, `python`,
   `btcrecover.py`, and `seedrecover.py` (or it gives you commands to run
   yourself).
3. You can identify whether the agent is local or cloud-hosted, so you can
   apply the right safety rules from Step 4 / 4a of `skills.md`.

---

## See also

* [`skills.md`](https://github.com/3rdIteration/btcrecover/blob/master/skills.md) — the actual skill the agent follows.
* [`AGENTS.md`](https://github.com/3rdIteration/btcrecover/blob/master/AGENTS.md) — repository-wide guardrails AI agents must respect.
* [Installing BTCRecover](INSTALL.md)
* [Seed Recovery Quickstart](Seedrecover_Quick_Start_Guide.md)
* [Password Recovery Quickstart](TUTORIAL.md)
* [Trustless (or Cloud) Recovery – Creating Wallet Extracts](Extract_Scripts.md)
* [Extracting Private Keys from Wallet Files (Decrypt & Dump)](Decrypting_dumping_walletfiles.md)
