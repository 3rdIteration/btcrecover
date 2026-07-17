# Programmatic & AI-Tool Interfaces

In addition to the interactive command line, BTCRecover exposes three
machine-friendly surfaces so scripts and AI agents can drive recovery and read
results without scraping human-readable output. All three share the same
structured result shape.

## 1. `--json` output mode

Both `btcrecover.py` and `seedrecover.py` accept `--json`. When set, the tool
prints **exactly one JSON object** on stdout and redirects all human-readable
progress/banners to stderr, so stdout is safe to parse.

```bash
python btcrecover.py --json --wallet wallet.dat --passwordlist guesses.txt
```

Example stdout (password tool):

```json
{"tool": "password", "status": "found", "found": true, "password": "btcr-test-password", "message": null}
```

Example stdout (seed tool):

```json
{"tool": "seed", "status": "found", "found": true, "mnemonic": "element entire ... connect baby", "path_coin": 0, "message": null}
```

`status` is one of `found`, `not_found`, `interrupted`, or `error`. The process
exit code is `0` for `found`/`not_found` and `1` for `interrupted`/`error`,
matching the normal CLI.

## 2. Python library API

`btcrecover.api` wraps the engines and returns structured result objects instead
of printing and calling `sys.exit`. The argument lists are identical to the CLI.

```python
from btcrecover import api

result = api.recover_seed([
    "--wallet-type", "bip39",
    "--addrs", "bc1qv87qf7prhjf2ld8vgm7l0mj59jggm6ae5jdkx2",
    "--mnemonic", "element entire sniff ... festival connect",
    "--addr-limit", "5",
])

if result.found:
    print("recovered:", result.mnemonic)
else:
    print("status:", result.status)

# JSON-serializable form (the same shape used by --json):
result.to_dict()
```

`recover_password(argv, quiet=True)` returns a `PasswordRecoveryResult`
(`status`, `found`, `password`, `message`); `recover_seed(argv, quiet=True)`
returns a `SeedRecoveryResult` (`status`, `found`, `mnemonic`, `path_coin`,
`message`). With `quiet=True` (the default) the engines' human output is sent to
stderr so your program's stdout stays clean.

## 3. MCP server (for AI agents)

The Model Context Protocol server lets agents such as Claude call BTCRecover as
native tools. Install the optional dependency and run it over stdio:

```bash
pip install "btcrecover[mcp]"
python -m btcrecover.mcp_server        # or: btcrecover-mcp
```

It exposes four tools:

| Tool | Purpose |
| --- | --- |
| `recover_password` | Run password/passphrase recovery (args mirror the CLI). |
| `recover_seed` | Run seed/mnemonic recovery (args mirror the CLI). |
| `inspect_wallet` | Autodetect a wallet file's type and report its difficulty, without recovering. |
| `list_wallet_types` | Enumerate supported password and seed wallet types. |

Example client configuration (stdio):

```json
{
  "mcpServers": {
    "btcrecover": {
      "command": "python",
      "args": ["-m", "btcrecover.mcp_server"]
    }
  }
}
```

### Safety and scope

The recovery tools run the search **synchronously and can take a long time** for
large search spaces. When driving them from an agent, keep each call bounded --
use a small `--passwordlist`/tokenlist and a low `--addr-limit` -- and treat a
long-running call as expected rather than retrying it. Use `inspect_wallet` first
to understand a wallet's difficulty before launching a full search.
