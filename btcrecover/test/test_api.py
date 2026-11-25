"""Tests for the structured library API (btcrecover.api) and --json CLI mode."""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from btcrecover import api
from btcrecover.test.test_passwords import can_load_coincurve

REPO_ROOT = Path(__file__).resolve().parents[2]
COMMON_PASSWORDLIST = REPO_ROOT / "docs" / "Usage_Examples" / "common_passwordlist.txt"

# A known-good BIP39 recovery: the mnemonic is missing its final word, which the
# engine recovers by matching the supplied native-segwit address.
#
# "--threads 1" forces the single-process search path. The full multiprocessing
# path does not run reliably in-process under the test runner on Windows (spawn
# re-imports the runner as __main__); the existing seed tests use the same trick.
BIP39_SEED_ARGS = [
    "--threads", "1",
    "--skip-pre-start", "--dsw", "--wallet-type", "bip39",
    "--addrs", "bc1qv87qf7prhjf2ld8vgm7l0mj59jggm6ae5jdkx2",
    "--mnemonic",
    "element entire sniff tired miracle solve shadow scatter hello never tank "
    "side sight isolate sister uniform advice pen praise soap lizard festival connect",
    "--addr-limit", "5",
]

# A known-good BIP39 passphrase recovery (the passphrase is the unknown).
BIP39_PASSPHRASE_ARGS = [
    "--threads", "1",
    "--skip-pre-start", "--dsw", "--bip39",
    "--addrs", "1AmugMgC6pBbJGYuYmuRrEpQVB9BBMvCCn",
    "--addr-limit", "10",
    "--mnemonic", "certain come keen collect slab gauge photo inside mechanic deny leader drop",
]


@unittest.skipUnless(can_load_coincurve(), "requires coincurve")
class TestSeedApi(unittest.TestCase):
    def test_recover_seed_found(self):
        result = api.recover_seed(BIP39_SEED_ARGS)
        self.assertEqual(result.status, "found")
        self.assertTrue(result.found)
        self.assertTrue(result.mnemonic.endswith("baby"))
        self.assertEqual(result.path_coin, 0)

    def test_recover_seed_not_found(self):
        # A complete, valid mnemonic with no typos allowed, checked against an
        # address that is not in the wallet -- a single candidate that cannot
        # match, so the search finishes quickly with "not found".
        args = [
            "--threads", "1", "--skip-pre-start", "--dsw",
            "--wallet-type", "bip39", "--typos", "0",
            "--addrs", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            "--mnemonic",
            "element entire sniff tired miracle solve shadow scatter hello never "
            "tank side sight isolate sister uniform advice pen praise soap lizard "
            "festival connect baby",
            "--addr-limit", "3",
        ]
        result = api.recover_seed(args)
        self.assertFalse(result.found)
        self.assertEqual(result.status, "not_found")

    def test_seed_result_to_dict_schema(self):
        result = api.recover_seed(BIP39_SEED_ARGS)
        d = result.to_dict()
        self.assertEqual(d["tool"], "seed")
        self.assertEqual(
            set(d), {"tool", "status", "found", "mnemonic", "path_coin", "message"}
        )


@unittest.skipUnless(can_load_coincurve(), "requires coincurve")
class TestPasswordApi(unittest.TestCase):
    def test_recover_password_found(self):
        args = BIP39_PASSPHRASE_ARGS + ["--passwordlist", str(COMMON_PASSWORDLIST)]
        result = api.recover_password(args)
        self.assertEqual(result.status, "found")
        self.assertTrue(result.found)
        self.assertEqual(result.password, "btcr-test-password")

    def test_recover_password_not_found(self):
        import tempfile

        with tempfile.NamedTemporaryFile(
            "w", suffix=".txt", delete=False, encoding="utf-8"
        ) as f:
            f.write("not-the-password\nalso-wrong\n")
            wrong_list = f.name
        try:
            args = BIP39_PASSPHRASE_ARGS + ["--passwordlist", wrong_list]
            result = api.recover_password(args)
            self.assertFalse(result.found)
            self.assertEqual(result.status, "not_found")
            self.assertIsNotNone(result.message)
        finally:
            # Best-effort: on Windows the engine may still hold the passwordlist
            # open, which blocks unlink. The OS reclaims the temp file later.
            try:
                os.unlink(wrong_list)
            except OSError:
                pass

    def test_password_result_to_dict_schema(self):
        args = BIP39_PASSPHRASE_ARGS + ["--passwordlist", str(COMMON_PASSWORDLIST)]
        d = api.recover_password(args).to_dict()
        self.assertEqual(d["tool"], "password")
        self.assertEqual(
            set(d), {"tool", "status", "found", "password", "message"}
        )


@unittest.skipUnless(can_load_coincurve(), "requires coincurve")
class TestJsonCli(unittest.TestCase):
    """The --json CLI mode must emit exactly one JSON object on stdout."""

    def _run(self, script, extra_args):
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join(
            [str(REPO_ROOT), env.get("PYTHONPATH", "")]
        )
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / script), "--json", *extra_args],
            cwd=str(REPO_ROOT), env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
        )

    def test_password_json_stdout_is_single_object(self):
        proc = self._run(
            "btcrecover.py",
            BIP39_PASSPHRASE_ARGS + ["--passwordlist", str(COMMON_PASSWORDLIST)],
        )
        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        self.assertEqual(len(lines), 1, msg="stdout was not a single line:\n" + proc.stdout)
        obj = json.loads(lines[0])
        self.assertEqual(obj["tool"], "password")
        self.assertEqual(obj["status"], "found")
        self.assertEqual(obj["password"], "btcr-test-password")

    def test_seed_json_stdout_is_single_object(self):
        proc = self._run("seedrecover.py", BIP39_SEED_ARGS)
        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        self.assertEqual(len(lines), 1, msg="stdout was not a single line:\n" + proc.stdout)
        obj = json.loads(lines[0])
        self.assertEqual(obj["tool"], "seed")
        self.assertEqual(obj["status"], "found")


class TestMcpTools(unittest.TestCase):
    """The MCP tool functions must work without the optional `mcp` package."""

    def test_list_wallet_types(self):
        from btcrecover import mcp_server

        result = mcp_server.list_wallet_types_tool()
        self.assertIn("password_wallet_types", result)
        self.assertIn("seed_wallet_types", result)
        self.assertTrue(result["password_wallet_types"])
        self.assertTrue(result["seed_wallet_types"])

    def test_inspect_wallet(self):
        from btcrecover import mcp_server

        wallet = REPO_ROOT / "btcrecover" / "test" / "test-wallets" / "bitcoincore-0.20.1-wallet.dat"
        info = mcp_server.inspect_wallet_tool(str(wallet))
        self.assertEqual(info["wallet_type"], "WalletBitcoinCore")
        self.assertIn("difficulty", info)

    def test_inspect_wallet_unrecognized(self):
        from btcrecover import mcp_server

        info = mcp_server.inspect_wallet_tool(str(REPO_ROOT / "does-not-exist.dat"))
        self.assertIn("error", info)


if __name__ == "__main__":
    unittest.main()
