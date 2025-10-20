"""End-to-end tests for a subset of the basic usage examples."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Sequence, Tuple

import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHON_EXECUTABLE = sys.executable

COMMON_PASSWORDLIST = REPO_ROOT / "docs" / "Usage_Examples" / "common_passwordlist.txt"


def _command(script: str, *args: str) -> list[str]:
    """Return a subprocess command invoking *script* with *args*."""

    return [PYTHON_EXECUTABLE, str(REPO_ROOT / script), *args]


def _run_command(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """Execute *command* in the repository root and capture output."""

    env = os.environ.copy()
    pythonpath_entries = [str(REPO_ROOT)]
    if env.get("PYTHONPATH"):
        pythonpath_entries.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(pythonpath_entries)

    return subprocess.run(
        command,
        cwd=str(REPO_ROOT),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=120,
    )


class CommandTestCase(unittest.TestCase):
    """Base class that provides helpers for invoking CLI usage examples."""

    expected_phrase: str

    def run_examples(self, examples: Iterable[Tuple[str, Sequence[str]]]) -> None:
        for description, command in examples:
            with self.subTest(description=description):
                result = _run_command(command)
                if result.returncode != 0:
                    self.fail(
                        "Command '{}' exited with {}\nOutput:\n{}".format(
                            " ".join(command), result.returncode, result.stdout
                        )
                    )
                self.assertIn(
                    self.expected_phrase,
                    result.stdout,
                    msg="Command '{}' did not report {}\nOutput:\n{}".format(
                        " ".join(command), self.expected_phrase, result.stdout
                    ),
                )


class TestBasicPasswordUsageExamples(CommandTestCase):
    """Smoke tests for representative password recovery usage commands."""

    expected_phrase = "Password found"

    def test_basic_password_examples(self) -> None:
        examples = [
            (
                "BIP38 paper wallet (Bitcoin)",
                _command(
                    "btcrecover.py",
                    "--skip-pre-start",
                    "--dsw",
                    "--bip38-enc-privkey",
                    "6PnM7h9sBC9EMZxLVsKzpafvBN8zjKp8MZj6h9mfvYEQRMkKBTPTyWZHHx",
                    "--passwordlist",
                    str(COMMON_PASSWORDLIST),
                ),
            ),
            (
                "BIP39 passphrase (Bitcoin)",
                _command(
                    "btcrecover.py",
                    "--skip-pre-start",
                    "--dsw",
                    "--bip39",
                    "--addrs",
                    "1AmugMgC6pBbJGYuYmuRrEpQVB9BBMvCCn",
                    "--addr-limit",
                    "10",
                    "--passwordlist",
                    str(COMMON_PASSWORDLIST),
                    "--mnemonic",
                    "certain come keen collect slab gauge photo inside mechanic deny leader drop",
                ),
            ),
            (
                "Electrum extra words",
                _command(
                    "btcrecover.py",
                    "--skip-pre-start",
                    "--dsw",
                    "--wallet-type",
                    "electrum2",
                    "--addrs",
                    "bc1q6n3u9aar3vgydfr6q23fzcfadh4zlp2ns2ljp6",
                    "--addr-limit",
                    "10",
                    "--passwordlist",
                    str(COMMON_PASSWORDLIST),
                    "--mnemonic",
                    "quote voice evidence aspect warfare hire system black rate wing ask rug",
                ),
            ),
        ]

        self.run_examples(examples)


class TestBasicSeedUsageExamples(CommandTestCase):
    """Smoke tests for representative seed recovery usage commands."""

    expected_phrase = "Seed found"

    def test_basic_seed_examples(self) -> None:
        examples = [
            (
                "BIP39 native segwit",
                _command(
                    "seedrecover.py",
                    "--skip-pre-start",
                    "--dsw",
                    "--wallet-type",
                    "bip39",
                    "--addrs",
                    "bc1qv87qf7prhjf2ld8vgm7l0mj59jggm6ae5jdkx2",
                    "--mnemonic",
                    "element entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect",
                    "--addr-limit",
                    "5",
                ),
            ),
            (
                "aezeed",
                _command(
                    "seedrecover.py",
                    "--skip-pre-start",
                    "--dsw",
                    "--wallet-type",
                    "aezeed",
                    "--addrs",
                    "1Hp6UXuJjzt9eSBa9LhtW97KPb44bq4CAQ",
                    "--mnemonic",
                    "absorb original enlist once climb erode kid thrive kitchen giant define tube orange leader harbor comfort olive fatal success suggest drink penalty chimney",
                    "--addr-limit",
                    "5",
                ),
            ),
            (
                "Cardano base address",
                _command(
                    "seedrecover.py",
                    "--skip-pre-start",
                    "--dsw",
                    "--wallet-type",
                    "cardano",
                    "--addrs",
                    "addr1qyr2c43g33hgwzyufdd6fztpvn5uq5lwc74j0kuqr7gdrq5dgrztddqtl8qhw93ay8r3g8kw67xs097u6gdspyfcrx5qfv739l",
                    "--mnemonic",
                    "wood blame garbage one federal jaguar slogan movie thunder seed apology trigger spoon basket fine culture boil render special enforce dish middle antique",
                ),
            ),
            (
                "SLIP39 damaged share",
                _command(
                    "seedrecover.py",
                    "--skip-pre-start",
                    "--dsw",
                    "--slip39",
                    "--mnemonic",
                    "hearing echo academic acid deny bracelet playoff exact fancy various evidence standard adjust muscle parcel sled crucial amazing mansion losing",
                    "--typos",
                    "2",
                ),
            ),
        ]

        self.run_examples(examples)


if __name__ == "__main__":
    unittest.main()
