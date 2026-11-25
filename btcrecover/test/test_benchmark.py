"""Check how benchmark.py builds each mode's command line."""

import argparse
import unittest
from unittest import mock

import benchmark


def _bench(label):
    benches = benchmark.get_password_benchmarks() + benchmark.get_seed_benchmarks()
    return next(bench for bench in benches if bench["label"] == label)


class TestConfigureMode(unittest.TestCase):
    def configure(self, label, mode, **kwargs):
        cmd = []
        return benchmark._configure_mode(cmd, _bench(label), mode, **kwargs), cmd

    def test_cpu_password_runs_force_the_cpu_backend(self):
        # Without --backend cpu, btcrecover's default "auto" may pick CUDA or
        # OpenCL for a run that benchmark.py labels CPU.
        for label in ("BIP38 Encrypted Key", "BIP39 Passphrase", "Blockchain.com (v5)"):
            self.assertEqual(self.configure(label, "cpu"), (None, ["--backend", "cpu"]))

    def test_cpu_seed_runs_add_nothing(self):
        # seedrecover has no --backend option; there's no auto-selection to stop.
        self.assertEqual(self.configure("BIP39 12-word Seed", "cpu"), (None, []))

    def test_cuda_only_runs_where_supported(self):
        reason, cmd = self.configure("BIP38 Encrypted Key", "cuda", cuda_args={"batch": 64})
        self.assertIsNone(reason)
        self.assertEqual(cmd, ["--enable-cuda", "--cuda-batch", "64"])
        for label in ("Blockchain.com (v5)", "BIP39 12-word Seed"):
            reason, cmd = self.configure(label, "cuda")
            self.assertIn("CUDA not supported", reason)
            self.assertEqual(cmd, [])

    def test_opencl_and_gpu_keep_their_existing_rules(self):
        self.assertEqual(self.configure("BIP38 Encrypted Key", "opencl"), (None, ["--enable-opencl"]))
        self.assertEqual(self.configure("BIP39 12-word Seed", "opencl"), (None, ["--enable-opencl"]))
        self.assertIsNotNone(self.configure("MultiBit HD", "opencl")[0])
        self.assertEqual(self.configure("Bitcoin Core (BDB)", "gpu"), (None, ["--enable-gpu"]))
        self.assertIsNotNone(self.configure("BIP38 Encrypted Key", "gpu")[0])
        self.assertIsNotNone(self.configure("BIP39 12-word Seed", "gpu")[0])


class TestRunAllBenchmarks(unittest.TestCase):
    def run_modes(self, cuda_available):
        args = argparse.Namespace(
            global_ws=None, local_ws=None, gpu_names=None,
            opencl_workgroup_size=None, opencl_platform=None, opencl_devices=None,
            cuda_batch=None, threads=None, duration=1, backend=None,
            backend_actual="coincurve", comment=None, wallet_type="password",
            gpu=False, opencl=False, cuda=True,
        )
        commands = []

        def fake_run(cmd, duration, label):
            commands.append((label, cmd))
            return {"label": label, "passwords_per_second": 1.0, "status": "ok"}

        with mock.patch.object(benchmark, "_get_cuda_info",
                               return_value={"available": cuda_available}), \
                mock.patch.object(benchmark, "get_system_info", return_value={}), \
                mock.patch.object(benchmark, "_get_btcrecover_version", return_value="test"), \
                mock.patch.object(benchmark, "run_benchmark", side_effect=fake_run), \
                mock.patch("builtins.print"):
            results = benchmark.run_all_benchmarks(args)
        return results, commands

    def test_cuda_mode_runs_bip38_when_available(self):
        results, commands = self.run_modes(cuda_available=True)
        cuda = [cmd for label, cmd in commands if label.endswith("(CUDA)")]
        self.assertEqual(len(cuda), 1)
        self.assertIn("--bip38-enc-privkey", cuda[0])
        self.assertIn("--enable-cuda", cuda[0])
        self.assertIn("cuda", {bench["mode"] for bench in results["benchmarks"]})
        # Every CPU password run is pinned to the CPU.
        for label, cmd in commands:
            if label.endswith("(CPU)"):
                self.assertEqual(cmd[cmd.index("--backend") + 1], "cpu")

    def test_cuda_mode_skipped_when_unavailable(self):
        _, commands = self.run_modes(cuda_available=False)
        self.assertFalse([label for label, _ in commands if label.endswith("(CUDA)")])
        self.assertTrue([label for label, _ in commands if label.endswith("(CPU)")])

    def test_subprocesses_disable_automatic_backend_selection(self):
        captured = {}

        class FakeProc:
            pid = 0
            stdout = iter(())

            def __init__(self, *args, **kwargs):
                captured.update(kwargs.get("env", {}))

            def wait(self, timeout=None):
                return 0

            def poll(self):
                return 0

        with mock.patch.object(benchmark.subprocess, "Popen", FakeProc), \
                mock.patch("builtins.print"):
            benchmark.run_benchmark(["python", "-c", "pass"], 1, "env check")
        self.assertEqual(captured.get("BTCRECOVER_AUTO_BACKEND"), "0")


if __name__ == "__main__":
    unittest.main()
