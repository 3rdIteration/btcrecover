"""Check benchmark tables across legacy and CUDA result formats."""

import unittest

import generate_benchmark_docs


class TestBenchmarkDocs(unittest.TestCase):
    def test_cuda_shares_wallet_column_and_supplies_difficulty(self):
        results = [{
            "system_info": {
                "cpu_model": "ExampleChip",
                "cpu_cores_physical": 8,
                "cpu_cores_logical": 16,
                "gpu": [{"name": "Example GPU"}],
            },
            # Deliberately shuffled: rendering must order modes consistently.
            "benchmarks": [
                {
                    "label": "BIP38 Encrypted Key (CUDA)",
                    "category": "password",
                    "mode": "cuda",
                    "passwords_per_second": 400,
                    "wallet_difficulty": "sCrypt N=14, r=8, p=8",
                },
                {
                    "label": "BIP38 Encrypted Key (OPENCL)",
                    "category": "password",
                    "mode": "opencl",
                    "passwords_per_second": 40,
                },
                {
                    "label": "BIP38 Encrypted Key (GPU)",
                    "category": "password",
                    "mode": "gpu",
                    "passwords_per_second": 30,
                },
                {
                    "label": "BIP38 Encrypted Key (CPU)",
                    "category": "password",
                    "mode": "cpu",
                    "passwords_per_second": 75,
                },
            ],
        }]

        markdown = generate_benchmark_docs.generate_markdown(results)

        self.assertEqual(markdown.count("BIP38 Encrypted Key"), 1)
        self.assertIn(
            "| System | Mode | BIP38 Encrypted Key - sCrypt N=14, r=8, p=8 |",
            markdown,
        )
        self.assertEqual(
            [line for line in markdown.splitlines() if line.startswith("| #1 ")],
            [
                "| #1 ExampleChip (8C/16T) | CPU | 75.00 p/s |",
                "| #1 Example GPU | GPU | 30.00 p/s |",
                "| #1 Example GPU | OPENCL | 40.00 p/s |",
                "| #1 Example GPU | CUDA | 400.00 p/s |",
            ],
        )

    def test_legacy_results_keep_default_cpu_mode_and_difficulty_priority(self):
        results = [{
            "system_info": {"cpu_model": "ExampleChip"},
            "benchmarks": [
                {
                    "label": "Example Wallet (OPENCL)",
                    "mode": "opencl",
                    "passwords_per_second": 2000,
                    "wallet_difficulty": "OpenCL difficulty",
                },
                {
                    "label": "Example Wallet (CPU)",
                    "passwords_per_second": 1000,
                    "wallet_difficulty": "CPU difficulty",
                },
            ],
        }]

        markdown = generate_benchmark_docs.generate_markdown(results)

        self.assertIn("### Other Benchmarks", markdown)
        self.assertIn("| System | Mode | Example Wallet - CPU difficulty |", markdown)
        self.assertNotIn("OpenCL difficulty", markdown)
        self.assertNotIn("CUDA", markdown)
        self.assertEqual(
            [line for line in markdown.splitlines() if line.startswith("| #1 ")],
            [
                "| #1 ExampleChip | CPU | 1.00 Kp/s |",
                "| #1 ExampleChip | OPENCL | 2.00 Kp/s |",
            ],
        )


if __name__ == "__main__":
    unittest.main()
