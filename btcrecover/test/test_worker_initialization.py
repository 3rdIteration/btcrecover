"""Check that failed GPU workers report errors instead of respawning."""

import multiprocessing
import os
import unittest
from types import SimpleNamespace
from unittest import mock

from btcrecover import btcrpass, opencl_helpers


class _CpuWallet:
    @staticmethod
    def return_verified_password_or_false(passwords):
        return False, len(passwords)

    @staticmethod
    def passwords_per_seconds(seconds):
        return 10


def _initialize_failing_worker():
    """Inject a context failure inside a real spawned pool worker."""
    btcrpass.loaded_wallet = None
    wallet = SimpleNamespace(opencl_algo=0, opencl_devices=[0])
    with mock.patch.object(
        opencl_helpers, "init_opencl_contexts",
        side_effect=RuntimeError("simulated GPU allocation failure"),
    ):
        btcrpass.init_worker(wallet, str)


class TestWorkerInitialization(unittest.TestCase):
    def test_failure_reaches_parent_without_replacing_worker(self):
        context = multiprocessing.get_context("spawn")
        with context.Pool(1, initializer=_initialize_failing_worker) as pool:
            original_pid = pool.apply_async(os.getpid).get(timeout=20)
            result = pool.apply_async(
                btcrpass.return_verified_password_or_false, (["candidate"],)
            )
            with self.assertRaisesRegex(
                btcrpass.WorkerInitializationError,
                "initialize OpenCL contexts.*simulated GPU allocation failure",
            ):
                result.get(timeout=20)
            self.assertEqual(
                original_pid, pool.apply_async(os.getpid).get(timeout=20)
            )

    def test_cpu_wallet_without_opencl_attributes(self):
        wallet = _CpuWallet()
        with mock.patch.object(btcrpass, "loaded_wallet", None), \
                mock.patch.object(btcrpass, "_worker_initialization_error", "old error"), \
                mock.patch.object(btcrpass, "set_process_priority_idle"), \
                mock.patch.object(btcrpass.signal, "signal"):
            btcrpass.init_worker(wallet, str)
            self.assertEqual(
                btcrpass.return_verified_password_or_false(["candidate"]),
                (False, 1),
            )

    def test_main_terminates_pool_after_initialization_error(self):
        error = btcrpass.WorkerInitializationError("GPU unavailable")

        def failed_results():
            raise error
            yield  # Make the error occur when main consumes the iterator.

        for save_seeds in (False, True):
            with self.subTest(save_seeds=save_seeds), \
                    mock.patch.object(btcrpass, "loaded_wallet", None), \
                    mock.patch.object(btcrpass.multiprocessing, "Queue") as create_queue, \
                    mock.patch.object(btcrpass.multiprocessing, "Process") as create_writer, \
                    mock.patch.object(btcrpass.multiprocessing, "Pool") as create_pool:
                wallet = _CpuWallet()
                wallet._savevalidseeds = save_seeds
                btcrpass.parse_arguments(
                    ["--performance", "--backend", "cpu", "--threads", "2",
                     "--skip-pre-start", "--no-progress", "--no-dupchecks",
                     "--disable-save-possible-passwords"],
                    wallet=wallet, disable_security_warning_param=True,
                )
                pool = create_pool.return_value
                pool.imap.return_value = failed_results()
                with self.assertRaisesRegex(
                    btcrpass.WorkerInitializationError, "GPU unavailable"
                ):
                    btcrpass.main()
                pool.terminate.assert_called_once_with()
                pool.join.assert_called_once_with()
                pool.close.assert_not_called()
                create_queue.return_value.close.assert_called_once_with()
                if save_seeds:
                    writer = create_writer.return_value
                    writer.start.assert_called_once_with()
                    writer.terminate.assert_called_once_with()
                    writer.join.assert_called_once_with()
                else:
                    create_writer.assert_not_called()


if __name__ == "__main__":
    unittest.main()
