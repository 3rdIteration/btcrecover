"""Exercise CUDA scratchpad and staging-buffer reuse without a CUDA device."""

import ctypes
import unittest
from types import SimpleNamespace
from unittest import mock

from btcrecover import cuda_scrypt

try:
    import numpy as np
except ImportError:
    np = None


class _DeviceArray:
    """Host storage exposing the small CuPy array interface used by ROMix."""

    def __init__(self, values):
        self.values = values
        self.data = SimpleNamespace(ptr=values.ctypes.data)

    def __getitem__(self, index):
        return _DeviceArray(self.values[index])


@unittest.skipIf(np is None, "requires NumPy")
class TestCudaBufferReuse(unittest.TestCase):
    def setUp(self):
        self.stream = mock.Mock(ptr=1)
        self.pool = mock.Mock()
        self.cp = SimpleNamespace(
            uint32=np.uint32,
            empty=mock.Mock(side_effect=self.allocate_device_array),
            get_default_memory_pool=mock.Mock(return_value=self.pool),
            cuda=SimpleNamespace(
                alloc_pinned_memory=mock.Mock(side_effect=bytearray),
                Stream=mock.Mock(return_value=self.stream),
                runtime=SimpleNamespace(
                    memcpyHostToDevice=1,
                    memcpyDeviceToHost=2,
                    memcpyAsync=mock.Mock(side_effect=self.copy_memory),
                ),
            ),
        )
        self.kernel = mock.Mock(side_effect=self.transform_wave)
        patches = (
            mock.patch.multiple(
                cuda_scrypt,
                _cp=self.cp,
                _V_buffer=None,
                _V_capacity_blocks=0,
                _V_memory_limit_blocks=0,
                _V_N=None,
                _stream=None,
                _pinned_in=None,
                _pinned_out=None,
                _np_in=None,
                _np_out=None,
                _d_blocks=None,
            ),
            mock.patch.object(cuda_scrypt, "_cupy", return_value=self.cp),
            mock.patch.object(cuda_scrypt, "_get_kernel", return_value=self.kernel),
        )
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        memory_limit_patch = mock.patch.object(
            cuda_scrypt, "_max_concurrent_blocks", return_value=8
        )
        self.memory_limit = memory_limit_patch.start()
        self.addCleanup(memory_limit_patch.stop)

    @staticmethod
    def allocate_device_array(shape, dtype):
        return _DeviceArray(np.empty(shape, dtype=dtype))

    @staticmethod
    def copy_memory(destination, source, size, direction, stream):
        ctypes.memmove(destination, source, size)

    @staticmethod
    def transform_wave(grid, block, arguments, shared_mem, stream):
        # A deterministic stand-in for ROMix verifies that every wave and
        # partial tail uses the correct staging buffers and input values.
        device_blocks, scratchpad, n, count = arguments
        device_blocks.values[:count] += np.uint32(1)

    def run_batch(self, count, n=16):
        host = np.arange(count * 256, dtype=np.uint32).reshape(count, 256)
        result = cuda_scrypt._romix_blocks(host, n)
        np.testing.assert_array_equal(result, host + np.uint32(1))

    def test_batches_larger_than_vram_reuse_buffers_across_waves(self):
        self.run_batch(16)
        scratchpad = cuda_scrypt._V_buffer
        pinned_input = cuda_scrypt._pinned_in
        pinned_output = cuda_scrypt._pinned_out
        device_blocks = cuda_scrypt._d_blocks

        for count in (16, 21, 3, 16):
            with self.subTest(count=count):
                self.run_batch(count)
                self.assertIs(cuda_scrypt._V_buffer, scratchpad)
                self.assertIs(cuda_scrypt._pinned_in, pinned_input)
                self.assertIs(cuda_scrypt._pinned_out, pinned_output)
                self.assertIs(cuda_scrypt._d_blocks, device_blocks)

        self.assertEqual(self.cp.empty.call_count, 2)
        self.assertEqual(self.cp.cuda.alloc_pinned_memory.call_count, 2)
        self.assertEqual(self.cp.cuda.Stream.call_count, 1)
        self.memory_limit.assert_called_once_with(16)
        self.assertEqual(self.kernel.call_count, 10)

    def test_small_initial_batch_can_grow_to_memory_limit(self):
        self.run_batch(2)
        self.assertEqual(cuda_scrypt._V_capacity_blocks, 2)
        initial_scratchpad = cuda_scrypt._V_buffer

        self.run_batch(6)
        self.assertEqual(cuda_scrypt._V_capacity_blocks, 6)
        self.assertIsNot(cuda_scrypt._V_buffer, initial_scratchpad)

        self.run_batch(12)
        self.assertEqual(cuda_scrypt._V_capacity_blocks, 8)
        self.run_batch(16)
        self.assertEqual(self.memory_limit.call_count, 3)
        self.assertEqual(self.cp.empty.call_count, 6)
        self.assertEqual(self.cp.cuda.alloc_pinned_memory.call_count, 6)

    def test_changed_scrypt_cost_reallocates_and_remeasures_memory(self):
        self.memory_limit.side_effect = (8, 4)
        self.run_batch(16, n=16)
        initial_scratchpad = cuda_scrypt._V_buffer
        initial_pinned_input = cuda_scrypt._pinned_in

        self.run_batch(16, n=32)
        self.assertIsNot(cuda_scrypt._V_buffer, initial_scratchpad)
        self.assertIsNot(cuda_scrypt._pinned_in, initial_pinned_input)
        self.assertEqual(cuda_scrypt._V_capacity_blocks, 4)
        self.assertEqual(cuda_scrypt._V_N, 32)
        self.run_batch(16, n=32)
        self.assertEqual(self.memory_limit.call_args_list, [mock.call(16), mock.call(32)])
        self.cp.empty.assert_any_call((4, 32 * 256), dtype=np.uint32)
        self.assertEqual(self.cp.empty.call_count, 4)

    def test_explicit_release_resets_cached_memory_budget(self):
        self.run_batch(16)
        cuda_scrypt.free_buffers()
        self.assertEqual(cuda_scrypt._V_memory_limit_blocks, 0)
        self.assertEqual(cuda_scrypt._V_capacity_blocks, 0)
        for name in ("_V_buffer", "_pinned_in", "_pinned_out", "_d_blocks", "_stream"):
            self.assertIsNone(getattr(cuda_scrypt, name))

        self.memory_limit.return_value = 4
        self.run_batch(16)
        self.assertEqual(cuda_scrypt._V_capacity_blocks, 4)
        self.assertEqual(self.memory_limit.call_count, 2)


if __name__ == "__main__":
    unittest.main()
