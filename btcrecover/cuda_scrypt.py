"""Optional CUDA-accelerated scrypt for BIP38 recovery (via CuPy).

BIP38 uses scrypt with N=2^14, r=8, p=8 -- a 16 MiB, memory-hard hash that the
generic OpenCL path runs at only ~40 hashes/s on a high-end NVIDIA GPU (it is
memory-bound and does not scale). This module provides a purpose-built CUDA
scrypt: one thread per hash performing the ROMix, with the 1 KiB working block
kept in shared memory (not spilled to local memory, which is what caps the naive
approach). The cheap 1-iteration PBKDF2 pre/post steps stay on the CPU.

Correctness is verified bit-for-bit against ``hashlib.scrypt`` in the test suite.
r is fixed at 8 (BIP38's value); the kernel is specialized accordingly.

CuPy is an optional dependency (``pip install btcrecover[cuda]``); importing this
module never fails, but :func:`is_available` returns False when CuPy or a CUDA
device is absent, and the recovery engine then falls back to OpenCL or CPU.
"""

import hashlib

_cp = None
_import_error = None

# Cached CUDA stream and pinned-memory staging buffers (allocated alongside the
# V scratchpad in _romix_blocks, released by free_buffers). _pinned_in/_pinned_out
# are the PinnedMemoryPointers (kept alive so the _np_in/_np_out numpy views that
# wrap them stay valid).
_stream = None
_pinned_in = None
_pinned_out = None
_np_in = None
_np_out = None
_d_blocks = None


def _cupy():
    global _cp, _import_error
    if _cp is None and _import_error is None:
        try:
            import cupy as cp
            _cp = cp
        except Exception as e:  # noqa: BLE001 -- any import/CUDA error means "unavailable"
            _import_error = e
    return _cp


def is_available():
    """True if CuPy is importable and at least one CUDA device is present."""
    cp = _cupy()
    if cp is None:
        return False
    try:
        return cp.cuda.runtime.getDeviceCount() > 0
    except Exception:  # noqa: BLE001
        return False


# One thread per hash performs the ROMix; the 256-word (1 KiB) working block X and
# scratch Y live in dynamic shared memory. r is fixed to 8 (WORDS = 2r*16 = 256).
_KERNEL_SRC = r"""
extern "C" {
#define ROTL(a,b) (((a)<<(b))|((a)>>(32-(b))))
#define R_VAL 8
#define TWOR 16
#define WORDS 256

__device__ __forceinline__ void salsa20_8(unsigned int* B) {
    unsigned int x[16];
    #pragma unroll
    for (int i=0;i<16;i++) x[i]=B[i];
    #pragma unroll
    for (int i=0;i<4;i++){
        x[ 4]^=ROTL(x[ 0]+x[12], 7); x[ 8]^=ROTL(x[ 4]+x[ 0], 9);
        x[12]^=ROTL(x[ 8]+x[ 4],13); x[ 0]^=ROTL(x[12]+x[ 8],18);
        x[ 9]^=ROTL(x[ 5]+x[ 1], 7); x[13]^=ROTL(x[ 9]+x[ 5], 9);
        x[ 1]^=ROTL(x[13]+x[ 9],13); x[ 5]^=ROTL(x[ 1]+x[13],18);
        x[14]^=ROTL(x[10]+x[ 6], 7); x[ 2]^=ROTL(x[14]+x[10], 9);
        x[ 6]^=ROTL(x[ 2]+x[14],13); x[10]^=ROTL(x[ 6]+x[ 2],18);
        x[ 3]^=ROTL(x[15]+x[11], 7); x[ 7]^=ROTL(x[ 3]+x[15], 9);
        x[11]^=ROTL(x[ 7]+x[ 3],13); x[15]^=ROTL(x[11]+x[ 7],18);
        x[ 1]^=ROTL(x[ 0]+x[ 3], 7); x[ 2]^=ROTL(x[ 1]+x[ 0], 9);
        x[ 3]^=ROTL(x[ 2]+x[ 1],13); x[ 0]^=ROTL(x[ 3]+x[ 2],18);
        x[ 6]^=ROTL(x[ 5]+x[ 4], 7); x[ 7]^=ROTL(x[ 6]+x[ 5], 9);
        x[ 4]^=ROTL(x[ 7]+x[ 6],13); x[ 5]^=ROTL(x[ 4]+x[ 7],18);
        x[11]^=ROTL(x[10]+x[ 9], 7); x[ 8]^=ROTL(x[11]+x[10], 9);
        x[ 9]^=ROTL(x[ 8]+x[11],13); x[10]^=ROTL(x[ 9]+x[ 8],18);
        x[12]^=ROTL(x[15]+x[14], 7); x[13]^=ROTL(x[12]+x[15], 9);
        x[14]^=ROTL(x[13]+x[12],13); x[15]^=ROTL(x[14]+x[13],18);
    }
    #pragma unroll
    for (int i=0;i<16;i++) B[i]+=x[i];
}

__device__ __forceinline__ void blockmix(const unsigned int* Bin, unsigned int* Bout) {
    unsigned int X[16];
    #pragma unroll
    for (int k=0;k<16;k++) X[k]=Bin[(TWOR-1)*16+k];
    for (int i=0;i<TWOR;i++){
        #pragma unroll
        for (int k=0;k<16;k++) X[k]^=Bin[i*16+k];
        salsa20_8(X);
        int out=(i&1)?(R_VAL+(i>>1)):(i>>1);
        #pragma unroll
        for (int k=0;k<16;k++) Bout[out*16+k]=X[k];
    }
}

// blocks: count * 256 uint32 (in place). Vg: count * N * 256 uint32 scratchpad.
__global__ void romix(unsigned int* blocks, unsigned int* Vg, const int N, const int count) {
    extern __shared__ unsigned int sh[];
    unsigned int* X = sh + (size_t)threadIdx.x * WORDS;
    unsigned int* Y = sh + (size_t)(blockDim.x + threadIdx.x) * WORDS;
    int idx = blockDim.x*blockIdx.x + threadIdx.x;
    if (idx >= count) return;
    unsigned int* B = blocks + (size_t)idx*WORDS;
    unsigned int* V = Vg + (size_t)idx*(size_t)N*WORDS;
    for (int k=0;k<WORDS;k++) X[k]=B[k];
    for (int i=0;i<N;i++){
        unsigned int* Vi = V + (size_t)i*WORDS;
        for (int k=0;k<WORDS;k++) Vi[k]=X[k];
        blockmix(X,Y);
        for (int k=0;k<WORDS;k++) X[k]=Y[k];
    }
    for (int i=0;i<N;i++){
        unsigned int j = X[(TWOR-1)*16] % (unsigned int)N;
        unsigned int* Vj = V + (size_t)j*WORDS;
        for (int k=0;k<WORDS;k++) X[k]^=Vj[k];
        blockmix(X,Y);
        for (int k=0;k<WORDS;k++) X[k]=Y[k];
    }
    for (int k=0;k<WORDS;k++) B[k]=X[k];
}
}
"""

# Threads per block. Kept small: this kernel is memory-bound and each thread needs
# 2 KiB of shared memory (X+Y), so lower occupancy per block is fine and leaves
# shared-memory headroom. Empirically TPB=8 is the sweet spot on Ada/Blackwell.
_THREADS_PER_BLOCK = 8
_WORDS = 256              # 2r * 16 for r=8
_BLOCK_BYTES = _WORDS * 4  # 1 KiB
_SHARED_BYTES = _THREADS_PER_BLOCK * _WORDS * 2 * 4

_kernel = None
_V_buffer = None
_V_capacity_blocks = 0
_V_memory_limit_blocks = 0
_V_N = None


def _get_kernel():
    global _kernel
    if _kernel is None:
        cp = _cupy()
        _kernel = cp.RawKernel(_KERNEL_SRC, "romix")
        _kernel.max_dynamic_shared_size_bytes = _SHARED_BYTES
    return _kernel


def free_buffers():
    """Release the cached ROMix scratchpad and staging buffers and return pooled device memory to the driver.

    Used when CUDA was benchmarked but another backend won the comparison, so the
    (potentially many GB) scratchpad isn't left tying up the GPU for the whole run.
    """
    global _V_buffer, _V_capacity_blocks, _V_N, _stream, _pinned_in, _pinned_out
    global _np_in, _np_out, _d_blocks, _V_memory_limit_blocks
    _V_buffer = None
    _V_capacity_blocks = 0
    _V_memory_limit_blocks = 0
    _V_N = None
    _stream = None
    _pinned_in = None
    _pinned_out = None
    _np_in = None
    _np_out = None
    _d_blocks = None
    if _cp is not None:
        try:
            _cp.get_default_memory_pool().free_all_blocks()
        except Exception:
            pass


def _max_concurrent_blocks(N):
    """How many 16 MiB ROMix scratchpads to run at once.

    Sized from *free* device memory, but only ever called when (re)allocating
    V, with any previous V already released — so it reflects real availability,
    including memory already used by a display, without the shrink-to-nothing
    feedback loop that would happen if it were measured while V was allocated.
    """
    cp = _cupy()
    free, _total = cp.cuda.runtime.memGetInfo()
    v_bytes_per_block = N * _BLOCK_BYTES
    usable = int(free * 0.85)  # leave headroom for I/O buffers, pool and driver
    return max(1, usable // v_bytes_per_block)


# Historical fixed default for --cuda-batch (BIP38: p=8, N=2^14).
DEFAULT_BATCH = 200


def suggest_batch(p=8, N=1 << 14):
    """Suggested default --cuda-batch: the number of passwords whose p*batch
    ROMix scratchpads fit in free VRAM in a single wave.

    The kernel is latency-bound, so a batch that spills into a second wave
    costs roughly an extra full wave rather than a proportional fraction
    (measured on an RTX 5090: one wave ~350 ms whether it holds 800 or 1600
    blocks, two waves ~1050 ms). On a 32 GB card this returns the historical
    default of 200; smaller cards get a smaller single-wave batch.
    """
    if not is_available():
        return DEFAULT_BATCH
    try:
        blocks = _max_concurrent_blocks(N)
    except Exception:  # noqa: BLE001 -- fall back to the historical default
        return DEFAULT_BATCH
    return max(25, min(DEFAULT_BATCH, blocks // max(1, p)))


def _romix_blocks(host_blocks, N):
    """Run ROMix over an (nblk, 256) uint32 host array, in waves that fit VRAM.

    The V scratchpad is allocated once (sized to fit VRAM) and reused across calls;
    its capacity is the wave size, so a normal-sized batch runs in a single kernel
    launch rather than many small serialized waves.
    """
    import numpy as np

    cp = _cupy()
    kernel = _get_kernel()
    nblk = host_blocks.shape[0]
    if not nblk:
        return host_blocks.copy()

    global _V_buffer, _V_capacity_blocks, _V_N, _stream, _pinned_in, _pinned_out
    global _np_in, _np_out, _d_blocks, _V_memory_limit_blocks
    needs_growth = (
        _V_capacity_blocks < nblk
        and _V_capacity_blocks < _V_memory_limit_blocks
    )
    if _V_buffer is None or _V_N != N or needs_growth:
        # (Re)allocate on the first call, when N changes, or when a batch
        # can use more of the memory budget than an earlier small batch did.
        # Once the scratchpad fills that budget, larger batches reuse it in
        # waves instead of reallocating the same buffers on every call.
        # free_buffers() releases the old scratchpad to the driver before
        # _max_concurrent_blocks() measures free memory, so the measurement
        # still reflects real availability.
        free_buffers()
        _V_memory_limit_blocks = _max_concurrent_blocks(N)
        cap = min(nblk, _V_memory_limit_blocks)
        _V_buffer = cp.empty((cap, N * _WORDS), dtype=cp.uint32)
        _V_capacity_blocks = cap
        _V_N = N
        # Persistent staging buffers: pinned host memory is what makes the
        # transfers below genuinely asynchronous (pageable copies are silently
        # staged and fully synchronized by the driver), and the device block
        # buffer is reused across calls and waves.
        nbytes = cap * _WORDS * 4
        _pinned_in = cp.cuda.alloc_pinned_memory(nbytes)
        _pinned_out = cp.cuda.alloc_pinned_memory(nbytes)
        # (count= is required: the pinned-memory pool may hand back a block
        # larger than requested, and the buffer protocol exposes all of it.)
        _np_in = np.frombuffer(_pinned_in, dtype=np.uint32,
                               count=cap * _WORDS).reshape(cap, _WORDS)
        _np_out = np.frombuffer(_pinned_out, dtype=np.uint32,
                                count=cap * _WORDS).reshape(cap, _WORDS)
        _d_blocks = cp.empty((cap, _WORDS), dtype=cp.uint32)
        _stream = cp.cuda.Stream()

    rt = cp.cuda.runtime
    wave = _V_capacity_blocks
    out = np.empty_like(host_blocks)
    for start in range(0, nblk, wave):
        end = min(start + wave, nblk)
        chunk = end - start
        nbytes = chunk * _WORDS * 4
        # Stage through pinned memory, then run H2D -> kernel -> D2H on the
        # dedicated stream and synchronize once per wave.
        np.copyto(_np_in[:chunk], host_blocks[start:end])
        rt.memcpyAsync(_d_blocks.data.ptr, _np_in.ctypes.data, nbytes,
                       rt.memcpyHostToDevice, _stream.ptr)
        grid = (chunk + _THREADS_PER_BLOCK - 1) // _THREADS_PER_BLOCK
        kernel(
            (grid,), (_THREADS_PER_BLOCK,),
            (_d_blocks[:chunk], _V_buffer, np.int32(N), np.int32(chunk)),
            shared_mem=_SHARED_BYTES, stream=_stream,
        )
        rt.memcpyAsync(_np_out.ctypes.data, _d_blocks.data.ptr, nbytes,
                       rt.memcpyDeviceToHost, _stream.ptr)
        _stream.synchronize()
        out[start:end] = _np_out[:chunk]
    return out


def scrypt_batch(passwords, salt, N, r, p, dklen):
    """CUDA scrypt for a list of password bytestrings. Returns a list of dk bytes.

    Mirrors ``hashlib.scrypt`` semantics. r must be 8 (BIP38). The memory-hard
    ROMix runs on the GPU; the two 1-iteration PBKDF2-SHA256 steps run on the CPU.
    """
    if r != 8:
        raise ValueError("cuda_scrypt only supports r=8 (BIP38)")
    if not isinstance(N, int) or N < 2 or N & (N - 1):
        raise ValueError("scrypt N must be a power of two greater than one")
    if not isinstance(p, int) or p < 1 or not isinstance(dklen, int) or dklen < 1:
        raise ValueError("scrypt p and dklen must be positive integers")
    passwords = list(passwords)
    if not passwords:
        return []

    import numpy as np

    blocklen = 128 * r  # 1024 bytes = 256 uint32
    # Expand each password to p blocks via PBKDF2-SHA256 (1 iteration).
    all_blocks = []
    for pw in passwords:
        b = hashlib.pbkdf2_hmac("sha256", pw, salt, 1, dklen=p * blocklen)
        for i in range(p):
            all_blocks.append(b[i * blocklen:(i + 1) * blocklen])
    if not all_blocks:
        return []
    host = np.frombuffer(b"".join(all_blocks), dtype=np.uint32).reshape(len(all_blocks), _WORDS).copy()

    mixed = _romix_blocks(host, N)
    mixed_bytes = mixed.tobytes()

    # Finalize: dk = PBKDF2-SHA256(pw, concat(p ROMix outputs), 1, dklen).
    results = []
    stride = p * blocklen
    for pi, pw in enumerate(passwords):
        expensive = mixed_bytes[pi * stride:(pi + 1) * stride]
        results.append(hashlib.pbkdf2_hmac("sha256", pw, expensive, 1, dklen=dklen))
    return results
