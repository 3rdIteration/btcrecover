#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B. Kerler 2018-2021
# MIT License
import os
from hashlib import pbkdf2_hmac
from binascii import unhexlify
from collections import deque
from itertools import chain, repeat, zip_longest
import numpy as np
import pyopencl as cl

# Minimum number of items to execute in a single OpenCL batch.  Some
# OpenCL runtimes (such as PoCL) crash when a kernel is launched with a
# very small global size, so pad the batch to at least this many items.
MIN_BATCH_SIZE = 8
from lib.opencl_brute.buffer_structs import buffer_structs
import os, sys, inspect

current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)

"""
    Original copyright:
    Copyright by B.Kerler 2017, PBKDF1_SHA1 and SHA256 PyOpenCl implementation, max 32 chars for password + salt
    MIT License
    Implementation was confirmed to work with
    Intel OpenCL on Intel(R) HD Graphics 520 and Intel(R) Core(TM) i5-6200U CPU and GeForce RTX 3080
"""
"""
    Adapted for generalising to more hash functions
    Allows any length input (efficiently, by declaring the max in advance)
     - salt ditched atm, but hoping to restore it
     - pbkdf2 forgotten about for now
"""


# Corresponding to opencl (CAN'T BE CHANGED):
r = 8
BLOCK_LEN_BYTES = 128 * r


# Little helper, (22,5) -> 5,5,5,5,2.  itertools is bae
def take_in_chunks(n, d):
    assert d > 0 and n >= 0
    return chain(repeat(d, n // d), filter(lambda x: x != 0, [n % d]))


def printif(b, s):
    if b:
        print(s)


class opencl_interface:
    debug = False
    inv_memory_density = 1

    # Initialiser for the key properties
    #   pbkdf related initialisation removed, will reappear somewhere else
    def __init__(
        self,
        platformNum,
        debug=0,
        write_combined_file=False,
        maxWorkgroupSize=60000,
        inv_memory_density=1,
        N_value=15,
        openclDevice=0,
    ):
        self.workgroupsize = 0
        self.computeunits = 0
        self.wordSize = None
        self.N = None
        self.wordType = None
        printif(debug, "Using Platform %d:" % platformNum)
        devices = cl.get_platforms()[platformNum].get_devices()
        self.platform_number = platformNum
        # Show devices for the platform, and adjust workgroup size
        # Create the context for GPU/CPU
        # Adjust workgroup size so that we don't run out of RAM:
        # As with bench_sCrypt.py, not really working!
        self.sworkgroupsize = self.determine_workgroupsize(N_value)
        self.inv_memory_density = inv_memory_density
        self.ctx = cl.Context(devices)
        self.queue = cl.CommandQueue(self.ctx, devices[openclDevice])
        self.debug = debug

        for device in devices:
            printif(
                debug,
                "--------------------------------------------------------------------------",
            )
            printif(debug, " Device - Name: " + device.name)
            printif(debug, " Device - Type: " + cl.device_type.to_string(device.type))
            printif(
                debug, " Device - Compute Units: {0}".format(device.max_compute_units)
            )
            printif(
                debug,
                " Device - Max Work Group Size: {0:.0f}".format(
                    device.max_work_group_size
                ),
            )
            printif(
                debug, " Device - Global memory size: {}".format(device.global_mem_size)
            )
            printif(
                debug, " Device - Local memory size:  {}".format(device.local_mem_size)
            )
            printif(
                debug,
                " Device - Max clock frequency: {} MHz".format(
                    device.max_clock_frequency
                ),
            )

            assert (
                device.endian_little == 1
            ), "DEVICE is not little endian : pretty sure we rely on this!"
            if self.workgroupsize == 0:
                self.workgroupsize = maxWorkgroupSize
                self.workgroupsize = min(self.workgroupsize, device.max_work_group_size)
            else:
                self.workgroupsize = min(self.workgroupsize, device.max_work_group_size)

            if self.computeunits == 0:
                self.computeunits = device.max_compute_units
            else:
                self.computeunits = min(self.computeunits, device.max_compute_units)

            # if device.max_work_group_size<self.workgroupsize:
            #    self.workgroupsize=device.max_work_group_size

        printif(debug, "\nUsing work group size of %d\n" % self.workgroupsize)

        # Set the debug flags
        # os.environ['PYOPENCL_COMPILER_OUTPUT'] = str(debug)
        self.write_combined_file = write_combined_file

    def compile(
        self, bufferStructsObj, library_file, footer_file=None, N=15, invMemoryDensity=2
    ):
        assert type(N) == int
        assert N < 20, (
            "N >= 20 won't fit in a single buffer, so is unsupported. "
            + "Nothing sane should use 20, is this wickr?"
        )
        self.N = N
        assert (
            bufferStructsObj is not None
        ), "need to supply a bufferStructsObj : set all to 0 if necessary"
        assert (
            bufferStructsObj.code is not None
        ), "bufferStructsObj should be initialised"
        bufStructs = bufferStructsObj
        self.wordSize = bufStructs.wordSize

        # set the np word type, for use in .run
        npType = {
            4: np.uint32,
            8: np.uint64,
        }
        self.wordType = npType[self.wordSize]

        if footer_file != None:
            src = bufStructs.code
        else:
            src = ""
        if library_file:
            with open(
                os.path.join("lib", "opencl_brute", "worker", "generic", library_file),
                "r",
            ) as rf:
                src += rf.read()

        if footer_file:
            with open(
                os.path.join("lib", "opencl_brute", "worker", "generic", footer_file),
                "r",
            ) as rf:
                src += rf.read()

        # Standardise to using no \r's, move to bytes to stop trickery
        src = src.encode("ascii")
        src = src.replace(b"\r\n", b"\n")

        # Debugging
        if self.write_combined_file:
            with open("combined_" + library_file, "wb") as wf:
                wf.write(src)

        # Convert back to text!
        src = src.decode("ascii")

        # Check that it starts with 2 newlines, for adding our defines
        if src.startswith("\n\n"):
            src = "\n\n" + src
            src = src[len("\n\n") :]
            # Prepend define N and invMemoryDensity
            defines = "#define N {}\n#define invMemoryDensity {}\n".format(
                N, invMemoryDensity
            )
            src = defines + src

        # Kernel function instantiation. Build returns self.
        prg = cl.Program(self.ctx, src).build()
        return prg

    # Forms the input buffer of derived keys
    # Returns the buffer and number in the buffer, <= n (iter may be exhausted)
    def make_input_buffer(self, dkIter, n):
        inpArray = bytearray()
        numEaten = n

        for i in range(n):
            try:
                dk = dkIter.__next__()
            except StopIteration:
                # Correct the chunk size and break
                numEaten = i
                break

            assert len(dk) == BLOCK_LEN_BYTES
            #   , "Derived key input is length {}, when we expected {}".format(len(dk), BLOCK_LEN_BYTES)

            inpArray.extend(dk)

        # pyopencl doesn't like empty buffers, so just cheer it up
        #   (making the buffer larger isn't an issue)
        if len(inpArray) == 0:
            inpArray = b"\x00"

        inp_g = cl.Buffer(
            self.ctx,
            cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR,
            hostbuf=inpArray,
        )

        return inp_g, numEaten

    def run(
        self, bufStructs, func, pwdIter, salt=b"", paddedLenFunc=None, rtnPwds=None
    ):
        # PaddedLenFunc is just for checking: lower bound with original length if not supplied
        wordType = self.wordType
        wordSize = self.wordSize
        ctx = self.ctx
        queue = self.queue
        hashBlockSize_bits = bufStructs.hashBlockSize_bits
        if not paddedLenFunc:
            paddedLenFunc = lambda x, bs: x

        # Checks on password list : not possible now we have iters!

        inBufSize_bytes = bufStructs.inBufferSize_bytes
        outBufSize_bytes = bufStructs.outBufferSize_bytes
        outBufferSize = bufStructs.outBufferSize
        saltBufferSize_bytes = bufStructs.saltBufferSize_bytes

        # Main loop is taking chunks of at most the workgroup size
        while True:
            # Moved to bytearray initially, avoiding copying and above all
            #   'np.append' which is horrific
            pwArray = bytearray()

            # For each password in our chunk, process it into pwArray, with length first
            # Notice that this lines up with the struct declared in the .cl file!
            chunkSize = self.workgroupsize
            for i in range(self.workgroupsize):
                try:
                    pw = pwdIter.__next__()
                    # Since we take a iterator, we feed the passwords back if requested
                    if rtnPwds is not None:
                        rtnPwds.append(pw)
                except StopIteration:
                    # Correct the chunk size and break
                    chunkSize = i
                    break

                pwLen = len(pw)
                # Now passing hash block size as a parameter.. could be None?
                assert (
                    paddedLenFunc(pwLen, hashBlockSize_bits // 8) <= inBufSize_bytes
                ), (
                    "password #"
                    + str(i)
                    + ", '"
                    + pw.decode()
                    + "' (length "
                    + str(pwLen)
                    + ") exceeds the input buffer (length "
                    + str(inBufSize_bytes)
                    + ") when padded"
                )

                # Add the length to our pwArray, then pad with 0s to struct size
                # prev code was np.array([pwLen], dtype=np.uint32), this ultimately is equivalent
                pwArray.extend(
                    pwLen.to_bytes(wordSize, "little")
                    + pw
                    + (b"\x00" * (inBufSize_bytes - pwLen))
                )

            if chunkSize == 0:
                break

            realChunk = chunkSize
            if chunkSize < MIN_BATCH_SIZE:
                pad = MIN_BATCH_SIZE - chunkSize
                pwArray.extend(b"\x00" * ((wordSize + inBufSize_bytes) * pad))
                chunkSize = MIN_BATCH_SIZE
            # print("Chunksize = {}".format(chunkSize))

            # Convert the pwArray into a numpy array, just the once.
            # Declare the numpy array for the digest output
            pwArray = np.frombuffer(pwArray, dtype=wordType)
            result = np.zeros(outBufferSize * chunkSize, dtype=wordType)

            # Make the salty array, with length at the front
            saltLen = len(salt)
            saltArray = bytearray(
                saltLen.to_bytes(wordSize, "little")
                + salt
                + (b"\x00" * (saltBufferSize_bytes - saltLen))
            )
            saltArray = np.frombuffer(saltArray, dtype=wordType)
            assert saltArray.nbytes - wordSize == saltBufferSize_bytes, (
                "Salt doesn't fit in the " "buffer! "
            )

            # Allocate memory for variables on the device
            pass_g = cl.Buffer(
                ctx,
                cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR,
                hostbuf=pwArray,
            )
            salt_g = cl.Buffer(
                ctx,
                cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR,
                hostbuf=saltArray,
            )
            result_g = cl.Buffer(ctx, cl.mem_flags.WRITE_ONLY, result.nbytes)

            # print("=========== Initial buffers ==============")
            # print(" pass_g.nbytes = {}".format(pwArray.nbytes))
            # print(" salt_g.nbytes = {}".format(saltArray.nbytes))
            # print(" result_g.nbytes = {}".format(result.nbytes))

            # Call Kernel. Automatically takes care of block/grid distribution
            pwdim = (chunkSize,)

            # Main function callback : could adapt to pass further data
            func(self, pwdim, pass_g, salt_g, result_g)
            # self.prg.hmac_main(self.queue, pwdim, None, pass_g, salt_g, result_g)

            # Read the results back into our array of int32s, then hexlify
            # Some inefficiency here, unavoidable using hexlify
            cl.enqueue_copy(queue, result, result_g)

            # Chop up into the individual hash digests, then trim to necessary hash length.

            # Yield this block of results
            results = [
                bytes(result[i : i + outBufSize_bytes // wordSize])
                for i in range(0, len(result), outBufSize_bytes // wordSize)
            ]
            yield results[:realChunk]

        # No main return
        return None

    def run_saltlist(
        self,
        bufStructs,
        func,
        saltIter,
        password=b"",
        paddedLenFunc=None,
        rtnSalts=None,
    ):
        # PaddedLenFunc is just for checking: lower bound with original length if not supplied
        wordType = self.wordType
        wordSize = self.wordSize
        ctx = self.ctx
        queue = self.queue
        hashBlockSize_bits = bufStructs.hashBlockSize_bits
        if not paddedLenFunc:
            paddedLenFunc = lambda x, bs: x

        # Checks on password list : not possible now we have iters!

        inBufSize_bytes = bufStructs.inBufferSize_bytes
        outBufSize_bytes = bufStructs.outBufferSize_bytes
        outBufferSize = bufStructs.outBufferSize

        # Main loop is taking chunks of at most the workgroup size
        while True:
            # Moved to bytearray initially, avoiding copying and above all
            #   'np.append' which is horrific
            saltArray = bytearray()

            # For each password in our chunk, process it into pwArray, with length first
            # Notice that this lines up with the struct declared in the .cl file!
            chunkSize = self.workgroupsize
            for i in range(self.workgroupsize):
                try:
                    salt = saltIter.__next__()
                    # Since we take a iterator, we feed the passwords back if requested
                    if rtnSalts != None:
                        rtnSalts.append(salt)
                except StopIteration:
                    # Correct the chunk size and break
                    chunkSize = i
                    break

                saltLen = len(salt)
                # Now passing hash block size as a parameter.. could be None?
                assert (
                    paddedLenFunc(saltLen, hashBlockSize_bits // 8) <= inBufSize_bytes
                ), (
                    "salt #"
                    + str(i)
                    + ", '"
                    + salt.decode()
                    + "' (length "
                    + str(saltLen)
                    + ") exceeds the input buffer (length "
                    + str(inBufSize_bytes)
                    + ") when padded"
                )

                # Add the length to our saltLen, then pad with 0s to struct size
                # prev code was np.array([saltLen], dtype=np.uint32), this ultimately is equivalent
                saltArray.extend((saltLen).to_bytes(self.wordSize, "little"))
                saltArray.extend(salt)
                saltArray.extend([0] * (inBufSize_bytes - saltLen))

            if chunkSize == 0:
                break

            realChunk = chunkSize
            if chunkSize < MIN_BATCH_SIZE:
                pad = MIN_BATCH_SIZE - chunkSize
                saltArray.extend(b"\x00" * ((self.wordSize + inBufSize_bytes) * pad))
                chunkSize = MIN_BATCH_SIZE
            # print("Chunksize = {}".format(chunkSize))

            # Convert the pwArray into a numpy array, just the once.
            # Declare the numpy array for the digest output
            saltArray = np.frombuffer(saltArray, dtype=self.wordType)
            result = np.zeros(bufStructs.outBufferSize * chunkSize, dtype=self.wordType)

            # Make the salty array, with length at the front
            pwLen = len(password)
            pwArray = bytearray((pwLen).to_bytes(self.wordSize, "little"))
            pwArray.extend(password)
            ##saltArray.extend(b"\x00" * ((-saltLen) % 4))
            pwArray.extend(b"\x00" * (bufStructs.pwdBufferSize_bytes - pwLen))
            pwArray = np.frombuffer(pwArray, dtype=self.wordType)
            assert (
                pwArray.nbytes - self.wordSize == bufStructs.pwdBufferSize_bytes
            ), "Salt doesn't fit in the buffer!"

            # Allocate memory for variables on the device
            pass_g = cl.Buffer(
                self.ctx,
                cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR,
                hostbuf=pwArray,
            )
            salt_g = cl.Buffer(
                self.ctx,
                cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR,
                hostbuf=saltArray,
            )
            result_g = cl.Buffer(self.ctx, cl.mem_flags.WRITE_ONLY, result.nbytes)

            # print("=========== Initial buffers ==============")
            # print(" pass_g.nbytes = {}".format(pwArray.nbytes))
            # print(" salt_g.nbytes = {}".format(saltArray.nbytes))
            # print(" result_g.nbytes = {}".format(result.nbytes))

            # Call Kernel. Automatically takes care of block/grid distribution
            pwdim = (chunkSize,)

            # Main function callback : could adapt to pass further data
            func(self, pwdim, pass_g, salt_g, result_g)
            ##self.prg.hmac_main(self.queue, pwdim, None, pass_g, salt_g, result_g)

            # Read the results back into our array of int32s, then hexlify
            # Some inefficiency here, unavoidable using hexlify
            cl.enqueue_copy(self.queue, result, result_g)

            # hexvalue = hexlify(result)

            # Chop up into the individual hash digests, then trim to necessary hash length.
            results = []
            # for i in range(0, len(hexvalue), outBufSize_hs):
            #    hexRes = hexvalue[i:i + outBufSize_hs].decode()
            #    results.append(hexRes)

            for i in range(0, len(result), outBufSize_bytes // bufStructs.wordSize):
                v = bytes(result[i : i + outBufSize_bytes // bufStructs.wordSize])
                results.append(v)

            # Yield this block of results
            yield results[:realChunk]

        # No main return
        return None

    def determine_workgroupsize(self, N_value=15):
        devices = cl.get_platforms()[self.platform_number].get_devices()
        wgSize = 0
        for device in devices:
            # Actually adjust based on invMemoryDensity!
            N_blocks_bytes = (1 << N_value) * BLOCK_LEN_BYTES // self.inv_memory_density
            memoryForOneCore = BLOCK_LEN_BYTES * 2 + N_blocks_bytes  # input, output & V

            ## ! Restrict to 98% of avaiable memory
            coresOnDevice = int(0.98 * device.global_mem_size) // memoryForOneCore
            percentUsage = (
                100 * memoryForOneCore * coresOnDevice / device.global_mem_size
            )
            percentUsage = str(percentUsage)[:4]
            if self.debug == 1:
                print(
                    "Using {} cores on device with global memory {}, = {}%".format(
                        coresOnDevice, device.global_mem_size, percentUsage
                    )
                )
            wgSize += coresOnDevice

        if self.debug == 1:
            print("Workgroup size determined as {}".format(wgSize))

        return wgSize

    def run_scrypt(self, sprg, kernelCall, dkIter):
        N_blocks_bytes = (1 << self.N) * BLOCK_LEN_BYTES

        # no. of cores' memory that we can fit into a single buffer
        #   (seemingly anyway, why isn't it 2^31?)
        # note: this is NOT the workgroupsize, nor does it bound it
        maxGangSize = (1 << 31) // N_blocks_bytes
        assert maxGangSize > 0, "Uh-oh we couldn't fit a single core's V in a buffer."

        #   A. Before the loop we produce our huge buffers, once only.
        #   B. Also make our output buffers & numpys now, just once, to save work
        #     Note these will be atleast big enough throughout the loop: sometimes they'll have extra room.
        largeBuffers = []
        outBuffers = []
        outNumpys = []
        outSizes = []
        for gangSize in take_in_chunks(self.sworkgroupsize, maxGangSize):
            # Produce the large buffer for storing this gang's V arrays
            # No longer producing a big bytes object in Python

            # arr = np.frombuffer(bytes(gangSize * N_blocks_bytes), dtype=np.uint32)
            # Why is this read only?
            arr_g = cl.Buffer(
                self.ctx, cl.mem_flags.READ_ONLY, size=gangSize * N_blocks_bytes
            )
            largeBuffers.append(arr_g)

            # Produce the gang's output buffer and (small) numpy array to copy out to
            nBytes = BLOCK_LEN_BYTES * gangSize
            result = np.zeros(nBytes // 4, dtype=np.uint32)
            assert nBytes == result.nbytes
            result_g = cl.Buffer(self.ctx, cl.mem_flags.WRITE_ONLY, nBytes)
            outBuffers.append(result_g)
            outNumpys.append(result)

            # No output from round 0!
            outSizes.append(0)

        # ! For minimal latency, we only block just before our next calls to the kernels:
        #     there is basically no work between the two.

        # Main loop is taking chunks of workgroup size,
        #   or less if we exhaust the input derived keys iter
        iterActive = True
        while iterActive:
            #   1. Make New SMALL input buffers (derived key buffer, was password & salt)
            #       if we exhaust dkIter, continue producing 'empty' input buffers, but mark to leave the main loop
            newInputs = []
            inCounts = []
            for gangSize in take_in_chunks(self.sworkgroupsize, maxGangSize):
                input_g, numEaten = self.make_input_buffer(dkIter, gangSize)
                iterActive = (
                    numEaten == gangSize
                )  # note gangSize > 0, so once False this will persist
                newInputs.append(input_g)
                inCounts.append(numEaten)

            #   2. (BLOCKING) wait for all our workers to finish (should be at similar times),
            #       and copy output buffers out to numpy (minimal time loss here, could use
            #       2 sets of output buffers instead)
            #   Note we may well have copied too much: this is dealt with in 4. below
            for outSize, outNumpy, outBuf in zip_longest(
                outSizes, outNumpys, outBuffers
            ):
                if outSize > 0:
                    cl.enqueue_copy(
                        self.queue, outNumpy, outBuf
                    )  # is_blocking defaults to true :)

            # print("Calling kernels..")
            #   3. (NON-BLOCKING) queue the kernel calls
            for input_g, arr_g, result_g, inCount in zip_longest(
                newInputs, largeBuffers, outBuffers, inCounts
            ):
                if inCount > 0:
                    dim = (inCount,)
                    # print("inCount = {}".format(inCount))
                    # print("All sizes in bytes (hopefully):")
                    # print("input_g.size = {}".format(input_g.size))
                    # print("arr_g.size = {}".format(arr_g.size))
                    # print("result_g.size = {}".format(result_g.size))
                    # print("\nOpenCL code now:\n")
                    kernelCall(sprg, (self.queue, dim, None, input_g, arr_g, result_g))
            # print("Kernels running..")

            #   4. Process the outputs from the last round, yielding now (while the GPUs are busy)
            #       Also copy the input counts across to output sizes, for the next loop / final processing below
            for i, (outNumpy, inCount) in enumerate(zip_longest(outNumpys, inCounts)):
                outSize = outSizes[i]

                assert outSize % BLOCK_LEN_BYTES == 0
                outBytes = outNumpy.tobytes()
                for j in range(0, outSize, BLOCK_LEN_BYTES):
                    yield outBytes[j : j + BLOCK_LEN_BYTES]

                outSizes[i] = inCount * BLOCK_LEN_BYTES

            # Note that if exiting here then we've updated the outSizes & called the functions
            # Just remains to capture & process the output..

        # print("Dropped out of loop")
        # Do a final loop of processing output (3 & 2)
        for outBuf, outNumpy, outSize in zip_longest(outBuffers, outNumpys, outSizes):
            # (BLOCKING) Copy!
            cl.enqueue_copy(self.queue, outNumpy, outBuf)

            assert outSize % BLOCK_LEN_BYTES == 0
            outBytes = outNumpy.tobytes()
            for i in range(0, outSize, BLOCK_LEN_BYTES):
                yield outBytes[i : i + BLOCK_LEN_BYTES]


def mdpad_128_func(pwdLen, blockSize):
    llen = pwdLen + 1 + 16
    llen += (-llen) % blockSize
    return llen


def mdpad_64_func(pwdLen, blockSize):
    # both parameters in bytes
    # length appended as a 64-bit integer
    llen = pwdLen + 1 + 8
    llen += (-llen) % blockSize
    return llen


def concat(ll):
    return [obj for lval in ll for obj in lval]


class opencl_algos:
    def __init__(
        self,
        platform,
        debug,
        write_combined_file,
        inv_memory_density=1,
        openclDevice=0,
        workgroupsize=None,
    ):
        if not debug:
            debug = 0
        kwargs = {}
        if workgroupsize is not None:
            kwargs["maxWorkgroupSize"] = workgroupsize
        self.opencl_ctx = opencl_interface(
            platform, debug, write_combined_file, openclDevice=openclDevice, **kwargs
        )
        self.platform_number = platform
        self.inv_memory_density = inv_memory_density
        self.max_out_bytes = 0

    def cl_scrypt_init(self, N_value=15, forceAltKernel=None):
        # Initialise the openCL context & compile, with both debugging settings off
        debug = 0
        bufStructs = buffer_structs()
        if forceAltKernel:
            print("Loading Alternative sCrypt Kernel:", forceAltKernel)
            sprg = self.opencl_ctx.compile(
                bufStructs,
                forceAltKernel,
                None,
                N=N_value,
                invMemoryDensity=self.inv_memory_density,
            )
        else:
            sprg = self.opencl_ctx.compile(
                bufStructs,
                "sCrypt.cl",
                None,
                N=N_value,
                invMemoryDensity=self.inv_memory_density,
            )
        return [sprg, bufStructs]

    def cl_scrypt(
        self,
        ctx,
        passwords,
        N_value=15,
        r_value=3,
        p_value=1,
        desired_key_length=32,
        hex_salt=unhexlify("DEADBEEFDEADBEEFDEADBEEFDEADBEEF"),
    ):

        def get_dk_iter(p, salt, pwdIter, rtnPwds=None):
            # r fixed as 8 in the OpenCL
            r_val = 8
            blockSize = 128 * r_val
            for pwd in pwdIter:
                if rtnPwds is not None:
                    rtnPwds.append(pwd)
                # Get derived key, then split into p chunks and yield
                dk = pbkdf2_hmac("sha256", pwd, salt, 1, dklen=blockSize * p)

                # Yield
                for i in range(p):
                    yield dk[i * blockSize : (i + 1) * blockSize]

        sprg = ctx[0]

        # Our callback with the kernel name
        # Debugging: calls Salsa20
        def kernel_call(snprg, params):
            return snprg.ROMix(*params)  # prg.ROMix(*params)

        # Derived key iter: yields p keys for each password
        passwordList = deque()
        dkIter = get_dk_iter(1 << p_value, hex_salt, passwords, passwordList)

        result = []
        # Main call.
        group = []
        result_append = result.append
        passwordList_popleft = passwordList.popleft
        for singleOutput in self.opencl_ctx.run_scrypt(sprg, kernel_call, dkIter):
            group.append(singleOutput)
            if len(group) == 1 << p_value:
                expensiveSalt = b"".join(group)
                commonPwd = passwordList_popleft()
                sCryptResult = pbkdf2_hmac(
                    "sha256", commonPwd, expensiveSalt, 1, desired_key_length
                )

                # For now print out for debugging
                # print("Password={}".format(commonPwd))
                # print("sCrypt={}".format(hexlify(sCryptResult).decode().upper()))
                # result.append("{}".format(hexlify(sCryptResult).decode().lower()))
                result_append(sCryptResult)
                group = []
        return result

    # def mdPadLenFunc(self, pwdLen):
    #    l = (pwdLen + 1 + 8)
    #    l += (64 - (l % 64)) % 64
    #    return l

    def cl_sha512_init(
        self, option="", max_in_bytes=128, max_salt_bytes=32, dklen=0, max_ct_bytes=0
    ):
        bufStructs = buffer_structs()
        bufStructs.specifySHA2(512, max_in_bytes, max_salt_bytes, dklen, max_ct_bytes)
        assert bufStructs.wordSize == 8  # set when you specify sha512
        prg = self.opencl_ctx.compile(bufStructs, "sha512.cl", option)
        return [prg, bufStructs]

    def cl_sha512(self, ctx, passwordlist):
        # self.cl_sha512_init()
        prg = ctx[0]
        bufStructs = ctx[1]

        def func(s, pwdim, pass_g, salt_g, result_g):
            prg.hash_main(s.queue, pwdim, None, pass_g, result_g)

        return concat(
            self.opencl_ctx.run(
                bufStructs, func, iter(passwordlist), b"", mdpad_128_func
            )
        )

    def cl_sha256_init(
        self, option="", max_in_bytes=128, max_salt_bytes=32, dklen=0, max_ct_bytes=0
    ):
        bufStructs = buffer_structs()
        bufStructs.specifySHA2(256, max_in_bytes, max_salt_bytes, dklen, max_ct_bytes)
        assert bufStructs.wordSize == 4  # set when you specify sha256
        prg = self.opencl_ctx.compile(bufStructs, "sha256.cl", option)
        return [prg, bufStructs]

    def cl_sha256(self, ctx, passwordlist):
        # self.cl_sha256_init()
        prg = ctx[0]
        bufStructs = ctx[1]

        def func(s, pwdim, pass_g, salt_g, result_g):
            prg.hash_main(s.queue, pwdim, None, pass_g, result_g)

        return concat(
            self.opencl_ctx.run(
                bufStructs, func, iter(passwordlist), b"", mdpad_64_func
            )
        )

    def cl_md5_init(self, option=""):
        bufStructs = buffer_structs()
        bufStructs.specifyMD5()
        assert bufStructs.wordSize == 4  # set when you specify md5
        prg = self.opencl_ctx.compile(bufStructs, "md5.cl", option)
        return [prg, bufStructs]

    def cl_md5(self, ctx, passwordlist):
        # self.cl_md5_init()
        prg = ctx[0]
        bufStructs = ctx[1]

        def func(s, pwdim, pass_g, salt_g, result_g):
            prg.hash_main(s.queue, pwdim, None, pass_g, result_g)

        return concat(
            self.opencl_ctx.run(
                bufStructs, func, iter(passwordlist), b"", mdpad_64_func
            )
        )

    def cl_sha1_init(self, option=""):
        bufStructs = buffer_structs()
        bufStructs.specifySHA1()
        assert bufStructs.wordSize == 4  # set when you specify sha1
        prg = self.opencl_ctx.compile(bufStructs, "sha1.cl", option)
        return [prg, bufStructs]

    def cl_sha1(self, ctx, passwordlist):
        # self.cl_sha1_init()
        prg = ctx[0]
        bufStructs = ctx[1]

        def func(s, pwdim, pass_g, salt_g, result_g):
            prg.hash_main(s.queue, pwdim, None, pass_g, result_g)

        return concat(
            self.opencl_ctx.run(
                bufStructs, func, iter(passwordlist), b"", mdpad_64_func
            )
        )

    # ===========================================================================================

    def cl_hmac(self, ctx, passwordlist, salt):
        prg = ctx[0]
        bufStructs = ctx[1]

        def func(s, pwdim, pass_g, salt_g, result_g):
            prg.hmac_main(s.queue, pwdim, None, pass_g, salt_g, result_g)

        return concat(self.opencl_ctx.run(bufStructs, func, iter(passwordlist), salt))

    def cl_md5_hmac(self, ctx, passwordlist, salt):
        # self.cl_md5_init("pbkdf2.cl")
        return self.cl_hmac(ctx, passwordlist, salt)

    def cl_sha1_hmac(self, ctx, passwordlist, salt):
        # self.cl_sha1_init("pbkdf2.cl")
        return self.cl_hmac(ctx, passwordlist, salt)

    def cl_sha256_hmac(self, ctx, passwordlist, salt):
        # self.cl_sha256_init("pbkdf2.cl")
        return self.cl_hmac(ctx, passwordlist, salt)

    def cl_sha512_hmac(self, ctx, passwordlist, salt):
        # self.cl_sha512_init("pbkdf2.cl")
        return self.cl_hmac(ctx, passwordlist, salt)

    # ===========================================================================================

    def cl_pbkdf2(self, ctx, passwordlist, salt, iters, dklen):
        prg = ctx[0]
        bufStructs = ctx[1]

        def func(s, pwdim, pass_g, salt_g, result_g):
            prg.pbkdf2(
                s.queue,
                pwdim,
                None,
                pass_g,
                salt_g,
                result_g,
                iters.to_bytes(4, "little"),
                dklen.to_bytes(4, "little"),
            )  # ! iters, dklen are always ints

        result = concat(self.opencl_ctx.run(bufStructs, func, iter(passwordlist), salt))
        if dklen != self.max_out_bytes:
            # We may have made more space for a multiple of the digest size
            result = [hexRes[:dklen] for hexRes in result]
        return result

    def cl_pbkdf2_init(self, rtype, saltlen, dklen):
        bufStructs = buffer_structs()
        if rtype == "md5":
            self.max_out_bytes = bufStructs.specifyMD5(128, saltlen, dklen)
            # hmac is defined in with pbkdf2, as a kernel function
            prg = self.opencl_ctx.compile(bufStructs, "md5.cl", "pbkdf2.cl")
        elif rtype == "sha1":
            if saltlen < 32 and dklen < 32:
                dklen = 32
                self.max_out_bytes = bufStructs.specifySHA1(32, saltlen, dklen)
                prg = self.opencl_ctx.compile(bufStructs, "pbkdf2_sha1_32.cl", None)
            else:
                self.max_out_bytes = bufStructs.specifySHA1(128, saltlen, dklen)
                prg = self.opencl_ctx.compile(bufStructs, "sha1.cl", "pbkdf2.cl")
        elif rtype == "sha256":
            if saltlen <= 64 and dklen <= 64:
                dklen = 64
            self.max_out_bytes = bufStructs.specifySHA2(256, 128, saltlen, dklen)
            if saltlen <= 64 and dklen <= 64:
                prg = self.opencl_ctx.compile(bufStructs, "pbkdf2_sha256_32.cl", None)
            else:
                prg = self.opencl_ctx.compile(bufStructs, "sha256.cl", "pbkdf2.cl")
        elif rtype == "sha512":
            self.max_out_bytes = bufStructs.specifySHA2(512, 256, saltlen, dklen)
            prg = self.opencl_ctx.compile(bufStructs, "sha512.cl", "pbkdf2.cl")
        else:
            assert "Error on hash type, unknown !!!"
        return [prg, bufStructs]

    # ===========================================================================================

    def cl_pbkdf2_saltlist(self, ctx, password, saltlist, iters, dklen):
        prg = ctx[0]
        bufStructs = ctx[1]

        def func(s, pwdim, pass_g, salt_g, result_g):
            prg.pbkdf2_saltlist(
                s.queue,
                pwdim,
                None,
                pass_g,
                salt_g,
                result_g,
                (iters).to_bytes(4, "little"),
                (dklen).to_bytes(4, "little"),
            )  # ! iters, dklen are always ints

        result = concat(
            self.opencl_ctx.run_saltlist(bufStructs, func, iter(saltlist), password)
        )
        if dklen != self.max_out_bytes:
            # We may have made more space for a multiple of the digest size
            result = [hexRes[:dklen] for hexRes in result]
        return result

    def cl_pbkdf2_saltlist_init(self, type, pwdlen, dklen):
        bufStructs = buffer_structs()
        if type == "md5":
            self.max_out_bytes = bufStructs.specifyMD5(
                max_in_bytes=128,
                max_salt_bytes=128,
                dklen=dklen,
                max_password_bytes=pwdlen,
            )
            ## hmac is defined in with pbkdf2, as a kernel function
            prg = self.opencl_ctx.compile(bufStructs, "md5.cl", "pbkdf2.cl")
        elif type == "sha1":
            self.max_out_bytes = bufStructs.specifySHA1(
                max_in_bytes=128,
                max_salt_bytes=128,
                dklen=dklen,
                max_password_bytes=pwdlen,
            )
            ## hmac is defined in with pbkdf2, as a kernel function
            prg = self.opencl_ctx.compile(bufStructs, "sha1.cl", "pbkdf2.cl")
        elif type == "sha256":
            self.max_out_bytes = bufStructs.specifySHA2(
                hashDigestSize_bits=256,
                max_in_bytes=128,
                max_salt_bytes=128,
                dklen=dklen,
                max_password_bytes=pwdlen,
            )
            prg = self.opencl_ctx.compile(bufStructs, "sha256.cl", "pbkdf2.cl")
        elif type == "sha512":
            self.max_out_bytes = bufStructs.specifySHA2(
                hashDigestSize_bits=512,
                max_in_bytes=256,
                max_salt_bytes=128,
                dklen=dklen,
                max_password_bytes=pwdlen,
            )
            prg = self.opencl_ctx.compile(bufStructs, "sha512.cl", "pbkdf2.cl")
        else:
            assert "Error on hash type, unknown !!!"
        return [prg, bufStructs]

    # ===========================================================================================

    def cl_hash_iterations(self, ctx, passwordlist, iters, hash_size):
        prg = ctx[0]
        bufStructs = ctx[1]

        def func(s, pwdim, pass_g, salt_g, result_g):
            prg.hash_iterations(
                s.queue,
                pwdim,
                None,
                pass_g,
                result_g,
                iters.to_bytes(4, "little"),
                hash_size.to_bytes(4, "little"),
            )  # ! iters are always ints

        return concat(
            self.opencl_ctx.run(
                bufStructs, func, iter(passwordlist), b"", mdpad_64_func
            )
        )

    def cl_hash_iterations_init(self, type):
        bufStructs = buffer_structs()
        if type == "md5":
            self.max_out_bytes = bufStructs.specifyMD5()
            ## hmac is defined in with pbkdf2, as a kernel function
            prg = self.opencl_ctx.compile(bufStructs, "md5.cl", "hash_iterations.cl")
        elif type == "sha1":
            self.max_out_bytes = bufStructs.specifySHA1()
            ## hmac is defined in with pbkdf2, as a kernel function
            prg = self.opencl_ctx.compile(bufStructs, "sha1.cl", "hash_iterations.cl")
        elif type == "sha256":
            self.max_out_bytes = bufStructs.specifySHA2()
            prg = self.opencl_ctx.compile(bufStructs, "sha256.cl", "hash_iterations.cl")
        elif type == "sha512":
            self.max_out_bytes = bufStructs.specifySHA2(512, 256, 0, 64)
            prg = self.opencl_ctx.compile(bufStructs, "sha512.cl", "hash_iterations.cl")
        else:
            assert "Error on hash type, unknown !!!"
        return [prg, bufStructs]
