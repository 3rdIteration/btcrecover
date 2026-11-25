import os

# Automatic backend selection (--backend auto) briefly benchmarks every GPU backend the
# machine supports. The suite runs hundreds of short recovery flows, so probing the GPU
# for each one would dominate the runtime and make results depend on the test machine's
# hardware. Tests that want a GPU backend still ask for it explicitly (--enable-opencl
# and friends); anything else may override this by setting the variable itself.
os.environ.setdefault("BTCRECOVER_AUTO_BACKEND", "0")
