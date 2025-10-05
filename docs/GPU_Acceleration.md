## BTCRecover GPU Acceleration Guide ##

### Performance Notes

BTCRecover includes support for using one or more graphics cards or dedicated accelerator cards to increase search performance. 

The performance increase that this offers depends on the type of wallet you are trying to recover, your CPU and your GPU.

For the sake of comparison, the CPU vs GPU performance for an i7-8750 vs an NVidia 1660ti, for a variety of wallets is generally:

| Recovery Type  | CPU Performance (kp/s)  | GPU Performance (kp/s)  | GPU speed boost vs CPU |
|---|---|---|---|
| Bitcoin Core (JTR Kernel)         | 0.07  | 6.75  | 96x |
| Bitcoin Core (OpenCL_Brute)       | 0.07  | 0.95  | 14x |
| Blockchain.com Main Password      | 1  | 10  | 10x |
| Blockchain.com Second Password    | 0.39  | 15.5  | 40x |
| Dogechain.info                    | 1.3     | 11.3   | 10x |
| Electrum 2 Wallet Password        | 4.5  | 21  | 4.5x |
| BIP39 Passphrase (Or Electrum 'Extra Words'  | 2.3 | 10.4 | 4.5 |
| BIP39 12 Word Seed                | 33  | 134  | 4.3x |
| BIP39 12 Word Seed (Tokenlist)    | 33  | 130  | 4x |
| BIP39 24 Word Seed                | 160  | 180  | 1.15x |
| BIP39 24 Word Seed (Tokenlist)    | 140  | 160  | 1.15x |
| Electrum Seed                     | 200  | 366  | 1.8x |
| BIP38 Encrypted Key               | 0.02 | 0.02 | 1x (But scales well with Multiple GPUs) |

**Don't simply assume that enabling GPU/OpenCL will give a speed boost at this point, especially if you have a very high end CPU and low end GPU... Test your command both with and without OpenCL/GPU and use the --no-eta and --performance arguments to evaluate performance**

_This drastic performance difference is mostly due to different parts of the process being CPU bound to varying degrees, particularly for BIP39 and Electrum seed recovery. As such shifting more processing in to the OpenCL and creating a more efficient seed generator will be future areas of work._

[You can also find performance information for a wide variety of GPUs, particularly multi-gpu situations, in this article here](Example_Multi-GPU_with_vastai.md)

## PyOpenCL Installation

GPU/OpenCL acceleration depends on your having a working install of PyOpenCL for OpenCL 1.2.

In order to use this feature, you must have a card and drivers which support OpenCL (most AMD and NVIDIA cards and drivers already support OpenCL on Windows), and you must install the required Python libraries as described below. 

GPU acceleration should also work on MacOS, however instructions for installing the required Python libraries are not currently included in this tutorial.

## PyOpenCL Installation for Windows
As of June 2023, PyOpenCL can now be simply installed via PIP and will work fine as long as you have the required GPU drivers installed on your system.

 1. Install the driver package for your GPU... Nothing else will work without this... 
 2. Open a command prompt window, and type this to install PyOpenCL and its dependencies: 

        pip3 install pyopencl

## PyOpenCL Installation for Linux

**Usage with Ubuntu 20.04**
1. For NVidia GPUs, install the Nvidia binary driver for your system. (In Ubuntu this is straight forward and explained here: https://help.ubuntu.com/community/BinaryDriverHowto/Nvidia#NVIDIA_driver_from_the_Ubuntu_repositories the 440 version of the driver metapack was tested and works fine) - I don't have a current AMD system to test with, but this should work fine as long as you have the AMD drivers installed...
2. Install the pyOpenCL library for your system.


        sudo apt install python3-pyopencl
        
Depending on your Linux environment, the Python libraries that are availale via APT may be very out of date and may not work correctly. In this case, you may need to install and build PyOpenCL via Pip. (And whether a particular version of PyOpenCL will build on your system may vary, so trying an older PyOpenCL package version may help, eg: pyopencl==2019.1.1) 

**Beyond this, no additional support will be provided for any distribution other than the most recent Ubuntu LTS release.**
Generally speaking, instructions for installing and configuring an environment for Hashcat will cover what you need to get your environment set up and working...
    
## Testing your System
To check if your PyOpenCL installation is working correctly, you can run the unit tests relating to the type of GPU accelerated recovery you want to run:


**Bitcoin Core John-The-Ripper Kernel (JTR)**

    python3 -m btcrecover.test.test_passwords -v GPUTests

Assuming the tests do not fail, GPU support can be enabled by adding the `--enable-gpu` option to the command line. There are other additional options, specifically `--global-ws` and `--local-ws`, which should also be provided along with particular values to improve the search performance. Unfortunately, the exact values for these options can only be determined by trial and error, as detailed below.

**Blockchain.com, Electrum Wallets & BIP39 Passphrases (Or Electrum 'Extra words') via OpenCL_Brute Kernel (Supports Bitcoin core too, but slower than JTR)**

    python3 -m btcrecover.test.test_passwords -v OpenCL_Tests
    
If all tests pass, then you can simply add --enable-opencl to the command line argument. The default for OpenCL platform selection and work group size should give a good result.

**BIP39 or Electrum Seed Recovery**

    python3 -m btcrecover.test.test_seeds -v OpenCL_Tests

If all tests pass, then you can simply add --enable-opencl to the command line argument. The default for OpenCL platform selection and work group size should give a good result.

### Performance Tuning: Background
The key thing to understand when it comes ot OpenCL performance tuning is that there is a fundamental difference between the way that a CPU processes instructions and a GPU.

CPU's can process commands very quickly, but can basically only perform once task at a time per CPU core. GPU's on the other hand can actually be slower at performing the same task, but the difference is that they might be able to perform a batch of 1000 tasks at the same time in parallel, rather than one after the other as occurs on a CPU.

What this means is that there can be significant perfomance differences for GPU processing depending on how large the batch of work that you are loading in to the GPU is. (And doing things like only half-filling the potential batch size will cut your performance in half)

As such, setting the Global and Local work-size arguments can make a massive difference for the JTR kernel, while using the workgroup-size command can make a big difference when using the OpenCL_Brute kernel (Though the defaults for the OpenCL_Brute kernel should automatically work out something close to optimal for your system)

This also means that performance bottleknecks that aren't an issue in CPU processing become a problem when using GPU processing. (This is precisely why a tokenlist for a 24 word seed doesn't get nearly as much of a performance boost solving as standard recovery with a BIP39 12 word seed)

This is also why you may find that there is some benefit to creating a checksummed seed list on one PC and loading that into another using the --savevalidseeds, --savevalidseeds-filesize, --multi-file-seedlist and --skip-worker-checksum arguments.

### Multi-GPU Systems
By default, both OpenCL kernels will use all GPUs that are available in a system, but they will utilise them a bit dfferently.

**JohnTheRipper Kernel (used by Bitcoin Core when the --enable-gpu argument is used)** 

Will just use a single CPU thread and use all GPUs, though it really needs the GPUs to be identical in terms of performance.

**The OpenCL_Brute kernel (enabled via the --enable-opencl argument)** 

Will allocate GPUs to threads in a round-robin. (Eg if you had 3 GPUs and 3 CPU cores, it would allocate a GPU1->CPU1, GPU2->CPU2, GPU3->CPU3, etc...) Given this, you will generally want to have at least as many threads as you have GPUs. (Though I haven't seen any systems other than ex-crypto mining rigs where you have more GPUs than CPUS) BTCRecover will default to using as many threads as there are logical CPU cores, but if your system has fewer cores than GPUs, you can always just manually specify the thread count with the --threads argument. **_Generally speaking, I would suggest that 2 threads per GPU is probably your best starting point performance wise..._**

You can also manually specify which OpenCL devices you want to use through the --opencl-devices argument. You can also list a GPU twice here, something that may be useful if one GPU is twice as powerful as the others, so you want it to be allocated a larger share. (eg: specifying GPUs 0 0 1 will allocate GPU0 to twice as many threads as GPU1) Like mentioned above, these GPUs are allocated in a round robin fashion, so you can basically specify as many devices as you have threads. 

### GPU performance tuning for Bitcoin Core and derived altcoin wallets with the JTR kernel###

A good starting point for these wallets is:

    python btcrecover.py --wallet ./btcrecover/test/test-wallets/bitcoincore-wallet.dat --performance --enable-gpu --global-ws 4096 --local-ws 256

The `--performance` option tells *btcrecover* to simply measure the performance until Ctrl-C is pressed, and not to try testing any particular passwords. You will still need a wallet file (or an `--extract-data` option) for performance testing. After you you have a baseline from this initial test, you can try different values for `--global-ws` and `--local-ws` to see if they improve or worsen performance.

For automated benchmarking you can add `--performance-runtime SECONDS` to stop the run after a fixed interval instead of relying on Ctrl-C. When a performance session exits (either manually or because the runtime limit was reached) *btcrecover* now prints a summary that includes the average kP/s rate, the elapsed time, and the number of passwords attempted, making it easier to track results from repeated tests.

If you want to explore a range of GPU settings automatically, add `--performance-scan` alongside `--performance`. By default this benchmarks several thread counts, global work sizes, and local work sizes (including the automatic `--local-ws` selection). You can further customize the scan with `--performance-scan-threads`, `--performance-scan-global-ws`, and `--performance-scan-local-ws` to explicitly control which values are tested. Each combination is executed as an individual performance run and summarized at the end so you can quickly spot the most efficient configuration for your hardware.

Finding the right values for `--global-ws` and `--local-ws` can make a 10x improvement, so it's usually worth the effort.

Generally when testing, you should increase or decrease these two values by powers of 2, for example you should increase or decrease them by 128 or 256 at a time. It's important to note that `--global-ws` must always be evenly divisible by `--local-ws`, otherwise *btcrecover* will exit with an error message.

Although this procedure can be tedious, with larger tokenlists or passwordlists it can make a significant difference.

### OpenCL performance tuning for other wallets ###

#### Limiting Derivation Paths Searched for Seed Based Wallets
By default, BTCRecover will now automatically search all common derivation paths for a given cryptocurrency. (eg: Bitcoin BIP44, 49 and 84) 

For CPU based recovery, this doesn't present a major decrease in performance, but depending on your CPU, this could **halve** your OpenCL performance. As such, if you know the derivation path that you are searching for, you should manually specify it via the --bip32-path command.

#### Address Generation Limit for Seed Based Wallets
Cryptocurrencies like Bitcoin will generally generate a new address each time you choose to "receive". The address generation limit (--addr-limit argument) tells BTCRecover how many addresses it should generate and search within for each seed. (This is why you want to use the earliest possible address from your wallet)

For CPU based recovery, setting the address generation limit to something like 10 doesn't make a huge impact on performance, whereas for OpenCL based recovery, an address generation limit as long as 10 can **halve** your search performance.

That said, if you are doing a recovery on something like an Ethereum or Ripple wallet, you can generally just leave your address generation limit at 1, as these account based cryptos tend to use a fixed receiving address. 

It should also be noted that if you are using an Address Database, you can generally just leave the address generation limit at 1...

#### Work Group Size

If you use the --opencl-info command, you will be presented with a list of OpenCL devices and their corresponding max work-group size. 

You can then use the --opencl-workgroup-size command to try setting the workgroup size manually.

**For Password Recovery:** You should try to set the workgroup command to be an exact multiple of the max workgroup size.

**For Seed Recovery** You will notice that seed recovery will automatically set the workgroup size to a much larger value.

This is because the majority of seeds generated are only checksummed, never fully hashed. The ratio of seeds generated:hashed varies for different wallet types and seed lenghts.

Generally speaking it is:
* BIP39 12 Word: 16:1
* BIP39 18 Word: 64:1
* BIP39 24 Word: 256:1
* Electrum   : 125:1

What this means is that in order to fill the maximum workgroup size for the GPU, the seedgenerator needs to pass it a chunk of possible seeds that is many times larger than the max workgroup size. (Eg: for a work group size of 1024, a BIP39 24 word seed will need 262,144 potential seeds)
