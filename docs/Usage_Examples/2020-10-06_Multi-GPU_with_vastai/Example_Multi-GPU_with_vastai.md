# Multi-GPU Password Recovery using Vast.ai
[YouTube Video can be found here: https://youtu.be/8Zqc-2Te3zQ](https://youtu.be/8Zqc-2Te3zQ)

## Background
Vast.ai is a service where users around the world can rent out their spare GPU power. It is often cheaper and faster than using rented services from commercial providers like Google or Amazon... This service is mostly used for training AIs but is also useful for running OpenCL processes like BTCRecover and Hashcat. 

This is great in that if you don't have a powerful GPU, it makes it possible to cheaply attempt password recovery in a matter of hours that might take weeks if run on your own hardware, particularly if you only have a CPU and not a powerful GPU... (Or are otherwise unable to run a process like this that might take several days) It is particularly useful with BTCRecover when run using a wallet extract, in that this allows you to securely recover the password without the possibility that the rented server owner can steal your funds.

It is also significantly cheaper than renting CPU time with a commercial service like Linode, particularly if you can rent multiple powerful servers, complete the search quickly, while still paying a similar price/hashrate. (Eg: A system that is 10x as powerful is often about 10x the price, all billed in 1s increments, so easy to only use what you need)

**This process is not secure for seed recovery, BIP39 seed recovery or where you upload the wallet file to the cloud server... At this time, BIP39 seed recovery also bottleknecks badly on CPU, so will see little benefit from this approach...**

## Performance

Blockchain.com Bechmark

```
python3 btcrecover.py --wallet ./btcrecover/test/test-wallets/blockchain-v3.0-MAY2020-wallet.aes.json --performance --enable-opencl
```

Bitcoin Core Benchmark

```
python3 btcrecover.py --wallet ./btcrecover/test/test-wallets/bitcoincore-wallet.dat --performance --enable-gpu --global-ws 4096 --local-ws 256
```

For the sake of comparison, I have run this benchmark on the following configurations.

| GPU(s) | Blockchain.com Performance (OpenCL) (kP/s) | Bitcoin Core (JTR) (kP/s) | Lowest Price ($/h) |
|---|---|---|---|
| i7 8750H (Reference-Local CPU) | 1 | 0.07 | 
| i5 4430 (Reference-Local CPU) | 0.7 | 0.05 |
| 1660ti (Reference-Local GPU) | 10 | 6.75 |
| RX570 (Reference-Local GPU) | 2.1 | 1.29 |
| 1x 1070 | 6.5 | 3.82 | 0.09 |
| 2x 1070 | 12.5 | 6.45 | 0.296 | 
| 10x 1070 | 41 |  | |
| 1070ti | 6 | 3.2 | 0.127 |
| 10x 1080 | 46 | 13.5 | 1.64 | 
| 1080ti | 6 | 3.5 | 0.1 | 0.1 |
| 2x 1080ti | 10.1 | 6.1 | 0.3 |
| 6x 1080ti | 28 | 9.75 | 1.02 |
| 2x 2070 | 16.6 | 12 | 0.48 |
| 10x 2070 Super | 63 | 16 | 1.6 |
| 2080ti | 9.4 | 6.4 | 0.2 | 0.2 |
| 2x 2080ti | 19.5 | 10.8 | 0.4 |
| 4x 2080ti | 37 | 16 | 1 |

_It's worth looking at the price/hour for different machines based on your time preference... Often a 2x 2080 machine will cost twice as much, to rent, but only require half as much rental time... Just be aware that the JTR kernel doesn't scale as well once you get past ~2x GPUs..._

## What you will need
* Secure Shell (SSH) software client like Putty (on Windows)
* (Optional) A Secure File Transfer tools like WinSCP (on Windows) - You will need this if you use a vast.ai instance to create your extract script, or if you try to copy autosave files.
* A Credit Card (To pay for Vast.ai time)

## Vast.ai Instance Settings

**OS Image**

Select the option for a custom image and enter the following.
```
dceoy/hashcat
```

**On-start script**
```
apt update
apt install python3 python3-pip python3-dev python3-pyopencl nano mc git python3-bsddb3 -y
apt install libssl-dev build-essential automake pkg-config libtool libffi-dev libgmp-dev libyaml-cpp-dev libsecp256k1-dev -y
git clone https://github.com/3rdIteration/btcrecover.git
pip3 install -r ~/btcrecover/requirements-full.txt
update-locale LANG=C.UTF-8
echo "set -g terminal-overrides \"xterm*:kLFT5=\eOD:kRIT5=\eOC:kUP5=\eOA:kDN5=\eOB:smkx@:rmkx@\"" > ~/.tmux.conf
```

_This will download all updates, clone BTCRecover in to the home folder, install all dependancies and get the environment ready to use BTCRecover. It normally finishes running within a few minutes of the vast.ai host reaching the "Successfully Loaded" status..._

**Disk Space to Allocate**

1GB is fine unless you are trying to use an AddressDB file... (In which case you will need to allocate sufficient space for the uncompressed AddressDB file + 1GB)

## Common Issues
Requirements not correctly installed...

### Incorrect Locale
Depending on whether you connected before the onStart script had finished running you might get an error like:

    OSError: Locale is currently set to XXXXX. This library needs the locale set to UTF-8 to function properly.

If you get this error, you basically just need to type in `exit` in the command prompt. This will terminate your SSH session. Once you reconnect via Putty, the locale issue will be resolved. (If not, wait a few minutes, type `exit` and reconnect)

### Connection Refused
Double check the connection IP and port, if you still can't connect, click "destroy" and try a different host... 

### OpenCL Program Build Failed

Somewhere in your terminal output you will see:
```
`clBuildProgram failed: BUILD_PROGRAM_FAILURE - clBuildProgram failed: BUILD_PROGRAM_FAILURE - clBuildProgram failed: BUILD_PROGRAM_FAILURE

Build on <pyopencl.Device 'GeForce GTX 1070 Ti' on 'NVIDIA CUDA' at 0x2e40da0>:

===========================================================================
Build on <pyopencl.Device 'GeForce GTX 1070 Ti' on 'NVIDIA CUDA' at 0x2e40df0>:


(options: -I /usr/local/lib/python3.6/dist-packages/pyopencl/cl)
(source saved as /tmp/tmpqqq0xe7b.cl)`
```

_This is an issue on this particular vast.ai host you have rented, destroy it and try a different one..._

### No BTCRecover folder...

type
```
cat onstart.log
```
to see how the on-start script is going... It might be stuck, may have hit an error, but simply giving it some more time may help...

In this situation, you can either manually run the start commands one at a time, but if they have failed, there are probably other issues with the host... If in doubt, just destroy the server and rent a different one... 

### Anything else...
Destroy the vast.ai host you have rented and rent another one... It's possible to get two faulty servers in a row, so try a new server at least 3 times...

## Step-By Step Process
1) Create a wallet extract for your wallet. (Optionally: Start the process on your PC through to the password counting step, then copy the autosave file to the Vast.ai host)

2) Create your token file and work out what sort of CPU/GPU power you will need

3) Create an account on https://vast.ai/

4) Select a server, add the server settings above and create it

5) Connect to the server via SCP and copy required files (Possibly including autosave files)

6) Connect and check that everything works... (Running one of the benchmark commands above is a good bet)

7) Run your BTCRecover command.

8) Destroy the server once complete.

**Make sure that you allocate at least one thread per GPU...**

## Usage example (Bitcoin Core wallet) 10x GPUs spread over 5 vast.ai instances... ~1000x faster than i7 CPU...

### 1) Create wallet extract on your home PC (or another vast.ai instance)

Creating Bitcoin Core wallet extracts requires the bsddb3 module. The above startup script installs the require package automatically on each vast.ai instance you create, on Windows, you can download and install a prebuilt module by [following the instructions here.](../../Extract_Scripts.md)

Once bsddb3 is installed, you can use the command:
```
python extract-bitcoincore-mkey.py ../btcrecover/test/test-wallets/bitcoincore-wallet.dat
```

This will produce

```
Partial Bitcoin Core encrypted master key, salt, iter_count, and crc in base64:
YmM65iRhIMReOQ2qaldHbn++T1fYP3nXX5tMHbaA/lqEbLhFk6/1Y5F5x0QJAQBI/maR
```

### 2) Create your tokenlist file and work out if a server is required
**The tokenlist used in this example is tokenListTest.txt**

``` linenums="1"
{% include "./tokenListTest.txt" %}
```

We will run this command locally to work out the number of possibilities, fix any errors in or Tokenlist and see if it's worth running on a cloud system... (Though you can just do all this on a vast.ai instance if you like)

```
python btcrecover.py --data-extract-string YmM65iRhIMReOQ2qaldHbn++T1fYP3nXX5tMHbaA/lqEbLhFk6/1Y5F5x0QJAQBI/maR --tokenlist ./docs/Usage_Examples/2020-10-06_Multi-GPU_with_vastai/tokenListTest.txt
```

The tokenlist in this example is very simple, has 11 rows with one token per row. It will test every possible combination of these tokens to find the password, testing about 50 million possible passwords. (No anchors of any kind in this example) This tokenlist is deliberately structured to find the correct password right towards the end of the run...

If run on my CPU, it would take 15 hours, on a 1660ti, ~1.5 hours and 10 minutes on 10x 2080ti... (5 2x2080ti vast.ai instances)

### Steps  3-6 covered in YouTube video

### 7) Run BTCRecover command

Copy the tokenlist to the server using using WinSCP, for the sake of simplicity and easy or reproducibility, lets say it is placed in the ./docs/Usage_Examples/2020-10-06_Multi-GPU_with_vastai/ folder

Once connected to the server, change to the btcrecover folder

```
cd btcrecover
```

So the commands will be:
Server 1: 
```
python3 btcrecover.py --data-extract-string YmM65iRhIMReOQ2qaldHbn++T1fYP3nXX5tMHbaA/lqEbLhFk6/1Y5F5x0QJAQBI/maR --tokenlist ./docs/Usage_Examples/2020-10-06_Multi-GPU_with_vastai/tokenListTest.txt --dsw --no-eta --no-dupchecks --enable-gpu --global-ws 4096 --local-ws 256 --autosave autosave.file --worker 1/5
```

Server 2:
```
python3 btcrecover.py --data-extract-string YmM65iRhIMReOQ2qaldHbn++T1fYP3nXX5tMHbaA/lqEbLhFk6/1Y5F5x0QJAQBI/maR --tokenlist ./docs/Usage_Examples/2020-10-06_Multi-GPU_with_vastai/tokenListTest.txt --dsw --no-eta --no-dupchecks --enable-gpu --global-ws 4096 --local-ws 256 --autosave autosave.file --worker 2/5
```

Server 3: 
```
python3 btcrecover.py --data-extract-string YmM65iRhIMReOQ2qaldHbn++T1fYP3nXX5tMHbaA/lqEbLhFk6/1Y5F5x0QJAQBI/maR --tokenlist ./docs/Usage_Examples/2020-10-06_Multi-GPU_with_vastai/tokenListTest.txt --dsw --no-eta --no-dupchecks --enable-gpu --global-ws 4096 --local-ws 256 --autosave autosave.file --worker 3/5
```

Server 4: 
```
python3 btcrecover.py --data-extract-string YmM65iRhIMReOQ2qaldHbn++T1fYP3nXX5tMHbaA/lqEbLhFk6/1Y5F5x0QJAQBI/maR --tokenlist ./docs/Usage_Examples/2020-10-06_Multi-GPU_with_vastai/tokenListTest.txt --dsw --no-eta --no-dupchecks --enable-gpu --global-ws 4096 --local-ws 256 --autosave autosave.file --worker 4/5
```

Server 5: 
```
python3 btcrecover.py --data-extract-string YmM65iRhIMReOQ2qaldHbn++T1fYP3nXX5tMHbaA/lqEbLhFk6/1Y5F5x0QJAQBI/maR --tokenlist ./docs/Usage_Examples/2020-10-06_Multi-GPU_with_vastai/tokenListTest.txt --dsw --no-eta --no-dupchecks --enable-gpu --global-ws 4096 --local-ws 256 --autosave autosave.file --worker 5/5
```
_Same command on each server, with the exception of the worker argument_

Autosave files will also need to be copied to/from the instance via something like WinSCP, as they aren't just plan text.

### 8) Once you have your password, you can destroy all the instances. (Alternatively, you can just stop it, but just be aware that re-starting it might take some time depending on whether the instance is available)


## Usage example (Blockchain.com wallet) 2x 10 GPU Instances ~100x faster than i7 CPU

### 1) Create wallet extract on your home PC (or another vast.ai instance)

```
python extract-blockchain-main-data.py ../btcrecover/test/test-wallets/blockchain-v3.0-MAY2020-wallet.aes.json
```

This will produce

```
Blockchain first 16 encrypted bytes, iv, and iter_count in base64:
Yms6A6G5G+a+Q2Sm8GwZcojLJOJFk2tMKKhzmgjn28BZuE6IEwAA2s7F2Q==
```

### 2) Create your tokenlist file and work out if a server is required
We will run this command locally to work out the number of possibilities, fix any errors in or Tokenlist and see if it's worth running on a cloud system... (Though you can just do all this on a vast.ai instance if you like)

```
python btcrecover.py --data-extract-string Yms6A6G5G+a+Q2Sm8GwZcojLJOJFk2tMKKhzmgjn28BZuE6IEwAA2s7F2Q== --tokenlist ./docs/Usage_Examples/2020-10-06_Multi-GPU_with_vastai/tokenListTest.txt
```

The tokenlist in this example is very simple, has 11 rows with one token per row. It will test every possible combination of these tokens to find the password, testing about 50 million possible passwords. (No anchors of any kind in this example) This tokenlist is deliberately structured to find the correct password right towards the end of the run...

If run on my CPU, it would take 15 hours, on a 1660ti, ~1.5 hours and 10 minutes on 20x 1080s... (2x 10x1080 vast.ai instances)

Once you are happy with your tokenlist and BTCRecover command, you can run it on a server.

### Steps  3-6 covered in YouTube video


### 7) Run BTCRecover command

In this example, we want to use at 20 GPUs (for the sake of illustration), so need to have at least 10 threads per server (2 threads per GPU is ideal) and use the worker command to spread the load. If you want to save money and try and use "interruptable" instances, or make sure that you don't lose your progress if your run out of credit and the instance pauses you can use autosave files via the autosave parameter.

Once connected to the server, change to the btcrecover folder

```
cd btcrecover
```
We will also just copy/paste the token file using Nano on the vast.ai instance and something like notepad on our home PC. (As opposed to using WinSCP like in the previous demo)

```
nano tokenlist.txt
```

(You could also copy the tokenlist file directly using something like WinSCP)

So the commands will be:
Server 1: 
```
python3 btcrecover.py --data-extract-string Yms6A6G5G+a+Q2Sm8GwZcojLJOJFk2tMKKhzmgjn28BZuE6IEwAA2s7F2Q== --tokenlist tokenlist.txt --dsw --no-eta --no-dupchecks --enable-opencl --threads 20 --autosave autosave.file --worker 1/2
```

Server 2: 
```
python3 btcrecover.py --data-extract-string Yms6A6G5G+a+Q2Sm8GwZcojLJOJFk2tMKKhzmgjn28BZuE6IEwAA2s7F2Q== --tokenlist tokenlist.txt --dsw --no-eta --no-dupchecks --enable-opencl --threads 20 --autosave autosave.file --worker 2/2
```

_Same command on each server, with the exception of the worker argument_

Autosave files will also need to be copied to/from the instance via something like WinSCP, as they aren't just plan text.

### 8) Once you have your password, you can destroy all the instances. (Alternatively, you can just stop it, but just be aware that re-starting it might take some time depending on whether the instance is available)

