# A collection of OpenCL helper functions that are common across both btcrpass and btcrseed (to avoid duplciation)
# btcrpass.py -- btcrecover main library
# Copyright (C) 2019-2021 Stephen Rothery
#
# This file is part of btcrecover.
#
# btcrecover is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.
#
# btcrecover is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/

try:
    from lib.opencl_brute import opencl
    from lib.opencl_brute.opencl_information import opencl_information
    import pyopencl
except:
    pass

import btcrecover.btcrpass

def auto_select_opencl_platform(loaded_wallet):
    best_device_worksize = 0
    best_score_sofar = -1
    for i, platformNum in enumerate(pyopencl.get_platforms()):
        for device in platformNum.get_devices():
            cur_score = 0
            if device.type & pyopencl.device_type.ACCELERATOR: # always best
                if "oclgrind" not in device.name.lower(): # Some simulators present as an accelerator...
                    cur_score += 8
            elif device.type & pyopencl.device_type.GPU: # better than CPU
                cur_score += 4
            if "nvidia" in device.vendor.lower(): # is never an IGP: very good
                cur_score += 2
            elif "amd" in device.vendor.lower(): # sometimes an IGP: good
                cur_score += 1
            if cur_score >= best_score_sofar:  # (intel is always an IGP)
                if cur_score > best_score_sofar:
                    best_score_sofar = cur_score
                    best_device = device.name
                    best_platform = i
                    if device.max_work_group_size > best_device_worksize:
                        best_device_worksize = device.max_work_group_size

    loaded_wallet.opencl_platform = best_platform
    loaded_wallet.opencl_device_worksize = best_device_worksize
    print("OpenCL: Auto Selecting Best Platform")

def init_opencl_contexts(loaded_wallet, openclDevice = 0):
    dklen = 64
    platform = loaded_wallet.opencl_platform
    debug = 0
    write_combined_file = False

    # Create three different objects to use for the contexts, this is required for things like warpwallet, as you can't
    # have a single opencl_algo object that is re-used for multiple contexts that use a different algo.
    loaded_wallet.opencl_algo = opencl.opencl_algos(platform, debug, write_combined_file, inv_memory_density=1,
                                                    openclDevice=openclDevice)
    loaded_wallet.opencl_algo_2 = opencl.opencl_algos(platform, debug, write_combined_file, inv_memory_density=1,
                                                    openclDevice=openclDevice)
    loaded_wallet.opencl_algo_3 = opencl.opencl_algos(platform, debug, write_combined_file, inv_memory_density=1,
                                                    openclDevice=openclDevice)

    # Password recovery for blockchain.com wallet
    if type(loaded_wallet) is btcrecover.btcrpass.WalletBlockchain:
        loaded_wallet.opencl_context_pbkdf2_sha1 = loaded_wallet.opencl_algo.cl_pbkdf2_init("sha1", len(
            loaded_wallet._salt_and_iv), 32)
        return

    # Password recovery for blockchain.com wallet second password
    elif type(loaded_wallet) is btcrecover.btcrpass.WalletBlockchainSecondpass:
        loaded_wallet.opencl_context_hash_iterations_sha256 = loaded_wallet.opencl_algo.cl_hash_iterations_init(
            "sha256")
        return

    # Password recovery for dogechain.info wallet
    elif type(loaded_wallet) is btcrecover.btcrpass.WalletDogechain:
        loaded_wallet.opencl_context_pbkdf2_sha256 = loaded_wallet.opencl_algo.cl_pbkdf2_init("sha256", len(
            loaded_wallet.salt), 32)
        return

    # Password recovery for Yoroi Cardano wallet
    elif type(loaded_wallet) is btcrecover.btcrpass.WalletYoroi:
        loaded_wallet.opencl_context_pbkdf2_sha512 = loaded_wallet.opencl_algo.cl_pbkdf2_init("sha512", 32, 32)
        return

    # Password recovery for Bitcoin core wallet (or clones)
    elif type(loaded_wallet) is btcrecover.btcrpass.WalletBitcoinCore:
        loaded_wallet.opencl_context_hash_iterations_sha512 = loaded_wallet.opencl_algo.cl_hash_iterations_init(
            "sha512")
        return

    # Password recovery for BIP38 wallet, load sCrypt context with a custom kernel
    elif type(loaded_wallet) is btcrecover.btcrpass.WalletBIP38:
        loaded_wallet.opencl_context_scrypt = loaded_wallet.opencl_algo.cl_scrypt_init(14, "sCrypt_Bip38fork.cl")
        return

    # Password recovery for Electrum28 Wallet files
    elif type(loaded_wallet) is btcrecover.btcrpass.WalletElectrum28:
        loaded_wallet.opencl_context_pbkdf2_sha512 = \
            loaded_wallet.opencl_algo.cl_pbkdf2_init("sha512",
                                                              len(b""),
                                                              dklen)
        return

    # Password recovery for BIP39 Passphrase or Electrum "Extra Words"
    elif type(loaded_wallet) is btcrecover.btcrpass.WalletBIP39:
        loaded_wallet.opencl_context_pbkdf2_sha512 = \
            loaded_wallet.opencl_algo.cl_pbkdf2_saltlist_init("sha512",
                                                              len(loaded_wallet._mnemonic.encode()),
                                                              dklen)
        return

    # Password recovery for brainwallets
    elif type(loaded_wallet) is btcrecover.btcrpass.WalletBrainwallet:
        loaded_wallet.opencl_context_sha256 = loaded_wallet.opencl_algo.cl_sha256_init()
        if loaded_wallet.isWarpwallet:
            #loaded_wallet.opencl_context_scrypt = loaded_wallet.opencl_algo_2.cl_scrypt_init(18, "sCrypt_Bip38forkN18.cl")
            loaded_wallet.opencl_context_pbkdf2_sha256 = \
                loaded_wallet.opencl_algo_3.cl_pbkdf2_init(rtype="sha256",
                                                         saltlen=len(loaded_wallet.salt) + 1,
                                                         dklen=32)
        return

    # Password recovery for Metamask wallets
    elif type(loaded_wallet) is btcrecover.btcrpass.WalletMetamask:
        if not loaded_wallet._mobileWallet:
            loaded_wallet.opencl_context_pbkdf2_sha256 = loaded_wallet.opencl_algo.cl_pbkdf2_saltlist_init("sha256", len(b""), 32)
        else:
            loaded_wallet.opencl_context_pbkdf2_sha512 = loaded_wallet.opencl_algo.cl_pbkdf2_saltlist_init("sha512", len(b""), 32)
        return

    # Seed Recovery for Cardano Wallets
    elif type(loaded_wallet) is btcrecover.btcrseed.WalletCardano:
        loaded_wallet.opencl_context_pbkdf2_sha512_saltlist = loaded_wallet.opencl_algo.cl_pbkdf2_saltlist_init("sha512", 64, dklen=96)
        loaded_wallet.opencl_context_pbkdf2_sha512 = []
        for salt in loaded_wallet._derivation_salts:
            loaded_wallet.opencl_context_pbkdf2_sha512.append(loaded_wallet.opencl_algo.cl_pbkdf2_init("sha512",
                                                                                                       len(
                                                                                                           b"mnemonic" + salt),
                                                                                                       dklen))
        return

    # Passphrase Recovery for Cardano Wallets
    elif type(loaded_wallet) is btcrecover.btcrpass.WalletCardano:
        loaded_wallet.opencl_context_pbkdf2_sha512_saltlist = loaded_wallet.opencl_algo.cl_pbkdf2_saltlist_init("sha512", len(loaded_wallet._mnemonic.encode()), dklen=64)
        loaded_wallet.opencl_context_pbkdf2_sha512 = loaded_wallet.opencl_algo.cl_pbkdf2_init("sha512", 33, dklen=96)
        return

    else: # Must a btcrseed.WalletBIP39 (Seed recovery for BIP39 or Electrum)
        loaded_wallet.opencl_context_pbkdf2_sha512 = []
        for salt in loaded_wallet._derivation_salts:
            loaded_wallet.opencl_context_pbkdf2_sha512.append(loaded_wallet.opencl_algo.cl_pbkdf2_init("sha512",
                                                                                              len(b"mnemonic"+salt), dklen))
        return