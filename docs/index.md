# BTCRecover
[![Last Push - All Tests (Base Modules)](https://github.com/3rdIteration/btcrecover/workflows/Last%20Push%20-%20All%20Tests%20(Base%20Modules)/badge.svg)](https://github.com/3rdIteration/btcrecover/actions?query=workflow%3A%22Last+Push+-+All+Tests+%28Base+Modules%29%22) [![Weekly - All Tests (Base Modules)](https://github.com/3rdIteration/btcrecover/workflows/Weekly%20-%20All%20Tests%20(Base%20Modules)/badge.svg)](https://github.com/3rdIteration/btcrecover/actions?query=workflow%3A%22Weekly+-+All+Tests+%28Base+Modules%29%22) [![Weekly Run All Tests (Base Modules)](https://github.com/3rdIteration/btcrecover/workflows/Weekly%20-%20All%20Tests%20(+Optional%20Modules)//badge.svg)](https://github.com/3rdIteration/btcrecover/actions?query=workflow%3A%22Weekly+-+All+Tests+%28%2BOptional+Modules%29%22) [![Documentation Status](https://readthedocs.org/projects/btcrecover/badge/?version=latest)](https://btcrecover.readthedocs.io/en/latest/?badge=latest) ![license](https://img.shields.io/badge/license-GPLv2-blue.svg) 

*BTCRecover* is an open source wallet password and seed recovery tool.

For seed based recovery, this is primarily useful in situations where you have lost/forgotten parts of your mnemonic, or have made an error transcribing it. (So you are either seeing an empty wallet or gettign an error that your seed is invalid)

For wallet password or passphrase recovery, it is primarily useful if you have a reasonable idea about what your password might be.

## Getting Started
Your best bet is to follow the [Installing BTCRecover guide](INSTALL.md), then read the "Quick Start" for the recovery type you want. [(Or look at some usage examples)](UsageExamples.md)

## Getting Support

If you need help, [your best bet is to look at my BTCRecover playlist on YouTube](https://www.youtube.com/playlist?list=PL7rfJxwogDzmd1IanPrmlTg3ewAIq-BZJ) and ask a question in the comments section for any of video closest to your situation.

If you have found a bug, please open an issue on Github here: [https://github.com/3rdIteration/btcrecover/issues](https://github.com/3rdIteration/btcrecover/issues)

## Features ##
* Seed/Passphrase Recovery when for: (Recovery without a known address requires an [Address Database](Creating_and_Using_AddressDB.md))
    * Avalanche
    * Bitcoin
    * Bitcoin Cash
    * Cardano (Shelley Era Addresses)
    * Cosmos (Atom) Any many other Cosmos Chains (Nym, GravityBridge, etc)
    * Dash
    * DigiByte
    * Dogecoin
    * Ethereum
    * Groestlcoin
    * Helium
    * Litecoin
    * Monacoin
    * Polkadot (sr25519, like those produced by polkadot.js)
    * Ripple
    * Secret Network
    * Solana
    * Stacks
    * Stellar
    * Tezos
    * Tron
    * Vertcoin
    * Zilliqa
    * And many other 'Bitcoin Like' cryptos
 * SLIP39 Passphrase Recovery for most coins supported by the Trezor T
    * Bitcoin
    * Bitcoin Cash
    * Dash
    * Digibyte
    * Dogecoin
    * Ethereum
    * Litecoin
    * Ripple
    * Vertcoin
 * [Descrambling 12 word seeds](BIP39_descrambling_seedlists.md) (Using Tokenlist feature for BIP39 seeds via seedrecover.py)
 * Wallet File password recovery for a range of wallets

* Seed Phrase (Mnemonic) Recovery for the following wallets
     * [Electrum](https://electrum.org/) (1.x, 2.x, 3.x and 4.x) (For Legacy and Segwit Wallets. Set --bip32-path "m/0'/0" for a Segwit wallet, leave bip32-path blank for Legacy... No support for 2fa wallets...)
     * [Electron-Cash](https://www.electroncash.org/) (2.x, 3.x and 4.x)
     * BIP-32/39 compliant wallets ([bitcoinj](https://bitcoinj.github.io/)), including:
         * [MultiBit HD](https://multibit.org/)
         * [Bitcoin Wallet for Android/BlackBerry](https://play.google.com/store/apps/details?id=de.schildbach.wallet) (with seeds previously extracted by [decrypt\_bitcoinj\_seeds](https://github.com/gurnec/decrypt_bitcoinj_seed))
         * [Hive for Android](https://play.google.com/store/apps/details?id=com.hivewallet.hive.cordova), [for iOS](https://github.com/hivewallet/hive-ios), and [Hive Web](https://hivewallet.com/)
         * [Breadwallet](https://brd.com/)
     * BIP-32/39/44 Bitcoin & Ethereum compliant wallets, including:
         * [Mycelium for Android](https://wallet.mycelium.com/)
         * [TREZOR](https://www.bitcointrezor.com/)
         * [Ledger](https://www.ledgerwallet.com/)
         * [Keepkey](https://shapeshift.io/keepkey/)
         * [Blockstream Jade](https://blockstream.com/jade/)
         * [Jaxx](https://jaxx.io/)
         * [Coinomi](https://www.coinomi.com/)
         * [Exodus](https://www.exodus.io/)
         * [MyEtherWallet](https://www.myetherwallet.com/)
         * [Bither](https://bither.net/)
         * [Blockchain.com](https://blockchain.com/wallet)
         * [Trust Wallet](https://trustwallet.com/)
         * [Encrypted (BIP-38) Paper Wallet Support (Eg: From Bitaddress.org)](https://bitaddress.org) Also works with altcoin forks like liteaddress.org, paper.dash.org, etc...
         * Brainwallets
            * Sha256(Passphrase) brainwallets (eg: Bitaddress.org, liteaddress.org, paper.dash.org)
            * sCrypt Secured Brainwallets (Eg: Warpwallet, Memwallet)
     * Ethereum Validator BIP39 Seed Recovery
 * Bitcoin wallet password recovery support for:
     * [Bitcoin Core](https://bitcoincore.org/)
     * [MultiBit HD](https://multibit.org/) and [MultiBit Classic](https://multibit.org/help/v0.5/help_contents.html)
     * [Electrum](https://electrum.org/) (1.x, 2.x, 3.x and 4.x) (For Legacy and Segwit Wallets. Set --bip32-path "m/0'/0" for a Segwit wallet, leave bip32-path blank for Legacy... No support for 2fa wallets...)
     * Most wallets based on [bitcoinj](https://bitcoinj.github.io/), including [Hive for OS X](https://github.com/hivewallet/hive-mac/wiki/FAQ)
     * BIP-39 passphrases (Also supports all cryptos supported for seed recovery, as well as recovering "Extra Words" for Electrum seeds)
     * [mSIGNA (CoinVault)](https://ciphrex.com/products/)
     * [Blockchain.com](https://blockchain.com/wallet)
     * [block.io](https://block.io/) (Recovery of wallet "Secret PIN")
     * [pywallet --dumpwallet](https://github.com/jackjack-jj/pywallet) of Bitcoin Unlimited/Classic/XT/Core wallets
     * [Bitcoin Wallet for Android/BlackBerry](https://play.google.com/store/apps/details?id=de.schildbach.wallet) spending PINs and encrypted backups
     * [KnC Wallet for Android](https://github.com/kncgroup/bitcoin-wallet) encrypted backups
     * [Bither](https://bither.net/)
 * Altcoin password recovery support for most wallets derived from one of those above, including:
     * [Coinomi](https://www.coinomi.com/en/) (Only supports password protected wallets)
     * [imToken](https://token.im/)
     * [Metamask](https://metamask.io/) (And Metamask clones like Binance Chain Wallet, Ronin Wallet, etc.)
     * [Litecoin Core](https://litecoin.org/)
     * [Electrum-LTC](https://electrum-ltc.org/) (For Legacy and Segwit Wallets. Set --bip32-path "m/0'/0" for a Segwit wallet, leave bip32-path blank for Legacy... No support for 2fa wallets...)
     * [Electron-Cash](https://www.electroncash.org/) (2.x, 3.x and 4.x)
     * [Litecoin Wallet for Android](https://litecoin.org/) encrypted backups
     * [Dogecoin Core](http://dogecoin.com/)
     * [MultiDoge](http://multidoge.org/)
     * [Dogechain.info](https://dogechain.info/)     
     * [Dogecoin Wallet for Android](http://dogecoin.com/) encrypted backups
     * [Yoroi Wallet for Cardano](https://yoroi-wallet.com/#/) Master_Passwords extracted from the wallet data (In browser or on rooted/jailbroken phones)
     * [Damaged Raw Eth Private Keys]() Individual Private keys that are missing characters.
     * [Ethereum UTC Keystore Files](https://myetherwallet.com) Ethereum Keystore files, typically used by wallets like MyEtherWallet, MyCrypto, etc. (Also often used by Eth clones like Theta, etc)
 * [Free and Open Source](http://en.wikipedia.org/wiki/Free_and_open-source_software) - anyone can download, inspect, use, and redistribute this software
 * Supported on Windows, Linux, and OS X
 * Support for Unicode passwords and seeds
 * Multithreaded searches, with user-selectable thread count
 * Ability to spread search workload over multiple devices
 * [GPU acceleration](GPU_Acceleration.md) for Bitcoin Core Passwords, Blockchain.com (Main and Second Password), Electrum Passwords + BIP39 and Electrum Seeds
 * Wildcard expansion for passwords
 * Typo simulation for passwords and seeds
 * Progress bar and ETA display (at the command line)
 * Optional autosave - interrupt and continue password recoveries without losing progress
 * Automated seed recovery with a simple graphical user interface
 * Ability to search multiple derivation paths simultaneously for a given seed via --pathlist command (example pathlist files in the )
 * “Offline” mode for nearly all supported wallets - use one of the [extract scripts (click for more information)](Extract_Scripts.md) to extract just enough information to attempt password recovery, without giving *btcrecover* or whoever runs it access to *any* of the addresses or private keys in your Bitcoin wallet.

If you want the tool to support a crypto/wallet that isn't listed above, please test that it works and submit a PR which includes a unit test for that coin and also any required code to accept the address format.

**_If you are trying to do a recovery for a coin/wallet that isn't listed above, feel free to contact me as it may be possible for you to sponsor the addition of that crypto as part of an assisted recovery fee._**