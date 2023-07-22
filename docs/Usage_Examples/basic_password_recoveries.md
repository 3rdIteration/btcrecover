# Basic Password/Passphrase Recoveries

None of these examples are concerned with arguments that you would use for different types of typos, tokenlists, etc.

The idea is that, if you are running this tool on Windows, you can directly copy/paste any of these examples. (They all use the same seeds and addresses that are in the automatic tests)

They will all find a result almost straight away.

**Basic Passwordlist used in basic examples below**
``` linenums="1"
{% include "common_passwordlist.txt" %}
```

## BIP38 Encrypted Paper Wallet Recovery.
**Notes**
BIP38 wallets are encrypted via sCrypt, so will be very slow to brute-force. GPU acceleration for these wallets is available, but doesn't offer much of a performance boost unless you have multiple GPUs or a particularly powerful GPU relative to your CPU... (Or some kind of dedicated OpenCL accelerator)

**Supported wallets**

* [bitaddress.org](https://www.bitaddress.org/)
* [liteaddress.org](https://liteaddress.org/)
* [paper.dash.org](https://paper.dash.org/)

And just about any other BIP38 encrypted private keys.

**Commands**

For Bitcoin (No coin needs to be specified, Bitcoin is checked by default)
```
python btcrecover.py --bip38-enc-privkey 6PnM7h9sBC9EMZxLVsKzpafvBN8zjKp8MZj6h9mfvYEQRMkKBTPTyWZHHx --passwordlist ./docs/Usage_Examples/common_passwordlist.txt
```
<br>
For Litecoin
```
python btcrecover.py --bip38-enc-privkey 6PfVHSTbgRNDaSwddBNgx2vMhMuNdiwRWjFgMGcJPb6J2pCG32SuL3vo6q --bip38-currency litecoin --passwordlist ./docs/Usage_Examples/common_passwordlist.txt
```
<br>
For Dash
```
python btcrecover.py --bip38-enc-privkey 6PnZC9Snn1DHyvfEq9UKUmZwonqpfaWav6vRiSVNXXLUEDAuikZTxBUTEA --bip38-currency dash --passwordlist ./docs/Usage_Examples/common_passwordlist.txt
```
<br>

## BIP39 Passphrase Protected Wallets & Electrum "Extra Words"
**Notes**
The language used to refer to a BIP39 passpharse can vary betwen vendors. Sometimes it is talked about as a "25th word", other times a "plausible deniability passphrase" or sometimes just as "passphrase". Just note that this is different from your wallet password or PIN.

The most common symptom of you having an error in your BIP39 passphrase is that your seed+passhrase will produce a set of completely empty accounts, with no balance or transaction history. (Every BIP39 passphrase is valid, so you will not get any kind of error message)

While BIP39 seed recovery can benefit from GPU acceleration, this is currently not the case for recovering a BIP39 passphrase.

All of the example commands below have the address generation limit set to 10, so the address they are searching for needs to be within the first 10 addresses in the wallet.

**Supported wallets**

* Most hardware wallets that support BIP39/44
    * Trezor (One and T)
    * Ledger Nano (S and X)
    * Keepkey
    * Coldcard
    * Bitbox02
    * Cobo Vault Pro
* Most Software Wallets that support BIP39/44
    * Wasabi Wallet (Wasabi refers to this as your wallet password)
    * Samourai Wallet
    * Coinomi
    * Mycelium
    * Zillet (Referrs to BIP39 passphrase as a "password based" wallet type)
    * Electrum
    * Exodus

**Commands**

### Basic Bitcoin Command

No need to specify `--wallet-type` This will support all Bitcoin address types (Legacy, Segwit or Native Segwit) without the need to add any additional parameters.
```
python btcrecover.py --bip39 --addrs 1AmugMgC6pBbJGYuYmuRrEpQVB9BBMvCCn --addr-limit 10 --passwordlist ./docs/Usage_Examples/common_passwordlist.txt --mnemonic "certain come keen collect slab gauge photo inside mechanic deny leader drop"
```
<br>

### Basic Bitcoin Electrum Wallet Command. 

These aren't BIP39, so need to use `--wallet-type electrum2` This will support both Legacy and Segwit Electrum wallets without any additional parameters. (It will also work with most Electrum Altcoin clones)
```
python btcrecover.py --wallet-type electrum2 --addrs bc1q6n3u9aar3vgydfr6q23fzcfadh4zlp2ns2ljp6 --addr-limit 10 --passwordlist ./docs/Usage_Examples/common_passwordlist.txt --mnemonic "quote voice evidence aspect warfare hire system black rate wing ask rug"
```
<br>

### Basic Ethereum Command

Need to specify the `--wallet-type` (But can leave off the `--bip39` argument, as it is implied)
```
python btcrecover.py --wallet-type ethereum --addrs 0x4daE22510CE2fE1BC81B97b31350Faf07c0A80D2 --addr-limit 10 --passwordlist ./docs/Usage_Examples/common_passwordlist.txt --mnemonic "cable top mango offer mule air lounge refuse stove text cattle opera"
```

<br>

### Ethereum Validator passphrase recovery. 

Just like with seed recovery, this works basically the same as a standard BIP39 passphrase and uses the validator pubkey (Aka Signing Key) as the address

```
python btcrecover.py --mnemonic "spatial evolve range inform burst screen session kind clap goat force sort" --addrs b08ef0d03052945b6c4207e9b64a41e7773bd7b635e5140e8d38c290b11959bbcbe218850c5a478394654d094094d175 --wallet-type ethereumvalidator --addr-limit 1 --tokenlist ./btcrecover/test/test-listfiles/tokenListTe
st.txt
```

<br>

### Basic Zilliqa Command

Need to specifcy the `--wallet-type` (But can leave off the `--bip39` argument, as it is implied)This will support all address types (Base16 and Bech32) without the need to add any additional parameters.

Note: Zilliqa seed recovery can't be used as the basis for recovering a Ledger Nano seed/passphrase at this time.

```
python btcrecover.py --wallet-type zilliqa --addrs zil1dcsu2uz0yczmunyk90e8g9sr5400c892yeh8fp --addr-limit 10 --passwordlist ./docs/Usage_Examples/common_passwordlist.txt --mnemonic "cable top mango offer mule air lounge refuse stove text cattle opera"
```
<br>

### Basic Bitcoin Cash Command

Need to specifcy the `--wallet-type` (But can leave off the `--bip39` argument, as it is implied) This will accept either Cashaddres or Legacy style addresses... This will also work for BCH forks like BSV...
```
python btcrecover.py --wallet-type bch --addrs bitcoincash:qqv8669jcauslc88ty5v0p7xj6p6gpmlgv04ejjq97 --addr-limit 10 --passwordlist ./docs/Usage_Examples/common_passwordlist.txt --mnemonic "cable top mango offer mule air lounge refuse stove text cattle opera"
```
<br>

### Basic Cardano

Need to specifcy the `--wallet-type` (But can leave off the `--bip39` argument, as it is implied) For Cardano recovers, [see the notes here as well.](bip39-accounts-and-altcoins.md) This will accept either base or stake addresses... (Byron-Era addresses are not supported))

```
python btcrecover.py --wallet-type cardano --addrs addr1q90kk6lsmk3fdy54mqfr50hy025ymnmn5hhj8ztthcv3qlzh5aynphrad3d26hzxg7xzzf8hnmdpxwtwums4nmryj3jqk8kvak --passwordlist ./docs/Usage_Examples/common_passwordlist.txt --mnemonic "ocean hidden kidney famous rich season gloom husband spring convince attitude boy"
```
<br>

### Basic Dash Command

Need to specifcy the `--wallet-type` (But can leave off the `--bip39` argument, as it is implied) 
```
python btcrecover.py --wallet-type dash --addrs XuTTeMZjUJuZGotrtTPRCmHCaxnX44a2aP --addr-limit 10 --passwordlist ./docs/Usage_Examples/common_passwordlist.txt --mnemonic "cable top mango offer mule air lounge refuse stove text cattle opera"
```
<br>

### Basic Dogecoin Command

Need to specifcy the `--wallet-type` (But can leave off the `--bip39` argument, as it is implied) 
```
python btcrecover.py --wallet-type dogecoin --addrs DSTy3eptg18QWm6pCJGG4BvodSkj3KWvHx --addr-limit 10 --passwordlist ./docs/Usage_Examples/common_passwordlist.txt --mnemonic "cable top mango offer mule air lounge refuse stove text cattle opera"
```
<br>

### Basic Vertcoin Command

Need to specifcy the `--wallet-type` (But can leave off the `--bip39` argument, as it is implied) This will support all address types (Legacy, Segwit or Native Segwit) without the need to add any additional parameters.
```
python btcrecover.py --wallet-type vertcoin --addrs Vwodj33bXcT7K1uWbTqtk9UKymYSMeaXc3 --addr-limit 10 --passwordlist ./docs/Usage_Examples/common_passwordlist.txt --mnemonic "cable top mango offer mule air lounge refuse stove text cattle opera"
```
<br>

### Basic Litecoin Command

Need to specifcy the `--wallet-type` (But can leave off the `--bip39` argument, as it is implied) This will support all address types (Legacy, Segwit or Native Segwit) without the need to add any additional parameters.
```
python btcrecover.py --wallet-type litecoin --addrs LdxLVMdt49CXcrnQRVJFRs8Yftu9dE8xxP --addr-limit 10 --passwordlist ./docs/Usage_Examples/common_passwordlist.txt --mnemonic "cable top mango offer mule air lounge refuse stove text cattle opera"
```
<br>

### Basic Monacoin Command

Need to specifcy the `--wallet-type` (But can leave off the `--bip39` argument, as it is implied) This will support all address types (Legacy, Segwit or Native Segwit) without the need to add any additional parameters.
```
python btcrecover.py --wallet-type monacoin --addrs MHLW7WdRKE1XBkLFS6oaTJE1nPCkD6acUd --addr-limit 10 --passwordlist ./docs/Usage_Examples/common_passwordlist.txt --mnemonic "cable top mango offer mule air lounge refuse stove text cattle opera"
```
<br>

### Basic DigiByte Command

Need to specifcy the `--wallet-type` (But can leave off the `--bip39` argument, as it is implied) This will support all address types (Legacy, Segwit or Native Segwit) without the need to add any additional parameters.
```
python btcrecover.py --wallet-type digibyte --addrs DNGbPa9QMbLgeVspu9jb6EEnXjJASMvA5r --addr-limit 10 --passwordlist ./docs/Usage_Examples/common_passwordlist.txt --mnemonic "cable top mango offer mule air lounge refuse stove text cattle opera"
```
<br>

### Basic GroestleCoin Command

Need to specifcy the `--wallet-type` (But can leave off the `--bip39` argument, as it is implied) This will support all address types (Legacy, Segwit or Native Segwit) without the need to add any additional parameters.

Note: This needs the groestlecoin_hash module to be installed...
```
python btcrecover.py --wallet-type groestlecoin --addrs FWzSMhK2TkotZodkApNxi4c6tvLUo7MBWk --addr-limit 10 --passwordlist ./docs/Usage_Examples/common_passwordlist.txt --mnemonic "cable top mango offer mule air lounge refuse stove text cattle opera"
```
<br>

### Basic Ripple Command

Need to specifcy the `--wallet-type` (But can leave off the `--bip39` argument, as it is implied) 
```
python btcrecover.py --wallet-type ripple --addrs rwv2s1wPjaCxmEFRm4j724yQ5Lh161mzwK --addr-limit 10 --passwordlist ./docs/Usage_Examples/common_passwordlist.txt --mnemonic "cable top mango offer mule air lounge refuse stove text cattle opera"
```
<br>

### Basic Tron Command

Need to specifcy the `--wallet-type` (But can leave off the `--bip39` argument, as it is implied) 
```
python btcrecover.py --wallet-type tron --addrs TGvJrj5D8qdzhcppg9RoLdfbEjDYCne8xc --addr-limit 10 --passwordlist ./docs/Usage_Examples/common_passwordlist.txt --mnemonic "have hint welcome skate cinnamon rabbit cable payment gift uncover column duck scissors wedding decorate under marine hurry scrub rapid change roast print arch" 
```
<br>

### Basic Polkadot(Substrate) Command

Need to specifcy the `--wallet-type` (But can leave off the `--bip39` argument, as it is implied) 

This command will search for the correct "secret derivation path"
```
python btcrecover.py --wallet-type polkadotsubstrate --addrs 12uMBgecqfkHTYZE4GFRx847CwR7sfs2bTdPbPLpzeMDGFwC --passwordlist ./docs/Usage_Examples/common_passwordlist.txt --mnemonic "toilet assume drama keen dust warrior stick quote palace imitate music disease" --substrate-path "//hard/soft"
```
<br>

### Basic Stacks Command

Need to specifcy the `--wallet-type` (But can leave off the `--bip39` argument, as it is implied) This example also has the address generation limit set to 10, so will check the first 10 "accounts" for a given seed+passphrase.
```
python btcrecover.py --wallet-type stacks --addrs SP2KJB4F9C91R3N5XSNQE0Z3G34DNJWQYTP3PBJTH --passwordlist ./docs/Usage_Examples/common_passwordlist.txt --mnemonic "ocean hidden kidney famous rich season gloom husband spring convince attitude boy" --addr-limit 10
```
<br>

## Brainwallets
**Notes**
Brainwallets are a very old (**and very unsafe**) type of wallet. Given this, most of them still produce addresses based on "uncompressed"

**Supported wallets**

* Sha256(Passphrase) Wallets
    * [bitaddress.org](https://www.bitaddress.org/)
    * [segwitaddress.org](https://segwitaddress.org/)
    * [liteaddress.org](https://liteaddress.org/)
    * [paper.dash.org](https://paper.dash.org/)
* Warpwallet Wallets
    * [WarpWallet](https://keybase.io/warp/)
    * [Memwallet](https://dvdbng.github.io/memwallet/)
    * [Mindwallet](https://patcito.github.io/mindwallet/)
  
### Sha256(Passphrase) Wallets
**Commands**

Basic Bitcoin Command (Will check both compressed and uncompressed address types, even though in this example this is a compressed address)
```
python btcrecover.py --brainwallet --addrs 1BBRWFHjFhEQc1iS6WTQCtPu2GtZvrRcwy --passwordlist ./docs/Usage_Examples/common_passwordlist.txt
```
<br>

Bitcoin Wallet, but set to only check uncompressed addresses. (Only use this for VERY old wallets that you are sure aren't a compressed address, though also consider that uncompressed is the default... Only gives a small speed boost)

```
python btcrecover.py --brainwallet --addrs 1MHoPPuGJyunUB5LZQF5dXTrLboEdxTmUm --skip-compressed --passwordlist ./docs/Usage_Examples/common_passwordlist.txt
```
<br>

P2SH Bitcoin Wallet (Like the kind you would get of something like segwitaddress.org, as of 2021, these are all compressed type addresses, so can skip checking uncomrpessed ones...)
```
python btcrecover.py --brainwallet --addrs 3C4dEdngg4wnmwDYSwiDLCweYawMGg8dVN --skip-uncompressed --passwordlist ./docs/Usage_Examples/common_passwordlist.txt
```
<br>

Bech32 Bitcoin Wallet. (From segwitaddress.org)
```
python btcrecover.py --brainwallet --addrs bc1qth4w90jmh0a6ug6pwsuyuk045fmtwzreg03gvj --skip-uncompressed --passwordlist ./docs/Usage_Examples/common_passwordlist.txt
```
<br>

Litecoin Wallet (From liteaddress.org - These are all uncompressed with no option to use compressed) No extra arguments are needed for these types of wallets.
```
python btcrecover.py --brainwallet --addrs LfWkecD6Pe9qiymVjYENuYXcYpAWjU3mXw --skip-compressed --passwordlist ./docs/Usage_Examples/common_passwordlist.txt
```
<br>

Dash Wallet (From paper.dash.org) - No compression parameters specificed, so it will just check both
```
python btcrecover.py --brainwallet --addrs XvyeDeZAGh8Nd7fvRHZJV49eAwNvfCubvB --passwordlist ./docs/Usage_Examples/common_passwordlist.txt
```
<br>


Dash Wallet (From paper.dash.org - Or if you know you used a compressed one... (Though Uncompressed is the default)
```
python btcrecover.py --brainwallet --addrs XksGLVwdDQSzkxK1xPmd4R5grcUFyB3ouY --skip-uncompressed --passwordlist ./docs/Usage_Examples/common_passwordlist.txt
```
<br>

### Warpwallets
Note: At this time, only Bitcoin and Litecoin are supported... (Eth could be easily added)

**Commands**

Basic Bitcoin Wallet with "btcr-test-password" as the salt. (Warpwallet suggested using your email address) These wallets are all "uncompressed" type, but the performance gain for this is so small compared to how long the sCrypt operation takes, it isn't worth not checking both types...
```
python btcrecover.py --warpwallet --warpwallet-salt btcr-test-password --addrs 1FThrDFjhSf8s1Aw2ed5U2sTrMz7HicZun --passwordlist ./docs/Usage_Examples/common_passwordlist.txt
```
<br>
Basic Litecoin Wallet with "btcr-test-password" as the salt. (Like what memwallet or mindwallet produces, so you need to add the --crypto argment and specify litecoin) These wallets are all "uncompressed" type, but the performance gain for this is so small compared to how long the sCrypt operation takes, it isn't worth not checking both types...

```
python btcrecover.py --warpwallet --warpwallet-salt btcr-test-password --crypto litecoin --addrs LeBzGzZFxRUzzRAtm8EB2Dw74jRfQqUZeq --passwordlist ./docs/Usage_Examples/common_passwordlist.txt
```

## Block.io Wallets
You would first download the wallet file using the instructions in the extract scripts section of the documentation.

You would then do a basic recovery with a command like the one below. (This command uses a sample wallet file bunlded with BTCRecover)
```
python btcrecover.py --wallet ./btcrecover/test/test-wallets/block.io.request.json --passwordlist ./docs/Usage_Examples/common_passwordlist.txt
```

## Dogechain.info Wallets
You would first download the wallet file using the instructions in the extract scripts section of the documentation. You can also use an extract script to securely run dogechain.info wallets on rented hardware. [See here for more info about Extract Scripts...](Extract_Scripts.md#usage-for-dogechaininfo)

You would then do a basic recovery with a command like the one below. (This command uses a sample wallet file bunlded with BTCRecover)

```
python btcrecover.py --wallet ./btcrecover/test/test-wallets/dogechain.wallet.aes.json --passwordlist ./docs/Usage_Examples/common_passwordlist.txt
```

## Ethereum Keystores
Do a basic recovery with a command like the one below. (This command uses a sample wallet file bunlded with BTCRecover)

```
python btcrecover.py --wallet ./btcrecover/test/test-wallets/utc-keystore-v3-scrypt-myetherwallet.json --passwordlist ./docs/Usage_Examples/common_passwordlist.txt
```

## imToken Wallet Keystores
Do a basic recovery with a command like the one below. (This command uses a sample wallet file bunlded with BTCRecover)

```
python btcrecover.py --wallet ./btcrecover/test/test-wallets/imtoken-identity.json --passwordlist ./docs/Usage_Examples/common_passwordlist.txt
```

## SLIP39 Passphrases
This uses much of the same syntax as recovering BIP39 passphrases. BTCRecover currently supports most of the coins that are supported by the Trezor T.

The main difference is that instead of entering a single mnemonic, you can either enter the SLIP39 shares via the command line as below, or you will be promtpted for them. You need to have a quorum of SLIP39 shares to be able to do a passphrase recovery...

Basic Bitcoin Command, so no need to specify `--wallet-type` This will support all Bitcoin address types (Legacy, Segwit or Native Segwit) without the need to add any additional parameters.
```
python btcrecover.py --slip39 --addrs bc1q76szkxz4cta5p5s66muskvads0nhwe5m5w07pq --addr-limit 10 --passwordlist ./docs/Usage_Examples/common_passwordlist.txt --slip39-shares "hearing echo academic acid deny bracelet playoff exact fancy various evidence standard adjust muscle parcel sled crucial amazing mansion losing" "hearing echo academic agency deliver join grant laden index depart deadline starting duration loud crystal bulge gasoline injury tofu together"
```
<br>

Basic Ethereum Command, so need to specifcy the `--wallet-type` (But can leave off the `--bip39` argument, as it is implied)
```
python btcrecover.py --slip39 --wallet-type ethereum --addrs 0x0Ef61684B1E671dcBee4D51646cA6247487Ef91a --addr-limit 10 --passwordlist ./docs/Usage_Examples/common_passwordlist.txt --slip39-shares "hearing echo academic acid deny bracelet playoff exact fancy various evidence standard adjust muscle parcel sled crucial amazing mansion losing" "hearing echo academic agency deliver join grant laden index depart deadline starting duration loud crystal bulge gasoline injury tofu together"
```
<br>

## Raw Private Keys##
BTCRecover an also be used to recover from situations where you have a damaged private key. 

This is handled in a similar way to a password recovery, so your private key guesses go in a tokenlist, using the %h wildcard to substitute hexidecimal characters or %b to substitute base58 characters. You can use either a tokenlist or a passwordlist, depending on your situation, as well as the standard typos. If you are using a tokenlist, you will just need to ensure that the private keys being produced match the length and characters required for a private key... 

If you know the address that the private key corresponds to, you can supply that, alternatively you can use an AddressDB. 

### Raw Eth Private Keys ###
You will also notice that the leading "0x" needs to be removed from the private key.

**Example tokenlist**
``` linenums="1"
{% include "eth_privkey_tokenlist.txt" %}
```

The tokenlist above is an example is a standard Eth private key (with the leading 0x removed) where there are three damanged parts. One single character (%h), one two-character (%2h) and one three-character (%3h) It will take about 20 mintes to run...

```
python btcrecover.py --rawprivatekey --addrs 0xB9644424F9E639D1D0F27C4897e696CC324948BB --wallet-type ethereum --tokenlist ./docs/Usage_Examples/eth_privkey_tokenlist.txt
```

## Raw Bitcoin Private Keys ##
Bitcoin private keys are supported in both Compressed and Uncompressed formats in Base58 and also as raw Hexidecimal keys.

If you are using a tokenlist (as in the examples below) with multiple private keys, one per line, you will also want to specify the "--max-tokens 1" argument.

**Example tokenlist**
``` linenums="1"
{% include "eth_privkey_tokenlist.txt" %}
```

The command below will attempt a recovery for an old-style, uncompressed private key with one missing character, using a tokenlist containing three possible private keys.

```
python btcrecover.py --rawprivatekey --addrs 1EDrqbJMVwjQ2K5avN3627NcAXyWbkpGBL --wallet-type bitcoin --max-tokens 1 --tokenlist ./docs/Usage_Examples/btc_privkey_tokenlist.txt
```

The command below will attempt a recovery for a more modern (compresseed, native-segwit address) private key with one missing character, using a tokenlist containing three possible private keys.

```
python btcrecover.py --rawprivatekey --addrs bc1qafy0ftpk5teeayjaqukyd244un8gxvdk8hl5j6 --wallet-type bitcoin --max-tokens 1 --tokenlist ./docs/Usage_Examples/btc_privkey_tokenlist.txt
```

You can also do raw private key repair, even if you don't have a record of the corresponding address, through using an AddressDB. (Also works for Eth, BCH, etc...)

```
python btcrecover.py --rawprivatekey --addressdb ./btcrecover/test/test-addressdbs/addresses-BTC-Test.db --wallet-type bitcoin --max-tokens 1 --tokenlist ./docs/Usage_Examples/btc_privkey_tokenlist.txt
```