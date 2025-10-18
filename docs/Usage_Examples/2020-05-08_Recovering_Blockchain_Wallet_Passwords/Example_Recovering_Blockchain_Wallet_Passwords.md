# Recovering Blockchain.com Wallets 
#### _Previously known as blockchain.info_
[YouTube Video can be found here: https://youtu.be/rkw23s7s4as](https://youtu.be/f63FpoTKwSw)

**Note:** The YouTube video and examples were made before OpenCL acceleration was added to Blockchain.com wallets and can give at least a 10x performance improvement. (See [GPU Accleration](../../GPU_Acceleration.md) for more info) 

## Overview
[Firstly you download the wallet file as per the process here:](../../TUTORIAL.md#downloading-blockchaincom-wallet-files)

Once you have that file, there are three ways that blockchain.com wallets can be recovered.

**1) Using the wallet file directly**

Running BTCRecover with a wallet.aes.json file downloaded from blockchain.com. This is the "normal" way of running BTCRecover where the person/PC running BTCRecover will have enough information to immediately use the recovered wallet file. (You will therefore want to take precautions around the environment you run BTCRecover in)

**2) Using a wallet file "extract"**

Extracting a small amount of data from the wallet file and running BTCRecover with that... What this means is that you can either give this portion of data to someone else to recover for you, or run it on some cloud based machine, without having to worry about it leaking info that would allow someone to steal your crypto. (You therefore don't need to worry as much about the security of the environmen in which you run BTCRecover) 

Using a wallet extract requires a few extra steps... [See here for more info about Extract Scripts...](../../Extract_Scripts.md)

**3) Recover the wallet password from legacy wallet recovery mnemonic**

Blockchain.info previously offered users a wallet recovery mnemonic phrase to [recover their wallet passwords](https://login.blockchain.com/wallet/recover-wallet) from different dictionaries [v2](https://github.com/blockchain/unused-My-Wallet/blob/master/mnemonic.js#L319), [v3](https://github.com/blockchain/unused-My-Wallet/blob/master/mnemonic_words_v3.html)

The recovery mnemonic phase can contain between 6 - 25+ words, though v2 mnemonics will be a multiple of 3

Once you recover your seed phrase it will reveal your password, the password can be used with the wallet the "normal" way, if you changed your password it will only recover the first password.

## Example 1 - Using a TokenList to recover wallet Main Password from a wallet file

### Download the wallet file...

[Download the wallet file as per the process here:](../../TUTORIAL.md#downloading-blockchaincom-wallet-files)

After doing the process above, we will save the wallet data in a file called wallet.aes.json (Which can just be left in your BTCRecover folder be used instead of the wallet file in any of the examples below)

### Create the TokenList File 
**Example Tokenlist - tokenListTest.txt**
``` linenums="1"
{% include "./tokenListTest.txt" %}
```

This file contains some basic tokens that make up the password. (Useful if you re-use sentences, words or phrases in passwords) It has one anchored token (eg: We know which token we started with) as well as some examples of OR type tokens where it will only select one per row. (In this case, let's say you used one of these characters - _ ! = @ in between words and also tended to add the year in there somewhere)

### Run BTCRecover on the Wallet File
**Command**

`python btcrecover.py --wallet btcrecover/test/test-wallets/blockchain-v3.0-MAY2020-wallet.aes.json --typos-capslock --tokenlist ./docs/Usage_Examples/2020-05-08_Recovering_Blockchain_Wallet_Passwords/tokenListTest.txt
`

If you had downloaded the wallet file as above, you would have a file wallet.aes.json in your BTCRecover folder. (You can copy it from this example folder if you like) You would then just use the command:

**Command**

`python btcrecover.py --wallet wallet.aes.json --typos-capslock --tokenlist ./docs/Usage_Examples/2020-05-08_Recovering_Blockchain_Wallet_Passwords/tokenListTest.txt
`

## Example 2 - Using a PasswordList+CommonTypos to recover a wallet Second Password from a wallet file

### Download the Wallet File the same as in the previous example...

Using the password that we found from the previous step... _btcr-test-password_

### Create the PasswordList File
**Example Passwordlist: passwordListTest_1.txt**

``` linenums="1"
{% include "./passwordListTest_1.txt" %}
```
This file contains the correct password with 4 typos in it + the first twenty options off the RockYou password list...

### Run BTCRecover on the Wallet File
**Command**

```
python btcrecover.py --wallet btcrecover/test/test-wallets/blockchain-v2.0-wallet.aes.json --blockchain-secondpass --typos-case --typos-delete --typos 4 --passwordlist docs/Usage_Examples/2020-05-08_Recovering_Blockchain_Wallet_Passwords/passwordListTest_1.txt
```

## Example 3 - Same as example 2 but using a wallet extract

### Extract Sample Data from a Wallet File to solve a second password
**Command**

`python ./extract-scripts/extract-blockchain-second-hash.py ./btcrecover/test/test-wallets/blockchain-v2.0-wallet.aes.json
`
We will then be prompted for the main wallet password which we know is btcr-test-password

This script will then return the data:

`Blockchain second password hash, salt, and iter_count in base64:
YnM6LeP7peG853HnQlaGswlwpwtqXKwa/1rLyeGzvKNl9HpyjnaeTCZDAaC4LbJcVkxaECcAACwXY6w=`

### Run BTCRecover with the Extracted Script
**Command**

`python btcrecover.py --data-extract --typos-case --typos-delete --typos 4 --passwordlist docs/Usage_Examples/2020-05-08_Recovering_Blockchain_Wallet_Passwords/passwordListTest_1.txt`

You will be prompted to enter the data extract, so paste `YnM6LeP7peG853HnQlaGswlwpwtqXKwa/1rLyeGzvKNl9HpyjnaeTCZDAaC4LbJcVkxaECcAACwXY6w=` from the previous step.

## Example 4 - Recovering the wallet password for a Blockchain Legacy Recovery Mnemonic

**Note:** These are an older type of mnemonic that is not the same as a BIP39 mnemonic. These mnemonics came in various lengths and could be used to recover either the account password, or the account ID and password. 

The password will only be the password that was set when the mnemonic was created, if the password was changed after this then this recovery mnemonic is of no use to you... If you still have the wallet.aes.json file, then you can also use the password derived from this process to decrypt/dump the wallet file.

### Run BTCRecover with your suspected seed phrase and length
BTCRecover will try different combinations and use a checksum to identify the correct seed phrase and password

**Command**

`python seedrecover.py --wallet-type blockchainpasswordv3 --mnemonic "carve witch manage yerevan yerevan yerevan yerevan yerevan yerevan yerevan yerevan hardly hamburgers insiders hamburgers ignite infernal" --mnemonic-length 17
`