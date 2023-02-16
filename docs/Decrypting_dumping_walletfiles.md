# Decrypting and Dumping Wallet Files

## Background
Some of the wallets types that BTCRecover supports are no longer maintained or safe to use (Eg: Multibit), can be difficult for some users to set up and use (eg: Bitcoin Core) or may have bugs in the wallet itself that prevent users who have the correct wallet and passwords from accessing their funds. (Eg: Some old Blockchain.com or blockchain.info wallets) Never mind that there might be some situations where the value of the funds are such that importing these recovered wallets back in to a hot wallet might be a really bad idea...

You may also just be interested in seeing what is in there or find this useful in terms of debugging...

As such, BTCRecover supports the ability to dump the raw decrypted wallet file or to dump the raw private keys in a format that can be imported directly in to wallets like Electrum which allows the funds to be securely moved through offline signing...

Support for dumping additional wallet types will be added over time...

Generally there are two commands used to dump wallet files.

    --dump-wallet FILENAME

    --dump-privkeys FILENAME

These above commands can be used as part of a standard recovery to automatically decrypt/dump the wallet if the password is found. 

There are also some extra parameters that mean you can avoid using a passwordlist or tokenlist if you are only interested in dumping/decrypting a wallet file...

    --correct-wallet-password
    --correct-wallet-secondpassword

### Blockchain.com Wallets (Previously known as blockchain.info)

**Important Note**
Some older blockchain.com wallets (2014-2015 era at least, perhaps more) have a bug where some private keys were incorrectly encoded and saved to the wallet file... (Basically if the hex encoded private key included any leading zeroes, these were left off, leading to private keys that are less than 32 bytes... The current blockchain.com simply rejects these as invalid and assumes an incorrect password...) The symptoms of this are that your wallet may have correctly worked until about 2015/2016, BTCRecover will correctly match the wallet passwords (main password and/or second passwords) yet you will be unable to log in with your wallet at blockchain.com (Perhaps being prompted for a second password at login time, not just when sending funds) nor import old backups of your wallet file in to the platform. Blockchain support will simply dismiss your concerns and insist that you have the wrong password... (And given they are a non-custodial platform, don't actually have any visibility in to your specific wallet file file to be able to debug it...) The solution is to dump the private keys from these wallet files (or keys) and to import them in to something like Electrum.

#### Decrypting/Dumping with Main Password
**Dumping Wallet File Without a Second Password**

You can use the following command to decrypt/dump one of the wallets that is included with the repository... The main password for this wallet is "mypassword""...

    python btcrecover.py --wallet ./btcrecover/test/test-wallets/blockchain-github-v1-1 --dump-wallet blockchain-github-v1-1_main_dump.txt --correct-wallet-password mypassword

This command will produce the following dump.

``` linenums="1"
{% include "../btcrecover/test/test-wallets/blockchain-github-v1-1_main_dump.txt" %}
```

The file above shows the full contents of the wallet as well, the base58 encoded private keys as well as the private keys that have been converted for both compressed and uncompresssed formats. (One one of these corresponds to the actual wallet address, I could tweak this to only dump one but there is no harm in simply importing both...)

**Dumping Private Keys for a wallet without a second password**

You can use the following command to dump the private keys from one of the wallets included in this repository to a file... The main password for this wallet is "mypassword"...

    python btcrecover.py --wallet ./btcrecover/test/test-wallets/blockchain-github-v1-1 --dump-privkeys blockchain-github-v1-1_main_privkeys.txt --correct-wallet-password mypassword

This command will produce the following dump.

``` linenums="1"
{% include "../btcrecover/test/test-wallets/blockchain-github-v1-1_main_privkeys.txt" %}
```

You can then copy/paste the contents of this file directly in to Electrum... (Like the examples above, this will include both compressed and uncompressed private keys)

**Dumping Wallet File (Where there is a second password)**

You can use the following command to decrypt/dump one of the wallets that is included with the repository... The main password for this wallet is "btcr-test-password"...

    python btcrecover.py --wallet ./btcrecover/test/test-wallets/blockchain-v2.0-wallet.aes.json --dump-wallet blockchain-v2.0-wallet.aes.json_main_dump.txt --correct-wallet-password btcr-test-password
    
This command will produce the following dump.

``` linenums="1"
{% include "../btcrecover/test/test-wallets/blockchain-v2.0-wallet.aes.json_main_dump.txt" %}
```

This example decrypts using the "main password only", meaning that the body of the file will be decrypted, including addresses, but the private keys will remain encrypted.


#### Decrypting/Dumping with Second Password
**Dumping Wallet File with a Second Password**

You can use the following command to decrypt/dump one of the wallets that is included with the repository... The main and second passwords for this wallet are "btcr-test-password"...

    python btcrecover.py --wallet ./btcrecover/test/test-wallets/blockchain-v2.0-wallet.aes.json --dump-wallet blockchain-v2.0-wallet.aes.json_secondpass_dump.txt --correct-wallet-password btcr-test-password --blockchain-secondpass --correct-wallet-secondpassword btcr-test-password

This command will produce the following dump.

``` linenums="1"
{% include "../btcrecover/test/test-wallets/blockchain-v2.0-wallet.aes.json_secondpass_dump.txt" %}
```

Like the example above, this wallet dump will include the encrypted private keys, raw decrypted private keys (in base58) and private keys, both compressed and uncompressed, that can be imported directly in to wallets like Electrum.

**Dumping Private Keys for a wallet with a second password**

You can use the following command to decrypt/dump one of the wallets that is included with the repository... The main and second passwords for this wallet are "btcr-test-password"...

    python btcrecover.py --wallet ./btcrecover/test/test-wallets/blockchain-v2.0-wallet.aes.json --dump-privkeys blockchain-v2.0-wallet.aes.json_secondpass_privkeys.txt --correct-wallet-password btcr-test-password --blockchain-secondpass --correct-wallet-secondpassword btcr-test-password
    
This command will produce the following dump.
    
``` linenums="1"
{% include "../btcrecover/test/test-wallets/blockchain-v2.0-wallet.aes.json_secondpass_privkeys.txt" %}
```

These can then be copy/pasted directly in to a wallet like Electrum.

### Coinomi Wallets

You can use the following command to decrypt/dump one of the wallets that is included with the repository... The main and second passwords for this wallet are "btcr-test-password"...

    python btcrecover.py --wallet ./btcrecover/test/test-wallets/coinomi.wallet.desktop --correct-wallet-password btcr-test-password --dump-privkeys coinomi.wallet.desktop.privkeys.txt

This command will produce the following dump.

``` linenums="1"
{% include "../btcrecover/test/test-wallets/coinomi.wallet.desktop.privkeys.txt" %}
```

### Metamask Wallets

You can use the following command to decrypt/dump one of the wallets that is included with the repository... The main and second passwords for this wallet are "btcr-test-password"...

    python btcrecover.py --wallet ./btcrecover/test/test-wallets/metamask/nkbihfbeogaeaoehlefnkodbefgpgknn --correct-wallet-password btcr-test-password --dump-privkeys metamask.privkeys.txt

This command will produce the following dump.

``` linenums="1"
{% include "../btcrecover/test/test-wallets/metamask.privkeys.txt" %}
```

### Multibit Classic Wallets Backups (And MultiDoge)
You can dump either .wallet files or key-backup files.

You can use the following command to decrypt/dump one of the Multibit Classic wallet keyfiles that is included with the repository... The main password for this wallet is "btcr-test-password"...

    python btcrecover.py --wallet ./btcrecover/test/test-wallets/multibit-wallet.key --correct-wallet-password btcr-test-password --dump-privkeys multibit-wallet.key.privkeys.txt

This command will produce the following dump.

``` linenums="1"
{% include "../btcrecover/test/test-wallets/multibit-wallet.key.privkeys.txt" %}
```
<br>
You can also decrypt/dump a .wallet file with the same type of command.

    python btcrecover.py --wallet ./btcrecover/test/test-wallets/multibit.wallet.bitcoinj.encrypted --correct-wallet-password btcr-test-password --dump-privkeys multibit.wallet.bitcoinj.encrypted.txt

Which will produce the following:
``` linenums="1"
{% include "../btcrecover/test/test-wallets/multibit.wallet.bitcoinj.encrypted.txt" %}
```
<br>
Likewise, you can decrypt/dump MultiDoge keyfiles with a command like:

    python btcrecover.py --wallet ./btcrecover/test/test-wallets/multidoge-wallet.key --correct-wallet-password btcr-test-password --dump-privkeys multidoge-wallet.key.privkeys.txt

This command will produce the following dump.

``` linenums="1"
{% include "../btcrecover/test/test-wallets/multidoge-wallet.key.privkeys.txt" %}
```

### Multibit HD Wallets

You can use the following command to decrypt/dump one of the wallets that is included with the repository... The main password for this wallet is "btcr-test-password"...

    python btcrecover.py --wallet ./btcrecover/test/test-wallets/multibithd-v0.5.0/mbhd.wallet.aes --correct-wallet-password btcr-test-password --dump-privkeys mbhd.wallet.aes.privkeys.txt

This command will produce the following dump.

``` linenums="1"
{% include "../btcrecover/test/test-wallets/multibithd-v0.5.0/mbhd.wallet.aes.privkeys.txt" %}
```

