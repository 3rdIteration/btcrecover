# *btcrecover* extract scripts #

Sometimes, it is not desirable to run *btcrecover* directly on the computer which stores the target wallet file. For example:

 * A computer or a cloud-based virtual machine with faster CPUs or GPUs might be a better place to run *btcrecover*.
 * Configuring *btcrecover* to search for your password correctly can be tricky; you might be interested in finding someone who can configure and run *btcrecover* for you on their computer.
 * You may not trust that *btcrecover* is free from harmful bugs or other malicious behavior. *btcrecover* is open source, and requires no untrustworthy binaries be installed. However it's also a fairly long and complicated Python script, which makes it difficult even for other Python programmers to be certain that it doesn't contain any harmful code (either intentionally malicious or just by accident).

The extract scripts in this directory are relatively short and simple scripts which extract the just enough information from a wallet file to allow *btcrecover* to perform a password search. These scripts never extract enough information to put any of your bitcoin funds at risk, even after the password is found.

For more information regarding *btcrecover*, please see [TUTORIAL.md](TUTORIAL.md).

## Download ##

You can download the entire *btcrecover* package from: <https://github.com/3rditeration/btcrecover/archive/master.zip>

If you'd prefer to download just a single extract script, please select the one for your wallet software from below, then right click and choose “Save link as...” or “Save target as...”:

 * Bitcoin Core - <https://github.com/3rditeration/btcrecover/raw/master/extract-scripts/extract-bitcoincore-mkey.py>
 * Bither - <https://github.com/3rditeration/btcrecover/raw/master/extract-scripts/extract-bither-partkey.py>
 * Blockchain main password - <https://github.com/3rditeration/btcrecover/raw/master/extract-scripts/extract-blockchain-main-data.py>
 * Blockchain second password -  <https://github.com/3rditeration/btcrecover/raw/master/extract-scripts/extract-blockchain-second-hash.py>
 * Electrum 1.x - <https://github.com/3rditeration/btcrecover/raw/master/extract-scripts/extract-electrum-halfseed.py>
 * Electrum 2.x - <https://github.com/3rditeration/btcrecover/raw/master/extract-scripts/extract-electrum2-partmpk.py>
 * mSIGNA - <https://github.com/3rditeration/btcrecover/raw/master/extract-scripts/extract-msigna-partmpk.py>
 * MultiBit Classic - <https://github.com/3rditeration/btcrecover/raw/master/extract-scripts/extract-multibit-privkey.py>
 * MultiBit HD - <https://github.com/3rditeration/btcrecover/raw/master/extract-scripts/extract-multibit-hd-data.py>

If you're on Windows, you will also need to install the latest version of Python 3.7 or above. For any other wallets, just follow the [instructions to install Python here](INSTALL.md#python).

----------

## Usage for Bitcoin Core ##

After downloading the script, **make a copy of your wallet.dat file into a different folder** (to make it easy, into the same folder as *extract-bitcoincore-mkey.py*). As an example for Windows, click on the Start Menu, then click “Run...”, and then type this to open your Bitcoin folder which contains your wallet.dat file: `%appdata%\Bitcoin`. From here you can copy and paste your wallet.dat file into a separate folder. Next you'll need to open a Command Prompt window and type something like this (depending on where the downloaded script is, and assuming you've made a copy of your wallet.dat into the same folder):

    cd btcrecover-master\extract-scripts
    python3 extract-bitcoincore-mkey.py wallet.dat

You should get a message which looks like this as a result:

    Bitcoin Core encrypted master key, salt, iter_count, and crc in base64:
    lV/wGO5oAUM42KTfq5s3egX3Uhk6gc5gEf1R3TppgzWNW7NGZQF5t5U3Ik0qYs5/dprb+ifLDHuGNQIA+8oRWA==

If you instead have a dump file of a Bitcoin Core wallet that was created by pywallet, just follow these same instructions except use the *extract-bitcoincore-mkey-from-pywallet.py* script instead.

When you (or someone else) runs *btcrecover* to search for passwords, you will not need your wallet file, only the output from *extract-bitcoincore-mkey.py*. To continue the example:

    cd btcrecover-master
    python3 btcrecover.py --data-extract --tokenlist tokens.txt
    Please enter the data from the extract script
    > lV/wGO5oAUM42KTfq5s3egX3Uhk6gc5gEf1R3TppgzWNW7NGZQF5t5U3Ik0qYs5/dprb+ifLDHuGNQIA+8oRWA==
    ...
    Password found: xxxx

### Bitcoin Core Technical Details ###

The *extract-bitcoincore-mkey.py* script is intentionally short and should be easy to read for any Python programmer. It opens a wallet.dat file using the Python bsddb.db (Or a Pure Python implementation if this module isn't available) or SQLite, and then extracts a single key/value pair with the key string of `\x04mkey\x01\x00\x00\x00`. This key/value pair contains an encrypted version of the Bitcoin Core “master key”, or mkey for short, along with some other information required to try decrypting the mkey, specifically the mkey salt and iteration count. This information is then converted to base64 format for easy copy/paste, and printed to the screen.

The encrypted mkey is useful to *btcrecover*, but it does not contain any of your Bitcoin address or private key information. *btcrecover* can attempt to decrypt the mkey by trying different password combinations. Should it succeed, it and whoever runs it will then know the password to your wallet file, but without the rest of your wallet file, the password and the decrypted mkey are of no use.

## Usage for Bither ##

After downloading the script, **make a copy of your wallet file into a different folder** (to make it easy, into the same folder as the extract script). As an example for Windows, click on the Start Menu, then click “Run...”, and then type this to open the folder which usually contains your wallet file: `%appdata%\Bither`. From here you can copy and paste your wallet file (it's usually named `address.db`), into a separate folder. Next you'll need to open a Command Prompt window and type something like this (depending on where the downloaded script is, and assuming your wallet file is in the same folder):

    cd btcrecover-master\extract-scripts
    python3 extract-bither-partkey.py address.db

You should get a message which looks like this:

    Bither partial encrypted private key, salt, and crc in base64:
    YnQ6PocfHvWGVbCzlVb9cUtPDjosnuB7RoyspTEzZZAqURlCsLudQaQ4IkIW8YE=

When you (or someone else) runs *btcrecover* to search for passwords, you will not need your wallet file, only the output from *extract-bither-partkey.py*. To continue the example:

    cd btcrecover-master
    python3 btcrecover.py --data-extract --tokenlist tokens.txt
    Please enter the data from the extract script
    > YnQ6PocfHvWGVbCzlVb9cUtPDjosnuB7RoyspTEzZZAqURlCsLudQaQ4IkIW8YE=
    ...
    Password found: xxxx

### Bither Technical Details ###

The *extract-bither-partkey.py* script is intentionally short and should be easy to read for any Python programmer. A Bither encrypted private key is 48 bytes long. It contains 32 bytes of encrypted private key data, followed by 16 bytes of encrypted padding.

Because only the last half of the private key is extracted, the private key cannot be feasibly reconstructed even if this half of the private key could be decrypted (assuming the password search succeeds). The remaining 16 bytes of padding, once decrypted, is predictable, and this allows *btcrecover* to use it to check passwords. It tries decrypting the bytes with each password, and once this results in valid padding, it has found the correct password.

Without access to the rest of your wallet file, it is impossible the decrypted padding could ever lead to a loss of funds.


## Usage for Blockchain.com ##

The first step is to download your Blockchain.com wallet backup file.

You will need to navigate to the `extract-scripts` folder of this package and run

`python3 download-blockchain-wallet.py`

When prompted, enter your wallet ID and then approve the login request on the email account associated with the wallet. Once the login is approved, your wallet.aes.json file will be saved to you PC.

Next you'll need to open a Command Prompt window and type something like this :

    python3 extract-blockchain-main-data.py wallet.aes.json

Of course, you need to replace the wallet file name with yours. You should get a message which looks like this as a result:

    Blockchain first 16 encrypted bytes, iv, and iter_count in base64:
    Yms6abF6aZYdu5sKpStKA4ihra6GEAeZTumFiIM0YQUkTjcQJwAAj8ekAQ==

When you (or someone else) runs *btcrecover* to search for passwords, you will not need your wallet file, only the output from *extract-blockchain-main-data.py*. To continue the example:

    btcrecover-master
    python3 btcrecover.py --data-extract --tokenlist tokens.txt
    Please enter the data from the extract script
    > Yms6abF6aZYdu5sKpStKA4ihra6GEAeZTumFiIM0YQUkTjcQJwAAj8ekAQ==
    ...
    Password found: xxxx

### Blockchain.com Second Passwords ###

If you've enabled the Second Password feature of your Blockchain.com wallet, and if you need to search for this second password, you must start by finding the main password if you don't already have it (see above). Once you have your main password, take your wallet backup file (it's usually named `wallet.aes.json`), and **make a copy of it into a different folder** (to make it easy, into the same folder as the extract script). Next you'll need to open a Command Prompt window and type something like this :

    cd btcrecover-master\extract-scripts
    python3 extract-blockchain-second-hash.py wallet.aes.json
    Please enter the Blockchain wallet's main password:

You need to enter your wallet's main password when prompted so that the extract script can remove the first level of encryption to gain access to the second level of encrypted data. You should get a message which looks like this as a result:

    Blockchain second password hash, salt, and iter_count in base64:
    YnM6LeP7peG853HnQlaGswlwpwtqXKwa/1rLyeGzvKNl9HpyjnaeTCZDAaC4LbJcVkxaECcAACwXY6w=

When you (or someone else) runs *btcrecover* to search for passwords, you will not need your wallet file, only the output from *extract-blockchain-second-hash.py*. To continue the example:

    cd btcrecover-master
    python3 btcrecover.py --data-extract --tokenlist tokens.txt
    Please enter the data from the extract script
    > YnM6LeP7peG853HnQlaGswlwpwtqXKwa/1rLyeGzvKNl9HpyjnaeTCZDAaC4LbJcVkxaECcAACwXY6w=
    ...
    Password found: xxxx

Please note that you must either download the entire *btcrecover* package which includes an AES decryption library, or you must already have PyCrypto installed in order to use the *extract-blockchain-second-hash.py* script.

### Blockchain.com Technical Details ###

The *extract-blockchain-main-data.py* script is intentionally short and should be easy to read for any Python programmer. This script extracts the first 32 bytes of encrypted data from a Blockchain.com wallet, of which 16 bytes are an AES initialization vector, and the remaining 16 bytes are the first encrypted AES block. This information is then converted to base64 format for easy copy/paste, and printed to the screen. The one encrypted block does not contain any private key information, but once decrypted it does contain a non-sensitive string (specifically the string "guid", "tx_notes", "address_book" or "double") which can be used by *btcrecover* to test for a successful password try.

The *extract-blockchain-second-hash.py* script is a bit longer, but it should still be short enough for most Python programmers to read and understand. After decrypting the first level of encryption of a Blockchain.com wallet, it extracts a password hash and salt which can be used by *btcrecover* to test for a successful password try. It does not extract any of the encrypted private keys.

Without access to the rest of your wallet file, the bits of information extracted by these scripts alone do not put any of your Bitcoin funds at risk, even after a successful password guess and decryption.

## Usage for Coinomi ##

**Note: This only supports wallets that are protected by a password. If you selected "no password", "biometrics" or "password + biometrics" then you will also need information from your phones keystore... (Which may be impossible to retrieve)**

The first step for Coinomi depends on which platform you are running it on.

For Windows users, it's simply a case of navigating to %localappdata%\Coinomi\Coinomi\wallets and you will find your wallet files. 

For Android users, you will need to have a rooted phone which will allow you to access the .wallet file in the Coinomi. (It should be found in the folder data\data\com.coinomi.wallet\files\wallets) How to get root access on your particular phone is beyond the scope of this document, but be warned that some methods of rooting your phone will involve a factory reset.

If there are mulitiple wallets there and you are not sure which is the correct one, the name of each wallet can be found in clear text at the end of the file. [See the test wallets included with this repository in ./btcrecover/test/test-wallets](https://github.com/3rdIteration/btcrecover/tree/master/btcrecover/test/test-wallets) for an example)

Once you have the file, you can either use it directly with BTCRecover, or you can create an extract.

    python extract-coinomi-privkey.py ../btcrecover/test/test-wallets/coinomi.wallet.android
    Coinomi partial first encrypted private key, salt, n, r, p and crc in base64:
    Y246uwodSaelErkb7GIYls3xaeX5i5YWtmh814zgsBCx+y8xgjp7Mul0TQBAAAAIAAEASAgdvw==

## Usage for Dogechain.info ##

[Firstly you download the wallet file as per the documentation here:](./TUTORIAL.md#downloading-dogechaininfo-wallet-files)

You can then create an extract script from the downloaded wallet file with the a command like the one below. (Which uses the sample wallet file that is part of the repository)

    python extract-dogechain-privkey.py ../btcrecover\test\test-wallets/dogechain.wallet.aes.json
    Dogechain first 16 encrypted bytes, iv, and iter_count in base64:
    ZGM6jJzIUd6i9DMEgCFG9JQ1/z4xSamItXAiQnV4AeJ0BwcZznn+169Eb84PFQ3QQ2JGiBMAAGL+4VE=

## Usage for Electrum ##

After downloading the script, **make a copy of your wallet file into a different folder** (to make it easy, into the same folder as the extract script). As an example for Windows, click on the Start Menu, then click “Run...”, and then type this to open the folder which contains the first wallet file created by Electrum after it is installed: `%appdata%\Electrum\wallets`. From here you can copy and paste your wallet file, usually named `default_wallet`, into a separate folder. Next you'll need to open a Command Prompt window and type something like this :

    cd btcrecover-master\extract-scripts
    python3 extract-electrum2-partmpk.py default_wallet

The example above assumes you have an Electrum 2.x wallet. If it's an Electrum 1.x wallet instead, replace *extract-electrum2-partmpk.py* with *extract-electrum-halfseed.py*. Of course, you'll also need to replace the wallet file name with yours. You should get a message which looks either like this:

    First half of encrypted Electrum seed, iv, and crc in base64:
    ZWw6kLJxTDF7LxneT7c5DblJ9k9WYwV6YUIUQO+IDiIXzMUZvsCT

Or like this, depending on the wallet details:

    Electrum2 partial encrypted master private key, iv, and crc in base64:
    ZTI69B961mYKYFV7Bg1zRYZ8ZGw4cE+2D8NF3lp6d2XPe8qTdJUz

When you (or someone else) runs *btcrecover* to search for passwords, you will not need your wallet file, only the output from *extract-electrum-halfseed.py*. To continue the example:

    cd btcrecover-master
    python3 btcrecover.py --data-extract --tokenlist tokens.txt
    Please enter the data from the extract script
    > ZWw6kLJxTDF7LxneT7c5DblJ9k9WYwV6YUIUQO+IDiIXzMUZvsCT
    ...
    Password found: xxxx

### Electrum 1.x Technical Details ###

The *extract-electrum-halfseed.py* script is intentionally short and should be easy to read for any Python programmer. An Electrum encrypted seed is 64 bytes long. It contains a 16-byte AES initialization vector, followed by 48 bytes of encrypted seed data, the last 16 of which are padding (so just 32 bytes of actual seed data). The script extracts the 16-byte initialization vector and just the first 16 bytes of actual seed data (50% of the seed).

Because only half of the seed is extracted, the private keys cannot be feasibly reconstructed even after the half-seed is decrypted (assuming the password search succeeds). Because these 16 characters, once decrypted, are hex encoded, *btcrecover* can use them alone to check passwords. It tries decrypting the bytes with each password, and once the result is a valid 16-character long hex-encoded string, it has found the correct password.

Without access to the rest of your wallet file, it is extremely unlikely that these 16 characters alone could put any of your Bitcoin funds at risk, even after a successful password guess and decryption.

### Electrum 2.x Technical Details ###

The *extract-electrum2-partmpk.py* script is intentionally short and should be easy to read for any Python programmer. An Electrum 2.x encrypted master private key (mpk) is 128 bytes long. It contains a 16-byte AES initialization vector, followed by 112 bytes of encrypted mpk data, with the last byte being padding (so 111 bytes of actual mpk data). Of these 111 bytes, roughly 18 comprise a header, the next 44 the chaincode, and the remaining 47 a private key. The script extracts the 16-byte initialization vector and just the first 16 bytes of mpk data, all of it non-sensitive header information.

Once decrypted, these 16 characters always begin with the string "xprv", and the remainder are base58 encoded, *btcrecover* can use them alone to check passwords. It tries decrypting the bytes with each password, and once the result is what's expected, it has found the correct password.

Without access to the rest of your wallet file, it is impossible the decrypted header information could ever lead to a loss of funds.

## Usage for Metamask ##
There are two extract scripts for Metamask, that lets you extract all the vault data (including old overwritten wallets) from the extension and one that allows you to create a n extract for trustedless recovery. 

For Chrome Based Browsers, you will need to locate the data folder for the browser extension.

For Metamask this is: %localappdata%\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn\

For Binance Wallet Extension this is: %localappdata%\Google\Chrome\User Data\Default\Local Extension Settings\fhbohimaelbohpjbbldcngcnapndodjp\

For Ronin Wallet this is: %localappdata%\Google\Chrome\User Data\Default\Local Extension Settings\fnjhmkhhmkbjkkabndcnnogagogbneec\

The paths for the extension data will be a bit different for other Chrome based browserse (Like Brave) but the general location and final folder name will be the same.

_You can then view all of the vault data for that extension by using a command similar to the one below (Except you will want to use the path to your own browser extension data)_

    python extract-metamask-vaults.py ../btcrecover/test/test-wallets/metamask/nkbihfbeogaeaoehlefnkodbefgpgknn
    ===== (Likely) Old Vault Data =====
    
    {"data":"vXOTraxWuDmDrhxZ759NodhTmd4UQkThRG6YLvPt14OdZgnvJo4P5wj+LRupmb+7Vql+fOM5IF33Qb3FQvWro8Ro201M1YOH5zBdSwK6wzYmlFndlwqgOq61HSDUD9Ee1ccUF/iUgqJIngCw9/bRo93kpj11MuVonNOayTFztRc68+/JPCmIe0vqPYShRfJbeI8IBvauJdUxg6VqG0PId0Pw30ZO3f3QXmKFE+ZoibgbO111j7gQ0l7j6KdABeA=","iv":"7hvnbvsoSQmAbWzfvtMkjA==","salt":"13+DUqg893kPM0MiJz3bz2iYGAxPtPisX1JE1+be9IU="}
    
    ===== Current Vault Data =====
    
    {"data":"Ny6zeXCgltvFkIWycZU3gYLocIM+gH/2m4fozdKdJxwff2BUHXaxBkaLDuzMs7WtazXJ+3P+XsFFG2W8+7tpNfCv2RCNNHWX9aVEBKeKEwQPUT6MD4rNU2XYykPROAcbdUPHKEVpaAEj+1VlCiMk1m3j7KhIHpt1cI7Qp8rV7lxzCUc5FWAWlc+gxvFTfSXOPJd0k23/F9MgRq0vn2h+UJolmLzpQFvEv2BUuL6CoEbog8Vn2N+ktypbR2pnNMA=","iv":"H82DrVooOndR7fk1SKKGwQ==","salt":"cxp0pRtsgyUBjll6MktU2HySubrtnMaPXAwaBsANA1Y="}

For Firefox, you will need to retrieve your Metamask vault using the process described here:
https://metamask.zendesk.com/hc/en-us/articles/360018766351-How-to-use-the-Vault-Decryptor-with-the-MetaMask-Vault-Data

Once you have the vault data, you can put it in a text file and you can either use it directly with BTCRecover, or you can create an extract.

    python extract-metamask-privkey.py ../btcrecover/test/test-wallets/metamask.9.8.4_firefox_vault
    Metamask first 16 encrypted bytes, iv, and salt in base64:
    bXQ6bB5JP1EW0xwBmWZ9vI/iw9IRkorRs9rI6wJCNrd8KUw61ubkQxf9JF9jDv9kZIlxVVkKb7lIwnt7+519MLodzoK0sOw=

## Usage for mSIGNA ##

After downloading the script, **make a copy of your wallet file into a different folder** (to make it easy, into the same folder as the extract script). As an example for Windows, click on the Start Menu, then click “Run...”, and then type this to open the folder which usually contains your wallet file: `%homedrive%%homepath%`. From here you can copy and paste your wallet file (it's a `.vault` file), into a separate folder. Next you'll need to open a Command Prompt window and type something like this (depending on where the downloaded script is, and assuming your wallet file is named `msigna-wallet.vault` and it's in the same folder):

    cd btcrecover-master\extract-scripts
    python3 extract-msigna-partmpk.py msigna-wallet.vault

You should get a message which looks like this:

    mSIGNA partial encrypted master private key, salt, and crc in base64:
    bXM6SWd6U+qTKOzQDfz8auBL1/tzu0kap7NMOqctt7U0nA8XOI6j6BCjxCsc7mU=

When you (or someone else) runs *btcrecover* to search for passwords, you will not need your wallet file, only the output from *extract-msigna-partmpk.py*. To continue the example:

    cd btcrecover-master
    python3 btcrecover.py --data-extract --tokenlist tokens.txt
    Please enter the data from the extract script
    > bXM6SWd6U+qTKOzQDfz8auBL1/tzu0kap7NMOqctt7U0nA8XOI6j6BCjxCsc7mU=
    ...
    Password found: xxxx

### mSIGNA Technical Details ###

The *extract-msigna-partmpk.py* script is intentionally short and should be easy to read for any Python programmer. An mSIGNA encrypted master private key is 48 bytes long. It contains 32 bytes of encrypted private key data, followed by 16 bytes of encrypted padding (the chaincode is stored separately).

Because only the last half of the private key is extracted, the wallet cannot be feasibly reconstructed even if this half of the private key could be decrypted (assuming the password search succeeds). The remaining 16 bytes of padding, once decrypted, is predictable, and this allows *btcrecover* to use it to check passwords. It tries decrypting the bytes with each password, and once this results in valid padding, it has found the correct password.

Without access to the rest of your wallet file, it is impossible the decrypted padding could ever lead to a loss of funds.


## Usage for MultiBit Classic ##

***Warning:*** Using the `extract-multibit-privkey.py` script on a MultiBit Classic key file, as described below, can lead to *false positives*. A *false positive* occurs when *btcrecover* reports that it has found the password, but is mistaken—the password which it displays may not be correct. If you plan to test a large number of passwords (on the order of 10 billion (10,000,000,000) or more), it's **strongly recommended** that you use *btcrecover* directly with a key file instead of using `extract-multibit-privkey.py`.

*btcrecover* doesn’t operate directly on MultiBit wallet files, instead it operates on MultiBit private key backup files. When you first add a password to your MultiBit wallet, and after that each time you add a new receiving address or change your wallet password, MultiBit creates an encrypted private key backup file in a `key-backup` directory that's near the wallet file. These private key backup files are much faster to try passwords against (by a factor of over 1,000), which is why *btcrecover* uses them. For the default wallet that is created when MultiBit is first installed, this directory is located here:

    %appdata%\MultiBit\multibit-data\key-backup

The key files have names which look like `walletname-20140407200743.key`. If you've created additional wallets, their `key-backup` directories will be located elsewhere and it's up to you to locate them.

For more details on locating your MultiBit private key backup files, see: <https://www.multibit.org/en/help/v0.5/help_fileDescriptions.html>

Once you've located the correct MultiBit private key backup file, **make a copy of it into a different folder** (to make it easy, into the same folder as the extract script). As an example for Windows, click on the Start Menu, then click “Run...”, and then type this to open the private key backup folder for the first wallet which MultiBit creates (this might not be the one you want, though...): `%appdata%\MultiBit\multibit-data\key-backup`. From here you can copy and paste a private key backup file into a separate folder. Next you'll need to open a Command Prompt window and type something like this (depending on where the downloaded script is, and assuming you've made a copy of the private key file into the same folder):

    cd btcrecover-master\extract-scripts
    python3 extract-multibit-privkey.py multibit-20140407200743.key

Of course, you need to replace the private key file name with yours. You should get a message which looks like this as a result:

    MultiBit partial first encrypted private key, salt, and crc in base64:
    bWI6sTaHldcBFFj9zlgNpO1szOwy8elpl20OWgj+lA==

When you (or someone else) runs *btcrecover* to search for passwords, you will not need your wallet file or the private key file, only the output from *extract-multibit-privkey.py*. To continue the example:

    cd btcrecover-master
    python3 btcrecover.py --data-extract --tokenlist tokens.txt
    Please enter the data from the extract script
    > bWI6sTaHldcBFFj9zlgNpO1szOwy8elpl20OWgj+lA==
    ...
    Password found: xxxx

### MultiBit Classic Technical Details ###

**Warning:** MultiBit Classic data-extracts have a false positive rate of approximately 1 in 3×10<sup>11</sup>. See the warning above for more information.

The *extract-multibit-privkey.py* script is intentionally short and should be easy to read for any Python programmer. This script extracts 8 bytes of password salt plus the first 16 encrypted base58-encoded characters (out of 52) from the first private key from a MultiBit private key backup file. Because less than 34% of a single private key is extracted, the private key itself cannot be feasibly reconstructed even after these first 16 bytes are decrypted (assuming the password search succeeds). Because these 16 characters, once decrypted, are base58 encoded, *btcrecover* can use them alone to check passwords. It tries decrypting the bytes with each password, and once the result is a valid 16-character long base58-encoded private key prefix, it has found the correct password.

Without access to the rest of your private key backup file or your wallet file, these 16 characters alone do not put any of your Bitcoin funds at risk, even after a successful password guess and decryption.


## Usage for MultiBit HD ##

After downloading the script, **make a copy of your mbhd.wallet.aes file into a different folder** (to make it easy, into the same folder as *extract-multibit-hd-data.py*). As an example for Windows, click on the Start Menu, then click “Run...”, and then type this: `%appdata%\MultiBitHD`. From here you can open your wallet folder, and copy and paste your mbhd.wallet.aes file into a separate folder. Next you'll need to open a Command Prompt window and type something like this (depending on where the downloaded script is, and assuming you've made a copy of your mbhd.wallet.aes into the same folder):

    cd btcrecover-master\extract-scripts
    python3 extract-multibit-hd-data.py mbhd.wallet.aes

You should get a message which looks like this as a result:

    MultiBit HD first 16 bytes of encrypted wallet and crc in base64:
    bTI6LbH/+ROEa0cQ0inH7V3thbdFJV4=

When you (or someone else) runs *btcrecover* to search for passwords, you will not need your wallet file, only the output from *extract-multibit-hd-data.py*. To continue the example:

    cd btcrecover-master
    python3 btcrecover.py --data-extract --tokenlist tokens.txt
    Please enter the data from the extract script
    > bTI6LbH/+ROEa0cQ0inH7V3thbdFJV4=
    ...
    Password found: xxxx

### MultiBit HD Technical Details ###

The *extract-multibit-hd-data* script is intentionally short and should be easy to read for any Python programmer. A MultiBit HD wallet file is entirely encrypted. The extract script simply reads the first 32 bytes from the wallet file.

These 32 bytes optionally (starting with MultiBit HD v0.5.0) start with a 16-byte AES initialization vector followed by the header bytes of a bitcoinj wallet file, specifically the byte string "\x0a?org.bitcoin." once decrypted (where the ? can be any byte). It tries decrypting the bytes with each password, and once the result is what's expected, it has found the correct password.

Without access to the rest of your wallet file, it is impossible the decrypted header information could ever lead to a loss of funds.

