# Recovery with an Address Database

## Background
When trying to recover BIP39/44 wallets, *seedrecover.py* and *btcrecover.py* tries different guesses based on the seed you entered, it needs a way to determine which seed guess is correct. Normally it uses each seed guess to create a master public key (an *mpk*) and compare it to the mpk you entered, or to create Bitcoin addresses and compare them to the addresses you entered. If you have neither your mpk nor any of your addresses, it's still possible to use *seedrecover.py* but it is more complicated and time consuming. **The main time cost in this process is in downloading the blockchain and generating the AddressDB, the actual checking part of the process runs at about the same speed regardless of whether it is being tested against a single address or an addressDB with 600,000 addresses in it... So if you are even a bit unsure about the addresses your wallet used, an AddressDB is very worthwhile**

This works by generating addresses, just as above, and then looking for each generated address in the entire blockchain. In order to do this, you must first create a database of addresses based on the blockchain.

There are two ways that an AddressDB can be generated, either through directly parsing raw blockchain data, or through processing a file containing a list of addresses. (This list of addresses can include any address types that BTCRecover supports, including addresses from multiple coin types)

## Pre-Made AddressDB Files
**Note: AddressDB files are not compatible between Python2 and Python3 branches of BTCRecover. Make sure you download the right one. (The master branch of this Github is all Python3 now...)**

I have created and uploaded AddressDatabases for some supported chains and will update them periodically.

**[You can download them from my website here...](https://cryptoguide.tips/btcrecover-addressdbs/)** (You can then unzip them and use the --addressdb to include the full path and filename to tell seedrecover.py or btcrecover.py where to look)

## Parameters to Manage AddressDB Size

**dblength**

This tool creates a database file where you need to specify its maximum size beforehand. This maximum number of addresses is given as a power of 2, eg: --dblength 30 makes space about for 2^30 addresses, just under a billion... Basically, if there are more addresses in the blockchain than room in the file, the program will just crash, so you may need to re-run it and increase --dblength by one. It defaults to 30, which creates an ~8GB file and is enough for the Bitcoin Blockchain in Nov 2018. (I plan to change this behavior so that by default it will start small and retry a few times as required after the Python3 move) **The thing is that the AddressDB file size depends on the max number of addresses it can accomodate, not how many are used.** What this means is that if you are generating an addressDB for a smaller blockchain like Vertcoin, you can get away with specifying a smaller dblength to save space. If you leave it as the defaults, you will end up with an 8GB file when a ~30mb file would have worked. **Though if you have plenty of HDD space, then it doesn't matter** 

A rought guide of the blockchain, AddressDB size and optimal parameters as at Jan 2021 is:

| Coin         | Blockchain Size | AddressDB Size  | Required DBLength |
| -------------|:---------------:| ---------------:|------------------:|
| Bitcoin      | 561 GB          | 16 GB            | 31                |
| Bitcoin Cash | 155 GB          | 4 GB            | 29                |
| Litecoin     | 133 GB            | 4 GB            | 29                |
| Vertcoin     | 5 GB            | 32 MB           | 22                |
| Monacoin     | 2.5 GB          | 32 MB           | 22                |
| Ethereum     | N/A (AddressList from BigQuery with ~250 million addresses)           | 4 GB             | 29
| Dogecoin      | N/A (Addresslist from BigQuery with ~60 million addresses) | 1GB | 27 |

_If in doubt, just download the full blockchain and parse it in it entritiy... The default will be fine..._

**Limiting Date Range for AddressDB Creation**

It is possible to create an address database that includes only addresses for transactions that happened between specific dates. This can be useful in that it requires less additional space for the AddressDB file and also uses significantly less ram. (Eg: You may select to only consider addresses that were used after you ordered your hardware wallet) This is done via the --blocks-startdate BLOCKS_STARTDATE and --blocks-enddate BLOCKS_ENDDATE arguments, with the date in the format of YYYY-MM-DD

**Skipping X Number of Block Files in AddressDB Creation**

It is also possible to tell the AddressDB creation script to start processing at a certain blockfile. This is helpful to speed up the processing of larger blockchains. (Eg: If you only wanted the addresses used in 2018 for Bitcoin) This is done via --first-block-file FIRST_BLOCK_FILE, with FIRST_BLOCK_FILE being the number of the block file. **This feature won't warn you if you tell it to start counting blocks AFTER the start-date if used with --blocks-startdate**

## Creating an AddressDB from Blockchain Data

You can generate an addressDB by parsing raw blockchain data from:
* Bitcoin
* Bitcoin Cash
* Litecoin
* Vertcoin
* Monacoin

It may also work with other 'bitcoin like' blockchains via attempting to foce it via the --dbyolo flag. (You will know that it is successfully parsing the blockchain if you see the number of addresses found increasing as it processes)

I have tested it and confirmed that it **doesn't** work with
* Dogecoin
* Verge
* Zcash and Zencash
* Monero
* Ethereum

For these blockchains, you will need to obtain a list of addresses (through something like Google BigQuery) and generate the addressDB from this list.

**Altcoin Blockchains**

This tool is tested to work with the blockchains specified above. By default, it will scan the default Bitcoin install directory and use that. If you have installed Bitcoin somewhere else, or you want to create an AddressDB from an alternative blockchain, you will need to manually specifiy its location with the --datadir argument.

The question of which blockchain you want to use comes down to your personal situation. That said, if you have a BIP39 wallet that you know you used to store Litecoin or Vertcoin at some point, then you may prefer to start by downloading and using one of these chains rather than downloading the full BTC blockchain. Your BIP39/44 wallet will use the same seed for all currencies, so it doesn't matter which one you use to recover your seed. 

**Examples to Reproduce**

If you want to run some tests against an AddressDB, there are for test DBs that are in the [./btcrecover/test/test-addressdbs](https://github.com/3rdIteration/btcrecover/tree/master/btcrecover/test/test-addressdbs) folder of this project. Basically they are small because they only contain 24hr hours worth of addresses from each block. (They were created with the --blocks-startdate and enddate arguments) 

You can run a test using one of these databases with the command:

   `python seedrecover.py --no-dupchecks --addr-limit 2 --bip32-path "m/44'/28'/1'/0" --big-typos 1 --addressdb ./btcrecover/test/test-addressdbs/addresses-VTC-Test.db --wallet-type bip39
`

And the seed with the number 1 instead of the first word...

   `1 entire sniff tired miracle solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby
`

You can find more examples of tests that use the small AddressDBs in the unit tests covered in [test_seeds.py](https://github.com/3rdIteration/btcrecover/blob/master/btcrecover/test/test_seeds.py) , just search for the methods starting with "test_addressdb_" and the parameters will list the addressDB limit, test phrase, derivation path and AddressDB used.

**Steps to Create an AddressDb from the Blockchain Data:**
 1. You must use a computer with enough space for the full blockchain that you want to process and RAM equal to double the AddressDB size that you will end up with (This is an extremely generous estimate, you will likely be fine with less, but pretty much need to have at least as much as the AddressDB you want to create) . You must have the 64-bit version of Python installed. (Other smaller blockchains require significantly less space and RAM)

 2. Install a full-node client for your blockchain of choice, such as [Bitcoin Core](https://bitcoincore.org/), [Bitcoin ABC](https://bitcoinabc.org), [Litecoin Core](https://litecoin.org), [Vertcoin](https://vertcoin.org/download-wallet/), [Monacoin Core](https://monacoin.org/). (A lite-client like Electrum, etc, won't work for this...)

 3. Start your full-node client and allow it to fully sync. Depending on your Internet connection and your computer, fully syncing a node can take one or more days. Starting `bitcoin-qt` (or `bitcoind`) with the `-dbcache #` option can help: the `#` is the amount of RAM, in MB, to use for the database cache. If your computer has at least 8 GB of RAM, giving up to `4000` MB to the `-dbcache` will speed things up. Installing Bitcoin on a computer with an SSD can also help.

 4. Once your full-node client is synced, close the full-node client software.

 5. (On OS X, rename the `create-address-db.py` script file to `create-address-db.command`.) Double-click on the `create-address-db.py` script (in the same folder as `seedrecover.py`) to build the address database using the fully-synced blockchain (it will be saved into the same directory as `create-address-db.py` with the name `addresses.db`) . This process will take about one hour, and use about 4 GB of both RAM and drive space.

 6. Follow the steps listed in the [Running *seedrecover.py*](Seedrecover_Quick_Start_Guide.md#running-seedrecoverpy) section, except that when you get to the address entry window in step 4, click `Cancel`.

 7. For the next step, you still need to choose an address generation limit. This should be the number of unused addresses you suspect you have at the beginning of your wallet before the first one you ever used. If you're sure you used the very first address in your wallet, you can use `1` here, but if you're not so sure, you should choose a higher estimate (although it may take longer for *seedrecover.py* to run).

Note that running with an AddressDB will use about the same amount of RAM as the size of the AddressDB file while it is running with an address database. (Eg: Full Bitcoin AddressDB will require about 8.5gb of RAM as of Nov 2019)

## Creating an AddressDB from an Address List

An alternative way to create an addressDB is to use a list of addresses. (eg: A list of all Eth addresses from something like Google BigQuery)

You simply need to specify the input list using the --inputlist parameter as well as specify the dblength that you want to use. (Otherwise it will default to 30, creating an 8gb file) You will likely also need the --multifileinputlist so that you can automatically include a list of files automatically created when you export data from bigquery to Google Cloud Storage.

If you want to combine addresses from multiple lists, or add a list of addresses to an existing blockchain generated addressDB, you can do this with the --update argument.

Adding a file with about ~10 million addresses will take about a minute... (Based on performance from BigQuery Eth data)

### Generating Address Lists from Google BigQuery

_**Note:** Data on Google BigQuery is only updated every 1-2 months, sometimes less often, so be sure to look at the "Last Modified" information for the dataset that you are using to generate an AddressDB to ensure that it will include transactions related to your wallet... (Eg: That you made at least one transaction prior to the "last modified" date)_ 

**Useful Google BigQuery Queries**

[All BTC Addresses](https://console.cloud.google.com/bigquery?sq=871259226971:05c3cbf256dd43a898f5168b94bc66cc)

[All Eth Addresses](https://console.cloud.google.com/bigquery?sq=871259226971:c6370cf863224be1942ecfdf03e0f0ca)

[All Doge Addresses](https://console.cloud.google.com/bigquery?sq=871259226971:c130730990e94212bf20b3dea5c4c815)

[All BCH Addresses](https://console.cloud.google.com/bigquery?sq=871259226971:1cb1a218b17d4498bb3d9103e5b2fb3a)

[All LTC Addresses](https://console.cloud.google.com/bigquery?sq=871259226971:13e998b9bf864df8b7c0772f4913b28d)

### Generating Address Lists from Blockchair Database Dumps
Blockchair distribute a range of different database dumps, specifically lists of addresses and balance. They can be found here: <https://blockchair.com/dumps#database>

The .tsv.gz files can be directly used to create address databases without decompressing the file via the --inputlist argument.

**Note: These lists of addresses only include addresses that currently have a balance, as opposed to the other methods here which will include all addresses which have ever had a balance. What this means is that if you use this data from blockchair, you may run in to issues with address-generation-limits. (Which are normally not a consideration when using address databases)**

### Generating Address Lists using Ethereum-ETL
Confirmed working for: 
* Binance Smart Chain with Geth Node installed as per: <https://docs.bnbchain.org/docs/validator/fullnode>

For EVM type chains (eg: Binance Smart Chain), another option is to use the Ethereum-ETL tool. This allows you to query a full node (Running Geth or Parity, or a fork of these) and retrieve human readable CSV data representing transations.

Once you have a Geth-Like node running, you can retrieve ETL data with a command like:

``
ethereumetl export_blocks_and_transactions --start-block STARTBLOCKNUMBER --end-block ENDBLOCKNUMBER --provider-uri http://FULLNODEIP:8545 --blocks-output LOCAL_BLOCKS_CSV_FILE --transactions-output LOCAL_TRANSACTIONS_CSV_FILE
``

Once you exported the transactions, you can then use the `addrListsFromETLTransactions.py` file in the `utilities` folder within this repository to produce files containing lists of addresses. These address lists can then be used to create an addressDB using the same process covered earlier.

The key thing to understand with this approach is that you will need several TB worth of disk space to store/run and several TB worth of additional space for the full Ethereum ETL output. (So you probably want about 10TB of space...)

### Checking/Validating AddressDBs
You can use the check-address-db.py file to test any addresslist file for whether it includes any given addresses.

For example, you could validate that the Dogecoin AddressDB (downloadable above) contains a few specific addresses with the command:

    python check-address-db.py --dbfilename "E:\CryptoGuide\OneDrive\AddressDBs (Mega)\addresses-DOGE.db" --checkaddresses DMQ6uuLAtNoe5y6DCpxk2Hy83nYSPDwb5T DFgLZmxFnzv2wR4GAGS3GeHvoEeSkz9ubU DKTHYZwd81xT7qJF33YRi7ftDkvouGdxxN

This will produce the following output

    Starting CheckAddressDB 1.9.0-CryptoGuide
    Loading address database ...
    Loaded 60750752 addresses from database ...
    DMQ6uuLAtNoe5y6DCpxk2Hy83nYSPDwb5T Found!
    DFgLZmxFnzv2wR4GAGS3GeHvoEeSkz9ubU Found!
    DKTHYZwd81xT7qJF33YRi7ftDkvouGdxxN Found!

**Checklist File**

The BTCRecover repository comes bundled with some basic lists of addresses that can be used to check that an addressDB contains addresses which were first seed over a specific time interval. These addresses were randomly selected off the blockchain and are spaced at approximately 6 month intervals. (So can be used to ensure that a given addressDB roughly covers the dates you need)

For example, you could validate that the Dogecoin AddressDB (downloadable above) contains addresses through to Feb 2021 with the command.
 
    python check-address-db.py --dbfilename addresses-DOGE.db --checkaddresslist ./addressdb-checklists/DOGE.txt
    
This will produce the following output

    Starting CheckAddressDB 1.9.0-CryptoGuide
    Loading address database ...
    Loaded 60750752 addresses from database ...
    Loading:  ./addressdb-checklists/DOGE.txt
    DMQ6uuLAtNoe5y6DCpxk2Hy83nYSPDwb5T Found! First Seen 2021-01-31
    DFgLZmxFnzv2wR4GAGS3GeHvoEeSkz9ubU Found! First seen 2020-06-29
    DKTHYZwd81xT7qJF33YRi7ftDkvouGdxxN Found! First seen 2019-12-30
    DPPg5BVqn7Ck5YVf6ei7NbXGVPDSzXnCBL Found! First seen 2019-05-17
    DBbTFW9PZJj9EsXu5Ji59Tp6ZdKNrTZmWq Found! First seen 2018-12-05
    DFJRDVzjk7NPbApWsLDreML7RDawp8UmoF Found! First seen 2018-05-16
    D9dWXJjYb4HDrXpdef234GHDDggrnGsfxm Found! First seen 2017-11-05
    D6A894uLhQjwSRpEroPMop4MPpUL4BZZHc Found! First seen 2017-05-19
    DGVxem7KdNBCJWygpRcypS5pMJgJVRZEXD Found! First seen 2016-12-25
    DMPHyer3WdKrSmwmFarXtXCxbbp4BMwo9J Found! First seen 2016-05-22
    DRusoAd1Q9PJq3KpkhXjpZAoCqdQzGS6AH Found! First seen 2015-12-29
    D6sxvQRSriU4pkozdYxDVRKRmoRYCVmqKv Found! First seen 2015-05-10
    DNULsd2gbojENHtRRx45PUWvPgkrbL2vjE Found! First seen 2014-12-15
    D5mrYgNeLwVXFyy9t9NhBpTqVaa58gUYAC Found! First seen 2014-04-29
    DLAznsPDLDRgsVcTFWRMYMG5uH6GddDtv8 Found! First seen 2013-12-07
