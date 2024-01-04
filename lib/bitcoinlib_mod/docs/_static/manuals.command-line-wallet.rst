Command Line Wallet
===================

Manage wallets from commandline. Allows you to

* Show wallets and wallet info
* Create single and multi signature wallets
* Delete wallets
* Generate receive addresses
* Create transactions
* Import and export transactions
* Sign transactions with available private keys
* Broadcast transaction to the network

The Command Line wallet Script can be found in the tools directory. If you call the script without
arguments it will show all available wallets.

Specify a wallet name or wallet ID to show more information about a wallet. If you specify a wallet
which doesn't exists the script will ask you if you want to create a new wallet.


Create wallet
-------------

To create a wallet just specify an unused wallet name:

.. code-block:: none

    $ clw mywallet
    Command Line Wallet for BitcoinLib

    Wallet mywallet does not exist, create new wallet [yN]? y

    CREATE wallet 'mywallet' (bitcoin network)

    Your mnemonic private key sentence is: mutual run dynamic armed brown meadow height elbow citizen put industry work

    Please write down on paper and backup. With this key you can restore your wallet and all keys

    Type 'yes' if you understood and wrote down your key: yes
    Updating wallet


Generate / show receive addresses
---------------------------------

To show an unused address to receive funds use the -r or --receive option. If you want to show QR
codes on the commandline install the pyqrcode module.

.. code-block:: none

    $ clw mywallet -r
    Command Line Wallet for BitcoinLib

    Receive address is 1JMKBiiDMdjTx6rfqGumALvcRMX6DQNeG1


Send funds / create transaction
-------------------------------

To send funds use the -t option followed by the address and amount. You can also repeat this to
send to multiple addresses.

A manual fee can be entered with the -f / --fee option.

The default behavior is to just show the transaction info and raw transaction. You can push this
to the network with a 3rd party. Use the -p / --push option to push the transaction to the
network.

.. code-block:: none

    $ clw -d dbtest mywallet -t 1FpBBJ2E9w9nqxHUAtQME8X4wGeAKBsKwZ 10000


Restore wallet with passphrase
------------------------------

To restore or create a wallet with a passphrase use new wallet name and the --passphrase option.
If it's an old wallet you can recreate and scan it with the -s option. This will create new
addresses and update unspend outputs.

.. code-block:: none

    $ clw mywallet --passphrase "mutual run dynamic armed brown meadow height elbow citizen put industry work"
    $ clw mywallet -s


Options Overview
----------------

Command Line Wallet for BitcoinLib

.. code-block:: none

    usage: clw.py [-h] [--wallet-remove] [--list-wallets] [--wallet-info]
                       [--update-utxos] [--update-transactions]
                       [--wallet-recreate] [--receive [NUMBER_OF_ADDRESSES]]
                       [--generate-key] [--export-private]
                       [--passphrase [PASSPHRASE [PASSPHRASE ...]]]
                       [--passphrase-strength PASSPHRASE_STRENGTH]
                       [--network NETWORK] [--database DATABASE]
                       [--create-from-key KEY]
                       [--create-multisig [NUMBER_OF_SIGNATURES_REQUIRED [KEYS ...]]]
                       [--create-transaction [ADDRESS_1 [AMOUNT_1 ...]]]
                       [--sweep ADDRESS] [--fee FEE] [--fee-per-kb FEE_PER_KB]
                       [--push] [--import-tx TRANSACTION]
                       [--import-tx-file FILENAME_TRANSACTION]
                       [wallet_name]

    BitcoinLib CLI

    positional arguments:
      wallet_name           Name of wallet to create or open. Used to store your
                            all your wallet keys and will be printed on each paper
                            wallet

    optional arguments:
      -h, --help            show this help message and exit

    Wallet Actions:
      --wallet-remove       Name or ID of wallet to remove, all keys and
                            transactions will be deleted
      --list-wallets, -l    List all known wallets in BitcoinLib database
      --wallet-info, -w     Show wallet information
      --update-utxos, -x    Update unspent transaction outputs (UTXO's) for this
                            wallet
      --update-transactions, -u
                            Update all transactions and UTXO's for this wallet
      --wallet-recreate, -z
                            Delete all keys and transactions and recreate wallet,
                            except for the masterkey(s). Use when updating fails
                            or other errors occur. Please backup your database and
                            masterkeys first.
      --receive [NUMBER_OF_ADDRESSES], -r [NUMBER_OF_ADDRESSES]
                            Show unused address to receive funds. Generate new
                            payment andchange addresses if no unused addresses are
                            available.
      --generate-key, -k    Generate a new masterkey, and show passphrase, WIF and
                            public account key. Use to create multisig wallet
      --export-private, -e  Export private key for this wallet and exit

    Wallet Setup:
      --passphrase [PASSPHRASE [PASSPHRASE ...]]
                            Passphrase to recover or create a wallet. Usually 12
                            or 24 words
      --passphrase-strength PASSPHRASE_STRENGTH
                            Number of bits for passphrase key. Default is 128,
                            lower is not adviced but can be used for testing. Set
                            to 256 bits for more future proof passphrases
      --network NETWORK, -n NETWORK
                            Specify 'bitcoin', 'litecoin', 'testnet' or other
                            supported network
      --database DATABASE, -d DATABASE
                            Name of specific database file to use
      --create-from-key KEY, -c KEY
                            Create a new wallet from specified key
      --create-multisig [NUMBER_OF_SIGNATURES_REQUIRED [KEYS ...]], -m [NUMBER_OF_SIGNATURES_REQUIRED [KEYS ...]]
                            Specificy number of signatures required followed by a
                            list of signatures. Example: -m 2 tprv8ZgxMBicQKsPd1Q4
                            4tfDiZC98iYouKRC2CzjT3HGt1yYw2zuX2awTotzGAZQEAU9bi2M5M
                            Cj8iedP9MREPjUgpDEBwBgGi2C8eK5zNYeiX8 tprv8ZgxMBicQKsP
                            eUbMS6kswJc11zgVEXUnUZuGo3bF6bBrAg1ieFfUdPc9UHqbD5HcXi
                            zThrcKike1c4z6xHrz6MWGwy8L6YKVbgJMeQHdWDp

    Transactions:
      --create-transaction [ADDRESS_1 [AMOUNT_1 ...]], -t [ADDRESS_1 [AMOUNT_1 ...]]
                            Create transaction. Specify address followed by
                            amount. Repeat for multiple outputs
      --sweep ADDRESS       Sweep wallet, transfer all funds to specified address
      --fee FEE, -f FEE     Transaction fee
      --fee-per-kb FEE_PER_KB
                            Transaction fee in sathosis (or smallest denominator)
                            per kilobyte
      --push, -p            Push created transaction to the network
      --import-tx TRANSACTION, -i TRANSACTION
                            Import raw transaction hash or transaction dictionary
                            in wallet and sign it with available key(s)
      --import-tx-file FILENAME_TRANSACTION, -a FILENAME_TRANSACTION
                            Import transaction dictionary or raw transaction
                            string from specified filename and sign it with
                            available key(s)
