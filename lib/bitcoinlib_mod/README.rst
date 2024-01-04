Python Bitcoin Library
======================

Bitcoin, Litecoin and Dash Crypto Currency Library for Python.

Includes a fully functional wallet, with multi signature, multi currency and multiple accounts.
You this library at a high level and create and manage wallets for the command line or at a low level
and create your own custom made transactions, keys or wallets.

The BitcoinLib connects to various service providers automatically to update wallets, transactions and
blockchain information. It does currently not parse the blockchain itself.


.. image:: https://travis-ci.org/1200wd/bitcoinlib.svg?branch=master
    :target: https://travis-ci.org/1200wd/bitcoinlib
    :alt: Travis
.. image:: https://img.shields.io/pypi/v/bitcoinlib.svg
    :target: https://pypi.org/pypi/bitcoinlib/
    :alt: PyPi
.. image:: https://readthedocs.org/projects/bitcoinlib/badge/?version=latest
    :target: http://bitcoinlib.readthedocs.io/en/latest/?badge=latest
    :alt: RTD
.. image:: https://coveralls.io/repos/github/1200wd/bitcoinlib/badge.svg?branch=installation-documentation-update
    :target: https://coveralls.io/github/1200wd/bitcoinlib?branch=master
    :alt: Coveralls


Documentation
-------------

Read the full documentation at: http://bitcoinlib.readthedocs.io/


Disclaimer
----------

This library is still in development, please use at your own risk and test sufficiently before using it in a
production environment.


Some Examples
=============

Wallet
------

The bitcoin library contains a wallet implementation using SQLAlchemy and SQLite3 to import, create and manage
keys in a Hierarchical Deterministic way.

Example: Create wallet and generate new address (key) to receive bitcoins

.. code-block:: pycon

   >>> from bitcoinlib.wallets import HDWallet
   >>> w = HDWallet.create('Wallet1')
   >>> key1 = w.get_key()
   >>> key1.address
   '1Fo7STj6LdRhUuD1AiEsHpH65pXzraGJ9j'

Now send a small transaction to your wallet and use the scan() method to update transactions and UTXO's

.. code-block:: pycon

    >>> w.scan()
    >>> w.info()  # Shows wallet information, keys, transactions and UTXO's

When your wallet received a payment and has unspent transaction outputs, you can send bitcoins easily.
If successful a transaction ID is returned

.. code-block:: pycon

    >>> t = w.send_to('12ooWd8Xag7hsgP9PBPnmyGe36VeUrpMSH', 100000)
    'b7feea5e7c79d4f6f343b5ca28fa2a1fcacfe9a2b7f44f3d2fd8d6c2d82c4078'
    >>> t.info  # Shows transaction information and send results


Wallet from passphrase with accounts and multiple currencies
------------------------------------------------------------

The following code creates a wallet with two bitcoin and one litecoin account from a Mnemonic passphrase.
The complete wallet can be recovered from the passphrase which is the masterkey.

.. code-block:: python

    from bitcoinlib.wallets import HDWallet, wallet_delete
    from bitcoinlib.mnemonic import Mnemonic

    passphrase = Mnemonic().generate()
    print(passphrase)
    w = HDWallet.create("Wallet2", keys=passphrase, network='bitcoin')
    account_btc2 = w.new_account('Account BTC 2')
    account_ltc1 = w.new_account('Account LTC', network='litecoin')
    w.get_key()
    w.get_key(account_btc2.account_id)
    w.get_key(account_ltc1.account_id)
    w.info()


Multi Signature Wallets
-----------------------

Create a Multisig wallet with 2 cosigner which both need to sign a transaction.

.. code-block:: python

    from bitcoinlib.wallets import HDWallet
    from bitcoinlib.keys import HDKey

    NETWORK = 'testnet'
    k1 = HDKey('tprv8ZgxMBicQKsPd1Q44tfDiZC98iYouKRC2CzjT3HGt1yYw2zuX2awTotzGAZQEAU9bi2M5MCj8iedP9MREPjUgpDEBwBgGi2C8eK'
                '5zNYeiX8', network=NETWORK)
    k2 = HDKey('tprv8ZgxMBicQKsPeUbMS6kswJc11zgVEXUnUZuGo3bF6bBrAg1ieFfUdPc9UHqbD5HcXizThrcKike1c4z6xHrz6MWGwy8L6YKVbgJ'
                'MeQHdWDp', network=NETWORK)
    w1 = HDWallet.create('multisig_2of2_cosigner1', sigs_required=2,
                         keys=[k1, k2.public_master(multisig=True)], network=NETWORK)
    w2 = HDWallet.create('multisig_2of2_cosigner2',  sigs_required=2,
                         keys=[k1.public_master(multisig=True), k2], network=NETWORK)
    print("Deposit testnet bitcoin to this address to create transaction: ", w1.get_key().address)

Create a transaction in the first wallet

.. code-block:: python

    w1.utxos_update()
    t = w1.sweep('mwCwTceJvYV27KXBc3NJZys6CjsgsoeHmf', min_confirms=0)
    t.info()

And then import the transaction in the second wallet, sign it and push it to the network

.. code-block:: python

    w2.get_key()
    t2 = w2.transaction_import(t)
    t2.sign()
    t2.send()
    t2.info()


Segregated Witness Wallet
-------------------------

Easily create and manage segwit wallets. Both native segwit with base32/bech32 addresses and P2SH nested segwit
wallets with traditional addresses are available.

Create a native single key P2WPKH wallet:

.. code-block:: pycon

    >>> from bitcoinlib.wallets import HDWallet
    >>> w = HDWallet.create('wallet_segwit_p2wpkh', witness_type='segwit')
    >>> w.get_key().address
    bc1q84y2quplejutvu0h4gw9hy59fppu3thg0u2xz3

Or create a P2SH nested single key P2SH_P2WPKH wallet:

.. code-block:: pycon

    >>> from bitcoinlib.wallets import HDWallet
    >>> w = HDWallet.create('wallet_segwit_p2sh_p2wpkh', witness_type='p2sh-segwit')
    >>> w.get_key().address
    36ESSWgR4WxXJSc4ysDSJvecyY6FJkhUbp


Command Line Tool
-----------------

With the command line tool you can create and manage wallet without any Python programming.

To create a new Bitcoin wallet

.. code-block:: bash

    $ clw NewWallet
    Command Line Wallet for BitcoinLib

    Wallet newwallet does not exist, create new wallet [yN]? y

    CREATE wallet 'newwallet' (bitcoin network)

    Your mnemonic private key sentence is: force humble chair kiss season ready elbow cool awake divorce famous tunnel

    Please write down on paper and backup. With this key you can restore your wallet and all keys


You can use clw to create simple or multisig wallets for various networks, manage public and private keys
and managing transactions.

For the full command line wallet documentation please read

http://bitcoinlib.readthedocs.io/en/latest/_static/manuals.command-line-wallet.html


Mnemonic key generation
-----------------------

Allows you to use easy to remember passphrases consisting of a number of words to store private keys (BIP0039).
You can password protect this passphrase (BIP0038), and use the HD Wallet structure to generate a almost infinite 
number of new private keys and bitcoin addresses (BIP0043 and BIP0044).

Example: Generate a list of words passphrase and derive a private key seed

.. code-block:: pycon

   >>> from bitcoinlib.mnemonic import Mnemonic
   >>> from bitcoinlib.encoding import to_hexstring
   >>> words = Mnemonic().generate()
   >>> words
   unique aisle iron extend earn cigar trust source next depart yard bind
   >>> to_hexstring(Mnemonic().to_seed(words))
   '9c6f41a347bf4f326f9c989fb522bec1b82c36463580d1769daadba7d59f69a305505fdd5d2131c9c60255c79279d4e8896155e0b126abea036da56a766f81a1'


Service providers
-----------------
Communicates with pools of bitcoin service providers to retreive transaction, address, blockchain information. 
Can be used to push a transaction to the network, determine optimal service fee for a transaction or to update your
wallet's balance.

When working with wallets connections to service providers are automatically managed so you don't have to worry
about them. You can however easily use the Service object directly.

Example: Get estimated transaction fee in sathosis per Kb for confirmation within 5 blocks

.. code-block:: pycon

   >>> from bitcoinlib.services.services import Service
   >>> Service().estimatefee(5)
   138964


Other Databases
---------------

Bitcoinlib uses the SQLite database by default but other databases are supported as well.
See http://bitcoinlib.readthedocs.io/en/latest/_static/manuals.databases.html for instructions on how to use
MySQL or PostgreSQL.


More examples
-------------
For more examples see https://github.com/1200wd/bitcoinlib/tree/master/examples


Implements the following Bitcoin Improvement Proposals
------------------------------------------------------
- Hierarchical Deterministic Wallets (BIP0032)
- Passphrase-protected private key (BIP0038)
- Mnemonic code for generating deterministic keys (BIP0039)
- Purpose Field for Deterministic Wallets (BIP0043)
- Multi-Account Hierarchy for Deterministic Wallets (BIP0044)
- Structure for Deterministic P2SH Multisignature Wallets (BIP0045)
- Bech32/base32 address format for native v0-16 witness outputs (BIP0173)
- Native and P2SH nested Segregated Witness transactions (BIP0141 and BIP0143)


Installing and updating
=======================

Pre-requirements Linux
----------------------

``sudo apt install build-essential python-dev python3-dev libgmp3-dev``

To install OpenSSL development package on Debian, Ubuntu or their derivatives

``sudo apt install libssl-dev``

To install OpenSSL development package on Fedora, CentOS or RHEL

``sudo yum install gcc openssl-devel``


Pre-requirements Windows
------------------------

This library requires a Microsoft Visual C++ Compiler. See
http://bitcoinlib.readthedocs.io/en/latest/_static/manuals.install.html

The fastecdsa library is not enabled at this moment on windows, the slower ecdsa library is installed.


Install with pip
----------------

``pip install bitcoinlib``

These packages will be installed
* fastecdsa (or ecdsa on Windows)
* pyaes
* scrypt
* sqlalchemy
* requests
* enum34 (for older Python installations)
* pathlib2 (for Python 2)
* six


Install development environment
-------------------------------

Required packages:

``sudo apt install -y postgresql postgresql-contrib mysql-server libpq-dev libmysqlclient-dev``

Create a virtual environment for instance on linux with virtualenv:

.. code-block:: bash

    $ virtualenv -p python3 venv/bitcoinlib
    $ source venv/bitcoinlib/bin/activate

Then clone the repository and install dependencies:

.. code-block:: bash

    $ git clone https://github.com/1200wd/bitcoinlib.git
    $ cd bitcoinlib
    $ pip install -r requirements-dev.txt


Troubleshooting
---------------

When you experience issues with the scrypt package when installing you can try to solve this by removing and reinstall
scrypt:

.. code-block:: bash

    $ pip uninstall scrypt
    $ pip install scrypt

Please make sure you also have the Python development and SSL development packages installed, see 'Other requirements'
above.

You can also use pyscrypt instead of scrypt. Pyscrypt is a pure Python scrypt password-based key derivation library.
It works but it is slow when using BIP38 password protected keys.

.. code-block:: bash

    $ pip install pyscrypt

If you run into issues to not hesitate to contact us or file an issue at https://github.com/1200wd/bitcoinlib/issues


Update library
--------------

Update to the latest version of the library with

.. code-block:: bash

    $ pip install bitcoinlib --upgrade

To upgrade make sure everything is backuped and run updatedb.py from the installation directory.

.. code-block:: bash

    $ python updatedb.py -d [<link-to-database-if-not-standard>]


For more information on installing, updating and maintenance see
https://bitcoinlib.readthedocs.io/en/latest/_static/manuals.install.html#installation


Future / Roadmap
================

* Create Script class and support advanced scripts
* Fully support timelocks
* Support for Trezor wallet
* Improve speed and security
* Integrate in ERP and shopping solutions such as Odoo, Magento, Shopware
* Support for lightning network
