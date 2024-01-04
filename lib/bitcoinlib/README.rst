Python Bitcoin Library
======================

Bitcoin cryptocurrency Library writen in Python.

Allows you to create a fully functional Bitcoin wallet with a single line of code.
Use this library to create and manage transactions, addresses/keys, wallets, mnemonic password phrases and blocks with
simple and straightforward Python code.

You can use this library at a high level and create and manage wallets from the command line or at a low level
and create your own custom made transactions, scripts, keys or wallets.

The BitcoinLib connects to various service providers automatically to update wallets, transaction and
blockchain information.

.. image:: https://github.com/1200wd/bitcoinlib/actions/workflows/unittests.yaml/badge.svg
    :target: https://github.com/1200wd/bitcoinlib/actions/workflows/unittests.yaml
    :alt: Unittests
.. image:: https://img.shields.io/pypi/v/bitcoinlib.svg
    :target: https://pypi.org/pypi/bitcoinlib/
    :alt: PyPi
.. image:: https://readthedocs.org/projects/bitcoinlib/badge/?version=latest
    :target: http://bitcoinlib.readthedocs.io/en/latest/?badge=latest
    :alt: RTD
.. image:: https://coveralls.io/repos/github/1200wd/bitcoinlib/badge.svg?branch=installation-documentation-update
    :target: https://coveralls.io/github/1200wd/bitcoinlib?branch=master
    :alt: Coveralls


Install
-------

Installed required packages

.. code-block:: bash

    $ sudo apt install build-essential python3-dev libgmp3-dev

Then install using pip

.. code-block:: bash

    $ pip install bitcoinlib

For more detailed installation instructions, how to install on other systems or troubleshooting please read https://bitcoinlib.readthedocs.io/en/latest/source/_static/manuals.install.html


Documentation
-------------

Read the full documentation at: http://bitcoinlib.readthedocs.io/


Example
-------

The bitcoin library contains a wallet implementation using SQLAlchemy and SQLite3 to import, create and manage
keys in a Hierarchical Deterministic way.

Example: Create wallet and generate new address (key) to receive bitcoins

.. code-block:: pycon

   >>> from bitcoinlib.wallets import Wallet
   >>> w = Wallet.create('Wallet1')
   >>> w.get_key().address
   '1Fo7STj6LdRhUuD1AiEsHpH65pXzraGJ9j'

Now send a small transaction to your wallet and use the scan() method to update transactions and UTXO's

.. code-block:: pycon

    >>> w.scan()
    >>> w.info()  # Shows wallet information, keys, transactions and UTXO's

When your wallet received a payment and has unspent transaction outputs, you can send bitcoins easily.
If successful a transaction ID is returned

.. code-block:: pycon

    >>> t = w.send_to('1PWXhWvUH3bcDWn6Fdq3xhMRPfxRXTjAi1', '0.001 BTC', offline=False)
    'b7feea5e7c79d4f6f343b5ca28fa2a1fcacfe9a2b7f44f3d2fd8d6c2d82c4078'
    >>> t.info  # Shows transaction information and send results


More examples
-------------

Checkout the documentation page https://bitcoinlib.readthedocs.io/en/latest/ or take a look at some
more examples at https://github.com/1200wd/bitcoinlib/tree/master/examples


Contact
-------

If you have any questions, encounter a problem or want to share an idea, please use Github Discussions
https://github.com/1200wd/bitcoinlib/discussions


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
- Bech32m format for v1+ witness addresses (BIP0350)
- and many more...


Future / Roadmap
----------------

- Support advanced scripts
- Fully support timelocks
- Support for lightning network
- Support for Trezor wallet or other hardware wallets
- Allow to scan full blockchain
- Integrate simple SPV client
- Support Schnorr signatures


Disclaimer
----------

This library is still in development, please use at your own risk and test sufficiently before using it in a
production environment.
