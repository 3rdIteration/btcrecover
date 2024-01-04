# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#
#    Create a multisig 2-of-3 wallet with Mnemonic passphrase keys, so wallet contains 3 keys and 2 signatures are
#    needed to sign a transaction / send a payment.
#
#    Transaction are created and signed with 1 signature on the online PC, on the other offline PC the transaction is
#    signed with a second private key. The third key is a stored on a paper in case one of the others keys is lost.
#
#    © 2017 - 2019 December - 1200 Web Development <http://1200wd.com/>
#

from __future__ import print_function

from pprint import pprint
from bitcoinlib.wallets import wallet_exists, HDWallet
from bitcoinlib.mnemonic import Mnemonic
from bitcoinlib.keys import HDKey

WALLET_NAME = "Multisig-2of3"
NETWORK = 'testnet'
KEY_STRENGTH = 128  # Remove this line to use the default 256 bit key strength
SIGNATURES_REQUIRED = 2
WITNESS_TYPE = 'segwit'  # Witness type can be legacy, p2sh-segwit or segwit

# from bitcoinlib.wallets import wallet_delete_if_exists
# wallet_delete_if_exists(WALLET_NAME, force=True)

if not wallet_exists(WALLET_NAME):
    # Define cosigners, format (name, key_type, [password], wallet)
    cosigners = [
        ('Offline PC', 'bip32', 'password'),
        ('Online PC', 'bip32', ''),
        ('Paper backup', 'single', ''),
    ]

    print("We will generate 3 private keys, to sign and send a transaction 2 keys are needed:"
          "\n- With 1 private key a wallet on this Offline PC is created"
          "\n- Use private key 2 to create a wallet on the Online PC"
          "\n- Store key 3 on a Paper in a safe in case one of the PC's is not available anymore"
          )
    key_lists = {}
    w_id = 0
    for cosigner in cosigners:
        print("\n")
        words = Mnemonic().generate(KEY_STRENGTH)
        password = ''
        if cosigner[2] == 'password':
            password = input("Please give password for cosigner '%s': " % cosigner[0])
        seed = Mnemonic().to_seed(words, password)
        hdkey = HDKey.from_seed(seed, network=NETWORK, key_type=cosigner[1], witness_type=WITNESS_TYPE)
        if cosigner[1] == 'bip32':
            public_account = hdkey.public_master_multisig(witness_type=WITNESS_TYPE)
        else:
            public_account = hdkey
        print("Key for cosigner '%s' generated. Please store both passphrase and password carefully!" % cosigner[0])
        print("Passphrase: %s" % words)
        print("Password: %s" % ('*' * len(password)))
        print("Share this public key below with other cosigner")
        print("Public key: %s" % public_account.wif_public())

        for w in cosigners:
            if cosigner[0] == w[0]:
                addkey = hdkey
            else:
                addkey = public_account.public()
            if w[0] not in key_lists:
                key_lists[w[0]] = []
            if addkey not in key_lists[w[0]]:
                key_lists[w[0]].append(addkey)

    offline_wallet = HDWallet.create(WALLET_NAME, key_lists['Offline PC'], sigs_required=SIGNATURES_REQUIRED,
                                     witness_type=WITNESS_TYPE, network=NETWORK)
    offline_wallet.new_key()

    print("\n\nA multisig wallet has been created on this system")
    offline_wallet.info()

    print("\n---> Please create a wallet on your Online PC like this:")
    print("from bitcoinlib.wallets import HDWallet")
    print("from bitcoinlib.keys import HDKey")
    print("")
    print("key_list = [")
    for key in key_lists['Online PC']:
        if key.key_type == 'single':
            print("     HDKey('%s', key_type='single', witness_type='%s')" % (key.wif_private(), WITNESS_TYPE))
        else:
            print("     '%s'," % key.wif_private())
    print("]")
    print("wlt = HDWallet.create('%s', key_list, sigs_required=2, witness_type='%s', network='%s')" %
          (WALLET_NAME, WITNESS_TYPE, NETWORK))
    print("wlt.get_key()")
    print("wlt.info()")
else:
    from bitcoinlib.config.config import BITCOINLIB_VERSION, BCL_DATABASE_DIR
    online_wallet = HDWallet(WALLET_NAME, db_uri=BCL_DATABASE_DIR + '/bitcoinlib.tmp.sqlite')
    online_wallet.utxos_update()
    online_wallet.info()
    utxos = online_wallet.utxos()
    if utxos:
        print("\nNew unspent outputs found!")
        print("Now a new transaction will be created to sweep this wallet and send bitcoins to a testnet faucet")
        send_to_address = 'n2eMqTT929pb1RDNuqEnxdaLau1rxy3efi'
        t = online_wallet.sweep(send_to_address, min_confirms=0)
        print(t.raw_hex())
        print("Now copy-and-paste the raw transaction hex to your Offline PC and sign it there with a second signature:")
        print("\nfrom bitcoinlib.wallets import HDWallet")
        print("")
        print("wlt = HDWallet('%s')" % WALLET_NAME)
        print("utxos = ", end='')
        pprint(utxos)
        print("")
        print("wlt.utxos_update(utxos=utxos)")
        print("t = wlt.transaction_import_raw('%s')" % t.raw_hex())
        print("t.sign()")
        print("")
        print("# Push the following raw transaction to the blockchain network on any online PC:")
        print("print(t.raw_hex())")
    else:
        print("\nPlease send funds to %s, so we can create a transaction" % online_wallet.get_key().address)
        print("\nRestart this program when funds are send...")
