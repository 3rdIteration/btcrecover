# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#
#    Multisig 3-of-5 wallet with Mnemonic passphrase keys
#
#    © 2017 November - 1200 Web Development <http://1200wd.com/>
#

from bitcoinlib.mnemonic import Mnemonic
from bitcoinlib.keys import HDKey

NETWORK = 'testnet'
KEY_STRENGHT = 128

words = Mnemonic().generate(KEY_STRENGHT)
print("A Mnemonic passphrase has been generated. Please write down and store carefully: \n%s" % words)
password = input("\nEnter a password if you would like to protect passphrase []: ")

seed = Mnemonic().to_seed(words, password)
hdkey = HDKey.from_seed(seed, network=NETWORK)
public_account_wif = hdkey.public_master_multisig()
print("\nPrivate key: \n%s" % hdkey.wif_private())
# print("Public key: \n%s" % hdkey.wif_public())
print("Public account key to share with other cosigners for a multisig BIP45 wallet: \n%s" % public_account_wif.wif())
