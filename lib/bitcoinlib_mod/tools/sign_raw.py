# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#
#    Import and sign multisig transaction with private key wif or passphrase
#
#    © 2019 December - 1200 Web Development <http://1200wd.com/>
#

from pprint import pprint
from bitcoinlib.transactions import Transaction
from bitcoinlib.mnemonic import Mnemonic
from bitcoinlib.keys import HDKey
from bitcoinlib.services.services import Service
from bitcoinlib.wallets import wallet_create_or_open, wallet_delete_if_exists

network = 'testnet'
# # Example wallet
# phrase1 = 'meadow bag inquiry eyebrow exotic onion skill clerk dish hunt caught road'
# phrase2 = 'east amount soap pause erosion invite mom finger oak still vast bacon'
# password2 = 'test'
# k2 = HDKey.from_passphrase(phrase2, network=network, password=password2, key_type='single').public()
# # wallet_delete_if_exists('Sign_raw_testwallet', force=True)
# w = wallet_create_or_open('Sign_raw_testwallet', [phrase1, k2], network=network, cosigner_id=0)
# w.get_key()
# w.utxos_update()
# w.info()
# t = w.sweep(w.new_key().address, 10000, fee=1000)
# raw_tx = t.raw_hex()
# t.info()

# Raw partially signed transaction transaction
raw_tx = ''
if not raw_tx:
    raw_tx = input("Paste raw transaction hex: ")

t = Transaction.import_raw(raw_tx)

key_str = input("Enter private key or passphrase: ")
if len(key_str.split(" ")) < 2:
    hdkey = HDKey(key_str)
else:
    password = input("Enter password []:")
    seed = Mnemonic().to_seed(key_str, password)
    hdkey = HDKey.from_seed(seed, network=network)

t.sign(hdkey)
t.info()

print("Raw signed transaction: ")
print(t.raw_hex())

if input("Try to send transaction [y/n] ") in ['y', 'Y']:
    srv = Service(network=network)
    res = srv.sendrawtransaction(t.raw())
    pprint(res)
