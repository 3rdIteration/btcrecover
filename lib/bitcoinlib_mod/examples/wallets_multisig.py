# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#
#    EXAMPLES - Creating and using Multisignature Wallets
#
#    © 2017 September - 1200 Web Development <http://1200wd.com/>
#

import os
from pprint import pprint
from bitcoinlib.wallets import *

test_databasefile = BCL_DATABASE_DIR + 'bitcoinlib.test.sqlite'
test_database = 'sqlite:///' + test_databasefile
if os.path.isfile(test_databasefile):
    os.remove(test_databasefile)

#
# Create a multi-signature wallet using Bitcoinlib testnet and then create a transaction
#

# Create 3 wallets with one private keys each, and 2 public keys corresponding with other wallets
NETWORK = 'bitcoinlib_test'
pk1 = HDKey(network=NETWORK)
pk2 = HDKey(network=NETWORK)
pk3 = HDKey(network=NETWORK)
klist = [pk1, pk2.public_master_multisig(), pk3.public_master_multisig()]
wl1 = HDWallet.create('multisig_2of3_cosigner1', sigs_required=2, keys=klist,
                      network=NETWORK, db_uri=test_database)
klist = [pk1.public_master_multisig(), pk2, pk3.public_master_multisig()]
wl2 = HDWallet.create('multisig_2of3_cosigner2',  sigs_required=2, keys=klist,
                      network=NETWORK, db_uri=test_database)
klist = [pk1.public_master_multisig(), pk2.public_master_multisig(), pk3]
wl3 = HDWallet.create('multisig_2of3_cosigner3', sigs_required=2, keys=klist,
                      network=NETWORK, db_uri=test_database)

# Generate a new key in each wallet, all these keys should be the same
nk1 = wl1.new_key(cosigner_id=1)
nk2 = wl2.new_key(cosigner_id=1)
nk3 = wl3.new_key(cosigner_id=1)
assert nk1.wif == nk2.wif == nk3.wif
print("Created new multisig address: ", nk1.wif)

# Create a transaction
fee = 29348
wl1.utxos_update()  # On bitcoinlib testnet, this automatically creates an UTXO
utxo = wl1.utxos()[0]
output_arr = [('23Gd1mfrqgaYiPGkMm5n5UDRkCxruDAA8wo', utxo['value'] - fee)]
input_arr = [(utxo['tx_hash'], utxo['output_n'], utxo['key_id'], utxo['value'])]
t = wl1.transaction_create(output_arr, input_arr, fee=fee)

# Now sign transaction with first wallet, should not verify yet
t.sign()
pprint(t.as_dict())
print("Verified (False): ", t.verify())

# Import transaction (with first signature) in 3rd wallet and sign with wallet's private key
wl3.utxos_update()
t2 = wl3.transaction_import(t)
t2.sign()
print("Verified (True): ", t2.verify())


#
# Create Multisig 2-of-2 testnet wallet, and sweep all UTXO's
#

# Create 2 cosigner multisig wallets
NETWORK = 'testnet'
pk1 = HDKey('tprv8ZgxMBicQKsPd1Q44tfDiZC98iYouKRC2CzjT3HGt1yYw2zuX2awTotzGAZQEAU9bi2M5MCj8iedP9MREPjUgpDEBwBgGi2C8eK'
            '5zNYeiX8', network=NETWORK)
pk2 = HDKey('tprv8ZgxMBicQKsPeUbMS6kswJc11zgVEXUnUZuGo3bF6bBrAg1ieFfUdPc9UHqbD5HcXizThrcKike1c4z6xHrz6MWGwy8L6YKVbgJ'
            'MeQHdWDp', network=NETWORK)
wl1 = HDWallet.create('multisig_2of2_cosigner1', sigs_required=2,
                      keys=[pk1, pk2.public_master_multisig()],
                      network=NETWORK, db_uri=test_database)
wl2 = HDWallet.create('multisig_2of2_cosigner2', sigs_required=2,
                      keys=[pk1.public_master_multisig(), pk2],
                      network=NETWORK, db_uri=test_database)
nk1 = wl1.new_key()
nk2 = wl2.new_key(cosigner_id=0)

# Create a transaction
wl1.utxos_update()
utxos = wl1.utxos()
if not utxos:
    print("Deposit testnet bitcoin to this address to create transaction: ", nk1.address)
else:
    print("Utxo found, sweep address to testnet faucet address")
    res = wl1.sweep('mwCwTceJvYV27KXBc3NJZys6CjsgsoeHmf', min_confirms=0)
    assert res.hash
    wl2.utxos_update()
    t2 = wl2.transaction_import(res)
    t2.sign()
    print("Verified (True): ", t2.verify())
    print("Push transaction result: ", t2.send())


#
# Multisig wallet using single keys for cosigner wallet instead of BIP32 type key structures
#

NETWORK = 'bitcoinlib_test'
pk1 = HDKey('YXscyqNJ5YK411nwB33KeVkhSVjwwUkSG9xG3hkaoQFEbTwNJSrNTfni3aSSYiKtPeUPrFLwDsqHwZjNXhYm2DLEkQoaoikHoK2emrHv'
            'mqSEZrKP', network=NETWORK)
pk2 = HDKey('YXscyqNJ5YK411nwB3kXiApMaJySYss8sMM9FYgXMtmQKmDTF9yiu7yBNKnVjE8WdVVvuhxLqS6kHvW2MPHKmYzbzEHQsDXXAZuu1rCs'
            'Hcp7rrJx', network=NETWORK, key_type='single')
wl1 = HDWallet.create('multisig_single_keys1', [pk1, pk2.public()],
                      sigs_required=2, network=NETWORK, db_uri=test_database)
wl2 = HDWallet.create('multisig_single_keys2', [pk1.public_master_multisig(), pk2],
                      sigs_required=2, network=NETWORK, db_uri=test_database)

# Create multisig keys and update UTXO's
wl1.new_key(cosigner_id=0)
wl2.new_key(cosigner_id=0)
wl1.utxos_update()
wl2.utxos_update()

# Create transaction and sign with both wallets, return address should be the same
t = wl2.transaction_create([('23Gd1mfrqgaYiPGkMm5n5UDRkCxruDAA8wo', 5000000)])
t.sign()
t2 = wl1.transaction_import(t)
t2.sign()
print("%s == %s: %s" % (t.outputs[1].address, t2.outputs[1].address, t.outputs[1].address == t2.outputs[1].address))
print("Verified (True): ", t2.verify())


#
# Example of a multisig 2-of-3 segwit wallet
#

NETWORK = 'bitcoin'
pk1 = HDKey(network=NETWORK, witness_type='segwit')                     # Private key for this wallet
pk2 = HDKey(network=NETWORK, witness_type='segwit')                     # Wallet of cosigner
pk3 = HDKey(network=NETWORK, witness_type='segwit', key_type='single')  # Backup key on paper

w = HDWallet.create('Segwit-multisig-2-of-3-wallet', [pk1, pk2.public_master_multisig(), pk3.public()],
                    sigs_required=2, network=NETWORK, db_uri=test_database)

w.info()
