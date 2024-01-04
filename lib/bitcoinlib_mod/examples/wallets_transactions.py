# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#
#    EXAMPLES - Wallets and Transactions
#
#    © 2018 February - 1200 Web Development <http://1200wd.com/>
#

import os
from pprint import pprint
from bitcoinlib.wallets import HDWallet, BCL_DATABASE_DIR


#
# Create Wallets
#

# First recreate database to avoid already exist errors
test_databasefile = BCL_DATABASE_DIR + 'bitcoinlib.test.sqlite'
test_database = 'sqlite:///' + test_databasefile
if os.path.isfile(test_databasefile):
    os.remove(test_databasefile)

print("\n=== Create a wallet and a simple transaction ===")
wlt = HDWallet.create('wlttest1', network='bitcoinlib_test', db_uri=test_database)
wlt.get_key()
wlt.utxos_update()  # Create some test UTXOs
wlt.info()
to_key = wlt.get_key()
print("\n- Create transaction (send to own wallet)")
t = wlt.send_to(to_key.address, 50000000)
t.info()

print("\n- Successfully send, updated wallet info:")
wlt.info()


print("\n=== Create a wallet, generate 6 UTXOs and create a sweep transaction ===")
wlt = HDWallet.create('wlttest2', network='bitcoinlib_test', db_uri=test_database)
wlt.get_key(number_of_keys=3)
wlt.utxos_update()  # Create some test UTXOs
wlt.info()
to_key = wlt.get_key()
print("\n- Create transaction to sweep wallet")
t = wlt.sweep('21Cr5enTHDejL7rQfyzMHQK3i7oAN3TZWDb')
t.info()

print("\n- Successfully send, updated wallet info:")
wlt.info()
