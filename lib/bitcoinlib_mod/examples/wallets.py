# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#
#    EXAMPLES - Creating and Using Cryptocurrency Wallets
#
#    © 2018 February - 1200 Web Development <http://1200wd.com/>
#

import os
from bitcoinlib.wallets import *
from bitcoinlib.mnemonic import Mnemonic


#
# Create Wallets
#

# First recreate database to avoid already exist errors
test_databasefile = BCL_DATABASE_DIR + 'bitcoinlib.test.sqlite'
test_database = 'sqlite:///' + test_databasefile
if os.path.isfile(test_databasefile):
    os.remove(test_databasefile)

print("\n=== Most simple way to create Bitcoin Wallet ===")
w = HDWallet.create('MyWallet', db_uri=test_database)
w.new_key()
w.info()

print("\n=== Create new Testnet Wallet and generate a some new keys ===")
with HDWallet.create(name='Personal', network='testnet', db_uri=test_database) as wallet:
    wallet.info(detail=3)
    wallet.new_account()
    new_key1 = wallet.new_key()
    new_key2 = wallet.new_key()
    new_key3 = wallet.new_key()
    new_key4 = wallet.new_key(change=1)
    new_key5 = wallet.key_for_path("m/44'/1'/100'/1200/1200")
    new_key6a = wallet.key_for_path("m/44'/1'/100'/1200/1201")
    new_key6b = wallet.key_for_path("m/44'/1'/100'/1200/1201")
    wallet.info(detail=3)
    donations_account = wallet.new_account()
    new_key8 = wallet.new_key(account_id=donations_account.account_id)
    wallet.info(detail=3)

print("\n=== Create new Wallet with Testnet master key and account ID 99 ===")
testnet_wallet = HDWallet.create(
    name='TestNetWallet',
    keys='tprv8ZgxMBicQKsPeWn8NtYVK5Hagad84UEPEs85EciCzf8xYWocuJovxsoNoxZAgfSrCp2xa6DdhDrzYVE8UXF75r2dKePyA'
         '7irEvBoe4aAn52',
    network='testnet',
    account_id=99,
    db_uri=test_database)
nk = testnet_wallet.new_key(account_id=99, name="Address #1")
nk2 = testnet_wallet.new_key(account_id=99, name="Address #2")
nkc = testnet_wallet.new_key_change(account_id=99, name="Change #1")
nkc2 = testnet_wallet.new_key_change(account_id=99, name="Change #2")
testnet_wallet.utxos_update()
testnet_wallet.info(detail=3)


#
# Using wallets
#

print("\n=== Three ways of getting the a HDWalletKey, with ID, address and name: ===")
print(testnet_wallet.key('n3UKaXBRDhTVpkvgRH7eARZFsYE989bHjw'))
print(testnet_wallet.key('TestNetWallet'))
print(testnet_wallet.key(testnet_wallet.key('TestNetWallet').key_id))

print("\n=== Import Account Bitcoin Testnet key with depth 3 ===")
accountkey = 'tprv8h4wEmfC2aSckSCYa68t8MhL7F8p9xAy322B5d6ipzY5ZWGGwksJMoajMCqd73cP4EVRygPQubgJPu9duBzPn3QV' \
             '8Y7KbKUnaMzxnnnsSvh'
wallet_import2 = HDWallet.create(
    db_uri=test_database,
    name='Account Import',
    keys=accountkey,
    network='testnet',
    account_id=99)
wallet_import2.info(detail=3)
del wallet_import2

print("\n=== Create simple wallet and import some unrelated private keys ===")
simple_wallet = HDWallet.create(
    name='Simple Wallet',
    keys='L5fbTtqEKPK6zeuCBivnQ8FALMEq6ZApD7wkHZoMUsBWcktBev73',
    db_uri=test_database)
simple_wallet.import_key('KxVjTaa4fd6gaga3YDDRDG56tn1UXdMF9fAMxehUH83PTjqk4xCs')
simple_wallet.import_key('L3RyKcjp8kzdJ6rhGhTC5bXWEYnC2eL3b1vrZoduXMht6m9MQeHy')
simple_wallet.utxos_update()
simple_wallet.info(detail=3)
del simple_wallet

print("\n=== Create wallet with public key to generate addresses without private key ===")
pubkey = 'tpubDDkyPBhSAx8DFYxx5aLjvKH6B6Eq2eDK1YN76x1WeijE8eVUswpibGbv8zJjD6yLDHzVcqWzSp2fWVFhEW9XnBssFqM' \
         'wt9SrsVeBeqfBbR3'
pubwal = HDWallet.create(
    db_uri=test_database,
    name='Import Public Key Wallet',
    keys=pubkey,
    network='testnet')
newkey = pubwal.new_key()
pubwal.info(detail=3)
del pubwal

print("\n=== Create Litecoin wallet ===")
litecoin_wallet = HDWallet.create(
    db_uri=test_database,
    name='Litecoin Wallet',
    network='litecoin')
litecoin_wallet.new_key()
litecoin_wallet.info(detail=3)
del litecoin_wallet

print("\n=== Create Dash wallet ===")
dash_wallet = HDWallet.create(
    db_uri=test_database,
    name='Dash Wallet',
    network='dash')
dash_wallet.new_key()
dash_wallet.info(detail=3)
del dash_wallet

print("\n=== Create Litecoin testnet Wallet from Mnemonic Passphrase ===")
words = 'blind frequent camera goddess pottery repair skull year mistake wrist lonely mix'
# Or use generate method:
#   words = Mnemonic('english').generate()
print("Generated Passphrase: %s" % words)
seed = Mnemonic().to_seed(words)
hdkey = HDKey.from_seed(seed, network='litecoin_testnet')
wallet = HDWallet.create(name='Mnemonic Wallet', network='litecoin_testnet',
                         keys=hdkey.wif(), db_uri=test_database)
wallet.new_key("Input", 0)
wallet.utxos_update()
wallet.info(detail=3)

print("\n=== Test import Litecoin key in Bitcoin wallet (should give error) ===")
w = HDWallet.create(
    name='Wallet Error',
    db_uri=test_database)
try:
    w.import_key(key='T43gB4F6k1Ly3YWbMuddq13xLb56hevUDP3RthKArr7FPHjQiXpp', network='litecoin')
except WalletError as e:
    print("Import litecoin key in bitcoin wallet gives an EXPECTED error: %s" % e)

print("\n=== Normalize BIP32 key path ===")
key_path = "m/44h/1'/0p/2000/1"
print("Raw: %s, Normalized: %s" % (key_path, normalize_path(key_path)))

print("\n=== Send test bitcoins to an address ===")
wallet_import = HDWallet('TestNetWallet', db_uri=test_database)
for _ in range(10):
    wallet_import.new_key()
wallet_import.utxos_update(99)
wallet_import.info()
utxos = wallet_import.utxos(99)
try:
    res = wallet_import.send_to('mxdLD8SAGS9fe2EeCXALDHcdTTbppMHp8N', 1000, 99)
    print("Send transaction result:")
    if res.hash:
        print("Successfully send, tx id:", res.hash)
    else:
        print("TX not send, result:", res.errors)
except WalletError as e:
    print("TX not send, error: %s" % e.msg)
except Exception as e:
    print(e)

#
# Segwit wallets
#
print("\n=== Create a Segwit Bitcoin and Litecoin Wallet ===")
w = HDWallet.create('SW-Wallet', witness_type='segwit', db_uri=test_database)
w.new_key()
w.new_key(network='litecoin')
w.info()

print("\n=== Create a P2SH Segwit Bitcoin and Litecoin Wallet ===")
w = HDWallet.create('P2SH-segwit-Wallet', witness_type='p2sh-segwit', db_uri=test_database)
w.new_key()
w.new_key(network='litecoin')
w.info()

#
# Manage Wallets
#
print("\n=== List wallets & delete a wallet ===")
print(','.join([w['name'] for w in wallets_list(db_uri=test_database)]))
res = wallet_delete('Personal', db_uri=test_database, force=True)
print(','.join([w['name'] for w in wallets_list(db_uri=test_database)]))
