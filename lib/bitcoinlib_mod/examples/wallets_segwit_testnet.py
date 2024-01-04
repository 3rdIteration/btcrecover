# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#
#    EXAMPLES - Segregated Witness Wallets
#
#    © 2018 October - 1200 Web Development <http://1200wd.com/>
#
#
# Create 4 different Segregated Witness wallets of which 2 Native segwit wallets and 2 wallets with P2SH embeded
# segwit scripts so every wallet can send payments to them.
#
# These four wallet types will be created:
# * P2WPKH - Pay-to-wallet-public-key-hash, Native SegWit single key
# * P2WSH - Pay-to-wallet-script-hash, Native SegWit multisig/script
# * P2SH-P2WPKH - P2WPKH nested in a P2SH script
# * P2SH-P2WSH - P2WSH nested in P2SH script
#
# If you deposit at least 0.001 TBTC test bitcoins to the first wallet, several transactions will be created for every
# kind of segwit wallet
#

from bitcoinlib.wallets import *
from bitcoinlib.keys import HDKey
from time import sleep


tx_fee = 500
tx_amount = 1000
wif = 'tprv8ZgxMBicQKsPdd7kWYnxC5BTucY6fESWSA9tWwtKiSpasvL1WDbtHNEU8sZDTWcoxG2qYzBA5HFWzR2NoxgG2MTyR8PeCry266DbmjF8pT4'
wif2 = 'tprv8ZgxMBicQKsPe2Fpzm7zK6WsUqcYGZsZe3vwvQGLEqe8eunrxJXXxaw3pF283uQ9J7EhTVazDhKVquwk8a5K1rSx3T9qZJiNHkzJz3sRrWd'

#
# CREATE WALLETS
#

# Segwit P2SH-P2WPKH Wallet
w1 = wallet_create_or_open('segwit_testnet_p2sh_p2wpkh', keys=wif, witness_type='p2sh-segwit', network='testnet')
w1_key = w1.get_key()

# Segwit Native P2WPKH Wallet
w2 = wallet_create_or_open('segwit_testnet_p2wpkh', keys=wif, witness_type='segwit', network='testnet')
w2_key = w2.get_key()

# Segwit Native P2WSH Wallet
w3 = wallet_create_or_open('segwit_testnet_p2wsh',
                           keys=[wif, HDKey(wif2).public_master_multisig(witness_type='segwit').public()],
                           witness_type='segwit', network='testnet')
w3_key = w3.get_key()

# Segwit P2SH-P2WSH Wallet
w4 = wallet_create_or_open('segwit_testnet_p2sh_p2wsh',
                           keys=[wif, HDKey(wif2).public_master_multisig(witness_type='p2sh-segwit').public()],
                           witness_type='p2sh-segwit', network='testnet')
w4_key = w4.get_key()


#
# SEND TRANSACTIONS
#

w1.utxos_update()
w1.info()
if not w1.utxos():
    print("No UTXO'S found, please make a test-bitcoin deposit to %s. Minimum amount needed is %d sathosi" %
          (w1_key.address, (4 * (tx_fee + tx_amount))))
else:
    print("Open balance: %s" % w1.balance())
    if w1.balance() < ((tx_fee+tx_amount)*4):
        print("Balance to low, please deposit at least %s to %s" %
              (((tx_fee+tx_amount)*4)-w1.balance(), w1_key.address))
    print("Sending transaction from wallet #1 to wallet #2:")
    t = w1.send_to(w2_key.address, 4 * tx_amount, fee=tx_fee)
    t.info()

    while True:
        w2.utxos_update()
        print("waiting for tx broadcast")
        sleep(1)
        if w2.utxos():
            print("Sending transaction from wallet #2 to wallet #3:")
            t2 = w2.send_to(w3_key.address, 3 * tx_amount, fee=tx_fee)
            t2.info()
            break

    while True:
        w3.utxos_update()
        print("waiting for tx broadcast")
        sleep(1)
        if w3.utxos():
            print("Sending transaction from wallet #3 to wallet #4:")
            t3 = w3.send_to(w4_key.address, 2 * tx_amount, fee=tx_fee)
            t3.sign(wif2)
            t3.send()
            t3.info()
            break

    while True:
        w4.utxos_update()
        print("waiting for tx broadcast")
        sleep(1)
        if w4.utxos():
            print("Sending transaction from wallet #4 to wallet #1:")
            t4 = w4.send_to(w1_key.address, tx_amount, fee=tx_fee)
            t4.sign(wif2)
            t4.send()
            t4.info()
            break
