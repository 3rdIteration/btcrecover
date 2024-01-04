# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#
#    Create Multisig 3-of-5 wallet
#
#    © 2017 November - 1200 Web Development <http://1200wd.com/>
#

from pprint import pprint
from bitcoinlib.wallets import wallet_exists, HDWallet, wallet_delete_if_exists
from bitcoinlib.keys import HDKey

WALLET_NAME = "Multisig_3of5"
NETWORK = 'testnet'
WITNESS_TYPE = 'p2sh-segwit'
SIGS_N = 5
SIGS_REQUIRED = 3


# COSIGNER DICTIONARY
# Create keys with mnemonic_key_create.py on separate instances and insert public or private key in dict
#
cosigners = [
    {
        'name': 'Anita',
        'key_type': 'bip44',
        'key': 'moral juice congress aerobic denial beyond purchase spider slide dwarf yard online'
    },
    {
        'name': 'Bart',
        'key_type': 'bip44',
        'key': 'concert planet pause then raccoon wait security stuff trim guilt deposit ranch'
    },
    {
        'name': 'Chris',
        'key_type': 'bip44',
        'key': 'surprise gasp certain ugly era confirm castle zoo near bread adapt deliver'
    },
    {
        'name': 'Daan',
        'key_type': 'bip44',
        'key': 'tprv8ZgxMBicQKsPeS4DjbqVkrV6u4i7wCvM6iUeiSPTFLuuN94bQjdmdmGrZ9cz29wjVc4oHqLZq9yd1Q1urjbpjTBVVFBK4TaGxy9kN68rUee'
    },
    {
        'name': 'Paper-Backup',
        'key_type': 'single',
        'key': 'nurse other famous achieve develop interest kangaroo jealous alpha machine ability swarm'
    },
]
COSIGNER_NAME_THIS_WALLET = 'Chris'

# wallet_delete_if_exists(WALLET_NAME)
if not wallet_exists(WALLET_NAME):
    # This wallets key list, use tools/mnemonic_key_create.py to create your own.
    #
    cosigners_private = []
    key_list = []
    for cosigner in cosigners:
        if not cosigner['key']:
            raise ValueError("Please create private keys with mnemonic_key_create.py and add to COSIGNERS definitions")
        if len(cosigner['key'].split(" ")) > 1:
            hdkey = HDKey.from_passphrase(cosigner['key'], key_type=cosigner['key_type'], witness_type=WITNESS_TYPE,
                                          network=NETWORK)
        else:
            hdkey = HDKey(cosigner['key'], key_type=cosigner['key_type'], witness_type=WITNESS_TYPE, network=NETWORK)
        if cosigner['name'] != COSIGNER_NAME_THIS_WALLET:
            if hdkey.key_type == 'single':
                hdkey = hdkey.public()
            else:
                hdkey = hdkey.public_master_multisig()
        cosigner['hdkey'] = hdkey
        key_list.append(hdkey)

    if len(key_list) != SIGS_N:
        raise ValueError("Number of cosigners (%d) is different then expected. SIG_N=%d" % (len(key_list), SIGS_N))
    wallet3o5 = HDWallet.create(WALLET_NAME, key_list, sigs_required=SIGS_REQUIRED, witness_type=WITNESS_TYPE,
                                network=NETWORK)
    wallet3o5.new_key()
    print("\n\nA multisig wallet with 1 key has been created on this system")
else:
    wallet3o5 = HDWallet(WALLET_NAME)

print("\nUpdating UTXO's...")
wallet3o5.utxos_update()
wallet3o5.info()
utxos = wallet3o5.utxos()
wallet3o5.info()

# Creating transactions just like in a normal wallet, then send raw transaction to other cosigners. They
# can sign the transaction with there on key and pass it on to the next signer or broadcast it to the network.
# You can use bitcoinlib/tools/sign_raw.py to import and sign a raw transaction.

t = None
if utxos:
    print("\nNew unspent outputs found!")
    print("Now a new transaction will be created to sweep this wallet and send bitcoins to a testnet faucet")
    send_to_address = '2NGZrVvZG92qGYqzTLjCAewvPZ7JE8S8VxE'
    t = wallet3o5.sweep(send_to_address, min_confirms=0, offline=True)
    print("Now send the raw transaction hex to one of the other cosigners to sign using sign_raw.py")
    print("Raw transaction: %s" % t.raw_hex())
else:
    print("Please send funds to %s, so we can create a transaction" % wallet3o5.get_key().address)
    print("Restart this program when funds are send...")

# Sign the transaction with 2 other cosigner keys and push the transaction
if t:
    t.sign(cosigners[0]['key'])
    t.sign(cosigners[4]['key'])
    t.send()
    t.info()
