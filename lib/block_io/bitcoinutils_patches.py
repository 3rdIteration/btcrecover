from decimal import Decimal
from binascii import hexlify, unhexlify
import hashlib
import ecdsa
import bitcoinutils.constants
import bitcoinutils.bech32
from lib.cashaddress import base58

bitcoinutils.constants.NETWORK_WIF_PREFIXES = { 'BTC': b'\x80',
                                                'LTC': b'\xb0',
                                                'DOGE': b'\x9e',
                                                'BTCTEST': b'\xef',
                                                'DOGETEST': b'\xf1',
                                                'LTCTEST': b'\xef'
                                               }

bitcoinutils.constants.NETWORK_P2PKH_PREFIXES = { 'BTC': b'\x00',
                                                  'BTCTEST': b'\x6f',
                                                  'LTC': b'\x30',
                                                  'DOGE': b'\x1e',
                                                  'LTCTEST': b'\x6f',
                                                  'DOGETEST': b'\x71'
                                                 }

bitcoinutils.constants.NETWORK_P2SH_PREFIXES = { 'BTC': b'\x05',
                                                 'BTCTEST': b'\xc4',
                                                 'LTC': b'\x32',
                                                 'DOGE': b'\x16',
                                                 'LTCTEST': b'\x3a',
                                                 'DOGETEST': b'\xc4'
                                                }

bitcoinutils.constants.NETWORK_SEGWIT_PREFIXES = { 'BTC': 'bc',
                                                   'BTCTEST': 'tb',
                                                   'LTC': 'ltc',
                                                   'LTCTEST': 'tltc',
                                                   'DOGE': 'doge',
                                                   'DOGETEST': 'tdge'
                                                  }

bitcoinutils.constants.DEFAULT_TX_VERSION =  (1).to_bytes(4, byteorder="little") # b'\x01\x00\x00\x00' # little-ended version 1

from bitcoinutils.setup import setup as bitcoinutils_setup
from bitcoinutils.setup import get_network as bitcoinutils_get_network
from bitcoinutils.keys import P2pkhAddress, PrivateKey, PublicKey, P2shAddress, P2wshAddress, Address
from bitcoinutils.script import Script
from bitcoinutils.transactions import Transaction, TxInput, TxOutput

# add p2sh_address.to_script_pub_key()
def added_p2sh_to_script_pub_key(self):
    return Script(['OP_HASH160', self.to_hash160(), 'OP_EQUAL'])

bitcoinutils.keys.P2shAddress.to_script_pub_key = added_p2sh_to_script_pub_key
####

# override to use low R signatures
def low_r_sign_input(self, tx_digest, sighash=bitcoinutils.constants.SIGHASH_ALL):
    # unlike the overriden method, this does not append SIGHASH_ALL,
    # so we'll do it ourselves if we add signatures to serialize the transaction
    counter = 0
    der_sig = None
    
    while True:
        extra_entropy = b""
        if (counter > 0):
            extra_entropy = (counter).to_bytes(32, byteorder="little") # bytearray.fromhex(hex(counter).split("x")[1].rjust(64,"0"))[::-1]
        der_sig = hexlify(self.key.sign_digest_deterministic(tx_digest, hashlib.sha256, ecdsa.util.sigencode_der_canonize, extra_entropy))
        if (int(der_sig[6:8],16) == 32 and int(der_sig[8:10],16) < 128):
            break
        counter = counter + 1
            
    return der_sig
        
bitcoinutils.keys.PrivateKey._sign_input = low_r_sign_input
####

# return output script given address
def get_output_script(address):

    # try to see if this a valid bech32 address
    decoded_bech32 = bitcoinutils.bech32.decode(bitcoinutils.constants.NETWORK_SEGWIT_PREFIXES[bitcoinutils_get_network()], address)
    output_script = None
    
    if (decoded_bech32[0] is None or decoded_bech32[1] is None):
        # failed to decode information for bech32 address, so let's try decoding it as legacy addresses
        addr_encoded = address.encode('ascii')
        decoded_hex = hexlify(base58.b58decode( addr_encoded ))
        network_prefix = decoded_hex[:2]
        address_hash160 = decoded_hex[2:len(decoded_hex)-8]
        decoded_checksum = decoded_hex[-8:]
        network_prefix_and_hash160 = decoded_hex[:len(decoded_hex)-8]
        correct_checksum = hexlify(hashlib.sha256(hashlib.sha256(unhexlify(network_prefix_and_hash160)).digest()).digest())

        if (correct_checksum[:8] != decoded_checksum):
            raise Exception("Invalid P2SH/P2PKH address checksum")

        # the address is fine, let's figure out if it's P2SH or P2PKH format
        if (bitcoinutils.constants.NETWORK_P2SH_PREFIXES[bitcoinutils_get_network()] == unhexlify(network_prefix)):
            output_script = Script(['OP_HASH160', address_hash160, 'OP_EQUAL'])
        elif (bitcoinutils.constants.NETWORK_P2PKH_PREFIXES[bitcoinutils_get_network()] == unhexlify(network_prefix)):
            output_script = Script(['OP_DUP', 'OP_HASH160', address_hash160, 'OP_EQUALVERIFY', 'OP_CHECKSIG'])
        else:
            raise Exception("Invalid address provided")
    elif (decoded_bech32[0] == 0 or decoded_bech32[0] == 1):
        # only support witness v0 and witness v1 addresses for now
        # it's a bech32/bech32m address
        output_script = Script(["OP_" + str(decoded_bech32[0]), hexlify(bytearray(decoded_bech32[1]))])
    else:
        raise Exception("Unsupported address provided")

    return output_script

####

# returns signature with sighash
def signature_with_sighash(signature, sighash = bitcoinutils.constants.SIGHASH_ALL):
    # takes signature as a hex
    return hexlify(unhexlify(signature) + (sighash).to_bytes(1, byteorder="big")) # byte order doesn't matter here since it's just one byte struct.pack('B', sighash))
####
