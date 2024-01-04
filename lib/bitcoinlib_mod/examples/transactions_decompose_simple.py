# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#
#    EXAMPLES - Decompose a simple transaction
#
#    © 2017 September - 1200 Web Development <http://1200wd.com/>
#

from pprint import pprint
from bitcoinlib.transactions import *


print("\n===  Example of a basic raw transaction with 1 input and 2 outputs (destination and change address). ===")
rt = '01000000'  # Version bytes in Little-Endian (reversed) format
# --- INPUTS ---
rt += '01'  # Number of UTXO's inputs
# Previous transaction hash (Little Endian format):
rt += 'a3919372c9807d92507289d71bdd38f10682a49c47e50dc0136996b43d8aa54e'
rt += '01000000'  # Index number of previous transaction
# - INPUT: SCRIPTSIG -
rt += '6a'  # Size of following unlocking script (ScripSig)
rt += '47'  # PUSHDATA 47 - Push following 47 bytes signature to stack
rt += '30'  # DER encoded Signature - Sequence
rt += '44'  # DER encoded Signature - Length
rt += '02'  # DER encoded Signature - Integer
rt += '20'  # DER encoded Signature - Length of X:
rt += '1f6e18f4532e14f328bc820cb78c53c57c91b1da9949fecb8cf42318b791fb38'
rt += '02'  # DER encoded Signature - Integer
rt += '20'  # DER encoded Signature - Lenght of Y:
rt += '45e78c9e55df1cf3db74bfd52ff2add2b59ba63e068680f0023e6a80ac9f51f4'
rt += '01'  # SIGHASH_ALL
# - INPUT: PUBLIC KEY -
rt += '21'  # PUSHDATA 21 - Push following 21 bytes public key to stack:
rt += '0239a18d586c34e51238a7c9a27a342abfb35e3e4aa5ac6559889db1dab2816e9d'
rt += 'feffffff'  # Sequence
# --- OUTPUTS ---
rt += '02'  # Number of outputs
rt += '3ef5980400000000'  # Output value in Little Endian format
rt += '19'  # Script length, of following scriptPubKey:
rt += '76a914af8e14a2cecd715c363b3a72b55b59a31e2acac988ac'
rt += '90940d0000000000'  # Output value #2 in Little Endian format
rt += '19'  # Script length, of following scriptPubKey:
rt += '76a914f0d34949650af161e7cb3f0325a1a8833075165088ac'
rt += 'b7740f00'  # Locktime

print("\nImport and deserialize raw transaction")
t = Transaction.import_raw(rt)
pprint(t.as_dict())
output_script = t.outputs[0].lock_script
print("\nOutput 1st Script Type: %s " % script_deserialize(output_script)['script_type'])
print("Output 1st Script String: %s" % script_to_string(output_script))
print("\nt.verified() ==> %s" % t.verify())
