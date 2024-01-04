# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#
#    EXAMPLES - Key and HDKey Class
#
#    © 2017 September - 1200 Web Development <http://1200wd.com/>
#

from pprint import pprint
from bitcoinlib.keys import *


# Key Class Examples

print("\n=== Generate random key ===")
k = Key()
k.info()

print("\n=== Import Public key ===")
K = Key('025c0de3b9c8ab18dd04e3511243ec2952002dbfadc864b9628910169d9b9b00ec')
K.info()

print("\n=== Import Private key as decimal ===")
pk = 45552833878247474734848656701264879218668934469350493760914973828870088122784
k = Key(import_key=pk, network='testnet')
k.info()

print("\n=== Import Private key as byte ===")
pk = b':\xbaAb\xc7%\x1c\x89\x12\x07\xb7G\x84\x05Q\xa7\x199\xb0\xde\x08\x1f\x85\xc4\xe4L\xf7\xc1>A\xda\xa6\x01'
k = Key(pk)
k.info()

print("\n=== Import Private WIF Key ===")
k = Key('L1odb1uUozbfK2NrsMyhJfvRsxGM2AxixgPL8vG9BUBnE6W1VyTX')
print("Private key     %s" % k.wif())
print("Private key hex %s " % k.private_hex)
print("Compressed      %s\n" % k.compressed)

print("\n=== Import Private Testnet Key ===")
k = Key('92Pg46rUhgTT7romnV7iGW6W1gbGdeezqdbJCzShkCsYNzyyNcc', network='testnet')
k.info()

print("\n=== Import Private Litecoin key (network derived from key) ===")
pk = 'T43gB4F6k1Ly3YWbMuddq13xLb56hevUDP3RthKArr7FPHjQiXpp'
k = Key(import_key=pk, network='litecoin')
k.info()

print("\n=== Import uncompressed Private Key and Encrypt with BIP38 ===")
k = Key('5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR')
print("Private key     %s" % k.wif())
print("Encrypted pk    %s " % k.bip38_encrypt('TestingOneTwoThree'))
print("Is Compressed   %s\n" % k.compressed)

print("\n=== Import and Decrypt BIP38 Key ===")
k = Key('6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg', passphrase='TestingOneTwoThree')
print("Private key     %s" % k.wif())
print("Is Compressed   %s\n" % k.compressed)

#
# Hierarchical Deterministic Key Class and Child Key Derivation Examples
#
print("\n=== Generate random HD Key on testnet ===")
hdk = HDKey(network='testnet')
print("Random BIP32 HD Key on testnet %s" % hdk.wif())

print("\n=== Import HD Key from seed ===")
k = HDKey.from_seed('000102030405060708090a0b0c0d0e0f')
print("HD Key WIF for seed 000102030405060708090a0b0c0d0e0f:  %s" % k.wif())
print("Key type is : %s" % k.key_type)

print("\n=== Generate random Litecoin key ===")
lk = HDKey(network='litecoin')
lk.info()

print("\n=== Generate random Dash key ===")
lk = HDKey(network='dash')
lk.info()

print("\n=== Import simple private key as HDKey ===")
k = HDKey('L5fbTtqEKPK6zeuCBivnQ8FALMEq6ZApD7wkHZoMUsBWcktBev73')
print("HD Key WIF for Private Key L5fbTtqEKPK6zeuCBivnQ8FALMEq6ZApD7wkHZoMUsBWcktBev73:  %s" % k.wif())
print("Key type is : %s" % k.key_type)

print("\n=== Derive path with Child Key derivation ===")
print("Derive path path 'm/0H/1':")
print("  Private Extended WIF: %s" % k.subkey_for_path('m/0H/1').wif())
print("  Public Extended WIF : %s\n" % k.subkey_for_path('m/0H/1').wif_public())

print("\n=== Test Child Key Derivation ===")
print("Use the 2 different methods to derive child keys. One through derivation from public parent, "
      "and one thought private parent. They should be the same.")
K = HDKey('xpub6ASuArnXKPbfEVRpCesNx4P939HDXENHkksgxsVG1yNp9958A33qYoPiTN9QrJmWFa2jNLdK84bWmyqTSPGtApP8P'
          '7nHUYwxHPhqmzUyeFG')
k = HDKey('xprv9wTYmMFdV23N21MM6dLNavSQV7Sj7meSPXx6AV5eTdqqGLjycVjb115Ec5LgRAXscPZgy5G4jQ9csyyZLN3PZLxoM'
          '1h3BoPuEJzsgeypdKj')

index = 1000
pub_with_pubparent = K.child_public(index).address()
pub_with_privparent = k.child_private(index).address()
if pub_with_privparent != pub_with_pubparent:
    print("Error index %4d: pub-child %s, priv-child %s" % (index, pub_with_privparent, pub_with_pubparent))
else:
    print("Child Key Derivation for key %d worked!" % index)
    print("%s == %s" % (pub_with_pubparent, pub_with_privparent))


#
# Addresses
#
print("\n=== Deserialize address ===")
pprint(deserialize_address('12ooWd8Xag7hsgP9PBPnmyGe36VeUrpMSH'))

print("\n=== Deserialize bech32 address ===")
pprint(deserialize_address('bc1qtlktwxgx3xu3r7fnt04q06e4gflpvmm70qw66rjckzyc0n54elxqsgqlpy'))

print("\n=== Create addreses from public key ===")
pk = HDKey().public_hex
print("Public key: %s" % pk)
print(Address(pk).address)
print(Address(pk, script_type='p2sh').address)
print(Address(pk, encoding='bech32').address)
print(Address(pk, script_type='p2sh', encoding='bech32').address)
print(Address(pk, encoding='bech32', network='litecoin').address)
print(Address(pk, encoding='bech32', network='dash').address)


#
# Multisig and segwit WIF key import
#

print("\n=== Import Segwit p2wpkh WIF key ===")
wif = 'zprvAWgYBBk7JR8GkLNSb2QvWhAjydfXoCkSBhvHichpYbqXHDYECcySV5dg1Bw2ybwfJmoLfU1NVzbiD95DVwP34nXPScCzUrLCa3c3WXtkNri'
k = HDKey(wif)
print("Witness type derived from wif %s is segwit (%s)" % (wif, k.witness_type))
print("Encoding derived from wif is bech32 (%s)" % k.encoding)
print("Segwit bech32 encoded address is %s" % k.address())


wif = 'Ypub6bjiQGLXZ4hTYTQY8eTwC82WSegNDbRiEaYpZQCekjpWqcD7CDU3NnX9SZuzqEUvnTum7X3ixhdMNmpBDTCsGkq38h2kWaGrHXouh7QV1Wx'
k = HDKey(wif)
print("\nWitness type derived from wif %s is p2sh-segwit (%s)" % (wif, k.witness_type))
print("Encoding derived from wif is base58 (%s)" % k.encoding)
print("Segwit P2SH base58 encoded address is %s" % k.address())
