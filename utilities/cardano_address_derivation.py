import sys
sys.path.append('./')
import lib.cardano.cardano_utils as cardano

import hashlib
import hmac
import lib.cardano.orakolo.HDEd25519 as HDEd25519
import lib.cardano.cardano_utils as cardano
import lib.bech32 as bech32
import binascii
import btcrecover.btcrseed

tests = [
( 
"Steve Adalite", #0
"icarus",
"cave table seven there praise limit fat decorate middle gold ten battle trigger luggage demand", #Tested in Adalite
"",
"90e0e68229be17d0ce9e5b740fcb3a65120a5dfb32ed5ff80b4821322e6d15487d10d38c7b2b8f4d0b657fbb5e825155e33088f1548cb5119b8cfe8208e5237cb27aa64ba43b25a388590b9883e6dc8c222fd56ce38caf95d143e0ecfca183b1"
),
(
"Icarus Test Vector (No Passphrase)", #1
"icarus",
"eight country switch draw meat scout mystery blade tip drift useless good keep usage title", #Icarus Test Vector
"",
"c065afd2832cd8b087c4d9ab7011f481ee1e0721e78ea5dd609f3ab3f156d245d176bd8fd4ec60b4731c3918a2a72a0226c0cd119ec35b47e4d55884667f552a23f7fdcd4a10c6cd2c7393ac61d877873e248f417634aa3d812af327ffe9d620"
),
(
"Icarus Test Vector (With Passphrase)", #2
"icarus",
"eight country switch draw meat scout mystery blade tip drift useless good keep usage title",
"foo",
"70531039904019351e1afb361cd1b312a4d0565d4ff9f8062d38acf4b15cce41d7b5738d9c893feea55512a3004acb0d222c35d3e3d5cde943a15a9824cbac59443cf67e589614076ba01e354b1a432e0e6db3b59e37fc56b5fb0222970a010e"
),
(
"Ledger Test Vector (No Iterations)", #3
"ledger",
"recall grace sport punch exhibit mad harbor stand obey short width stem awkward used stairs wool ugly trap season stove worth toward congress jaguar", #Ledger Test Vector no iterations
"",
"a08cf85b564ecf3b947d8d4321fb96d70ee7bb760877e371899b14e2ccf88658104b884682b57efd97decbb318a45c05a527b9cc5c2f64f7352935a049ceea60680d52308194ccef2a18e6812b452a5815fbd7f5babc083856919aaf668fe7e4"
),
(
"Ledger Test Vector (Iterations, No Passphrase)", #4
"ledger",
"correct cherry mammal bubble want mandate polar hazard crater better craft exotic choice fun tourist census gap lottery neglect address glow carry old business", #Ledger Test vector with iterations
"",
"1091f9fd9d2febbb74f08798490d5a5727eacb9aa0316c9eeecf1ff2cb5d8e55bc21db1a20a1d2df9260b49090c35476d25ecefa391baf3231e56699974bdd46652f8e7dd4f2a66032ed48bfdffa4327d371432917ad13909af5c47d0d356beb"
),
(
"Ledger Test Vector (Passphrase)", #5
"ledger",
"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art", #Ledger Test vector with iterations + passphrase
"foo",
"f053a1e752de5c26197b60f032a4809f08bb3e5d90484fe42024be31efcba7578d914d3ff992e21652fee6a4d99f6091006938fac2c0c0f9d2de0ba64b754e92a4f3723f23472077aa4cd4dd8a8a175dba07ea1852dad1cf268c61a2679c3890"
),
(
"Byron Test Vector (No Iterations)", #6
"byron",
"roast crime bounce convince core happy pitch safe brush exit basic among",
"",
"60f6e2b12f4c51ed2a42163935fd95a6c39126e88571fe5ffd0332a4924e5e5e9ceda72e3e526a625ea86d16151957d45747fff0f8fcd00e394b132155dfdfc2918019cda35f1df96dd5a798da4c40a2f382358496e6468e4e276db5ec35235f"
),
(
"Byron Test Vector (4 Iterations)",#7
"byron",
"legend dismiss verify kit faint hurdle orange wine panther question knife lion",
"",
"c89fe21ec722ee174be77d7f91683dcfd307055b04613f064835bf37c58f6a5f362a4ce30a325527ff66b6fbaa43e57c1bf14edac749be3d75819e7759e9e6c82b264afa7c1fd5b3cd51be3053ccbdb0224f82f7d1c7023a96ce97cb4efca945"
),
(
"Steve Trezor Test Vector",#8
"icarus",
"ocean hidden kidney famous rich season gloom husband spring convince attitude boy",
"",
""
),
    ("Trezor 24 word vector", #9
     "trezor-icarus",
     "wood blame garbage one federal jaguar slogan movie thunder seed apology trigger spoon depth basket fine culture boil render special enforce dish middle antique",
     "",
     "")
]

#Test address derivation
print("\n\n==Test Address Derivation==")
description, mk_type, mnemonic, passphrase, correct_mk = tests[9]
print(description)
print(mnemonic)

#btcrseed_obj = btcrecover.btcrseed.WalletBIP39.create_from_params(addresses=["bc1qztc99re7ml7hv4q4ds3jv29w7u4evwqd6t76kz"], address_limit=1)

#masterkey = cardano.generateMasterKey_Icarus(mnemonic=mnemonic,passphrase=passphrase.encode(), wordlist=btcrseed_obj._language_words["en"], langcode="en", trezor=True)
masterkey = cardano.generateMasterKey_Ledger(mnemonic, passphrase.encode())

#entropy = cardano.mnemonic_to_entropy(words=mnemonic, wordlist=btcrseed_obj._language_words["en"], langcode="en", trezorDerivation=True)
#print("Entropy Length:", len(entropy))
#data = hashlib.pbkdf2_hmac("SHA512", password=passphrase.encode(), salt=entropy, iterations=4096, dklen=96)

#masterkey = cardano.generateRootKey_Icarus(data)

(kL, kR), AP ,cP = masterkey
print("Master Key")
print("kL:",kL.hex())
print("kR:",kR.hex())
print("AP:",AP.hex())
print("cP:",cP.hex())
#
# from nacl.encoding import RawEncoder, HexEncoder
# from nacl.signing import SigningKey
# from nacl.bindings import crypto_scalarmult_ed25519_base
#
# nacl = SigningKey(kL, RawEncoder)
# print("NaCL Privkey:", nacl.encode(encoder=HexEncoder))
# # Obtain the verify key for a given signing key
# verify_key = nacl.verify_key
#
# # Serialize the verify key to send it to a third party
# verify_key_hex = verify_key.encode(encoder=HexEncoder)
#
# print("NaCL Pubkey: ", verify_key_hex)
# from lib.ecpy.curves import Curve,Point
# # root public key
# # A = _crypto_scalarmult_curve25519_base(bytes(kL))
# cv25519 = Curve.get_curve("Ed25519")
# k_scalar = int.from_bytes(bytes(kL), 'little')
# P = k_scalar * cv25519.generator
# print("ECPY:", P)
# A = cv25519.encode_point(P)
#
# test = crypto_scalarmult_ed25519_base(k_scalar)
# print("NACL", test)
#
# exit()
account_node = cardano.derive_child_keys(masterkey, "1852'/1815'/0'", True)
(kL, kR), AP, cP = account_node
print("Account Key")
print("kL:",kL.hex())
print("kR:",kR.hex())
print("AP:",AP.hex())
print("cP:",cP.hex())

spend_node = cardano.derive_child_keys(account_node, "0/0", False)
(AP, cP) = spend_node
print("Spending Key")
print("AP:",AP.hex())
print("cP:",cP.hex())

spend_pubkeyhash = hashlib.blake2b(AP, digest_size=28).digest()

stake_node = cardano.derive_child_keys(account_node, "2/0", False)
(AP, cP) = stake_node
print("Staking Key")
print("AP:",AP.hex())
print("cP:",cP.hex())

stake_pubkeyhash = hashlib.blake2b(AP, digest_size=28).digest()

bech32_data = b"\x01" + spend_pubkeyhash + stake_pubkeyhash

print(bech32_data.hex())

data = bytes.fromhex(bech32_data.hex())

out_data = bech32.convertbits(data, 8, 5)

encoded_address = bech32.bech32_encode("addr", out_data)

print(encoded_address)




