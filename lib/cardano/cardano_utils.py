from lib.mnemonic import Mnemonic
from lib.ecpy.curves import Curve,Point
import lib.cardano.orakolo.HDEd25519 as HDEd25519
import hashlib, hmac

def generateMasterKey_Icarus(mnemonic, passphrase):
    mnemo = Mnemonic("english")
    seed = mnemo.to_entropy(mnemonic)
    data = hashlib.pbkdf2_hmac("SHA512", password=passphrase, salt=seed, iterations=4096, dklen=96)
    iL, iR, cc = data[:32], data[32:64], data[64:]

    iL = tweakBits_shelly(bytearray(iL));

    rootkey_public = root_public_key(iL)

    return (iL, iR), cc, rootkey_public

def generateMasterKey_Ledger(mnemonic, passphrase):
    derivation_salt = b"mnemonic" + passphrase
    derivation_password = mnemonic.encode()

    data = hashlib.pbkdf2_hmac("SHA512", password=derivation_password, salt=derivation_salt, iterations=2048, dklen=64)

    cc = hmac.new(key=b"ed25519 seed", msg=b'\x01' + data, digestmod=hashlib.sha256).digest()

    iL, iR = hashRepeatedly_ledger(data);

    iL = tweakBits_shelly(bytearray(iL))

    rootkey_public = root_public_key(iL)

    return (iL, iR), cc, rootkey_public


def hashRepeatedly_ledger(message):
    iL_iR = hmac.new(key=b"ed25519 seed", msg=message, digestmod=hashlib.sha512).digest()

    iL, iR = iL_iR[:32], iL_iR[32:]

    if (iL[31] & 0b00100000):
        return hashRepeatedly_ledger(iL + iR)

    return (iL, iR)

def tweakBits_shelly(data):
    # on the ed25519 scalar leftmost 32 bytes:
    # clear the lowest 3 bits
    # clear the highest bit
    # clear the 3rd highest bit
    # set the highest 2nd bit
    data[0]  = data[0]  & 0b11111000
    data[31] = data[31] & 0b00011111
    data[31] = data[31] | 0b01000000

    return bytes(data)

# Pulled from orakolo HDEd25519 root_key_slip10 (Using it here for more genralised address derivation)
def root_public_key(kL):
    # root public key
    #A = _crypto_scalarmult_curve25519_base(bytes(kL))
    cv25519 = Curve.get_curve("Ed25519")
    k_scalar = int.from_bytes(bytes(kL), 'little')
    P = k_scalar*cv25519.generator
    A =  cv25519.encode_point(P)
    return A

# Pulled from orakolo HDEd25519 derive_seed (Using it here for more flexibility in terms of derivation)
def derive_child_keys(root, path, private):
    if private:
        node = root
    else :
        (kLP, kRP), AP, cP = root
        node = (AP,cP)

    BIP32Ed25519_class = HDEd25519.BIP32Ed25519()
    for i in path.split('/'):
        if i.endswith("'"):
            i = int(i[:-1]) + 2**31
        else:
            i = int(i)

        if private:
          node = BIP32Ed25519_class.private_child_key(node, i)
          ((kLP, kRP), AP, cP) = node
        else:
          node = BIP32Ed25519_class.public_child_key(node, i)
          (AP, cP) = node

    return node

def create_base_addresses(rootkey, spend_path, stake_path, addr_count):
    pass

# Note: This doesn't appear to work when compared to the CIP-003 Test Vectors, haven't validated them any further
def generateMasterKey_Byron(mnemonic):
    mnemo = Mnemonic("english")
    seed = mnemo.to_entropy(mnemonic)
    return hashRepeatedly_byron(seed, 1)

# Note: This doesn't appear to work when compared to the CIP-003 Test Vectors, haven't validated them any further
def hashRepeatedly_byron(key, i):
    iL_iR = hmac.new(key=bytes(key), msg=b"Root Seed Chain %d" % i, digestmod=hashlib.sha512).digest()

    iL, iR = iL_iR[:32], iL_iR[32:]

    prv = cardano_tweakBits_byron(bytearray(hashlib.sha512(iL).digest()))

    # print("{:08b}".format(prv[31] & 0b00100000))
    if (prv[31] & 0b00100000):
        print("Repeat")
        return hashRepeatedly_byron(key, i + 1)

    return (prv + iR)

# Note: This doesn't appear to work when compared to the CIP-003 Test Vectors, haven't validated them any further
def cardano_tweakBits_byron(data):
    # clear the lowest 3 bits
    # clear the highest bit
    # set the highest 2nd bit
    data[0]  = data[0]  & 0b11111000
    data[31] = data[31] & 0b01111111
    data[31] = data[31] | 0b01000000;

    return bytes(data);