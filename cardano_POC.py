import hashlib
import hmac
from lib.mnemonic import Mnemonic
import lib.cardano.orakolo.HDEd25519 as HDEd25519
from lib.ecpy.curves import Curve,Point
import lib.bech32 as bech32
import binascii

TRACE=True
INDENT=0
def trace(x):
    global TRACE
    if (TRACE):
        print("%s%s"%(" "*INDENT,x))

def ENTER(x) :
  global INDENT
  trace("Enter %s"%x)
  INDENT = INDENT+4

def LEAVE(x) :
  global INDENT
  INDENT = INDENT-4
  trace("Leave %s"%x)

ed25519_n = 2**252 + 27742317777372353535851937790883648493

def _NFKDbytes(str):
    return  unicodedata.normalize('NFKD', str).encode()

def _h512(m):
    return hashlib.sha512(m).digest()

def _h256(m):
    return hashlib.sha256(m).digest()

def _Fk(message, secret):
    return hmac.new(secret, message, hashlib.sha512).digest()

def _Fk256(message, secret):
    return hmac.new(secret, message, hashlib.sha256).digest()

def _get_bit(character, pattern):
    return character & pattern

def _set_bit(character, pattern):
    return character | pattern

def _clear_bit(character, pattern):
    return character & ~pattern

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
)
]

def generateMasterKey_Icarus(mnemonic, passphrase):
    mnemo = Mnemonic("english")
    seed = mnemo.to_entropy(mnemonic)
    data = hashlib.pbkdf2_hmac("SHA512", password=passphrase, salt=seed, iterations=4096, dklen=96)
    
    return cardano_tweakBits_shelly(bytearray(data));

def generateMasterKey_Ledger(mnemonic, passphrase):
    mnemo = Mnemonic("english")
    seed = mnemo.to_entropy(mnemonic)
    
    derivation_salt = b"mnemonic" + passphrase
    derivation_password = mnemonic.encode()

    data = hashlib.pbkdf2_hmac("SHA512", password=derivation_password, salt=derivation_salt, iterations=2048, dklen=64)
    
    obj = HDEd25519.BIP32Ed25519()
    
    obj.root_key_slip10(data)
    
    #data = hashlib.pbkdf2_hmac("SHA512", password=derivation_password, salt=derivation_salt, iterations=2048, dklen=64)
    
    cc = hmac.new(key=b"ed25519 seed", msg=b'\x01'+data, digestmod=hashlib.sha256).digest()
    
    #data = hashlib.pbkdf2_hmac("SHA512", password=derivation_password, salt=derivation_salt, iterations=2048, dklen=64)

    iL, iR = hashRepeatedly_ledger(data);

    return (cardano_tweakBits_shelly(bytearray(iL)) + iR + cc)

def hashRepeatedly_ledger(message):
    iL_iR = hmac.new(key=b"ed25519 seed", msg=message, digestmod=hashlib.sha512).digest()

    iL, iR = iL_iR[:32], iL_iR[32:]
    
    if (iL[31] & 0b00100000):
        print("Repeating")
        return hashRepeatedly_ledger(iL + iR)

    return (iL, iR)

def generateMasterKey_Byron(mnemonic):
    mnemo = Mnemonic("english")
    seed = mnemo.to_entropy(mnemonic)
    return hashRepeatedly_byron(seed, 1)

def hashRepeatedly_byron(key, i):
    iL_iR = hmac.new(key=bytes(key), msg=b"Root Seed Chain %d" % i, digestmod=hashlib.sha512).digest()

    iL, iR = iL_iR[:32], iL_iR[32:]
    
    prv = cardano_tweakBits_byron(bytearray(hashlib.sha512(iL).digest()))

    #print("{:08b}".format(prv[31] & 0b00100000))
    if (prv[31] & 0b00100000):
        print("Repeat")
        return hashRepeatedly_byron(key, i+1)

    return (prv + iR)

def cardano_tweakBits_shelly(data):
    # on the ed25519 scalar leftmost 32 bytes:
    # clear the lowest 3 bits
    # clear the highest bit
    # clear the 3rd highest bit
    # set the highest 2nd bit
    data[0]  = data[0]  & 0b11111000
    data[31] = data[31] & 0b00011111
    data[31] = data[31] | 0b01000000

    return bytes(data)
    
def root_public_key(rootkey):
    kL, kR, c = rootkey[:32], rootkey[32:64], rootkey[64:]    
    # root public key
    #A = _crypto_scalarmult_curve25519_base(bytes(kL))
    cv25519 = Curve.get_curve("Ed25519")
    k_scalar = int.from_bytes(bytes(kL), 'little')
    P = k_scalar*cv25519.generator
    A =  cv25519.encode_point(P)

    trace("root key: ")
    trace("kL %s"%binascii.hexlify(kL))
    trace("kR %s"%binascii.hexlify(kR))
    trace("A  %s"%binascii.hexlify(A))
    trace("c  %s"%binascii.hexlify(c))
    LEAVE("root_key_slip10")
    return A

def private_child_key(node, i):
    """
    INPUT:
      (kL,kR): 64 bytes private eddsa key
      A      : 32 bytes public key (y coordinatte only), optionnal as A = kR.G (y coordinatte only)
      c      : 32 bytes chain code
      i      : child index to compute (hardened if >= 0x80000000)

    OUTPUT:
      (kL_i,kR_i): 64 bytes ith-child private eddsa key
      A_i        : 32 bytes ith-child public key, A_i = kR_i.G (y coordinatte only)
      c_i        : 32 bytes ith-child chain code

    PROCESS:
      1. encode i 4-bytes little endian, il = encode_U32LE(i)
      2. if i is less than 2^31
           - compute Z   = HMAC-SHA512(key=c, Data=0x02 | A | il )
           - compute c_  = HMAC-SHA512(key=c, Data=0x03 | A | il )
         else
           - compute Z   = HMAC-SHA512(key=c, Data=0x00 | kL | kR | il )
           - compute c_  = HMAC-SHA512(key=c, Data=0x01 | kL | kR | il )
      3. ci = lowest_32bytes(c_)
      4. set ZL = highest_28bytes(Z)
         set ZR = lowest_32bytes(Z)
      5. compute kL_i:
            zl_  = LEBytes_to_int(ZL)
            kL_  = LEBytes_to_int(kL)
            kLi_ = zl_*8 + kL_
            if kLi_ % order == 0: child does not exist
            kL_i = int_to_LEBytes(kLi_)
      6. compute kR_i
            zr_  = LEBytes_to_int(ZR)
            kR_  = LEBytes_to_int(kR)
            kRi_ = (zr_ + kRn_) % 2^256
            kR_i = int_to_LEBytes(kRi_)
      7. compute A
            A = kLi_.G
      8. return (kL_i,kR_i), A_i, c
    """

    #ENTER("private_child_key")
    if not node:
        trace("not node")
    #    LEAVE("private_child_key")
        return None
    # unpack argument
    ((kLP, kRP), AP, cP) = node
    assert 0 <= i < 2**32

    i_bytes = i.to_bytes(4, 'little')
    #trace("private_child_key/kLP     : %s"%binascii.hexlify(kLP))
    #trace("private_child_key/kRP     : %s"%binascii.hexlify(kRP))
    #trace("private_child_key/AP      : %s"%binascii.hexlify(AP))
    #trace("private_child_key/cP      : %s"%binascii.hexlify(cP))
    #trace("private_child_key/i       : %.04x"%i)

    #compute Z,c
    if i < 2**31:
        # regular child
    #    trace("regular Z input           : %s"%binascii.hexlify(b'\x02' + AP + i_bytes))
        Z = _Fk(b'\x02' + AP + i_bytes, cP)
    #    trace("regular c input           : %s"%binascii.hexlify(b'\x03' + AP + i_bytes))
        c = _Fk(b'\x03' + AP + i_bytes, cP)[32:]
    else:
        # harderned child
    #    trace("harderned Z input     : %s"%binascii.hexlify(b'\x00' + (kLP + kRP) + i_bytes))
        Z = _Fk(b'\x00' + (kLP + kRP) + i_bytes, cP)
    #    trace("harderned c input     : %s"%binascii.hexlify(b'\x01' + (kLP + kRP) + i_bytes))
        c = _Fk(b'\x01' + (kLP + kRP) + i_bytes, cP)[32:]
    #trace("private_child_key/Z       : %s"%binascii.hexlify(Z))
    #trace("private_child_key/c       : %s"%binascii.hexlify(c))

    ZL, ZR = Z[:28], Z[32:]
    #trace("private_child_key/ZL      : %s"%binascii.hexlify(ZL))
    #trace("private_child_key/ZR      : %s"%binascii.hexlify(ZR))

    #compute KLi
    #trace("private_child_key/ZLint   : %x"%int.from_bytes(ZL, 'little'))
    #trace("private_child_key/kLPint  : %x"%int.from_bytes(kLP, 'little'))
    kLn = int.from_bytes(ZL, 'little') * 8 + int.from_bytes(kLP, 'little')
    #trace("private_child_key/kLn     : %x"%kLn)

    if kLn % ed25519_n == 0:
    #    trace("kLn is 0")
    #    LEAVE("private_child_key")
        return None

    #compute KRi
    #trace("private_child_key/ZRint   : %x"%int.from_bytes(ZR, 'little'))
    #trace("private_child_key/kRPint  : %x"%int.from_bytes(kRP, 'little'))
    kRn = (
        int.from_bytes(ZR, 'little') + int.from_bytes(kRP, 'little')
    ) % 2**256
    #trace("private_child_key/kRn     : %x"%kRn)

    kL = kLn.to_bytes(32, 'little')
    kR = kRn.to_bytes(32, 'little')
    #trace("private_child_key/kL      : %s"%binascii.hexlify(kL))
    #trace("private_child_key/kR      : %s"%binascii.hexlify(kR))

    #compue Ai
    #A =_crypto_scalarmult_curve25519_base(kL)
    cv25519 = Curve.get_curve("Ed25519")
    k_scalar = int.from_bytes(kL, 'little')
    #trace("scalar                    : %x"%k_scalar)
    P = k_scalar*cv25519.generator
    #trace("Not encoded pubkey       : %s"%str(P))
    A =  cv25519.encode_point(P)
    #trace("private_child_key/A       : %s"%binascii.hexlify(A))

    #LEAVE("private_child_key")
    return ((kL, kR), A, c)


def public_child_key(node, i):
    """
    INPUT:
      A      : 32 bytes public key (y coordinatte only), optionnal as A = kR.G (y coordinatte only)
      c      : 32 bytes chain code
      i      : child index to compute (hardened if >= 0x80000000)

    OUTPUT:
      A_i        : 32 bytes ith-child public key, A_i = kR_i.G (y coordinatte only)
      c_i        : 32 bytes ith-child chain code

    PROCESS:
      1. encode i 4-bytes little endian, il = encode_U32LE(i)
      2. if i is less than 2^31
           - compute Z   = HMAC-SHA512(key=c, Data=0x02 | A | il )
           - compute c_  = HMAC-SHA512(key=c, Data=0x03 | A | il )
         else
           - reject inputed, hardened path for public path is not possible

      3. ci = lowest_32bytes(c_)
      4. set ZL = highest_28bytes(Z)
         set ZR = lowest_32bytes(Z)
      5. compute kL_i:
            zl_  = LEBytes_to_int(ZL)
            kL_  = LEBytes_to_int(kL)
            kLi_ = zl_*8 + kL_
            if kLi_ % order == 0: child does not exist
            kL_i = int_to_LEBytes(kLi_)
      6. compute kR_i
            zr_  = LEBytes_to_int(ZR)
            kR_  = LEBytes_to_int(kR)
            kRi_ = (zr_ + kRn_) % 2^256
            kR_i = int_to_LEBytes(kRi_)
      7. compute A
            A = kLi_.G
      8. return (kL_i,kR_i), A_i, c
    """

    #ENTER("public_child_key")
    if not node:
        trace("not node")
    #    LEAVE("public_child_key ")
        return None
    # unpack argument
    (AP, cP) = node
    assert 0 <= i < 2**32

    i_bytes = i.to_bytes(4, 'little')
    #trace("public_child_key/AP      : %s"%binascii.hexlify(AP))
    #trace("public_child_key/cP      : %s"%binascii.hexlify(cP))
    #trace("public_child_key/i       : %.04x"%i)

    #compute Z,c
    if i < 2**31:
        # regular child
        trace("regular Z input           : %s"%binascii.hexlify(b'\x02' + AP + i_bytes))
        Z = _Fk(b'\x02' + AP + i_bytes, cP)
        trace("regular c input           : %s"%binascii.hexlify(b'\x03' + AP + i_bytes))
        c = _Fk(b'\x03' + AP + i_bytes, cP)[32:]
    else:
        # harderned child
     #   trace("harderned input:hardened path for public path is not possible")
     #   LEAVE("public_child_key ")
        return None

    #trace("public_child_key/Z       : %s"%binascii.hexlify(Z))
    #trace("public_child_key/c       : %s"%binascii.hexlify(c))

    ZL, ZR = Z[:28], Z[32:]
    #trace("public_child_key/ZL      : %s"%binascii.hexlify(ZL))
    #trace("public_child_key/ZR      : %s"%binascii.hexlify(ZR))

    #compute ZLi
    #trace("public_child_key/ZLint   : %x"%int.from_bytes(ZL, 'little'))
    ZLint = int.from_bytes(ZL, 'little')

    #trace("public_child_key/8*ZLint : %x"%(8*ZLint))
    ZLint_x_8 = 8*ZLint


    #compue Ai
    #A = AP + _crypto_scalarmult_curve25519_base(ZLint_x_8)
    cv25519 = Curve.get_curve("Ed25519")
    P = ZLint_x_8*cv25519.generator
    #trace("not encoded 8*ZL*G       : %s"%str(P))
    Q = cv25519.decode_point(AP)
    #trace("decoded AP               : %s"%str(Q))
    PQ = P+Q
    #trace("not encoded AP+8*ZL*G    : %s"%str(PQ))
    A = cv25519.encode_point(PQ)
    #trace("public_child_key/A       : %s"%binascii.hexlify(A))

    LEAVE("public_child_key")
    return (A, c)

def cardano_tweakBits_byron(data):
    # clear the lowest 3 bits
    # clear the highest bit
    # set the highest 2nd bit
    data[0]  = data[0]  & 0b11111000
    data[31] = data[31] & 0b01111111
    data[31] = data[31] | 0b01000000;

    return bytes(data);

def derive_child_keys(root, path, private):
    if private:
        node = root
    else :
        ((kLP, kRP), AP, cP) = root
        node = (AP,cP)
    for i in path.split('/'):
        if i.endswith("'"):
            i = int(i[:-1]) + 2**31
        else:
            i = int(i)

        if private:
          node = private_child_key(node, i)
          ((kLP, kRP), AP, cP) = node
          #trace("Node %d"%i)
          #trace("  kLP:%s" % binascii.hexlify(kLP))
          #trace("  kRP:%s" % binascii.hexlify(kRP))
          #trace("   AP:%s" % binascii.hexlify(AP))
          #trace("   cP:%s" % binascii.hexlify(cP))
          #trace("   KeyHash:%s" % hashlib.blake2b(AP, digest_size=28).hexdigest())
        else:
          node = public_child_key(node, i)
          (AP, cP) = node
          #trace("Node %d"%i)
          #trace("   AP:%s" % binascii.hexlify(AP))
          #trace("   cP:%s" % binascii.hexlify(cP))
          #trace("   KeyHash:%s" % hashlib.blake2b(data=AP, digest_size=28).digest().hex())
    #LEAVE("derive_seed")
    return node

for description, mk_type, mnemonic, passphrase, correct_mk in tests:
    
    if mk_type == "icarus":
        derived_mk = generateMasterKey_Icarus(mnemonic=mnemonic,passphrase=passphrase.encode()).hex()  
    elif mk_type == "ledger":
        derived_mk = generateMasterKey_Ledger(mnemonic=mnemonic,passphrase=passphrase.encode()).hex()
    elif mk_type == "byron":
        derived_mk = generateMasterKey_Byron(mnemonic=mnemonic).hex()
    
    print(description, " ", correct_mk == derived_mk)

    if correct_mk != derived_mk:
        print("Expected: ", correct_mk)
        print("Derived:  ", derived_mk)
        
#Test address derivation
print("\n\n==Test Address Derivation==")
description, mk_type, mnemonic, passphrase, correct_mk = tests[8]
print(description)
rootkey = generateMasterKey_Icarus(mnemonic=mnemonic,passphrase=passphrase.encode())
rootkey_kL, rootkey_kR, rootkey_cc = rootkey[:32], rootkey[32:64], rootkey[64:]
print("kL:",rootkey_kL.hex())
print("kR:",rootkey_kR.hex())
print("CC:",rootkey_cc.hex())

rootkey_public = root_public_key(rootkey)
root = ((rootkey_kL, rootkey_kR), rootkey_public, rootkey_cc)

account_node = derive_child_keys(root, "1852'/1815'/0'", True)

print("Spending Keys")
node = derive_child_keys(account_node, "0/0", False)
(AP, cP) = node
spend_pubkeyhash = hashlib.blake2b(AP, digest_size=28).digest()

print("Staking Keys")
node = derive_child_keys(account_node, "2/0", False)
(AP, cP) = node
stake_pubkeyhash = hashlib.blake2b(AP, digest_size=28).digest()

bech32_data = b"\x01" + spend_pubkeyhash + stake_pubkeyhash

print(bech32_data.hex())

data = bytes.fromhex(bech32_data.hex())

out_data = bech32.convertbits(data, 8, 5)

encoded_address = bech32.bech32_encode("addr", out_data)

print(encoded_address)




