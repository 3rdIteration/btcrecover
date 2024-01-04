# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    ENCODING - Methods for encoding and conversion
#    © 2016 - 2023 May - 1200 Web Development <http://1200wd.com/>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import math
import numbers
from copy import deepcopy
import hashlib
import unicodedata
from lib.bitcoinlib.main import *
_logger = logging.getLogger(__name__)


SCRYPT_ERROR = None
USING_MODULE_SCRYPT = os.getenv("USING_MODULE_SCRYPT") not in ["false", "False", "0", "FALSE"]

try:
    from Crypto.Hash import RIPEMD160
except ImportError as err:
    _logger.warning("Could not import RIPEMD160 from cryptodome, will try do use hashlib but this could lead to errors")

try:
    from Crypto.Cipher import AES
except ImportError as PYAES_ERROR:
    _logger.warning("MISSING MODULES! Please install pycryptodome")
    _logger.warning("The bip38_decrypt and bip38_encrypt methods need the pycryptodome library to work!")
#
# try:
#     if USING_MODULE_SCRYPT is not False:
#         import scrypt
#         USING_MODULE_SCRYPT = True
# except ImportError as SCRYPT_ERROR:
#     try:
#         from Crypto.Protocol.KDF import scrypt
#         _logger.info("Using scrypt method from pycryptodome")
#     except ImportError as err:
#         _logger.info("Could not import scrypt from pycryptodome: %s" % str(err))
#         pass
#
# if 'scrypt' not in sys.modules and 'Crypto.Protocol.KDF' not in sys.modules:
#     try:
#         import pyscrypt as scrypt
#     except ImportError:
#         _logger.warning("MISSING MODULES! Please install scrypt, pycryptodome or pyscrypt")
#         _logger.warning("The bip38_decrypt and bip38_encrypt methods need a scrypt library to work!")
#     USING_MODULE_SCRYPT = False
#
# USE_FASTECDSA = os.getenv("USE_FASTECDSA") not in ["false", "False", "0", "FALSE"]
# try:
#     if USE_FASTECDSA is not False:
#         from fastecdsa.encoding.der import DEREncoder
#         USE_FASTECDSA = True
# except ImportError:
#     pass
# if 'fastecdsa' not in sys.modules:
#     _logger.warning("Could not include fastecdsa library, using slower ecdsa instead.")
#     USE_FASTECDSA = False
#     try:
#         import ecdsa
#     except ImportError:
#         raise ImportError("Could not include ecdsa library. Please install fastecdsa or ecdsa library.")


class EncodingError(Exception):
    """ Log and raise encoding errors """
    def __init__(self, msg=''):
        self.msg = msg

    def __str__(self):
        return self.msg


bytesascii = b''
for bxn in range(256):
    bytesascii += bytes((bxn,))

code_strings = {
    2: b'01',
    3: b' ,.',
    10: b'0123456789',
    16: b'0123456789abcdef',
    32: b'abcdefghijklmnopqrstuvwxyz234567',
    58: b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
    256: b''.join([bytes((csx,)) for csx in range(256)]),
    'bech32': b'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
}


def _get_code_string(base):
    if base in code_strings:
        return code_strings[base]
    else:
        return list(range(0, base))


def _array_to_codestring(array, base):
    codebase = code_strings[base]
    codestring = ""
    for i in array:
        codestring += chr(codebase[i])
    return codestring


def _codestring_to_array(codestring, base):
    codestring = bytes(codestring, 'utf8')
    codebase = code_strings[base]
    array = []
    for s in codestring:
        try:
            array.append(codebase.index(s))
        except ValueError:
            raise EncodingError("Character '%s' not found in codebase" % s)
    return array


def normalize_var(var, base=256):
    """
    For Python 2 convert variable to string

    For Python 3 convert to bytes

    Convert decimals to integer type

    :param var: input variable in any format
    :type var: str, byte
    :param base: specify variable format, i.e. 10 for decimal, 16 for hex
    :type base: int

    :return: Normalized var in string for Python 2, bytes for Python 3, decimal for base10
    """
    try:
        if isinstance(var, str):
            var = var.encode('ISO-8859-1')
    except ValueError:
        try:
            var = var.encode('utf-8')
        except ValueError:
            raise EncodingError("Unknown character '%s' in input format" % var)

    if base == 10:
        return int(var)
    elif isinstance(var, list):
        return deepcopy(var)
    else:
        return var


def change_base(chars, base_from, base_to, min_length=0, output_even=None, output_as_list=None):
    """
    Convert input chars from one numeric base to another. For instance from hexadecimal (base-16) to decimal (base-10)

    From and to numeric base can be any base. If base is not found in definitions an array of index numbers will be returned

    Examples:

    >>> change_base('FF', 16, 10)
    255
    >>> change_base('101', 2, 10)
    5

    Convert base-58 public WIF of a key to hexadecimal format

    >>> change_base('xpub661MyMwAqRbcFnkbk13gaJba22ibnEdJS7KAMY99C4jBBHMxWaCBSTrTinNTc9G5LTFtUqbLpWnzY5yPTNEF9u8sB1kBSygy4UsvuViAmiR', 58, 16)
    '0488b21e0000000000000000007d3cc6702f48bf618f3f14cce5ee2cacf3f70933345ee4710af6fa4a330cc7d503c045227451b3454ca8b6022b0f0155271d013b58d57d322fd05b519753a46e876388698a'

    Convert base-58 address to public key hash: '00' + length '21' + 20 byte key

    >>> change_base('142Zp9WZn9Fh4MV8F3H5Dv4Rbg7Ja1sPWZ', 58, 16)
    '0021342f229392d7c9ed82c932916cee6517fbc9a2487cd97a'

    Convert to 2048-base, for example a Mnemonic word list. Will return a list of integers

    >>> change_base(100, 16, 2048)
    [100]

    :param chars: Input string
    :type chars: any
    :param base_from: Base number or name from input. For example 2 for binary, 10 for decimal and 16 for hexadecimal
    :type base_from: int, str
    :param base_to: Base number or name for output. For example 2 for binary, 10 for decimal and 16 for hexadecimal
    :type base_to: int
    :param min_length: Minimal output length. Required for decimal, advised for all output to avoid leading zeros conversion problems.
    :type min_length: int
    :param output_even: Specify if output must contain an even number of characters. Sometimes handy for hex conversions.
    :type output_even: bool
    :param output_as_list: Always output as list instead of string.
    :type output_as_list: bool

    :return str, list: Base converted input as string or list.
    """
    if base_from == 10 and not min_length:
        raise EncodingError("For a decimal input a minimum output length is required")

    code_str = _get_code_string(base_to)

    if base_to not in code_strings:
        output_as_list = True

    code_str_from = _get_code_string(base_from)
    if not isinstance(code_str_from, (bytes, list)):
        raise EncodingError("Code strings must be a list or defined as bytes")
    output = []
    input_dec = 0
    addzeros = 0
    inp = normalize_var(chars, base_from)

    # Use bytes and int's methods for standard conversions to speedup things
    if not min_length:
        if base_from == 256 and base_to == 16:
            return inp.hex()
        elif base_from == 16 and base_to == 256:
            return bytes.fromhex(chars)
    if base_from == 16 and base_to == 10:
        return int(inp, 16)
    if base_from == 10 and base_to == 16:
        hex_outp = hex(inp)[2:]
        return hex_outp.zfill(min_length) if min_length else hex_outp
    if base_from == 256 and base_to == 10:
        return int.from_bytes(inp, 'big')
    if base_from == 10 and base_to == 256:
        return inp.to_bytes(min_length, byteorder='big')
    if base_from == 256 and base_to == 58:
        return base58encode(inp)
    if base_from == 16 and base_to == 58:
        return base58encode(bytes.fromhex(chars))

    if output_even is None and base_to == 16:
        output_even = True

    if isinstance(inp, numbers.Number):
        input_dec = inp
    elif isinstance(inp, (str, list, bytes)):
        factor = 1
        while len(inp):
            if isinstance(inp, list):
                item = inp.pop()
            else:
                item = inp[-1:]
                inp = inp[:-1]
            try:
                pos = code_str_from.index(item)
            except ValueError:
                try:
                    pos = code_str_from.index(item.lower())
                except ValueError:
                    raise EncodingError("Unknown character %s found in input string" % item)
            input_dec += pos * factor

            # Add leading zero if there are leading zero's in input
            firstchar = chr(code_str_from[0]).encode('utf-8')
            if not pos * factor:
                if isinstance(inp, list):
                    if not len([x for x in inp if x != firstchar]):
                        addzeros += 1
                elif not len(inp.strip(firstchar)):
                    addzeros += 1
            factor *= base_from
    else:
        raise EncodingError("Unknown input format %s" % inp)

    # Convert decimal to output base
    while input_dec != 0:
        input_dec, remainder = divmod(input_dec, base_to)
        output = [code_str[remainder]] + output

    if base_to != 10:
        pos_fact = math.log(base_to, base_from)
        expected_length = len(str(chars)) / pos_fact

        zeros = int(addzeros / pos_fact)
        if addzeros == 1:
            zeros = 1
        # Different rules for base58 addresses
        if (base_from == 256 and base_to == 58) or (base_from == 58 and base_to == 256):
            zeros = addzeros
        elif base_from == 16 and base_to == 58:
            zeros = -(-addzeros // 2)
        elif base_from == 58 and base_to == 16:
            zeros = addzeros * 2

        for _ in range(zeros):
            if base_to != 10 and not expected_length == len(output):
                output = [code_str[0]] + output

        # Add zero's to make even number of digits on Hex output (or if specified)
        if output_even and len(output) % 2:
            output = [code_str[0]] + output

        # Add leading zero's
        while len(output) < min_length:
            output = [code_str[0]] + output

    if not output_as_list and isinstance(output, list):
        output = 0 if not len(output) else ''.join([chr(c) for c in output])
    if base_to == 10:
        return int(0) or (output != '' and int(output))
    if base_to == 256 and not output_as_list:
        return output.encode('ISO-8859-1')
    else:
        return output


def base58encode(inp):
    """
    Convert bytes to base58 encode string

    :param inp: Input string
    :type inp: bytes

    :return str:
    """
    origlen = len(inp)
    inp = inp.lstrip(b'\0')
    padding_zeros = origlen - len(inp)
    code_str = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    acc = int.from_bytes(inp, 'big')

    string = ''
    while acc:
        acc, idx = divmod(acc, 58)
        string = code_str[idx:idx + 1] + string
    return '1' * padding_zeros + string


def varbyteint_to_int(byteint):
    """
    Convert CompactSize Variable length integer in byte format to integer.

    See https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer for specification

    >>> varbyteint_to_int(bytes.fromhex('fd1027'))
    (10000, 3)

    :param byteint: 1-9 byte representation
    :type byteint: bytes, list

    :return (int, int): tuple wit converted integer and size
    """
    if not isinstance(byteint, (bytes, list)):
        raise EncodingError("Byteint must be a list or defined as bytes")
    if byteint == b'':
        return 0, 0
    ni = byteint[0]
    if ni < 253:
        return ni, 1
    if ni == 253:  # integer of 2 bytes
        size = 2
    elif ni == 254:  # integer of 4 bytes
        size = 4
    else:  # integer of 8 bytes
        size = 8
    return int.from_bytes(byteint[1:1+size][::-1], 'big'), size + 1


def read_varbyteint(s):
    """
    Read variable length integer from BytesIO stream. Wrapper for the varbyteint_to_int method

    :param s: A binary stream
    :type s: BytesIO

    :return int:
    """
    pos = s.tell()
    value, size = varbyteint_to_int(s.read(9))
    s.seek(pos + size)
    return value


def read_varbyteint_return(s):
    """
    Read variable length integer from BytesIO stream. Return original converted bytes (to reconstruct transaction or
    script).

    :param s: A binary stream
    :type s: BytesIO

    :return (int, bytes):
    """
    pos = s.tell()
    byteint = s.read(9)
    if not byteint:
        return 0, b''

    ni = byteint[0]
    if ni < 253:
        s.seek(pos + 1)
        return ni, byteint[0:1]
    if ni == 253:  # integer of 2 bytes
        size = 2
    elif ni == 254:  # integer of 4 bytes
        size = 4
    else:  # integer of 8 bytes
        size = 8
    varbytes = byteint[1:1+size]
    s.seek(pos + size + 1)
    return int.from_bytes(varbytes[::-1], 'big'), byteint[0:1] + varbytes


def int_to_varbyteint(inp):
    """
    Convert integer to CompactSize Variable length integer in byte format.

    See https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer for specification

    >>> int_to_varbyteint(10000).hex()
    'fd1027'

    :param inp: Integer to convert
    :type inp: int

    :return: byteint: 1-9 byte representation as integer
    """
    if not isinstance(inp, numbers.Number):
        raise EncodingError("Input must be a number type")
    if inp < 0xfd:
        return inp.to_bytes(1, 'little')
    elif inp < 0xffff:
        return b'\xfd' + inp.to_bytes(2, 'little')
    elif inp < 0xffffffff:
        return b'\xfe' + inp.to_bytes(4, 'little')
    else:
        return b'\xff' + inp.to_bytes(8, 'little')


def convert_der_sig(signature, as_hex=True):
    """
    Extract content from DER encoded string: Convert DER encoded signature to signature string.

    :param signature: DER signature
    :type signature: bytes
    :param as_hex: Output as hexstring
    :type as_hex: bool

    :return bytes, str: Signature
    """

    if not signature:
        return ""
    if USE_FASTECDSA:
        r, s = DEREncoder.decode_signature(bytes(signature))
    else:
        sg, junk = ecdsa.der.remove_sequence(signature)
        if junk != b'':
            raise EncodingError("Junk found in encoding sequence %s" % junk)
        r, sg = ecdsa.der.remove_integer(sg)
        s, sg = ecdsa.der.remove_integer(sg)
    sig = '%064x%064x' % (r, s)
    if as_hex:
        return sig
    else:
        return bytes.fromhex(sig)


def der_encode_sig(r, s):
    """
    Create DER encoded signature string with signature r and s value.

    :param r: r value of signature
    :type r: int
    :param s: s value of signature
    :type s: int

    :return bytes:
    """
    if USE_FASTECDSA:
        return DEREncoder.encode_signature(r, s)
    else:
        rb = ecdsa.der.encode_integer(r)
        sb = ecdsa.der.encode_integer(s)
        return ecdsa.der.encode_sequence(rb, sb)


def addr_to_pubkeyhash(address, as_hex=False, encoding=None):
    """
    Convert base58 or bech32 address to public key hash

    Wrapper for the :func:`addr_base58_to_pubkeyhash` and :func:`addr_bech32_to_pubkeyhash` method

    :param address: Crypto currency address in base-58 format
    :type address: str
    :param as_hex: Output as hexstring
    :type as_hex: bool
    :param encoding: Address encoding used: base58 or bech32. Default is base58. Try to derive from address if encoding=None is provided
    :type encoding: str

    :return bytes, str: public key hash
    """

    if encoding == 'base58' or encoding is None:
        try:
            pkh = addr_base58_to_pubkeyhash(address, as_hex)
        except EncodingError:
            pkh = None
        if pkh is not None:
            return pkh
    if encoding == 'bech32' or encoding is None:
        return addr_bech32_to_pubkeyhash(address, as_hex=as_hex)


def addr_base58_to_pubkeyhash(address, as_hex=False):
    """
    Convert Base58 encoded address to public key hash

    >>> addr_base58_to_pubkeyhash('142Zp9WZn9Fh4MV8F3H5Dv4Rbg7Ja1sPWZ', as_hex=True)
    '21342f229392d7c9ed82c932916cee6517fbc9a2'

    :param address: Crypto currency address in base-58 format
    :type address: str, bytes
    :param as_hex: Output as hexstring
    :type as_hex: bool

    :return bytes, str: Public Key Hash
    """

    try:
        address = change_base(address, 58, 256, 25)
    except EncodingError as err:
        raise EncodingError("Invalid address %s: %s" % (address, err))
    if len(address) != 25:
        raise EncodingError("Invalid address hash160 length, should be 25 characters not %d" % len(address))
    check = address[-4:]
    pkh = address[:-4]
    checksum = double_sha256(pkh)[0:4]
    assert (check == checksum), "Invalid address, checksum incorrect"
    if as_hex:
        return pkh.hex()[2:]
    else:
        return pkh[1:]


def addr_bech32_to_pubkeyhash(bech, prefix=None, include_witver=False, as_hex=False):
    """
    Decode bech32 / segwit address to public key hash

    >>> addr_bech32_to_pubkeyhash('bc1qy8qmc6262m68ny0ftlexs4h9paud8sgce3sf84', as_hex=True)
    '21c1bc695a56f47991e95ff26856e50f78d3c118'

    Validate the bech32 string, and determine HRP and data. Only standard data size of 20 and 32 bytes are excepted

    :param bech: Bech32 address to convert
    :type bech: str
    :param prefix: Address prefix called Human-readable part. Default is None and tries to derive prefix, for bitcoin specify 'bc' and for bitcoin testnet 'tb'
    :type prefix: str
    :param include_witver: Include witness version in output? Default is False
    :type include_witver: bool
    :param as_hex: Output public key hash as hex or bytes. Default is False
    :type as_hex: bool

    :return str: Public Key Hash
    """
    if (any(ord(x) < 33 or ord(x) > 126 for x in bech)) or (bech.lower() != bech and bech.upper() != bech):
        raise EncodingError("Invalid bech32 character in bech string")
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        raise EncodingError("Invalid bech32 string length")
    if prefix and prefix != bech[:pos]:
        raise EncodingError("Invalid bech32 address. Prefix '%s', prefix expected is '%s'" % (bech[:pos], prefix))
    hrp = bech[:pos]
    data = _codestring_to_array(bech[pos + 1:], 'bech32')
    hrp_expanded = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    check = _bech32_polymod(hrp_expanded + data)
    if not (check == 1 or check == BECH32M_CONST):
        raise EncodingError("Bech polymod check failed")
    if data[0] == 0 and check != 1:
        raise EncodingError("Invalid checksum (Bech32m instead of Bech32)")
    if data[0] != 0 and check != BECH32M_CONST:
        raise EncodingError("Invalid checksum (Bech32 instead of Bech32m)")
    data = data[:-6]
    decoded = bytes(convertbits(data[1:], 5, 8, pad=False))
    if decoded is None or len(decoded) < 2 or len(decoded) > 40:
        raise EncodingError("Invalid decoded data length, must be between 2 and 40")
    if data[0] > 16:
        raise EncodingError("Invalid witness version")
    if data[0] == 0 and len(decoded) not in [20, 32]:
        raise EncodingError("Invalid decoded data length, must be 20 or 32 bytes")
    prefix = b''
    if include_witver:
        datalen = len(decoded)
        prefix = bytes([data[0] + 0x50 if data[0] else 0, datalen])
    if as_hex:
        return (prefix + decoded).hex()
    return prefix + decoded


def addr_bech32_checksum(bech):
    """
    Get bech32 checksum. Returns 1 for bech32 addresses and 0x2bc830a3 for bech32m addresses.
    More info https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki

    >>> addr_bech32_checksum('bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y')
    734539939

    :param bech: Bech32 address to convert
    :type bech: str

    :return bool: Bech32 checksum
    """

    bech = bech.lower()
    pos = bech.rfind('1')
    hrp = bech[:pos]
    data = _codestring_to_array(bech[pos + 1:], 'bech32')
    hrp_expanded = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    return _bech32_polymod(hrp_expanded + data)


def pubkeyhash_to_addr(pubkeyhash, prefix=None, encoding='base58', witver=0):
    """
    Convert public key hash to base58 encoded address

    Wrapper for the :func:`pubkeyhash_to_addr_base58` and :func:`pubkeyhash_to_addr_bech32` method

    :param pubkeyhash: Public key hash
    :type pubkeyhash: bytes, str
    :param prefix: Prefix version byte of network, default is bitcoin '\x00'
    :type prefix: str, bytes
    :param encoding: Encoding of address to calculate: base58 or bech32. Default is base58
    :type encoding: str
    :param witver: Witness version used. Currently used for Taproot addresses with witver=1. Ignored for base58 addresses
    :type witver: int

    :return str: Base58 or bech32 encoded address

    """
    if encoding == 'base58':
        if prefix is None:
            prefix = b'\x00'
        return pubkeyhash_to_addr_base58(pubkeyhash, prefix)
    elif encoding == 'bech32':
        if prefix is None:
            prefix = 'bc'
        return pubkeyhash_to_addr_bech32(pubkeyhash, prefix, witver)
    else:
        raise EncodingError("Encoding %s not supported" % encoding)


def pubkeyhash_to_addr_base58(pubkeyhash, prefix=b'\x00'):
    """
    Convert public key hash to base58 encoded address

    >>> pubkeyhash_to_addr_base58('21342f229392d7c9ed82c932916cee6517fbc9a2')
    '142Zp9WZn9Fh4MV8F3H5Dv4Rbg7Ja1sPWZ'

    :param pubkeyhash: Public key hash
    :type pubkeyhash: bytes, str
    :param prefix: Prefix version byte of network, default is bitcoin '\x00'
    :type prefix: str, bytes

    :return str: Base-58 encoded address
    """
    key = to_bytes(prefix) + to_bytes(pubkeyhash)
    addr256 = key + double_sha256(key)[:4]
    return base58encode(addr256)


def pubkeyhash_to_addr_bech32(pubkeyhash, prefix='bc', witver=0, separator='1', checksum_xor=1):
    """
    Encode public key hash as bech32 encoded (segwit) address

    >>> pubkeyhash_to_addr_bech32('21c1bc695a56f47991e95ff26856e50f78d3c118')
    'bc1qy8qmc6262m68ny0ftlexs4h9paud8sgce3sf84'

    Format of address is prefix/hrp + seperator + bech32 address + checksum

    For more information see BIP173 proposal at https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki

    :param pubkeyhash: Public key hash
    :type pubkeyhash: str, bytes
    :param prefix: Address prefix or Human-readable part. Default is 'bc' an abbreviation of Bitcoin. Use 'tb' for testnet.
    :type prefix: str
    :param witver: Witness version between 0 and 16
    :type witver: int
    :param separator: Separator char between hrp and data, should always be left to '1' otherwise it's not standard.
    :type separator: str
    :param checksum_xor: checksum 1 for bech32 v0 addresses and 0x2bc830a3 for bech32m v1+ addresses
    :type checksum_xor: int

    :return str: Bech32 encoded address
    """

    pubkeyhash = list(to_bytes(pubkeyhash))

    # To simplify and speedup: assume pubkeyhash of size 20, 32 and 40 does not contain witness version and size byte
    if len(pubkeyhash) not in [20, 32, 40]:
        if pubkeyhash[0] != 0:
            witver = pubkeyhash[0] - 0x50
        if pubkeyhash[1] != len(pubkeyhash[2:]):
            raise EncodingError("Incorrect pubkeyhash length")
        pubkeyhash = pubkeyhash[2:]

    if witver > 16:
        raise EncodingError("Witness version must be between 0 and 16")

    if checksum_xor == BECH32M_CONST and not witver:
        witver = 1
    elif witver > 0:
        checksum_xor = BECH32M_CONST

    data = [witver] + convertbits(pubkeyhash, 8, 5)

    # Expand the HRP into values for checksum computation
    hrp_expanded = [ord(x) >> 5 for x in prefix] + [0] + [ord(x) & 31 for x in prefix]
    polymod = _bech32_polymod(hrp_expanded + data + [0, 0, 0, 0, 0, 0]) ^ checksum_xor
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

    return prefix + separator + _array_to_codestring(data, 'bech32') + _array_to_codestring(checksum, 'bech32')


def _bech32_polymod(values):
    """
    Internal function that computes the Bech32 checksum
    """
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def convertbits(data, frombits, tobits, pad=True):
    """
    'General power-of-2 base conversion'

    Source: https://github.com/sipa/bech32/tree/master/ref/python

    :param data: Data values to convert
    :type data: list
    :param frombits: Number of bits in source data
    :type frombits: int
    :param tobits: Number of bits in result data
    :type tobits: int
    :param pad: Use padding zero's or not. Default is True
    :type pad: bool

    :return list: Converted values
    """
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def varstr(string):
    """
    Convert string to variably sized string: Bytestring preceded with length byte

    >>> varstr(to_bytes('5468697320737472696e67206861732061206c656e677468206f66203330')).hex()
    '1e5468697320737472696e67206861732061206c656e677468206f66203330'

    :param string: String input
    :type string: bytes, str

    :return bytes: varstring
    """
    s = normalize_var(string)
    if s == b'\0':
        return s
    return int_to_varbyteint(len(s)) + s


def to_bytes(string, unhexlify=True):
    """
    Convert string, hexadecimal string to bytes

    :param string: String to convert
    :type string: str, bytes
    :param unhexlify: Try to unhexlify hexstring
    :type unhexlify: bool

    :return: Bytes var
    """
    if not string:
        return b''
    if unhexlify:
        try:
            if isinstance(string, bytes):
                string = string.decode()
            s = bytes.fromhex(string)
            return s
        except (TypeError, ValueError):
            pass
    if isinstance(string, bytes):
        return string
    else:
        return bytes(string, 'utf8')


def to_hexstring(string):
    """
    Convert bytes, string to a hexadecimal string. Use instead of built-in hex() method if format
    of input string is not known.

    >>> to_hexstring(b'\\x12\\xaa\\xdd')
    '12aadd'

    :param string: Variable to convert to hex string
    :type string: bytes, str

    :return: hexstring
    """
    if not string:
        return ''
    try:
        bytes.fromhex(string)
        return string
    except (ValueError, TypeError):
        pass

    if not isinstance(string, bytes):
        string = bytes(string, 'utf8')
    return string.hex()


def normalize_string(string):
    """
    Normalize a string to the default NFKD unicode format
    See https://en.wikipedia.org/wiki/Unicode_equivalence#Normalization

    :param string: string value
    :type string: bytes, str

    :return: string
    """
    if isinstance(string, bytes):
        utxt = string.decode('utf8')
    elif isinstance(string, TYPE_TEXT):
        utxt = string
    else:
        raise TypeError("String value expected")

    return unicodedata.normalize('NFKD', utxt)


def double_sha256(string, as_hex=False):
    """
    Get double SHA256 hash of string

    :param string: String to be hashed
    :type string: bytes
    :param as_hex: Return value as hexadecimal string. Default is False
    :type as_hex: bool

    :return bytes, str:
    """
    if not as_hex:
        return hashlib.sha256(hashlib.sha256(string).digest()).digest()
    else:
        return hashlib.sha256(hashlib.sha256(string).digest()).hexdigest()


def ripemd160(string):
    try:
        return RIPEMD160.new(string).digest()
    except Exception:
        return hashlib.new('ripemd160', string).digest()


def hash160(string):
    """
    Creates a RIPEMD-160 + SHA256 hash of the input string

    :param string: Script
    :type string: bytes

    :return bytes: RIPEMD-160 hash of script
    """
    return ripemd160(hashlib.sha256(string).digest())


def aes_encrypt(data, key):
    """
    Encrypt data using AES Symmetric Block cipher Encryption in SIV mode (see
    https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html#siv-mode)

    A nonce is not used so data is encrypted deterministic, in SIV mode this doesn't reduce security.

    Method returns a byte string with ciphertext and a 16-byte tag. The ciphertext has the same length as the data.

    Data can be decrypted with the :func:`aes_decrypt` method

    :param data: Data to encrypt
    :type data: bytes
    :param key: The cryptographic key, size must be 32 bytes because AES-128 is used as cipher
    :type key: bytes

    :return bytes: Ciphertext and 16 bytes tag

    """
    cipher = AES.new(key, AES.MODE_SIV)
    ct, tag = cipher.encrypt_and_digest(data)
    return ct + tag


def aes_decrypt(encrypted_data, key):
    """
    Decrypt encrypted data using AES Symmetric Block cipher Encryption in SIV mode. Use to decrypt data encrypted
    with the :func:`aes_encrypt` method. The encrypted data attribute must contain a Ciphertext and 16-byte tag.

    A nonce is not used so data is encrypted deterministic, in SIV mode this doesn't reduce security.
    (see https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html#siv-mode)

    :param encrypted_data: Data to decrypt. Must consist of a ciphertext and 16 byte tag.
    :type encrypted_data: bytes
    :param key: The cryptographic key, size must be 32 bytes because AES-128 is used as cipher
    :type key: bytes

    :return bytes: Ciphertext and 16 bytes tag

    """
    ct = encrypted_data[:-16]
    tag = encrypted_data[-16:]
    cipher2 = AES.new(key, AES.MODE_SIV)
    return cipher2.decrypt_and_verify(ct, tag)


def bip38_decrypt(encrypted_privkey, password):
    """
    BIP0038 non-ec-multiply decryption. Returns WIF private key.
    Based on code from https://github.com/nomorecoin/python-bip38-testing
    This method is called by Key class init function when importing BIP0038 key.

    :param encrypted_privkey: Encrypted private key using WIF protected key format
    :type encrypted_privkey: str
    :param password: Required password for decryption
    :type password: str

    :return tupple (bytes, bytes): (Private Key bytes, 4 byte address hash for verification)
    """
    d = change_base(encrypted_privkey, 58, 256)[2:]
    flagbyte = d[0:1]
    d = d[1:]
    if flagbyte == b'\xc0':
        compressed = False
    elif flagbyte == b'\xe0':
        compressed = True
    else:
        raise EncodingError("Unrecognised password protected key format. Flagbyte incorrect.")
    if isinstance(password, str):
        password = password.encode('utf-8')
    addresshash = d[0:4]
    d = d[4:-4]
    try:
        key = scrypt(password, addresshash, 64, 16384, 8, 8)
    except Exception:
        key = scrypt.hash(password, addresshash, 16384, 8, 8, 64)
    derivedhalf1 = key[0:32]
    derivedhalf2 = key[32:64]
    encryptedhalf1 = d[0:16]
    encryptedhalf2 = d[16:32]
    # aes = pyaes.AESModeOfOperationECB(derivedhalf2)
    aes = AES.new(derivedhalf2, AES.MODE_ECB)
    decryptedhalf2 = aes.decrypt(encryptedhalf2)
    decryptedhalf1 = aes.decrypt(encryptedhalf1)
    priv = decryptedhalf1 + decryptedhalf2
    priv = (int.from_bytes(priv, 'big') ^ int.from_bytes(derivedhalf1, 'big')).to_bytes(32, 'big')
    # if compressed:
    #     # FIXME: This works but does probably not follow the BIP38 standards (was before: priv = b'\0' + priv)
    #     priv += b'\1'
    return priv, addresshash, compressed


def bip38_encrypt(private_hex, address, password, flagbyte=b'\xe0'):
    """
    BIP0038 non-ec-multiply encryption. Returns BIP0038 encrypted private key
    Based on code from https://github.com/nomorecoin/python-bip38-testing

    :param private_hex: Private key in hex format
    :type private_hex: str
    :param address: Address string
    :type address: str
    :param password: Required password for encryption
    :type password: str
    :param flagbyte: Flagbyte prefix for WIF
    :type flagbyte: bytes

    :return str: BIP38 password encrypted private key
    """
    if isinstance(address, str):
        address = address.encode('utf-8')
    if isinstance(password, str):
        password = password.encode('utf-8')
    addresshash = double_sha256(address)[0:4]
    try:
        key = scrypt(password, addresshash, 64, 16384, 8, 8)
    except Exception:
        key = scrypt.hash(password, addresshash, 16384, 8, 8, 64)
    derivedhalf1 = key[0:32]
    derivedhalf2 = key[32:64]
    aes = AES.new(derivedhalf2, AES.MODE_ECB)
    # aes = pyaes.AESModeOfOperationECB(derivedhalf2)
    encryptedhalf1 = \
        aes.encrypt((int(private_hex[0:32], 16) ^ int.from_bytes(derivedhalf1[0:16], 'big')).to_bytes(16, 'big'))
    encryptedhalf2 = \
        aes.encrypt((int(private_hex[32:64], 16) ^ int.from_bytes(derivedhalf1[16:32], 'big')).to_bytes(16, 'big'))
    encrypted_privkey = b'\x01\x42' + flagbyte + addresshash + encryptedhalf1 + encryptedhalf2
    encrypted_privkey += double_sha256(encrypted_privkey)[:4]
    return base58encode(encrypted_privkey)


class Quantity:
    """
    Class to convert very large or very small numbers to a readable format.

    Provided value is converted to number between 0 and 1000, and a metric prefix will be added.

    >>> # Example - the Hashrate on 10th July 2020
    >>> str(Quantity(122972532877979100000, 'H/s'))
    '122.973 EH/s'

    """

    def __init__(self, value, units='', precision=3):
        """
        Convert given value to number between 0 and 1000 and determine metric prefix

        :param value: Value as integer in base 0
        :type value: int, float
        :param units: Base units, so 'g' for grams for instance
        :type units: str
        :param precision: Number of digits after the comma
        :type precision: int

        """
        # Metric prefixes according to BIPM, the International System of Units (SI) in 10**3 steps
        self.prefix_list = list('yzafpnμm1kMGTPEZY')
        self.base = self.prefix_list.index('1')
        assert value >= 0

        self.absolute = value
        self.units = units
        self.precision = precision
        while value != 0 and (value < 1 or value > 1000) and 0 < self.base < len(self.prefix_list)-1:
            if value > 1000:
                self.base += 1
                value /= 1000.0
            elif value < 1000:
                self.base -= 1
                value *= 1000.0
        self.value = value

    def __str__(self):
        # > Python 3.6: return f"{self.value:4.{self.precision}f} {self.prefix_list[self.base]}{self.units}"
        prefix = self.prefix_list[self.base]
        if prefix == '1':
            prefix = ''
        return ('%4.*f %s%s' % (self.precision, self.value, prefix, self.units)).strip()
