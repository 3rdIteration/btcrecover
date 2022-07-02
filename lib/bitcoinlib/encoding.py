# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    ENCODING - Methods for encoding and conversion
#    © 2016 - 2020 February - 1200 Web Development <http://1200wd.com/>
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

import os
import math
import numbers
from copy import deepcopy
import hashlib
import lib.pyaes as pyaes
import binascii
import unicodedata
import struct
from lib.bitcoinlib.main import *
try:
    import groestlcoin_hash
except:
    pass
_logger = logging.getLogger(__name__)


hashlib_ripemd160_available = False
# Enable functions that may not work for some standard libraries in some environments
try:
    # this will work with micropython and python < 3.10
    # but will raise and exception if ripemd is not supported (python3.10, openssl 3)
    hashlib.new('ripemd160')
    hashlib_ripemd160_available = True
    def ripemd160(msg):
        return hashlib.new('ripemd160', msg).digest()
except:
    # otherwise use pure python implementation
    from lib.embit.py_ripemd160 import ripemd160


# SCRYPT_ERROR = None
# USING_MODULE_SCRYPT = os.getenv("USING_MODULE_SCRYPT") not in ["false", "False", "0", "FALSE"]

# try:
    # if USING_MODULE_SCRYPT != False:
        # import scrypt
        # USING_MODULE_SCRYPT = True
# except ImportError as SCRYPT_ERROR:
    # pass
# if 'scrypt' not in sys.modules:
    # import pyscrypt as scrypt
    # USING_MODULE_SCRYPT = False

# if not USING_MODULE_SCRYPT:
    # if 'scrypt_error' not in locals():
        # SCRYPT_ERROR = 'unknown'
    # _logger.warning("Error when trying to import scrypt module", SCRYPT_ERROR)
#
# USE_FASTECDSA = os.getenv("USE_FASTECDSA") not in ["false", "False", "0", "FALSE"]
# try:
#     if USE_FASTECDSA != False:
#         from fastecdsa.encoding.der import DEREncoder
#         USE_FASTECDSA = True
# except ImportError:
#     pass
# if 'fastecdsa' not in sys.modules:
#     _logger.warning("Could not include fastecdsa library, using slower ecdsa instead. ")
#     USE_FASTECDSA = False
#     import ecdsa


class EncodingError(Exception):
    """ Log and raise encoding errors """
    def __init__(self, msg=''):
        self.msg = msg

    def __str__(self):
        return self.msg


bytesascii = b''
for x in range(256):
    bytesascii += bytes(bytearray((x,)))

code_strings = {
    2: b'01',
    3: b' ,.',
    10: b'0123456789',
    16: b'0123456789abcdef',
    32: b'abcdefghijklmnopqrstuvwxyz234567',
    58: b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
    256: b''.join([bytes(bytearray((x,))) for x in range(256)]),
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
        if not PY3:
            codestring += codebase[i]
        else:
            codestring += chr(codebase[i])
    return codestring


def _codestring_to_array(codestring, base):
    codestring = to_bytes(codestring)
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
    :type var: str, byte, bytearray, unicode
    :param base: specify variable format, i.e. 10 for decimal, 16 for hex
    :type base: int

    :return: Normalized var in string for Python 2, bytes for Python 3, decimal for base10
    """
    try:
        if PY3 and isinstance(var, str):
            var = var.encode('ISO-8859-1')
    except ValueError:
        try:
            var = var.encode('utf-8')
        except ValueError:
            raise EncodingError("Unknown character '%s' in input format" % var)

    if not PY3 and isinstance(var, unicode):
        try:
            var = str(var)
        except UnicodeEncodeError:
            try:
                var = var.encode('utf-8')
            except ValueError:
                raise EncodingError("Cannot convert this unicode to string format")

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
    :type base_from: int
    :param base_to: Base number or name for output. For example 2 for binary, 10 for decimal and 16 for hexadecimal
    :type base_to: int
    :param min_length: Minimal output length. Required for decimal, advised for all output to avoid leading zeros conversion problems.
    :type min_length: int
    :param output_even: Specify if output must contain a even number of characters. Sometimes handy for hex conversions.
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

    # Use binascii and int for standard conversions to speedup things
    if not min_length:
        if base_from == 256 and base_to == 16:
            return to_hexstring(inp)
        elif base_from == 16 and base_to == 256:
            return binascii.unhexlify(inp)
    if base_from == 16 and base_to == 10:
        return int(inp, 16)

    if output_even is None and base_to == 16:
        output_even = True

    if isinstance(inp, numbers.Number):
        input_dec = inp
    elif isinstance(inp, (str, list, bytes, bytearray)):
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
            if not pos * factor:
                if not PY3:
                    firstchar = code_str_from[0]
                else:
                    firstchar = chr(code_str_from[0]).encode('utf-8')
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
        if len(output) == 0:
            output = 0
        elif not PY3:
            output = ''.join(output)
        else:
            co = ''
            for c in output:
                co += chr(c)
            output = co
        # elif isinstance(output[0], bytes):
        #     output = b''.join(output)
        # elif isinstance(output[0], int):
        #     co = ''
        #     for c in output:
        #         co += chr(c)
        #     output = co
        # else:
        #     output = ''.join(output)
    if base_to == 10:
        return int(0) or (output != '' and int(output))
    if PY3 and base_to == 256 and not output_as_list:
        return output.encode('ISO-8859-1')
    else:
        return output


def varbyteint_to_int(byteint):
    """
    Convert CompactSize Variable length integer in byte format to integer.

    See https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer for specification

    >>> varbyteint_to_int(to_bytes('fd1027'))
    (10000, 3)

    :param byteint: 1-9 byte representation
    :type byteint: bytes, list, bytearray

    :return (int, int): tuple wit converted integer and size
    """
    if not isinstance(byteint, (bytes, list, bytearray)):
        raise EncodingError("Byteint must be a list or defined as bytes")
    if PY3 or isinstance(byteint, (list, bytearray)):
        ni = byteint[0]
    else:
        ni = ord(byteint[0])
    if ni < 253:
        return ni, 1
    if ni == 253:  # integer of 2 bytes
        size = 2
    elif ni == 254:  # integer of 4 bytes
        size = 4
    else:  # integer of 8 bytes
        size = 8
    return change_base(byteint[1:1+size][::-1], 256, 10), size + 1


def int_to_varbyteint(inp):
    """
    Convert integer to CompactSize Variable length integer in byte format.

    See https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer for specification

    >>> to_hexstring(int_to_varbyteint(10000))
    'fd1027'

    :param inp: Integer to convert
    :type inp: int

    :return: byteint: 1-9 byte representation as integer
    """
    if not isinstance(inp, numbers.Number):
        raise EncodingError("Input must be a number type")
    if inp < 0xfd:
        return struct.pack('B', inp)
    elif inp < 0xffff:
        return struct.pack('<cH', b'\xfd', inp)
    elif inp < 0xffffffff:
        return struct.pack('<cL', b'\xfe', inp)
    else:
        return struct.pack('<cQ', b'\xff', inp)

#
# def convert_der_sig(signature, as_hex=True):
#     """
#     Extract content from DER encoded string: Convert DER encoded signature to signature string.
#
#     :param signature: DER signature
#     :type signature: bytes
#     :param as_hex: Output as hexstring
#     :type as_hex: bool
#
#     :return bytes, str: Signature
#     """
#
#     if not signature:
#         return ""
#     if USE_FASTECDSA:
#         r, s = DEREncoder.decode_signature(bytes(signature))
#     else:
#         sg, junk = ecdsa.der.remove_sequence(signature)
#         if junk != b'':
#             raise EncodingError("Junk found in encoding sequence %s" % junk)
#         r, sg = ecdsa.der.remove_integer(sg)
#         s, sg = ecdsa.der.remove_integer(sg)
#     sig = '%064x%064x' % (r, s)
#     if as_hex:
#         return sig
#     else:
#         return binascii.unhexlify(sig)
#
#
# def der_encode_sig(r, s):
#     """
#     Create DER encoded signature string with signature r and s value.
#
#     :param r: r value of signature
#     :type r: int
#     :param s: s value of signature
#     :type s: int
#
#     :return bytes:
#     """
#     if USE_FASTECDSA:
#         return DEREncoder.encode_signature(r, s)
#     else:
#         rb = ecdsa.der.encode_integer(r)
#         sb = ecdsa.der.encode_integer(s)
#         return ecdsa.der.encode_sequence(rb, sb)


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
    check = address[-4:]
    pkh = address[:-4]
    checksum = double_sha256(pkh)[0:4]
    assert (check == checksum), "Invalid address, checksum incorrect"
    if as_hex:
        return change_base(pkh, 256, 16)[2:]
    else:
        return pkh[1:]

def grs_addr_base58_to_pubkeyhash(address, as_hex=False):
    """
    Convert Base58 encoded address to public key hash (Groestlcoin)

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
    check = address[-4:]
    pkh = address[:-4]
    #x = to_bytes(pkh, 'utf8')
    checksum = groestlcoin_hash.getHash(pkh, len(pkh))[0:4]
    assert (check == checksum), "Invalid GRS address, checksum incorrect"
    if as_hex:
        return change_base(pkh, 256, 16)[2:]
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
    else:
        hrp = bech[:pos]
    data = _codestring_to_array(bech[pos + 1:], 'bech32')
    hrp_expanded = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    if not _bech32_polymod(hrp_expanded + data) == 1:
        raise EncodingError("Bech polymod check failed")

    # Terra Station does BECH32 encoding in a slightly incompatible way, so detect and fix that if it comes
    if hrp == "terra":
        data = [0] + data[:-6]
    else:
        data = data[:-6]

    decoded = bytearray(convertbits(data[1:], 5, 8, pad=False))
    if decoded is None or len(decoded) < 2 or len(decoded) > 40:
        raise EncodingError("Invalid decoded data length, must be between 2 and 40")
    if data[0] > 16:
        raise EncodingError("Invalid decoded data length")
    if data[0] == 0 and len(decoded) not in [20, 32]:
        raise EncodingError("Invalid decoded data length, must be 20 or 32 bytes")
    prefix = b''
    if include_witver:
        datalen = len(decoded)
        prefix = bytearray([data[0] + 0x50 if data[0] else 0, datalen])
    if as_hex:
        return change_base(prefix + decoded, 256, 16)
    return prefix + decoded


def pubkeyhash_to_addr(pubkeyhash, prefix=None, encoding='base58'):
    """
    Convert public key hash to base58 encoded address

    Wrapper for the :func:`pubkeyhash_to_addr_base58` and :func:`pubkeyhash_to_addr_bech32` method

    :param pubkeyhash: Public key hash
    :type pubkeyhash: bytes, str
    :param prefix: Prefix version byte of network, default is bitcoin '\x00'
    :type prefix: str, bytes
    :param encoding: Encoding of address to calculate: base58 or bech32. Default is base58
    :type encoding: str

    :return str: Base58 or bech32 encoded address

    """
    if encoding == 'base58':
        if prefix is None:
            prefix = b'\x00'
        return pubkeyhash_to_addr_base58(pubkeyhash, prefix)
    elif encoding == 'bech32':
        if prefix is None:
            prefix = 'bc'
        return pubkeyhash_to_addr_bech32(pubkeyhash, prefix)
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
    # prefix = to_bytes(prefix)
    key = to_bytearray(prefix) + to_bytearray(pubkeyhash)
    addr256 = key + double_sha256(key)[:4]
    return change_base(addr256, 256, 58)


def pubkeyhash_to_addr_bech32(pubkeyhash, prefix='bc', witver=0, separator='1'):
    """
    Encode public key hash as bech32 encoded (segwit) address

    >>> pubkeyhash_to_addr_bech32('21c1bc695a56f47991e95ff26856e50f78d3c118')
    'bc1qy8qmc6262m68ny0ftlexs4h9paud8sgce3sf84'

    Format of address is prefix/hrp + seperator + bech32 address + checksum

    For more information see BIP173 proposal at https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki

    :param pubkeyhash: Public key hash
    :type pubkeyhash: str, bytes, bytearray
    :param prefix: Address prefix or Human-readable part. Default is 'bc' an abbreviation of Bitcoin. Use 'tb' for testnet.
    :type prefix: str
    :param witver: Witness version between 0 and 16
    :type witver: int
    :param separator: Separator char between hrp and data, should always be left to '1' otherwise its not standard.
    :type separator: str

    :return str: Bech32 encoded address
    """

    if not isinstance(pubkeyhash, bytearray):
        pubkeyhash = bytearray(to_bytes(pubkeyhash))

    if len(pubkeyhash) not in [20, 32]:
        if int(pubkeyhash[0]) != 0:
            witver = int(pubkeyhash[0]) - 0x50
        pubkeyhash = pubkeyhash[2:]

    data = [witver] + convertbits(pubkeyhash, 8, 5)

    # Expand the HRP into values for checksum computation
    hrp_expanded = [ord(x) >> 5 for x in prefix] + [0] + [ord(x) & 31 for x in prefix]
    polymod = _bech32_polymod(hrp_expanded + data + [0, 0, 0, 0, 0, 0]) ^ 1
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
    :type data: list, bytearray
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
        if not PY3 and isinstance(value, str):
            value = int(value, 16)
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

    >>> to_hexstring(varstr(to_bytes('5468697320737472696e67206861732061206c656e677468206f66203330')))
    '1e5468697320737472696e67206861732061206c656e677468206f66203330'

    :param string: String input
    :type string: bytes, str

    :return bytes: varstring
    """
    s = normalize_var(string)
    if s == b'\0':
        return s
    return int_to_varbyteint(len(s)) + s


def to_bytearray(string):
    """
    Convert String, Unicode or Bytes to Python 2 and 3 compatible ByteArray

    :param string: String, Unicode, Bytes or ByteArray
    :type string: bytes, str, bytearray

    :return bytearray:
    """
    if isinstance(string, TYPE_TEXT):
        try:
            string = binascii.unhexlify(string)
        except (TypeError, binascii.Error):
            pass
    return bytearray(string)


def to_bytes(string, unhexlify=True):
    """
    Convert String, Unicode or ByteArray to Bytes

    :param string: String to convert
    :type string: str, unicode, bytes, bytearray
    :param unhexlify: Try to unhexlify hexstring
    :type unhexlify: bool

    :return: Bytes var
    """
    s = normalize_var(string)
    if unhexlify:
        try:
            s = binascii.unhexlify(s)
            return s
        except (TypeError, binascii.Error):
            pass
    return s


def to_hexstring(string):
    """
    Convert Bytes or ByteArray to hexadecimal string

    >>> to_hexstring('\x12\xaa\xdd')
    '12aadd'

    :param string: Variable to convert to hex string
    :type string: bytes, bytearray, str

    :return: hexstring
    """
    string = normalize_var(string)

    if isinstance(string, (str, bytes)):
        try:
            binascii.unhexlify(string)
            if PY3:
                return str(string, 'ISO-8859-1')
            else:
                return string
        except (TypeError, binascii.Error):
            pass

    s = binascii.hexlify(string)
    if PY3:
        return str(s, 'ISO-8859-1')
    else:
        return s


def normalize_string(string):
    """
    Normalize a string to the default NFKD unicode format
    See https://en.wikipedia.org/wiki/Unicode_equivalence#Normalization

    :param string: string value
    :type string: bytes, bytearray, str

    :return: string
    """
    if isinstance(string, str if sys.version < '3' else bytes):
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


def hash160(string):
    """
    Creates a RIPEMD-160 + SHA256 hash of the input string

    :param string: Script
    :type string: bytes

    :return bytes: RIPEMD-160 hash of script
    """
    return ripemd160(hashlib.sha256(string).digest())


def bip38_decrypt(encrypted_privkey, passphrase):
    """
    BIP0038 non-ec-multiply decryption. Returns WIF private key.
    Based on code from https://github.com/nomorecoin/python-bip38-testing
    This method is called by Key class init function when importing BIP0038 key.

    :param encrypted_privkey: Encrypted private key using WIF protected key format
    :type encrypted_privkey: str
    :param passphrase: Required passphrase for decryption
    :type passphrase: str

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
    if isinstance(passphrase, str) and sys.version_info > (3,):
        passphrase = passphrase.encode('utf-8')
    addresshash = d[0:4]
    d = d[4:-4]
    key = scrypt.hash(passphrase, addresshash, 16384, 8, 8, 64)
    derivedhalf1 = key[0:32]
    derivedhalf2 = key[32:64]
    encryptedhalf1 = d[0:16]
    encryptedhalf2 = d[16:32]
    aes = pyaes.AESModeOfOperationECB(derivedhalf2)
    decryptedhalf2 = aes.decrypt(encryptedhalf2)
    decryptedhalf1 = aes.decrypt(encryptedhalf1)
    priv = decryptedhalf1 + decryptedhalf2
    priv = binascii.unhexlify('%064x' % (int(binascii.hexlify(priv), 16) ^ int(binascii.hexlify(derivedhalf1), 16)))
    # if compressed:
    #     # FIXME: This works but does probably not follow the BIP38 standards (was before: priv = b'\0' + priv)
    #     priv += b'\1'
    return priv, addresshash, compressed


def bip38_encrypt(private_hex, address, passphrase, flagbyte=b'\xe0'):
    """
    BIP0038 non-ec-multiply encryption. Returns BIP0038 encrypted private key
    Based on code from https://github.com/nomorecoin/python-bip38-testing

    :param private_hex: Private key in hex format
    :type private_hex: str
    :param address: Address string
    :type address: str
    :param passphrase: Required passphrase for encryption
    :type passphrase: str
    :param flagbyte: Flagbyte prefix for WIF
    :type flagbyte: bytearray

    :return str: BIP38 passphrase encrypted private key
    """
    if isinstance(address, str) and sys.version_info > (3,):
        address = address.encode('utf-8')
    if isinstance(passphrase, str) and sys.version_info > (3,):
        passphrase = passphrase.encode('utf-8')
    addresshash = double_sha256(address)[0:4]
    key = scrypt.hash(passphrase, addresshash, 16384, 8, 8, 64)
    derivedhalf1 = key[0:32]
    derivedhalf2 = key[32:64]
    aes = pyaes.AESModeOfOperationECB(derivedhalf2)
    encryptedhalf1 = aes.encrypt(binascii.unhexlify('%0.32x' % (int(private_hex[0:32], 16) ^
                                                                int(binascii.hexlify(derivedhalf1[0:16]), 16))))
    encryptedhalf2 = aes.encrypt(binascii.unhexlify('%0.32x' % (int(private_hex[32:64], 16) ^
                                                                int(binascii.hexlify(derivedhalf1[16:32]), 16))))
    encrypted_privkey = b'\x01\x42' + flagbyte + addresshash + encryptedhalf1 + encryptedhalf2
    encrypted_privkey += double_sha256(encrypted_privkey)[:4]
    return change_base(encrypted_privkey, 256, 58)
