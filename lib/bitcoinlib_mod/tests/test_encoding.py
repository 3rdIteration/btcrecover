# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    Unit Tests for Key, Encoding and Mnemonic Class
#    © 2016 - 2018 October - 1200 Web Development <http://1200wd.com/>
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

import unittest

from bitcoinlib.encoding import *
from bitcoinlib.encoding import _bech32_polymod, _codestring_to_array


class TestEncodingMethodsChangeBase(unittest.TestCase):

    def test_change_base_hex_bit(self):
        self.assertEqual('11110001', change_base('F1', 16, 2))

    def test_change_base_hex_bit_lowercase(self):
        self.assertEqual('10100011', change_base('a3', 16, 2))

    def test_change_base_bit_hex(self):
        self.assertEqual('f1', change_base('11110001', 2, 16))

    def test_change_base_hex_dec(self):
        self.assertEqual(61441, change_base('f001', 16, 10))

    def test_change_base_dec_hex(self):
        self.assertEqual('f001', change_base('61441', 10, 16, 4))

    def test_change_base_b58_dec(self):
        self.assertEqual(5283658277747592673868818217239156372404875337009783985623,
                         change_base('1LeNnaRtV52nNtZXvtw6PaGKpk46hU1Xmx', 58, 10))

    def test_change_base_b58_bin(self):
        self.assertEqual(b'\x00\xd7{\xf7b\x8c\x19\xe6\x99\x01\r)xz)\xaf\xcf\x8e\x92\xadZ\x05=U\xd7',
                         change_base('1LeNnaRtV52nNtZXvtw6PaGKpk46hU1Xmx', 58, 256))

    def test_change_base_b58_hex(self):
        self.assertEqual('00D77BF7628C19E699010D29787A29AFCF8E92AD5A053D55D7',
                         change_base('1LeNnaRtV52nNtZXvtw6PaGKpk46hU1Xmx', 58, 16).upper())

    def test_change_base_dec_b58(self):
        self.assertEqual('LeNnaRtV52nNtZXvtw6PaGKpk46hU1Xmx',
                         change_base('5283658277747592673868818217239156372404875337009783985623', 10, 58, 33))

    def test_change_base_padding(self):
        self.assertEqual('0011', change_base(3, 10, 2, 4))

    def test_change_base_bin_b58(self):
        self.assertEqual('16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM',
                         change_base("\x00\x01\tfw`\x06\x95=UgC\x9e^9\xf8j\r';\xee\xd6\x19g\xf6", 256, 58))

    def test_change_base_hex_bin(self):
        self.assertEqual(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f',
                         change_base("000102030405060708090a0b0c0d0e0f", 16, 256))

    def test_change_base32_base3(self):
        self.assertEqual(',   . .. ., .   ,. .,  ,. .., . ,..  .,. ,..,, . . .,.,..  ,...,, ,, .,.,,,.,,,...  . , .,,,'
                         '. ...,, .,.,.  ,,..,,,,.', change_base("Oh what a fun we have !", 256, 3))

    # Tests for bug with leading zero's
    def test_change_base_leading_zeros(self):
        self.assertEqual(b'\x00\x00\x03', change_base("000003", 16, 256))

    def test_change_base_leading_zeros2(self):
        self.assertEqual('1L', change_base('0013', 16, 58))

    def test_change_base_leading_zeros3(self):
        self.assertEqual('1L', change_base('013', 16, 58))

    def test_change_base_leading_zeros4(self):
        self.assertEqual(b'\x04G\x81', change_base('044781', 16, 256))

    def test_change_base_leading_zeros_binascii(self):
        y = 251863285056225027460663457133976813779860093019161001622713253221998044380
        self.assertEqual(64, len(change_base(y, 10, 16, 64)))

    def test_change_base_zero_int(self):
        self.assertEqual(0, change_base(b'\0', 256, 10))

    def test_change_base_encodings_bytes(self):
        self.assertEqual('4c52127a72fb42b82439ab18697dcfcfb96ac63ba8209833b2e29f2302b8993f45e743412d65c7a571da70259d4'
                         'f6795e98af20e6e57603314a662a49c198199',
                         change_base(b'LR\x12zr\xfbB\xb8$9\xab\x18i}\xcf\xcf\xb9j\xc6;\xa8 \x983\xb2\xe2\x9f#\x02\xb8'
                                     b'\x99?E\xe7CA-e\xc7\xa5q\xdap%\x9dOg\x95\xe9\x8a\xf2\x0enW`3\x14\xa6b\xa4\x9c'
                                     b'\x19\x81\x99', 256, 16))

    def test_change_base_encodings_utf8(self):
        self.assertEqual('e782ba20e5ae8b20e69ab420e6b2bb20e4bcaf20e58f8a20e7819820e586b620e5bf9920e9808320e6b99820e8'
                         '898720e4be8b20e8ae9320e5bfa0',
                         change_base("為 宋 暴 治 伯 及 灘 冶 忙 逃 湘 艇 例 讓 忠", 256, 16))

    def test_change_base_list(self):
        self.assertEqual('00124c', change_base([b'\0', b'\x12', b'L'], 256, 16, 6))

    def test_change_base_bytes_as_string(self):
        s = '\xc8\xe9\t\x96\xc7\xc6\x08\x0e\xe0b\x84`\x0chN\xd9\x04\xd1L\\'
        self.assertEqual('c8e90996c7c6080ee06284600c684ed904d14c5c', change_base(s, 256, 16))

    def test_change_base_decimal_input_lenght_exception(self):
        self.assertRaisesRegexp(EncodingError, "For a decimal input a minimum output length is required",
                                change_base, 100, 10, 2)

    def test_encoding_exceptions(self):
        self.assertRaisesRegexp(EncodingError, "Unknown input format {}",
                                change_base, {}, 4, 2)
        if PY3:
            self.assertRaisesRegexp(EncodingError, "Byteint must be a list or defined as bytes",
                                    varbyteint_to_int, 'fd1027')
        self.assertRaisesRegexp(EncodingError, "Input must be a number type",
                                int_to_varbyteint, '1000')
        self.assertRaisesRegexp(TypeError, "String value expected", normalize_string, 100)
        self.assertRaisesRegexp(EncodingError, "Encoding base32 not supported", pubkeyhash_to_addr, '123',
                                encoding='base32')
        addr = 'qc1qy8qmc6262m68ny0ftlexs4h9paud8sgce3sf84'
        self.assertRaisesRegexp(EncodingError, "Invalid bech32 address. Prefix 'qc', prefix expected is 'bc'",
                                addr_bech32_to_pubkeyhash, addr, prefix='bc')


class TestEncodingMethodsAddressConversion(unittest.TestCase):

    def test_address_to_pkh_conversion_1(self):
        self.assertEqual('13d215d212cd5188ae02c5635faabdc4d7d4ec91',
                         addr_to_pubkeyhash('12ooWd8Xag7hsgP9PBPnmyGe36VeUrpMSH', True))

    def test_address_to_pkh_conversion_2(self):
        self.assertEqual('00' * 20,
                         addr_to_pubkeyhash('1111111111111111111114oLvT2', True))

    def test_address_to_pkh_conversion_3(self):
        self.assertEqual(b'\xFF' * 20,
                         addr_to_pubkeyhash('1QLbz7JHiBTspS962RLKV8GndWFwi5j6Qr', False))

    def test_pkh_to_addr_conversion_1(self):
        self.assertEqual('12ooWd8Xag7hsgP9PBPnmyGe36VeUrpMSH',
                         pubkeyhash_to_addr('13d215d212cd5188ae02c5635faabdc4d7d4ec91'))

    def test_pkh_to_addr_conversion_2(self):
        self.assertEqual('11111111111111111111111111114oLvT2',
                         pubkeyhash_to_addr('00' * 20))

    def test_address_to_pkh_bech32(self):
        addr = 'bc1qy8qmc6262m68ny0ftlexs4h9paud8sgce3sf84'
        self.assertEqual(addr_to_pubkeyhash(addr), b'!\xc1\xbciZV\xf4y\x91\xe9_\xf2hV\xe5\x0fx\xd3\xc1\x18')
        self.assertEqual(addr_to_pubkeyhash(addr, as_hex=True), '21c1bc695a56f47991e95ff26856e50f78d3c118')

    def test_pkh_to_bech32_address(self):
        addr = pubkeyhash_to_addr('45d093a97d5710c80363c69618e826efad42edb1', encoding='bech32')
        self.assertEqual(addr, 'bc1qghgf82ta2ugvsqmrc6tp36pxa7k59md3czjhjc')


class TestEncodingMethodsStructures(unittest.TestCase):

    def test_varbyteint_to_int_1(self):
        self.assertEqual(100, varbyteint_to_int(b'd')[0])

    def test_varbyteint_to_int_2(self):
        self.assertEqual(254, varbyteint_to_int(b'\xfe\xfe\x00')[0])

    def test_varbyteint_to_int_3(self):
        self.assertEqual(18440744073009551600, varbyteint_to_int(b'\xff\xf0\xd8\x9f\xf9\x07\xaf\xea\xff')[0])

    def test_int_to_varbyteint_1(self):
        self.assertEqual(b'd', int_to_varbyteint(100))

    def test_int_to_varbyteint_2(self):
        self.assertEqual(b'\xfd\xfd\x00', int_to_varbyteint(253))

    def test_int_to_varbyteint_3(self):
        self.assertEqual(b'\xff\xff\xff\xff\xff\xff\xff\xff\xff', int_to_varbyteint(18446744073709551615))

    def test_varstr(self):
        self.assertEqual(b'\x1eThis string has a length of 30',
                         varstr('This string has a length of 30'))

    def test_convert_der_sig(self):
        sig = b'0E\x02!\x00\xe7\x1a\x8d\xd8>y\xfb\xd6/r\xa3\xd0\xd8\xa8\x1f\xdd\xbaS[\xd0\xf0\x88\xfa\x8b\xe1L' \
              b'\xd3F\x7f\xe5\x17\xae\x02 _l\xa4\x89LS\xcd\x8em&\xf7\x99uN\xb6\xfc\x0e\x86\xf6\x12\xd6\xdejL|' \
              b'\x07\xdcX \xa0\xe5\x18'
        self.assertEqual('e71a8dd83e79fbd62f72a3d0d8a81fddba535bd0f088fa8be14cd3467fe517ae5f6ca4894c53cd8e6d26f'
                         '799754eb6fc0e86f612d6de6a4c7c07dc5820a0e518', convert_der_sig(sig))

    def test_to_bytes_hex(self):
        self.assertEqual(b'\xde\xad\xbe\xef', to_bytes('deadbeef'))

    def test_to_bytes_nohex(self):
        self.assertEqual(b'deadbeefnohex', to_bytes('deadbeefnohex'))

    def test_to_bytes_nounhexlify(self):
        self.assertEqual(b'deadbeef', to_bytes('deadbeef', unhexlify=False))

    def test_to_bytes_unicode(self):
        self.assertEqual(b'\x07\xdcX \xa0\xe5\x18!]!,\xd5\x18\x8a\xe0,V5\xfa\xab',
                         to_bytes(u'07dc5820a0e518215d212cd5188ae02c5635faab'))

    def test_to_bytes_byteshex(self):
        self.assertEqual(b'\x07\xdcX \xa0\xe5\x18!]!,\xd5\x18\x8a\xe0,V5\xfa\xab',
                         to_bytes(b'07dc5820a0e518215d212cd5188ae02c5635faab'))

    def test_to_bytes_bytearray(self):
        self.assertEqual(bytearray(b'\x06\x07<F\x00\xff   \xc8\x1b'),
                         to_bytes(bytearray([6, 7, 60, 70, 0, 255, 32, 32, 32, 200, 27])))

    def test_to_hexstring_string(self):
        self.assertEqual('deadbeef', to_hexstring('deadbeef'))

    def test_to_hexstring_bytes(self):
        self.assertEqual('707974686f6e6973636f6f6c', to_hexstring(b'pythoniscool'))

    def test_to_hexstring_bytes2(self):
        self.assertEqual('07dc5820a0e518215d212cd5188ae02c5635faab',
                         to_hexstring(b'\x07\xdcX \xa0\xe5\x18!]!,\xd5\x18\x8a\xe0,V5\xfa\xab'))

    def test_to_hexstring_unicode(self):
        self.assertEqual('07dc5820a0e518215d212cd5188ae02c5635faab',
                         to_hexstring(u'07dc5820a0e518215d212cd5188ae02c5635faab'))

    def test_to_hexstring_bytearray(self):
        self.assertEqual('06073c4600ff202020c81b',
                         to_hexstring(bytearray([6, 7, 60, 70, 0, 255, 32, 32, 32, 200, 27])))

    def test_der_encode_sig(self):
        r = 80828100789555555332401870818771238079532314371107341426356071258591122886343
        s = 15674820848044112551623338734376985640551839688984719714434052277382938010325
        der_sig = '3045022100b2b31575f8536b284410d01217f688be3a9faf4ba0ba3a9093f983e40d630' \
                  'ec7022022a7a25b01403cff0d00b3b853d230f8e96ff832b15d4ccc75203cb65896a2d5'
        self.assertEqual(to_hexstring(der_encode_sig(r, s)), der_sig)


VALID_CHECKSUM = [
    "A12UEL5L",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
]

INVALID_CHECKSUM = [
    " 1nwldj5",
    "\x7F" + "1axkwrx",
    "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
    "pzry9x0s0muk",
    "1pzry9x0s0muk",
    "x1b4n0q5v",
    "li1dgmt3",
    "de1lg7wt\xff",
]

VALID_ADDRESS = [
    ["BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "0014751e76e8199196d454941c45d1b3a323f1433bd6"],
    ["tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
     "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"],
    ["bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
     "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"],
    ["BC1SW50QA3JX3S", "6002751e"],
    ["bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj", "5210751e76e8199196d454941c45d1b3a323"],
    ["tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
     "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"],
]

INVALID_ADDRESS = [
    "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
    "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
    "bc1rw5uspcuh",
    "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
    "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
    "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
    "bc1gmk9yu",
]

INVALID_ADDRESS_ENC = [
    ("BC", 0, 20),
    ("bc", 0, 21),
    ("bc", 17, 32),
    ("bc", 1, 1),
    ("bc", 16, 41),
]


class TestEncodingBech32SegwitAddresses(unittest.TestCase):
    """
    Reference tests for bech32 segwit adresses

    Copyright (c) 2017 Pieter Wuille
    Source: https://github.com/sipa/bech32/tree/master/ref/python
    """

    def test_valid_checksum(self):
        """Test checksum creation and validation."""
        for test in VALID_CHECKSUM:
            pos = test.rfind('1')
            test = test.lower()
            hrp = test[:pos]
            data = _codestring_to_array(test[pos + 1:], 'bech32')
            hrp_expanded = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
            self.assertEqual(_bech32_polymod(hrp_expanded + data), 1, msg="Invalid checksum for address %s" % test)
            test = test[:pos+1] + chr(ord(test[pos + 1]) ^ 1) + test[pos+2:]
            try:
                self.assertFalse(addr_bech32_to_pubkeyhash(test, hrp))
            except EncodingError:
                continue

    def test_invalid_checksum(self):
        """Test validation of invalid checksums."""
        for test in INVALID_CHECKSUM:
            try:
                pos = test.rfind('1')
                hrp = test[:pos]
                self.assertRaises(EncodingError, addr_bech32_to_pubkeyhash, test, hrp)
            except EncodingError as e:
                self.assertIn("not found in codebase", e.msg)

    def test_valid_address(self):
        """Test whether valid addresses decode to the correct output."""
        for (address, hexscript) in VALID_ADDRESS:
            try:
                scriptpubkey = addr_bech32_to_pubkeyhash(address, include_witver=True)
            except EncodingError:
                scriptpubkey = addr_bech32_to_pubkeyhash(address, prefix='tb', include_witver=True)
            self.assertEqual(scriptpubkey, binascii.unhexlify(hexscript))
            addr = pubkeyhash_to_addr_bech32(scriptpubkey, address[:2].lower())
            self.assertEqual(address.lower(), addr)

    def test_invalid_address(self):
        """Test whether invalid addresses fail to decode."""
        for test in INVALID_ADDRESS:
            self.assertRaises(EncodingError, addr_bech32_to_pubkeyhash, "bc", test)
            self.assertRaises(EncodingError, addr_bech32_to_pubkeyhash, "tb", test)


class TestEncodingConfig(unittest.TestCase):

    def test_config_opcodes(self):
        self.assertEqual(opcode('OP_CHECKLOCKTIMEVERIFY'), b'\xb1')
        self.assertEqual(opcode('OP_CHECKLOCKTIMEVERIFY', as_bytes=False), 177)


if __name__ == '__main__':
    unittest.main()
