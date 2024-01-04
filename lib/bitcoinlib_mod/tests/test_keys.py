# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    Unit Tests for Key, Encoding and Mnemonic Class
#    © 2017-2018 July - 1200 Web Development <http://1200wd.com/>
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
import unittest
import json

from bitcoinlib.networks import NETWORK_DEFINITIONS
from bitcoinlib.keys import *

# Number of bulktests for generation of private, public keys and HDKeys. Set to 0 to disable
# WARNING: Can be slow for a larger number of tests
BULKTESTCOUNT = 10


class TestKeyClasses(unittest.TestCase):

    def test_keys_classes_dunder_methods(self):
        pk = 'xprv9s21ZrQH143K4EDmQNMBqXwUTcrRoUctKkTegGsaBcMLnR1fJkMjVSRwVswjHzJspfWCUwzge1F521cY4wfWD54tzXVUqeo' \
             'TFkZo17HiK2y'
        k = HDKey(pk)
        self.assertEqual(str(k), 'd3caaca97fbba3d4ebd87e855c6e05080b0ac9118bd886c0f575d79940bd6eb4')
        self.assertEqual(int(k), 95796105828208927954168018443072630832764875640480247096632116413925408206516)
        k2 = HDKey(pk)
        self.assertTrue(k == k2)
        pubk2 = HDKey(k.wif_public())
        self.assertEqual(str(pubk2), '03dc86716b2be27a0575558bac73279290ac22c3ea0240e42a2152d584f2b4006b')
        self.assertTrue(k.public() == pubk2)
        
    def test_dict_and_json_outputs(self):
        k = HDKey()
        k.address(script_type='p2wsh', encoding='bech32')
        self.assertTrue(isinstance(json.loads(k.address_obj.as_json()), dict))
        self.assertTrue(isinstance(k.address_obj.as_dict(), dict))
        self.assertTrue(isinstance(json.loads(k.as_json()), dict))
        self.assertTrue(isinstance(k.as_dict(), dict))
        k = Key()
        self.assertTrue(isinstance(json.loads(k.as_json()), dict))
        self.assertTrue(isinstance(k.as_dict(), dict))
        self.assertTrue(isinstance(json.loads(k.as_json(include_private=True)), dict))
        self.assertTrue(isinstance(k.as_dict(include_private=True), dict))

    def test_path_expand(self):
        self.assertListEqual(path_expand([0]), ['m', "44'", "0'", "0'", '0', '0'])
        self.assertListEqual(path_expand([10, 20]), ['m', "44'", "0'", "0'", '10', '20'])
        self.assertListEqual(path_expand([10, 20], witness_type='segwit'), ['m', "84'", "0'", "0'", '10', '20'])
        self.assertListEqual(path_expand([], witness_type='p2sh-segwit'), ['m', "49'", "0'", "0'", '0', '0'])
        self.assertListEqual(path_expand([99], witness_type='p2sh-segwit', multisig=True),
                             ['m', "48'", "0'", "0'", "1'", '0', '99'])
        self.assertRaisesRegexp(BKeyError, "Invalid path provided. Path should be shorter than 6 items.",
                                path_expand, [0, 1, 2, 3, 4, 5, 6])
        self.assertRaisesRegexp(BKeyError, "Please provide path as list with at least 1 item",
                                path_expand, 5)


class TestGetKeyFormat(unittest.TestCase):

    def test_format_wif_uncompressed(self):
        key = '5Hwgr3u458GLafKBgxtssHSPqJnYoGrSzgQsPwLFhLNYskDPyyA'
        self.assertEqual('wif', get_key_format(key)['format'])

    def test_format_wif_compressed(self):
        key = 'L2Q5U2zjxeoSf3dcNZsk19Z9bGr7RMeCTigvv7gJNJQq9uzQnF47'
        self.assertEqual('wif_compressed', get_key_format(key)['format'])

    def test_format_bin_uncompressed(self):
        key = b'\x04\xa8\x82\xd4\x14\xe4x\x03\x9c\xd5\xb5*\x92\xff\xb1=\xd5\xe6\xbdE\x15It9\xdf\xfdi\x1a\x0f\x12\xaf' \
              b'\x95u\xfa4\x9bV\x94\xed1U\xb16\xf0\x9ec\x97Z\x17\x00\xc9\xf4\xd4\xdf\x84\x93#\xda\xc0l\xf3\xbddX\xcd'
        self.assertEqual('bin', get_key_format(key)['format'])

    def test_format_hdkey_private(self):
        key = 'xprv9s21ZrQH143K2JF8RafpqtKiTbsbaxEeUaMnNHsm5o6wCW3z8ySyH4UxFVSfZ8n7ESu7fgir8imbZKLYVBxFPND1pniTZ81v' \
              'Kfd45EHKX73'
        self.assertEqual('hdkey_private', get_key_format(key)['format'])

    def test_format_hdkey_public(self):
        key = 'xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3' \
              'DChhqPQBnU'
        self.assertEqual('hdkey_public', get_key_format(key)['format'])

    def test_format_hdkey_private_litecoin(self):
        key = 'ttpv96BtqegdxXceS41gmguxRWjtFdG11XqquvaPcpionXB8oQ2zkXYY9vCvykdfLEeeihx1SxP3t7ranmqLHKbmgfiMFR7967urhq' \
              'oAq5eBHur'
        self.assertEqual('hdkey_private', get_key_format(key)['format'])
        self.assertIn('litecoin_testnet', get_key_format(key)['networks'])

    def test_format_hdkey_mnemonic(self):
        self.assertEqual(get_key_format('abandon car zoo')['format'], 'mnemonic')

    def test_format_key_exceptions(self):
        self.assertRaisesRegexp(BKeyError, "Key empty, please specify a valid key", get_key_format, '')
        self.assertRaisesRegexp(BKeyError, "Attribute 'is_private' must be False or True", get_key_format,
                                '666368e477a8ddd46808c527cc3c506719bb3f52a927b6c13532984b714b56ad', 3)


class TestPrivateKeyConversions(unittest.TestCase):

    def setUp(self):
        self.privatekey_hex = 'b954f71933986e3de76d3a94454dc52ec082c662ba67ca3ba48ff72bc2704a58'
        self.k = Key(self.privatekey_hex, compressed=True)
        self.ku = Key(self.privatekey_hex, compressed=False)

    def test_private_key_conversions_dec(self):
        self.assertEqual(83827997552125623280808720137320612316470870230953489181279239295529837939288,
                         self.k.secret)

    def test_private_key_conversions_hex(self):
        self.assertEqual('b954f71933986e3de76d3a94454dc52ec082c662ba67ca3ba48ff72bc2704a58', self.k.private_hex)

    def test_private_key_conversions_wif_uncompressed(self):
        self.assertEqual('5KDudqswBNJ8mf2k7Gxn72UknDBh7GFjj9NGJrY22SY1hjKS1gF', self.ku.wif())

    def test_private_key_conversions_wif(self):
        self.assertEqual('L3RyKcjp8kzdJ6rhGhTC5bXWEYnC2eL3b1vrZoduXMht6m9MQeHy', self.k.wif())
        if not PY3:
            return
        self.assertEqual('XHVtmt8BSSd5MRs5JTT4apiX9a3mUSwHxbGm6Ky6qiyyVvFRhmU7', self.k.wif(prefix='cc'))
        self.assertEqual('XHVtmt8BSSd5MRs5JTT4apiX9a3mUSwHxbGm6Ky6qiyyVvFRhmU7', self.k.wif(prefix=b'\xcc'))

    def test_private_key_public(self):
        self.assertEqual('034781e448a7ff0e1b66f1a249b4c952dae33326cf57c0a643738886f4efcd14d5', self.k.public_hex)

    def test_private_key_public_uncompressed(self):
        self.assertEqual('044781e448a7ff0e1b66f1a249b4c952dae33326cf57c0a643738886f4efcd14d57a380bc32c26f46e733c'
                         'd991064c2e7f7d532b9c9ca825671a8809ab6876c78b', self.ku.public_uncompressed_hex)


class TestPrivateKeyImport(unittest.TestCase):

    def test_private_key_import_key(self):
        self.k = Key(61876261089097932796193024729035977913579848833009517639587741086858579422075)
        self.assertEqual('L1odb1uUozbfK2NrsMyhJfvRsxGM2AxixgPL8vG9BUBnE6W1VyTX', self.k.wif())

    def test_private_key_import_key_str(self):
        self.k = Key('61876261089097932796193024729035977913579848833009517639587741086858579422075')
        self.assertEqual('L1odb1uUozbfK2NrsMyhJfvRsxGM2AxixgPL8vG9BUBnE6W1VyTX', self.k.wif())

    def test_private_key_import_key_hex_compressed(self):
        self.k = Key('1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD01')
        self.assertEqual('KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ', self.k.wif())

    def test_private_key_import_key_byte(self):
        pk = b':\xbaAb\xc7%\x1c\x89\x12\x07\xb7G\x84\x05Q\xa7\x199\xb0\xde\x08\x1f\x85\xc4\xe4L\xf7\xc1>A\xda\xa6\x01'
        self.k = Key(pk)
        self.assertEqual('KyBsPXxTuVD82av65KZkrGrWi5qLMah5SdNq6uftawDbgKa2wv6S', self.k.wif())

    def test_private_key_import_hex(self):
        pk = '4781e448a7ff0e1b66f1a249b4c952dae33326cf57c0a643738886f4efcd14d57a380bc32c26f46e733cd' \
             '991064c2e7f7d532b9c9ca825671a8809ab6876c78b'
        k = Key(pk)
        self.assertEqual('f93677c417d4750c7a5806f849739265cc46b8a9', to_hexstring(k.hash160))

    def test_private_key_import_key_bytearray(self):
        pk = bytearray(b':\xbaAb\xc7%\x1c\x89\x12\x07\xb7G\x84\x05Q\xa7\x199\xb0\xde\x08\x1f\x85\xc4\xe4L\xf7\xc1>'
                       b'A\xda\xa6\x01')
        self.k = Key(pk)
        self.assertEqual('KyBsPXxTuVD82av65KZkrGrWi5qLMah5SdNq6uftawDbgKa2wv6S', self.k.wif())

    def test_private_key_import_wif(self):
        self.k = Key('L1odb1uUozbfK2NrsMyhJfvRsxGM2AxixgPL8vG9BUBnE6W1VyTX')
        self.assertEqual('88ccb90221d9b44df8dd317307de2d6019c9c7448dccaa1e45bae77e5a022b7b', self.k.private_hex)

    def test_private_key_import_wif_uncompressed(self):
        self.k = Key('5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS')
        self.assertFalse(self.k.compressed)
        self.assertEqual('c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a', self.k.private_hex)

    def test_private_key_import_generate_random(self):
        self.k = Key()
        self.assertIn(self.k.wif()[0], ['K', 'L'])
        self.assertEqual(52, len(self.k.wif()))

    def test_private_key_import_error_1(self):
        self.assertRaisesRegexp(BKeyError, "Invalid checksum, not a valid WIF key",
                                Key, 'L1odb1uUozbfK2NrsMyhJfvRsxGM2axixgPL8vG9BUBnE6W1VyTX')

    def test_private_key_import_error_2(self):
        self.assertRaisesRegexp(BKeyError, "Unrecognised key format",
                                Key, 'M1odb1uUozbfK2NrsMyhJfvRsxGM2AxixgPL8vG9BUBnE6W1VyTX')

    def test_private_key_import_testnet(self):
        self.k = Key('92Pg46rUhgTT7romnV7iGW6W1gbGdeezqdbJCzShkCsYNzyyNcc', 'testnet')
        self.assertEqual('92Pg46rUhgTT7romnV7iGW6W1gbGdeezqdbJCzShkCsYNzyyNcc', self.k.wif())
        self.assertEqual('mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn', self.k.address())


class TestPublicKeyConversion(unittest.TestCase):

    def setUp(self):
        self.publickey_hex = '044781e448a7ff0e1b66f1a249b4c952dae33326cf57c0a643738886f4efcd14d57a380bc32c26f46e733cd' \
                             '991064c2e7f7d532b9c9ca825671a8809ab6876c78b'
        self.K = Key(self.publickey_hex)
        self.KC = Key('034781e448a7ff0e1b66f1a249b4c952dae33326cf57c0a643738886f4efcd14d5')

    def test_public_key_get_address_uncompressed(self):
        self.assertEqual('12ooWDQp6mujkVpEWHdfHmfM4rU17bokWw', self.K.address_uncompressed())

    def test_public_key_get_address(self):
        self.assertEqual('1P2X35YnajqoBXtPpQXJzV1QMnqSZQsn82', self.KC.address())

    def test_public_key_get_point(self):
        self.assertEqual((32343711077743629729728681292399790965391040816412086995020432364076041835733,
                          55281192143835269607479311758661973079027103826274522268778194868406595274635),
                         self.K.public_point())

    def test_public_key_get_hash160_uncompressed(self):
        self.assertEqual('13d21450578cd8f8645d2e56e684deb7cd77864b', to_hexstring(self.K.hash160))

    def test_public_key_get_hash160(self):
        self.assertEqual('f19c417fd97e364afb06e1edd2c0e6a7ecf1af00', to_hexstring(self.KC.hash160))

    def test_public_key_try_private(self):
        self.assertFalse(self.K.private_hex)

    def test_public_key_import_error(self):
        self.assertRaisesRegexp(BKeyError, "Unrecognised key format",
                                Key, '064781e448a7ff0e1b66f1a249b4c952dae33326cf57c0a643738886f4efcd14d5')

    def test_litecoin_private_key(self):
        KC_LTC = Key('0bc295d0b20b0e2ff6ab2c4982583d4f84936a17689aaca031a803dcf4a3b139', network='litecoin')
        self.assertEqual(KC_LTC.wif(), 'T3SqWmDzttRHnfypMorvRgPpG48UH1ZE7apvoLUGTDidKtf3Ts2u')
        self.assertEqual(KC_LTC.address(), 'LeA97dLDPrjRsPhwrQJxUWJUPErGo516Ct')
        self.assertEqual(KC_LTC.public_hex, '02967b4671563ceeab16f22c36605d97fbf254fadba0fa48f75c03f27d11584f92')


class TestPublicKeyUncompressed(unittest.TestCase):

    def setUp(self):
        self.K = Key('025c0de3b9c8ab18dd04e3511243ec2952002dbfadc864b9628910169d9b9b00ec')

    def test_public_key_point(self):
        self.assertEqual((41637322786646325214887832269588396900663353932545912953362782457239403430124,
                          16388935128781238405526710466724741593761085120864331449066658622400339362166),
                         self.K.public_point(),)

    def test_public_key_uncompressed(self):
        self.assertEqual('045c0de3b9c8ab18dd04e3511243ec2952002dbfadc864b9628910169d9b9b00ec243bcefdd4347074d4'
                         '4bd7356d6a53c495737dd96295e2a9374bf5f02ebfc176',
                         self.K.public_uncompressed_hex)

    def test_public_key_address_uncompressed(self):
        self.assertEqual('1thMirt546nngXqyPEz532S8fLwbozud8', self.K.address_uncompressed())


class TestHDKeysImport(unittest.TestCase):

    def setUp(self):
        self.k = HDKey.from_seed('000102030405060708090a0b0c0d0e0f')
        self.k2 = HDKey.from_seed('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a878'
                                  '4817e7b7875726f6c696663605d5a5754514e4b484542')
        self.xpub = HDKey('xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqse'
                          'fD265TMg7usUDFdp6W1EGMcet8')

    def test_hdkey_import_seed_1(self):

        self.assertEqual('xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TG'
                         'tRBeJgk33yuGBxrMPHi', self.k.wif(is_private=True))
        self.assertEqual('xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TM'
                         'g7usUDFdp6W1EGMcet8', self.k.wif())

    def test_hdkey_import_seed_2(self):
        self.assertEqual('xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3L'
                         'qFtT2emdEXVYsCzC2U', self.k2.wif(is_private=True))
        self.assertEqual('xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJ'
                         'Y47LJhkJ8UB7WEGuduB', self.k2.wif_public())

    def test_hdkey_random(self):
        self.k = HDKey()
        self.assertEqual('xprv', self.k.wif(is_private=True)[:4])
        self.assertEqual(111, len(self.k.wif(is_private=True)))

    def test_hdkey_import_extended_private_key(self):
        extkey = 'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4m' \
                 'LTj34bhnZX7UiM'
        self.k = HDKey(extkey)
        self.assertEqual(extkey, self.k.wif(is_private=True))

    def test_hdkey_import_extended_public_key(self):
        extkey = 'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7' \
                 'DogT5Uv6fcLW5'
        self.k = HDKey(extkey)
        self.assertEqual(extkey, self.k.wif())

    def test_hdkey_import_simple_key(self):
        self.k = HDKey('L45TpiVN3C8Q3MoosGDzug1acpnFjysseBLVboszztmEyotdSJ9g')
        self.assertEqual(
            'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAbeoRRpMHE67jGmBQKCr2YovK2G23x5uzaztRbEW9pc'
            'j6SqMFd', self.k.wif(is_private=True))

    def test_hdkey_import_bip38_key(self):
        if USING_MODULE_SCRYPT:
            self.k = HDKey('6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo',
                           passphrase='TestingOneTwoThree')
            self.assertEqual('L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP', self.k.wif_key())

    def test_hdkey_import_public(self):
        self.assertEqual('15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', self.xpub.address())
        self.assertEqual('0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2',
                         self.xpub.public_hex)

    def test_hdkey_import_public_try_private(self):
        try:
            self.xpub.wif()
        except KeyError as e:
            self.assertEqual('WIF format not supported for public key', e.args[0])
        try:
            self.xpub.private_hex
        except KeyError as e:
            self.assertEqual('WIF format not supported for public key', e.args[0])

    def test_hdkey_import_segwit_wifs(self):
        wifs = [
            ('zprvAe9nVpMfBzSSSCr8WHYiv5a6TeSojETexJfZhvu9oYuENwQkEqRHH7nnwGzscgkCCu9S2PrwnD1VJHXXfLUbSG8yqZoKpi2CaoY'
             'Kdz7pKM1', True),
            ('zpub6s98uKtZ2MzjegvbcK5jHDWq1gHJ8hBWKXbAWKJmMtSDFjjtnNjXpv7GnXmDGZzG36XMgLaC3JewffU5pukcUtYuEpRJEkVAiFU'
             'mdA5GaXM', False),
            ('yprvAEWM3LZ7vwNRTroi67SjcpexaVEdbEMAgHbiefDibSqssbrqyh9joH6BY6DRzkoGMX9nLxXoa5yYT64r3zQ2i9sQa51iQhzjwUj'
             '2UJ2GES4', True),
            ('Ypub6jkwv4tzCZJNe6j1JHZgwUmj6yCi5iEBNHrP1RDFyR13RwRNB5foJWeinpcBTqfv2uUe7mWSwsF1am4cVLN99xrkADPWrDick3S'
             'aP8nxY8N', False)
        ]
        for wif in wifs:
            self.assertEqual(HDKey(wif[0]).wif(is_private=wif[1]), wif[0])

    def test_hdkey_import_from_private_byte(self):
        if not PY3:
            return
        keystr = b"fch\xe4w\xa8\xdd\xd4h\x08\xc5'\xcc<Pg\x19\xbb?R\xa9'\xb6\xc152\x98KqKV\xad\x91`G-a\xb1\xad\xd8eL" \
                 b"\xcc\x8an\x94\xa3\x93\xb5\xa5\xe6\xc3\xf1\x98\x91h6wt\xf0z=\x1f\x17"
        hdkey = HDKey(keystr)
        self.assertEqual(hdkey.address(), '17N9VQbP89ThunSq7Yo2VooXCFTW1Lp8bd')


class TestHDKeysChildKeyDerivation(unittest.TestCase):

    def setUp(self):
        self.k = HDKey.from_seed('000102030405060708090a0b0c0d0e0f')
        self.k2 = HDKey.from_seed('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8'
                                  '784817e7b7875726f6c696663605d5a5754514e4b484542')

    def test_hdkey_path_m_0h(self):
        sk = self.k.subkey_for_path('m/0H')
        self.assertEqual('xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7'
                         'XnxHrnYeSvkzY7d2bhkJ7', sk.wif(is_private=True))
        self.assertEqual('xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9x'
                         'v5ski8PX9rL2dZXvgGDnw', sk.wif())

    def test_hdkey_path_m_0h_1(self):
        sk = self.k.subkey_for_path('m/0H/1')
        self.assertEqual('xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H'
                         '2EU4pWcQDnRnrVA1xe8fs', sk.wif(is_private=True))
        self.assertEqual('xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqc'
                         'k2AxYysAA7xmALppuCkwQ', sk.wif())

    def test_hdkey_path_m_0h_1_2h(self):
        sk = self.k.subkey_for_path('m/0h/1/2h')
        self.assertEqual('xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjAN'
                         'TtpgP4mLTj34bhnZX7UiM', sk.wif(is_private=True))
        self.assertEqual('xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4'
                         'trkrX7x7DogT5Uv6fcLW5', sk.wif())

    def test_hdkey_path_m_0h_1_2h_1000000000(self):
        sk = self.k.subkey_for_path('m/0h/1/2h/2/1000000000')
        self.assertEqual('xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUi'
                         'hUZREPSL39UNdE3BBDu76', sk.wif(is_private=True))
        self.assertEqual('xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTv'
                         'XEYBVPamhGW6cFJodrTHy',
                         sk.wif_public())

    def test_hdkey_path_key2(self):
        sk = self.k2.subkey_for_path('m/0/2147483647h/1/2147483646h/2')
        self.assertEqual('xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEc'
                         'BYJUuekgW4BYPJcr9E7j',
                         sk.wif(is_private=True))
        self.assertEqual('xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb'
                         '9rXpVGyy3bdW6EEgAtqt',
                         sk.wif_public())

    def test_hdkey_path_M_0_1_public(self):
        sk = self.k.subkey_for_path('M/0/1')
        self.assertEqual('xpub6AvUGrnEpfvJBbfx7sQ89Q8hEMPM65UteqEX4yUbUiES2jHfjexmfJoxCGSwFMZiPBaKQT1RiKWrKfuDV4vpgVs'
                         '4Xn8PpPTR2i79rwHd4Zr', sk.wif())

    def test_hdkey_path_invalid(self):
        with self.assertRaises(BKeyError):
            self.k2.subkey_for_path('m/0/').wif()

    def test_hdkey_path_invalid2(self):
        with self.assertRaises(BKeyError):
            self.k2.subkey_for_path('m/-1').wif()

    def test_hdkey_bip44_account(self):
        pk = 'tprv8ZgxMBicQKsPdvHCP6VxtFgowj2k7nBJnuRiVWE4DReDFojkLjyqdT8mtR6XJK9dRBcaa3RwvqiKFjsEQVhKfQmHZCCYf4jRTWv' \
             'JuVuK67n'
        k = HDKey(pk)
        self.assertEqual(k.public_master(3, 45, as_private=True).private_hex,
                         '232b9d7b48fa4ca6e842f09f6811ff03cf33ba0582b4cca5752deec2e746c186')

    def test_hdkey_bip44_account_litecoin(self):
        pk = 'Ltpv71G8qDifUiNes8hK1m3ZjL3bW76X4AKF3J26FVDM5awe6mWdyyzZgTrbvkK5z4WQyKkyVnDvC56KfRaHHhcZjWcWvRFCzBYUsCc' \
             'FoNNHjck'
        k = HDKey(pk, network='litecoin')
        self.assertEqual(k.public_master().address(), 'LZ4gg2m6uNY3vj9RUFkderRP18ChTwWyiq')

    def test_hdkey_derive_from_public_error(self):
        k = HDKey().public()
        self.assertRaisesRegexp(BKeyError, "Need a private key to create child private key", k.child_private)
        k0 = HDKey()
        k1 = k0.child_private(10, hardened=True)
        self.assertRaisesRegexp(BKeyError, "Cannot derive hardened key from public private key",
                                k1.child_public, 2147483659)


class TestHDKeysPublicChildKeyDerivation(unittest.TestCase):

    def setUp(self):
        self.K = HDKey('xpub6ASuArnXKPbfEVRpCesNx4P939HDXENHkksgxsVG1yNp9958A33qYoPiTN9QrJmWFa2jNLdK84bWmyqTSPGtApP8P'
                       '7nHUYwxHPhqmzUyeFG')
        self.k = HDKey('xprv9wTYmMFdV23N21MM6dLNavSQV7Sj7meSPXx6AV5eTdqqGLjycVjb115Ec5LgRAXscPZgy5G4jQ9csyyZLN3PZLxoM'
                       '1h3BoPuEJzsgeypdKj')

    def test_hdkey_derive_public_child_key(self):
        self.assertEqual('1BvgsfsZQVtkLS69NvGF8rw6NZW2ShJQHr', self.K.child_public(0).address())

    def test_hdkey_derive_public_child_key2(self):
        self.assertEqual('17JbSP83rPWmbdcdtiiTNqBE8MgGN8kmUk', self.K.child_public(8).address())

    def test_hdkey_private_key(self):
        self.assertEqual('KxABnXp7SiuWi218c14KkjEMV7SjcfXnvsWaveNVxWZU1Rwi8zNQ',
                         self.k.child_private(7).wif_key())

    def test_hdkey_private_key_hardened(self):
        self.k2 = HDKey('xprv9s21ZrQH143K31AgNK5pyVvW23gHnkBq2wh5aEk6g1s496M8ZMjxncCKZKgb5j'
                        'ZoY5eSJMJ2Vbyvi2hbmQnCuHBujZ2WXGTux1X2k9Krdtq')
        self.assertEqual('xprv9wTErTSu5AWGkDeUPmqBcbZWX1xq85ZNX9iQRQW9DXwygFp7iRGJo79dsVctcsCHsnZ3XU3DhsuaGZbDh8iDkB'
                         'N45k67UKsJUXM1JfRCdn1', str(self.k2.subkey_for_path('3/2H').wif(is_private=True)))

    def test_hdkey_litecoin(self):
        k = HDKey('Ltpv71G8qDifUiNetj2H4no6Q4oB8o2eUH8tSU2BsJDGyKTyMJ6ejPDXHWtQeTzKQdEeEexxyw3vSAYtxnAz3qYZc'
                  '59jfTiqHLzjKkwJ9iDJ1uC', network='litecoin')
        self.assertEqual('LWsiwZnGg74CFHEaLPzfASxktrzDYYSwvM', k.child_public(0).address())
        self.assertEqual('LfH72Fgeikvhu1y5rtMAkQ5SS5aJJUafLX', k.child_public(100).address())
        self.assertEqual('T65a5dNtdayWp9F638f8fokiyixCA4fhyzb7FWFYXjejqjaxKRSc', k.child_private(6).wif_key())
        self.assertEqual('Ltpv75tiiksDF3fUqK8jkAfwY1h3zDLs3oCFQa5wXDNh981n6LDJZ6juFWUJwwkN3pKbr3diSdMkZfYAhwhkhjP9qG'
                         'wviSbMXtEJYxoH2m3FbDQ', str(k.subkey_for_path('3H/1').wif(is_private=True)))


class TestHDKeys(unittest.TestCase):

    def test_hdkey_testnet_random(self):
        self.k = HDKey(network='testnet')

        self.assertEqual('tprv', self.k.wif(is_private=True)[:4])
        self.assertEqual('tpub', self.k.wif_public()[:4])
        self.assertIn(self.k.address()[:1], ['m', 'n'])

    def test_hdkey_testnet_import(self):
        self.k = HDKey('tprv8ZgxMBicQKsPf2S18qpSypHPZBK7mdiwvXHPh5TSjGjm2pLacP4tEqVjLVyagTLLgSZK4YyBNb4eytBykE755Kc'
                       'L9YXAqPtfERNRfwRt54M')

        self.assertEqual('cPSokRrLueavzAmVBmAXwgALkumRNMN9pErvRLAXvx58NBJAkEYJ', self.k.wif_key())
        self.assertEqual('tpubD6NzVbkrYhZ4YVTo2VV3PDwW8Cq3vxurVptAybVk9YY9sJbMEmtURL7bWgKxXSWSahXu6HbHkdpjBGzwYYkJm'
                         'u2VmoeHuiTmzHZpJo8Cdpb', self.k.wif_public())
        self.assertEqual('n4c8TKkqUmj3b8VJrTioiZuciyaCDRd6iE', self.k.address())

    def test_hdkey_uncompressed_key_conversion(self):
        key = Key('5JGSWMSfKiXVDvXzUeod8HeSsGRpHWQgrETithYjZKcxWNpexVK')
        hdkey = HDKey(key)
        hdkey_uncompressed = HDKey(hdkey.wif(is_private=True), compressed=False)
        hdkey_compressed = HDKey(hdkey.wif(is_private=True))

        self.assertFalse(key.compressed)
        self.assertFalse(hdkey.compressed)
        self.assertEqual(hdkey_uncompressed.private_hex, hdkey_compressed.private_hex)
        self.assertEqual(hdkey_uncompressed.wif(), hdkey.wif())
        self.assertEqual(hdkey_compressed.wif_key(), 'KyD9aZEG9cHZa3Hnh3rnTAUHAs6XhroYtJQwuBy4qfBhzHGEApgv')

    def test_hdkey_wif_prefixes(self):
        for network in list(NETWORK_DEFINITIONS.keys()):
            k = HDKey(network=network)
            for witness_type in ['legacy', 'p2sh-segwit', 'segwit']:
                for multisig in [False, True]:
                    if network[:4] == 'dash' and witness_type != 'legacy':
                        break
                    kwif = k.wif_private(witness_type=witness_type, multisig=multisig)
                    hdkey = wif_prefix_search(kwif, witness_type=witness_type, multisig=multisig, network=network)
                    pwif = k.wif_public(witness_type=witness_type, multisig=multisig)
                    hdkey_pub = wif_prefix_search(pwif, witness_type=witness_type, multisig=multisig, network=network)
                    self.assertTrue(kwif[:4] == hdkey[0]['prefix_str'])
                    self.assertTrue(pwif[:4] == hdkey_pub[0]['prefix_str'])

    def test_hdkey_info(self):
        k = HDKey()
        self.assertIsNone(k.info())

    def test_hdkey_network_change(self):
        pk = '688e4b153100f6d4526a00a3fffb47d971a32a54950ec00fab8c22fa8480edfe'
        k = HDKey(pk)
        k.network_change('litecoin')
        self.assertEqual(k.address(), 'LPsPTgctprGZ6FEc7QFAugr6qg8XV3X4tg')


class TestBip38(unittest.TestCase):

    def setUp(self):
        workdir = os.path.dirname(__file__)
        with open('%s/%s' % (workdir, 'bip38_protected_key_tests.json'), 'r') as f:
            self.vectors = json.load(f)

    def test_encrypt_private_key(self):
        if not USING_MODULE_SCRYPT:
            return
        for v in self.vectors["valid"]:
            k = Key(v['wif'])
            print("Check %s + %s = %s " % (v['wif'], v['passphrase'], v['bip38']))
            self.assertEqual(str(v['bip38']), k.bip38_encrypt(str(v['passphrase'])))

    def test_decrypt_bip38_key(self):
        if not USING_MODULE_SCRYPT:
            return
        for v in self.vectors["valid"]:
            k = Key(v['bip38'], passphrase=str(v['passphrase']))
            print("Check %s - %s = %s " % (v['bip38'], v['passphrase'], v['wif']))
            self.assertEqual(str(v['wif']), k.wif())

    def test_bip38_invalid_keys(self):
        if not USING_MODULE_SCRYPT:
            return
        for v in self.vectors["invalid"]["verify"]:
            print("Checking invalid key %s" % v['base58'])
            self.assertRaisesRegexp(Exception, "", Key, str(v['base58']))

    def test_bip38_other_networks(self):
        if not USING_MODULE_SCRYPT:
            return
        networks = ['testnet', 'litecoin', 'dash']
        for network in networks:
            k = Key(network=network)
            enc_key = k.bip38_encrypt('password')
            k2 = Key(enc_key, passphrase='password', network=network)
            self.assertEqual(k.wif(), k2.wif())

    def test_bip38_hdkey_method(self):
        pkwif = '5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5'
        bip38_wif = '6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq'
        k = HDKey(pkwif)
        self.assertEqual(k.bip38_encrypt('Satoshi'), bip38_wif)


class TestKeysBulk(unittest.TestCase):
    """
    Test Child Key Derivation

    Use the 2 different methods to derive child keys. One through derivation from public parent,
    and one thought private parent. They should be the same.
    """

    def setUp(self):
        self.K = HDKey('xpub6ASuArnXKPbfEVRpCesNx4P939HDXENHkksgxsVG1yNp9958A33qYoPiTN9QrJmWFa2jNLdK84bWmyqTSPGtApP8P'
                       '7nHUYwxHPhqmzUyeFG')
        self.k = HDKey('xprv9wTYmMFdV23N21MM6dLNavSQV7Sj7meSPXx6AV5eTdqqGLjycVjb115Ec5LgRAXscPZgy5G4jQ9csyyZLN3PZLxoM'
                       '1h3BoPuEJzsgeypdKj')

    def test_hdkey_derive_from_public_and_private_index(self):
        global BULKTESTCOUNT
        if not BULKTESTCOUNT:
            self.skipTest("Skip bulktesting. Bulktestcount == 0")
        for i in range(BULKTESTCOUNT):
            pub_with_pubparent = self.K.child_public(i).address()
            pub_with_privparent = self.k.child_private(i).address()
            if pub_with_privparent != pub_with_pubparent:
                print("Error index %4d: pub-child %s, priv-child %s" % (i, pub_with_privparent, pub_with_pubparent))
            self.assertEqual(pub_with_pubparent, pub_with_privparent)

    def test_hdkey_derive_from_public_and_private_random(self):
        global BULKTESTCOUNT
        if not BULKTESTCOUNT:
            self.skipTest("Skip bulktesting. Bulktestcount == 0")
        for i in range(BULKTESTCOUNT):
            k = HDKey()
            pubk = HDKey(k.wif_public())
            pub_with_pubparent = pubk.child_public().address()
            pub_with_privparent = k.child_private().address()
            if pub_with_privparent != pub_with_pubparent:
                print("Error random key: %4d: pub-child %s, priv-child %s" %
                      (i, pub_with_privparent, pub_with_pubparent))
            self.assertEqual(pub_with_pubparent, pub_with_privparent)


class TestKeysAddress(unittest.TestCase):
    """
    Tests for Address class. Address format, conversion and representation

    """

    def test_keys_address_import_conversion(self):
        address_legacy = '3LPrWmWj1pYPEs8dGsPtWfmg2E9LhL5BHj'
        address = 'MSbzpevgxwPp3NQXNkPELK25Lvjng7DcBk'
        ac = Address.import_address(address_legacy, network_overrides={"prefix_address_p2sh": "32"})
        self.assertEqual(ac.address, address)

    def test_keys_address_encodings(self):
        pk = '7cc7ed043b4240945e744387f8943151de86843025682bf40fa94ef086eeb686'
        a = Address(pk, network='testnet')
        self.assertEqual(a.address, 'mmAXD1HJtV9pdffPvBJkuT4qQrbFMwb4pR')
        self.assertEqual(a.with_prefix(b'\x88'), 'wpcbpijWdzjj5W9ZXfdj2asW9U2q7gYCmw')
        a = Address(pk, script_type='p2sh', network='testnet')
        self.assertEqual(a.address, '2MxtnuEcoEpYJ9WWkzqcr87ChujVRk1DFsZ')
        a = Address(pk, encoding='bech32', network='testnet')
        self.assertEqual(a.address, 'tb1q8hehumvm039nxnwwtqdjr7qmm46sfxrdw7vc3g')

    def test_keys_address_deserialize_exceptions(self):
        self.assertRaisesRegexp(BKeyError, "Invalid address 17N9VQbP89ThunSq7Yo2VooXCFTW1Lp8bb, checksum incorrect",
                                deserialize_address, '17N9VQbP89ThunSq7Yo2VooXCFTW1Lp8bb', encoding='base58')
        self.assertRaisesRegexp(EncodingError,
                                "Address 17N9VQbP89ThunSq7Yo2VooXCFTW1Lp8bd is not in specified encoding bs",
                                deserialize_address, '17N9VQbP89ThunSq7Yo2VooXCFTW1Lp8bd', encoding='bs')
        self.assertRaisesRegexp(EncodingError,
                                "Invalid address 17N9VQbP89ThunSq7Yo2VooXCFTW1Lp8bb: "
                                "Invalid bech32 character in bech string",
                                deserialize_address, '17N9VQbP89ThunSq7Yo2VooXCFTW1Lp8bb', encoding='bech32')
        self.assertRaisesRegexp(EncodingError,
                                "Address bc1qk077yl8zf6yty25rgrys8h40j8adun267y3m44 is not in specified "
                                "encoding base58",
                                deserialize_address, 'bc1qk077yl8zf6yty25rgrys8h40j8adun267y3m44', encoding='base58')

    def test_keys_address_deserialize_litecoin(self):
        address = '3N59KFZBzpnq4EoXo2cDn2GKjX1dfkv1nB'
        addr_dict = deserialize_address(address, network='litecoin_legacy')
        self.assertEqual(addr_dict['network'], 'litecoin_legacy')

    def test_keys_address_litecoin_import(self):
        address = 'LUPKYv9Z7AvQgxuVkDdqQrBDswsQJMxsN8'
        a = Address.import_address(address)
        self.assertEqual(a.hashed_data, '647ea562d9e72daca10fa476297f10576f284ba4')
        self.assertEqual(a.network.name, 'litecoin')
        self.assertEqual(a.address_orig, 'LUPKYv9Z7AvQgxuVkDdqQrBDswsQJMxsN8')

    def test_keys_address_deserialize_bech32(self):
        address = 'bc1qk077yl8zf6yty25rgrys8h40j8adun267y3m44'
        addr_dict = deserialize_address(address)
        self.assertEqual(addr_dict['public_key_hash'], 'b3fde27ce24e88b22a8340c903deaf91fade4d5a')
        self.assertEqual(addr_dict['encoding'], 'bech32')
        self.assertEqual(addr_dict['script_type'], 'p2wpkh')

    def test_key_address_p2sh_p2wpkh(self):
        pk = 'd80229e1b5eae5b4f9e11698d73f5468e45631e6d256e500ceb51f4f49d99e78'
        addr = Address(HDKey(pk).public_byte, script_type='p2sh_p2wpkh')
        self.assertEqual(addr.redeemscript, b"\x00\x14\x1e\xf4h\x07'\x1bM4RJ\xb9b\x11\xb9X\x81h\xdei:")
        self.assertEqual(addr.address, '3Disr2CmERuYuuMkkfGrjRUHqDENQvtNep')

    def test_keys_address_deserialize_bech32_p2wsh(self):
        address = 'bc1qcuk5gxz4v962tne5mld4ztjakktmlupqd7jxn5k57774fuyzzplszs4ppd'
        addr_dict = deserialize_address(address)
        self.assertEqual(addr_dict['public_key_hash'],
                         'c72d4418556174a5cf34dfdb512e5db597bff0206fa469d2d4f7bd54f082107f')
        self.assertEqual(addr_dict['encoding'], 'bech32')
        self.assertEqual(addr_dict['script_type'], 'p2wsh')

    def test_keys_address_conversion(self):
        self.assertEqual(addr_convert('1GMDUKLom6bJuY37RuFNc6PHv1rv2Hziuo', prefix='bc', to_encoding='bech32'),
                         'bc1q4pwfmstmw8q80nxtxud2h42lev9xzcjqwqyq7t')
        self.assertEqual(addr_convert('1GMDUKLom6bJuY37RuFNc6PHv1rv2Hziuo', prefix=b'\x05'),
                         '3H3EPrqFJzugzhjYYzuy2ikE4Y9dWPJjnQ')
        self.assertEqual(addr_convert('bc1q4pwfmstmw8q80nxtxud2h42lev9xzcjqwqyq7t', prefix=b'\x00',
                                      to_encoding='base58'), '1GMDUKLom6bJuY37RuFNc6PHv1rv2Hziuo')
        self.assertEqual(addr_convert('bc1q4pwfmstmw8q80nxtxud2h42lev9xzcjqwqyq7t', prefix='tb'),
                         'tb1q4pwfmstmw8q80nxtxud2h42lev9xzcjqyxln9c')

    def test_keys_address_import_ambigue_bech32(self):
        # Import bech32 address with only base58 characters
        pk = '73c32f225a98ac084565429d5a15148dad5d9f6ef7cc7a5d901c9dfd6bb6027a'
        addr = Address(HDKey(pk).public_hex, witness_type='segwit')
        self.assertEqual(deserialize_address(addr.address, encoding='bech32')['encoding'], 'bech32')

    def test_keys_hdkey_segwit(self):
        k1 = HDKey('L1TZxZ9RgwFKiGPm6P7J9REQFKG9ymwLSsTwQSwxzLyDJs3CcRkF', witness_type='segwit')
        self.assertEqual(k1.address(), 'bc1qmk9myu4zf590ae2mfq3m63rlfhd5scatl4ckmw')

        phrase = 'scan display embark segment deputy lesson vanish second wonder erase crumble swing'
        k2 = HDKey.from_passphrase(phrase, witness_type='segwit', multisig=True)
        self.assertEqual(k2.address(), 'bc1qvj6c7n0hpl9t5r80zya4uukf0zens8ulxgwc0avnxsengtr5juss4pqeqy')


class TestKeysDash(unittest.TestCase):
    def test_format_wif_compressed_private_dash(self):
        key = 'XH2Yndjv6Ks3XEHGaSMDhUMTAMZTTWv5nEN958Y7VMyQXBCJVQmM'
        self.assertEqual('wif_compressed', get_key_format(key)['format'])
        self.assertEqual(['dash'], get_key_format(key)['networks'])

    def test_format_wif_private_dash(self):
        key = '7rrHic4Nzr8iMSfaSFMSXvKgTb7Sw3FHwevGsnD2vYwU5btpXRT'
        self.assertEqual('wif', get_key_format(key)['format'])
        self.assertEqual(['dash'], get_key_format(key)['networks'])

    def test_format_hdkey_private_dash(self):
        key = 'xprv9s21ZrQH143K3D4pKs8hj46ixU3T2vPsdmfMsoYjytd15C84SoRRkXebFFb3o4j6R5srg7btramafwcfdiibf2CWqMJLEX6jL2' \
              'YUrLR7VfS'
        self.assertEqual('hdkey_private', get_key_format(key)['format'])
        self.assertIn('dash', get_key_format(key)['networks'])

    def test_dash_private_key(self):
        KC_DASH = Key('000ece5e695793773007ac225a21fd570aa10f64d4da7ba29e6eabb0e34aae6b', network='dash_testnet')
        self.assertEqual(KC_DASH.wif(), 'cMapAmsnHr2UZ2ZCjZZfRru8dS9PLjYjTVjbnrR7suqducfQNYnX')
        self.assertEqual(KC_DASH.address(), 'ya3XLrAqfHFTFEZvDno9kv3MHREzHQzQMq')
        self.assertEqual(KC_DASH.public_hex, '02d092ed110b2d127c160ef1d72dc158fa96a3d32b41b9680ea6ef35e194bbc83e')

    def test_hdkey_bip44_account_dash(self):
        pk = 'xprv9s21ZrQH143K3cq8ueA8GV9uv7cHqkyQGBQu8YZkAU2EXG5oSKVFeQnYK25zhHEEqqjfyTFEcV5enh6vh4tFA3FvdGuWAqPqvY' \
             'ECNLB78mV'
        k = HDKey(pk, network='dash')
        self.assertEqual(k.account_key().wif(is_private=True), 'xprv9ySHTHmm4KdkKa2RV2zuSmVUAPNynEvkrCDVa95Js9StLECY2'
                                                               'RjuxNpHKaVfA2hnjob5Zumx1kTg3MhQPsZf7W5h8aEM61AMSqz1zV'
                                                               'Wjt4Q')

    def test_hdkey_dash(self):
        k = HDKey('xprv9s21ZrQH143K4EGnYMHVxNp8JgqXCyywC3CGTrSzSudH3iRgC1gPTYgce4xamXMnyDAX8Qv8tvuW1LEgkZSrXiC25LqTJN'
                  '8RpCKS5ixcQWD', network='dash')
        self.assertEqual('XkQ9Vudjgq62pvuG9K7pknVbiViZzZjWkJ', k.child_public(0).address())
        self.assertEqual('XtqfKEcdtn1QioGRie41uP79gGC6yPzmnz', k.child_public(100).address())
        self.assertEqual('XEYoxQJvhuXCXMpUFjf9knkJrFeE3mYp9mbFXG6mR3EK2Vvzi8vA', k.child_private(6).wif_key())
        self.assertEqual('xprv9wZJLyzHEFzD3w3uazhGhbytbsVbrHQ5Spc7qkuwsPqUQo2VTxhpyoYRGD7o1T4AKZkfjGrWHtHrS4GUkBxzUH'
                         'ozuqu8c2n3d7sjbmyPdFC', str(k.subkey_for_path('3H/1').wif(is_private=True)))


class TestKeysSignatures(unittest.TestCase):

    def test_signatures(self):
        sig_tests = [
            # tx_hash, key_hex, k, signature, DER encoded sign.
            ('0d12fdc4aac9eaaab9730999e0ce84c3bd5bb38dfd1f4c90c613ee177987429c',
             'b2da575054fb5daba0efde613b0b8e37159b8110e4be50f73cbe6479f6038f5b', 1002,
             '70b55404702ffa86ecfa4e88e0f354004a0965a5eea5fbbd297436001ae920df5da0917d7bd645c2a09671894375e3d353313'
             '8e8de09bc89cb251cbfae4cc523',
             '3044022070b55404702ffa86ecfa4e88e0f354004a0965a5eea5fbbd297436001ae920df02205da0917d7bd645c2a09671894'
             '375e3d3533138e8de09bc89cb251cbfae4cc523'),
            (b'\r\x12\xfd\xc4\xaa\xc9\xea\xaa\xb9s\t\x99\xe0\xce\x84\xc3\xbd[\xb3\x8d\xfd\x1fL\x90\xc6\x13\xee\x17y'
             b'\x87B\x9c',
             'b2da575054fb5daba0efde613b0b8e37159b8110e4be50f73cbe6479f6038f5b', 1002,
             '70b55404702ffa86ecfa4e88e0f354004a0965a5eea5fbbd297436001ae920df5da0917d7bd645c2a09671894375e3d353313'
             '8e8de09bc89cb251cbfae4cc523',
             '3044022070b55404702ffa86ecfa4e88e0f354004a0965a5eea5fbbd297436001ae920df02205da0917d7bd645c2a09671894'
             '375e3d3533138e8de09bc89cb251cbfae4cc523'),
            ('01000000978ee762c58d54f55f604c666218620cc3e665180f45098bb329d2a3d873cb733bb13029ce7b1f559ef5e747fcac4'
             '39f1455a2ec7c5f09b72290795e70665044babdf37f9e78ce9886cf8814d6c2fa590ade790dc7177da742867b3c5b35a81d00'
             '0000001976a91478fa2e39b03d5e98027665c3a69371c01ee031ee88aca086010000000000ffffffff98c930a52608751d9dd'
             '31d63c3ce09deb473e8de5c0a6ed2e3273dc6747d7bc60000000001000000',
             'b2da575054fb5daba0efde613b0b8e37159b8110e4be50f73cbe6479f6038f5b', 1002,
             '70b55404702ffa86ecfa4e88e0f354004a0965a5eea5fbbd297436001ae920df5da0917d7bd645c2a09671894375e3d353313'
             '8e8de09bc89cb251cbfae4cc523',
             '3044022070b55404702ffa86ecfa4e88e0f354004a0965a5eea5fbbd297436001ae920df02205da0917d7bd645c2a09671894'
             '375e3d3533138e8de09bc89cb251cbfae4cc523'),
            ('e63be0b7ef061a60dd03fab16c19c496a0f4905639413d41a8fd3a705f2e486b',
             'fd4b7465dadd8e8fe2dd8b8fa505c619e2959d5a6438daf7716a47e4617524a2', 1234567890,
             '2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef226875b0fec3497d7cd812912003d5a44ed2965'
             '0d339299081debf75c29dc4dbc6',
             '304402202b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef2202206875b0fec3497d7cd81291200'
             '3d5a44ed29650d339299081debf75c29dc4dbc6'),
            ('c77545c8084b6178366d4e9a06cf99a28d7b5ff94ba8bd76bbbce66ba8cdef70',
             HDKey('xprv9s21ZrQH143K2YEun3sBzwSaFLn6bnBa6nkodJrDfZSty6L7Ba9JR5tMdhc7viB9dPu6LpQ9UqrsDsrJ8GNLQHf4SKA'
                   'zGrXL6Pp5kjojqzi', network='bitcoin'),
             92517795607469467391485978923218300650097355078673652603133403767271895603938,
             '40aa86a597ecd19aa60c1f18390543cc5c38049a18a8515aed095a4b15e1d8ea2226efba29871477ab925e75356fda036f06d'
             '293d02fc9b0f9d49e09d8149e9d',
             '3044022040aa86a597ecd19aa60c1f18390543cc5c38049a18a8515aed095a4b15e1d8ea02202226efba29871477ab925e753'
             '56fda036f06d293d02fc9b0f9d49e09d8149e9d')
        ]
        sig_method1 = sign(sig_tests[0][0], sig_tests[0][1], k=sig_tests[0][2])
        self.assertEqual(sig_method1.hex(), sig_tests[0][3])
        self.assertEqual(to_hexstring(sig_method1.as_der_encoded()), sig_tests[0][4])
        count = 0
        for case in sig_tests:
            sig = Signature.create(case[0], case[1], k=case[2])
            self.assertEqual(sig.hex(), case[3], msg="Error in #%d: %s != %s" % (count, sig.hex(), case[3]))
            self.assertEqual(to_hexstring(sig.as_der_encoded()), case[4])
            self.assertTrue(sig.verify())
            count += 1

    def test_rfc6979(self):
        if not USE_FASTECDSA:
            # This test are only usefull when fastecdsa library is used
            return True

        # source: https://bitcointalk.org/index.php?topic=285142.40
        # Test Vectors for RFC 6979 ECDSA, secp256k1, SHA-256
        # (private key, message, expected k, expected signature)
        test_vectors = [
            (0x1, "Satoshi Nakamoto", 0x8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15,
             "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d82442ce9d2b916064108014783e923ec36b4974"
             "3e2ffa1c4496f01a512aafd9e5"),
            (0x1, "All those moments will be lost in time, like tears in rain. Time to die...",
             0x38AA22D72376B4DBC472E06C3BA403EE0A394DA63FC58D88686C611ABA98D6B3,
             "8600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6b547fe64427496db33bf66019dacbf0039c04199"
             "abb0122918601db38a72cfc21"),
            (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140, "Satoshi Nakamoto",
             0x33A19B60E25FB6F4435AF53A3D42D493644827367E6453928554F43E49AA6F90,
             "fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447cd6af2d06b39cd0eb1bc8603e159ef5c20a5c8ad685a45b"
             "06ce9bebed3f153d10d93bed5"),
            (0xf8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181, "Alan Turing",
             0x525A82B70E67874398067543FD84C83D30C175FDC45FDEEE082FE13B1D7CFDF1,
             "7063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c58dfcc1e00a35e1572f366ffe34ba0fc47db1e7"
             "189759b9fb233c5b05ab388ea"),
            (0xe91671c46231f833a6406ccbea0e3e392c76c167bac1cb013f6f1013980455c2,
             "There is a computer disease that anybody who works with computers knows about. It's a very serious "
             "disease and it interferes completely with the work. The trouble with computers is that you 'play' with "
             "them!",
             0x1F4B84C23A86A221D233F2521BE018D9318639D5B8BBD6374A8A59232D16AD3D,
             "b552edd27580141f3b2a5463048cb7cd3e047b97c9f98076c32dbdf85a68718b279fa72dd19bfae05577e06c7c0c1900c371fc"
             "d5893f7e1d56a37d30174671f6"),
            (0x69ec59eaa1f4f2e36b639716b7c30ca86d9a5375c7b38d8918bd9c0ebc80ba64,
             "Computer science is no more about computers than astronomy is about telescopes.", None,
             "7186363571d65e084e7f02b0b77c3ec44fb1b257dee26274c38c928986fea45d0de0b38e06807e46bda1f1e293f4f6323e854c"
             "86d58abdd00c46c16441085df6"),
            (0x0000000000000000000000000000000000000000000000000000000000000001,
             "Everything should be made as simple as possible, but not simpler.", None,
             "33a69cd2065432a30f3d1ce4eb0d59b8ab58c74f27c41a7fdb5696ad4e6108c96f807982866f785d3f6418d24163ddae117b7d"
             "b4d5fdf0071de069fa54342262"),
            (0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140,
             "Equations are more important to me, because politics is for the present, but an equation is something "
             "for eternity.", None,
             "54c4a33c6423d689378f160a7ff8b61330444abb58fb470f96ea16d99d4a2fed07082304410efa6b2943111b6a4e0aaa7b7db5"
             "5a07e9861d1fb3cb1f421044a5"),
            (0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140,
             "Not only is the Universe stranger than we think, it is stranger than we can think.", None,
             "ff466a9f1b7b273e2f4c3ffe032eb2e814121ed18ef84665d0f515360dab3dd06fc95f5132e5ecfdc8e5e6e616cc77151455d"
             "46ed48f5589b7db7771a332b283"),
            (0x0000000000000000000000000000000000000000000000000000000000000001,
             "How wonderful that we have met with a paradox. Now we have some hope of making progress.", None,
             "c0dafec8251f1d5010289d210232220b03202cba34ec11fec58b3e93a85b91d375afdc06b7d6322a590955bf264e7aaa15584"
             "7f614d80078a90292fe205064d3"),
            (0x00000000000000000000000000007246174ab1e92e9149c6e446fe194d072637,
             "...if you aren't, at any given time, scandalized by code you wrote five or even three years ago, you're "
             "not learning anywhere near enough", None,
             "fbfe5076a15860ba8ed00e75e9bd22e05d230f02a936b653eb55b61c99dda4870e68880ebb0050fe4312b1b1eb0899e1b82da89"
             "baa5b895f612619edf34cbd37"),
            (0x000000000000000000000000000000000000000000056916d0f9b31dc9b637f3,
             "The question of whether computers can think is like the question of whether submarines can swim.", None,
             "cde1302d83f8dd835d89aef803c74a119f561fbaef3eb9129e45f30de86abbf906ce643f5049ee1f27890467b77a6a8e11ec46"
             "61cc38cd8badf90115fbd03cef")
        ]

        for vector in test_vectors:
            msg = to_bytes(vector[1])
            x = int(vector[0])
            rfc6979 = RFC6979(msg, x, secp256k1_n, hashlib.sha256)
            k = rfc6979.gen_nonce()
            expected = vector[2]
            if expected is not None:
                self.assertEqual(k, expected)
            msg_hash = hashlib.sha256(to_bytes(vector[1])).digest()
            sig = sign(msg_hash, x, k=k)
            self.assertEqual(sig.hex(), vector[3])

    def test_sig_from_r_and_s(self):
        r = 0x657912a72d3ac8169fe8eaecd5ab401c94fc9981717e3e6dd4971889f785790c
        s = 0x00ed3bf3456eb76677fd899c8ccd1cc6d1ebc631b94c42f7c4578f28590d651c6e
        expected_der = '30450220657912a72d3ac8169fe8eaecd5ab401c94fc9981717e3e6dd4971889f785790c022100ed3bf345' \
                       '6eb76677fd899c8ccd1cc6d1ebc631b94c42f7c4578f28590d651c6e'
        expected_sig_bytes = b'ey\x12\xa7-:\xc8\x16\x9f\xe8\xea\xec\xd5\xab@\x1c\x94\xfc\x99\x81q~>m\xd4\x97\x18' \
                             b'\x89\xf7\x85y\x0c\xed;\xf3En\xb7fw\xfd\x89\x9c\x8c\xcd\x1c\xc6\xd1\xeb\xc61\xb9LB' \
                             b'\xf7\xc4W\x8f(Y\re\x1cn'
        expected_sig_hex = '657912a72d3ac8169fe8eaecd5ab401c94fc9981717e3e6dd4971889f785790ced3bf3456eb76677fd899' \
                           'c8ccd1cc6d1ebc631b94c42f7c4578f28590d651c6e'

        sig = Signature(r, s)
        self.assertEqual(to_hexstring(sig.as_der_encoded()), expected_der)
        self.assertEqual(sig.bytes(), expected_sig_bytes)
        self.assertEqual(sig.hex(), expected_sig_hex)

    def test_sig_rs_out_of_curve(self):
        outofcurveint = 115792089237316195423570985008687907852837564279074904382605163141518161494339
        self.assertRaisesRegexp(BKeyError, "r is not a positive integer smaller than the curve order",
                                Signature, outofcurveint, 10)
        self.assertRaisesRegexp(BKeyError, "r is not a positive integer smaller than the curve order",
                                Signature, 0, 10)
        self.assertRaisesRegexp(BKeyError, "s is not a positive integer smaller than the curve order",
                                Signature, 11, outofcurveint)


if __name__ == '__main__':
    unittest.main()
