# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    Unit Tests for Key, Encoding and Mnemonic Class
#    © 2016 - 2019 December - 1200 Web Development <http://1200wd.com/>
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

from bitcoinlib.keys import HDKey
from bitcoinlib.encoding import change_base
from bitcoinlib.mnemonic import Mnemonic


class TestMnemonics(unittest.TestCase):

    def _check_list(self, language, vectors):
        mnemo = Mnemonic(language)
        for v in vectors:
            if v[0]:
                phrase = mnemo.to_mnemonic(v[0], check_on_curve=False)
            else:
                phrase = v[1]
            seed = change_base(mnemo.to_seed(phrase, v[4], validate=False), 256, 16)
            # print("Test %s => %s" % (v[0], phrase))
            self.assertEqual(v[1], phrase)
            self.assertEqual(v[2], seed)
            k = HDKey.from_seed(seed)
            self.assertEqual(k.wif(is_private=True), v[3])

    # From Copyright (c) 2013 Pavol Rusnak <https://github.com/trezor/python-mnemonic>
    def test_vectors(self):
        workdir = os.path.dirname(__file__)
        with open('%s/%s' % (workdir, 'mnemonics_tests.json')) as f:
            vectors = json.load(f)
        for lang in vectors.keys():
            self._check_list(lang, vectors[lang])

    def test_mnemonic_generate(self):
        phrase = Mnemonic(language='dutch').generate()
        self.assertEqual(len(phrase.split(' ')), 12)
        self.assertEqual(Mnemonic.detect_language(phrase), 'dutch')

    def test_mnemonic_generate_error(self):
        self.assertRaisesRegexp(ValueError, 'Strength should be divisible by 32', Mnemonic().generate, 11)

    def test_mnemonic_to_entropy(self):
        phrase = 'usage grid neither voice worry armor sudden core excuse keen stand pudding'
        self.assertEqual(Mnemonic().to_entropy(phrase), b'\xef\x8c\xceP\xfa\xbf\xdc\x17\xf6!\x82O\x0f7RV')

    def test_mnemonic_to_mnemonic(self):
        self.assertEqual(Mnemonic().to_mnemonic('28acfc94465fd2f6774759d6897ec122'),
                         'chunk gun celery million wood kite tackle twenty story episode raccoon dutch')
        self.assertEqual(Mnemonic().to_mnemonic('28acfc94465fd2f6774759d6897ec122', add_checksum=False),
                         'action filter venture match garlic nut oven modify output dwarf wild cattle')
        self.assertRaisesRegexp(ValueError, "Integer value of data should be in secp256k1 domain between 1 and "
                                            "secp256k1_n-1", Mnemonic().to_mnemonic,
                                '28acfc94465fd2f6774759d6897ec12228acfc94465fd2f6774759d6897ec12228acfc94465fd2f6774')

    def test_mnemonic_to_seed_invalid_checksum(self):
        phrase = "runway truly foil future recall scatter garage over floor clutch shy boat"
        self.assertRaisesRegexp(ValueError, "Invalid checksum 0110 for entropy", Mnemonic().to_seed, phrase)

    def test_mnemonic_exceptions(self):
        self.assertRaisesRegexp(ValueError, "Strength should be divisible by 32", Mnemonic().generate, 20)
        self.assertRaisesRegexp(ValueError, "Data length in bits should be divisible by 32", Mnemonic().checksum,
                                'aabbccddeeff')
        self.assertRaisesRegexp(Warning, "Unrecognised word",
                                Mnemonic().sanitize_mnemonic,
                                'action filter venture match garlic nut oven modify output dwarf wild fiets')
        self.assertRaisesRegexp(Warning, "Could not detect language",
                                Mnemonic().detect_language,
                                'floep fliep')

    def test_mnemonic_wordlists(self):
        self.assertEqual(Mnemonic().word(2047), 'zoo')
        self.assertEqual(Mnemonic(language='spanish').word(2047), 'zurdo')
        self.assertEqual(Mnemonic(language='french').word(2047), 'zoologie')
        self.assertEqual(Mnemonic(language='italian').word(2047), 'zuppa')
        self.assertEqual(Mnemonic(language='japanese').word(2047), 'われる')
        self.assertEqual(Mnemonic(language='chinese_simplified').word(2047), '歇')
        self.assertEqual(Mnemonic(language='chinese_traditional').word(2047), '歇')
        self.assertEqual(len(Mnemonic().wordlist()), 2048)

if __name__ == '__main__':
    unittest.main()
