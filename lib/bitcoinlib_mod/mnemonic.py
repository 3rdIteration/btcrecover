# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    MNEMONIC class for BIP0039 Mnemonic Key management
#    © 2016 - 2019 November - 1200 Web Development <http://1200wd.com/>
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

import hashlib
from lib.bitcoinlib.encoding import change_base, normalize_string, to_bytes
from lib.bitcoinlib.config.secp256k1 import secp256k1_n
from lib.bitcoinlib.main import *


class Mnemonic(object):
    """
    Class to convert, generate and parse Mnemonic sentences
    
    Implementation of BIP0039 for Mnemonics passphrases 

    Took some parts from Pavol Rusnak Trezors implementation, see https://github.com/trezor/python-mnemonic
    """

    def __init__(self, language=DEFAULT_LANGUAGE):
        """
        Init Mnemonic class and read wordlist of specified language
        
        :param language: use specific wordlist, i.e. chinese, dutch (in development), english, french, italian, japanese or spanish. Leave empty for default 'english'
        :type language: str
        
        """
        self._wordlist = []
        with open(os.path.join(str(BCL_INSTALL_DIR), 'wordlist', '%s.txt' % language)) as f:
            self._wordlist = [w.strip() for w in f.readlines()]
        # FIXME: Use code below instead of os.path, but doesn't work with pathlib2 (Python 2)
        # with Path(BCL_INSTALL_DIR, 'wordlist', '%s.txt' % language).open() as f:
        #     self._wordlist = [w.strip() for w in f.readlines()]

    @staticmethod
    def checksum(data):
        """
        Calculates checksum for given data key

        :param data: key string
        :type data: bytes, hexstring
        
        :return str: Checksum of key in bits
        """
        data = to_bytes(data)
        if len(data) % 4 > 0:
            raise ValueError('Data length in bits should be divisible by 32, but it is not (%d bytes = %d bits).' %
                             (len(data), len(data) * 8))
        key_hash = hashlib.sha256(data).digest()
        return change_base(key_hash, 256, 2, 256)[:len(data) * 8 // 32]

    def to_seed(self, words, password='', validate=True):
        """
        Use Mnemonic words and optionally a password to create a PBKDF2 seed (Password-Based Key Derivation Function 2)
        
        First use 'sanitize_mnemonic' to determine language and validate and check words

        >>> from bitcoinlib.encoding import to_hexstring
        >>> to_hexstring(Mnemonic().to_seed('chunk gun celery million wood kite tackle twenty story episode raccoon dutch'))
        '6969ed4666db67fc74fae7869e2acf3c766b5ef95f5e31eb2fcebd93d76069c6de971225f700042b0b513f0ad6c8562277fc4b5ee1344b720f1686dc2dccc220'

        :param words: Mnemonic passphrase as string with space separated words
        :type words: str
        :param password: A password to protect key, leave empty to disable
        :type password: str
        :param validate: Validate checksum for given word phrase, default is True
        :type validate: bool
        
        :return bytes: PBKDF2 seed
        """
        words = self.sanitize_mnemonic(words)
        # Check if passphrase is valid
        if validate:
            self.to_entropy(words)
        mnemonic = to_bytes(words)
        password = to_bytes(password)
        return hashlib.pbkdf2_hmac(hash_name='sha512', password=mnemonic, salt=b'mnemonic' + password,
                                   iterations=2048)

    def word(self, index):
        """
        Get word from wordlist
        
        :param index: word index ID
        :type index: int
        
        :return str: A word from the dictionary 
        """
        return self._wordlist[index]

    def wordlist(self):
        """
        Get full selected wordlist. A wordlist is selected when initializing Mnemonic class
        
        :return list: Full list with 2048 words 
        """
        return self._wordlist

    def generate(self, strength=128, add_checksum=True):
        """
        Generate a random Mnemonic key
        
        Uses cryptographically secure os.urandom() function to generate data. Then creates a Mnemonic sentence with
        the 'to_mnemonic' method.

        :param strength: Key strength in number of bits as multiply of 32, default is 128 bits. It advised to specify 128 bits or more, i.e.: 128, 256, 512 or 1024
        :type strength: int
        :param add_checksum: Included a checksum? Default is True
        :type add_checksum: bool
        
        :return str: Mnemonic passphrase consisting of a space seperated list of words
        """
        if strength % 32 > 0:
            raise ValueError("Strength should be divisible by 32")
        data = os.urandom(strength // 8)
        return self.to_mnemonic(data, add_checksum=add_checksum)

    def to_mnemonic(self, data, add_checksum=True, check_on_curve=True):
        """
        Convert key data entropy to Mnemonic sentence

        >>> Mnemonic().to_mnemonic('28acfc94465fd2f6774759d6897ec122')
        'chunk gun celery million wood kite tackle twenty story episode raccoon dutch'

        :param data: Key data entropy
        :type data: bytes, hexstring
        :param add_checksum: Included a checksum? Default is True
        :type add_checksum: bool
        :param check_on_curve: Check if data integer value is on secp256k1 curve. Should be enabled when not testing and working with crypto
        :type check_on_curve: bool
        
        :return str: Mnemonic passphrase consisting of a space seperated list of words
        """
        data = to_bytes(data)
        data_int = change_base(data, 256, 10)
        if check_on_curve and not 0 < data_int < secp256k1_n:
            raise ValueError("Integer value of data should be in secp256k1 domain between 1 and secp256k1_n-1")
        if add_checksum:
            binresult = change_base(data_int, 10, 2, len(data) * 8) + self.checksum(data)
            wi = change_base(binresult, 2, 2048)
        else:
            wi = change_base(data_int, 10, 2048, len(data) // 1.375 + len(data) % 1.375 > 0)
        return normalize_string(' '.join([self._wordlist[i] for i in wi]))

    def to_entropy(self, words, includes_checksum=True):
        """
        Convert Mnemonic words back to key data entropy

        >>> from bitcoinlib.encoding import to_hexstring
        >>> to_hexstring(Mnemonic().to_entropy('chunk gun celery million wood kite tackle twenty story episode raccoon dutch'))
        '28acfc94465fd2f6774759d6897ec122'


        :param words: Mnemonic words as string of list of words
        :type words: str
        :param includes_checksum: Boolean to specify if checksum is used. Default is True
        :type includes_checksum: bool
        
        :return bytes: Entropy seed
        """
        words = self.sanitize_mnemonic(words)
        if isinstance(words, TYPE_TEXT):
            words = words.split(' ')
        wi = []
        for word in words:
            wi.append(self._wordlist.index(word))
        ent = change_base(wi, 2048, 256, output_even=False)
        if includes_checksum:
            binresult = change_base(ent, 256, 2, len(ent) * 4)
            ent = change_base(binresult[:-len(binresult) // 33], 2, 256)

            # Check checksum
            checksum = binresult[-len(binresult) // 33:]
            if checksum != self.checksum(ent):
                raise ValueError("Invalid checksum %s for entropy %s" % (checksum, ent))

        return ent

    @staticmethod
    def detect_language(words):
        """
        Detect language of given phrase

        >>> Mnemonic().detect_language('chunk gun celery million wood kite tackle twenty story episode raccoon dutch')
        'english'
        
        :param words: List of space separated words
        :type words: str
        
        :return str: Language 
        """
        words = normalize_string(words)
        if isinstance(words, TYPE_TEXT):
            words = words.split(' ')

        wlcount = {}
        # TODO: Use for fn in Path(BCL_INSTALL_DIR, 'wordlist').iterdir():
        #     if fn.suffix == ".txt":
        for fn in os.listdir(os.path.join(str(BCL_INSTALL_DIR), 'wordlist')):
            if fn.endswith(".txt"):
                with open(os.path.join(str(BCL_INSTALL_DIR), 'wordlist', fn)) as f:
                    wordlist = [w.strip() for w in f.readlines()]
                    language = fn.split('.')[0]
                    wlcount[language] = 0
                    for word in words:
                        if sys.version < '3':
                            word = word.encode('utf-8')
                        if word in wordlist:
                            wlcount[language] += 1
        detlang = max(wlcount.keys(), key=(lambda key: wlcount[key]))
        if not wlcount[detlang]:
            raise Warning("Could not detect language of Mnemonic sentence %s" % words)
        return detlang

    def sanitize_mnemonic(self, words):
        """
        Check and convert list of words to utf-8 encoding.
        
        Raises an error if unrecognised word is found
        
        :param words: List of space separated words
        :type words: str
        
        :return str: Sanitized list of words
        """
        words = normalize_string(words)
        language = self.detect_language(words)
        if isinstance(words, TYPE_TEXT):
            words = words.split(' ')
        # TODO: Path(BCL_INSTALL_DIR, 'wordlist', '%s.txt' % language).open() as f:
        with open(os.path.join(str(BCL_INSTALL_DIR), 'wordlist', '%s.txt' % language)) as f:
            wordlist = [w.strip() for w in f.readlines()]
            for word in words:
                if sys.version < '3':
                    word = word.encode('utf-8')
                if word not in wordlist:
                    raise Warning("Unrecognised word %s in mnemonic sentence" % word.encode('utf8'))
        return ' '.join(words)
