# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    BitcoinLib Test Network for Unit Tests
#    © 2018 February - 1200 Web Development <http://1200wd.com/>
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

import logging
import hashlib
from bitcoinlib.services.baseclient import BaseClient
from bitcoinlib.main import MAX_TRANSACTIONS
from bitcoinlib.encoding import addr_to_pubkeyhash, addr_bech32_to_pubkeyhash, double_sha256, to_bytes

_logger = logging.getLogger(__name__)

PROVIDERNAME = 'bitcoinlib'


class BitcoinLibTestClient(BaseClient):
    """
    Dummy service client for bitcoinlib test network. Only used for testing.

    Does not make any connection to a service provider, so can be used offline.

    """

    def __init__(self, network, base_url, denominator, *args):
        super(self.__class__, self).__init__(network, PROVIDERNAME, base_url, denominator, *args)

    def getbalance(self, addresslist):
        """
        Dummy getbalance method for bitcoinlib testnet

        :param addresslist: List of addresses
        :type addresslist: list

        :return int:
        """
        return self.units * len(addresslist)

    def _get_txid(self, address, n):
        try:
            pkh = str(n).encode() + addr_to_pubkeyhash(address)[1:]
        except Exception:
            pkh = str(n).encode() + addr_bech32_to_pubkeyhash(address)[1:]
        return hashlib.sha256(pkh).hexdigest()

    def getutxos(self, address, after_txid='', limit=10, utxos_per_address=2):
        """
        Dummy method to retreive UTXO's. This method creates a new UTXO for each address provided out of the
        testnet void, which can be used to create test transactions for the bitcoinlib testnet.

        :param address: Address string
        :type address: str
        :param after_txid: Transaction ID of last known transaction. Only check for utxos after given tx id. Default: Leave empty to return all utxos. If used only provide a single address
        :type after_txid: str
        :param limit: Maximum number of utxo's to return
        :type limit: int

        :return list: The created UTXO set
        """
        utxos = []
        for n in range(utxos_per_address):
            txid = self._get_txid(address, n)
            utxos.append(
                {
                    'address': address,
                    'txid': txid,
                    'confirmations': 10,
                    'output_n': 0,
                    'index': 0,
                    'value': 1 * self.units,
                    'script': '',
                }
            )
        return utxos

    # def gettransaction(self, tx_id):

    # def gettransactions(self, address, after_txid='', limit=MAX_TRANSACTIONS):

    def sendrawtransaction(self, rawtx):
        """
        Dummy method to send transactions on the bitcoinlib testnet. The bitcoinlib testnet does not exists,
        so it just returns the transaction hash.

        :param rawtx: A raw transaction hash
        :type rawtx: bytes, str

        :return str: Transaction hash
        """
        txid = double_sha256(to_bytes(rawtx))[::-1].hex()
        return {
            'txid': txid,
            'response_dict': {}
        }

    def estimatefee(self, blocks):
        """
        Dummy estimate fee method for the bitcoinlib testnet.

        :param blocks: Number of blocks
        :type blocks: int

        :return int: Fee as 100000 // number of blocks
        """
        return 100000 // blocks

    def blockcount(self):
        return 1

    def mempool(self, txid=''):
        return [txid]
