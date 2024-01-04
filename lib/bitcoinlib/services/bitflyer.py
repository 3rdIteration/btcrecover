# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    Blocksmurfer client
#    © 2020 Januari - 1200 Web Development <http://1200wd.com/>
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
from datetime import datetime
from bitcoinlib.services.baseclient import BaseClient, ClientError
from bitcoinlib.transactions import Transaction
from bitcoinlib.keys import Address

PROVIDERNAME = 'bitflyer'


_logger = logging.getLogger(__name__)


class BitflyerClient(BaseClient):

    def __init__(self, network, base_url, denominator, *args):
        super(self.__class__, self).__init__(network, PROVIDERNAME, base_url, denominator, *args)

    def compose_request(self, function, parameter='', parameter2='', method='get'):
        url_path = function
        if parameter:
            url_path += '/' + str(parameter)
        if parameter2:
            url_path += '/' + str(parameter2)
        return self.request(url_path, method=method)

    def getbalance(self, addresslist):
        balance = 0
        for address in addresslist:
            res = self.compose_request('address', address)
            balance += res['unconfirmed_balance']
        return balance

    # def getutxos(self, address, after_txid='', limit=MAX_TRANSACTIONS):

    # def gettransaction(self, txid, block_count=None):
    #     tx = self.compose_request('tx', txid)
    #     # tx_date = None if not tx.get('received_date') else datetime.strptime(tx['received_date'],
    #     #                                                                      "%Y-%m-%dT%H:%M:%S.%f")
    #     t = Transaction(locktime=tx['lock_time'], version=tx['version'], network=self.network,
    #                     # fee=tx['fees'], size=tx['size'], txid=tx['tx_hash'], date=tx_date,
    #                     confirmations=tx['confirmed'], block_height=tx['block_height'],
    #                     status='confirmed' if tx['confirmed'] else 'unconfirmed')
    #     for ti in tx['inputs']:
    #         a = Address.parse(ti['address'])
    #         t.add_input(prev_txid=ti['prev_hash'], output_n=ti['prev_index'], unlocking_script=ti['script'],
    #                     value=ti['value'], address=ti['address'], sequence=ti['sequence'],
    #                     witness_type=a.witness_type, strict=self.strict)
    #     if 'segwit' in [i.witness_type for i in t.inputs] or 'p2sh-segwit' in [i.witness_type for i in t.inputs]:
    #         t.witness_type = 'segwit'
    #     for to in tx['outputs']:
    #         t.add_output(value=to['value'], address=to['address'], lock_script=to['script'], strict=self.strict)
    #     t.update_totals()
    #     return t

    # def gettransactions(self, address, after_txid='', limit=MAX_TRANSACTIONS):

    # def getrawtransaction(self, txid):

    # def sendrawtransaction(self, rawtx):

    # def estimatefee(self, blocks):

    def blockcount(self):
        res = self.compose_request('block', 'latest')
        return res['height']

    # def mempool(self, txid):

    # def getblock(self, blockid, parse_transactions, page, limit):

    # def getrawblock(self, blockid):

    # def isspent(self, txid, output_n):

    # def getinfo(self):
