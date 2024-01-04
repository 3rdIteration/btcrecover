# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    BitGo Client
#    © 2017-2019 July - 1200 Web Development <http://1200wd.com/>
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
from bitcoinlib.main import MAX_TRANSACTIONS
from bitcoinlib.services.baseclient import BaseClient, ClientError
from bitcoinlib.transactions import Transaction

_logger = logging.getLogger(__name__)

PROVIDERNAME = 'bitgo'
LIMIT_TX = 49


class BitGoClient(BaseClient):

    def __init__(self, network, base_url, denominator, *args):
        super(self.__class__, self).__init__(network, PROVIDERNAME, base_url, denominator, *args)

    def compose_request(self, category, data, cmd='', variables=None, method='get'):
        if data:
            data = '/' + data
        url_path = category + data
        if cmd != '':
            url_path += '/' + cmd
        return self.request(url_path, variables, method=method)

    def getbalance(self, addresslist):
        balance = 0
        for address in addresslist:
            res = self.compose_request('address', address)
            balance += res['balance']
        return balance

    def getutxos(self, address, after_txid='', max_txs=MAX_TRANSACTIONS):
        utxos = []
        skip = 0
        total = 1
        while total > skip:
            variables = {'limit': 100, 'skip': skip}
            res = self.compose_request('address', address, 'unspents', variables)
            for utxo in res['unspents'][::-1]:
                if utxo['tx_hash'] == after_txid:
                    break
                utxos.append(
                    {
                        'address': utxo['address'],
                        'tx_hash': utxo['tx_hash'],
                        'confirmations': utxo['confirmations'],
                        'output_n': utxo['tx_output_n'],
                        'input_n': 0,
                        'block_height': utxo['blockHeight'],
                        'fee': None,
                        'size': 0,
                        'value': int(round(utxo['value'] * self.units, 0)),
                        'script': utxo['script'],
                        'date': datetime.strptime(utxo['date'], "%Y-%m-%dT%H:%M:%S.%fZ")
                     }
                )
            total = res['total']
            skip = res['start'] + res['count']
            if skip > 2000:
                _logger.info("BitGoClient: UTXO's list has been truncated, list is incomplete")
                break
        return utxos[::-1][:max_txs]

    def gettransaction(self, tx_id):
        tx = self.compose_request('tx', tx_id)
        t = Transaction.import_raw(tx['hex'], network=self.network)
        if tx['confirmations']:
            t.status = 'confirmed'
        t.hash = tx_id
        t.date = datetime.strptime(tx['date'], "%Y-%m-%dT%H:%M:%S.%fZ")
        t.confirmations = tx['confirmations']
        if 'height' in tx:
            t.block_height = tx['height']
            t.block_hash = tx['blockhash']
        t.fee = tx['fee']
        t.rawtx = tx['hex']
        t.size = len(tx['hex']) // 2
        t.network = self.network
        if t.coinbase:
            input_values = []
            t.input_total = t.output_total
        else:
            input_values = [(inp['account'], -inp['value']) for inp in tx['entries'] if inp['value'] < 0]
            if len(input_values) >= 49:
                raise ClientError("More then 49 transaction inputs not supported by bitgo")
            t.input_total = sum([x[1] for x in input_values])
        for i in t.inputs:
            if not i.address:
                raise ClientError("Address missing in input. Provider might not support segwit transactions")
            if len(t.inputs) != len(input_values):
                i.value = None
                continue
            value = [x[1] for x in input_values if x[0] == i.address]
            if len(value) != 1:
                _logger.info("BitGoClient: Address %s input value should be found exactly 1 times in value list" %
                                i.address)
                i.value = None
            else:
                i.value = value[0]
        for o in t.outputs:
            o.spent = None
        if t.input_total != t.output_total + t.fee:
            t.input_total = t.output_total + t.fee
        return t

    def gettransactions(self, address, after_txid='', max_txs=MAX_TRANSACTIONS):
        txs = []
        txids = []
        skip = 0
        total = 1
        while total > skip:
            variables = {'limit': LIMIT_TX, 'skip': skip}
            res = self.compose_request('address', address, 'tx', variables)
            for tx in res['transactions']:
                if tx['id'] not in txids:
                    txids.insert(0, tx['id'])
            total = res['total']
            # if total > 2000:
            #     raise ClientError("BitGoClient: Transactions list limit exceeded > 2000")
            skip = res['start'] + res['count']
            if len(txids) > max_txs:
                break
        if after_txid:
            txids = txids[txids.index(after_txid) + 1:]
        for txid in txids[:max_txs]:
            txs.append(self.gettransaction(txid))
        return txs

    def getrawtransaction(self, txid):
        tx = self.compose_request('tx', txid)
        t = Transaction.import_raw(tx['hex'], network=self.network)
        for i in t.inputs:
            if not i.address:
                raise ClientError("Address missing in input. Provider might not support segwit transactions")
        return tx['hex']

    # def sendrawtransaction

    def estimatefee(self, blocks):
        res = self.compose_request('tx', 'fee', variables={'numBlocks': blocks})
        return res['feePerKb']

    def blockcount(self):
        return self.compose_request('block', 'latest')['height']

    # def mempool
