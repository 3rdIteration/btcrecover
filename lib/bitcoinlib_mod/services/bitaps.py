# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    BitAps client
#    © 2019 August - 1200 Web Development <http://1200wd.com/>
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
import logging
from datetime import datetime
from bitcoinlib.main import MAX_TRANSACTIONS
from bitcoinlib.services.baseclient import BaseClient, ClientError
from bitcoinlib.transactions import Transaction
from bitcoinlib.keys import deserialize_address
from bitcoinlib.encoding import EncodingError, varstr, to_bytes

_logger = logging.getLogger(__name__)

PROVIDERNAME = 'bitaps'
# Please note: In the Bitaps API, the first couple of Bitcoin blocks are not correctly indexed,
# so transactions from these blocks are missing.


class BitapsClient(BaseClient):

    def __init__(self, network, base_url, denominator, *args):
        super(self.__class__, self).__init__(network, PROVIDERNAME, base_url, denominator, *args)

    def compose_request(self, category, command='', data='', variables=None, type='blockchain', method='get'):
        url_path = type + '/' + category
        if command:
            url_path += '/' + command
        if data:
            if url_path[-1:] != '/':
                url_path += '/'
            url_path += data
        return self.request(url_path, variables=variables, method=method)

    def _parse_transaction(self, tx):
        t = Transaction.import_raw(tx['rawTx'], network=self.network)
        t.status = 'unconfirmed'
        if tx['confirmations']:
            t.status = 'confirmed'
        t.hash = tx['txId']
        if 'timestamp' in tx and tx['timestamp']:
            t.date = datetime.fromtimestamp(tx['timestamp'])
        elif 'blockTime' in tx and tx['blockTime']:
            t.date = datetime.fromtimestamp(tx['blockTime'])
        t.confirmations = tx['confirmations']
        if 'blockHeight' in tx:
            t.block_height = tx['blockHeight']
            t.block_hash = tx['blockHash']
        t.fee = tx['fee']
        t.rawtx = tx['rawTx']
        t.size = tx['size']
        t.network = self.network
        if not t.coinbase:
            for i in t.inputs:
                i.value = tx['vIn'][str(i.index_n)]['amount']
        for o in t.outputs:
            if tx['vOut'][str(o.output_n)]['spent']:
                o.spent = True
        if t.coinbase:
            t.input_total = tx['outputsAmount'] - t.fee
        else:
            t.input_total = tx['inputsAmount']
        t.output_total = tx['outputsAmount']
        return t

    def getbalance(self, addresslist):
        balance = 0
        for address in addresslist:
            res = self.compose_request('address', 'state', address)
            balance += res['data']['balance']
        return balance

    def getutxos(self, address, after_txid='', max_txs=MAX_TRANSACTIONS):
        utxos = []
        page = 1
        while True:
            variables = {'mode': 'verbose', 'limit': 50, 'page': page, 'order': '1'}
            try:
                res = self.compose_request('address', 'transactions', address, variables)
                res2 = self.compose_request('address', 'unconfirmed/transactions', address, variables)
            except ClientError as e:
                if "address not found" in self.resp.text:
                    return []
                else:
                    raise ClientError(e.msg)
            txs = res['data']['list']
            txs += res2['data']['list']
            for tx in txs:
                for outp in tx['vOut']:
                    utxo = tx['vOut'][outp]
                    if 'address' not in utxo or utxo['address'] != address or utxo['spent']:
                        continue
                    utxos.append(
                        {
                            'address': utxo['address'],
                            'tx_hash': tx['txId'],
                            'confirmations': 0 if 'confirmations' not in tx else tx['confirmations'],
                            'output_n': int(outp),
                            'input_n': 0,
                            'block_height': None if 'blockHeight' not in tx else tx['blockHeight'],
                            'fee': None,
                            'size': 0,
                            'value': utxo['value'],
                            'script': utxo['scriptPubKey'],
                            'date': datetime.fromtimestamp(tx['timestamp'])
                         }
                    )
                if tx['hash'] == after_txid:
                    utxos = []
            page += 1
            if page > res['data']['pages']:
                break
        return utxos[:max_txs]

    def gettransaction(self, txid):
        res = self.compose_request('transaction', txid)
        return self._parse_transaction(res['data'])

    def gettransactions(self, address, after_txid='', max_txs=MAX_TRANSACTIONS):
        page = 0
        txs = []
        while True:
            variables = {'mode': 'verbose', 'limit': 50, 'page': page, 'order': '1'}
            try:
                res = self.compose_request('address', 'transactions', address, variables)
            except ClientError:
                if "address not found" in self.resp.text:
                    return []
            for tx in res['data']['list']:
                txs.append(self._parse_transaction(tx))
                if tx['txId'] == after_txid:
                    txs = []
            if len(txs) > max_txs:
                break
            page += 1
            if page > res['data']['pages']:
                break
        return txs[:max_txs]

    def getrawtransaction(self, txid):
        tx = self.compose_request('transaction', txid)
        return tx['data']['rawTx']

    # def sendrawtransaction

    # def estimatefee

    def blockcount(self):
        return self.compose_request('block', 'last')['data']['block']['height']

    def mempool(self, txid):
        if txid:
            t = self.gettransaction(txid)
            if t and not t.confirmations:
                return [t.hash]
        else:
            res = self.compose_request('transactions', type='mempool')
            return [tx['hash'] for tx in res['data']['transactions']]
        return []
