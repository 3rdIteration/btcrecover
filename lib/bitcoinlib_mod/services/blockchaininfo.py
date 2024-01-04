# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    blockchain_info client
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
import struct
from datetime import datetime
from bitcoinlib.main import MAX_TRANSACTIONS
from bitcoinlib.services.baseclient import BaseClient
from bitcoinlib.transactions import Transaction


PROVIDERNAME = 'blockchaininfo'

_logger = logging.getLogger(__name__)


class BlockchainInfoClient(BaseClient):

    def __init__(self, network, base_url, denominator, *args):
        super(self.__class__, self).__init__(network, PROVIDERNAME, base_url, denominator, *args)

    def compose_request(self, cmd, parameter='', variables=None, method='get'):
        url_path = cmd
        if parameter:
            url_path += '/' + parameter
        return self.request(url_path, variables, method=method)

    def getbalance(self, addresslist):
        addresses = {'active': '|'.join(addresslist)}
        res = self.compose_request('balance', variables=addresses)
        balance = 0
        for address in res:
            balance += res[address]['final_balance']
        return balance

    def getutxos(self, address, after_txid='', max_txs=MAX_TRANSACTIONS):
        utxos = []
        variables = {'active': address, 'limit': 1000}
        res = self.compose_request('unspent', variables=variables)
        if len(res['unspent_outputs']) > 299:
            _logger.info("BlockchainInfoClient: Large number of outputs for address %s, "
                            "UTXO list may be incomplete" % address)
        res['unspent_outputs'].sort(key=lambda x: x['confirmations'])
        for utxo in res['unspent_outputs']:
            if utxo['tx_hash_big_endian'] == after_txid:
                break
            utxos.append({
                'address': address,
                'tx_hash': utxo['tx_hash_big_endian'],
                'confirmations': utxo['confirmations'],
                'output_n': utxo['tx_output_n'],
                'input_n':  utxo['tx_index'],
                'block_height': None,
                'fee': None,
                'size': 0,
                'value': int(round(utxo['value'] * self.units, 0)),
                'script': utxo['script'],
                'date': None
            })
        return utxos[::-1][:max_txs]

    def gettransaction(self, tx_id):
        tx = self.compose_request('rawtx', tx_id)
        raw_tx = self.getrawtransaction(tx_id)
        t = Transaction.import_raw(raw_tx, self.network)
        input_total = 0
        for n, i in enumerate(t.inputs):
            if 'prev_out' in tx['inputs'][n]:
                i.value = tx['inputs'][n]['prev_out']['value']
                input_total += i.value
        for n, o in enumerate(t.outputs):
            o.spent = tx['out'][n]['spent']
        if 'block_height' in tx and tx['block_height']:
            t.status = 'confirmed'
        else:
            t.status = 'unconfirmed'
        t.hash = tx_id
        t.date = datetime.fromtimestamp(tx['time'])
        t.block_height = 0 if 'block_height' not in tx else tx['block_height']
        t.rawtx = raw_tx
        t.size = tx['size']
        t.network_name = self.network
        t.locktime = tx['lock_time']
        t.version = struct.pack('>L', tx['ver'])
        t.input_total = input_total
        if t.coinbase:
            t.input_total = t.output_total
        t.fee = t.input_total - t.output_total
        return t

    def gettransactions(self, address, after_txid='', max_txs=MAX_TRANSACTIONS):
        txs = []
        txids = []
        variables = {'limit': 100}
        res = self.compose_request('rawaddr', address, variables=variables)
        latest_block = self.blockcount()
        for tx in res['txs']:
            if tx['hash'] not in txids:
                txids.insert(0, tx['hash'])
        if after_txid:
            txids = txids[txids.index(after_txid) + 1:]
        for txid in txids[:max_txs]:
            t = self.gettransaction(txid)
            t.confirmations = latest_block - t.block_height
            txs.append(t)
        return txs

    def getrawtransaction(self, tx_id):
        return self.compose_request('rawtx', tx_id, {'format': 'hex'})

    # def sendrawtransaction()

    # def estimatefee()

    def blockcount(self):
        return self.compose_request('latestblock')['height']

    def mempool(self, txid=''):
        if txid:
            tx = self.compose_request('rawtx', txid)
            if 'block_height' not in tx:
                return [tx['hash']]
        else:
            txs = self.compose_request('unconfirmed-transactions', variables={'format': 'json'})
            return [tx['hash'] for tx in txs['txs']]
        return []
