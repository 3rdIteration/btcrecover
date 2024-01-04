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

    def getutxos(self, address, after_txid='', limit=MAX_TRANSACTIONS):
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
                'txid': utxo['tx_hash_big_endian'],
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
        return utxos[::-1][:limit]

    def gettransaction(self, txid, latest_block=None):
        self.latest_block = self.latest_block if not latest_block else latest_block
        tx = self.compose_request('rawtx', txid)
        rawtx = self.getrawtransaction(txid)
        t = Transaction.parse_hex(rawtx, strict=self.strict, network=self.network)
        input_total = 0
        for n, i in enumerate(t.inputs):
            if 'prev_out' in tx['inputs'][n]:
                i.value = 0 if not tx['inputs'][n]['prev_out'] else tx['inputs'][n]['prev_out']['value']
                input_total += i.value
        for n, o in enumerate(t.outputs):
            o.spent = tx['out'][n]['spent']
        if 'block_height' in tx and tx['block_height']:
            if not self.latest_block:
                self.latest_block = self.blockcount()
            t.status = 'confirmed'
            t.date = datetime.utcfromtimestamp(tx['time'])
            t.block_height = tx['block_height']
            t.confirmations = 1
            if self.latest_block > t.block_height:
                t.confirmations = self.latest_block - t.block_height
        else:
            t.status = 'unconfirmed'
            t.confirmations = 0
            t.date = None
        t.rawtx = bytes.fromhex(rawtx)
        t.size = tx['size']
        t.network_name = self.network
        t.locktime = tx['lock_time']
        t.version_int = tx['ver']
        t.version = tx['ver'].to_bytes(4, 'big')
        t.input_total = input_total
        t.fee = 0
        if t.input_total:
            t.fee = t.input_total - t.output_total
        return t

    def gettransactions(self, address, after_txid='', limit=MAX_TRANSACTIONS):
        txs = []
        txids = []
        variables = {'limit': 100}
        res = self.compose_request('rawaddr', address, variables=variables)
        self.latest_block = self.blockcount() if not self.latest_block else self.latest_block
        for tx in res['txs']:
            if tx['hash'] not in txids:
                txids.insert(0, tx['hash'])
        if after_txid:
            txids = txids[txids.index(after_txid) + 1:]
        for txid in txids[:limit]:
            t = self.gettransaction(txid, latest_block=self.latest_block)
            t.confirmations = 0 if not t.block_height else self.latest_block - t.block_height
            txs.append(t)
        return txs

    def getrawtransaction(self, txid):
        return self.compose_request('rawtx', txid, {'format': 'hex'})

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

    def getblock(self, blockid, parse_transactions, page, limit):
        bd = self.compose_request('rawblock', str(blockid))
        if parse_transactions:
            txs = []
            self.latest_block = self.blockcount() if not self.latest_block else self.latest_block
            for tx in bd['tx'][(page-1)*limit:page*limit]:
                # try:
                txs.append(self.gettransaction(tx['hash'], latest_block=self.latest_block))
                # except Exception as e:
                #     _logger.error("Could not parse tx %s with error %s" % (tx['hash'], e))
        else:
            txs = [tx['hash'] for tx in bd['tx']]

        block = {
            'bits': bd['bits'],
            'depth': None,
            'block_hash': bd['hash'],
            'height': bd['height'],
            'merkle_root': bd['mrkl_root'],
            'nonce': abs(bd['nonce']),
            'prev_block': bd['prev_block'],
            'time': bd['time'],
            'tx_count': len(bd['tx']),
            'txs': txs,
            'version': bd['ver'],
            'page': page,
            'pages': None if not limit else int(len(bd['tx']) // limit) + (len(bd['tx']) % limit > 0),
            'limit': limit
        }
        return block

    def getrawblock(self, blockid):
        return self.compose_request('rawblock', str(blockid), {'format': 'hex'})

    # def isspent(self, txid, index):

    def getinfo(self):
        import requests
        import json
        info = json.loads(requests.get('https://api.blockchain.info/stats', timeout=self.timeout).text)
        unconfirmed = self.compose_request('q', 'unconfirmedcount')
        return {
            'blockcount': info['n_blocks_total'],
            'chain': '',
            'difficulty': info['difficulty'],
            'hashrate': int(float(info['hash_rate'] * 10**9)),
            'mempool_size': unconfirmed,
        }
