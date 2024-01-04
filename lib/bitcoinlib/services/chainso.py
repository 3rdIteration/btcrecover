# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    Chain.so client
#    © 2017-2022 October - 1200 Web Development <http://1200wd.com/>
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

PROVIDERNAME = 'chainso'


class ChainSo(BaseClient):

    def __init__(self, network, base_url, denominator, *args):
        super(self.__class__, self).__init__(network, PROVIDERNAME, base_url, denominator, *args)

    def compose_request(self, function, data='', parameter='', variables=None, method='get'):
        url_path = function
        url_path += '/' + self.provider_coin_id
        if data:
            url_path += '/' + data
        if parameter:
            url_path += '/' + parameter
        if variables is None:
            variables = {}
        if self.api_key:
            variables.update({'api_key': self.api_key})
        return self.request(url_path, variables, method)

    def sendrawtransaction(self, rawtx):
        res = self.compose_request('send_tx', variables={'tx_hex': rawtx}, method='post')
        return {
            'txid': '' if 'data' not in res else res['data']['txid'],
            'response_dict': res
        }

    def getbalance(self, addresslist):
        balance = 0.0
        for address in addresslist:
            res = self.compose_request('get_address_balance', address)
            balance += float(res['data']['confirmed_balance']) + float(res['data']['unconfirmed_balance'])
        return int(balance * self.units)

    def getutxos(self, address, after_txid='', limit=MAX_TRANSACTIONS):
        txs = []
        lasttx = after_txid
        res = self.compose_request('get_tx_unspent', address, lasttx)
        if res['status'] != 'success':
            pass
        for tx in res['data']['txs'][:limit]:
            txs.append({
                'address': address,
                'txid': tx['txid'],
                'confirmations': tx['confirmations'],
                'output_n': -1 if 'output_no' not in tx else tx['output_no'],
                'input_n': -1 if 'input_no' not in tx else tx['input_no'],
                'block_height': None,
                'fee': None,
                'size': 0,
                'value': int(round(float(tx['value']) * self.units, 0)),
                'script': tx['script_hex'],
                'date': datetime.utcfromtimestamp(tx['time']),
            })
        if len(txs) >= 1000:
            _logger.warning("ChainSo: transaction list has been truncated, and thus is incomplete")
        return txs

    def getrawtransaction(self, txid):
        res = self.compose_request('get_tx', txid)
        return res['data']['tx_hex']

    def gettransaction(self, txid, block_height=None):
        res = self.compose_request('get_tx', txid)
        tx = res['data']
        rawtx = tx['tx_hex']
        t = Transaction.parse_hex(rawtx, strict=self.strict, network=self.network)
        input_total = 0
        output_total = 0
        if not t.coinbase:
            for n, i in enumerate(t.inputs):
                i.value = int(round(float(tx['inputs'][n]['value']) * self.units, 0))
                input_total += i.value
        for o in t.outputs:
            o.spent = None
            output_total += o.value
        if not t.block_height and tx['confirmations']:
            t.block_height = self.getblock(tx['blockhash'], False, 1, 1)['height']
        t.block_hash = tx['blockhash']
        t.rawtx = bytes.fromhex(rawtx)
        t.size = tx['size']
        t.network = self.network
        t.locktime = tx['locktime']
        t.input_total = input_total
        t.output_total = output_total
        t.fee = 0
        if t.input_total:
            t.fee = t.input_total - t.output_total
        t.confirmations = tx['confirmations']
        if tx['confirmations']:
            t.status = 'confirmed'
            t.date = datetime.utcfromtimestamp(tx['time'])
        else:
            t.status = 'unconfirmed'
            t.date = None
        return t

    def gettransactions(self, address, after_txid='', limit=MAX_TRANSACTIONS):
        txs = []
        res1 = self.compose_request('get_tx_received', address, after_txid)
        if res1['status'] != 'success':
            raise ClientError("Chainso get_tx_received request unsuccessful, status: %s" % res1['status'])
        res2 = self.compose_request('get_tx_spent', address, after_txid)
        if res2['status'] != 'success':
            raise ClientError("Chainso get_tx_spent request unsuccessful, status: %s" % res2['status'])
        res = res1['data']['txs'] + res2['data']['txs']
        res = sorted(res, key=lambda x: x['time'])
        tx_conf = []
        for t in res:
            tt = (t['confirmations'], t['txid'])
            if tt not in tx_conf:
                tx_conf.append(tt)
        for tx in tx_conf[:limit]:
            t = self.gettransaction(tx[1])
            txs.append(t)
        return txs

    def blockcount(self):
        return self.compose_request('get_info')['data']['blocks']

    def mempool(self, txid):
        res = self.compose_request('is_tx_confirmed', txid)
        if res['status'] == 'success' and res['data']['confirmations'] == 0:
            return [txid]
        return []

    def getblock(self, blockid, parse_transactions, page, limit):
        if limit > 5:
            limit = 5
        bd = self.compose_request('get_block', str(blockid))['data']
        if parse_transactions:
            txs = []
            for txid in bd['txs'][(page-1)*limit:page*limit]:
                # try:
                txs.append(self.gettransaction(txid, block_height=bd['block_no']))
                # except Exception as e:
                #     raise ClientError("Could not parse tx %s with error %s" % (txid, e))
        else:
            txs = bd['txs']

        n_txs = len(bd['txs'])
        block = {
            'bits': None,
            'depth': bd['confirmations'],
            'block_hash': bd['blockhash'],
            'height': bd['block_no'],
            'merkle_root': bd['merkleroot'],
            'nonce': None,
            'prev_block': bd['previous_blockhash'],
            'time': bd['time'],
            'tx_count': n_txs,
            'txs': txs,
            'version': b'',
            'page': page,
            'pages': None if not limit else int(n_txs // limit) + (n_txs % limit > 0),
            'limit': limit
        }
        return block

    # def getrawblock(self, blockid):

    # def isspent(self, txid, output_n):

    def getinfo(self):
        info = self.compose_request('get_info')['data']
        return {
            'blockcount': info['blocks'],
            'chain': info['name'],
            'difficulty': int(float(info['mining_difficulty'])),
            'hashrate': int(float(info['hashrate'])),
            'mempool_size': int(info['unconfirmed_txs']),
        }
