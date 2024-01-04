# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    litecoinblockexplorer.net Client
#    © 2019-2023 May - 1200 Web Development <http://1200wd.com/>
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

PROVIDERNAME = 'litecoinblockexplorer'
REQUEST_LIMIT = 50

_logger = logging.getLogger(__name__)


class LitecoinBlockexplorerClient(BaseClient):

    def __init__(self, network, base_url, denominator, *args):
        super(self.__class__, self).__init__(network, PROVIDERNAME, base_url, denominator, *args)

    def compose_request(self, category, data, cmd='', variables=None, method='get', offset=0):
        url_path = category
        if data:
            url_path += '/' + data + ('' if not cmd else '/' + cmd)
        if variables is None:
            variables = {}
        variables.update({'from': offset, 'to': offset+REQUEST_LIMIT})
        return self.request(url_path, variables, method=method)

    def _convert_to_transaction(self, tx):
        if tx['confirmations']:
            status = 'confirmed'
        else:
            status = 'unconfirmed'
        fees = None if 'fees' not in tx else int(round(float(tx['fees']) * self.units, 0))
        value_in = 0 if 'valueIn' not in tx else int(round(float(tx['valueIn']) * self.units, 0))
        txdate = None
        if 'blocktime' in tx:
            txdate = datetime.utcfromtimestamp(tx['blocktime'])
        t = Transaction.parse_hex(tx['hex'], strict=self.strict, network=self.network)
        t.fee = fees
        t.input_total = value_in
        t.output_total = int(round(float(tx['valueOut']) * self.units, 0))
        t.fees = int(round(float(tx['fees']) * self.units, 0))
        t.date = txdate
        t.confirmations = tx['confirmations']
        t.block_height = tx['blockheight']
        if t.confirmations == 0:
            t.block_height = None
            t.date = None
        t.block_hash = tx.get('blockhash', '')
        t.status = status
        for n, ti in enumerate(tx['vin']):
            t.inputs[n].value = int(round(float(ti['value'] or 0) * self.units, 0))
        for i, to in enumerate(tx['vout']):
            t.outputs[i].spent = to['spent']
        return t

    def getbalance(self, addresslist):
        balance = 0
        addresslist = self._addresslist_convert(addresslist)
        for a in addresslist:
            res = self.compose_request('address', a.address)
            balance += int(float(res['balance']) / self.network.denominator)
        return balance

    def getutxos(self, address, after_txid='', limit=MAX_TRANSACTIONS):
        address = self._address_convert(address)
        res = self.compose_request('utxo', address.address)
        txs = []
        for tx in res:
            if tx['txid'] == after_txid:
                break
            txs.append({
                'address': address.address_orig,
                'txid': tx['txid'],
                'confirmations': tx['confirmations'],
                'output_n': tx['vout'],
                'input_n': 0,
                'block_height': tx['height'],
                'fee': None,
                'size': 0,
                'value': tx['satoshis'],
                'script': tx.get('scriptPubKey', ''),
                'date': None
            })
        return txs[::-1][:limit]

    def gettransaction(self, txid):
        tx = self.compose_request('tx', txid)
        return self._convert_to_transaction(tx)

    # FIXME: Not available anymore
    # def gettransactions(self, address, after_txid='', limit=MAX_TRANSACTIONS):
    #     address = self._address_convert(address)
    #     res = self.compose_request('addrs', address.address, 'txs')
    #     txs = []
    #     txs_dict = res['items'][::-1]
    #     if after_txid:
    #         txs_dict = txs_dict[[t['txid'] for t in txs_dict].index(after_txid) + 1:]
    #     for tx in txs_dict[:limit]:
    #         if tx['txid'] == after_txid:
    #             break
    #         txs.append(self._convert_to_transaction(tx))
    #     return txs

    def getrawtransaction(self, txid):
        res = self.compose_request('tx', txid)
        return res['hex']

    def sendrawtransaction(self, rawtx):
        res = self.compose_request('sendtx', data=rawtx)
        return {
            'txid': res['result'],
            'response_dict': res
        }

    def estimatefee(self, blocks):
        res = self.compose_request('estimatefee', str(int(blocks)+1))
        return int(float(res['result']) / self.network.denominator)

    def blockcount(self):
        res = self.compose_request('status', '', variables={'q': 'getinfo'})
        return res['blockbook']['bestHeight']

    def mempool(self, txid):
        res = self.compose_request('tx', txid)
        if res['confirmations'] == 0:
            return res['txid']
        return []

    def getblock(self, blockid, parse_transactions, page, limit):
        bd = self.compose_request('block', str(blockid))
        if parse_transactions:
            txs = []
            for tx in bd['txs'][(page-1)*limit:page*limit]:
                txs.append(self.gettransaction(tx['txid']))
        else:
            txs = [tx['txid'] for tx in bd['txs']]

        block = {
            'bits': int(bd['bits'], 16),
            'depth': bd['confirmations'],
            'block_hash': bd['hash'],
            'height': bd['height'],
            'merkle_root': bd['merkleRoot'],
            'nonce': int(bd['nonce']),
            'prev_block': bd['previousBlockHash'],
            'time': bd['time'],
            'tx_count': bd['txCount'],
            'txs': txs,
            'version': bd['version'],
            'page': page,
            'pages': None if not limit else int(len(bd['txs']) // limit) + (len(bd['txs']) % limit > 0),
            'limit': limit
        }
        return block

    # def getrawblock(self, blockid):

    def isspent(self, txid, output_n):
        t = self.gettransaction(txid)
        return 1 if t.outputs[output_n].spent else 0

    def getinfo(self):
        info = self.compose_request('status', '')
        return {
            'blockcount': info['backend']['blocks'],
            'chain': info['backend']['chain'],
            'difficulty': int(float(info['backend']['difficulty'])),
            'hashrate': 0,
            'mempool_size': info['blockbook']['mempoolSize'],
        }
