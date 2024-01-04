# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    BlockstreamClient client
#    © 2019 November - 1200 Web Development <http://1200wd.com/>
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
from bitcoinlib.encoding import to_hexstring

PROVIDERNAME = 'groestlcoinesplora'
# Please note: In the Blockstream API, the first couple of Groestlcoin blocks are not correctly indexed,
# so transactions from these blocks are missing.

_logger = logging.getLogger(__name__)


class GroesltcoinEsploraClient(BaseClient):

    def __init__(self, network, base_url, denominator, *args):
        super(self.__class__, self).__init__(network, PROVIDERNAME, base_url, denominator, *args)

    def compose_request(self, function, data='', parameter='', variables=None, post_data='', method='get'):
        url_path = function
        if data:
            url_path += '/' + data
        if parameter:
            url_path += '/' + parameter
        if variables is None:
            variables = {}
        if self.api_key:
            variables.update({'token': self.api_key})
        return self.request(url_path, variables, method, post_data=post_data)

    def getbalance(self, addresslist):
        balance = 0
        for address in addresslist:
            res = self.compose_request('address', data=address)
            balance += (res['chain_stats']['funded_txo_sum'] - res['chain_stats']['spent_txo_sum'])
        return balance

    def getutxos(self, address, after_txid='', max_txs=MAX_TRANSACTIONS):
        res = self.compose_request('address', address, 'utxo')
        blockcount = self.blockcount()
        utxos = []
        # # key=lambda k: (k[2], pow(10, 20)-k[0].transaction_id, k[3]), reverse=True
        res = sorted(res, key=lambda k: 0 if 'block_height' not in k['status'] else k['status']['block_height'])
        for a in res:
            confirmations = 0
            block_height = None
            if 'block_height' in a['status']:
                block_height = a['status']['block_height']
                confirmations = blockcount - block_height
            utxos.append({
                'address': address,
                'tx_hash': a['txid'],
                'confirmations': confirmations,
                'output_n': a['vout'],
                'input_n': 0,
                'block_height': block_height,
                'fee': None,
                'size': 0,
                'value': a['value'],
                'script': '',
                'date': None if 'block_time' not in a['status'] else datetime.fromtimestamp(a['status']['block_time'])
            })
            if a['txid'] == after_txid:
                utxos = []
        return utxos[:max_txs]

    def _parse_transaction(self, tx, blockcount=None):
        if not blockcount:
            blockcount = self.blockcount()
        confirmations = 0
        block_height = None
        if 'block_height' in tx['status']:
            block_height = tx['status']['block_height']
            confirmations = blockcount - block_height
        status = 'unconfirmed'
        if tx['status']['confirmed']:
            status = 'confirmed'
        fee = None if 'fee' not in tx else tx['fee']
        t = Transaction(locktime=tx['locktime'], version=tx['version'], network=self.network,
                        fee=fee, size=tx['size'], hash=tx['txid'],
                        date=None if 'block_time' not in tx['status'] else datetime.fromtimestamp(tx['status']['block_time']),
                        confirmations=confirmations, block_height=block_height, status=status,
                        coinbase=tx['vin'][0]['is_coinbase'])
        index_n = 0
        for ti in tx['vin']:
            if tx['vin'][0]['is_coinbase']:
                t.add_input(prev_hash=ti['txid'], output_n=ti['vout'], index_n=index_n,
                            unlocking_script=ti['scriptsig'], value=sum([o['value'] for o in tx['vout']]))
            else:
                t.add_input(prev_hash=ti['txid'], output_n=ti['vout'],
                            unlocking_script_unsigned=ti['prevout']['scriptpubkey'], index_n=index_n,
                            value=ti['prevout']['value'], address=ti['prevout']['scriptpubkey_address'],
                            unlocking_script=ti['scriptsig'])
            index_n += 1
        index_n = 0
        for to in tx['vout']:
            address = ''
            if 'scriptpubkey_address' in to:
                address = to['scriptpubkey_address']
            t.add_output(value=to['value'], address=address, lock_script=to['scriptpubkey'],
                         output_n=index_n, spent=None)
            index_n += 1
        if 'segwit' in [i.witness_type for i in t.inputs]:
            t.witness_type = 'segwit'
        t.update_totals()
        return t

    def gettransaction(self, txid):
        tx = self.compose_request('tx', txid)
        return self._parse_transaction(tx)

    def gettransactions(self, address, after_txid='', max_txs=MAX_TRANSACTIONS):
        block_height = self.blockcount()
        prtxs = []
        before_txid = ''
        while True:
            parameter = 'txs'
            if before_txid:
                parameter = 'txs/chain/%s' % before_txid
            res = self.compose_request('address', address, parameter)
            prtxs += res
            if len(res) == 25:
                before_txid = res[-1:]['txid']
            else:
                break
        txs = []
        for tx in prtxs[::-1]:
            t = self._parse_transaction(tx, block_height)
            if t:
                txs.append(t)
            if t.hash == after_txid:
                txs = []
            if len(txs) > max_txs:
                break
        return txs[:max_txs]

    def getrawtransaction(self, txid):
        return self.compose_request('tx', txid, 'hex')

    def sendrawtransaction(self, rawtx):
        res = self.compose_request('tx', post_data=rawtx, method='post')
        return {
            'txid': res,
            'response_dict': res
        }

    def estimatefee(self, blocks):
        est = self.compose_request('fee-estimates')
        closest = (sorted([int(i) - blocks for i in est.keys() if int(i) - blocks >= 0]))
        if closest:
            return int(est[str(closest[0] + blocks)] * 1024)
        else:
            return int(est[str(sorted([int(i) for i in est.keys()])[-1:][0])] * 1024)

    def blockcount(self):
        return self.compose_request('blocks', 'tip', 'height')

    def mempool(self, txid):
        if txid:
            t = self.gettransaction(txid)
            if t and not t.confirmations:
                return [t.hash]
        else:
            return self.compose_request('mempool', 'txids')
        return []
