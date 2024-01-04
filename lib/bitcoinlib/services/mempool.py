# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    mempool.space client
#    © 2021-2023 May - 1200 Web Development <http://1200wd.com/>
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
from bitcoinlib.encoding import varstr

PROVIDERNAME = 'mempool'
# Please note: In the Blockstream API, the first couple of Bitcoin blocks are not correctly indexed,
# so transactions from these blocks are missing.

_logger = logging.getLogger(__name__)


class MempoolClient(BaseClient):

    def __init__(self, network, base_url, denominator, *args):
        super(self.__class__, self).__init__(network, PROVIDERNAME, base_url, denominator, *args)

    def compose_request(self, function, data='', parameter='', parameter2='', variables=None, post_data='',
                        method='get'):
        url_path = function
        if data:
            url_path += '/' + data
        if parameter:
            url_path += '/' + parameter
        if parameter2:
            url_path += '/' + parameter2
        if variables is None:
            variables = {}
        if self.api_key:
            variables.update({'token': self.api_key})
        return self.request(url_path, variables, method, post_data=post_data)

    def getbalance(self, addresslist):
        balance = 0
        for address in addresslist:
            res = self.compose_request('address', address)
            balance += res['chain_stats']['funded_txo_sum'] - res['chain_stats']['spent_txo_sum']
        return balance

    def getutxos(self, address, after_txid='', limit=MAX_TRANSACTIONS):
        self.latest_block = self.blockcount() if not self.latest_block else self.latest_block
        res = self.compose_request('address', address, 'utxo')
        utxos = []
        # # key=lambda k: (k[2], pow(10, 20)-k[0].transaction_id, k[3]), reverse=True
        res = sorted(res, key=lambda k: 0 if 'block_height' not in k['status'] else k['status']['block_height'])
        for a in res:
            confirmations = 0
            block_height = None
            if 'block_height' in a['status']:
                block_height = a['status']['block_height']
                confirmations = self.latest_block - block_height
            utxos.append({
                'address': address,
                'txid': a['txid'],
                'confirmations': confirmations,
                'output_n': a['vout'],
                'input_n': 0,
                'block_height': block_height,
                'fee': None,
                'size': 0,
                'value': a['value'],
                'script': '',
                'date': None if 'block_time' not in a['status'] else datetime.utcfromtimestamp(a['status']['block_time'])
            })
            if a['txid'] == after_txid:
                utxos = []
        return utxos[:limit]

    def _parse_transaction(self, tx):
        block_height = None if 'block_height' not in tx['status'] else tx['status']['block_height']
        confirmations = 0
        tx_date = None
        status = 'unconfirmed'
        if tx['status']['confirmed']:
            if block_height:
                self.latest_block = self.blockcount() if not self.latest_block else self.latest_block
                confirmations = self.latest_block - block_height + 1
            tx_date = datetime.utcfromtimestamp(tx['status']['block_time'])
            status = 'confirmed'

        t = Transaction(locktime=tx['locktime'], version=tx['version'], network=self.network, block_height=block_height,
                        fee=tx['fee'], size=tx['size'], txid=tx['txid'], date=tx_date, confirmations=confirmations,
                        status=status, coinbase=tx['vin'][0]['is_coinbase'])
        for ti in tx['vin']:
            if ti['is_coinbase']:
                t.add_input(prev_txid=ti['txid'], output_n=ti['vout'], unlocking_script=ti['scriptsig'], value=0,
                            sequence=ti['sequence'], strict=self.strict)
            else:
                t.add_input(prev_txid=ti['txid'], output_n=ti['vout'],
                            unlocking_script=ti['scriptsig'], value=ti['prevout']['value'],
                            address=ti['prevout'].get('scriptpubkey_address', ''),
                            unlocking_script_unsigned=ti['prevout']['scriptpubkey'], sequence=ti['sequence'],
                            witnesses=None if 'witness' not in ti else [bytes.fromhex(w) for w in ti['witness']],
                            strict=self.strict)
        for to in tx['vout']:
            t.add_output(value=to['value'], address=to.get('scriptpubkey_address', ''), spent=None,
                         lock_script=to['scriptpubkey'], strict=self.strict)
        if 'segwit' in [i.witness_type for i in t.inputs] or 'p2sh-segwit' in [i.witness_type for i in t.inputs]:
            t.witness_type = 'segwit'
        t.update_totals()
        return t

    def gettransaction(self, txid):
        tx = self.compose_request('tx', txid)
        return self._parse_transaction(tx)

    def gettransactions(self, address, after_txid='', limit=MAX_TRANSACTIONS):
        prtxs = []
        before_txid = ''
        while True:
            txs = self.compose_request('address', address, 'txs', before_txid)
            prtxs += txs
            if len(txs) == 25:
                before_txid = txs[-1:][0]['txid']
            else:
                break
            if len(prtxs) > 100:
                break
        txs = []
        for tx in prtxs[::-1]:
            t = self._parse_transaction(tx)
            if t:
                txs.append(t)
            if t.txid == after_txid:
                txs = []
            if len(txs) > limit:
                break
        return txs[:limit]

    def getrawtransaction(self, txid):
        return self.compose_request('tx', txid, 'hex')

    def sendrawtransaction(self, rawtx):
        return self.compose_request('tx', post_data=rawtx, method='post')

    def estimatefee(self, blocks):
        estimates = self.compose_request('v1/fees', 'recommended')
        if blocks < 2:
            return estimates['fastestFee'] * 1000
        elif blocks < 4:
            return estimates['halfHourFee'] * 1000
        if blocks < 7:
            return estimates['hourFee'] * 1000
        else:
            return estimates['minimumFee'] * 1000

    def blockcount(self):
        res = self.compose_request('blocks', 'tip', 'height')
        return res

    def mempool(self, txid=''):
        txids = self.compose_request('mempool', 'txids')
        if not txid:
            return txids
        if txid in txids:
            return [txid]
        return []

    def getblock(self, blockid, parse_transactions, page, limit):
        if isinstance(blockid, int):
            blockid = self.compose_request('block-height', str(blockid))
        if (page == 1 and limit == 10) or limit > 25:
            limit = 25
        bd = self.compose_request('block', blockid)
        btxs = self.compose_request('block', blockid, 'txs', str((page-1)*limit))
        if parse_transactions:
            txs = []
            for tx in btxs[:limit]:
                txs.append(self._parse_transaction(tx))
        else:
            txs = [tx['txid'] for tx in btxs]

        block = {
            'bits': bd['bits'],
            'depth': None,
            'block_hash': bd['id'],
            'height': bd['height'],
            'merkle_root': bd['merkle_root'],
            'nonce': bd['nonce'],
            'prev_block': bd['previousblockhash'],
            'time': bd['timestamp'],
            'tx_count': bd['tx_count'],
            'txs': txs,
            'version': bd['version'],
            'page': page,
            'pages': None if not limit else int(bd['tx_count'] // limit) + (bd['tx_count'] % limit > 0),
            'limit': limit
        }
        return block

    def getrawblock(self, blockid):
        if isinstance(blockid, int):
            blockid = self.compose_request('block-height', str(blockid))
        return self.compose_request('block', blockid, 'raw').hex()

    def isspent(self, txid, output_n):
        res = self.compose_request('tx', txid, 'outspend', str(output_n))
        return 1 if res['spent'] else 0

    # def getinfo(self):
