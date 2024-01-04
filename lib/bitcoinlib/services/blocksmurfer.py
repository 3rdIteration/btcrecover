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
from bitcoinlib.main import MAX_TRANSACTIONS
from bitcoinlib.services.baseclient import BaseClient, ClientError
from bitcoinlib.transactions import Transaction

PROVIDERNAME = 'blocksmurfer'


_logger = logging.getLogger(__name__)


class BlocksmurferClient(BaseClient):

    def __init__(self, network, base_url, denominator, *args):
        super(self.__class__, self).__init__(network, PROVIDERNAME, base_url, denominator, *args)

    def compose_request(self, function, parameter='', parameter2='', variables=None, post_data='', method='get'):
        url_path = function
        if parameter:
            url_path += '/' + str(parameter)
        if parameter2:
            url_path += '/' + str(parameter2)
        if variables is None:
            variables = {}
        if self.api_key:
            variables.update({'token': self.api_key})
        return self.request(url_path, variables, method, post_data=post_data)

    def getbalance(self, addresslist):
        balance = 0
        for address in addresslist:
            res = self.compose_request('address_balance', address)
            balance += res['balance']
        return balance

    # TODO: fix blocksmurfer api
    def getutxos(self, address, after_txid='', limit=MAX_TRANSACTIONS):
        res = self.compose_request('utxos', address, variables={'after_txid': after_txid})
        self.latest_block = self.blockcount() if not self.latest_block else self.latest_block
        utxos = []
        for u in res:
            block_height = None if not u['block_height'] else u['block_height']
            confirmations = u['confirmations']
            if block_height and not confirmations:
                confirmations = self.latest_block - block_height
            utxos.append({
                'address': address,
                'txid': u['txid'],
                'confirmations': confirmations,
                'output_n': u['output_n'],
                'input_n': u['input_n'],
                'block_height': block_height,
                'fee': u['fee'],
                'size': u['size'],
                'value': u['value'],
                'script': u['script'],
                'date': datetime.strptime(u['date'][:19], "%Y-%m-%dT%H:%M:%S")
            })
        return utxos[:limit]

    def _parse_transaction(self, tx, block_height=None):
        block_height = block_height if not tx['block_height'] else tx['block_height']
        confirmations = tx['confirmations']
        if block_height and not confirmations and tx['status'] == 'confirmed':
            self.latest_block = self.blockcount() if not self.latest_block else self.latest_block
            confirmations = self.latest_block - block_height
        # FIXME: Blocksmurfer returns 'date' or 'time', should be consistent
        tx_date = None if not tx.get('date') else datetime.strptime(tx['date'], "%Y-%m-%dT%H:%M:%S")
        if not tx_date and 'time' in tx:
            tx_date = datetime.utcfromtimestamp(tx['time'])
        t = Transaction(locktime=tx['locktime'], version=tx['version'], network=self.network,
                        fee=tx['fee'], size=tx['size'], txid=tx['txid'], date=tx_date, input_total=tx['input_total'],
                        output_total=tx['output_total'], confirmations=confirmations, block_height=block_height,
                        status=tx['status'], coinbase=tx['coinbase'], rawtx=bytes.fromhex(tx['raw_hex']),
                        witness_type=tx['witness_type'])
        for ti in tx['inputs']:
            t.add_input(prev_txid=ti['prev_txid'], output_n=ti['output_n'], keys=ti.get('keys', []),
                        index_n=ti['index_n'], unlocking_script=ti['script'], value=ti['value'],
                        public_hash=bytes.fromhex(ti['public_hash']), address=ti['address'],
                        witness_type=ti['witness_type'], locktime_cltv=ti['locktime_cltv'],
                        locktime_csv=ti['locktime_csv'], signatures=ti['signatures'], compressed=ti['compressed'],
                        encoding=ti['encoding'], unlocking_script_unsigned=ti['script_code'],
                        sigs_required=ti['sigs_required'], sequence=ti['sequence'],
                        witnesses=[bytes.fromhex(w) for w in ti['witnesses']], script_type=ti['script_type'],
                        strict=self.strict)
        for to in tx['outputs']:
            t.add_output(value=to['value'], address=to['address'], public_hash=to['public_hash'],
                         lock_script=to['script'], spent=to['spent'], strict=self.strict)
        t.update_totals()
        return t

    def gettransaction(self, txid, block_count=None):
        tx = self.compose_request('transaction', txid)
        return self._parse_transaction(tx, block_count)

    def gettransactions(self, address, after_txid='', limit=MAX_TRANSACTIONS):
        prtxs = []
        while True:
            txs = self.compose_request('transactions', address, variables={'after_txid': after_txid})
            prtxs += txs
            if not txs or len(txs) < limit:
                break
            after_txid = txs[-1:][0]['txid']
        txs = []
        for tx in prtxs:
            t = self._parse_transaction(tx)
            if t:
                txs.append(t)
        return txs[:limit]

    def getrawtransaction(self, txid):
        tx = self.compose_request('transaction', txid, variables={'raw': True})
        return tx['raw_hex']

    def sendrawtransaction(self, rawtx):
        res = self.compose_request('transaction_broadcast', post_data=rawtx, method='post')
        return {
            'txid': res['txid'],
            'response_dict': res
        }

    def estimatefee(self, blocks):
        variables = {
            'blocks': str(blocks)
        }
        res = self.compose_request('fees', variables=variables)
        return res['estimated_fee_sat_kb']

    def blockcount(self):
        return self.compose_request('blockcount')['blockcount']

    def mempool(self, txid):
        if txid:
            t = self.gettransaction(txid)
            if t and not t.confirmations:
                return [t.txid]
        # else:
            # return self.compose_request('mempool', 'txids')
        return []

    def getblock(self, blockid, parse_transactions, page, limit):
        variables = {'parse_transactions': parse_transactions, 'page': page, 'limit': limit}
        bd = self.compose_request('block', str(blockid), variables=variables)

        txs = []
        if parse_transactions and bd['transactions'] and isinstance(bd['transactions'][0], dict):
            self.latest_block = self.blockcount() if not self.latest_block else self.latest_block
            for tx in bd['transactions']:
                tx['confirmations'] = bd['depth']
                tx['time'] = bd['time']
                tx['block_height'] = bd['height']
                tx['block_hash'] = bd['block_hash']
                t = self._parse_transaction(tx, self.latest_block)
                if t.txid != tx['txid']:
                    raise ClientError("Could not parse tx %s. Different txid's" % (tx['txid']))
                txs.append(t)
        else:
            txs = bd['transactions']

        block = {
            'bits': bd['bits'],
            'depth': bd['depth'],
            'block_hash': bd['block_hash'],
            'height': bd['height'],
            'merkle_root': bd['merkle_root'],
            'nonce': bd['nonce'],
            'prev_block': bd['prev_block'],
            'time': bd['time'],
            'tx_count': bd['tx_count'],
            'txs': txs,
            'version': bd['version'],
            'page': page,
            'pages': None if not limit else int(bd['tx_count'] // limit) + (bd['tx_count'] % limit > 0),
            'limit': limit
        }
        return block

    def getrawblock(self, blockid):
        res = self.compose_request('rawblock', blockid)
        return res

    def isspent(self, txid, output_n):
        res = self.compose_request('isspent', txid, str(output_n))
        return 1 if res['spent'] else 0

    def getinfo(self):
        res = self.compose_request('')
        info = {k: v for k, v in res.items() if k in ['chain', 'blockcount', 'hashrate', 'mempool_size',
                                                      'difficulty']}
        return info
