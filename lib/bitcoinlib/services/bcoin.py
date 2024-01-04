# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    Client for Bcoin Node
#    © 2019 - 2023 March - 1200 Web Development <http://1200wd.com/>
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

from bitcoinlib.main import *
from bitcoinlib.services.baseclient import BaseClient, ClientError
from bitcoinlib.transactions import Transaction, transaction_update_spents


PROVIDERNAME = 'bcoin'

_logger = logging.getLogger(__name__)


class BcoinClient(BaseClient):
    """
    Class to interact with Bcoin API
    """

    def __init__(self, network, base_url, denominator, *args):
        super(self.__class__, self).__init__(network, PROVIDERNAME, base_url, denominator, *args)

    def compose_request(self, func, data='', parameter='', variables=None, method='get'):
        url_path = func
        if data:
            url_path += '/' + str(data)
        if parameter:
            url_path += '/' + parameter
        if variables is None:
            variables = {}
        return self.request(url_path, variables, method, secure=False)

    def _parse_transaction(self, tx):
        status = 'unconfirmed'
        if tx['confirmations']:
            status = 'confirmed'
        t = Transaction.parse_hex(tx['hex'], strict=False, network=self.network)
        t.locktime = tx['locktime']
        t.network = self.network
        t.fee = tx['fee']
        t.date = datetime.utcfromtimestamp(tx['time']) if tx['time'] else None
        t.confirmations = tx['confirmations']
        t.block_height = tx['height'] if tx['height'] > 0 else None
        t.block_hash = tx['block']
        t.status = status
        if not t.coinbase:
            for i in t.inputs:
                i.value = tx['inputs'][t.inputs.index(i)]['coin']['value']
        for o in t.outputs:
            o.spent = None
        t.update_totals()
        return t

    def getbalance(self, addresslist):
        balance = 0.0
        from bitcoinlib.services.services import Service
        for address in addresslist:
            # First get all transactions for this address from the blockchain
            srv = Service(network=self.network.name, providers=['bcoin'])
            txs = srv.gettransactions(address, limit=MAX_TRANSACTIONS)

            # Fail if large number of transactions are found
            if not srv.complete:
                raise ClientError("If not all transactions are known, we cannot determine utxo's. "
                                  "Increase limit or use other provider.")

            for a in [output for outputs in [t.outputs for t in txs] for output in outputs]:
                if a.address == address:
                    balance += a.value
            for a in [i for inputs in [t.inputs for t in txs] for i in inputs]:
                if a.address == address:
                    balance -= a.value
        return int(balance)

    def getutxos(self, address, after_txid='', limit=MAX_TRANSACTIONS):
        # First get all transactions for this address from the blockchain
        txs = self.gettransactions(address, limit=50)

        # Fail if large number of transactions are found
        if len(txs) > 50:
            raise ClientError("If not all transactions are known, we cannot determine utxo's")

        utxos = []
        for tx in txs:
            for unspent in tx.outputs:
                if unspent.address != address:
                    continue
                if not self.isspent(tx.txid, unspent.output_n):
                    utxos.append(
                        {
                            'address': unspent.address,
                            'txid': tx.txid,
                            'confirmations': tx.confirmations,
                            'output_n': unspent.output_n,
                            'input_n': 0,
                            'block_height': tx.block_height,
                            'fee': tx.fee,
                            'size': tx.size,
                            'value': unspent.value,
                            'script': unspent.lock_script.hex(),
                            'date': tx.date,
                         }
                    )
                    if tx.txid == after_txid:
                        utxos = []
        return utxos[:limit]

    def gettransaction(self, txid):
        tx = self.compose_request('tx', txid)
        return self._parse_transaction(tx)

    def gettransactions(self, address, after_txid='', limit=MAX_TRANSACTIONS):
        assert(limit > 0)
        txs = []
        while True:
            variables = {'limit': limit, 'after': after_txid}
            res = self.compose_request('tx', 'address', address, variables)
            for tx in res:
                txs.append(self._parse_transaction(tx))
            if not txs or len(txs) >= limit:
                break
            if len(res) == limit:
                after_txid = res[limit-1]['hash']
            else:
                break

        # Check which outputs are spent/unspent for this address
        if not after_txid and len(txs) != limit:
            txs = transaction_update_spents(txs, address)
        return txs

    def getrawtransaction(self, txid):
        return self.compose_request('tx', txid)['hex']

    def sendrawtransaction(self, rawtx):
        res = self.compose_request('broadcast', variables={'tx': rawtx}, method='post')
        txid = ''
        if 'success' in res and res['success']:
            t = Transaction.parse_hex(rawtx, network=self.network)
            txid = t.txid
        return {
            'txid': txid,
            'response_dict': res
        }

    def estimatefee(self, blocks):
        if blocks > 15:
            blocks = 15
        fee = self.compose_request('fee', variables={'blocks': blocks})['rate']
        if not fee:
            return False
        return fee

    def blockcount(self):
        return self.compose_request('')['chain']['height']

    def mempool(self, txid=''):
        txids = self.compose_request('mempool')
        if not txid:
            return txids
        elif txid in txids:
            return [txid]
        return []

    def getblock(self, blockid, parse_transactions, page, limit):
        block = self.compose_request('block', str(blockid))
        block['tx_count'] = len(block['txs'])
        txs = block['txs']
        parsed_txs = []
        if parse_transactions:
            txs = txs[(page-1)*limit:page*limit]
        for tx in txs:
            tx['confirmations'] = block['depth']
            tx['time'] = block['time']
            tx['height'] = block['height']
            tx['block'] = block['hash']
            if parse_transactions:
                t = self._parse_transaction(tx)
                parsed_txs.append(t)
            else:
                parsed_txs.append(tx['hash'])

        block['time'] = block['time']
        block['txs'] = parsed_txs
        block['page'] = page
        block['pages'] = None if not limit else int(block['tx_count'] // limit) + (block['tx_count'] % limit > 0)
        block['limit'] = limit
        block['prev_block'] = block.pop('prevBlock')
        block['merkle_root'] = block.pop('merkleRoot')
        block['block_hash'] = block.pop('hash')
        return block

    def getrawblock(self, blockid):
        try:
            blockid = int(blockid)
            data = {
                "method": "getblockbyheight",
                "params": [blockid, 0, 0]
            }
        except ValueError:
            data = {
                "method": "getblock",
                "params": [blockid, 0, 0]
            }
        res = self.compose_request('', method='post', variables=data)
        return res['result']

    def isspent(self, txid, index):
        try:
            self.compose_request('coin', txid, str(index))
        except ClientError:
            return 1
        return 0

    def getinfo(self):
        res = self.compose_request('', variables={'method': 'getmininginfo'}, method='post')
        info = res['result']
        return {
            'blockcount': info['blocks'],
            'chain': info['chain'],
            'difficulty': info['difficulty'],
            'hashrate': info['networkhashps'],
            'mempool_size': info['pooledtx']
        }
