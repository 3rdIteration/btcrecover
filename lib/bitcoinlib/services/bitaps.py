# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    BitAps client
#    © 2019 - 2023 May - 1200 Web Development <http://1200wd.com/>
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

PROVIDERNAME = 'bitaps'
# Please note: In the Bitaps API, the first couple of Bitcoin blocks are not correctly indexed,
# so transactions from these blocks are missing.


class BitapsClient(BaseClient):

    def __init__(self, network, base_url, denominator, *args):
        super(self.__class__, self).__init__(network, PROVIDERNAME, base_url, denominator, *args)

    def compose_request(self, category, command='', data='', variables=None, req_type='blockchain', method='get'):
        url_path = req_type + '/' + category
        if command:
            url_path += '/' + command
        if data:
            if url_path[-1:] != '/':
                url_path += '/'
            url_path += data
        return self.request(url_path, variables=variables, method=method)

    def _parse_transaction(self, tx):
        status = 'unconfirmed'
        if tx['confirmations']:
            status = 'confirmed'
        date = None
        if 'timestamp' in tx and tx['timestamp']:
            date = datetime.utcfromtimestamp(tx['timestamp'])
        elif 'blockTime' in tx and tx['blockTime']:
            date = datetime.utcfromtimestamp(tx['blockTime'])
        block_height = None
        if 'blockHeight' in tx:
            block_height = tx['blockHeight']
        witness_type = 'legacy'
        if tx['segwit']:
            witness_type = 'segwit'

        t = Transaction(
            locktime=tx['lockTime'], version=tx['version'], network=self.network, fee=tx['fee'],
            fee_per_kb=None if 'feeRate' not in tx else int(tx['feeRate']), size=tx['size'],
            txid=tx['txId'], date=date, confirmations=tx['confirmations'], block_height=block_height,
            input_total=tx['inputsAmount'], output_total=tx['outputsAmount'], status=status, coinbase=tx['coinbase'],
            verified=None if 'valid' not in tx else tx['valid'], witness_type=witness_type)

        for n, ti in tx['vIn'].items():
            if t.coinbase:
                t.add_input(prev_txid=ti['txId'], output_n=ti['vOut'], unlocking_script=ti['scriptSig'],
                            sequence=ti['sequence'], index_n=int(n), value=0)
            else:
                t.add_input(prev_txid=ti['txId'], output_n=ti['vOut'], unlocking_script=ti['scriptSig'],
                            unlocking_script_unsigned=ti['scriptPubKey'], witnesses=ti.get('txInWitness', []),
                            address='' if 'address' not in ti else ti['address'], sequence=ti['sequence'],
                            index_n=int(n), value=ti['amount'], strict=self.strict)

        for _, to in tx['vOut'].items():
            spending_txid = None if not to['spent'] else to['spent'][0]['txId']
            spending_index_n = None if not to['spent'] else to['spent'][0]['vIn']
            t.add_output(to['value'], '' if 'address' not in to else to['address'],
                         '' if 'addressHash' not in to else to['addressHash'], lock_script=to['scriptPubKey'],
                         spent=bool(to['spent']), spending_txid=spending_txid, spending_index_n=spending_index_n,
                         strict=self.strict)

        return t

    def getbalance(self, addresslist):
        balance = 0
        for address in addresslist:
            res = self.compose_request('address', 'state', address)
            balance += res['data']['balance']
        return balance

    def getutxos(self, address, after_txid='', limit=MAX_TRANSACTIONS):
        utxos = []
        page = 1
        while True:
            variables = {'mode': 'verbose', 'limit': 50, 'page': page, 'order': 'asc'}
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
                            'txid': tx['txId'],
                            'confirmations': 0 if 'confirmations' not in tx else tx['confirmations'],
                            'output_n': int(outp),
                            'input_n': 0,
                            'block_height': None if 'blockHeight' not in tx else tx['blockHeight'],
                            'fee': None,
                            'size': 0,
                            'value': utxo['value'],
                            'script': utxo['scriptPubKey'],
                            'date': datetime.utcfromtimestamp(tx['timestamp'])
                         }
                    )
                if tx['txId'] == after_txid:
                    utxos = []
            page += 1
            if page > res['data']['pages']:
                break
        return utxos[:limit]

    def gettransaction(self, txid):
        res = self.compose_request('transaction', txid)
        return self._parse_transaction(res['data'])

    def gettransactions(self, address, after_txid='', limit=MAX_TRANSACTIONS):
        page = 0
        txs = []
        while True:
            variables = {'mode': 'verbose', 'limit': MAX_TRANSACTIONS, 'page': page, 'order': 'asc'}
            try:
                res = self.compose_request('address', 'transactions', address, variables)
            except ClientError:
                if "address not found" in self.resp.text:
                    return []
            for tx in res['data']['list']:
                txs.append(self._parse_transaction(tx))
                if tx['txId'] == after_txid:
                    txs = []
            if len(txs) > limit:
                break
            page += 1
            if page >= res['data']['pages']:
                break
        return txs[:limit]

    # def getrawtransaction(self, txid):
    #     tx = self.compose_request('transaction', txid)
    #     return tx['data']['rawTx']

    # def sendrawtransaction

    # def estimatefee

    def blockcount(self):
        return self.compose_request('block', 'last')['data']['height']

    # def mempool(self, txid):
    #     if txid:
    #         t = self.gettransaction(txid)
    #         if t and not t.confirmations:
    #             return [t.txid]
    #     else:
    #         res = self.compose_request('transactions', type='mempool')
    #         return [tx['hash'] for tx in res['data']['transactions']]
    #     return []

    # FIXME: Bitaps doesn't seem to return block data anymore...
    # def getblock(self, blockid, parse_transactions, page, limit):
    #     if limit > 100:
    #         limit = 100
    #     res = self.compose_request('block', str(blockid),
    #                                variables={'transactions': True, 'limit': limit, 'page': page})
    #     bd = res['data']['block']
    #     td = res['data']['transactions']
    #     txids = [tx['txId'] for tx in td['list']]
    #     if parse_transactions:
    #         txs = []
    #         for txid in txids:
    #             try:
    #                 txs.append(self.gettransaction(txid))
    #             except Exception as e:
    #                 _logger.error("Could not parse tx %s with error %s" % (txid, e))
    #     else:
    #         txs = txids
    #
    #     block = {
    #         'bits': bd['bits'],
    #         'depth': bd['confirmations'],
    #         'hash': bd['hash'],
    #         'height': bd['height'],
    #         'merkle_root': bd['merkleRoot'],
    #         'nonce': bd['nonce'],
    #         'prev_block': bd['previousBlockHash'],
    #         'time': datetime.utcfromtimestamp(bd['blockTime']),
    #         'total_txs': bd['transactionsCount'],
    #         'txs': txs,
    #         'version': bd['version'],
    #         'page': td['page'],
    #         'pages': td['pages'],
    #         'limit': td['limit']
    #     }
    #     return block

    # def isspent(self, txid, output_n):
    #     t = self.gettransaction(txid)
    #     return 1 if t.outputs[output_n].spent else 0

    # def getinfo(self):
