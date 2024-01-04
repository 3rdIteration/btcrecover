# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    Blockchair client
#    © 2018-2019 July - 1200 Web Development <http://1200wd.com/>
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
try:
    from datetime import timezone
except Exception:
    pass
from bitcoinlib.main import MAX_TRANSACTIONS
from bitcoinlib.services.baseclient import BaseClient, ClientError
from bitcoinlib.transactions import Transaction
from bitcoinlib.keys import deserialize_address, Address
from bitcoinlib.encoding import EncodingError, varstr

_logger = logging.getLogger(__name__)

PROVIDERNAME = 'blockchair'
REQUEST_LIMIT = 100


class BlockChairClient(BaseClient):

    def __init__(self, network, base_url, denominator, *args):
        super(self.__class__, self).__init__(network, PROVIDERNAME, base_url, denominator, *args)

    def compose_request(self, command, query_vars=None, variables=None, data=None, offset=0, limit=REQUEST_LIMIT,
                        method='get'):
        url_path = ''
        if not variables:
            variables = {}
        if command not in ['stats', 'mempool']:
            variables.update({'limit': limit})
        if offset:
            variables.update({'offset': offset})
        if command:
            url_path += command
        if data:
            if url_path[-1:] != '/':
                url_path += '/'
            url_path += data
        if query_vars:
            varstr = ','.join(['%s(%s)' % (qv, query_vars[qv]) for qv in query_vars])
            variables.update({'q': varstr})
        return self.request(url_path, variables, method=method)

    def getbalance(self, addresslist):
        balance = 0
        for address in addresslist:
            res = self.compose_request('dashboards/address/', data=address)
            balance += int(res['data'][address]['address']['balance'])
        return balance

    def getutxos(self, address, after_txid='', limit=MAX_TRANSACTIONS):
        utxos = []
        offset = 0
        while True:
            res = self.compose_request('outputs', {'recipient': address, 'is_spent': 'false'}, offset=offset)
            if len(res['data']) == REQUEST_LIMIT:
                raise ClientError("Blockchair returned more then maximum of %d data rows" % REQUEST_LIMIT)
            current_block = res['context']['state']
            for utxo in res['data'][::-1]:
                if utxo['is_spent']:
                    continue
                if utxo['transaction_hash'] == after_txid:
                    utxos = []
                    continue
                utxos.append({
                    'address': address,
                    'txid': utxo['transaction_hash'],
                    'confirmations': current_block - utxo['block_id'],
                    'output_n': utxo['index'],
                    'input_n': 0,
                    'block_height': utxo['block_id'],
                    'fee': None,
                    'size': 0,
                    'value': utxo['value'],
                    'script': utxo['script_hex'],
                    'date': datetime.strptime(utxo['time'], "%Y-%m-%d %H:%M:%S")
                })
            if not len(res['data']) or len(res['data']) < REQUEST_LIMIT:
                break
            offset += REQUEST_LIMIT
        return utxos[:limit]

    def gettransaction(self, tx_id):
        res = self.compose_request('dashboards/transaction/', data=tx_id)

        tx = res['data'][tx_id]['transaction']
        confirmations = 0 if tx['block_id'] <= 0 else res['context']['state'] - tx['block_id']
        status = 'unconfirmed'
        if confirmations:
            status = 'confirmed'
        witness_type = 'legacy'
        if tx['has_witness']:
            witness_type = 'segwit'
        input_total = tx['input_total']
        t = Transaction(locktime=tx['lock_time'], version=tx['version'], network=self.network,
                        fee=tx['fee'], size=tx['size'], txid=tx['hash'],
                        date=None if not confirmations else datetime.strptime(tx['time'], "%Y-%m-%d %H:%M:%S"),
                        confirmations=confirmations, block_height=tx['block_id'] if tx['block_id'] > 0 else None,
                        status=status, input_total=input_total, coinbase=tx['is_coinbase'],
                        output_total=tx['output_total'], witness_type=witness_type)
        index_n = 0
        if not res['data'][tx_id]['inputs']:
            # This is a coinbase transaction, add input
            t.add_input(prev_txid=b'\00' * 32, output_n=0, value=0)

        for ti in res['data'][tx_id]['inputs']:
            if ti['spending_witness']:
                # witnesses = b"".join([varstr(bytes.fromhex(x)) for x in ti['spending_witness'].split(",")])
                witnesses = ti['spending_witness'].split(",")
                address = Address.parse(ti['recipient'])
                if address.script_type == 'p2sh':
                    witness_type = 'p2sh-segwit'
                else:
                    witness_type = 'segwit'
                t.add_input(prev_txid=ti['transaction_hash'], output_n=ti['index'],
                            unlocking_script=ti['spending_signature_hex'],
                            witnesses=witnesses, index_n=index_n, value=ti['value'],
                            address=address, witness_type=witness_type, sequence=ti['spending_sequence'], strict=self.strict)
            else:
                t.add_input(prev_txid=ti['transaction_hash'], output_n=ti['index'],
                            unlocking_script=ti['spending_signature_hex'], index_n=index_n, value=ti['value'],
                            address=ti['recipient'], unlocking_script_unsigned=ti['script_hex'],
                            sequence=ti['spending_sequence'], strict=self.strict)
            index_n += 1
        for to in res['data'][tx_id]['outputs']:
            try:
                deserialize_address(to['recipient'], network=self.network.name)
                addr = to['recipient']
            except EncodingError:
                addr = ''
            t.add_output(value=to['value'], address=addr, lock_script=to['script_hex'],
                         spent=to['is_spent'], output_n=to['index'], spending_txid=to['spending_transaction_hash'],
                         spending_index_n=to['spending_index'], strict=self.strict)
        return t

    def gettransactions(self, address, after_txid='', limit=MAX_TRANSACTIONS):
        txids = []
        offset = 0
        while True:
            res = self.compose_request('dashboards/address/', data=address, offset=offset)
            addr = res['data'][address]
            if not addr['transactions']:
                break
            txids = addr['transactions'][::-1] + txids
            offset += 50
            if len(txids) > limit:
                break
        if after_txid:
            txids = txids[txids.index(after_txid)+1:]
        txs = []
        for txid in txids[:limit]:
            txs.append(self.gettransaction(txid))
        return txs

    def getrawtransaction(self, txid):
        res = self.compose_request('raw/transaction', data=txid)
        return res['data'][txid]['raw_transaction']

    def sendrawtransaction(self, rawtx):
        res = self.compose_request('push/transaction', variables={'data': rawtx}, method='post')
        return {
            'txid': res['data']['transaction_hash'],
            'response_dict': res
        }

    def estimatefee(self, blocks):
        return self.compose_request('stats')['data']['suggested_transaction_fee_per_byte_sat'] * 1000

    def blockcount(self):
        """
        Get latest block number: The block number of last block in longest chain on the blockchain

        :return int:
        """
        res = self.compose_request('stats')
        return res['context']['state']

    def mempool(self, txid=''):
        if txid:
            res = self.compose_request('mempool', {'hash': txid}, data='transactions')
        else:
            res = self.compose_request('mempool', data='transactions')
        return [tx['hash'] for tx in res['data'] if 'hash' in tx]

    def getblock(self, blockid, parse_transactions, page, limit):
        if limit > 100:
            limit = 100
        res = self.compose_request('dashboards/block/', data=str(blockid), offset=(page-1)*limit, limit=limit)
        bd = res['data'][str(blockid)]['block']
        txids = res['data'][str(blockid)]['transactions']
        if parse_transactions:
            txs = []
            for txid in txids:
                txs.append(self.gettransaction(txid))
        else:
            txs = txids

        block = {
            'bits': bd['bits'],
            'depth': None,
            'block_hash': bd['hash'],
            'height': bd['id'],
            'merkle_root': bd['merkle_root'],
            'nonce': bd['nonce'],
            'prev_block': b'',
            'time': int(datetime.strptime(bd['time'], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()),
            'tx_count': bd['transaction_count'],
            'txs': txs,
            'version': bd['version'],
            'page': page,
            'pages': None if not limit else int(bd['transaction_count'] // limit) + (bd['transaction_count'] % limit > 0),
            'limit': limit
        }
        return block

    def getrawblock(self, blockid):
        res = self.compose_request('raw/block/', data=str(blockid))
        rb = res['data'][str(blockid)]['raw_block']
        return rb

    def isspent(self, txid, output_n):
        t = self.gettransaction(txid)
        return 1 if t.outputs[output_n].spent else 0

    def getinfo(self):
        info = self.compose_request('stats')['data']
        return {
            'blockcount': info['best_block_height'],
            'chain': '',
            'difficulty': int(float(info['difficulty'])),
            'hashrate': int(info['hashrate_24h']),
            'mempool_size': int(info['mempool_transactions']),
        }
