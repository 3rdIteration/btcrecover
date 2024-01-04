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
from bitcoinlib.services.baseclient import BaseClient
from bitcoinlib.transactions import Transaction


PROVIDERNAME = 'blockstream'
# Please note: In the Blockstream API, the first couple of Bitcoin blocks are not correctly indexed,
# so transactions from these blocks are missing.

_logger = logging.getLogger(__name__)


class BlockstreamClient(BaseClient):

    def __init__(self, network, base_url, denominator, *args):
        super(self.__class__, self).__init__(network, PROVIDERNAME, base_url, denominator, *args)

    def compose_request(self, function, data='', parameter='', parameter2='', variables=None, post_data='', method='get'):
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
            res = self.compose_request('address', data=address)
            balance += (res['chain_stats']['funded_txo_sum'] - res['chain_stats']['spent_txo_sum'])
        return balance

    def getutxos(self, address, after_txid='', limit=MAX_TRANSACTIONS):
        res = self.compose_request('address', address, 'utxo')
        self.latest_block = self.blockcount() if not self.latest_block else self.latest_block
        utxos = []
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
        confirmations = 0
        block_height = None
        if 'block_height' in tx['status']:
            block_height = tx['status']['block_height']
            confirmations = self.latest_block - block_height
        status = 'unconfirmed'
        if tx['status']['confirmed']:
            status = 'confirmed'
        fee = None if 'fee' not in tx else tx['fee']
        t = Transaction(locktime=tx['locktime'], version=tx['version'], network=self.network,
                        fee=fee, size=tx['size'], txid=tx['txid'],
                        date=None if 'block_time' not in tx['status'] else datetime.utcfromtimestamp(tx['status']['block_time']),
                        confirmations=confirmations, block_height=block_height, status=status,
                        coinbase=tx['vin'][0]['is_coinbase'])
        index_n = 0
        for ti in tx['vin']:
            if tx['vin'][0]['is_coinbase']:
                t.add_input(prev_txid=ti['txid'], output_n=ti['vout'], index_n=index_n,
                            unlocking_script=ti['scriptsig'], value=0, sequence=ti['sequence'], strict=self.strict)
            else:
                witnesses = []
                if 'witness' in ti:
                    witnesses = [bytes.fromhex(w) for w in ti['witness']]
                t.add_input(prev_txid=ti['txid'], output_n=ti['vout'], index_n=index_n,
                            unlocking_script=ti['scriptsig'], value=ti['prevout']['value'],
                            address='' if 'scriptpubkey_address' not in ti['prevout']
                            else ti['prevout']['scriptpubkey_address'], sequence=ti['sequence'],
                            unlocking_script_unsigned=ti['prevout']['scriptpubkey'], witnesses=witnesses, strict=self.strict)
            index_n += 1
        index_n = 0
        if len(tx['vout']) > 101:
            # Every output needs an extra query, stop execution if there are too many transaction outputs
            return False
        for to in tx['vout']:
            address = ''
            if 'scriptpubkey_address' in to:
                address = to['scriptpubkey_address']
            spent = self.isspent(t.txid, index_n)
            t.add_output(value=to['value'], address=address, lock_script=to['scriptpubkey'],
                         output_n=index_n, spent=spent, strict=self.strict)
            index_n += 1
        if 'segwit' in [i.witness_type for i in t.inputs] or 'p2sh-segwit' in [i.witness_type for i in t.inputs]:
            t.witness_type = 'segwit'
        t.update_totals()
        t.size = tx['size']
        return t

    def gettransaction(self, txid):
        tx = self.compose_request('tx', txid)
        return self._parse_transaction(tx)

    def gettransactions(self, address, after_txid='', limit=MAX_TRANSACTIONS):
        self.latest_block = self.blockcount() if not self.latest_block else self.latest_block
        prtxs = []
        before_txid = ''
        while True:
            parameter = 'txs'
            if before_txid:
                parameter = 'txs/chain/%s' % before_txid
            res = self.compose_request('address', address, parameter)
            prtxs += res
            if len(res) == 25:
                before_txid = res[-1:][0]['txid']
            else:
                break
            if len(prtxs) > limit:
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
        res = self.compose_request('tx', post_data=rawtx, method='post')
        return {
            'txid': res,
            'response_dict': res
        }

    def estimatefee(self, blocks):
        est = self.compose_request('fee-estimates')
        closest = (sorted([int(i) - blocks for i in est.keys() if int(i) - blocks >= 0]))
        # FIXME: temporary fix for too low testnet tx fees:
        if self.network.name == 'testnet':
            return 2000
        if closest:
            return int(est[str(closest[0] + blocks)] * 1000)
        else:
            return int(est[str(sorted([int(i) for i in est.keys()])[-1:][0])] * 1000)

    def blockcount(self):
        return self.compose_request('blocks', 'tip', 'height')

    def mempool(self, txid):
        if txid:
            t = self.gettransaction(txid)
            if t and not t.confirmations:
                return [t.txid]
            else:
                return []
        else:
            return self.compose_request('mempool', 'txids')

    def getblock(self, blockid, parse_transactions, page, limit):
        if isinstance(blockid, int):
            blockid = self.compose_request('block-height', str(blockid))
        if (page == 1 and limit == 10) or limit > 25:
            limit = 25
        # elif page > 1:
        #     if limit % 25 != 0:
        #         return False
        bd = self.compose_request('block', blockid)
        btxs = self.compose_request('block', blockid, 'txs', str((page-1)*limit))
        if parse_transactions:
            txs = []
            self.latest_block = self.blockcount() if not self.latest_block else self.latest_block
            for tx in btxs[:limit]:
                # try:
                txs.append(self._parse_transaction(tx))
                # except Exception as e:
                #     _logger.error("Could not parse tx %s with error %s" % (tx['txid'], e))
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
        rawblock = self.compose_request('block', blockid, 'raw')
        hexrawblock = rawblock.hex()
        return hexrawblock

    def isspent(self, txid, output_n):
        res = self.compose_request('tx', txid, 'outspend', str(output_n))
        return 1 if res['spent'] else 0

    # def getinfo(self):