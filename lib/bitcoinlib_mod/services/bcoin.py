# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    Client for Bcoin Node
#    © 2019 June - 1200 Web Development <http://1200wd.com/>
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

from datetime import datetime
from time import sleep
from requests import ReadTimeout
from bitcoinlib.main import *
from bitcoinlib.services.baseclient import BaseClient, ClientError
from bitcoinlib.transactions import Transaction
from bitcoinlib.encoding import to_hexstring


PROVIDERNAME = 'bcoin'
LIMIT_TX = 10

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
            url_path += '/' + data
        if parameter:
            url_path += '/' + parameter
        if variables is None:
            variables = {}
        return self.request(url_path, variables, method, secure=False)

    def _parse_transaction(self, tx):
        status = 'unconfirmed'
        if tx['confirmations']:
            status = 'confirmed'
        t = Transaction.import_raw(tx['hex'])
        t.locktime = tx['locktime']
        t.network = self.network
        t.fee = tx['fee']
        t.date = datetime.fromtimestamp(tx['time'])
        t.confirmations = tx['confirmations']
        t.block_height = tx['height']
        t.block_hash = tx['block']
        t.status = status
        if t.coinbase:
            t.input_total = t.output_total
            t.inputs[0].value = t.output_total
        else:
            for i in t.inputs:
                i.value = tx['inputs'][t.inputs.index(i)]['coin']['value']
        for o in t.outputs:
            o.spent = None
        t.update_totals()
        return t

    def isspent(self, tx_id, index):
        try:
            self.compose_request('coin', tx_id, str(index))
        except ClientError:
            return True
        return False

    # def getbalance(self, addresslist):
    #     balance = 0.0
    #     for address in addresslist:
    #         res = tx = self.compose_request('address', address)
    #         balance += int(res['balance'])
    #     return int(balance * self.units)

    def getutxos(self, address, after_txid='', max_txs=MAX_TRANSACTIONS):
        txs = self.gettransactions(address, after_txid=after_txid, max_txs=max_txs)
        utxos = []
        for tx in txs:
            for unspent in tx.outputs:
                if unspent.address != address:
                    continue
                if not self.isspent(tx.hash, unspent.output_n):
                    utxos.append(
                        {
                            'address': unspent.address,
                            'tx_hash': tx.hash,
                            'confirmations': tx.confirmations,
                            'output_n': unspent.output_n,
                            'input_n': 0,
                            'block_height': tx.block_height,
                            'fee': tx.fee,
                            'size': tx.size,
                            'value': unspent.value,
                            'script': to_hexstring(unspent.lock_script),
                            'date': tx.date,
                         }
                    )
        return utxos

    def gettransaction(self, txid):
        tx = self.compose_request('tx', txid)
        return self._parse_transaction(tx)

    def gettransactions(self, address, after_txid='', max_txs=MAX_TRANSACTIONS):
        txs = []
        while True:
            variables = {'limit': LIMIT_TX, 'after': after_txid}
            retries = 0
            while retries < 3:
                try:
                    res = self.compose_request('tx', 'address', address, variables)
                except ReadTimeout as e:
                    sleep(3)
                    _logger.info("Bcoin client error: %s" % e)
                    retries += 1
                else:
                    break
                finally:
                    if retries == 3:
                        raise ClientError("Max retries exceeded with bcoin Client")
            for tx in res:
                txs.append(self._parse_transaction(tx))
            if len(txs) >= max_txs:
                break
            if len(res) == LIMIT_TX:
                after_txid = res[LIMIT_TX-1]['hash']
            else:
                break

        # Check which outputs are spent/unspent for this address
        if not after_txid:
            address_inputs = [(to_hexstring(inp.prev_hash), inp.output_n_int) for ti in
                              [t.inputs for t in txs] for inp in ti if inp.address == address]
            for tx in txs:
                for to in tx.outputs:
                    if to.address != address:
                        continue
                    spent = True if (tx.hash, to.output_n) in address_inputs else False
                    txs[txs.index(tx)].outputs[to.output_n].spent = spent
        return txs

    def getrawtransaction(self, txid):
        return self.compose_request('tx', txid)['hex']

    def sendrawtransaction(self, rawtx):
        res = self.compose_request('broadcast', variables={'tx': rawtx}, method='post')
        txid = ''
        if 'success' in res and res['success']:
            t = Transaction.import_raw(rawtx)
            txid = t.hash
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
