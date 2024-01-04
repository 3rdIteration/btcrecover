# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    CryptoID Chainz client
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
import struct
from datetime import datetime
from bitcoinlib.main import MAX_TRANSACTIONS
from bitcoinlib.services.baseclient import BaseClient, ClientError
from bitcoinlib.transactions import Transaction


_logger = logging.getLogger(__name__)

PROVIDERNAME = 'cryptoid'


class CryptoID(BaseClient):

    def __init__(self, network, base_url, denominator, *args):
        super(self.__class__, self).__init__(network, PROVIDERNAME, base_url, denominator, *args)

    def compose_request(self, func=None, path_type='api', variables=None, method='get'):
        # API path: http://chainz.cryptoid.info/ltc/api.dws
        # Explorer path for raw tx: https://chainz.cryptoid.info/explorer/tx.raw.dws
        if variables is None:
            variables = {}
        if path_type == 'api':
            url_path = '%s/api.dws' % self.provider_coin_id
            variables.update({'q': func})
        else:
            url_path = 'explorer/tx.raw.dws'
            variables.update({'coin': self.provider_coin_id})
        if not self.api_key:
            raise ClientError("Request a CryptoID API key before using this provider")
        variables.update({'key': self.api_key})
        return self.request(url_path, variables, method)

    def getbalance(self, addresslist):
        balance = 0.0
        addresslist = self._addresslist_convert(addresslist)
        for a in addresslist:
            res = self.compose_request('getbalance', variables={'a': a.address})
            balance += float(res)
        return int(balance * self.units)

    def getutxos(self, address, after_txid='', max_txs=MAX_TRANSACTIONS):
        if not self.api_key:
            raise ClientError("Method getutxos() is not available for CryptoID without API key")
        utxos = []
        address = self._address_convert(address)
        variables = {'active': address.address}
        res = self.compose_request('unspent', variables=variables)
        if len(res['unspent_outputs']) > 50:
            _logger.info("CryptoID: Large number of outputs for address %s, "
                            "UTXO list may be incomplete" % address.address)
        for utxo in res['unspent_outputs'][::-1]:
            if utxo['tx_hash'] == after_txid:
                break
            utxos.append({
                'address': address.address_orig,
                'tx_hash': utxo['tx_hash'],
                'confirmations': utxo['confirmations'],
                'output_n': utxo['tx_output_n'] if 'tx_output_n' in utxo else utxo['tx_ouput_n'],
                'input_n': 0,
                'block_height': None,
                'fee': None,
                'size': 0,
                'value': int(utxo['value']),
                'script': utxo['script'],
                'date': None
            })
        return utxos[::-1][:max_txs]

    def gettransaction(self, tx_id):
        variables = {'id': tx_id, 'hex': None}
        tx = self.compose_request(path_type='explorer', variables=variables)
        t = Transaction.import_raw(tx['hex'], self.network)
        variables = {'t': tx_id}
        tx_api = self.compose_request('txinfo', path_type='api', variables=variables)
        for n, i in enumerate(t.inputs):
            if i.script_type != 'coinbase':
                i.value = int(round(tx_api['inputs'][n]['amount'] * self.units, 0))
            else:
                t.coinbase = True
        for n, o in enumerate(t.outputs):
            o.spent = None
        if tx['confirmations']:
            t.status = 'confirmed'
        else:
            t.status = 'unconfirmed'
        t.hash = tx_id
        t.date = datetime.fromtimestamp(tx['time'])
        t.block_height = tx_api['block']
        t.block_hash = tx['blockhash']
        t.confirmations = tx['confirmations']
        t.rawtx = tx['hex']
        t.size = tx['size']
        t.network = self.network
        t.locktime = tx['locktime']
        t.version = struct.pack('>L', tx['version'])
        t.output_total = int(round(tx_api['total_output'] * self.units, 0))
        t.input_total = t.output_total
        if not t.coinbase:
            t.input_total = int(round(tx_api['total_input'] * self.units, 0))
        t.fee = t.input_total - t.output_total
        return t

    def gettransactions(self, address, after_txid='', max_txs=MAX_TRANSACTIONS):
        address = self._address_convert(address)
        txs = []
        txids = []
        variables = {'active': address.address, 'n': 100}
        res = self.compose_request('multiaddr', variables=variables)
        for tx in res['txs']:
            if tx['hash'] not in txids:
                txids.insert(0, tx['hash'])
        if after_txid:
            txids = txids[txids.index(after_txid) + 1:]
        for txid in txids[:max_txs]:
            t = self.gettransaction(txid)
            txs.append(t)
        return txs

    def getrawtransaction(self, tx_id):
        variables = {'id': tx_id, 'hex': None}
        tx = self.compose_request(path_type='explorer', variables=variables)
        return tx['hex']

    # def sendrawtransaction

    # def estimatefee

    def blockcount(self):
        r = self.compose_request('getblockcount', path_type='api')
        return r

    def mempool(self, txid):
        variables = {'id': txid, 'hex': None}
        tx = self.compose_request(path_type='explorer', variables=variables)
        if 'confirmations' not in tx:
            return [tx['txid']]
        return []
