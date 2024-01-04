# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    Smartbit.com.au client
#    © 2019 August - 1200 Web Development <http://1200wd.com/>
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
from bitcoinlib.encoding import varstr, to_bytes, to_hexstring

_logger = logging.getLogger(__name__)

PROVIDERNAME = 'smartbit'
# Please note: In the Bitaps API, the first couple of Bitcoin blocks are not correctly indexed,
# so transactions from these blocks are missing.


class SmartbitClient(BaseClient):

    def __init__(self, network, base_url, denominator, *args):
        super(self.__class__, self).__init__(network, PROVIDERNAME, base_url, denominator, *args)

    def compose_request(self, category, command='', data='', variables=None, type='blockchain', method='get'):
        url_path = type + '/' + category
        if data:
            if url_path[-1:] != '/':
                url_path += '/'
            url_path += data
        if command:
            url_path += '/' + command
        return self.request(url_path, variables=variables, method=method)

    def _parse_transaction(self, tx):
        status = 'unconfirmed'
        if tx['confirmations']:
            status = 'confirmed'
        witness_type = 'legacy'
        if 'inputs' in tx and [ti['witness'] for ti in tx['inputs'] if ti['witness'] and ti['witness'] != ['NULL']]:
            witness_type = 'segwit'
        input_total = tx['input_amount_int']
        t_time = None
        if tx['time']:
            t_time = datetime.fromtimestamp(tx['time'])
        if tx['coinbase']:
            input_total = tx['output_amount_int']
        t = Transaction(locktime=tx['locktime'], version=int(tx['version']), network=self.network, fee=tx['fee_int'],
                        size=tx['size'], hash=tx['txid'], date=t_time,
                        confirmations=tx['confirmations'], block_height=tx['block'], status=status,
                        input_total=input_total, coinbase=tx['coinbase'],
                        output_total=tx['output_amount_int'], witness_type=witness_type)
        index_n = 0
        if tx['coinbase']:
            t.add_input(prev_hash=b'\00' * 32, output_n=0, value=input_total)
        else:
            for ti in tx['inputs']:
                unlocking_script = ti['script_sig']['hex']
                witness_type = 'legacy'
                if ti['witness'] and ti['witness'] != ['NULL']:
                    witness_type = 'segwit'
                    unlocking_script = b"".join([varstr(to_bytes(x)) for x in ti['witness']])
                # if tx['inputs']['witness']

                t.add_input(prev_hash=ti['txid'], output_n=ti['vout'], unlocking_script=unlocking_script,
                            index_n=index_n, value=ti['value_int'], address=ti['addresses'][0], sequence=ti['sequence'],
                            witness_type=witness_type)
                index_n += 1

                # if ti['spending_witness']:
                #     witnesses = b"".join([varstr(to_bytes(x)) for x in ti['spending_witness'].split(",")])
                #     t.add_input(prev_hash=ti['transaction_hash'], output_n=ti['index'],
                #                 unlocking_script=witnesses, index_n=index_n, value=ti['value'],
                #                 address=ti['recipient'], witness_type='segwit')
                # else:
                #     t.add_input(prev_hash=ti['transaction_hash'], output_n=ti['index'],
                #                 unlocking_script_unsigned=ti['script_hex'], index_n=index_n, value=ti['value'],
                #                 address=ti['recipient'], unlocking_script=ti['spending_signature_hex'])


        for to in tx['outputs']:
            spent = True if 'spend_txid' in to and to['spend_txid'] else False
            address = ''
            if to['addresses']:
                address = to['addresses'][0]
            t.add_output(value=to['value_int'], address=address, lock_script=to['script_pub_key']['hex'],
                         spent=spent, output_n=to['n'])
        return t

    def getbalance(self, addresslist):
        res = self.compose_request('address', 'wallet', ','.join(addresslist))
        return res['wallet']['total']['received_int']

    def getutxos(self, address, after_txid='', max_txs=MAX_TRANSACTIONS):
        utxos = []
        utxo_list = []
        next_link = ''
        while True:
            variables = {'limit': 10, 'next': next_link, 'dir': 'asc'}
            res = self.compose_request('address', 'unspent', address, variables=variables)
            next_link = res['paging']['next']
            for utxo in res['unspent']:
                utxo_list.append(utxo['txid'])
                if utxo['txid'] == after_txid:
                    utxo_list = []
            if not next_link:
                break
        for txid in utxo_list[:max_txs]:
            t = self.gettransaction(txid)
            for utxo in t.outputs:
                if utxo.address != address:
                    continue
                utxos.append(
                    {
                        'address': utxo.address,
                        'tx_hash': t.hash,
                        'confirmations': t.confirmations,
                        'output_n': utxo.output_n,
                        'input_n': 0,
                        'block_height': t.block_height,
                        'fee': t.fee,
                        'size': t.size,
                        'value': utxo.value,
                        'script': to_hexstring(utxo.lock_script),
                        'date': t.date
                    })
        return utxos

    def gettransaction(self, txid):
        res = self.compose_request('tx', data=txid)
        return self._parse_transaction(res['transaction'])

    def gettransactions(self, address, after_txid='', max_txs=MAX_TRANSACTIONS):
        txs = []
        next_link = ''
        while True:
            variables = {'limit': 10, 'next': next_link, 'dir': 'asc'}
            res = self.compose_request('address', data=address, variables=variables)
            next_link = '' if 'transaction_paging' not in res['address'] else \
                res['address']['transaction_paging']['next']
            if 'transactions' not in res['address']:
                break
            for tx in res['address']['transactions']:
                t = self._parse_transaction(tx)
                txs.append(t)
                if t.hash == after_txid:
                    txs = []
            if not next_link:
                break
        return txs[:max_txs]

    def getrawtransaction(self, txid):
        res = self.compose_request('tx', data=txid, command='hex')
        return res['hex'][0]['hex']

    def sendrawtransaction(self, rawtx):
        res = self.compose_request('pushtx', variables={'hex': rawtx}, method='post')
        return {
            'txid': res['txid'],
            'response_dict': res
        }

    # def estimatefee

    def blockcount(self):
        return self.compose_request('totals')['totals']['block_count']

    def mempool(self, txid):
        if txid:
            tx = self.compose_request('tx', data=txid)
            if tx['transaction']['confirmations'] == 0:
                return [tx['transaction']['hash']]
        return []
