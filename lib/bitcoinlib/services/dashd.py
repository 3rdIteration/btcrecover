# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    dashd deamon
#    © 2018-2022 Oct - 1200 Web Development <http://1200wd.com/>
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
#
# You can connect to a dash testnet deamon by adding the following provider to providers.json
# "dashd.testnet": {
#   "provider": "dashd",
#   "network": "dash_testnet",
#   "client_class": "DashdClient",
#   "url": "http://user:password@server_url:19998",
#   "api_key": "",
#   "priority": 11,
#   "denominator": 100000000
# }

import configparser
from bitcoinlib.main import *
from bitcoinlib.services.authproxy import AuthServiceProxy
from bitcoinlib.services.baseclient import BaseClient
from bitcoinlib.transactions import Transaction


PROVIDERNAME = 'dashd'

_logger = logging.getLogger(__name__)


class ConfigError(Exception):
    def __init__(self, msg=''):
        self.msg = msg
        _logger.info(msg)

    def __str__(self):
        return self.msg


class DashdClient(BaseClient):
    """
    Class to interact with dashd, the Dash deamon
    """

    @staticmethod
    def from_config(configfile=None, network='dash', **kargs):
        """
        Read settings from dashd config file

        :param configfile: Path to config file. Leave empty to look in default places
        :type: str
        :param network: Dash mainnet or testnet. Default is dash mainnet
        :type: str

        :return DashdClient:
        """
        config = configparser.ConfigParser(strict=False)
        if not configfile:
            cfn = os.path.join(os.path.expanduser("~"), '.bitcoinlib/dash.conf')
            if not os.path.isfile(cfn):
                cfn = os.path.join(os.path.expanduser("~"), '.dashcore/dash.conf')
            if not os.path.isfile(cfn):
                raise ConfigError("Please install dash client and specify a path to config file if path is not "
                                  "default. Or place a config file in .bitcoinlib/dash.conf to reference to "
                                  "an external server.")
        else:
            cfn = os.path.join(BCL_DATA_DIR, 'config', configfile)
            if not os.path.isfile(cfn):
                raise ConfigError("Config file %s not found" % cfn)
        with open(cfn, 'r') as f:
            config_string = '[rpc]\n' + f.read()
        config.read_string(config_string)

        try:
            if int(config.get('rpc', 'testnet')):
                network = 'testnet'
        except configparser.NoOptionError:
            pass
        if config.get('rpc', 'rpcpassword') == 'specify_rpc_password':
            raise ConfigError("Please update config settings in %s" % cfn)
        try:
            port = config.get('rpc', 'port')
        except configparser.NoOptionError:
            if network == 'testnet':
                port = 19998
            else:
                port = 9998
        server = '127.0.0.1'
        if 'bind' in config['rpc']:
            server = config.get('rpc', 'bind')
        elif 'externalip' in config['rpc']:
            server = config.get('rpc', 'externalip')
        url = "http://%s:%s@%s:%s" % (config.get('rpc', 'rpcuser'), config.get('rpc', 'rpcpassword'), server, port)
        return DashdClient(network, url, **kargs)

    def __init__(self, network='dash', base_url='', denominator=100000000, **kargs):
        """
        Open connection to dashcore node

        :param network: Dash mainnet or testnet. Default is dash mainnet
        :type: str
        :param base_url: Connection URL in format http(s)://user:password@host:port.
        :type: str
        :param denominator: Denominator for this currency. Should be always 100000000 (satoshis) for Dash
        :type: str
        """
        if not base_url:
            bdc = self.from_config('', network)
            base_url = bdc.base_url
            network = bdc.network
        _logger.info("Connect to dashd")
        self.proxy = AuthServiceProxy(base_url)
        super(self.__class__, self).__init__(network, PROVIDERNAME, base_url, denominator, **kargs)

    def _parse_transaction(self, tx, block_height=None, get_input_values=True):
        t = Transaction.parse_hex(tx['hex'], strict=self.strict, network=self.network)
        t.confirmations = None if 'confirmations' not in tx else tx['confirmations']
        if t.confirmations or block_height:
            t.status = 'confirmed'
            t.verified = True
        for i in t.inputs:
            if i.prev_txid == b'\x00' * 32:
                i.script_type = 'coinbase'
                continue
            if get_input_values:
                txi = self.proxy.getrawtransaction(i.prev_txid.hex(), 1)
                i.value = int(round(float(txi['vout'][i.output_n_int]['value']) / self.network.denominator))
        for o in t.outputs:
            o.spent = None
        t.block_height = block_height
        t.version = tx['version'].to_bytes(4, 'big')
        t.date = datetime.utcfromtimestamp(tx['blocktime'])
        t.update_totals()
        return t

    def gettransaction(self, txid):
        tx = self.proxy.getrawtransaction(txid, 1)
        return self._parse_transaction(tx)

    def getrawtransaction(self, txid):
        res = self.proxy.getrawtransaction(txid)
        return res

    def sendrawtransaction(self, rawtx):
        res = self.proxy.sendrawtransaction(rawtx)
        return {
            'txid': res,
            'response_dict': res
        }

    def estimatefee(self, blocks):
        try:
            res = self.proxy.estimatesmartfee(blocks)['feerate']
        except KeyError:
            res = self.proxy.estimatefee(blocks)
        return int(res * self.units)

    def blockcount(self):
        return self.proxy.getblockcount()

    def getutxos(self, address, after_txid='', limit=MAX_TRANSACTIONS):
        txs = []

        txs_list = self.proxy.listunspent(0, 99999999, [address])
        for t in sorted(txs_list, key=lambda x: x['confirmations'], reverse=True):
            txs.append({
                'address': t['address'],
                'txid': t['txid'],
                'confirmations': t['confirmations'],
                'output_n': t['vout'],
                'input_n': -1,
                'block_height': None,
                'fee': None,
                'size': 0,
                'value': int(t['amount'] * self.units),
                'script': t['scriptPubKey'],
                'date': None,
            })
            if t['txid'] == after_txid:
                txs = []

        return txs

    def getblock(self, blockid, parse_transactions=True, page=1, limit=None):
        if isinstance(blockid, int):
            blockid = self.proxy.getblockhash(blockid)
        if not limit:
            limit = 99999

        txs = []
        if parse_transactions:
            bd = self.proxy.getblock(blockid, 2)
            for tx in bd['tx'][(page - 1) * limit:page * limit]:
                # try:
                tx['blocktime'] = bd['time']
                tx['blockhash'] = bd['hash']
                txs.append(self._parse_transaction(tx, block_height=bd['height'], get_input_values=False))
                # except Exception as e:
                #     _logger.error("Could not parse tx %s with error %s" % (tx['txid'], e))
            # txs += [tx['hash'] for tx in bd['tx'][len(txs):]]
        else:
            bd = self.proxy.getblock(blockid, 1)
            txs = bd['tx']

        block = {
            'bits': int(bd['bits'], 16),
            'depth': bd['confirmations'],
            'hash': bd['hash'],
            'height': bd['height'],
            'merkle_root': bd['merkleroot'],
            'nonce': bd['nonce'],
            'prev_block': bd['previousblockhash'],
            'time': bd['time'],
            'total_txs': bd['nTx'],
            'txs': txs,
            'version': bd['version'],
            'page': page,
            'pages': None,
            'limit': limit
        }
        return block

    def getrawblock(self, blockid):
        if isinstance(blockid, int):
            blockid = self.proxy.getblockhash(blockid)
        return self.proxy.getblock(blockid, 0)

    def isspent(self, txid, index):
        res = self.proxy.gettxout(txid, index)
        if not res:
            return 1
        return 0

    def getinfo(self):
        info = self.proxy.getmininginfo()
        return {
            'blockcount': info['blocks'],
            'chain': info['chain'],
            'difficulty': int(info['difficulty']),
            'hashrate': int(info['networkhashps']),
            'mempool_size': int(info['pooledtx']),
        }


if __name__ == '__main__':
    #
    # SOME EXAMPLES
    #

    from pprint import pprint

    # 1. Connect by specifying connection URL
    # base_url = 'http://dashrpcuser:passwd@host:9998'
    # bdc = DashdClient(base_url=base_url)

    # 2. Or connect using default settings or settings from config file
    bdc = DashdClient()

    print("\n=== SERVERINFO ===")
    pprint(bdc.proxy.getnetworkinfo())

    print("\n=== Best Block ===")
    blockhash = bdc.proxy.getbestblockhash()
    bestblock = bdc.proxy.getblock(blockhash)
    bestblock['tx'] = '...' + str(len(bestblock['tx'])) + ' transactions...'
    pprint(bestblock)

    print("\n=== Mempool ===")
    rmp = bdc.proxy.getrawmempool()
    pprint(rmp[:25])
    print('... truncated ...')
    print("Mempool Size %d" % len(rmp))

    print("\n=== Raw Transaction by txid ===")
    t = bdc.getrawtransaction('c3d2a934ef8eb9b2291d113b330b9244c1521ef73df0a4b04c39e851112f01af')
    pprint(t)

    print("\n=== Current network fees ===")
    t = bdc.estimatefee(5)
    pprint(t)
