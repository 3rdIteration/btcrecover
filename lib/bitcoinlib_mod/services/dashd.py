# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    dashd deamon
#    © 2018 June - 1200 Web Development <http://1200wd.com/>
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

from datetime import datetime
from bitcoinlib.main import *
from bitcoinlib.services.authproxy import AuthServiceProxy
from bitcoinlib.services.baseclient import BaseClient
from bitcoinlib.transactions import Transaction
from bitcoinlib.encoding import to_hexstring


PROVIDERNAME = 'dashd'

_logger = logging.getLogger(__name__)


class ConfigError(Exception):
    def __init__(self, msg=''):
        self.msg = msg
        _logger.info(msg)

    def __str__(self):
        return self.msg

try:
    import configparser
except ImportError:
    import ConfigParser as configparser


class DashdClient(BaseClient):
    """
    Class to interact with dashd, the Dash deamon
    """

    @staticmethod
    def from_config(configfile=None, network='dash'):
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
            cfn = os.path.join(os.path.expanduser("~"), '.bitcoinlib/config/dash.conf')
            if not os.path.isfile(cfn):
                cfn = os.path.join(os.path.expanduser("~"), '.dashcore/dash.conf')
            if not os.path.isfile(cfn):
                raise ConfigError("Please install dash client and specify a path to config file if path is not "
                                  "default. Or place a config file in .bitcoinlib/config/dash.conf to reference to "
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
        return DashdClient(network, url)

    def __init__(self, network='dash', base_url='', denominator=100000000, *args):
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
        if len(base_url.split(':')) != 4:
            raise ConfigError("Dashd connection URL must be of format 'http(s)://user:password@host:port,"
                              "current format is %s. Please set url in providers.json file" % base_url)
        if 'password' in base_url:
            raise ConfigError("Invalid password 'password' in dashd provider settings. "
                              "Please set password and url in providers.json file")
        _logger.info("Connect to dashd on %s" % base_url)
        self.proxy = AuthServiceProxy(base_url)
        super(self.__class__, self).__init__(network, PROVIDERNAME, base_url, denominator, *args)

    def gettransaction(self, txid):
        tx = self.proxy.getrawtransaction(txid, 1)
        t = Transaction.import_raw(tx['hex'], network=self.network)
        t.confirmations = tx['confirmations']
        if t.confirmations:
            t.status = 'confirmed'
            t.verified = True
        for i in t.inputs:
            txi = self.proxy.getrawtransaction(to_hexstring(i.prev_hash), 1)
            value = int(float(txi['vout'][i.output_n_int]['value']) / self.network.denominator)
            i.value = value
        t.block_hash = tx['blockhash']
        t.version = tx['version']
        t.date = datetime.fromtimestamp(tx['blocktime'])
        t.update_totals()
        return t

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

    def getutxos(self, address, after_txid='', max_txs=MAX_TRANSACTIONS):
        txs = []

        for t in self.proxy.listunspent(0, 99999999, [address]):
            txs.append({
                'address': t['address'],
                'tx_hash': t['txid'],
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

        return txs

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
