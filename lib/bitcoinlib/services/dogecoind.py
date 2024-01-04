# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    Client for dogecoind daemon
#    © 2017-2022 Oct - 1200 Web Development <http://1200wd.com/>
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

import configparser
from datetime import datetime
from bitcoinlib.main import *
from bitcoinlib.services.authproxy import AuthServiceProxy
from bitcoinlib.services.baseclient import BaseClient, ClientError
from bitcoinlib.transactions import Transaction
from bitcoinlib.networks import Network


PROVIDERNAME = 'dogecoind'

_logger = logging.getLogger(__name__)


class ConfigError(Exception):
    def __init__(self, msg=''):
        self.msg = msg
        _logger.info(msg)

    def __str__(self):
        return self.msg


def _read_from_config(configparser, section, value, fallback=None):
    try:
        return configparser.get(section, value)
    except Exception:
        return fallback


class DogecoindClient(BaseClient):
    """
    Class to interact with dogecoind, the Dogecoin daemon
    """

    @staticmethod
    def from_config(configfile=None, network='dogecoin', **kargs):
        """
        Read settings from dogecoind config file

        :param configfile: Path to config file. Leave empty to look in default places
        :type: str
        :param network: Dogecoin mainnet or testnet. Default is dogecoin mainnet
        :type: str

        :return DogecoindClient:
        """
        try:
            config = configparser.ConfigParser(strict=False)
        except TypeError:
            config = configparser.ConfigParser()
        config_fn = 'dogecoin.conf'
        if isinstance(network, Network):
            network = network.name
        if network == 'testnet':
            config_fn = 'dogecoin-testnet.conf'

        cfn = None
        if not configfile:
            config_locations = ['~/.bitcoinlib', '~/.dogecoin', '~/Application Data/Dogecoin',
                                '~/Library/Application Support/Dogecoin']
            for location in config_locations:
                cfn = Path(location, config_fn).expanduser()
                if cfn.exists():
                    break
        else:
            cfn = Path(BCL_DATA_DIR, 'config', configfile)
        if not cfn or not cfn.is_file():
            raise ConfigError("Config file %s not found. Please install dogecoin client and specify a path to config "
                              "file if path is not default. Or place a config file in .bitcoinlib/dogecoin.conf to "
                              "reference to an external server." % cfn)

        try:
            config.read(cfn)
        except Exception:
            with cfn.open() as f:
                config_string = '[rpc]\n' + f.read()
            config.read_string(config_string)

        testnet = _read_from_config(config, 'rpc', 'testnet')
        if testnet:
            network = 'testnet'
        if _read_from_config(config, 'rpc', 'rpcpassword') == 'specify_rpc_password':
            raise ConfigError("Please update config settings in %s" % cfn)
        if network == 'testnet':
            port = 44555
        else:
            port = 22555
        port = _read_from_config(config, 'rpc', 'rpcport', port)
        server = '127.0.0.1'
        server = _read_from_config(config, 'rpc', 'rpcconnect', server)
        server = _read_from_config(config, 'rpc', 'bind', server)
        server = _read_from_config(config, 'rpc', 'externalip', server)

        url = "http://%s:%s@%s:%s" % (config.get('rpc', 'rpcuser'), config.get('rpc', 'rpcpassword'), server, port)
        return DogecoindClient(network, url, **kargs)

    def __init__(self, network='dogecoin', base_url='', denominator=100000000, **kargs):
        """
        Open connection to dogecoin node

        :param network: Dogecoin mainnet or testnet. Default is dogecoin mainnet
        :type: str
        :param base_url: Connection URL in format http(s)://user:password@host:port.
        :type: str
        :param denominator: Denominator for this currency. Should be always 100000000 (satoshis) for dogecoin
        :type: str
        """
        if isinstance(network, Network):
            network = network.name
        if not base_url:
            bdc = self.from_config('', network)
            base_url = bdc.base_url
            network = bdc.network
        if len(base_url.split(':')) != 4:
            raise ConfigError("Dogecoind connection URL must be of format 'http(s)://user:password@host:port,"
                              "current format is %s. Please set url in providers.json file or check dogecoin config "
                              "file" % base_url)
        if 'password' in base_url:
            raise ConfigError("Invalid password in dogecoind provider settings. "
                              "Please replace default password and set url in providers.json or dogecoin.conf file")
        _logger.info("Connect to dogecoind")
        self.proxy = AuthServiceProxy(base_url)
        super(self.__class__, self).__init__(network, PROVIDERNAME, base_url, denominator, **kargs)

    def getutxos(self, address, after_txid='', max_txs=MAX_TRANSACTIONS):
        txs = []

        for t in self.proxy.listunspent(0, 99999999, [address]):
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

        return txs

    def gettransaction(self, txid, block_height=None, get_input_values=True):
        tx = self.proxy.getrawtransaction(txid, 1)
        t = Transaction.parse_hex(tx['hex'], strict=self.strict, network=self.network)
        t.confirmations = tx['confirmations']
        if t.confirmations:
            t.status = 'confirmed'
            t.verified = True
        for i in t.inputs:
            if i.prev_txid == b'\x00' * 32:
                i.value = t.output_total
                i.script_type = 'coinbase'
                continue
            if get_input_values:
                txi = self.proxy.getrawtransaction(i.prev_txid.hex(), 1)
                i.value = int(round(float(txi['vout'][i.output_n_int]['value']) / self.network.denominator))
        for o in t.outputs:
            o.spent = None
        t.version = tx['version'].to_bytes(4, 'big')
        t.date = datetime.fromtimestamp(tx['blocktime'])
        t.block_height = block_height
        t.update_totals()
        return t

    def getrawtransaction(self, txid):
        return self.proxy.getrawtransaction(txid)

    def sendrawtransaction(self, rawtx):
        res = self.proxy.sendrawtransaction(rawtx)
        return {
            'txid': res,
            'response_dict': res
        }

    def estimatefee(self, blocks):
        pres = ''
        try:
            pres = self.proxy.estimatesmartfee(blocks)
            res = pres['feerate']
        except KeyError as e:
            _logger.info("dogecoind error: %s, %s" % (e, pres))
            res = self.proxy.estimatefee(blocks)
        return int(res * self.units)

    def blockcount(self):
        return self.proxy.getblockcount()

    def mempool(self, txid=''):
        txids = self.proxy.getrawmempool()
        if not txid:
            return txids
        elif txid in txids:
            return [txid]
        return []

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
    # base_url = 'http://dogecoinrpc:passwd@host:8332'
    # bdc = BitcoindClient(base_url=base_url)

    # 2. Or connect using default settings or settings from config file
    bdc = DogecoindClient()

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
    t = bdc.getrawtransaction('7eb5332699644b753cd3f5afba9562e67612ea71ef119af1ac46559adb69ea0d')
    pprint(t)

    print("\n=== Current network fees ===")
    t = bdc.estimatefee(5)
    pprint(t)
