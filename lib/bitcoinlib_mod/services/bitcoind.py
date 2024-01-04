# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    Client for bitcoind deamon
#    © 2017 June - 1200 Web Development <http://1200wd.com/>
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
from bitcoinlib.main import *
from bitcoinlib.services.authproxy import AuthServiceProxy
from bitcoinlib.services.baseclient import BaseClient, ClientError
from bitcoinlib.transactions import Transaction
from bitcoinlib.encoding import to_hexstring
from bitcoinlib.networks import Network


PROVIDERNAME = 'bitcoind'

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


def _read_from_config(configparser, section, value, fallback=None):
    try:
        return configparser.get(section, value)
    except Exception:
        return fallback


class BitcoindClient(BaseClient):
    """
    Class to interact with bitcoind, the Bitcoin deamon
    """

    @staticmethod
    def from_config(configfile=None, network='bitcoin'):
        """
        Read settings from bitcoind config file

        :param configfile: Path to config file. Leave empty to look in default places
        :type: str
        :param network: Bitcoin mainnet or testnet. Default is bitcoin mainnet
        :type: str

        :return BitcoindClient:
        """
        try:
            config = configparser.ConfigParser(strict=False)
        except TypeError:
            config = configparser.ConfigParser()
        config_fn = 'bitcoin.conf'
        if isinstance(network, Network):
            network = network.name
        if network == 'testnet':
            config_fn = 'bitcoin-testnet.conf'

        cfn = None
        if not configfile:
            config_locations = ['~/.bitcoinlib', '~/.bitcoin', '~/Application Data/Bitcoin',
                                '~/Library/Application Support/Bitcoin']
            for location in config_locations:
                cfn = Path(location, config_fn).expanduser()
                if cfn.exists():
                    break
        else:
            cfn = Path(BCL_DATA_DIR, 'config', configfile)
        if not cfn or not cfn.is_file():
            raise ConfigError("Config file %s not found. Please install bitcoin client and specify a path to config "
                              "file if path is not default. Or place a config file in .bitcoinlib/bitcoin.conf to "
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
            port = 18332
        else:
            port = 8332
        port = _read_from_config(config, 'rpc', 'rpcport', port)
        server = '127.0.0.1'
        server = _read_from_config(config, 'rpc', 'rpcconnect', server)
        server = _read_from_config(config, 'rpc', 'bind', server)
        server = _read_from_config(config, 'rpc', 'externalip', server)

        url = "http://%s:%s@%s:%s" % (config.get('rpc', 'rpcuser'), config.get('rpc', 'rpcpassword'), server, port)
        return BitcoindClient(network, url)

    def __init__(self, network='bitcoin', base_url='', denominator=100000000, *args):
        """
        Open connection to bitcoin node

        :param network: Bitcoin mainnet or testnet. Default is bitcoin mainnet
        :type: str
        :param base_url: Connection URL in format http(s)://user:password@host:port.
        :type: str
        :param denominator: Denominator for this currency. Should be always 100000000 (satoshis) for bitcoin
        :type: str
        """
        if isinstance(network, Network):
            network = network.name
        if not base_url:
            bdc = self.from_config('', network)
            base_url = bdc.base_url
            network = bdc.network
        if len(base_url.split(':')) != 4:
            raise ConfigError("Bitcoind connection URL must be of format 'http(s)://user:password@host:port,"
                              "current format is %s. Please set url in providers.json file or check bitcoin config "
                              "file" % base_url)
        if 'password' in base_url:
            raise ConfigError("Invalid password in bitcoind provider settings. "
                              "Please replace default password and set url in providers.json or bitcoin.conf file")
        _logger.info("Connect to bitcoind on %s" % base_url)
        self.proxy = AuthServiceProxy(base_url)
        super(self.__class__, self).__init__(network, PROVIDERNAME, base_url, denominator, *args)

    # def getbalance

    def getutxos(self, address, after_txid='', max_txs=MAX_TRANSACTIONS):
        txs = []

        res = self.proxy.getaddressinfo(address)
        if not (res['ismine'] or res['iswatchonly']):
            raise ClientError("Address %s not found in bitcoind wallet, use 'importaddress' to add address to "
                              "wallet." % address)

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

    def gettransaction(self, txid):
        tx = self.proxy.getrawtransaction(txid, 1)
        t = Transaction.import_raw(tx['hex'], network=self.network)
        t.confirmations = tx['confirmations']
        if t.confirmations:
            t.status = 'confirmed'
            t.verified = True
        for i in t.inputs:
            if i.prev_hash == b'\x00' * 32:
                i.value = t.output_total
                i.script_type = 'coinbase'
                continue
            txi = self.proxy.getrawtransaction(to_hexstring(i.prev_hash), 1)
            i.value = int(round(float(txi['vout'][i.output_n_int]['value']) / self.network.denominator))
        for o in t.outputs:
            o.spent = None
        t.block_hash = tx['blockhash']
        t.version = struct.pack('>L', tx['version'])
        t.date = datetime.fromtimestamp(tx['blocktime'])
        t.hash = txid
        t.update_totals()
        return t

    # def gettransactions

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
        pres = ''
        try:
            pres = self.proxy.estimatesmartfee(blocks)
            res = pres['feerate']
        except KeyError as e:
            _logger.info("bitcoind error: %s, %s" % (e, pres))
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


if __name__ == '__main__':
    #
    # SOME EXAMPLES
    #

    from pprint import pprint

    # 1. Connect by specifying connection URL
    # base_url = 'http://bitcoinrpc:passwd@host:8332'
    # bdc = BitcoindClient(base_url=base_url)

    # 2. Or connect using default settings or settings from config file
    bdc = BitcoindClient()

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
