# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    SERVICES - Main Service connector
#    © 2017 - 2019 August - 1200 Web Development <http://1200wd.com/>
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

import os
import logging
import json
import random
import time
from bitcoinlib.config.config import BLOCK_COUNT_CACHE_TIME
from bitcoinlib.main import BCL_DATA_DIR, TYPE_TEXT, MAX_TRANSACTIONS, TIMEOUT_REQUESTS
from bitcoinlib import services
from bitcoinlib.networks import DEFAULT_NETWORK, Network
from bitcoinlib.encoding import to_hexstring
from bitcoinlib.db_cache import *
from bitcoinlib.transactions import Transaction


_logger = logging.getLogger(__name__)


class ServiceError(Exception):
    def __init__(self, msg=''):
        self.msg = msg
        _logger.error(msg)

    def __str__(self):
        return self.msg


class Service(object):
    """
    Class to connect to various cryptocurrency service providers. Use to receive network and blockchain information,
    get specific transaction information, current network fees or push a raw transaction.

    The Service class connects to 1 or more service providers at random to retrieve or send information. If a service
    providers fails to correctly respond the Service class will try another available provider.

    """

    def __init__(self, network=DEFAULT_NETWORK, min_providers=1, max_providers=1, providers=None,
                 timeout=TIMEOUT_REQUESTS, cache_uri=None):
        """
        Open a service object for the specified network. By default the object connect to 1 service provider, but you
        can specify a list of providers or a minimum or maximum number of providers.

        :param network: Specify network used
        :type network: str, Network
        :param min_providers: Minimum number of providers to connect to. Default is 1. Use for instance to receive fee information from a number of providers and calculate the average fee.
        :type min_providers: int
        :param max_providers: Maximum number of providers to connect to. Default is 1.
        :type max_providers: int
        :param providers: List of providers to connect to. Default is all providers and select a provider at random.
        :type providers: list, str
        :param timeout: Timeout for web requests. Leave empty to use default from config settings
        :type timeout: int
        :param cache_uri: Database to use for caching
        :type cache_uri: str

        """

        self.network = network
        if not isinstance(network, Network):
            self.network = Network(network)
        if min_providers > max_providers:
            max_providers = min_providers
        fn = Path(BCL_DATA_DIR, 'providers.json')
        f = fn.open("r")

        try:
            self.providers_defined = json.loads(f.read())
        except json.decoder.JSONDecodeError as e:  # pragma: no cover
            errstr = "Error reading provider definitions from %s: %s" % (fn, e)
            _logger.warning(errstr)
            raise ServiceError(errstr)
        f.close()

        provider_list = list([self.providers_defined[x]['provider'] for x in self.providers_defined])
        if providers is None:
            providers = []
        if not isinstance(providers, list):
            providers = [providers]
        for p in providers:
            if p not in provider_list:
                raise ServiceError("Provider '%s' not found in provider definitions" % p)

        self.providers = {}
        for p in self.providers_defined:
            if (self.providers_defined[p]['network'] == network or self.providers_defined[p]['network'] == '') and \
                    (not providers or self.providers_defined[p]['provider'] in providers):
                self.providers.update({p: self.providers_defined[p]})

        if not self.providers:
            raise ServiceError("No providers found for network %s" % network)
        self.min_providers = min_providers
        self.max_providers = max_providers
        self.results = {}
        self.errors = {}
        self.resultcount = 0
        self.complete = None
        self.timeout = timeout
        self._blockcount_update = 0
        self._blockcount = None
        self.cache = None
        self.cache = Cache(self.network, db_uri=cache_uri)
        self.results_cache_n = 0
        if self.min_providers > 1:
            self._blockcount = Service(network=network).blockcount()
        else:
            self._blockcount = self.blockcount()

    def _reset_results(self):
        self.results = {}
        self.errors = {}
        self.complete = None
        self.resultcount = 0

    def _provider_execute(self, method, *arguments):
        self._reset_results()
        provider_lst = [p[0] for p in sorted([(x, self.providers[x]['priority']) for x in self.providers],
                        key=lambda x: (x[1], random.random()), reverse=True)]

        for sp in provider_lst:
            if self.resultcount >= self.max_providers:
                break
            try:
                if sp not in ['bitcoind', 'litecoind', 'dashd', 'caching'] and not self.providers[sp]['url'] and \
                        self.network.name != 'bitcoinlib_test':
                    continue
                client = getattr(services, self.providers[sp]['provider'])
                providerclient = getattr(client, self.providers[sp]['client_class'])
                pc_instance = providerclient(
                    self.network, self.providers[sp]['url'], self.providers[sp]['denominator'],
                    self.providers[sp]['api_key'], self.providers[sp]['provider_coin_id'],
                    self.providers[sp]['network_overrides'], self.timeout, self._blockcount)
                if not hasattr(pc_instance, method):
                    continue
                providermethod = getattr(pc_instance, method)
                res = providermethod(*arguments)
                if res is False:  # pragma: no cover
                    self.errors.update(
                        {sp: 'Received empty response'}
                    )
                    _logger.info("Empty response from %s when calling %s" % (sp, method))
                    continue
                self.results.update(
                    {sp: res}
                )
                self.resultcount += 1
            except Exception as e:
                if not isinstance(e, AttributeError):
                    try:
                        err = e.msg
                    except AttributeError:
                        err = e
                    self.errors.update(
                        {sp: err}
                    )
                    # -- Use this to debug specific Services errors --
                    # from pprint import pprint
                    # pprint(self.errors)
                _logger.info("%s.%s(%s) Error %s" % (sp, method, arguments, e))

            if self.resultcount >= self.max_providers:
                break

        if not self.resultcount:
            _logger.warning("No successfull response from any serviceprovider: %s" % list(self.providers.keys()))
            return False
        return list(self.results.values())[0]

    def getbalance(self, addresslist, addresses_per_request=5):
        """
        Get total balance for address or list of addresses

        :param addresslist: Address or list of addresses
        :type addresslist: list, str
        :param addresses_per_request: Maximum number of addresses per request. Default is 5. Use lower setting when you experience timeouts or service request errors, or higher when possible.
        :type addresses_per_request: int

        :return dict: Balance per address
        """
        if not addresslist:
            return
        if isinstance(addresslist, TYPE_TEXT):
            addresslist = [addresslist]

        tot_balance = 0
        while addresslist:
            balance = self._provider_execute('getbalance', addresslist[:addresses_per_request])
            if balance:
                tot_balance += balance
            addresslist = addresslist[addresses_per_request:]
        return tot_balance

    def getutxos(self, address, after_txid='', max_txs=MAX_TRANSACTIONS):
        """
        Get list of unspent outputs (UTXO's) for specified address.

        Sorted from old to new, so highest number of confirmations first.

        :param address: Address string
        :type address: str
        :param after_txid: Transaction ID of last known transaction. Only check for utxos after given tx id. Default: Leave empty to return all utxos.
        :type after_txid: str
        :param max_txs: Maximum number of utxo's to return
        :type max_txs: int

        :return dict: UTXO's per address
        """
        if not isinstance(address, TYPE_TEXT):
            raise ServiceError("Address parameter must be of type text")
        self.results_cache_n = 0
        self.complete = True

        utxos_cache = []
        if self.min_providers <= 1:
            utxos_cache = self.cache.getutxos(address, after_txid)
        if utxos_cache:
            self.results_cache_n = len(utxos_cache)
            db_addr = self.cache.getaddress(address)
            if db_addr and db_addr.last_block >= self._blockcount:
                return utxos_cache
            else:
                after_txid = utxos_cache[-1:][0]['tx_hash']

        utxos = self._provider_execute('getutxos', address, after_txid, max_txs)
        if utxos and len(utxos) >= max_txs:
            self.complete = False

        return utxos_cache + utxos

    def gettransaction(self, txid):
        """
        Get a transaction by its transaction hash. Convert to Bitcoinlib transaction object.

        :param txid: Transaction identification hash
        :type txid: str, bytes

        :return Transaction: A single transaction object
        """
        txid = to_hexstring(txid)
        tx = None
        self.results_cache_n = 0

        if self.min_providers <= 1:
            tx = self.cache.gettransaction(txid)
            if tx:
                self.results_cache_n = 1
        if not tx:
            tx = self._provider_execute('gettransaction', txid)
            if len(self.results) and self.min_providers <= 1:
                self.cache.store_transaction(tx, 0)
        return tx

    def gettransactions(self, address, after_txid='', max_txs=MAX_TRANSACTIONS):
        """
        Get all transactions for specified address.

        Sorted from old to new, so transactions with highest number of confirmations first.

        :param address: Address string
        :type address: str
        :param after_txid: Transaction ID of last known transaction. Only check for transactions after given tx id. Default: Leave empty to return all transaction. If used only provide a single address
        :type after_txid: str
        :param max_txs: Maximum number of transactions to return
        :type max_txs: int

        :return list: List of Transaction objects
        """
        self._reset_results()
        self.results_cache_n = 0
        if not address:
            return []
        if not isinstance(address, TYPE_TEXT):
            raise ServiceError("Address parameter must be of type text")
        if after_txid is None:
            after_txid = ''
        db_addr = self.cache.getaddress(address)
        txs_cache = []
        qry_after_txid = after_txid

        # Retrieve transactions from cache
        if self.min_providers <= 1:  # Disable cache if comparing providers
            txs_cache = self.cache.gettransactions(address, after_txid, max_txs)
            if txs_cache:
                self.results_cache_n = len(txs_cache)
                if len(txs_cache) == max_txs:
                    return txs_cache
                max_txs = max_txs - len(txs_cache)
                qry_after_txid = txs_cache[-1:][0].hash

        # Get (extra) transactions from service providers
        txs = []
        if not(db_addr and db_addr.last_block >= self._blockcount):
            txs = self._provider_execute('gettransactions', address, qry_after_txid,  max_txs)
            if txs == False:
                raise ServiceError("Error when retrieving transactions from service provider")

        # Store transactions and address in cache
        # - disable cache if comparing providers or if after_txid is used and no cache is available
        if self.min_providers <= 1 and not(after_txid and not db_addr):
        # if self.min_providers <= 1:
            last_block = self._blockcount
            self.complete = True
            if len(txs) == max_txs:
                self.complete = False
                last_block = txs[-1:][0].block_height
            if len(self.results):
                order_n = 0
                for tx in txs:
                    res = self.cache.store_transaction(tx, order_n)
                    order_n += 1
                    # Failure to store transaction: stop caching transaction and store last tx block height - 1
                    if res == False:
                        if tx.block_height:
                            last_block = tx.block_height - 1
                        break
                self.cache.store_address(address, last_block)

        return txs_cache + txs

    def getrawtransaction(self, txid):
        """
        Get a raw transaction by its transaction hash

        :param txid: Transaction identification hash
        :type txid: str, bytes

        :return str: Raw transaction as hexstring
        """
        txid = to_hexstring(txid)
        self.results_cache_n = 0
        rawtx = self.cache.getrawtransaction(txid)
        if rawtx:
            self.results_cache_n = 1
            return rawtx
        return self._provider_execute('getrawtransaction', txid)

    def sendrawtransaction(self, rawtx):
        """
        Push a raw transaction to the network

        :param rawtx: Raw transaction as hexstring or bytes
        :type rawtx: str, bytes

        :return dict: Send transaction result
        """
        rawtx = to_hexstring(rawtx)
        return self._provider_execute('sendrawtransaction', rawtx)

    def estimatefee(self, blocks=3):
        """
        Estimate fee per kilobyte for a transaction for this network with expected confirmation within a certain
        amount of blocks

        :param blocks: Expection confirmation time in blocks. Default is 3.
        :type blocks: int

        :return int: Fee in smallest network denominator (satoshi)
        """
        self.results_cache_n = 0
        if self.min_providers <= 1:  # Disable cache if comparing providers
            fee = self.cache.estimatefee(blocks)
            if fee:
                self.results_cache_n = 1
                return fee
        fee = self._provider_execute('estimatefee', blocks)
        if not fee:  # pragma: no cover
            if self.network.fee_default:
                fee = self.network.fee_default
            else:
                raise ServiceError("Could not estimate fees, please define default fees in network settings")
        self.cache.store_estimated_fee(blocks, fee)
        return fee

    def blockcount(self):
        """
        Get latest block number: The block number of last block in longest chain on the Blockchain.

        Block count is cashed for BLOCK_COUNT_CACHE_TIME seconds to avoid to many calls to service providers.

        :return int:
        """

        blockcount = self.cache.blockcount()
        last_cache_blockcount = self.cache.blockcount(never_expires=True)
        if blockcount:
            self._blockcount = blockcount
            return blockcount

        current_timestamp = time.time()
        if self._blockcount_update < current_timestamp - BLOCK_COUNT_CACHE_TIME:
            new_count = self._provider_execute('blockcount')
            if not self._blockcount or (new_count and new_count > self._blockcount):
                self._blockcount = new_count
                self._blockcount_update = time.time()
            if last_cache_blockcount > self._blockcount:
                return last_cache_blockcount
            # Store result in cache
            if len(self.results) and list(self.results.keys())[0] != 'caching':
                self.cache.store_blockcount(self._blockcount)
        return self._blockcount

    def mempool(self, txid=''):
        """
        Get list of all transaction IDs in the current mempool

        A full list of transactions ID's will only be returned if a bcoin or bitcoind client is available. Otherwise
        specify the txid option to verify if a transaction is added to the mempool.

        :param txid: Check if transaction with this hash exists in memory pool
        :type txid: str
        
        :return list: 
        """
        return self._provider_execute('mempool', txid)


class Cache(object):
    """
    Store transaction, utxo and address information in database to increase speed and avoid duplicate calls to
    service providers.

    Once confirmed a transaction is immutable so we have to fetch it from a service provider only once. When checking
    for new transactions or utxo's for a certain address we only have to check the new blocks.

    This class is used by the Service class and normally you won't need to access it directly.

    """

    def __init__(self, network, db_uri=''):
        """
        Open Cache class

        :param network: Specify network used
        :type network: str, Network
        :param db_uri: Database to use for caching
        :type db_uri: str
        """
        self.session = None
        if SERVICE_CACHING_ENABLED:
            self.session = DbInit(db_uri=db_uri).session
        self.network = network

    def _parse_db_transaction(self, db_tx):
        t = Transaction.import_raw(db_tx.raw, db_tx.network_name)
        for n in db_tx.nodes:
            if n.is_input:
                t.inputs[n.output_n].value = n.value
                t.inputs[n.output_n].address = n.address
            else:
                t.outputs[n.output_n].spent = n.spent
        t.hash = db_tx.txid
        t.date = db_tx.date
        t.confirmations = db_tx.confirmations
        t.block_hash = db_tx.block_hash
        t.block_height = db_tx.block_height
        t.status = 'confirmed'
        t.fee = db_tx.fee
        t.update_totals()
        if t.coinbase:
            t.input_total = t.output_total
        _logger.info("Retrieved transaction %s from cache" % t.hash)
        return t

    def gettransaction(self, txid):
        """
        Get transaction from cache. Returns False if not available

        :param txid: Transaction identification hash
        :type txid: str

        :return Transaction: A single transaction object
        """
        if not SERVICE_CACHING_ENABLED:
            return False
        db_tx = self.session.query(dbCacheTransaction).filter_by(txid=txid, network_name=self.network.name).first()
        if not db_tx:
            return False
        db_tx.txid = txid
        return self._parse_db_transaction(db_tx)

    def getaddress(self, address):
        """
        Get address information from cache, with links to transactions and utxo's and latest update information.

        :param address: Address string
        :type address: str

        :return dbCacheAddress: An address cache database object
        """
        if not SERVICE_CACHING_ENABLED:
            return []
        return self.session.query(dbCacheAddress).filter_by(address=address, network_name=self.network.name).scalar()

    def gettransactions(self, address, after_txid='', max_txs=MAX_TRANSACTIONS):
        """
        Get transactions from cache. Returns empty list if no transactions are found or caching is disabled.

        :param address: Address string
        :type address: str
        :param after_txid: Transaction ID of last known transaction. Only check for transactions after given tx id. Default: Leave empty to return all transaction. If used only provide a single address
        :type after_txid: str
        :param max_txs: Maximum number of transactions to return
        :type max_txs: int

        :return list: List of Transaction objects
        """
        if not SERVICE_CACHING_ENABLED:
            return []
        db_addr = self.getaddress(address)
        txs = []
        if db_addr:
            if after_txid:
                after_tx = self.session.query(dbCacheTransaction).\
                    filter_by(txid=after_txid, network_name=self.network.name).scalar()
                if after_tx:
                    db_txs = self.session.query(dbCacheTransaction).join(dbCacheTransactionNode).\
                        filter(dbCacheTransactionNode.address == address,
                               dbCacheTransaction.block_height >= after_tx.block_height).\
                        order_by(dbCacheTransaction.block_height, dbCacheTransaction.order_n).all()
                    db_txs2 = []
                    for d in db_txs:
                        db_txs2.append(d)
                        if d.txid == after_txid:
                            db_txs2 = []
                    db_txs = db_txs2
                else:
                    return []
            else:
                db_txs = self.session.query(dbCacheTransaction).join(dbCacheTransactionNode). \
                    filter(dbCacheTransactionNode.address == address). \
                    order_by(dbCacheTransaction.block_height, dbCacheTransaction.order_n).all()
            for db_tx in db_txs:
                txs.append(self._parse_db_transaction(db_tx))
                if len(txs) >= max_txs:
                    break
            return txs
        return []

    def getrawtransaction(self, txid):
        """
        Get a raw transaction string from the database cache if available

        :param txid: Transaction identification hash
        :type txid: str, bytes

        :return str: Raw transaction as hexstring
        """
        if not SERVICE_CACHING_ENABLED:
            return False
        tx = self.session.query(dbCacheTransaction).filter_by(txid=txid, network_name=self.network.name).first()
        if not tx:
            return False
        return tx.raw

    def getutxos(self, address, after_txid=''):
        """
        Get list of unspent outputs (UTXO's) for specified address from database cache.

        Sorted from old to new, so highest number of confirmations first.

        :param address: Address string
        :type address: str
        :param after_txid: Transaction ID of last known transaction. Only check for utxos after given tx id. Default: Leave empty to return all utxos.
        :type after_txid: str

        :return dict: UTXO's per address
        """
        if not SERVICE_CACHING_ENABLED:
            return []
        db_utxos = self.session.query(dbCacheTransactionNode.spent, dbCacheTransactionNode.output_n,
                                      dbCacheTransactionNode.value, dbCacheTransaction.confirmations,
                                      dbCacheTransaction.block_height, dbCacheTransaction.fee,
                                      dbCacheTransaction.date, dbCacheTransaction.txid).join(dbCacheTransaction). \
            order_by(dbCacheTransaction.block_height, dbCacheTransaction.order_n). \
            filter(dbCacheTransactionNode.address == address, dbCacheTransactionNode.is_input == False,
                   dbCacheTransaction.network_name == self.network.name).all()
        utxos = []
        for db_utxo in db_utxos:
            if db_utxo.spent == False:
                utxos.append({
                    'address': address,
                    'tx_hash': db_utxo.txid,
                    'confirmations': db_utxo.confirmations,
                    'output_n': db_utxo.output_n,
                    'input_n': 0,
                    'block_height': db_utxo.block_height,
                    'fee': db_utxo.fee,
                    'size': 0,
                    'value': db_utxo.value,
                    'script': '',
                    'date': db_utxo.date
                })
            elif db_utxo.spent is None:
                return []
            if db_utxo == after_txid:
                utxos = []
        return utxos

    def estimatefee(self, blocks):
        """
        Get fee estimation from cache for confirmation within specified amount of blocks.

        Stored in cache in three groups: low, medium and high fees.

        :param blocks: Expection confirmation time in blocks.
        :type blocks: int

        :return int: Fee in smallest network denominator (satoshi)
        """
        if not SERVICE_CACHING_ENABLED:
            return False
        if blocks <= 1:
            varname = 'fee_high'
        elif blocks <= 5:
            varname = 'fee_medium'
        else:
            varname = 'fee_low'
        dbvar = self.session.query(dbCacheVars).filter_by(varname=varname, network_name=self.network.name).\
                                                filter(dbCacheVars.expires > datetime.datetime.now()).scalar()
        if dbvar:
            return int(dbvar.value)
        return False

    def blockcount(self, never_expires=False):
        """
        Get number of blocks on the current network from cache if recent data is available.

        :param never_expires: Always return latest blockcount found. Can be used to avoid return to old blocks if service providers are not up-to-date.
        :type never_expires: bool

        :return int:
        """
        if not SERVICE_CACHING_ENABLED:
            return False
        qr = self.session.query(dbCacheVars).filter_by(varname='blockcount', network_name=self.network.name)
        if not never_expires:
            qr = qr.filter(dbCacheVars.expires > datetime.datetime.now())
        dbvar = qr.scalar()
        if dbvar:
            return int(dbvar.value)
        return False

    def store_blockcount(self, blockcount):
        """
        Store network blockcount in cache for 60 seconds

        :param blockcount: Number of latest block
        :type blockcount: int, str

        :return:
        """
        if not SERVICE_CACHING_ENABLED:
            return
        dbvar = dbCacheVars(varname='blockcount', network_name=self.network.name, value=str(blockcount), type='int',
                            expires=datetime.datetime.now() + datetime.timedelta(seconds=60))
        self.session.merge(dbvar)
        self.session.commit()

    def store_transaction(self, t, order_n):
        """
        Store transaction in cache. Use order number to determine order in a block

        :param t: Transaction
        :type t: Transaction
        :param order_n: Order in block
        :type order_n: int

        :return:
        """
        if not SERVICE_CACHING_ENABLED:
            return
        # Only store complete and confirmed transaction in cache
        if not t.hash or not t.date or not t.block_height or not t.network or not t.confirmations:    # pragma: no cover
            _logger.info("Caching failure tx: Incomplete transaction missing hash, date, block_height, "
                         "network or confirmations info")
            return False
        raw_hex = t.raw_hex()
        if not raw_hex:    # pragma: no cover
            _logger.info("Caching failure tx: Raw hex missing in transaction")
            return False
        if self.session.query(dbCacheTransaction).filter_by(txid=t.hash).count():
            return
        new_tx = dbCacheTransaction(txid=t.hash, date=t.date, confirmations=t.confirmations,
                                    block_height=t.block_height, block_hash=t.block_hash, network_name=t.network.name,
                                    fee=t.fee, raw=raw_hex, order_n=order_n)
        self.session.add(new_tx)
        for i in t.inputs:
            if i.value is None or i.address is None or i.output_n is None:    # pragma: no cover
                _logger.info("Caching failure tx: Input value, address or output_n missing")
                return False
            new_node = dbCacheTransactionNode(txid=t.hash, address=i.address, output_n=i.index_n, value=i.value,
                                              is_input=True)
            self.session.add(new_node)
            self.session.commit()
        for o in t.outputs:
            if o.value is None or o.address is None or o.output_n is None:    # pragma: no cover
                _logger.info("Caching failure tx: Output value, address, spent info or output_n missing")
                return False
            new_node = dbCacheTransactionNode(txid=t.hash, address=o.address, output_n=o.output_n, value=o.value,
                                              is_input=False, spent=o.spent)
            self.session.add(new_node)
            self.session.commit()

        try:
            self.session.commit()
            _logger.info("Added transaction %s to cache" % t.hash)
        except Exception as e:    # pragma: no cover
            _logger.warning("Caching failure tx: %s" % e)

    def store_address(self, address, last_block, balance=0):
        """
        Store address information in cache

        :param address: Address string
        :type address: str
        :param last_block: Number or last block retrieved from service provider. For instance if address contains a large number of transactions and they will be retrieved in more then one request.
        :type last_block: int
        :param balance: Total balance of address in sathosis, or smallest network detominator
        :type balance: int

        :return:
        """
        if not SERVICE_CACHING_ENABLED:
            return
        new_address = dbCacheAddress(address=address, network_name=self.network.name, last_block=last_block,
                                     balance=balance)
        self.session.merge(new_address)
        try:
            self.session.commit()
        except Exception as e:    # pragma: no cover
            _logger.warning("Caching failure addr: %s" % e)

    def store_estimated_fee(self, blocks, fee):
        """
        Store estimated fee retrieved from service providers in cache.

        :param blocks: Confirmation within x blocks
        :type blocks: int
        :param fee: Estimated fee in Sathosis
        :type fee: int

        :return:
        """
        if not SERVICE_CACHING_ENABLED:
            return
        if blocks <= 1:
            varname = 'fee_high'
        elif blocks <= 5:
            varname = 'fee_medium'
        else:
            varname = 'fee_low'
        dbvar = dbCacheVars(varname=varname, network_name=self.network.name, value=fee, type='int',
                            expires=datetime.datetime.now() + datetime.timedelta(seconds=600))
        self.session.merge(dbvar)
        self.session.commit()
