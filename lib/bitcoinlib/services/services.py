# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    SERVICES - Main Service connector
#    © 2017-2022 - 1200 Web Development <http://1200wd.com/>
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

import json
import random
import time
from datetime import timedelta
from sqlalchemy import func
from bitcoinlib import services
from bitcoinlib.networks import Network
from bitcoinlib.encoding import to_bytes, int_to_varbyteint, varstr, varbyteint_to_int
from bitcoinlib.db_cache import *
from bitcoinlib.transactions import Transaction, transaction_update_spents
from bitcoinlib.blocks import Block


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
                 timeout=TIMEOUT_REQUESTS, cache_uri=None, ignore_priority=False, exclude_providers=None,
                 max_errors=SERVICE_MAX_ERRORS, strict=True):
        """
        Create a service object for the specified network. By default, the object connect to 1 service provider, but you
        can specify a list of providers or a minimum or maximum number of providers.

        :param network: Specify network used
        :type network: str, Network
        :param min_providers: Minimum number of providers to connect to. Default is 1. Use for instance to receive fee information from a number of providers and calculate the average fee.
        :type min_providers: int
        :param max_providers: Maximum number of providers to connect to. Default is 1.
        :type max_providers: int
        :param providers: List of providers to connect to. Default is all providers and select a provider at random.
        :type providers: list of str
        :param timeout: Timeout for web requests. Leave empty to use default from config settings
        :type timeout: int
        :param cache_uri: Database to use for caching
        :type cache_uri: str
        :param ignore_priority: Ignores provider priority if set to True. Could be used for unit testing, so no providers are missed when testing. Default is False
        :type ignore_priority: bool
        :param exclude_providers: Exclude providers in this list, can be used when problems with certain providers arise.
        :type exclude_providers: list of str
        :param strict: Strict checks of valid signatures, scripts and transactions. Normally use strict=True for wallets, transaction validations etcetera. For blockchain parsing strict=False should be used, but be sure to check warnings in the log file. Default is True.
        :type strict: bool

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
        if exclude_providers is None:
            exclude_providers = []
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
        for nop in exclude_providers:
            if nop in self.providers:
                del(self.providers[nop])

        if not self.providers:
            raise ServiceError("No providers found for network %s" % network)
        self.min_providers = min_providers
        self.max_providers = max_providers
        self.results = {}
        self.errors = {}
        self.resultcount = 0
        self.max_errors = max_errors
        self.complete = None
        self.timeout = timeout
        self._blockcount_update = 0
        self._blockcount = None
        self.cache = None
        self.cache_uri = cache_uri
        try:
            self.cache = Cache(self.network, db_uri=cache_uri)
        except Exception as e:
            self.cache = Cache(self.network, db_uri='')
            _logger.warning("Could not connect to cache database. Error: %s" % e)
        self.results_cache_n = 0
        self.ignore_priority = ignore_priority
        self.strict = strict
        if self.min_providers > 1:
            self._blockcount = Service(network=network, cache_uri=cache_uri).blockcount()
        else:
            self._blockcount = self.blockcount()

    def __exit__(self):
        try:
            self.cache.session.close()
        except Exception:
            pass

    def _reset_results(self):
        self.results = {}
        self.errors = {}
        self.complete = None
        self.resultcount = 0

    def _provider_execute(self, method, *arguments):
        self._reset_results()
        provider_lst = [p[0] for p in sorted([(x, self.providers[x]['priority']) for x in self.providers],
                        key=lambda x: (x[1], random.random()), reverse=True)]
        if self.ignore_priority:
            random.shuffle(provider_lst)

        for sp in provider_lst:
            if self.resultcount >= self.max_providers:
                break
            try:
                if sp not in ['bitcoind', 'litecoind', 'dashd', 'dogecoind', 'caching'] and not self.providers[sp]['url'] and \
                        self.network.name != 'bitcoinlib_test':
                    continue
                client = getattr(services, self.providers[sp]['provider'])
                providerclient = getattr(client, self.providers[sp]['client_class'])
                pc_instance = providerclient(
                    self.network, self.providers[sp]['url'], self.providers[sp]['denominator'],
                    self.providers[sp]['api_key'], self.providers[sp]['provider_coin_id'],
                    self.providers[sp]['network_overrides'], self.timeout, self._blockcount, self.strict)
                if not hasattr(pc_instance, method):
                    _logger.debug("Method %s not found for provider %s" % (method, sp))
                    continue
                if self.providers[sp]['api_key'] == 'api-key-needed':
                    _logger.debug("API key needed for provider %s" % sp)
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
                _logger.debug("Executed method %s from provider %s" % (method, sp))
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
                    _logger.debug("Error %s on provider %s" % (e, sp))
                    # -- Use this to debug specific Services errors --
                    # from pprint import pprint
                    # pprint(self.errors)

                if len(self.errors) >= self.max_errors:
                    _logger.warning("Aborting, max errors exceeded: %s" %
                                    list(self.errors.keys()))
                    if len(self.results):
                        return list(self.results.values())[0]
                    else:
                        return False

            if self.resultcount >= self.max_providers:
                break

        if not self.resultcount:
            raise ServiceError("No successful response from any serviceprovider: %s" % list(self.providers.keys()))
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
        if isinstance(addresslist, TYPE_TEXT):
            addresslist = [addresslist]

        tot_balance = 0
        while addresslist:
            for address in addresslist:
                db_addr = self.cache.getaddress(address)
                if db_addr and db_addr.last_block and db_addr.last_block >= self.blockcount() and db_addr.balance:
                    tot_balance += db_addr.balance
                    addresslist.remove(address)

            balance = self._provider_execute('getbalance', addresslist[:addresses_per_request])
            if balance:
                tot_balance += balance
            if len(addresslist) == 1:
                self.cache.store_address(addresslist[0], balance=balance)
            addresslist = addresslist[addresses_per_request:]
        return tot_balance

    def getutxos(self, address, after_txid='', limit=MAX_TRANSACTIONS):
        """
        Get list of unspent outputs (UTXO's) for specified address.

        Sorted from old to new, so the highest number of confirmations first.

        :param address: Address string
        :type address: str
        :param after_txid: Transaction ID of last known transaction. Only check for utxos after given tx id. Default: Leave empty to return all utxos.
        :type after_txid: str
        :param limit: Maximum number of utxo's to return. Sometimes ignored by service providers if more results are returned by default.
        :type limit: int

        :return dict: UTXO's per address
        """
        if not isinstance(address, TYPE_TEXT):
            raise ServiceError("Address parameter must be of type text")
        self.results_cache_n = 0
        self.complete = True

        utxos_cache = []
        if self.min_providers <= 1:
            utxos_cache = self.cache.getutxos(address, bytes.fromhex(after_txid)) or []
        if utxos_cache:
            self.results_cache_n = len(utxos_cache)

            # Last updated block does not always include spent info...
            # if db_addr and db_addr.last_block and db_addr.last_block >= self.blockcount():
            #     return utxos_cache
            after_txid = utxos_cache[-1:][0]['txid']

        utxos = self._provider_execute('getutxos', address, after_txid, limit)
        if utxos is False:
            raise ServiceError("Error when retrieving UTXO's")
        else:
            # Update cache_transactions_node
            for utxo in utxos:
                self.cache.store_utxo(utxo['txid'], utxo['output_n'], commit=False)
            self.cache.commit()
            if utxos and len(utxos) >= limit:
                self.complete = False
            elif not after_txid:
                balance = sum(u['value'] for u in utxos)
                self.cache.store_address(address, balance=balance, n_utxos=len(utxos))

        return utxos_cache + utxos

    def gettransaction(self, txid):
        """
        Get a transaction by its transaction hash. Convert to Bitcoinlib Transaction object.

        :param txid: Transaction identification hash
        :type txid: str

        :return Transaction: A single transaction object
        """
        tx = None
        self.results_cache_n = 0

        if self.min_providers <= 1:
            tx = self.cache.gettransaction(bytes.fromhex(txid))
            if tx:
                self.results_cache_n = 1
        if not tx:
            tx = self._provider_execute('gettransaction', txid)
            if tx and tx.txid != txid:
                _logger.warning("Incorrect txid after parsing")
                tx.txid = txid
            if len(self.results) and self.min_providers <= 1:
                self.cache.store_transaction(tx)
        return tx

    def gettransactions(self, address, after_txid='', limit=MAX_TRANSACTIONS):
        """
        Get all transactions for specified address.

        Sorted from old to new, so transactions with highest number of confirmations first.

        :param address: Address string
        :type address: str
        :param after_txid: Transaction ID of last known transaction. Only check for transactions after given tx id. Default: Leave empty to return all transaction. If used only provide a single address
        :type after_txid: str
        :param limit: Maximum number of transactions to return
        :type limit: int

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
        qry_after_txid = bytes.fromhex(after_txid)

        # Retrieve transactions from cache
        caching_enabled = True
        if self.min_providers > 1:  # Disable cache if comparing providers
            caching_enabled = False

        if caching_enabled:
            txs_cache = self.cache.gettransactions(address, qry_after_txid, limit) or []
            if txs_cache:
                self.results_cache_n = len(txs_cache)
                if len(txs_cache) == limit:
                    return txs_cache
                limit = limit - len(txs_cache)
                qry_after_txid = bytes.fromhex(txs_cache[-1:][0].txid)

        # Get (extra) transactions from service providers
        txs = []
        if not(db_addr and db_addr.last_block and db_addr.last_block >= self.blockcount()) or not caching_enabled:
            txs = self._provider_execute('gettransactions', address, qry_after_txid.hex(),  limit)
            if txs is False:
                raise ServiceError("Error when retrieving transactions from service provider")

        # Store transactions and address in cache
        # - disable cache if comparing providers or if after_txid is used and no cache is available
        last_block = None
        last_txid = None
        if self.min_providers <= 1 and not(after_txid and not db_addr) and caching_enabled:
            last_block = self.blockcount()
            last_txid = qry_after_txid
            self.complete = True
            if len(txs) == limit:
                self.complete = False
                last_block = txs[-1:][0].block_height
            if len(txs):
                last_txid = bytes.fromhex(txs[-1:][0].txid)
            if len(self.results):
                order_n = 0
                for t in txs:
                    if t.confirmations != 0:
                        res = self.cache.store_transaction(t, order_n, commit=False)
                        order_n += 1
                        # Failure to store transaction: stop caching transaction and store last tx block height - 1
                        if res is False:
                            if t.block_height:
                                last_block = t.block_height - 1
                            break
                self.cache.commit()
                self.cache.store_address(address, last_block, last_txid=last_txid, txs_complete=self.complete)

        all_txs = txs_cache + txs
        # If we have txs for this address update spent and balance information in cache
        if self.complete:
            all_txs = transaction_update_spents(all_txs, address)
            if caching_enabled:
                self.cache.store_address(address, last_block, last_txid=last_txid, txs_complete=True)
                for t in all_txs:
                    self.cache.store_transaction(t, commit=False)
                self.cache.commit()
        return all_txs

    def getrawtransaction(self, txid):
        """
        Get a raw transaction by its transaction hash

        :param txid: Transaction identification hash
        :type txid: str

        :return str: Raw transaction as hexstring
        """
        self.results_cache_n = 0
        rawtx = self.cache.getrawtransaction(bytes.fromhex(txid))
        if rawtx:
            self.results_cache_n = 1
            return rawtx
        return self._provider_execute('getrawtransaction', txid)

    def sendrawtransaction(self, rawtx):
        """
        Push a raw transaction to the network

        :param rawtx: Raw transaction as hexstring or bytes
        :type rawtx: str

        :return dict: Send transaction result
        """
        return self._provider_execute('sendrawtransaction', rawtx)

    def estimatefee(self, blocks=3, priority=''):
        """
        Estimate fee per kilobyte for a transaction for this network with expected confirmation within a certain
        amount of blocks

        :param blocks: Expected confirmation time in blocks. Default is 3.
        :type blocks: int
        :param priority: Priority for transaction: can be 'low', 'medium' or 'high'. Overwrites value supplied in 'blocks' argument
        :type priority: str

        :return int: Fee in the smallest network denominator (satoshi)
        """
        self.results_cache_n = 0
        if priority:
            if priority == 'low':
                blocks = 10
            elif priority == 'high':
                blocks = 1
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
        if fee < self.network.fee_min:
            fee = self.network.fee_min
        elif fee > self.network.fee_max:
            fee = self.network.fee_max
        self.cache.store_estimated_fee(blocks, fee)
        return fee

    def blockcount(self):
        """
        Get the latest block number: The block number of last block in longest chain on the Blockchain.

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
                self._blockcount_update = current_timestamp
            if last_cache_blockcount > self._blockcount:
                return last_cache_blockcount
            # Store result in cache
            if len(self.results) and list(self.results.keys())[0] != 'caching':
                self.cache.store_blockcount(self._blockcount)
        return self._blockcount

    def getblock(self, blockid, parse_transactions=True, page=1, limit=None):
        """
        Get block with specified block height or block hash from service providers.

        If parse_transaction is set to True a list of Transaction object will be returned otherwise a
        list of transaction ID's.

        Some providers require 1 or 2 extra request per transaction, so to avoid timeouts or rate limiting errors
        you can specify a page and limit for the transaction. For instance with page=2, limit=4 only transaction
        5 to 8 are returned to the Blocks's 'transaction' attribute.

        If you only use a local bcoin or bitcoind provider, make sure you set the limit to maximum (i.e. 9999)
        because all transactions are already downloaded when fetching the block.

        >>> from bitcoinlib.services.services import Service
        >>> srv = Service()
        >>> b = srv.getblock(0)
        >>> b
        <Block(000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f, 0, transactions: 1)>

        :param blockid: Hash or block height of block
        :type blockid: str, int
        :param parse_transactions: Return Transaction objects or just transaction ID's. Default is return txids.
        :type parse_transactions: bool
        :param page: Page number of transaction paging. Default is start from the beginning: 1
        :type page: int
        :param limit: Maximum amount of transaction to return. Default is 25 if parse transaction is enabled, otherwise returns all txid's (9999)
        :type limit: int

        :return Block:
        """
        if limit is None:
            limit = 25 if parse_transactions else 99999

        block = self.cache.getblock(blockid)
        is_last_page = False
        if block:
            # Block found get transactions from cache
            txs = self.cache.getblocktransactions(block.height, page, limit)
            if parse_transactions:
                block.transactions = txs
            else:
                block.transactions = [tx.txid for tx in txs]
            if block.transactions:
                self.results_cache_n = 1
            is_last_page = page*limit > block.tx_count
        if not block or (not len(block.transactions) and limit != 0) or (not is_last_page and len(block.transactions) < limit) or \
                (is_last_page and ((page-1)*limit - block.tx_count + len(block.transactions)) < 0):
            self.results_cache_n = 0
            bd = self._provider_execute('getblock', blockid, parse_transactions, page, limit)
            if not bd or isinstance(bd, bool):
                return False
            block = Block(bd['block_hash'], bd['version'], bd['prev_block'], bd['merkle_root'], bd['time'], bd['bits'],
                          bd['nonce'], bd['txs'], bd['height'], bd['depth'], self.network)
            block.tx_count = bd['tx_count']
            block.limit = limit
            block.page = page

            if parse_transactions and self.min_providers <= 1:
                order_n = (page-1)*limit
                for tx in block.transactions:
                    if isinstance(tx, Transaction):
                        self.cache.store_transaction(tx, order_n, commit=False)
                    order_n += 1
                self.cache.commit()
            self.complete = True if len(block.transactions) == block.tx_count else False
            self.cache.store_block(block)
        return block

    def getrawblock(self, blockid):
        """
        Get raw block as hexadecimal string for block with specified hash or block height.

        Not many providers offer this option, and it can be slow, so it is advised to use a local client such
        as bitcoind.

        :param blockid: Block hash or block height
        :type blockid: str, int

        :return str:
        """
        return self._provider_execute('getrawblock', blockid)

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

    def getcacheaddressinfo(self, address):
        """
        Get address information from cache. I.e. balance, number of transactions, number of utox's, etc

        Cache will only be filled after all transactions for a specific address are retrieved (with gettransactions ie)

        :param address: address string
        :type address: str

        :return dict:
        """
        addr_dict = {'address': address}
        addr_rec = self.cache.getaddress(address)
        if isinstance(addr_rec, DbCacheAddress):
            addr_dict['balance'] = addr_rec.balance
            addr_dict['last_block'] = addr_rec.last_block
            addr_dict['n_txs'] = addr_rec.n_txs
            addr_dict['n_utxos'] = addr_rec.n_utxos
        return addr_dict

    def isspent(self, txid, output_n):
        """
        Check if the output with provided transaction ID and output number is spent.

        :param txid: Transaction ID hex
        :type txid: str
        :param output_n: Output number
        :type output_n: int

        :return bool:
        """
        t = self.cache.gettransaction(bytes.fromhex(txid))
        if t and len(t.outputs) > output_n and t.outputs[output_n].spent is not None:
            return t.outputs[output_n].spent
        else:
            return bool(self._provider_execute('isspent', txid, output_n))

    def getinfo(self):
        """
        Returns info about current network. Such as difficulty, latest block, mempool size and network hashrate.

        :return dict:
        """
        return self._provider_execute('getinfo')

    def getinputvalues(self, t):
        """
        Retrieve values for transaction inputs for given Transaction.

        Raw transactions as stored on the blockchain do not contain the input values but only the previous
        transaction hash and index number. This method retrieves the previous transaction and reads the value.

        :param t: Transaction
        :type t: Transaction

        :return Transaction:
        """
        prev_txs = []
        for i in t.inputs:
            if not i.value:
                if i.prev_txid not in prev_txs:
                    prev_t = self.gettransaction(i.prev_txid.hex())
                else:
                    prev_t = [t for t in prev_txs if t.txid == i.prev_txid][0]
                i.value = prev_t.outputs[i.output_n_int].value
        return t


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
            self.session = DbCache(db_uri=db_uri).session
        self.network = network

    def __exit__(self):
        try:
            self.session.close()
        except Exception:
            pass

    def cache_enabled(self):
        """
        Check if caching is enabled. Returns False if SERVICE_CACHING_ENABLED is False or no session is defined.

        :return bool:
        """
        if not SERVICE_CACHING_ENABLED or not self.session:
            return False
        return True

    def commit(self):
        """
        Commit queries in self.session. Rollback if commit fails.

        :return:
        """
        if not self.session:
            return
        try:
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise

    @staticmethod
    def _parse_db_transaction(db_tx):
        t = Transaction(locktime=db_tx.locktime, version=db_tx.version, network=db_tx.network_name,
                        fee=db_tx.fee, txid=db_tx.txid.hex(), date=db_tx.date, confirmations=db_tx.confirmations,
                        block_height=db_tx.block_height, status='confirmed', witness_type=db_tx.witness_type.value)
        for n in db_tx.nodes:
            if n.is_input:
                if n.ref_txid == b'\00' * 32:
                    t.coinbase = True
                t.add_input(n.ref_txid.hex(), n.ref_index_n, unlocking_script=n.script, address=n.address,
                            sequence=n.sequence, value=n.value, index_n=n.index_n, witnesses=n.witnesses, strict=False)
            else:
                t.add_output(n.value, n.address, lock_script=n.script, spent=n.spent, output_n=n.index_n,
                             spending_txid=None if not n.ref_txid else n.ref_txid.hex(),
                             spending_index_n=n.ref_index_n, strict=False)

        t.update_totals()
        t.size = len(t.raw())
        t.calc_weight_units()
        _logger.info("Retrieved transaction %s from cache" % t.txid)
        return t

    def gettransaction(self, txid):
        """
        Get transaction from cache. Returns False if not available

        :param txid: Transaction identification hash
        :type txid: bytes

        :return Transaction: A single Transaction object
        """
        if not self.cache_enabled():
            return False
        db_tx = self.session.query(DbCacheTransaction).filter_by(txid=txid, network_name=self.network.name).first()
        if not db_tx:
            return False
        db_tx.txid = txid
        t = self._parse_db_transaction(db_tx)
        if t.block_height:
            t.confirmations = (self.blockcount() - t.block_height) + 1
        return t

    def getaddress(self, address):
        """
        Get address information from cache, with links to transactions and utxo's and latest update information.

        :param address: Address string
        :type address: str

        :return DbCacheAddress: An address cache database object
        """
        if not self.cache_enabled():
            return
        return self.session.query(DbCacheAddress).filter_by(address=address, network_name=self.network.name).scalar()

    def gettransactions(self, address, after_txid='', limit=MAX_TRANSACTIONS):
        """
        Get transactions from cache. Returns empty list if no transactions are found or caching is disabled.

        :param address: Address string
        :type address: str
        :param after_txid: Transaction ID of last known transaction. Only check for transactions after given tx id. Default: Leave empty to return all transaction. If used only provide a single address
        :type after_txid: bytes
        :param limit: Maximum number of transactions to return
        :type limit: int

        :return list: List of Transaction objects
        """
        if not self.cache_enabled():
            return False
        db_addr = self.getaddress(address)
        txs = []
        if db_addr:
            if after_txid:
                after_tx = self.session.query(DbCacheTransaction).\
                    filter_by(txid=after_txid, network_name=self.network.name).scalar()
                if after_tx and db_addr.last_block and after_tx.block_height:
                    db_txs = self.session.query(DbCacheTransaction).join(DbCacheTransactionNode).\
                        filter(DbCacheTransactionNode.address == address,
                               DbCacheTransaction.block_height >= after_tx.block_height,
                               DbCacheTransaction.block_height <= db_addr.last_block).\
                        order_by(DbCacheTransaction.block_height, DbCacheTransaction.order_n).all()
                    db_txs2 = []
                    for d in db_txs:
                        db_txs2.append(d)
                        if d.txid == after_txid:
                            db_txs2 = []
                    db_txs = db_txs2
                else:
                    return []
            else:
                db_txs = self.session.query(DbCacheTransaction).join(DbCacheTransactionNode). \
                    filter(DbCacheTransactionNode.address == address). \
                    order_by(DbCacheTransaction.block_height, DbCacheTransaction.order_n).all()
            for db_tx in db_txs:
                t = self._parse_db_transaction(db_tx)
                if t:
                    if t.block_height:
                        t.confirmations = (self.blockcount() - t.block_height) + 1
                    txs.append(t)
                    if len(txs) >= limit:
                        break
            return txs
        return []

    def getblocktransactions(self, height, page, limit):
        """
        Get range of transactions from a block

        :param height: Block height
        :type height: int
        :param page: Transaction page
        :type page: int
        :param limit: Number of transactions per page
        :type limit: int

        :return:
        """
        if not self.cache_enabled():
            return False
        n_from = (page-1) * limit
        n_to = page * limit
        db_txs = self.session.query(DbCacheTransaction).\
            filter(DbCacheTransaction.block_height == height, DbCacheTransaction.order_n >= n_from,
                   DbCacheTransaction.order_n < n_to).all()
        txs = []
        for db_tx in db_txs:
            t = self._parse_db_transaction(db_tx)
            if t:
                txs.append(t)
        return txs

    def getrawtransaction(self, txid):
        """
        Get a raw transaction string from the database cache if available

        :param txid: Transaction identification hash
        :type txid: bytes

        :return str: Raw transaction as hexstring
        """
        if not self.cache_enabled():
            return False
        tx = self.session.query(DbCacheTransaction).filter_by(txid=txid, network_name=self.network.name).first()
        if not tx:
            return False
        t = self._parse_db_transaction(tx)
        return t.raw_hex()

    def getutxos(self, address, after_txid=''):
        """
        Get list of unspent outputs (UTXO's) for specified address from database cache.

        Sorted from old to new, so highest number of confirmations first.

        :param address: Address string
        :type address: str
        :param after_txid: Transaction ID of last known transaction. Only check for utxos after given tx id. Default: Leave empty to return all utxos.
        :type after_txid: bytes

        :return dict: UTXO's per address
        """
        if not self.cache_enabled():
            return False
        db_utxos = self.session.query(DbCacheTransactionNode.spent, DbCacheTransactionNode.index_n,
                                      DbCacheTransactionNode.value, DbCacheTransaction.confirmations,
                                      DbCacheTransaction.block_height, DbCacheTransaction.fee,
                                      DbCacheTransaction.date, DbCacheTransaction.txid).join(DbCacheTransaction). \
            order_by(DbCacheTransaction.block_height, DbCacheTransaction.order_n). \
            filter(DbCacheTransactionNode.address == address, DbCacheTransactionNode.is_input == False,
                   DbCacheTransaction.network_name == self.network.name).all()
        utxos = []
        for db_utxo in db_utxos:
            if db_utxo.spent is False:
                utxos.append({
                    'address': address,
                    'txid': db_utxo.txid.hex(),
                    'confirmations': db_utxo.confirmations,
                    'output_n': db_utxo.index_n,
                    'input_n': 0,
                    'block_height': db_utxo.block_height,
                    'fee': db_utxo.fee,
                    'size': 0,
                    'value': db_utxo.value,
                    'script': '',
                    'date': db_utxo.date
                })
            elif db_utxo.spent is None:
                return utxos
            if db_utxo.txid == after_txid:
                utxos = []
        return utxos

    def estimatefee(self, blocks):
        """
        Get fee estimation from cache for confirmation within specified amount of blocks.

        Stored in cache in three groups: low, medium and high fees.

        :param blocks: Expected confirmation time in blocks.
        :type blocks: int

        :return int: Fee in the smallest network denominator (satoshi)
        """
        if not self.cache_enabled():
            return False
        if blocks <= 1:
            varname = 'fee_high'
        elif blocks <= 5:
            varname = 'fee_medium'
        else:
            varname = 'fee_low'
        dbvar = self.session.query(DbCacheVars).filter_by(varname=varname, network_name=self.network.name).\
            filter(DbCacheVars.expires > datetime.now()).scalar()
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
        if not self.cache_enabled():
            return False
        qr = self.session.query(DbCacheVars).filter_by(varname='blockcount', network_name=self.network.name)
        if not never_expires:
            qr = qr.filter(DbCacheVars.expires > datetime.now())
        dbvar = qr.scalar()
        if dbvar:
            return int(dbvar.value)
        return False

    def getblock(self, blockid):
        """
        Get specific block from database cache.

        :param blockid: Block height or block hash
        :type blockid: int, str

        :return Block:
        """
        if not self.cache_enabled():
            return False
        qr = self.session.query(DbCacheBlock)
        if isinstance(blockid, int):
            block = qr.filter_by(height=blockid, network_name=self.network.name).scalar()
        else:
            block = qr.filter_by(block_hash=to_bytes(blockid)).scalar()
        if not block:
            return False
        b = Block(block_hash=block.block_hash, height=block.height, network=block.network_name,
                  merkle_root=block.merkle_root, time=block.time, nonce=block.nonce,
                  version=block.version, prev_block=block.prev_block, bits=block.bits)
        b.tx_count = block.tx_count
        _logger.info("Retrieved block with height %d from cache" % b.height)
        return b

    def store_blockcount(self, blockcount):
        """
        Store network blockcount in cache for 60 seconds

        :param blockcount: Number of latest block
        :type blockcount: int, str

        :return:
        """
        if not self.cache_enabled():
            return
        dbvar = DbCacheVars(varname='blockcount', network_name=self.network.name, value=str(blockcount), type='int',
                            expires=datetime.now() + timedelta(seconds=60))
        self.session.merge(dbvar)
        self.commit()

    def store_transaction(self, t, order_n=None, commit=True):
        """
        Store transaction in cache. Use order number to determine order in a block

        :param t: Transaction
        :type t: Transaction
        :param order_n: Order in block
        :type order_n: int
        :param commit: Commit transaction to database. Default is True. Can be disabled if a larger number of transactions are added to cache, so you can commit outside this method.
        :type commit: bool

        :return:
        """
        if not self.cache_enabled():
            return
        # Only store complete and confirmed transaction in cache
        if not t.txid:    # pragma: no cover
            _logger.info("Caching failure tx: Missing transaction hash")
            return False
        elif not t.date or not t.block_height or not t.network:
            _logger.info("Caching failure tx: Incomplete transaction missing date, block height or network info")
            return False
        elif not t.coinbase and [i for i in t.inputs if not i.value]:
            _logger.info("Caching failure tx: One the transaction inputs has value 0")
            return False
        # TODO: Check if inputs / outputs are complete? script, value, prev_txid, sequence, output/input_n

        txid = bytes.fromhex(t.txid)
        if self.session.query(DbCacheTransaction).filter_by(txid=txid).count():
            return
        new_tx = DbCacheTransaction(txid=txid, date=t.date, confirmations=t.confirmations,
                                    block_height=t.block_height, network_name=t.network.name,
                                    fee=t.fee, order_n=order_n, version=t.version_int,
                                    locktime=t.locktime, witness_type=t.witness_type)
        self.session.add(new_tx)
        for i in t.inputs:
            if i.value is None or i.address is None or i.output_n is None:    # pragma: no cover
                _logger.info("Caching failure tx: Input value, address or output_n missing")
                return False
            witnesses = int_to_varbyteint(len(i.witnesses)) + b''.join([bytes(varstr(w)) for w in i.witnesses])
            new_node = DbCacheTransactionNode(txid=txid, address=i.address, index_n=i.index_n, value=i.value,
                                              is_input=True, ref_txid=i.prev_txid, ref_index_n=i.output_n_int,
                                              script=i.unlocking_script, sequence=i.sequence, witnesses=witnesses)
            self.session.add(new_node)
        for o in t.outputs:
            if o.value is None or o.address is None or o.output_n is None:    # pragma: no cover
                _logger.info("Caching failure tx: Output value, address or output_n missing")
                return False
            new_node = DbCacheTransactionNode(
                txid=txid, address=o.address, index_n=o.output_n, value=o.value, is_input=False, spent=o.spent,
                ref_txid=None if not o.spending_txid else bytes.fromhex(o.spending_txid),
                ref_index_n=o.spending_index_n, script=o.lock_script)
            self.session.add(new_node)

        if commit:
            try:
                self.commit()
                _logger.info("Added transaction %s to cache" % t.txid)
            except Exception as e:    # pragma: no cover
                _logger.warning("Caching failure tx: %s" % e)

    def store_utxo(self, txid, index_n, commit=True):
        """
        Store utxo in cache. Updates only known transaction outputs for transactions which are fully cached

        :param txid: Transaction ID
        :type txid: str
        :param index_n: Index number of output
        :type index_n: int
        :param commit: Commit transaction to database. Default is True. Can be disabled if a larger number of transactions are added to cache, so you can commit outside this method.
        :type commit: bool

        :return:
        """
        if not self.cache_enabled():
            return False
        txid = bytes.fromhex(txid)
        result = self.session.query(DbCacheTransactionNode). \
            filter(DbCacheTransactionNode.txid == txid, DbCacheTransactionNode.index_n == index_n,
                   DbCacheTransactionNode.is_input == False).\
            update({DbCacheTransactionNode.spent: False})
        if commit:
            try:
                self.commit()
            except Exception as e:    # pragma: no cover
                _logger.warning("Caching failure utxo %s:%d: %s" % (txid.hex(), index_n, e))

    def store_address(self, address, last_block=None, balance=0, n_utxos=None, txs_complete=False, last_txid=None):
        """
        Store address information in cache

        :param address: Address string
        :type address: str
        :param last_block: Number or last block retrieved from service provider. For instance if address contains a large number of transactions and they will be retrieved in more then one request.
        :type last_block: int
        :param balance: Total balance of address in sathosis, or smallest network detominator
        :type balance: int
        :param n_utxos: Total number of UTXO's for this address
        :type n_utxos: int
        :param txs_complete: True if all transactions for this address are added to cache
        :type txs_complete: bool
        :param last_txid: Transaction ID of last transaction downloaded from blockchain
        :type last_txid: bytes

 .       :return:
        """
        if not self.cache_enabled():
            return
        n_txs = None
        if txs_complete:
            n_txs = len(self.session.query(DbCacheTransaction).join(DbCacheTransactionNode).
                        filter(DbCacheTransactionNode.address == address).all())
            if n_utxos is None:
                n_utxos = self.session.query(DbCacheTransactionNode).\
                    filter(DbCacheTransactionNode.address == address, DbCacheTransactionNode.spent.is_(False),
                           DbCacheTransactionNode.is_input.is_(False)).count()
                if self.session.query(DbCacheTransactionNode).\
                        filter(DbCacheTransactionNode.address == address, DbCacheTransactionNode.spent.is_(None),
                               DbCacheTransactionNode.is_input.is_(False)).count():
                    n_utxos = None
            if not balance:
                plusmin = self.session.query(DbCacheTransactionNode.is_input, func.sum(DbCacheTransactionNode.value)). \
                    filter(DbCacheTransactionNode.address == address). \
                    group_by(DbCacheTransactionNode.is_input).all()
                balance = 0 if not plusmin else sum([(-p[1] if p[0] else p[1]) for p in plusmin])
        db_addr = self.getaddress(address)
        new_address = DbCacheAddress(
            address=address, network_name=self.network.name,
            last_block=last_block if last_block else getattr(db_addr, 'last_block', None),
            balance=balance if balance is not None else getattr(db_addr, 'balance', None),
            n_utxos=n_utxos if n_utxos is not None else getattr(db_addr, 'n_utxos', None),
            n_txs=n_txs if n_txs is not None else getattr(db_addr, 'n_txs', None),
            last_txid=last_txid if last_txid is not None else getattr(db_addr, 'last_txid', None))
        self.session.merge(new_address)
        try:
            self.commit()
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
        if not self.cache_enabled():
            return
        if blocks <= 1:
            varname = 'fee_high'
        elif blocks <= 5:
            varname = 'fee_medium'
        else:
            varname = 'fee_low'
        dbvar = DbCacheVars(varname=varname, network_name=self.network.name, value=str(fee), type='int',
                            expires=datetime.now() + timedelta(seconds=600))
        self.session.merge(dbvar)
        self.commit()

    def store_block(self, block):
        """
        Store block in cache database

        :param block: Block
        :type block: Block

        :return:
        """
        if not self.cache_enabled():
            return
        if not (block.height and block.block_hash and block.prev_block and block.merkle_root and
                block.bits and block.version) \
                and not block.block_hash == b'\x00\x00\x00\x00\x00\x19\xd6h\x9c\x08Z\xe1e\x83\x1e\x93O\xf7c\xaeF' \
                                            b'\xa2\xa6\xc1r\xb3\xf1\xb6\n\x8c\xe2o':  # Bitcoin genesis block
            _logger.info("Caching failure block: incomplete data")
            return

        new_block = DbCacheBlock(
            block_hash=block.block_hash, height=block.height, network_name=self.network.name,
            version=block.version_int, prev_block=block.prev_block, bits=block.bits_int,
            merkle_root=block.merkle_root, nonce=block.nonce_int, time=block.time, tx_count=block.tx_count)
        self.session.merge(new_block)
        try:
            self.commit()
        except Exception as e:    # pragma: no cover
            _logger.warning("Caching failure block: %s" % e)
