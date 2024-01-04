# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    Cache DataBase - SqlAlchemy database definitions for caching
#    © 2020 - 2023 May - 1200 Web Development <http://1200wd.com/>
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

from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, BigInteger, String, Boolean, ForeignKey, DateTime, Enum, LargeBinary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, close_all_sessions
# try:
#     import mysql.connector
#     from parameterized import parameterized_class
#     import psycopg2
#     from psycopg2 import sql
#     from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
# except ImportError as e:
#     print("Could not import all modules. Error: %s" % e)
#     # from psycopg2cffi import compat  # Use for PyPy support
#     # compat.register()
#     pass  # Only necessary when mysql or postgres is used
from urllib.parse import urlparse
from bitcoinlib.main import *


_logger = logging.getLogger(__name__)
try:
    dbcacheurl_obj = urlparse(DEFAULT_DATABASE_CACHE)
    if dbcacheurl_obj.netloc:
        dbcacheurl = dbcacheurl_obj.netloc.replace(dbcacheurl_obj.password, 'xxx')
    else:
        dbcacheurl = dbcacheurl_obj.path
    _logger.info("Default Cache Database %s" % dbcacheurl)
except Exception:
    _logger.warning("Default Cache Database: unable to parse URL")
Base = declarative_base()


class WitnessTypeTransactions(enum.Enum):
    legacy = "legacy"
    segwit = "segwit"


class DbCache:
    """
    Cache Database object. Initialize database and open session when creating database object.

    Create new database if is doesn't exist yet

    """
    def __init__(self, db_uri=None):
        self.engine = None
        self.session = None
        if db_uri is None:
            db_uri = DEFAULT_DATABASE_CACHE
        elif not db_uri:
            return
        self.o = urlparse(db_uri)

        if not self.o.scheme or len(self.o.scheme) < 2:
            db_uri = 'sqlite:///%s' % db_uri
        if db_uri.startswith("sqlite://") and ALLOW_DATABASE_THREADS:
            db_uri += "&" if "?" in db_uri else "?"
            db_uri += "check_same_thread=False"
        if self.o.scheme == 'mysql':
            db_uri += "&" if "?" in db_uri else "?"
            db_uri += 'binary_prefix=true'
        self.engine = create_engine(db_uri, isolation_level='READ UNCOMMITTED')

        Session = sessionmaker(bind=self.engine)
        Base.metadata.create_all(self.engine)
        self.db_uri = db_uri
        _logger.info("Using cache database: %s://%s:%s/%s" % (self.o.scheme or '', self.o.hostname or '',
                                                              self.o.port or '', self.o.path or ''))
        self.session = Session()

    def drop_db(self):
        self.session.commit()
        # self.session.close_all()
        close_all_sessions()
        Base.metadata.drop_all(self.engine)


class DbCacheTransactionNode(Base):
    """
    Link table for cache transactions and addresses
    """
    __tablename__ = 'cache_transactions_node'
    txid = Column(LargeBinary(32), ForeignKey('cache_transactions.txid'), primary_key=True)
    transaction = relationship("DbCacheTransaction", back_populates='nodes', doc="Related transaction object")
    index_n = Column(Integer, primary_key=True, doc="Order of input/output in this transaction")
    value = Column(BigInteger, default=0, doc="Value of transaction input")
    address = Column(String(255), index=True, doc="Address string base32 or base58 encoded")
    script = Column(LargeBinary, doc="Locking or unlocking script")
    witnesses = Column(LargeBinary, doc="Witnesses (signatures) used in Segwit transaction inputs")
    sequence = Column(BigInteger, default=0xffffffff,
                      doc="Transaction sequence number. Used for timelock transaction inputs")
    is_input = Column(Boolean, primary_key=True, doc="True if input, False if output")
    spent = Column(Boolean, default=None, doc="Is output spent?")
    ref_txid = Column(LargeBinary(32), index=True, doc="Transaction hash of input which spends this output")
    ref_index_n = Column(BigInteger, doc="Index number of transaction input which spends this output")

    def prev_txid(self):
        if self.is_input:
            return self.ref_txid

    def output_n(self):
        if self.is_input:
            return self.ref_index_n

    def spending_txid(self):
        if not self.is_input:
            return self.ref_txid

    def spending_index_n(self):
        if not self.is_input:
            return self.ref_index_n


class DbCacheTransaction(Base):
    """
    Transaction Cache Table

    Database which stores transactions received from service providers as cache

    """
    __tablename__ = 'cache_transactions'
    txid = Column(LargeBinary(32), primary_key=True, doc="Hexadecimal representation of transaction hash or transaction ID")
    date = Column(DateTime, doc="Date when transaction was confirmed and included in a block")
    version = Column(BigInteger, default=1,
                     doc="Tranaction version. Default is 1 but some wallets use another version number")
    locktime = Column(BigInteger, default=0,
                      doc="Transaction level locktime. Locks the transaction until a specified block "
                          "(value from 1 to 5 million) or until a certain time (Timestamp in seconds after 1-jan-1970)."
                          " Default value is 0 for transactions without locktime")
    confirmations = Column(Integer, default=0,
                           doc="Number of confirmation when this transaction is included in a block. "
                               "Default is 0: unconfirmed")
    block_height = Column(Integer, index=True, doc="Height of block this transaction is included in")
    network_name = Column(String(20), doc="Blockchain network name of this transaction")
    fee = Column(BigInteger, doc="Transaction fee")
    nodes = relationship("DbCacheTransactionNode", cascade="all,delete",
                         doc="List of all inputs and outputs as DbCacheTransactionNode objects")
    order_n = Column(Integer, doc="Order of transaction in block")
    witness_type = Column(Enum(WitnessTypeTransactions), default=WitnessTypeTransactions.legacy,
                          doc="Transaction type enum: legacy or segwit")


class DbCacheAddress(Base):
    """
    Address Cache Table

    Stores transactions and unspent outputs (UTXO's) per address

    """
    __tablename__ = 'cache_address'
    address = Column(String(255), primary_key=True, doc="Address string base32 or base58 encoded")
    network_name = Column(String(20), doc="Blockchain network name of this transaction")
    balance = Column(BigInteger, default=0, doc="Total balance of UTXO's linked to this key")
    last_block = Column(Integer, doc="Number of last updated block")
    last_txid = Column(LargeBinary(32), doc="Transaction ID of latest transaction in cache")
    n_utxos = Column(Integer, doc="Total number of UTXO's for this address")
    n_txs = Column(Integer, doc="Total number of transactions for this address")


class DbCacheBlock(Base):
    """
    Block Cache Table

    Stores block headers
    """
    __tablename__ = 'cache_blocks'
    height = Column(Integer, primary_key=True, doc="Height or sequence number for this block")
    block_hash = Column(LargeBinary(32), index=True, doc="Hash of this block")
    network_name = Column(String(20), doc="Blockchain network name")
    version = Column(BigInteger, doc="Block version to specify which features are used (hex)")
    prev_block = Column(LargeBinary(32), doc="Block hash of previous block")
    merkle_root = Column(LargeBinary(32), doc="Merkle root used to validate transaction in block")
    time = Column(BigInteger, doc="Timestamp to indicated when block was created")
    bits = Column(BigInteger, doc="Encoding for proof-of-work, used to determine target and difficulty")
    nonce = Column(BigInteger, doc="Nonce (number used only once or n-once) is used to create different block hashes")
    tx_count = Column(Integer, doc="Number of transactions included in this block")


class DbCacheVars(Base):
    """
    Table to store various blockchain related variables
    """
    __tablename__ = 'cache_variables'
    varname = Column(String(50), primary_key=True, doc="Variable unique name")
    network_name = Column(String(20), primary_key=True, doc="Blockchain network name of this transaction")
    value = Column(String(255), doc="Value of variable")
    type = Column(String(20), doc="Type of variable: int, string or float")
    expires = Column(DateTime, doc="Datetime value when variable expires")
