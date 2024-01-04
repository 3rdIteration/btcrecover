# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    Cache DataBase - SqlAlchemy database definitions for caching
#    © 2020 February - 1200 Web Development <http://1200wd.com/>
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

try:
    import enum
except ImportError:
    import enum34 as enum
import datetime
from sqlalchemy import create_engine
from sqlalchemy import (Column, Integer, BigInteger, UniqueConstraint, CheckConstraint, String, Boolean, Sequence,
                        ForeignKey, DateTime, Numeric, Text)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse
from lib.bitcoinlib.main import *

_logger = logging.getLogger(__name__)
_logger.info("Using Cache Database %s" % DEFAULT_DATABASE_CACHE)
Base = declarative_base()


class DbInit:
    """
    Initialize database and open session

    Create new database if is doesn't exist yet

    """
    def __init__(self, db_uri=None):
        if db_uri is None:
            db_uri = DEFAULT_DATABASE_CACHE
        o = urlparse(db_uri)
        if not o.scheme or len(o.scheme) < 2:
            db_uri = 'sqlite:///%s' % db_uri
        if db_uri.startswith("sqlite://") and ALLOW_DATABASE_THREADS:
            if "?" in db_uri: db_uri += "&"
            else: db_uri += "?"
            db_uri += "check_same_thread=False"
        self.engine = create_engine(db_uri, isolation_level='READ UNCOMMITTED')
        Session = sessionmaker(bind=self.engine)

        Base.metadata.create_all(self.engine)
        self.session = Session()


class dbCacheTransactionNode(Base):
    """
    Link table for cache transactions and addresses
    """
    __tablename__ = 'cache_transactions_node'
    txid = Column(String(64), ForeignKey('cache_transactions.txid'), primary_key=True)
    transaction = relationship("dbCacheTransaction", back_populates='nodes', doc="Related transaction object")
    output_n = Column(BigInteger, primary_key=True, doc="Output_n of previous transaction output that is spent in this input")
    value = Column(Numeric(25, 0, asdecimal=False), default=0, doc="Value of transaction input")
    is_input = Column(Boolean, primary_key=True, doc="True if input, False if output")
    address = Column(String(255), doc="Address string base32 or base58 encoded")
    spent = Column(Boolean, default=None, doc="Is output spent?")


class dbCacheTransaction(Base):
    """
    Transaction Cache Table

    Database which stores transactions received from service providers as cache

    """
    __tablename__ = 'cache_transactions'
    txid = Column(String(64), primary_key=True, doc="Hexadecimal representation of transaction hash or transaction ID")
    date = Column(DateTime, default=datetime.datetime.utcnow,
                  doc="Date when transaction was confirmed and included in a block. "
                      "Or when it was created when transaction is not send or confirmed")
    confirmations = Column(Integer, default=0,
                           doc="Number of confirmation when this transaction is included in a block. "
                               "Default is 0: unconfirmed")
    block_height = Column(Integer, index=True, doc="Number of block this transaction is included in")
    block_hash = Column(String(64), index=True, doc="Transaction is included in block with this hash")
    network_name = Column(String(20), doc="Blockchain network name of this transaction")
    fee = Column(Integer, doc="Transaction fee")
    raw = Column(Text(),
                 doc="Raw transaction hexadecimal string. Transaction is included in raw format on the blockchain")
    nodes = relationship("dbCacheTransactionNode", cascade="all,delete",
                         doc="List of all inputs and outputs as dbCacheTransactionNode objects")
    order_n = Column(Integer, doc='Order of transaction in block')


class dbCacheAddress(Base):
    """
    Address Cache Table

    Stores transactions and unspent outputs (UTXO's) per address

    """
    __tablename__ = 'cache_address'
    address = Column(String(255), primary_key=True, doc="Address string base32 or base58 encoded")
    network_name = Column(String(20), doc="Blockchain network name of this transaction")
    balance = Column(Numeric(25, 0, asdecimal=False), default=0, doc="Total balance of UTXO's linked to this key")
    last_block = Column(Integer, doc="Number of last updated block")


class dbCacheVars(Base):
    """
    Table to store various blockchain related variables
    """
    __tablename__ = 'cache_variables'
    varname = Column(String(50), primary_key=True, doc="Variable unique name")
    network_name = Column(String(20), primary_key=True, doc="Blockchain network name of this transaction")
    value = Column(String(255), doc="Value of variable")
    type = Column(String(20), doc="Type of variable: int, string or float")
    expires = Column(DateTime, doc="Datetime value when variable expires")


if __name__ == '__main__':
    DbInit()
