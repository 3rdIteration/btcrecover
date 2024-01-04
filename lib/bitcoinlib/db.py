# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    DataBase - SqlAlchemy database definitions
#    © 2016 - 2023 May - 1200 Web Development <http://1200wd.com/>
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
from sqlalchemy import (Column, Integer, BigInteger, UniqueConstraint, CheckConstraint, String, Boolean, Sequence,
                        ForeignKey, DateTime, LargeBinary, TypeDecorator)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker, relationship, close_all_sessions
from urllib.parse import urlparse
from bitcoinlib.main import *
from bitcoinlib.encoding import aes_encrypt, aes_decrypt

_logger = logging.getLogger(__name__)
Base = declarative_base()


@compiles(LargeBinary, "mysql")
def compile_largebinary_mysql(type_, compiler, **kwargs):
    length = type_.length
    element = "BLOB" if not length else "VARBINARY(%d)" % length
    return element


class Db:
    """
    Bitcoinlib Database object used by Service() and HDWallet() class. Initialize database and open session when
    creating database object.

    Create new database if is doesn't exist yet

    """
    def __init__(self, db_uri=None, password=None):
        if db_uri is None:
            db_uri = DEFAULT_DATABASE
        self.o = urlparse(db_uri)
        if not self.o.scheme or \
                len(self.o.scheme) < 2:  # Dirty hack to avoid issues with urlparse on Windows confusing drive with scheme
            if password:
                # Warning: This requires the pysqlcipher3 module
                db_uri = 'sqlite+pysqlcipher://:%s@/%s?cipher=aes-256-cfb&kdf_iter=64000' % (password, db_uri)
            else:
                db_uri = 'sqlite:///%s' % db_uri
        elif password:
            raise NotImplementedError("Password protection is only available for sqlite databases at the moment")

        if db_uri.startswith("sqlite") and ALLOW_DATABASE_THREADS:
            db_uri += "&" if "?" in db_uri else "?"
            db_uri += "check_same_thread=False"
        if self.o.scheme == 'mysql':
            db_uri += "&" if "?" in db_uri else "?"
            db_uri += 'binary_prefix=true'
        self.engine = create_engine(db_uri, isolation_level='READ UNCOMMITTED')

        Session = sessionmaker(bind=self.engine)
        Base.metadata.create_all(self.engine)
        self._import_config_data(Session)
        self.session = Session()

        _logger.info("Using database: %s://%s:%s/%s" % (self.o.scheme or '', self.o.hostname or '',
                                                        self.o.port or '', self.o.path or ''))
        self.db_uri = db_uri

        # VERIFY AND UPDATE DATABASE
        # Just a very simple database update script, without any external libraries for now
        #
        version_db = self.session.query(DbConfig.value).filter_by(variable='version').scalar()
        if version_db[:3] == '0.4' and BITCOINLIB_VERSION[:3] >= '0.5':
            raise ValueError("Old database version found (<0.4.19). Can not convert to >0.5 version database "
                             "automatically, use updatedb.py tool to update")
        try:
            if BITCOINLIB_VERSION != version_db:
                _logger.warning("BitcoinLib database (%s) is from different version then library code (%s). "
                                "Let's try to update database." % (version_db, BITCOINLIB_VERSION))
                db_update(self, version_db, BITCOINLIB_VERSION)
        except Exception as e:
            _logger.warning("Error when verifying version or updating database: %s" % e)

    def drop_db(self, yes_i_am_sure=False):
        if yes_i_am_sure:
            self.session.commit()
            self.session.close_all()
            close_all_sessions()
            Base.metadata.drop_all(self.engine)

    @staticmethod
    def _import_config_data(ses):
        session = ses()
        installation_date = session.query(DbConfig.value).filter_by(variable='installation_date').scalar()
        if not installation_date:
            session.merge(DbConfig(variable='version', value=BITCOINLIB_VERSION))
            session.merge(DbConfig(variable='installation_date', value=str(datetime.now())))
            url = ''
            try:
                url = str(session.bind.url)
            except Exception:
                pass
            session.merge(DbConfig(variable='installation_url', value=url))
            session.commit()
        session.close()


def add_column(engine, table_name, column):
    """
    Used to add new column to database with migration and update scripts

    :param engine:
    :param table_name:
    :param column:
    :return:
    """
    column_name = column.compile(dialect=engine.dialect)
    column_type = column.type.compile(engine.dialect)
    engine.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table_name, column_name, column_type))


class EncryptedBinary(TypeDecorator):
    """
    FieldType for encrypted Binary storage using EAS encryption
    """

    impl = LargeBinary
    cache_ok = True
    key = None
    if DATABASE_ENCRYPTION_ENABLED:
        if not DB_FIELD_ENCRYPTION_KEY:
            _logger.warning("Database encryption is enabled but value DB_FIELD_ENCRYPTION_KEY not found in "
                            "environment. Please supply 32 bytes key as hexadecimal string.")
        else:
            key = bytes().fromhex(DB_FIELD_ENCRYPTION_KEY)

    def process_bind_param(self, value, dialect):
        if value is None or self.key is None or not DATABASE_ENCRYPTION_ENABLED:
            return value
        return aes_encrypt(value, self.key)

    def process_result_value(self, value, dialect):
        if value is None or self.key is None or not DATABASE_ENCRYPTION_ENABLED:
            return value
        return aes_decrypt(value, self.key)


class EncryptedString(TypeDecorator):
    """
    FieldType for encrypted String storage using EAS encryption
    """

    impl = String
    cache_ok = True
    key = None
    if DATABASE_ENCRYPTION_ENABLED:
        if not DB_FIELD_ENCRYPTION_KEY:
            _logger.warning("Database encryption is enabled but value DB_FIELD_ENCRYPTION_KEY not found in "
                            "environment. Please supply 32 bytes key as hexadecimal string.")
        else:
            impl = LargeBinary
            key = bytes().fromhex(DB_FIELD_ENCRYPTION_KEY)

    def process_bind_param(self, value, dialect):
        if value is None or self.key is None or not DATABASE_ENCRYPTION_ENABLED:
            return value
        if not isinstance(value, bytes):
            value = bytes(value, 'utf8')
        return aes_encrypt(value, self.key)

    def process_result_value(self, value, dialect):
        if value is None or self.key is None or not DATABASE_ENCRYPTION_ENABLED:
            return value
        return aes_decrypt(value, self.key).decode('utf8')


class DbConfig(Base):
    """
    BitcoinLib configuration variables

    """
    __tablename__ = 'config'
    variable = Column(String(30), primary_key=True)
    value = Column(String(255))


class DbWallet(Base):
    """
    Database definitions for wallets in Sqlalchemy format

    Contains one or more keys.

    """
    __tablename__ = 'wallets'
    id = Column(Integer, Sequence('wallet_id_seq'), primary_key=True, doc="Unique wallet ID")
    name = Column(String(80), unique=True, doc="Unique wallet name")
    owner = Column(String(50), doc="Wallet owner")
    network_name = Column(String(20), ForeignKey('networks.name'), doc="Name of network, i.e.: bitcoin, litecoin")
    network = relationship("DbNetwork", doc="Link to DbNetwork object")
    purpose = Column(Integer,
                     doc="Wallet purpose ID. BIP-44 purpose field, indicating which key-scheme is used default is 44")
    scheme = Column(String(25), doc="Key structure type, can be BIP-32 or single")
    witness_type = Column(String(20), default='legacy',
                          doc="Wallet witness type. Can be 'legacy', 'segwit' or 'p2sh-segwit'. Default is legacy.")
    encoding = Column(String(15), default='base58',
                      doc="Default encoding to use for address generation, i.e. base58 or bech32. Default is base58.")
    main_key_id = Column(Integer,
                         doc="Masterkey ID for this wallet. All other keys are derived from the masterkey in a "
                             "HD wallet bip32 wallet")
    keys = relationship("DbKey", back_populates="wallet", doc="Link to keys (DbKeys objects) in this wallet")
    transactions = relationship("DbTransaction", back_populates="wallet",
                                doc="Link to transaction (DbTransactions) in this wallet")
    multisig_n_required = Column(Integer, default=1, doc="Number of required signature for multisig, "
                                                         "only used for multisignature master key")
    sort_keys = Column(Boolean, default=False, doc="Sort keys in multisig wallet")
    parent_id = Column(Integer, ForeignKey('wallets.id'), doc="Wallet ID of parent wallet, used in multisig wallets")
    children = relationship("DbWallet", lazy="joined", join_depth=2,
                            doc="Wallet IDs of children wallets, used in multisig wallets")
    multisig = Column(Boolean, default=True, doc="Indicates if wallet is a multisig wallet. Default is True")
    cosigner_id = Column(Integer,
                         doc="ID of cosigner of this wallet. Used in multisig wallets to differentiate between "
                             "different wallets")
    key_path = Column(String(100),
                      doc="Key path structure used in this wallet. Key path for multisig wallet, use to create "
                          "your own non-standard key path. Key path must follow the following rules: "
                          "* Path start with masterkey (m) and end with change / address_index "
                          "* If accounts are used, the account level must be 3. I.e.: m/purpose/coin_type/account/ "
                          "* All keys must be hardened, except for change, address_index or cosigner_id "
                          " Max length of path is 8 levels")
    default_account_id = Column(Integer, doc="ID of default account for this wallet if multiple accounts are used")

    __table_args__ = (
        CheckConstraint(scheme.in_(['single', 'bip32']), name='constraint_allowed_schemes'),
        CheckConstraint(encoding.in_(['base58', 'bech32']), name='constraint_default_address_encodings_allowed'),
        CheckConstraint(witness_type.in_(['legacy', 'segwit', 'p2sh-segwit']), name='wallet_constraint_allowed_types'),
    )

    def __repr__(self):
        return "<DbWallet(name='%s', network='%s'>" % (self.name, self.network_name)


class DbKeyMultisigChildren(Base):
    """
    Use many-to-many relationship for multisig keys. A multisig keys contains 2 or more child keys
    and a child key can be used in more then one multisig key.

    """
    __tablename__ = 'key_multisig_children'

    parent_id = Column(Integer, ForeignKey('keys.id'), primary_key=True)
    child_id = Column(Integer, ForeignKey('keys.id'), primary_key=True)
    key_order = Column(Integer, Sequence('key_multisig_children_id_seq'))


class DbKey(Base):
    """
    Database definitions for keys in Sqlalchemy format

    Part of a wallet, and used by transactions

    """
    __tablename__ = 'keys'
    id = Column(Integer, Sequence('key_id_seq'), primary_key=True, doc="Unique Key ID")
    parent_id = Column(Integer, Sequence('parent_id_seq'), doc="Parent Key ID. Used in HD wallets")
    name = Column(String(80), index=True, doc="Key name string")
    account_id = Column(Integer, index=True, doc="ID of account if key is part of a HD structure")
    depth = Column(Integer,
                   doc="Depth of key if it is part of a HD structure. Depth=0 means masterkey, "
                       "depth=1 are the masterkeys children.")
    change = Column(Integer, doc="Change or normal address: Normal=0, Change=1")
    address_index = Column(BigInteger, doc="Index of address in HD key structure address level")
    public = Column(LargeBinary(128), index=True, doc="Bytes representation of public key")
    private = Column(EncryptedBinary(48), doc="Bytes representation of private key")
    wif = Column(EncryptedString(255), index=True, doc="Public or private WIF (Wallet Import Format) representation")
    compressed = Column(Boolean, default=True, doc="Is key compressed or not. Default is True")
    key_type = Column(String(10), default='bip32', doc="Type of key: single, bip32 or multisig. Default is bip32")
    address = Column(String(255), index=True,
                     doc="Address representation of key. An cryptocurrency address is a hash of the public key")
    cosigner_id = Column(Integer, doc="ID of cosigner, used if key is part of HD Wallet")
    encoding = Column(String(15), default='base58', doc='Encoding used to represent address: base58 or bech32')
    purpose = Column(Integer, default=44, doc="Purpose ID, default is 44")
    is_private = Column(Boolean, doc="Is key private or not?")
    path = Column(String(100), doc="String of BIP-32 key path")
    wallet_id = Column(Integer, ForeignKey('wallets.id'), index=True, doc="Wallet ID which contains this key")
    wallet = relationship("DbWallet", back_populates="keys", doc="Related Wallet object")
    transaction_inputs = relationship("DbTransactionInput", cascade="all,delete", back_populates="key",
                                      doc="All DbTransactionInput objects this key is part of")
    transaction_outputs = relationship("DbTransactionOutput", cascade="all,delete", back_populates="key",
                                       doc="All DbTransactionOutput objects this key is part of")
    balance = Column(BigInteger, default=0, doc="Total balance of UTXO's linked to this key")
    used = Column(Boolean, default=False, doc="Has key already been used on the blockchain in as input or output? "
                                              "Default is False")
    network_name = Column(String(20), ForeignKey('networks.name'),
                          doc="Name of key network, i.e. bitcoin, litecoin, dash")
    latest_txid = Column(LargeBinary(32), doc="TxId of latest transaction downloaded from the blockchain")
    network = relationship("DbNetwork", doc="DbNetwork object for this key")
    multisig_parents = relationship("DbKeyMultisigChildren", backref='child_key',
                                    primaryjoin=id == DbKeyMultisigChildren.child_id,
                                    doc="List of parent keys")
    multisig_children = relationship("DbKeyMultisigChildren", backref='parent_key',
                                     order_by="DbKeyMultisigChildren.key_order",
                                     primaryjoin=id == DbKeyMultisigChildren.parent_id,
                                     doc="List of children keys")

    __table_args__ = (
        CheckConstraint(key_type.in_(['single', 'bip32', 'multisig']), name='constraint_key_types_allowed'),
        CheckConstraint(encoding.in_(['base58', 'bech32']), name='constraint_address_encodings_allowed'),
        UniqueConstraint('wallet_id', 'public', name='constraint_wallet_pubkey_unique'),
        UniqueConstraint('wallet_id', 'private', name='constraint_wallet_privkey_unique'),
        UniqueConstraint('wallet_id', 'wif', name='constraint_wallet_wif_unique'),
        UniqueConstraint('wallet_id', 'address', name='constraint_wallet_address_unique'),
    )

    def __repr__(self):
        return "<DbKey(id='%s', name='%s', wif='%s'>" % (self.id, self.name, self.wif)


class DbNetwork(Base):
    """
    Database definitions for networks in Sqlalchemy format

    Most network settings and variables can be found outside the database in the libraries configurations settings.
    Use the bitcoinlib/data/networks.json file to view and manage settings.

    """
    __tablename__ = 'networks'
    name = Column(String(20), unique=True, primary_key=True, doc="Network name, i.e.: bitcoin, litecoin, dash")
    description = Column(String(50))

    def __repr__(self):
        return "<DbNetwork(name='%s', description='%s'>" % (self.name, self.description)


# class TransactionType(enum.Enum):
#     """
#     Incoming or Outgoing transaction Enumeration
#     """
#     incoming = 1
#     outgoing = 2


class DbTransaction(Base):
    """
    Database definitions for transactions in Sqlalchemy format

    Refers to 1 or more keys which can be part of a wallet

    """
    __tablename__ = 'transactions'
    id = Column(Integer, Sequence('transaction_id_seq'), primary_key=True,
                doc="Unique transaction index for internal usage")
    txid = Column(LargeBinary(32), index=True, doc="Bytes representation of transaction ID")
    wallet_id = Column(Integer, ForeignKey('wallets.id'), index=True,
                       doc="ID of wallet which contains this transaction")
    account_id = Column(Integer, index=True, doc="ID of account")
    wallet = relationship("DbWallet", back_populates="transactions",
                          doc="Link to Wallet object which contains this transaction")
    witness_type = Column(String(20), default='legacy', doc="Is this a legacy or segwit transaction?")
    version = Column(BigInteger, default=1,
                     doc="Tranaction version. Default is 1 but some wallets use another version number")
    locktime = Column(BigInteger, default=0,
                      doc="Transaction level locktime. Locks the transaction until a specified block "
                          "(value from 1 to 5 million) or until a certain time (Timestamp in seconds after 1-jan-1970)."
                          " Default value is 0 for transactions without locktime")
    date = Column(DateTime, default=datetime.utcnow,
                  doc="Date when transaction was confirmed and included in a block. "
                      "Or when it was created when transaction is not send or confirmed")
    coinbase = Column(Boolean, default=False, doc="Is True when this is a coinbase transaction, default is False")
    confirmations = Column(Integer, default=0,
                           doc="Number of confirmation when this transaction is included in a block. "
                               "Default is 0: unconfirmed")
    block_height = Column(Integer, index=True, doc="Number of block this transaction is included in")
    size = Column(Integer, doc="Size of the raw transaction in bytes")
    fee = Column(BigInteger, doc="Transaction fee")
    inputs = relationship("DbTransactionInput", cascade="all,delete",
                          doc="List of all inputs as DbTransactionInput objects")
    outputs = relationship("DbTransactionOutput", cascade="all,delete",
                           doc="List of all outputs as DbTransactionOutput objects")
    status = Column(String(20), default='new',
                    doc="Current status of transaction, can be one of the following: new', "
                        "'unconfirmed', 'confirmed'. Default is 'new'")
    is_complete = Column(Boolean, default=True, doc="Allow to store incomplete transactions, for instance if not all "
                                                    "inputs are known when retrieving UTXO's")
    input_total = Column(BigInteger, default=0,
                         doc="Total value of the inputs of this transaction. Input total = Output total + fee. "
                             "Default is 0")
    output_total = Column(BigInteger, default=0,
                          doc="Total value of the outputs of this transaction. Output total = Input total - fee")
    network_name = Column(String(20), ForeignKey('networks.name'), doc="Blockchain network name of this transaction")
    network = relationship("DbNetwork", doc="Link to DbNetwork object")
    raw = Column(LargeBinary,
                 doc="Raw transaction hexadecimal string. Transaction is included in raw format on the blockchain")
    verified = Column(Boolean, default=False, doc="Is transaction verified. Default is False")

    __table_args__ = (
        UniqueConstraint('wallet_id', 'txid', name='constraint_wallet_transaction_hash_unique'),
        CheckConstraint(status.in_(['new', 'unconfirmed', 'confirmed']),
                        name='constraint_status_allowed'),
        CheckConstraint(witness_type.in_(['legacy', 'segwit']), name='transaction_constraint_allowed_types'),
    )

    def __repr__(self):
        return "<DbTransaction(txid='%s', confirmations='%s')>" % (self.txid, self.confirmations)


class DbTransactionInput(Base):
    """
    Transaction Input Table

    Relates to Transaction table and Key table

    """
    __tablename__ = 'transaction_inputs'
    transaction_id = Column(Integer, ForeignKey('transactions.id'), primary_key=True,
                            doc="Input is part of transaction with this ID")
    transaction = relationship("DbTransaction", back_populates='inputs', doc="Related DbTransaction object")
    index_n = Column(Integer, primary_key=True, doc="Index number of transaction input")
    key_id = Column(Integer, ForeignKey('keys.id'), index=True, doc="ID of key used in this input")
    key = relationship("DbKey", back_populates="transaction_inputs", doc="Related DbKey object")
    address = Column(String(255),
                     doc="Address string of input, used if no key is associated. "
                         "An cryptocurrency address is a hash of the public key or a redeemscript")
    witnesses = Column(LargeBinary, doc="Witnesses (signatures) used in Segwit transaction inputs")
    witness_type = Column(String(20), default='legacy',
                          doc="Type of transaction, can be legacy, segwit or p2sh-segwit. Default is legacy")
    prev_txid = Column(LargeBinary(32),
                       doc="Transaction hash of previous transaction. Previous unspent outputs (UTXO) is spent "
                           "in this input")
    output_n = Column(BigInteger, doc="Output_n of previous transaction output that is spent in this input")
    script = Column(LargeBinary, doc="Unlocking script to unlock previous locked output")
    script_type = Column(String(20), default='sig_pubkey',
                         doc="Unlocking script type. Can be 'coinbase', 'sig_pubkey', 'p2sh_multisig', 'signature', "
                             "'unknown', 'p2sh_p2wpkh' or 'p2sh_p2wsh'. Default is sig_pubkey")
    sequence = Column(BigInteger, doc="Transaction sequence number. Used for timelock transaction inputs")
    value = Column(BigInteger, default=0, doc="Value of transaction input")
    double_spend = Column(Boolean, default=False,
                          doc="Indicates if a service provider tagged this transaction as double spend")

    __table_args__ = (CheckConstraint(witness_type.in_(['legacy', 'segwit', 'p2sh-segwit']),
                                      name='transactioninput_constraint_allowed_types'),
                      UniqueConstraint('transaction_id', 'index_n', name='constraint_transaction_input_unique'))


class DbTransactionOutput(Base):
    """
    Transaction Output Table

    Relates to Transaction and Key table

    When spent is False output is considered an UTXO

    """
    __tablename__ = 'transaction_outputs'
    transaction_id = Column(Integer, ForeignKey('transactions.id'), primary_key=True,
                            doc="Transaction ID of parent transaction")
    transaction = relationship("DbTransaction", back_populates='outputs',
                               doc="Link to transaction object")
    output_n = Column(Integer, primary_key=True, doc="Sequence number of transaction output")
    key_id = Column(Integer, ForeignKey('keys.id'), index=True, doc="ID of key used in this transaction output")
    key = relationship("DbKey", back_populates="transaction_outputs", doc="List of DbKey object used in this output")
    address = Column(String(255),
                     doc="Address string of output, used if no key is associated. "
                         "An cryptocurrency address is a hash of the public key or a redeemscript")
    script = Column(LargeBinary, doc="Locking script which locks transaction output")
    script_type = Column(String(20), default='p2pkh',
                         doc="Locking script type. Can be one of these values: 'p2pkh', 'multisig', 'p2sh', 'p2pk', "
                             "'nulldata', 'unknown', 'p2wpkh', 'p2wsh', 'p2tr'. Default is p2pkh")
    value = Column(BigInteger, default=0, doc="Total transaction output value")
    spent = Column(Boolean, default=False, doc="Indicated if output is already spent in another transaction")
    spending_txid = Column(LargeBinary(32), doc="Transaction hash of input which spends this output")
    spending_index_n = Column(Integer, doc="Index number of transaction input which spends this output")

    __table_args__ = (UniqueConstraint('transaction_id', 'output_n', name='constraint_transaction_output_unique'),)


def db_update_version_id(db, version):
    _logger.info("Updated BitcoinLib database to version %s" % version)
    db.session.query(DbConfig).filter(DbConfig.variable == 'version').update(
        {DbConfig.value: version})
    db.session.commit()
    return version


def db_update(db, version_db, code_version=BITCOINLIB_VERSION):
    # Database changes from version 0.5+
    #
    if version_db <= '0.6.3' and code_version > '0.6.3':
        # Example: column = Column('latest_txid', String(32))
        column = Column('witnesses', LargeBinary, doc="Witnesses (signatures) used in Segwit transaction inputs")
        add_column(db.engine, 'transaction_inputs', column)
        # version_db = db_update_version_id(db, '0.6.4')
    version_db = db_update_version_id(db, code_version)
    return version_db
