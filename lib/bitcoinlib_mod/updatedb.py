# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    Update database
#    © 2017 November - 1200 Web Development <http://1200wd.com/>
#
#    This script creates a database with latest structure and copies only wallets and keys from old database
#    Transactions, UTXO's and values are not copied, but can be recreated with utxos_update and transaction_update
#    methods of the Wallet class.
#

import os
import sys
import argparse
from copy import deepcopy
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from shutil import move
from bitcoinlib.main import DEFAULT_DATABASE, BCL_DATABASE_DIR, BITCOINLIB_VERSION
from bitcoinlib.db import Base, DbWallet, DbKey, DbKeyMultisigChildren, DbConfig
try:
    input = raw_input
except NameError:
    pass

print("Database should update automatically when using BitcoinLib. If automatic update fails you can run this script. "
      "!!! After everything is backuped !!!")

def parse_args():
    parser = argparse.ArgumentParser(description='BitcoinLib Database update script')
    parser.add_argument('--database', '-d', default='sqlite:///' + DEFAULT_DATABASE,
                        help="Name of specific database file to use",)
    pa = parser.parse_args()
    return pa


args = parse_args()
database_file = args.database
if not os.path.isfile(database_file):
    database_file = os.path.join(BCL_DATABASE_DIR, database_file)
database_backup_file = os.path.join(BCL_DATABASE_DIR, "%s.backup-%s" %
                                    (database_file, datetime.now().strftime("%Y%m%d-%I:%M")))

print("\nWallet and Key data will be copied to new database. Transaction data will NOT be copied")
print("Updating database file: %s" % database_file)
print("Old database will be backed up to %s" % database_backup_file)

if input("Type 'y' or 'Y' to continue or any other key to cancel: ") not in ['y', 'Y']:
    print("Aborted by user")
    sys.exit()


# Move old database to temporary database
move(database_file, database_backup_file)

try:
    # Create new database
    engine = create_engine('sqlite:///%s' % database_file)
    Base.metadata.create_all(engine)

    # Copy wallets and keys to new database
    Session = sessionmaker(bind=engine)
    session = Session()

    engine_backup = create_engine('sqlite:///%s' % database_backup_file)
    Session_backup = sessionmaker(bind=engine_backup)
    session_backup = Session_backup()

    wallets = session_backup.execute("SELECT * FROM wallets")
    for wallet in wallets:
        fields = dict(wallet)

        # Update, rename
        try:
            del(fields['balance'])
        except:
            pass
        if fields['scheme'] == 'bip44':
            fields['scheme'] = 'bip32'
        elif fields['scheme'] == 'multisig':
            fields['scheme'] = 'bip32'
            fields['multisig'] = True

        # Remove unused fields
        db_field_names = [field[0] for field in DbWallet.__table__.columns.items()]
        fields_copy = deepcopy(fields)
        for f in fields_copy:
            if f not in db_field_names:
                del(fields[f])

        session.add(DbWallet(**fields))
    session.commit()

    keys = session_backup.execute("SELECT * FROM keys")
    for key in keys:
        fields = dict(key)

        # Update for 'key' field
        if 'key' in fields:
            if fields['is_private']:
                fields['private'] = fields['key']
            else:
                fields['public'] = fields['key']
            del(fields['key'])

        # Remove unused fields
        db_field_names = [field[0] for field in DbKey.__table__.columns.items()]
        fields_copy = deepcopy(fields)
        for f in fields_copy:
            if f not in db_field_names:
                del(fields[f])

        fields['used'] = False  # To force rescan of all keys
        session.add(DbKey(**fields))
    session.commit()

    keysubs = session_backup.execute("SELECT * FROM key_multisig_children")
    for keysub in keysubs:
        fields = dict(keysub)
        session.add(DbKeyMultisigChildren(**fields))
    session.commit()

    session.query(DbConfig).filter(DbConfig.variable == 'version').update({DbConfig.value: BITCOINLIB_VERSION})
    session.add(DbConfig(variable='version', value=BITCOINLIB_VERSION))
    session.add(DbConfig(variable='upgrade_date', value=str(datetime.now())))
    session.commit()

    print("Database %s has been updated, backup of old database has been created at %s" %
          (database_file, database_backup_file))

except Exception as e:
    # If ANYTHING goes wrong move back to old database
    print(e)
    print("Errors occured, database not updated")
    move(database_backup_file, database_file)
