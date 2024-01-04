# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    Unit Tests for Database
#    © 2019 December - 1200 Web Development <http://1200wd.com/>
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

import unittest
from tests.db_0_4_10 import DbInit as DbInitOld
from bitcoinlib.db import *


DATABASEFILE_UNITTESTS = os.path.join(str(BCL_DATABASE_DIR), 'bitcoinlib.unittest.sqlite')


class TestDb(unittest.TestCase):

    def test_database_upgrade(self):
        if os.path.isfile(DATABASEFILE_UNITTESTS):
            os.remove(DATABASEFILE_UNITTESTS)
        dbold = DbInitOld(DATABASEFILE_UNITTESTS)

        self.assertFalse('latest_txid' in dbold.engine.execute("SELECT * FROM keys").keys())
        self.assertFalse('address' in dbold.engine.execute("SELECT * FROM transaction_inputs").keys())
        version_db = dbold.session.query(DbConfig.value).filter_by(variable='version').scalar()
        self.assertEqual(version_db, '0.4.10')

        db_update(dbold, version_db, '0.4.11')
        self.assertTrue('latest_txid' in dbold.engine.execute("SELECT * FROM keys").keys())
        version_db = dbold.session.query(DbConfig.value).filter_by(variable='version').scalar()
        self.assertEqual(version_db, '0.4.11')

        db_update(dbold, version_db, '0.4.12')
        self.assertTrue('address' in dbold.engine.execute("SELECT * FROM transaction_inputs").keys())
        version_db = dbold.session.query(DbConfig.value).filter_by(variable='version').scalar()
        self.assertEqual(version_db, '0.4.12')


if __name__ == '__main__':
    unittest.main()
