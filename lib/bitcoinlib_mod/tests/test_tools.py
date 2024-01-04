# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    Unit Tests for Bitcoinlib Tools
#    © 2018 May - 1200 Web Development <http://1200wd.com/>
#

import os
import sys
import unittest
from subprocess import Popen, PIPE

try:
    import mysql.connector
    import psycopg2
    from parameterized import parameterized_class
    from psycopg2 import sql
    from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
except ImportError:
    pass  # Only necessary when mysql or postgres is used

from bitcoinlib.main import UNITTESTS_FULL_DATABASE_TEST
from bitcoinlib.db import BCL_DATABASE_DIR
from bitcoinlib.encoding import normalize_string

SQLITE_DATABASE_FILE = os.path.join(str(BCL_DATABASE_DIR), 'bitcoinlib.unittest.sqlite')
DATABASE_NAME = 'bitcoinlib_unittest'


def init_sqlite(_):
    if os.path.isfile(SQLITE_DATABASE_FILE):
        os.remove(SQLITE_DATABASE_FILE)


def init_postgresql(_):
    con = psycopg2.connect(user='postgres', host='localhost', password='postgres')
    con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cur = con.cursor()
    cur.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(
        sql.Identifier(DATABASE_NAME))
    )
    cur.execute(sql.SQL("CREATE DATABASE {}").format(
        sql.Identifier(DATABASE_NAME))
    )
    cur.close()
    con.close()


def init_mysql(_):
    con = mysql.connector.connect(user='root', host='localhost')
    cur = con.cursor()
    cur.execute("DROP DATABASE IF EXISTS {}".format(DATABASE_NAME))
    cur.execute("CREATE DATABASE {}".format(DATABASE_NAME))
    con.commit()
    cur.close()
    con.close()

db_uris = (('sqlite:///' + SQLITE_DATABASE_FILE, init_sqlite),)
if UNITTESTS_FULL_DATABASE_TEST:
    db_uris += (
        ('mysql://root@localhost:3306/' + DATABASE_NAME, init_mysql),
        ('postgresql://postgres:postgres@localhost:5432/' + DATABASE_NAME, init_postgresql),
    )


@parameterized_class(('DATABASE_URI', 'init_fn'), db_uris)
class TestToolsCommandLineWallet(unittest.TestCase):

    def setUp(self):
        self.init_fn()
        self.python_executable = sys.executable
        self.clw_executable = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                            '../bitcoinlib/tools/clw.py'))

    def test_tools_clw_create_wallet(self):
        cmd_wlt_create = '%s %s test --passphrase "emotion camp sponsor curious bacon squeeze bean world ' \
                         'actual chicken obscure spray" -r -d %s' % \
                         (self.python_executable, self.clw_executable, self.DATABASE_URI)
        cmd_wlt_delete = "%s %s test --wallet-remove -d %s" % \
                         (self.python_executable, self.clw_executable, self.DATABASE_URI)
        output_wlt_create = "14guS7uQpEbgf1e8TDo1zTEURJW3NGPc9E"
        output_wlt_delete = "Wallet test has been removed"

        process = Popen(cmd_wlt_create, stdin=PIPE, stdout=PIPE, shell=True)
        poutput = process.communicate(input=b'y')
        self.assertIn(output_wlt_create, normalize_string(poutput[0]))
        process = Popen(cmd_wlt_delete, stdin=PIPE, stdout=PIPE, shell=True)
        poutput = process.communicate(input=b'test')
        self.assertIn(output_wlt_delete, normalize_string(poutput[0]))

    def test_tools_clw_create_multisig_wallet(self):
        key_list = [
            'tprv8ZgxMBicQKsPd1Q44tfDiZC98iYouKRC2CzjT3HGt1yYw2zuX2awTotzGAZQEAU9bi2M5MCj8iedP9MREPjUgpDEBwBgGi2C8eK'
            '5zNYeiX8',
            'tprv8ZgxMBicQKsPeUbMS6kswJc11zgVEXUnUZuGo3bF6bBrAg1ieFfUdPc9UHqbD5HcXizThrcKike1c4z6xHrz6MWGwy8L6YKVbgJ'
            'MeQHdWDp'
        ]
        cmd_wlt_create = "%s %s testms -m 2 2 %s -r -n testnet -d %s" % \
                         (self.python_executable, self.clw_executable, ' '.join(key_list), self.DATABASE_URI)
        cmd_wlt_delete = "%s %s testms --wallet-remove -d %s" % \
                         (self.python_executable, self.clw_executable, self.DATABASE_URI)
        output_wlt_create = "2NBrLTapyFqU4Wo29xG4QeEt8kn38KVWRR"
        output_wlt_delete = "Wallet testms has been removed"

        process = Popen(cmd_wlt_create, stdin=PIPE, stdout=PIPE, shell=True)
        poutput = process.communicate(input=b'y')
        self.assertIn(output_wlt_create, normalize_string(poutput[0]))
        process = Popen(cmd_wlt_delete, stdin=PIPE, stdout=PIPE, shell=True)
        poutput = process.communicate(input=b'testms')
        self.assertIn(output_wlt_delete, normalize_string(poutput[0]))

    def test_tools_clw_create_multisig_wallet_one_key(self):
        key_list = [
            'tprv8ZgxMBicQKsPd1Q44tfDiZC98iYouKRC2CzjT3HGt1yYw2zuX2awTotzGAZQEAU9bi2M5MCj8iedP9MREPjUgpDEBwBgGi2C8eK'
            '5zNYeiX8'
        ]
        cmd_wlt_create = "%s %s testms1 -m 2 2 %s -r -n testnet -d %s" % \
                         (self.python_executable, self.clw_executable, ' '.join(key_list), self.DATABASE_URI)
        cmd_wlt_delete = "%s %s testms1 --wallet-remove -d %s" % \
                         (self.python_executable, self.clw_executable, self.DATABASE_URI)
        output_wlt_create = "if you understood and wrote down your key: Receive address:"
        output_wlt_delete = "Wallet testms1 has been removed"

        process = Popen(cmd_wlt_create, stdin=PIPE, stdout=PIPE, shell=True)
        poutput = process.communicate(input=b'y\nyes')
        self.assertIn(output_wlt_create, normalize_string(poutput[0]))
        process = Popen(cmd_wlt_delete, stdin=PIPE, stdout=PIPE, shell=True)
        poutput = process.communicate(input=b'testms1')
        self.assertIn(output_wlt_delete, normalize_string(poutput[0]))

    def test_tools_clw_create_multisig_wallet_error(self):
        cmd_wlt_create = "%s %s testms2 -m 2 a -d %s" % \
                         (self.python_executable, self.clw_executable, self.DATABASE_URI)
        output_wlt_create = "Number of signatures required (second argument) must be a numeric value"
        process = Popen(cmd_wlt_create, stdin=PIPE, stdout=PIPE, shell=True)
        poutput = process.communicate(input=b'y')
        self.assertIn(output_wlt_create, normalize_string(poutput[0]))

    def test_tools_clw_transaction_with_script(self):
        cmd_wlt_create = '%s %s test2 --passphrase "emotion camp sponsor curious bacon squeeze bean world ' \
                         'actual chicken obscure spray" -r -n bitcoinlib_test -d %s' % \
                         (self.python_executable, self.clw_executable, self.DATABASE_URI)
        cmd_wlt_update = "%s %s test2 -d %s" % \
                         (self.python_executable, self.clw_executable, self.DATABASE_URI)
        cmd_wlt_transaction = "%s %s test2 -d %s -t 21HVXMEdxdgjNzgfERhPwX4okXZ8WijHkvu 50000000 -f 100000 -p" % \
                              (self.python_executable, self.clw_executable, self.DATABASE_URI)
        cmd_wlt_delete = "%s %s test2 --wallet-remove -d %s" % \
                         (self.python_executable, self.clw_executable, self.DATABASE_URI)
        output_wlt_create = "21GPfxeCbBunsVev4uS6exPhqE8brPs1ZDF"
        output_wlt_transaction = 'Transaction pushed to network'
        output_wlt_delete = "Wallet test2 has been removed"

        process = Popen(cmd_wlt_create, stdin=PIPE, stdout=PIPE, shell=True)
        poutput = process.communicate(input=b'y')
        self.assertIn(output_wlt_create, normalize_string(poutput[0]))

        process = Popen(cmd_wlt_update, stdout=PIPE, shell=True)
        process.communicate()

        process = Popen(cmd_wlt_transaction, stdout=PIPE, shell=True)
        poutput = process.communicate()
        self.assertIn(output_wlt_transaction, normalize_string(poutput[0]))

        process = Popen(cmd_wlt_delete, stdin=PIPE, stdout=PIPE, shell=True)
        poutput = process.communicate(input=b'test2')
        self.assertIn(output_wlt_delete, normalize_string(poutput[0]))

    def test_tools_clw_create_litecoin_segwit_wallet(self):
        cmd_wlt_create = '%s %s ltcsw --passphrase "lounge chief tip frog camera build trouble write end ' \
                         'sword order share" -r -d %s -y segwit -n litecoin' % \
                         (self.python_executable, self.clw_executable, self.DATABASE_URI)
        cmd_wlt_delete = "%s %s ltcsw --wallet-remove -d %s" % \
                         (self.python_executable, self.clw_executable, self.DATABASE_URI)
        output_wlt_create = "ltc1qgc7c2z56rr4lftg0fr8tgh2vknqc3yuydedu6m"
        output_wlt_delete = "Wallet ltcsw has been removed"

        process = Popen(cmd_wlt_create, stdin=PIPE, stdout=PIPE, shell=True)
        poutput = process.communicate(input=b'y')
        self.assertIn(output_wlt_create, normalize_string(poutput[0]))
        process = Popen(cmd_wlt_delete, stdin=PIPE, stdout=PIPE, shell=True)
        poutput = process.communicate(input=b'ltcsw')
        self.assertIn(output_wlt_delete, normalize_string(poutput[0]))

    def test_tools_clw_create_multisig_wallet_p2sh_segwit(self):
        key_list = [
            'YprvANkMzkodih9AKnvFGXTm8Fid3b6wDWoRq5GxmoFb8Rwoa4YsJvoHtbd6jFhCiCzG8Da3bFbkBeQq7Lz1YDAqufAZB5paBaZTEv8'
            'A1Yxfi5R',
            'YprvANkMzkodih9AJ6UamjW9rTWqBDMm5Be3M2cKybivd6V1MSMnKnGDkUXsVkz1hPKKNPFRZS9fFchRGKTgKdyTsppMuHjQQMVFBLY'
            'Ghp5MTsC',
            'YprvANkMzkodih9AKQ8evAkiDWCzpQsU6N1uasNtWznNj44Y2X6FJqkv9wcfavxVEkz9qru7VKRhzmQXqy562b9Tk4JGdsaVazByzmX'
            '7FW6wpKW'
        ]
        cmd_wlt_create = "%s %s testms-p2sh-segwit -m 3 2 %s -r -y p2sh-segwit -d %s" % \
                         (self.python_executable, self.clw_executable, ' '.join(key_list), self.DATABASE_URI)
        cmd_wlt_delete = "%s %s testms-p2sh-segwit --wallet-remove -d %s" % \
                         (self.python_executable, self.clw_executable, self.DATABASE_URI)
        output_wlt_create = "3MtNi5U2cjs3EcPizzjarSz87pU9DTANge"
        output_wlt_delete = "Wallet testms-p2sh-segwit has been removed"

        process = Popen(cmd_wlt_create, stdin=PIPE, stdout=PIPE, shell=True)
        poutput = process.communicate(input=b'y')
        self.assertIn(output_wlt_create, normalize_string(poutput[0]))
        process = Popen(cmd_wlt_delete, stdin=PIPE, stdout=PIPE, shell=True)
        poutput = process.communicate(input=b'testms-p2sh-segwit')
        self.assertIn(output_wlt_delete, normalize_string(poutput[0]))


if __name__ == '__main__':
    unittest.main()
