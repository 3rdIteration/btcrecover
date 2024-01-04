# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#
#    EXAMPLES - Deserialize and Verify all transactions from the latest block
#    Just use for testing and experimenting, this library is not optimized for blockchain parsing!
#
#    © 2018 October - 1200 Web Development <http://1200wd.com/>
#

from bitcoinlib.services.services import *
from bitcoinlib.services.bitcoind import *
from pprint import pprint


bdc = BitcoindClient()

# Check bitcoind connection
pprint(bdc.proxy.getnetworkinfo())

# Get latest block
latest_block_hash = bdc.proxy.getbestblockhash()
print("Getting latest block with hash %s" % latest_block_hash)
latest_block = bdc.proxy.getblock(latest_block_hash)
transactions = latest_block['tx']
print("Found %d transactions" % len(transactions))

srv = Service(network='bitcoin')

MAX_TRANSACTIONS = 100
count = 0
count_segwit = 0
for txid in transactions[:MAX_TRANSACTIONS]:
    print("\n=== Deserialize transaction #%d (segwit %d) ===" % (count, count_segwit))
    count += 1
    t = srv.gettransaction(txid)
    t.verify()
    t.info()
    if t.witness_type != 'legacy':
        count_segwit += 1
    if not t.verified:
        input("Transaction could not be verified, press any key to continue")
