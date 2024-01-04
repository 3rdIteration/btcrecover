# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#
#    EXAMPLES - Use bitcoind as service provider
#
#    © 2018 March - 1200 Web Development <http://1200wd.com/>
#

from pprint import pprint
from bitcoinlib.transactions import *
from bitcoinlib.services.bitcoind import BitcoindClient

# Provide a connection URL to your bitcoind instance, or leave empty to search service on localhost
# Connection URL Example:
#   http://user:password@server_url:18332 (use port 8332 for mainnet)
base_url = ''
bdc = BitcoindClient(base_url=base_url)

# Deserialize and verify a transaction
txid = 'd323c517751b118984bb3f709d762cd17e55326f2bcb4e8b82a9145b361a6ff2'
rt = bdc.getrawtransaction(txid)
print("Raw: %s" % rt)
t = Transaction.import_raw(rt)
pprint(t.as_dict())
print("Verified: %s" % t.verify())

# Deserialize transactions in latest block with bitcoind client
MAX_TRANSACTIONS_VIEW = 100
error_count = 0
if MAX_TRANSACTIONS_VIEW:
    print("\n=== DESERIALIZE LAST BLOCKS TRANSACTIONS ===")
    blockhash = bdc.proxy.getbestblockhash()
    bestblock = bdc.proxy.getblock(blockhash)
    print('... %d transactions found' % len(bestblock['tx']))
    ci = 0
    ct = len(bestblock['tx'])
    for txid in bestblock['tx']:
        ci += 1
        print("\n[%d/%d] Deserialize txid %s" % (ci, ct, txid))
        rt = bdc.getrawtransaction(txid)
        print("Raw: %s" % rt)
        t = Transaction.import_raw(rt)
        pprint(t.as_dict())
        try:
            print("Verified: %s" % t.verify())
        except TransactionError as Err:
            print("Verification Error:", Err)
        if ci > MAX_TRANSACTIONS_VIEW:
            break
    print("===   %d raw transactions deserialised   ===" %
          (ct if ct < MAX_TRANSACTIONS_VIEW else MAX_TRANSACTIONS_VIEW))
    print("===   errorcount %d" % error_count)
    print("===   D O N E   ===")

    # Deserialize transactions in the bitcoind mempool client
    print("\n=== DESERIALIZE MEMPOOL TRANSACTIONS ===")
    newtxs = bdc.proxy.getrawmempool()
    ci = 0
    ct = len(newtxs)
    print("Found %d transactions in mempool" % len(newtxs))
    for txid in newtxs:
        ci += 1
        print("[%d/%d] Deserialize txid %s" % (ci, ct, txid))
        try:
            rt = bdc.getrawtransaction(txid)
            print("- raw %s" % rt)
            t = Transaction.import_raw(rt)
            pprint(t.as_dict())
        except Exception as e:
            print("Error when importing raw transaction %d, error %s", (txid, e))
            error_count += 1
        if ci > MAX_TRANSACTIONS_VIEW:
            break
    print("===   %d mempool transactions deserialised   ===" %
          (ct if ct < MAX_TRANSACTIONS_VIEW else MAX_TRANSACTIONS_VIEW))
    print("===   errorcount %d" % error_count)
    print("===   D O N E   ===")
