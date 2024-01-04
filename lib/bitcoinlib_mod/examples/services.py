# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#
#    EXAMPLES - Creating and Using Cryptocurrency Wallets
#
#    © 2017 November - 1200 Web Development <http://1200wd.com/>
#

from pprint import pprint
from bitcoinlib.services.services import *


# Tests for specific provider
srv = Service(network='bitcoin', providers=['coinfees'])
print("Estimated bitcoin transaction fee:", srv.estimatefee(3))

# Get Balance and UTXO's for given bitcoin testnet3 addresses
address = 'mqR6Dndmez8WMpb1hBJbGbrQ2mpAU73hQC'
srv = Service(network='testnet', min_providers=5)
print("Balance of address %s: %s" % (address, srv.getbalance(address)))
print("\nAll results as dict:")
pprint(srv.results)
print("\nUTXOs list:")
pprint(srv.getutxos(address))

# GET Raw Transaction data for given Transaction ID
t = 'd3c7fbd3a4ca1cca789560348a86facb3bb21dcd75ed38e85235fb6a32802955'
print("\nGET Raw Transaction:")
pprint(Service(network='testnet', min_providers=2).getrawtransaction(t))

# SEND Raw Transaction data (UTXO's already spent, so should give 'missing inputs' error)
rt = '010000000108004b4c0394a211d4ec0d344b70bf1e3b1ce1731d11d1d30279ab0c0f6d9fd7000000006c493046022100ab18a72f7' \
     '87e4c8ea5d2f983b99df28d27e13482b91fd6d48701c055af92f525022100d1c26b8a779896a53a026248388896501e724e46407f' \
     '14a4a1b6478d3293da24012103e428723c145e61c35c070da86faadaf0fab21939223a5e6ce3e1cfd76bad133dffffffff0240420' \
     'f00000000001976a914bbaeed8a02f64c9d40462d323d379b8f27ad9f1a88ac905d1818000000001976a914046858970a72d33817' \
     '474c0e24e530d78716fc9c88ac00000000'
print("\nSEND Raw Transaction:")
srv = Service(network='testnet')
if srv.sendrawtransaction(rt):
    print("Transaction send, result: ")
    pprint(srv.results)
else:
    print("Transaction could not be send, errors:")
    pprint(srv.errors)

# Get current estimated networks fees
print("\nCurrent estimated networks fees:")
srv = Service(min_providers=10)
srv.estimatefee(5)
pprint(srv.results)

# Test address with huge number of UTXO's
# addresslst = '16ZbpCEyVVdqu8VycWR8thUL2Rd9JnjzHt'
# addresslst = '1KwA4fS4uVuCNjCtMivE7m5ATbv93UZg8V'
# srv = Service(network='bitcoin', min_providers=10)
# utxos = srv.getutxos(addresslst)
# results = srv.results
# for res in results:
#     print(res, len(results[res]))

# Get transactions by hash
srv = Service()
res = srv.gettransaction('2ae77540ec3ef7b5001de90194ed0ade7522239fe0fc57c12c772d67274e2700')
pprint(res)
