# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#
#    EXAMPLES - Network class
#
#    © 2017 - 2019 February - 1200 Web Development <http://1200wd.com/>
#

from bitcoinlib.networks import *

#
# Network examples
#

network = Network('bitcoin')
print("\n=== Get all WIF prefixes ===")
print("WIF Prefixes: %s" % network_values_for('prefix_wif'))

print("\n=== Get all HDkey private prefixes ===")
print("HDkey private prefixes: %s" % network_values_for('prefix_wif'))

print("\n=== Get network(s) for WIF prefix B0 ===")
print("WIF Prefixes: %s" % network_by_value('prefix_wif', 'B0'))

print("\n=== Get HD key private prefix for current network ===")
print("self.prefix_hdkey_private: %s" % network.wif_prefix())

print("\n=== Network parameters ===")
for k in network.__dir__():
    if k[:1] != '_':
        v = eval('network.%s' % k)
        if not callable(v):
            print("%25s: %s" % (k, v))

wif = 'Zpub74CSuvLPQxWkdW7bivQAhomXZTzbE8quAakKRg1C3x7uDcCCeh7zPp1tZrtJrscihJRASZWjZQ7nPQj1SHTn8gkzAHPZL3dC' \
      'MbMQLFwMKVV'
print("\n=== Search for WIF prefix ===")
print("WIF: %s" % wif)
print(wif_prefix_search(wif))
