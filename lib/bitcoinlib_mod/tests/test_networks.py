# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    Unit Tests for Bitcoinlib Network Class
#    © 2018 August - 1200 Web Development <http://1200wd.com/>
#

import unittest
from bitcoinlib.networks import *


class TestNetworks(unittest.TestCase):

    def test_networks_prefix_wif_network_by_value(self):
        self.assertEqual(network_by_value('prefix_wif', '80'), ['bitcoin'])
        self.assertEqual(network_by_value('prefix_wif', 10), [])

    def test_networks_prefix_bech32_network_by_value(self):
        self.assertEqual(network_by_value('prefix_bech32', 'tb'), ['testnet'])

    def test_networks_prefix_bech32_network_by_value_sorted(self):
        self.assertEqual(network_by_value('prefix_bech32', 'ltc'), ['litecoin', 'litecoin_legacy'])

    def test_networks_prefix_hdkey_wif(self):
        network = Network('bitcoin')
        self.assertEqual(network.wif_prefix(is_private=True), b'\x04\x88\xad\xe4')

    def test_networks_print_value(self):
        network = Network('dash')
        self.assertEqual(network.print_value(10000), '0.00010000 DASH')

    def test_networks_network_value_for(self):
        prefixes = network_values_for('prefix_wif')
        expected_prefixes = [b'\xb0', b'\xef', b'\x99', b'\x80', b'\xcc']
        for expected in expected_prefixes:
            self.assertIn(expected, prefixes)
        self.assertEqual(network_values_for('denominator')[0], 1e-8)
        self.assertIn('BTC', network_values_for('currency_code'))

    def test_network_defined(self):
        self.assertTrue(network_defined('bitcoin'))
        self.assertFalse(network_defined('bitcoiiin'))
        self.assertRaisesRegexp(NetworkError, "Network bitcoiin not found in network definitions", Network, 'bitcoiin')

    def test_wif_prefix_search(self):
        exp_dict = {
            'is_private': True,
            'multisig': False,
            'network': 'bitcoin',
            'prefix': '0488ADE4',
            'prefix_str': 'xprv',
            'script_type': 'p2pkh',
            'witness_type': 'legacy'}
        self.assertEqual(wif_prefix_search('0488ADE4', network='bitcoin', multisig=False)[0], exp_dict)
        self.assertEqual(wif_prefix_search('lettrythisstrangestring', network='bitcoin', multisig=False), [])


if __name__ == '__main__':
    unittest.main()
