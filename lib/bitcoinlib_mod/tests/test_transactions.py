# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    Unit Tests for Transaction Class
#    © 2019 November - 1200 Web Development <http://1200wd.com/>
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
from bitcoinlib.transactions import *
from bitcoinlib.keys import HDKey, BKeyError
from tests.test_custom import CustomAssertions


class TestTransactionInputs(unittest.TestCase):
    def test_transaction_input_add_str(self):
        ph = "81b4c832d70cb56ff957589752eb4125a4cab78a25a8fc52d6a09e5bd4404d48"
        ti = Input(ph, 0)
        self.assertEqual(ph, to_hexstring(ti.prev_hash))
        self.assertEqual(repr(ti), "<Input(prev_hash='81b4c832d70cb56ff957589752eb4125a4cab78a25a8fc52d6a09e5bd4404d"
                                   "48', output_n=0, address='', index_n=0, type='sig_pubkey')>")

    def test_transaction_input_add_bytes(self):
        ph = "81b4c832d70cb56ff957589752eb4125a4cab78a25a8fc52d6a09e5bd4404d48"
        ti = Input(prev_hash=to_bytes(ph), output_n=0)
        self.assertEqual(ph, to_hexstring(ti.prev_hash))

    def test_transaction_input_add_bytearray(self):
        ph = "81b4c832d70cb56ff957589752eb4125a4cab78a25a8fc52d6a09e5bd4404d48"
        ti = Input(prev_hash=to_bytearray(ph), output_n=0)
        self.assertEqual(ph, to_hexstring(ti.prev_hash))

    def test_transaction_input_add_scriptsig(self):
        prev_hash = b"\xe3>\xbd\x17\x93\x8b\xc0\x13\xc6(\x95\x89*\xacT\xdf?[\xce\x96\xe4K\x89I\x94\x92ut\x1b\x14'\xe5"
        output_index = b'\x00\x00\x00\x00'
        unlock_scr = \
            b"G0D\x02 l\xa2\x8f{\xaf\xdde\xbd\xfc\x0f\xbd\x88\xf5\xa5\xb0\x03i\x91'\xca\xf0\xff\xf6\xe6U5\xd7\xf11" \
            b"\x15,\x03\x02 \x16\x170?c\x8e\x08\x94\x7f\x18i~\xdc\xb3\xa7\xa5:\xe6m\xf9O&)\xdb\x98\xdc\x0c\xc5\x07k4" \
            b"\xb7\x01!\x020\x9a\x19i\x19\xcf\xf1\xd1\x87T'\x1b\xe7\xeeT\xd1\xb3\x7fAL\xbb)+U\xd7\xed\x1f\r\xc8 \x9d" \
            b"\x13"
        ti = Input(prev_hash, output_index, unlocking_script=unlock_scr)
        expected_dict = {
            'output_n': 0,
            'script': '47304402206ca28f7bafdd65bdfc0fbd88f5a5b003699127caf0fff6e65535d7f131152c0302201617'
                      '303f638e08947f18697edcb3a7a53ae66df94f2629db98dc0cc5076b34b7012102309a196919cff1d1'
                      '8754271be7ee54d1b37f414cbb292b55d7ed1f0dc8209d13',
            'sequence': 4294967295,
            'prev_hash': 'e33ebd17938bc013c62895892aac54df3f5bce96e44b8949949275741b1427e5',
            'index_n': 0,
            'address': '1L1Gohs21Xg54MvHuBMbmxhZSNCa1d3Cc2',
            'script_type': 'sig_pubkey'
        }
        ti_dict = {key: ti.as_dict()[key] for key in
                   ['output_n', 'script', 'sequence', 'prev_hash', 'index_n', 'address', 'script_type']}
        self.assertDictEqual(expected_dict, ti_dict)

    def test_transaction_input_add_coinbase(self):
        ti = Input(b'\0' * 32, 0)
        self.assertEqual('coinbase', ti.script_type)

    def test_transaction_input_add_public_key(self):
        ph = 'f2b3eb2deb76566e7324307cd47c35eeb88413f971d88519859b1834307ecfec'
        k = Key(0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725, compressed=False)
        ti = Input(prev_hash=ph, output_n=1, keys=k.public(), compressed=k.compressed)
        self.assertEqual('16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM', ti.keys[0].address())

    def test_transaction_input_with_pkh(self):
        ki = Key('cTuDU2P6AhB72ZrhHRnFTcZRoHdnoWkp7sSMPCBnrMG23nRNnjUX', network='dash_testnet', compressed=False)
        prev_tx = "5b5903a9e5f5a1fee68fbd597085969a36789dc5b5e397dad76a57c3fb7c232a"
        output_n = 0
        ki_public_hash = ki.hash160
        ti = Input(prev_hash=prev_tx, output_n=output_n, public_hash=ki_public_hash, network='dash_testnet',
                   compressed=False)
        self.assertEqual(ti.address, 'yWut2kHY6nXbpgqatMCNkwsxoYHcpWeF6Q')

    def test_transaction_input_locking_script(self):
        ph = "81b4c832d70cb56ff957589752eb4125a4cab78a25a8fc52d6a09e5bd4404d48"
        ti = Input(ph, 0, unlocking_script_unsigned='76a91423e102597c4a99516f851406f935a6e634dbccec88ac')
        self.assertEqual(ti.address, '14GiCdJHj3bznWpcocjcu9ByCmDPEhEoP8')

    def test_transaction_compressed_mixup_error(self):
        k = HDKey(compressed=False)
        ph = "81b4c832d70cb56ff957589752eb4125a4cab78a25a8fc52d6a09e5bd4404d48"
        ti = Input(ph, 0, keys=k, compressed=True)
        self.assertFalse(ti.compressed)


class TestTransactionOutputs(unittest.TestCase):

    def test_transaction_output_add_address(self):
        to = Output(1000, '12ooWd8Xag7hsgP9PBPnmyGe36VeUrpMSH')
        self.assertEqual(b'v\xa9\x14\x13\xd2\x15\xd2\x12\xcdQ\x88\xae\x02\xc5c_\xaa\xbd\xc4\xd7\xd4\xec\x91\x88\xac',
                         to.lock_script)
        self.assertEqual(repr(to), '<Output(value=1000, address=12ooWd8Xag7hsgP9PBPnmyGe36VeUrpMSH, type=p2pkh)>')

    def test_transaction_output_add_address_p2sh(self):
        to = Output(1000, '2N5WPJ2qPzVpy5LeE576JCwZfWg1ikjUxdK', network='testnet')
        self.assertEqual(b'\xa9\x14\x86\x7f\x84`u\x87\xf7\xc2\x05G@\xc6\xca\xe0\x92\x98\xcc\xbc\xd5(\x87',
                         to.lock_script)

    def test_transaction_output_add_public_key(self):
        to = Output(1000000000, public_key='0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470'
                                           '243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6')
        self.assertEqual(b"v\xa9\x14\x01\tfw`\x06\x95=UgC\x9e^9\xf8j\r';\xee\x88\xac",
                         to.lock_script)

    def test_transaction_output_add_public_key_hash(self):
        to = Output(1000, public_hash='010966776006953d5567439e5e39f86a0d273bee')
        self.assertEqual(b"v\xa9\x14\x01\tfw`\x06\x95=UgC\x9e^9\xf8j\r';\xee\x88\xac",
                         to.lock_script)

    def test_transaction_output_add_script(self):
        to = Output(1000, lock_script='76a91423e102597c4a99516f851406f935a6e634dbccec88ac')
        self.assertEqual('14GiCdJHj3bznWpcocjcu9ByCmDPEhEoP8', to.address)


class TestTransactions(unittest.TestCase):
    def setUp(self):
        workdir = os.path.dirname(__file__)
        with open('%s/%s' % (workdir, 'transactions_raw.json'), 'r') as f:
            d = json.load(f)
        self.rawtxs = d['transactions']

    def test_transactions_deserialize_raw(self):
        for r in self.rawtxs:
            # print("Deserialize %s" % r[0], r[1])
            t = Transaction.import_raw(r[1], r[4])
            self.assertEqual(len(t.inputs), r[2], msg="Incorrect numbers of inputs for tx '%s'" % r[0])
            self.assertEqual(len(t.outputs), r[3], msg="Incorrect numbers of outputs for tx '%s'" % r[0])

    def test_transactions_deserialize_raw_unicode(self):
        rawtx = u'01000000012ba87637d74080d041795915f843484523f7693ac1f1b359771b751acd2fef79010000006a4730440220722' \
                u'7634b962914c3310c6f71fb37c25ad64f239aead11a1a1e2de8b6d95d4de6022072d3841de897be38bd9ae0067e059bd7' \
                u'ad6947ae3731d97823801c09e00a70be0121033ef5447f54712d6a1aba7e77ad9f09ab77c21c84d1811a1b82a96fa08d9' \
                u'733deffffffff02be9d9600000000001976a914b66e314587c282d5ce290918228e390c0279884688ace280590b0b0000' \
                u'001976a914f2ea76adc2345f3591ce997def9043fbe68ecc1a88ac00000000'
        self.assertEqual('1P9RQEr2XeE3PEb44ZE35sfZRRW1JHU8qx',
                         Transaction.import_raw(rawtx).as_dict()['outputs'][1]['address'])

    def test_transactions_deserialize_raw_bytearray(self):
        rawtx = bytearray(b'0100000001685c7c35aabe690cc99f947a8172ad075d4401448a212b9f26607d6ec5530915010000006a4730'
                          b'440220337117278ee2fc7ae222ec1547b3a40fa39a05f91c1e19db60060541c4b3d6e4022020188e1d5d843c'
                          b'045ddac78c42ed9ff6a1078414d15a9f065495628fde9d1e55012102d04293c65effbea9d61727374612820d'
                          b'192cd6d04f106a62c6a6768719de41dcffffffff026804ab01000000001976a914cf75d22e78c86e2e3d29f7'
                          b'a772f8ffd62391190388ac442d0304000000001976a9145b92b92ddd598d2d4977b3c4e5f552332aed743188'
                          b'ac00000000')
        self.assertEqual('19MCFyVmyEhFjYNS8aKJT454jm4YZQjbqm',
                         Transaction.import_raw(rawtx).as_dict()['outputs'][1]['address'])

    def test_transactions_deserialize_p2sh_output(self):
        rawtx = '01000000011a422ceb2104d9c3ace9fcbda16b9a9f12a1a93c389a0740c70c9b56d3a0c7bf00000000fd4501004730440220' \
                '7ed9498344a1ddb6e52d2b3fb270c85ec49527fe7cc0915264aa334a9d61a7770220032cb9d97cec92d027fcf80f0e11fbe7' \
                'f454db77ea49e1efebea725bfb08195e0147304402204acac2c8c9f84b083d2768c358645e0dc56e13fa0eb625b74d1f9e67' \
                'f061fb3f02207eb66aae538afeeaeb2eea96e8863793d3a96232587b440e7453ea8c6316d6de01483045022100d868fe1026' \
                'd496f262e269e2f644f05a84ce13f5e532d6356d901a0d7bd8dc7c0220573717a3bfabc491a2d8a38380a4a2c9d6e709650c' \
                '6624538a2d361bbae0b0fe014c69532103ccf652bab8cf942453d68a2539560e5f267ee01f757395db96eab57bbb888af621' \
                '0272a9d882836778834d454e9293486f2da74ebdce82282bfcfaf2873a95ac2e5d21023c7776e9908983e35e3304c540816f' \
                'ab387523fd7bdce168be7bbfef7afc4c6e53aeffffffff02a08601000000000017a914eb2f6545c638f7ab3897dfeb9e92bb' \
                '8b11b840c687f23a0d000000000017a9145ac6cc10677d242eeb260dae9770221be9c87c8b8700000000'
        t = Transaction.import_raw(rawtx, 'testnet')
        self.assertEqual(t.inputs[0].address, '2N5WPJ2qPzVpy5LeE576JCwZfWg1ikjUxdK')
        self.assertEqual(t.outputs[0].address, '2NEgmZU64NjiZsxPULekrFcqdS7YwvYh24r')
        self.assertEqual(t.outputs[1].address, '2N1XCxDRsyi8so3wr6C5xj5Arcv2wej7znf')

    def test_transactions_deserialize_errors(self):
        rawtx = '01000000000102c114c54564ea09b33c73bfd0237a4d283fe9e73285ad6d34fd3fa42c99f194640300000000ffffffff'
        self.assertRaisesRegexp(TransactionError,
                                'Input transaction hash not found. Probably malformed raw transaction',
                                Transaction.import_raw, rawtx)
        rawtx = '01000000000101c114c54564ea09b33c73bfd0237a4d283fe9e73285ad6d34fd3fa42c99f194640300000000ffffffff0200' \
                'e1f5050000000017a914e10a445f3084bd131394c66bf0023653dcc247ab877cdb3b0300000000220020701a8d401c84fb13' \
                'e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004830450221009c5bd2fa1acb5884fca1612217bd65992c96' \
                'c839accea226a3c59d7cc28779c502202cff98a71d195ab61c08fc126577466bb05ae0bfce5554b59455bd758309d4950148' \
                '3045022100f81ce75339657d31698793e78f475c04fe56bafdb3cfc6e1035846aeeeb98f7902203ad5b1bcb96494457197cb' \
                '3c12b67ddd3cf8127fe054dec971c858252c004bf8016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea36' \
                '8e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5' \
                'ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae000000'
        self.assertRaisesRegexp(TransactionError,
                                'Error when deserializing raw transaction, bytes left for locktime must be 4 not 3',
                                Transaction.import_raw, rawtx)
        rawtx = '01000000000101c114c54564ea09b33c73bfd0237a4d283fe9e73285ad6d34fd3fa42c99f194640300000000ffffffff0200' \
                'e1f5050000000017a914e10a445f3084bd131394c66bf0023653dcc247ab877cdb3b0300000000220020701a8d401c84fb13' \
                'e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004830450221009c5bd2fa1acb5884fca1612217bd65992c96' \
                'c839accea226a3c59d7cc28779c502202cff98a71d195ab61c08fc126577466bb05ae0bfce5554b59455bd758309d4950148' \
                '3045022100f81ce75339657d31698793e78f475c04fe56bafdb3cfc6e1035846aeeeb98f7902203ad5b1bcb96494457197cb' \
                '3c12b67ddd3cf8127fe054dec971c858252c004bf8016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea36' \
                '8e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70f01874496feff2103c96d495bfdd5' \
                'ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000'
        self.assertRaisesRegexp(TransactionError,
                                'Could not parse witnesses in transaction. Multisig redeemscript expected',
                                Transaction.import_raw, rawtx)

    def test_transactions_verify_signature(self):
        for r in self.rawtxs:
            # print("Verify %s" % r[0])
            t = Transaction.import_raw(r[1], r[4])
            if len(t.inputs) < 5:
                self.assertTrue(t.verify(), msg="Can not verify transaction '%s'" % r[0])

    def test_transactions_serialize_raw(self):
        for r in self.rawtxs:
            t = Transaction.import_raw(r[1], r[4])
            self.assertEqual(binascii.hexlify(t.raw()).decode(), r[1],
                             "Deserialize / serialize error in transaction %s" % r[0])

    def test_transactions_sign_1(self):
        pk = Key('cR6pgV8bCweLX1JVN3Q1iqxXvaw4ow9rrp8RenvJcckCMEbZKNtz', network='testnet')  # Private key for import
        inp = Input(prev_hash='d3c7fbd3a4ca1cca789560348a86facb3bb21dcd75ed38e85235fb6a32802955', output_n=1,
                    keys=pk.public(), network='testnet')
        # key for address mkzpsGwaUU7rYzrDZZVXFne7dXEeo6Zpw2
        pubkey = Key('0391634874ffca219ff5633f814f7f013f7385c66c65c8c7d81e7076a5926f1a75', network='testnet')
        out = Output(880000, public_hash=pubkey.hash160, network='testnet')
        t = Transaction([inp], [out], network='testnet')
        t.sign(pk)
        self.assertTrue(t.verify(), msg="Can not verify transaction '%s'")
        self.assertEqual(t.as_dict()['inputs'][0]['address'], 'n3UKaXBRDhTVpkvgRH7eARZFsYE989bHjw')
        self.assertEqual(t.as_dict()['outputs'][0]['address'], 'mkzpsGwaUU7rYzrDZZVXFne7dXEeo6Zpw2')

    def test_transactions_sign_2(self):
        pk = Key('KwbbBb6iz1hGq6dNF9UsHc7cWaXJZfoQGFWeozexqnWA4M7aSwh4')  # Private key for import
        inp = Input(prev_hash='fdaa42051b1fc9226797b2ef9700a7148ee8be9466fc8408379814cb0b1d88e3',
                    output_n=1, keys=pk.public())
        out = Output(95000, address='1K5j3KpsSt2FyumzLmoVjmFWVcpFhXHvNF')
        t = Transaction([inp], [out])
        t.sign(pk)
        self.assertTrue(t.verify(), msg="Can not verify transaction '%s'")

    def test_transactions_multiple_outputs(self):
        t = Transaction()
        t.add_output(2710000, '12ooWd8Xag7hsgP9PBPnmyGe36VeUrpMSH')
        t.add_output(2720000, '1D1gLEHsvjunpJxqjkWcPZqU4QzzRrHDdL')
        t.add_output(2730000, '15pV2dYQAWeahtTVGAzDeX1K1ndqgRU2go')
        t.add_input('82b48b128232256d1d5ce0c6ae7f7897f2b464d44456c25d7cf2be51626530d9', 0)
        self.assertEqual(3, len(t.outputs))

    def test_transactions_sign_multiple_inputs(self):
        # Two private keys with 1 UTXO on the blockchain each
        wif1 = 'xprvA3PZhxgsb5cogy52pm8eJf21gW2epoetxdCZxpmBWddViHmB7wgR4apQVxRHmyngapZ14pBzWSCP6sztWn8EaMmnwZaj' \
               'fs7oS6rZDYdnrwh'
        wif2 = 'xprvA3PZhxgsb5cojKHWdGGFBNut51QbAe5arWb7s7cJ9cT6zThQJFvYKKZDcmFirWJVVHgRYzqLc9XnuDMrP3Qwy8sK8Zu5' \
               'MisgvXVtGdwDhrH'

        # Create inputs with a UTXO with 2 unspent outputs which corresponds to this private keys
        utxo_hash = '0177ac29fa8b2960051321c730c6f15017503aa5b9c1dd2d61e7286e366fbaba'
        pk1 = HDKey(wif1)
        pk2 = HDKey(wif2)
        input1 = Input(prev_hash=utxo_hash, output_n=0, keys=pk1.public_byte, index_n=0)
        input2 = Input(prev_hash=utxo_hash, output_n=1, keys=pk2.public_byte, index_n=1)

        # Create a transaction with 2 inputs, and add 2 outputs below
        osm_address = '1J3pt9koWJZTo2jarg98RL89iJqff9Kobp'
        change_address = '1Ht9iDJ3FjwweQNuj451QVL6RAP5qxadFb'
        output1 = Output(value=900000, address=osm_address)
        output2 = Output(value=150000, address=change_address)
        t = Transaction(inputs=[input1, input2], outputs=[output1, output2])

        # Sign the inputs and verify
        # See txid 1ec28c925df0079ead9976d38165909ccb3580a428ce069ee13e63879df0c2fc
        t.sign(pk1, 0)
        t.sign(pk2.private_byte, 1)
        self.assertTrue(t.verify())

    def test_transactions_estimate_size_p2pkh(self):
        t = Transaction()
        t.add_output(2710000, '12ooWd8Xag7hsgP9PBPnmyGe36VeUrpMSH')
        t.add_output(2720000, '1D1gLEHsvjunpJxqjkWcPZqU4QzzRrHDdL')
        t.add_input('82b48b128232256d1d5ce0c6ae7f7897f2b464d44456c25d7cf2be51626530d9', 0)
        self.assertEqual(t.estimate_size(), 225)

    def test_transactions_estimate_size_nulldata(self):
        t = Transaction()
        lock_script = b'j' + varstr(b'Please leave a message after the beep')
        t.add_output(0, lock_script=lock_script)
        t.add_input('82b48b128232256d1d5ce0c6ae7f7897f2b464d44456c25d7cf2be51626530d9', 0)
        self.assertEqual(t.estimate_size(add_change_output=True), 239)

    def test_transaction_very_large(self):
        rawtx = \
            "01000000c972c418613686d2cc505ebc86e676c0b81619bf718f931491db8bc721c6d25a3d680000008a47304402206ccc63" \
            "5218de7e7c4c50be294ca9c4214f47ac8e365d6f17e9916f2e6c128a1e022048df1d6699fa363b85f0c51940c408bd74f37f" \
            "e35bcab06425339522cfbf28b50141046a11580e919a254797f72a42c52777fef4f7a2e0dbee4eabbb5790c52427f0986cdf" \
            "e390b11d12a79f072389d37fb753222b23c5ccda336995b22de7733b60baffffffffc97a9c71e460e49b7bc54bd3c57966f2" \
            "dc46a9515a605a4dbefc38bfd41ffd7f000000006a47304402205192f9ed6ea4e5117cb0754c38c6ea78b6a1aa25edf6b3a8" \
            "61c203596a8de88702207ff2c0891425016521c237fac54a325d0468bf79e9922ae55dc859833b9af94e01210325b1c99312" \
            "f8a504b2fd321dfeda17ab1da2d19992ddce7c7a6dbf7d2b25617effffffff5a80a26cfeca40b104f67e12c795af2cc74af4" \
            "c60a7af9b9db6e1688a99670aa010000006b483045022100e3efeb99bb2702f818baec5e7f18b7cbd724925c984c278c3477" \
            "f9b8aba54b1e022069dbc00ee96e5abb52197c31f8ae1e6a90272df1066f195b7ccf817f2a7e4855012102935008b57e0721" \
            "ffeea0e5ee6604fdf0ffdf5eb294c8a70a21476d9dcf970cdeffffffffad4c0e2625d4eb404ba31fd85e9d1ccec518878462" \
            "cf07c9050445bfecc379dc010000006a473044022077178b3a23429a868d395ee86d1a941ae6acabbfb30e9a7fb2f9daf782" \
            "c5f8010220437f0d445e5a4267cef3bb5a455359401752f333b246822349c1190237f2eabb012103fd78465f7db610e6d926" \
            "d10d2b8113b4a57dbcd87c4164ed3715409d3435facaffffffffe62719f4cf4499cb971320c0160f85cb2ba5dc24aa143712" \
            "dc41b0c3353bddcd000000006a47304402206258f1664b3efeb00e3a1832967af3023c7d1bbbb6c88da4b21e9fe02c7edc56" \
            "022030d02396bff06254ebb6b24b8a8ae401b198b4a989c45ee5fb8d7664d8f05d2b012103961ddbf735adeaa3eae71be51f" \
            "e0514a9419f2637f1486e90cac737e011612edffffffffd5a19e0a99c2799f895708930e202d4d5bf041b02ad6219ac9ec7f" \
            "4afa7cc4d60e0000006b483045022100da48870c6871d2be19e92a8d862bc7985b413200689587ceec773fcbc0eace9d0220" \
            "7cb096851dacde56d4353dd98046731684d7658ca8a950c7885808ed571a9dc9012103fe19745c983bf3af748ffa988b988e" \
            "8b42f9dff5eff1e432d8d3c7ce08d1fbd3ffffffff3d2f192145077a4ccd26f64011c8847f52be5cbc3979f87bc28fb36420" \
            "e4cb9e2c0000006a47304402202e45b384ec0fb734cc7a8dcf613e44365fd9a2b7f7e1ee80721e4b83e80109c20220496b89" \
            "bfa0cfa5fb7de122f150f8103c597a33adfeef5d65c69d12a5d7b90941012102758998b8e7d703679d4d3df3ba0f5f3d9e3a" \
            "15686a2189d885b3d1c3871a2de7ffffffffa1bdceffc3f8cbb517ac9735db006e8cc2ba23e141a490c4c774362732ed52d6" \
            "370000006b483045022100f572a13b5aec72ef6456cf12d580bae5cc16e8798010db2373f64f27c8d8d1950220410d493697" \
            "f44c2f1aa6e1a65c57d2b85aba03420f6ecb50fb2eaa3864857840012102668b744af319e5eb573517f38f692f340cb81680" \
            "786d9453f47a32ca88e38916ffffffff2d745050903feb670d347b4267c869dbedfd926ab3c076e5ea6faf50912e8b270000" \
            "00006a4730440220385537bbdae1e0bdeda10f528897ab65feb9258ddbccf904ccc12dde15f984ce0220551eae7a07748b9b" \
            "ffaa64bef81ea5b1026c233a20e95645c7a5dd0683c5c1370121024e5c3c969a1b4794b96544d2077ccaf19297218ee9a703" \
            "c536302a92048a6bccffffffffbcc8e24e1631a7e205be89425dac6fe1e0952b5c78cca7b3a78172561f029d25000000006b" \
            "483045022100d95606ea86de36ccbf0becf723b433d6327b3bdeb0eedf1c391526a64f208e5c022062ad1549484f0d611b3c" \
            "6970680dc88a97321873a9cf44052fe71a4f40186b4d012102d899378ed629a5b91a7c6d9cfb6ccfe69f81db55fa12241ea1" \
            "9dde6344a74b00ffffffff4eec122e5f76e8af7ecf0039ee5a28262bf42addee4653e378ec60302c689c87070000006b4830" \
            "45022100be8f3ca46fcd71d61f72d90aa9bfe7df3ff844c0e233e1e281a73ddaca29e4a20220503f085815ae4c367cb9d3e3" \
            "d2b75795e78d77a0a49a1b86a9b28edaef7477d8012102f141cb162d27fc9291bf9dfbe238da52934743093f358ff9e0cd90" \
            "7ba1d275d4ffffffffda178ed8bf509cb0944acb59a2e495f979b4bd7ee3b1f1fa02f1499aaf31c565030000006a47304402" \
            "203cdc4a465b7e9a03cebd23a00e98cea7d23ade706f6aca3565917b775ffeb4a3022001a1bff5d3b03108373d99e1d3f1f2" \
            "35924988a0a03dd7fa6aef24e9c7099e2e01210325eccf6727ca37de6cda85aeb046017021067f1d4800201c8bfcef666c53" \
            "00c2ffffffffa2a5248bf2b3c54a2dfced81ee05c2adab67237715d85bd2562e752be5a5018b010000006b483045022100c6" \
            "8b30e1996b45095928221c82cdd2def49e5af725a6b933c8b0304bfe4d4ab70220268cd9835ca77451a353c1dac581fc8596" \
            "f79185738d414866b2c4ba3bc1a36b012102a46b4061982eb84cd0cee210bc8a287c67d92835b16efa95af27916050f4bf91" \
            "ffffffff527f349d73784270aec12d1427c1f8ddb60340022e11db992dd0ce5504f74033110000006b483045022100ced168" \
            "eda4560a73f5452ff844107fbc8f69e216f7d921cb3ad539c970bb83d10220047d409fad85d7b615bd5cfbc87af1912dbdc8" \
            "7024e652f03f8b80373a74ed7101210338087a2d765219fd67d6b22d6fac8b7e6ce18a58410efb0ab6347cfdc2b056d1ffff" \
            "ffff2a18bcee08c6af4bf58ab3b54b05af2a922f4fb2dfcc02c975360772244da000000000006b48304502210091c907b760" \
            "7b0782d159301dfa1cc59313311035d401229d2bf36309f8e9b0b802201b1ec6fee83c9ecceeb57c37bc24941b0501be3691" \
            "e8dd883cd8878212f92637012102d9a995eb27f8e25a58a44e764b2f668a8860cacdf227d1d57f3f4653dbe3bef8ffffffff" \
            "c36f16768f4eea815c99b2101d53df939228a923578f4378943c1068b33d62f2010000006b483045022100d67aa721ac2001" \
            "a487a90dc3f2b4c515196459b0dcfe11504b9e16c2293c685002204cdfdffb7e7ad2b90a8d7b1fc054506f33614cec4af79f" \
            "bd595cf671221af51901210380bbf01f728a88d1c3575dbbcf9dc2ba5bc12586ffe3062ce6575e438359d254ffffffffda17" \
            "8ed8bf509cb0944acb59a2e495f979b4bd7ee3b1f1fa02f1499aaf31c565020000006a473044022012cd5757262c5f8fecb1" \
            "d46640c6326b442ba3acd84c2ece6bb509182da8cdff02203df7cb3c91eb331e6bbafc134b9544719acc5f6c1adb944d224b" \
            "6b30deb3f31b01210351648059dc4006ff016615791a4af405bfe1f7898cda7613a79467bb8b85d8ffffffffffda5c942e5d" \
            "926609d9d78f565bdd9f5fccdd2ef1493d6243b9ece3919821661d160000006b4830450221009c2fcadfc5de64afc74c212f" \
            "760f25deb6a7a02d97661e8f94344c1ab12622d302206aa11c34c8c330db400ee831c94c4f4a147f9e6bb3b20d6e3ffb941e" \
            "c974f5860121032f99cdc63014048d4e1eecf8712fc1aaad4c3a6cdce805da908b3692e16ac309ffffffff7d06bf5432c905" \
            "9f2435b56e4d3a68cf45bf5188c98c19bbd745a710f096f851010000006b483045022100966229cbf16c0e203bfdc0748cb8" \
            "0990d1278883d00f5bfcb73c570973014ab70220268739f545108c8564c5344d359f4b740c551656e3ac9061a9f32d64c4d4" \
            "6a6d01210239016502d38c52e253399aa4696596b44cc0ce89dc842e5beb829d339866789effffffff0c4bbed5006534b097" \
            "e98f9166748317b8a2069c8aba863ed8672de4e99b08f2000000006a47304402200dc609485087d9edc0220172dd29e13f39" \
            "cec2330b230b63177a9a8fb98ac34602204d8cfd5a2ea9738417fb0398ee48a75e53aaeeeadf51d378fe4a170ef699996801" \
            "2102edfa89d7a2cb0f20de43c048ed4df798fe7a02e30fce1f5ef5f4c95e3907256bffffffffbb4860714e126397a470689b" \
            "24eb02c49519e353195279eefc2dddd17ddf6fdb180000006b48304502210082f138c81ca38ec80880afdb99cdf1a91bef11" \
            "c51af1e2b4b121325a1fe22d1c02206f23dd8fd9ef71b3703a03edfc5f0f0499f373f18ae569b30ef7c587c0e25c7f012102" \
            "1c6a44b531044738cb505f31752b368fc7cbe45873ea4fc39d25beb7db98caafffffffffbb4860714e126397a470689b24eb" \
            "02c49519e353195279eefc2dddd17ddf6fdb2a0000006a47304402202c69ec3315fe496d638a700ec1cecbc3b90fe5588312" \
            "1e582ee42d738688cfc202203da04fa4196ce61e2a388887a7d58931a23ef701e975cfd8f5cd49f6c0cdbd4f012103aeb9ab" \
            "7af1da0e5668e35a57c9c366810ce2aa2f32aca322fdef11dbe990115affffffff3d2f192145077a4ccd26f64011c8847f52" \
            "be5cbc3979f87bc28fb36420e4cb9e1f0000006b483045022100dd2d01c5695c01239ead4c8f7ec3db87a8210b1e0198dc88" \
            "03659d08562b531c022008b4b8c9a48e939b0d28323e479d8ea5a95fe4bb611eec5e6b111de9b74bd2a0012102b1cd8f0bcf" \
            "f6d78240a837962be811461d7913d646a7755bfe3f33caa49a8a44ffffffffc9bf82060fb814ad23dfd6992f9637d122940d" \
            "db9ee48806818ceb2e7e2ae036000000006a473044022062f8cf460f313123f8519436aa14134fe3f7abd077b0354c3bc5b3" \
            "59dbf4ad4502204ca6481f1d17a6d26d2138047d0d36c38735a40cd52e2b370d8837fbfbe2234d012102fa9205a16d61c2c4" \
            "4af1f74085bdcdd976f15c25616927967f7afd5c5422c837ffffffffcf0ca7939670f9c3b048be46b04e90bff8092bc5c88b" \
            "fb649282b2ebb353e913010000006b483045022100ba98b0b0c567c38185cfaaf3ffabf93f3570836260234bfd4507ae3135" \
            "f11ae802200ce7331f72256b7609ec4ab138839c477292338ea0236dbddee063640cedb66c01210387fb23120e9685ff630d" \
            "7c837c342be9299c900759d1d85f4691bc900aebc3b5ffffffffcaa6e063ace12fd2f12c663a08ace9ec5f8a362a94dec444" \
            "9d24cc049b201f93190000006a47304402203f4e9496c716f780f48f1ba2f98bda4b066f4183d2fbb57d763a0bf8c87a4870" \
            "0220282cbdff83ee6cdb85bbcbc81e050f0a6e59c61f5b63dca708416ada472e630f012102999d10009aaf2f3c7a89d4554a" \
            "8e297663f86a0bab5f83a1d49bad9d22f40d7cffffffff5f7c87debcf0b94f75bdd5cc4ce69b95038e2cda811c81de51219e" \
            "0e0498abb6630000006a473044022068ce82e623c8dbc259cd6b4683aa49b2ba9ecf52db984e6174288c0cd8afe270022064" \
            "737ad9708c243e3fbcbc64c21090fda1a55da5d20c700bd6ccc6572601ff71012103410b2a42c149296f1a24ca96e3395bae" \
            "f46bafca4235e23267d624c47291ac0affffffff6f9af01e5bb5e8a4de075b5565010d97ba50eb77cca7b4493138261ee92d" \
            "68e9010000006b483045022100f749afaed3f93a52dea7b565c885949af8d4d04912e466092d751cb5adbdd22602207fb5f5" \
            "fe7022ff29c67b1560994b4c03efea7851d828d18130cf59817d8aa48c0121024a67495815b21e46e6545e19dee93c559c3a" \
            "5a7991d0df5a0fc44d630432e6ebffffffff4c7bdb3bce9f0368a4ed987f5ee0e30a33deb0e1244b427fb1de2606edf59886" \
            "010000006b483045022100a6cae24c55f593238bec8641157bb14199038cf178773dbaa54a7875561481d102202ea7bd924b" \
            "2085e7f2a7433ff3bfd39cf894f3232f2ca4fa5246379f6f47fb510121035797b05898f9f4d40bb969fc5951958f328ab8bd" \
            "a784b726b99759037b3d1a77ffffffffd983a82b0ac4ba506567c23569d879ce20a9d147661cc7b22d6c871c6f0d7c5d0a00" \
            "00006a473044022016f76eff94232eb90a94e61dd1adc20c12c2aa33d27d98c8d1315266f40decbe02200517bb9d6cc95e1b" \
            "69b6555d85b9e4054fddd4e4ed3f9cd67cb027cd2dbe1f67012102e2c847071fc7a1374ff6ff8ea5334dfca6f5bcd701e969" \
            "5dfc966efebf1cea7bffffffff53f171de0b46d1ab5a45d462f82496b710d8617059e663d47568078defcfb9ee010000006b" \
            "483045022100ebb2d0f8326b24ecd3a8150d02610f111a1f69e68e11bbb70b5a4be48dd39cfe022069fa63001b4d6c8e99fa" \
            "333244feee058f167b54b1fdd1f7ec6664cca6b0f03f012103aa2bc558ce9edc9ed98f6863eb5eebd162b858acaf97ee7a43" \
            "0f57b39a0b9043ffffffff21627ed487f9bb0dab30f269151b6f80ee58f83c7d9097eecc28f7348f0c87ec0e0000006a4730" \
            "4402205785d4a592646167c1a168d5ac8fd20c62db9ea1eb3a0a803a4fe3b3e5ea224102203e6171a5792c1eab34673b5e8f" \
            "4b2317a7704c523fc0456b1bb3e0613323b1cc0121023c0e58c0b7939bc866bd328bbd6266370177d6897356e0c079d423b4" \
            "a46ec928ffffffff6112b411e8bf89c1179050d44ac69ccb482db359622a5c3391e71b018f12310d000000006a4730440220" \
            "277f91a70a5198473b56223d7b82a2bc25bfa4b7b9f1c2f178820a2a49ef25e702200e2092887ec8e5016735902a4ab7e679" \
            "209907e584c0b9336a6546958f0daf260121034c63e41ca3808c3049ca89d12796b00d64d0bb5c99d830e04d3285b2a279d9" \
            "afffffffffce1e4f8100e9b85c55816c09aa506db4de962f0ac2e8ee705546e757c1d4da9a260000006b4830450221008d2f" \
            "5cca61ae40c5d4e08039836728b769c07a8263a8e9c61b4a0b373dd2f5eb022001597e65abcd6e9f6d4ad2560f2df5cd167d" \
            "16cd62c7cd8b999fba823d8caea4012102831801a17384242c19cd781e1778e718a0706af888743c95389a000d87a7e9ccff" \
            "ffffffd3b0498cf3a04bed0df72c4c787c57731471b130a7a496640850732c69f1206f000000006b483045022100e3de84cb" \
            "986d700eea9df815f9f7dffe134c8d142cd590184c2259cca563ccc1022029924f528e3ab39159ec48401103d9831894ce3c" \
            "56db0004824fcea96b5b9a2d012102dfb74cad7ed5b9160f619cb8d4808e06bc82a3f642bd3dc6635157bb6e51a6c5ffffff" \
            "ff2b3614dfe77e72f3ea2d64d93bf05bdb2cd8fdd76abf98c4059617c1d8b80662000000006b483045022100cc80180da2c0" \
            "047f96e6d1d77180a8b92ad33733c0955a96347d6b6a7a6736d00220239f9edd3bd5b8d7489ed9e17ea6925c93fd269f5129" \
            "660af7602c0c59278c3b0121023503763b5f10bcecea2c8d420bd81d51a02b62e17d2694a8a8d550e7fbcb516dffffffff53" \
            "12609e21488d3dc46a9a50ea16f3a01f39e47de74d5767e41c7c0dda2b5a5e010000006a47304402201aac51efc8f5aa003c" \
            "5c04b582504c79738732af3b93deefe198cdb1edbad94e02201c5f3a0f979a8705f188a95d4740079c2b4f8fc4f5a25e6d36" \
            "813caecd2a9640012102ee632bd014aa22a53b66db196bfe981a183ff02c9a355a0d81d1f8f7f8dd29ceffffffffa1bdceff" \
            "c3f8cbb517ac9735db006e8cc2ba23e141a490c4c774362732ed52d6550000006a47304402201ba6edfd407fcd1c8503eead" \
            "1964c5f225449c386c9c7f4bf2f3bc0ecb7b6de702204cfe6d7cbabe763859783d72f48684cb18280352451d2fc25d5f4af2" \
            "e64daa4401210371d26b123aff3c5445d015d7f9c32b1080bac57fc8ff58d47b1f05d77190d57effffffff4feed05f92fa19" \
            "e1c7c6aeb41cab99bfac5e9c4d3cfce144a9d25ffd8e605434230000006b483045022100d8b6d2902ad21dc590dcef7b4fde" \
            "eb9348d6c086e61d9a3b9d63ff3570a528a702203734558c2cfc2604a6fc47bf0b0a0bc983f3337448811b6bf231bf67e97a" \
            "fefd012103898478fe9495ec2a325140851d313d14eaf014909965368e27b20598ff7fd3d7ffffffff2e246054ac689caa41" \
            "0a9aea9c3afb8a75e5aa66d7b4cc602470227c47eff360010000006b483045022100e1d93205ebf326b22cd9d5209c6cf0f5" \
            "d976a8edef67c75b71842abb36b1d117022014f1c575bd8e33660f5769c696bd1f40b8399b9626e0882269783d4f9adbd81a" \
            "01210228724474d29d5366b43e1ca80c060c7fd45929caf949d0cc89e75c5403a8b624ffffffff54ca97ca4e4af4741882fd" \
            "9e128bebf0e8fe64674648620a252cf63a00ef161c010000006a473044022022c23742286ce784355d8488b828754e4ace46" \
            "40de6ac03df6759a4dcf28b9ce0220798ca21cf8cbb996330323465648b8bac73d646ca6084fc5a70160c07d62d05a012103" \
            "3dff1152a079aa79ca55a08ffcf9e6bf10f429fbd828241acf78ef143a15f008ffffffff8ab10e4d71964abd59bf762c5c8b" \
            "a39abaab102e5b7bc260f65b781e0d8c50ee010000006b483045022100ee9b1d970059f804b606afd66412fa8df6e55db012" \
            "ceb05ed224a0c8056a29ff02207557881ca97c9271649667fc3e0b0b59fe4d41ee8f484d49eef16fa547989ef901210203a8" \
            "388a54d18acbd940699fe64d962716a227dcc91c67a4493065fcf0993b63fffffffffbff9dde46f0ed1b2d67bc848ef08d2b" \
            "306040d963f5b6f9d73a950a0cce8585010000006b483045022100adf27d81573e550856e71d12ac2c1d689ff4b1509ab96e" \
            "9f1839a19daaf9b85a02200dcf67b201d23b416465b1e52927dd8de87b3c3c72231a86c52f5b254cd8bff901210346e9c291" \
            "588beedc369d30d40c5d5130d235231a6127796202c8f3d07130581fffffffffae46a903e3122b095dced1529d61a87d1f5b" \
            "8ede5df3e02d578c3af635cff79c000000006b483045022100e4cadcb1e72663ee009abc914dfb98e90f6dc7db35905e0038" \
            "f595b712cc09f002202bd4de789322e76bc2c323a7cd24a568e7e8a6a53d4b280cc68ce4aab3eda7cc01210354fc92085898" \
            "3c1eee3d053996cc532a590054620d9c8cc7411c5dd487a0dbcbffffffffbcfd634febad994dbab167f9f526a01fd224d3b9" \
            "bcb32a78fa245d0c1c5173644d0000006b4830450221008416d159873a29b179063c25ee6b18bac5021edebc85be8e31dbef" \
            "cff6521920022077c26264b40e395223c78773f86eefff89678a086b6493503c5c298821fbd778012102ac7c410f9fd62f7f" \
            "dec23cc8aeb7a8c85eb0f9220ebae6f033e30209993e7d42ffffffffe55b7a662301cf6b446db8a04e8a93163472b5aa93a4" \
            "888fbe6018a529b4a560040000006a4730440220251f6408436c4bb651bac8cddf731a92e5b01a542aca69510de51e98e920" \
            "eb3a02203d8c0f0f0273bb0982fceb96af0f3748e50e8cc3b0297237c7a090df345960d8012103deb1be90674cab31e218b6" \
            "8d37f015242254b71103db4ba407e1e9b8634d98e2ffffffffa1bdceffc3f8cbb517ac9735db006e8cc2ba23e141a490c4c7" \
            "74362732ed52d6260000006a473044022066450e57231bdf9fb33750c308a81df37f92c848c6e50e349926139926df12e002" \
            "2066bf02ac2a72a6c179a80bc70314c762143fe7b1b81f0e111ef5cb2bd86ea374012102069b8e5e8f658604418275d78659" \
            "3b2d90c009dcda41dba60c88ce5edc2477dbffffffffea4be1d41e03487dfc40b344b7d9cd0777a164f2188de52f7369e8c7" \
            "5319156c000000006a473044022070c32f4a7aa3b75ca99501722c505854e03a8cbffdd5821c34dc7fa4e654a66402206696" \
            "e9412d87b63b610d49811288b6e4ef4afe1a2d3eb7a536afaa93b1b76671012102d07a1be48fa23f61ec57bff6a90be40e7c" \
            "10934c8a417e1d2997b624d82df78affffffffb7c21711aec406bb33cc13af3d712f532074878fb6f972b81fb8a60eb50a4b" \
            "7d000000006b483045022100c122928a7398c215fae2e76f1901d79cfb7104966bd94f1f7bc3bf1503ea27ea0220322dec5a" \
            "269ae88a591f4038edab089254fc70e06f10214c1403e1b17cc5bd6701210353e61ab2f8e880b30c3c56da75bfb4439ae05e" \
            "0860ef4f3af760f88bae1c592effffffff6cd50851343a8f395259781683af9c5ca6ccb9cb3445e900d93c35e387d68d3001" \
            "0000006a47304402202cd65e0448a3f4f1a8490f8483a2aeb049c37423dd657b2e1d16dcff87e7d93702201b705cadfbb4c2" \
            "b7fa3b27441f25c205018e43593281b3feec3609fdd799e448012103637210126471dae2e979c9434d80151f47fcf5207c72" \
            "74d42d6eddc91b9ea8feffffffff1315b23b3ee63c4b28fd25f8d810adf829d2ae3ae04f5df253aa413cca6cf22600000000" \
            "6b4830450221008e90343d8cca985f7dd8ca547a75b5c6834fcebca28129b78d8809e9eeb1162e022004773fea01376628b1" \
            "1350c8d4b1b9cf1dec30d2d9a038a40a6cf79cc07172e10121026955a9aa438d59e6c818b0109d50a2c664a5f93a999c6a52" \
            "96e68dceb1a9ca55ffffffff42af101e0540efa26dbeae07d4e31fa9716b4ffc8b02fee161a294fc43336c8c270000006b48" \
            "3045022100a9eaaf12cdca674b0ec5a174c2d22d2c399aba0d6835103d1532354e23a4cca502206956eae676fab1006febed" \
            "5d3558250559e57bc715499420df4c4fc8fc9561f201210251693e77a72e1922218b90938840e1fa7aae88998b68178d8658" \
            "a7d8f2918cb3ffffffffdb65d67ca4d650bd3d46305ae0797080371f7234c5f16e0d96f5fc4961da7625000000006a473044" \
            "022037fb57558d23c5b863142110d93440cabeaaf5a5b0fac15be73798ef9abaf184022035bb4a86d87877b188a5470ac39f" \
            "2e855c9bd073a8f8219f7090280a85faa464012102287d6c229508af0769813a1216cae0d820ed740b71997716a4564491bd" \
            "96912bffffffff10db396ddf200fab5ffca4bd3aee06f5346dd8cee739ccbb7d7ef4a7031b3126240000006a473044022076" \
            "9c908791ce30a330a1e413f1fcd94772c1f7928dcbdc153062c8cdc0a1fc5c022005217d40dbf7cb2341d71c87baae7b8435" \
            "70b2dcf7a4df0d2a46499b37438658012103beb13ca3c262f9c52bda856a256bcfc63ea6c85c5d48e51dcea2b192589c177b" \
            "ffffffff4adafe09dd6c9cd7ea9ea8c722c0b044bacf3df339ffc119fe4d4079dca74827010000006a47304402206c281f66" \
            "799b4faf36e5608613251fc22550da008768ac2db9559aae9f8642c702206c8332573188cc702ff9cde4b1609be81367d4b8" \
            "5ae653bbb5a76d102a9ec9bd012103371fd39933b7569ce2ff1c5939907bc23515739f7adde3f140fa14b15616f3afffffff" \
            "ffda178ed8bf509cb0944acb59a2e495f979b4bd7ee3b1f1fa02f1499aaf31c565430000006b483045022100f6e4fa456595" \
            "a8ef839e1c216b3094c93379e6f13f181759bb66212e547720ae02204873d1af2f59bc409458ee4eaeb57cd7c4cf954edf98" \
            "2c8454d87c44c01a12b0012103993981af119cb4e94797a4526a7cbb386a9160a123d8862aabd1076c6d8659a6ffffffffab" \
            "d9df76d030a37a6086469c281d2dc0a893843bb232f9a19b847e6470a6c01c000000006a4730440220521a019fab11f9a933" \
            "888f2cab71ef5136a2246ad4f7a740c09da215baa8eb9202202c30876ec775cbe6d44151cfab96c7989b567a5cc696c60911" \
            "3d049385388707012102feb9ea23e2e38a8160800f5f770bfd7c65135e44a949951eee0a69ac145c0da2ffffffffe2f0c5af" \
            "acde99452d548d9b64baf7649a3d2e699fa768020ebc76f0b1ee9a650f0000006a47304402201a77e3109f6a68b792b8c8bb" \
            "77f7731f32a376eaf88dd60ffe7394fdec3216dc02203755630622554d3cbd0c4bd872c0a9494445de0e9e89384983a17f77" \
            "d1f70732012103b79436ce00e54d433787f3c309e429d2243b7ed46910d30d3db20b75aad4f2fcffffffffda1a58dbb30054" \
            "80bf3d8957cd18f6f5e8624c1b8f42d9aa77cf40d30f0366a6010000006a473044022053064848c2925879665fa971a26571" \
            "b6e4b893e48e36661f2d751f217f252e5402204b4d22cc82b6d7efb53594c4b6d400072c5bb8c23c7053f20cfca280ac9fc9" \
            "9d012103f9e03925ebc5a6ddf0026fe93cc261053ecea46cff870525a408c44400eed1a9ffffffffc9a23c13a4aec2f8d3eb" \
            "e6e48833da1bcf5e7d288020310ea3c094ff9712ea7f090000006a473044022039d22487afc7b84e826e4ec097a5bf6bb3ca" \
            "53117fc32d61833a16e8c698f5b20220369285bb03ee7bc3a01b4ea5062c5123194010c54814e896588b69d4f498ca590121" \
            "03dbbf9c6867631eed42713fffd531481b5c2e041fbeead1b32e6dfb717870cae6ffffffff0c6da6d60cbdae0c1ad760c800" \
            "946912bf1f02a028c6308d53a3e314e1c5bf70010000006a47304402203324a060462b050ca12e746acd4218952e263522bd" \
            "74c346175afa525cdf449802203e6a7ffc2274ccc8699afa535c73da037781e14e7c983c9e0cb431895f818745012103b94b" \
            "8ebb777748c4733a596c7eb381fc9ec69304677b0811a5f535f7b2d6283bffffffff6ee09b10f14c01954c3f281323c7c021" \
            "8ef5fd3bc789674852cba99d74d3e101000000006b483045022100eeca1e6006ddd95997bc6f498977242fcd01d6d115421e" \
            "f9df9f69359785697802206e4578bd407d64a6e65a1c8ee3e2e2c6f04c3427eeb68733eb722b70afb0bec60121039a729f76" \
            "0b32226b41b50142b1fffdbe7c042e1c7f0f3a892eb8fa3c23aca61cffffffffe61960ad9c9aaa1ac8bca321151cbe953509" \
            "aab8732d67c7da5803ced2a0c33c000000006b483045022100bec76bf75bc035ef52b35c0cd29f26c5af43b24a6dc28d0664" \
            "62f84351d1bd7d022034687e0be134d70aac8bb8cd0c832d35e4c7d19f36fd6179ed2f75a56bc2b949012103661cf108b98a" \
            "c338e4d64bddf8ea10a6f393010aeaf78f89a3aa0a151f3d0413ffffffffb100e556416a1d71adbafce425447c9233015e67" \
            "3885905fdc4949c54b258ad8000000006a47304402204206c65414459c3559061087fd06860c504ada5eefee8edbfb046319" \
            "f828812602205e779a9f39dc7fb3d67a384d66880980f069c165e7ad8b2e6e45d2c6ac9ab2810121031748ae0bd1a87131e0" \
            "4d1e5cc982c6895b2255ad5826d6c67c4033b32a283cddffffffff79a484af0a181acb20ab996cc28b2691a4c87ad2d97228" \
            "7aa74637e1acdfe5a7180000006b48304502210097d5d1dbc3a5ef26b89e2cbc2b947fa55bc01e2d5c9f093af07d22ca9e24" \
            "c4b402204076d026842c84419853951c6011509bd8f2089897ab8cc6fc8391c1ab2333e901210254a0e9a915ea942bb6c6a1" \
            "6e7d335a36249f9720a00cdff0a99f358404384654ffffffffcf203b1f305c3b73c46ba6603887df99457e1748962df99e5b" \
            "bb4125e4d4ca39000000006a4730440220114469a2530105831cd4972bf806e6dbca09391f86e627947e79bd8b62cac1e802" \
            "207174e4ac6df93514790995b022b0ab21245291b457d8cd8857a1cee46b444d280121025929239dc2deceef90569b2ed236" \
            "9267e31c4666e1c15b3a0a0ca77eb9651a2fffffffffbb4860714e126397a470689b24eb02c49519e353195279eefc2dddd1" \
            "7ddf6fdb200000006a473044022025934e6a5300abf6a5311c7014fb073f6bfbb5e5dd5759c697430087e9365a4802204bc9" \
            "52143427b950efd97c7a73e8f372e74d120d6c5f47d5ad2683a9b798adb6012102c4252b0df23f7faf953fe04c7810c33e79" \
            "dec49be953e370553e206087b91e6dffffffff0ba76725daf82738f25452cb3643487804c380cf0f386232353302d398a795" \
            "bf040000006b483045022100fcd5d998a1f6efdd66a23fc01b28d9e3f8984ab8e406c7472fe61aec5a7e8d79022004ee7668" \
            "4e9b75850502e9789be2870b64448ee51766c1dd1b77ba8bb1db5f24012103e7516e8e129c5ad137530ce2674219f293c9ca" \
            "e0c5bb7ac8dfbe40e2ecbf6a67ffffffff2d25c6ac80f18b3b23a51951c121efe0bfaa03c73a462506afa585adca536f6900" \
            "0000006b483045022100830da6cdfd7234a528e90cc09130be0995df5ea26b592f845618f22fbaf79e3b02200257c6c2f61a" \
            "a3c74aca9ebb0b1b678dc929b90781520fec1879becc59581aa501210290bcef38cd6aa8c30109d773917e65a5968d836080" \
            "e90b30c20b0d78a25fd580ffffffff79a484af0a181acb20ab996cc28b2691a4c87ad2d972287aa74637e1acdfe5a70d0000" \
            "006b483045022100f405f1541792ba43244210051d80d9907dbd209a9de4d9885a1b9f8349a21f7002200f6e9bd8705513fe" \
            "e69996ca593a74cedd49839ed81fa811089166a04061cd33012103d390a5cace9d14c9dcf5ac7a73f5736e99d473b3ef813f" \
            "6a488ec8c707dcb728ffffffffd5a19e0a99c2799f895708930e202d4d5bf041b02ad6219ac9ec7f4afa7cc4d6120000006a" \
            "473044022022f7659f0256805a8bdc68a8ae58e9e92ca1f917c7fd6b4c26c03a89b9f57e3e02207da26cee0dc1c896e0aec7" \
            "b4f51a4b418a2ca62f84da823fd918583af9e3227e012102fd640b7308e0862eec2007ebd75612d1d9490925c13534a65065" \
            "220c76797522ffffffff1c2ed827f03a5da84b17fe35230412bd89723de94529aea1018af036bcd6fb03000000006a473044" \
            "022074e9047311ff17ba80572643cb3322cc0c292c8183d1244d1358c858d812182e02207e6069029addd44f2cc3e75a741a" \
            "241195cb60f5150be736e21477c034f6c2e3012103c62cc63c1db82f75543b3022203e07782107db58731bfbd5bd7d4734ef" \
            "06097fffffffffea465a5b27ff54263bb244a68f5ee9c06d2ea5c80e0695b2ca44087e3e64320e010000006a473044022071" \
            "19cf9366b2121bfad4c2db420318eb813c96d583e1a96b8478c68db756c24d0220234d1a00715701f851bde95122f753d03a" \
            "33ac7c0fa95d93f612676f042296bd012103e989ce5bf55bc7ac75d20f58712104459a104ca3b58120b5efb9a40cd3c74cb4" \
            "ffffffff4ebd2a8a52fa476d3ec3a1bcbf30379ebffa2fdc863e9354dfee7018efe53087010000006b483045022100f1808e" \
            "8911f9af842c3dbd29849a4454ea6c0b80294ff53e98ba7775903d249802204e3d6d67cb26dc3ced1465f212acbcba74654d" \
            "e8990a1715b12c01ed6c1d45bc0121031fefeb9752c675c54bd235d114624ea3b77295ef7f3d32017c377c1368fd80c3ffff" \
            "ffff1201dad8f28de61239583b645c49b076650e8fdb2006457bffbb93bd17ec6109000000006b48304502210090b948398e" \
            "8e0f17698c81e992dc7aa75e29e5b78c756a15c7307e43c9bfa14d0220046e2dd51c71c484cd94922cfc07ca49de8617c989" \
            "fca241b74ef655901e2421012102e0bf91e39d666cd74ef2bf6fffdc543cd9d5587d7c0023bdfadc66092bc5b183ffffffff" \
            "552d01382de54895b7e6f33fa8293015d31b24f999cfa337cfa6192bd66a42f8020000006a47304402202a8fb561a089600a" \
            "1ecf1deaabd5c5dc08cc08d1302004805d79248f231085bd022003460edf0cd10e066ee97f50696e8f90ce4e0e9d10a2ac1e" \
            "094d8af43af480110121038ff468aadbc399e317ad6e23086271aadb2a0ee92eafb0f0b834f4977d6e8797ffffffff61069c" \
            "30a79846057caa5f629faa8114eb355d1a2e460d1d336032636ea7ac8e010000006a47304402201ddb54676318ea9c1e4482" \
            "88288dbae402ee746cccd70463df6dc289e4b61cc102201765ac070281d339ea08ce745c666de331017c5d538bf209b8533f" \
            "0a8d49b52b0121039fdd459f94254606a6757853249f699370a52146618c46eef71264f21391b3a0ffffffff988fcdb167c2" \
            "dd56b131e7c5c374ddab5fb146a697b0fdd8f87090470328cb58110000006b483045022100c6c326e06bd21f5b6dc709b7df" \
            "72664f462c98f13aa073cca0e8d4a36deec845022062a07bf84f5cc8666123f3c0844fc56f26c98335d030585a1a8864c0ce" \
            "6ace1701210289914ad5b75a0434b278dc8a9c79e8c33d6201fd0910a52b3eae0f3c74c3728cffffffff0cc61d79683c32fc" \
            "0936971e6320ce88bdf7fcfe29e5e4031158c506c91bcfbf010000006a473044022025ab04157232abcacf02aeb105eaeb0f" \
            "6eddf0fce42b60e3cabb6b95f2e7c30302204ba2a6c6a857dcb4ca6e9947e67c469d911a057f9d971b380977487215acb59a" \
            "012103a347af1b2f4ca48f590dfcda8d47c0f440c89ad8d7a084a031435fddbf16318affffffffe3d8dd9c979e8c3266dac8" \
            "9019775fe1fa1ca09ac083934b86f8ad2f7cb14fce000000006a473044022011c40ef003a0043fdf8d58cc674963fddc5bc2" \
            "54d2c15f33d8d171ef9e2add6402205d3780dd4a80a734b7a9353485cd608fb80d2080fa207082143d0f18fd746eaa012103" \
            "93e2d8009a08f3b6039e52f0b3fe40aca0d9ee99672df5d00ae621dc23d8a436ffffffff5f7c87debcf0b94f75bdd5cc4ce6" \
            "9b95038e2cda811c81de51219e0e0498abb6140000006a4730440220743963026c56c8364a5fedb6f10417ce5c030c0276b4" \
            "7cc1ed494442e52550120220053be7e963dc21624f86c4257c6a12fc60fe8fa43696141ccfe2d50ed981e10201210244f0f2" \
            "a037191ae41cec2832b44a0b2abe31303fb29d81ae258080c646bf4d37ffffffffcc746e63eac78cfe458a560865521b8b16" \
            "f87397f700aa2bc68c802b40378d3b060000006a47304402201354bccad23c3da99d8b1256d56316fda8f2461b4836b5e7b5" \
            "777b2bb93da4a10220663694ad7f620604ff1d1ca339727ca844f83c761332bb29556052bec65af7c50121033ef0fa7a4c03" \
            "5967970c0aaeb9b5dea706e305864490323bb3535f5e4b3493eafffffffffba6e3fb66e8625475cc8ee6682dbd16d7d86377" \
            "5988c5eb5fa1cebafade588b000000006a473044022001c92da2152879c11a74e0a023b21d2bf7ac04d2947e15fe2525ce4c" \
            "7724df4102203810023750f8a0e9175446abada96a0e1acffddc345481bbb3ab1a44c2c98555012102e721f0c86de0483fda" \
            "618e21e6e1763dbfae4a2d3227df92f28ae30261a3a0dbffffffffed429ce82ceb3c0a8a0320a0628f239e5b2774282f4f01" \
            "2c9d948c3842239149040000006b483045022100a2a69900f7814dfc3cbc5941246036b44a205e1a3be28b6a08ce60d4fdfe" \
            "b6320220170259119d61fe611634f446372ba905f8f6bcfa0b35c1b3f369b9b43c2732bc0121022e6ed75d6cafcefc65b2a6" \
            "d191a4ec4e4cbc99fbcfe14684939c59aa0981aa67ffffffff527f349d73784270aec12d1427c1f8ddb60340022e11db992d" \
            "d0ce5504f74033180000006b483045022100c6e380e672630fd6d149736d8da83c6dd76d32dc683e205ae2bb41f254da6831" \
            "02200b99a821bdad4b7a16728842092ca4f0dd39fe8e3d59f2cd860bb41c19c2535101210256cf77a103333f18b2aeea9a68" \
            "4b1b1a487b9d7f035bcb3a949ecea38b32b4c1ffffffffbe9867e770b1399e7d14c7759a496420fb1f4cf5211efb7fe2d02c" \
            "39fd7bea64300000006a473044022021e1e2ca84e0c6397088f952981a7e8935fafc017f2f4d4bc4ef54ee474cd6e402202d" \
            "a4f61cd6d89589a717542f45446a95885b97a7c58ca0fc1c9f27ff35bcdc9b012102a9b82bc28e120a93d4070620e974d0e8" \
            "f8ad024515d38147355e1660bba32e6cffffffff782ccef377d775e70bfbb164868df313c8e9b7a96862e3af3737b869f347" \
            "a597000000006b483045022100dfd73dbe90ea4d0fb6d620367465b65aa18b6ca289a7b9eb776c170bfbd3b1e002206bffa6" \
            "487fa8bea806ca46c0cbd587540cfc2d38e069c8a55846409533c9834c012102730f6b6181add8d45df6de18001e8a104016" \
            "f45193b314b6fa23109ea6497cf4ffffffffcaa6e063ace12fd2f12c663a08ace9ec5f8a362a94dec4449d24cc049b201f93" \
            "100000006a4730440220397a9273bb53e6a5cfd4ecfc5f7498698f8d75e384b25a097bb9c636c7958224022026b506a9b073" \
            "0f246af2161ffd40972891240d05a5b2b90a488fb78057de86fd01210225c21b98f8076df591415a28842be8032f2d4d410f" \
            "a7d0e151f99866b25ff417ffffffff4bb5468795871c089ac9c49fb6fc6d9a3b4f93ab437d875e4be609e9c3d4bc00000000" \
            "006a47304402205e42e858f6e4c3cc66acad488bb950e09cf51711a8ef6fcbc596e4326497354b022005f343f188be176ccf" \
            "985ca546eeb1375abfc7646259fd0562e39a947ffcab30012103fe04c04d96db7ba5d518e6c86d9f51d9a5a7fee3a2e963e1" \
            "728cbb7e84157f17ffffffff48b834b088a7d359ed117f1d639839525c1127a70e61cae4b9c58f702a6e8d59000000006a47" \
            "3044022032ca659a6f7fceaec16c21c0f516e6fa8a9b93bc67d37d92d6558aed2f5a2a34022079b5bebc07850c406e5bf84e" \
            "7c9fcfb98d0a54a22f1bd5cf5e7add2040ce27c80121022209a4630c207f34249ab8c42e420b7238678d273faed21b8e760c" \
            "5763912df8ffffffffee658aaa456b8b4beac4967945188e23b830a7f62669a97ecc08fd588561a726000000006a47304402" \
            "206a4503b1598d6de187e3c847aac916f2df9a6cc5b6ee1a17241de91d69f86b390220201ddf8cf6ec027561347f826dc22a" \
            "f46ba6881262ea08df2d58986661a21ada012102190972c88235f0274880f3f3972a15a717697c722b45d6afb67ce2343dfb" \
            "2b83ffffffffbcfd634febad994dbab167f9f526a01fd224d3b9bcb32a78fa245d0c1c517364450000006b483045022100a9" \
            "5fbf56b1dde95452813ee38f83f0d3b3cb843703e111c9e565a91217271352022043e93d49893cf0befc2a54cbf91060ffd0" \
            "0b6fcd521e3584089694e9eeca39d0012102373d9a9e5dc8b624aa32b16b044058523cfb8c7edb133e10b4d68605eb3480db" \
            "fffffffff0ac34306f33f533875fd60ca1bdec40c90098b9ba2ed1092bd0365d0b560115000000006a473044022074ea34cf" \
            "a7efafcd300a35f4a6d228a02d1aa52eacb22e724b7b3dfd13998a5e022051c6248bcb9d84464ff6000d3aa37873f4b4eb82" \
            "4b8778f87715df80b123cb9a012103093b14bd367d63ae71af94e6cf7dcc478ac3695260be34f5f73da7736e66e20cffffff" \
            "ffea829d057a42fa263e20d058d33a42d7a56cfc34f1d4999afc955dfa8b66faf60c0000006a47304402200dee71fb5fc282" \
            "73a56da111cd34afd1694d0355b5ff7346fe4864d0e629fff0022007501ca8f5fa69e09c8e1c5d878a2c371e38d167d2ac7e" \
            "c692a3694202404c32012102b2906461624fcf6c35f73a7ed9830b1245f34c7338cf163688ba862b4f82e0d6ffffffff5abd" \
            "ad07f31fae884eb92ee6970d8405c01cb87f8af9c0d1edbcd15bc95f5fe2000000006a47304402201a5f3709db2a1d8fcf02" \
            "d9446d4600ee536ba23b4aca9f5b0ec7ffdffe964843022030fee2938808b25ddaa298677780b71749e80d097e967c824855" \
            "4d312960331b012103bbd4d73c6c3550933ef3611f5bc10232d0e40150485931fc57bfa17735267c19ffffffff03daf7b9e8" \
            "95d2b0261a253f14aae5651be58662f84964543501a0eacabb4052000000006a47304402207dab7ac4ef147915a4dfa6508a" \
            "6ab87841c0690201312c4e07dfd88bca535e0702203184cf13ec8bb06790354db1d99963a5024964db2ebf7afb2d216caaa0" \
            "679f1e012102eaa43b7babc38b8c6df43c99ee1a150599bf3de9ffea62527beb2503b75526d2ffffffff4ccfbc1b56ba7ad9" \
            "9d1cd987c790d1e98d8fa8733d3c69c81bbb362eba12ccdf000000006a47304402204f4814ae5ebad51baa19ca613b02db36" \
            "766c530b44c4a252370bb698a8c12c9202203cbccfba1771e0e3c5a734f50a52a071173ec77ddabf8a89e10b316a2985600e" \
            "012103bbb1f700117e20ccc3d9a00cbe7049c25fce1d0fdd1304038a1fc272daae0204ffffffffa2ea4bff20b21792df46ef" \
            "12e70d8bd88816a717aafb9f496c2123a18c4d6af5000000006b48304502210099af3ea4e0f6f22b93e463997eca442857c6" \
            "f5a78dd3d120daadfd555b2ae18a02207566b213b4083ae650e3dcb0c2080635aeba8ea3d61c845f1272ddd9fc8164220121" \
            "02b345e41e89c8ebb01bcb2b5665ff2133ee886f85fb17aa67957a69fbe77108a3ffffffffa662e98d171e6a04d73c4783c2" \
            "708b50aa8b02ef432f4917a840de5012b4b373000000006b483045022100b85d0f2261e42a0909b7727f54ba2d72b32dd893" \
            "b70216acf0263e6c76b95aec02205d35ecda7211d71f8a606760bcaa754efb72d27c63eedfaaf9a16f2451fe89cd0121025f" \
            "de8acfcc08e4b3a06fdb181236ae84c80f7feefd43111166db66ed42da61f7ffffffff5f7c87debcf0b94f75bdd5cc4ce69b" \
            "95038e2cda811c81de51219e0e0498abb6150000006a473044022021645897d0a57f88ff81113d46f24fc12620b6be9821d9" \
            "6ae4f43e5c86981c440220744a183a75ee111c851230c29950cc2b6bae3e68ce10cec06b22257a12b1bfe2012103c0ba9cf0" \
            "3e97c15b36766fc5ef928d98507c02769169264e8226bb58f44a582bffffffffda178ed8bf509cb0944acb59a2e495f979b4" \
            "bd7ee3b1f1fa02f1499aaf31c5654d0000006a47304402203db1d955fbe87729ad1c62fa852a08ad90438bb3a11fcd4dde5c" \
            "cfce80c85f2e022062292849d143f1685e34856595b552c5e410aca2636bdb85d3be51a775830c88012103a2f06b137d81c0" \
            "6cc1de692850ed94ba1901f610ee8416c6e24ec878754199a0ffffffffb703695fb5aaf83eaff6776ea6f182e76e04ca337b" \
            "ccc49365cfe3fe457f1288120000006b483045022100f61975785e2b6329da9065e43e855692161aa1c773b575612690e7ac" \
            "b2042af202205e868a4df6bb200979bdf99e2be3f979981e9674cbc8455c3384a2be1bbb91d6012102f9a9a2a7de780e2a8c" \
            "c23bd215dfd2d5aa9b5cf8e1c099a894019eaec8f7ecd8ffffffffddecc6d08570f5854fa6708bdcc431a5d0e24715b541c5" \
            "bf153231811da8309e000000006a4730440220218e609af14d4b817478a101a4e77c5315c1d0d434c04708906115ec5e7dc3" \
            "3502206411bfd586f883f4714703cfb52f3c8145d991096e0b0169998f35d126987e570121038802825e4e0108e69a6db782" \
            "c66d3bb5fe8cf7fc630bc11892444ee5c6aae8d2ffffffffbcfd634febad994dbab167f9f526a01fd224d3b9bcb32a78fa24" \
            "5d0c1c517364010000006a4730440220057650930462bd5ff1ecb8bffad5679c1c196ec855d7a7fbcee8ac88a97149020220" \
            "02951f4da565faa574c2d8d4b006a081f9037af759e11a252f703098c38b87d901210345001ff4c0fb18c3341d17356d65ba" \
            "280d58ad663bd43f5f789689d67381577affffffffa1bdceffc3f8cbb517ac9735db006e8cc2ba23e141a490c4c774362732" \
            "ed52d61c0000006b483045022100e3b30197bc99f22f48760185cfe86a0aa1c8230f5aedb32a683f6182891ee08302202e9c" \
            "6570cb80d8b6fddd9aa1c1bf067092d4b292e9ba83d474a0774ba48202ea012102b94b5defee98bad42ba08b28f4166b4197" \
            "4c60168ef9654a3907ccc812f82e75ffffffffda178ed8bf509cb0944acb59a2e495f979b4bd7ee3b1f1fa02f1499aaf31c5" \
            "654f0000006a47304402205b64508b1b0fbc7aaf26d6ef70b49bdcacc54cd17694dca39bb46a8f88cc79f1022000bdab7914" \
            "3ce55a63093bf0dee3234769f4b140ea6b497450371df15dc3a87901210338f182348ce297d131e8ab6095090da6f302c26b" \
            "d3cb2d70711422845676c8c0ffffffffdaebe4d11f4284118bea930c2e2a9880a0547dd23633d93945288463227d11170000" \
            "00006b483045022100fe79777a80c9020984ed47a29f113ce09dca75b162ea5af711f96fa12f645cf902206f8f45e73d11c1" \
            "16e2b254f1518a127941726e25ae812e61648c49ee2a2ddd45012102bf9900edea5e11bd5bd8499b5343fb0c9850bea5b1e6" \
            "75e41ab7c8a8ad211f8cffffffffb75bb1dc1cecab7382d9203a7399fc532e11ea6c8a60f5274ed40087d9667f5003000000" \
            "6a473044022042e13aba33e1f62cc0419e97f513736b1582bb686d9620e5270f9aa6fed3148c022054651cd30a5906d09a7a" \
            "b1784b81ca3570e812d3b6603f3d28cd3232ceb164600121021f523c2865c2e6c93a1cea9e1563742640318870743d5760ed" \
            "c720d2fc29cfb4ffffffff8657752ca6a1d0e53c4d85007a5c9ded070d07bef8031e259bacb527650e290e000000006b4830" \
            "45022100bc0d66f643f70f485e5cd19326fae71b8df2156e2310167046579b27ec399903022014e884d319762b679bc85bc5" \
            "f5ac86a4fdeba2377d6e5805eca58554a355e2a40121037e8fd2ef5a10637b7391748e229200a56ab5b29adcc2ff6861035b" \
            "9fc597c5a2ffffffffef4819b69b4f50f4fce3ddbea13fe64e7705c2acda53739791b7535197a5d79c010000006b48304502" \
            "2100de1471d225e14927f7519f272a6be354b75a1f33f63749f1bbbc20f9bfca75e202207a0f0816fef7c8ec80f338eeacd8" \
            "01427d8aca63f9d1604b746f8b767701657c0121028ae7104074e3a1d9e96c75a7b58d2d6a40fd994818550f457b7b4521b9" \
            "afbf0affffffff593ea9eda33f3506a85e3eb38701c638c3e408746b8a6d604d25160cc6e70ad50f0000006b483045022100" \
            "f9a6c7ba4c70c105f0a0cca97afed2aaa6abb26a42bc9cd7636aacdc4bb159a102204dfbe0a541b106b93c6443601673cbe9" \
            "715a9aae42e468ba9c46510f6a403b700121036e06d042b2e07a339a259faa2c4cf5ca95c9782c4ac748d046d8ea7d9f5861" \
            "ffffffffff109ba7a550f997e44e86599faf6cd778432b43eb4f8947435f63940d9fa8c4e3050000006a47304402204eed9f" \
            "17086239a960fae847faedaa3dfa83e448001d92cba7d6cbe3ee4a8b5a0220786ed87e8d0a774ef36042c40e4e10dcbaa49d" \
            "e17e89283c1ed785741ea3efdf0121039341f270b93a704026e038f429cf1997b6f56a73075774ed741bcf8ee0900ac1ffff" \
            "ffff26495ea687081c55fd119aa479071729219d4bff75013f8b1546365f71f9940d1a0000006a473044022056da90b3be62" \
            "a26b3adc678f69ebaf234939d4115f4c8e6271d81dab41e49d7e02206c6deeb12d2d71e5179d06631d8c7ca9ba8fa979fa00" \
            "fb656a5cd497ff69aadc0121029a033b48faf1c37e9eccaa113adfbb238c863c829c70709f2261b698d7be5597ffffffff01" \
            "65258bd8b95cef098dafdfb1c28206e50ee899424cda4e46acdde811ab4a8c370000006b483045022100bdc4f3f95c90a221" \
            "c40b2f0bd156dde0ee9911dcb765426bdbede2f71fe5664802201aa78d0d832631863595d6e4c339ddedfb2307e0ffc7c73e" \
            "41b057d1b4b12ea70121031ef1484cfd7034b61f971a85ec39d9addedd9d99ba1324d14ff811dd1217b388ffffffff02073b" \
            "01ecad9c9911b49df1783508a6491be9cc7c20866eed693d1ee54946f70e0000006b483045022100c6dbbb095ca0134ca3c7" \
            "d8ca7684daa8397c5431c004307599abdb240b2393930220770302f0c548f0c99f317b0ab397d3d89e1cb34021dbbb1b011c" \
            "9198e12c62c90121023e1bdca5cce080f152876df677d19d88893b19c298e072bac35f1608bab45638ffffffff028ff2f0bf" \
            "c7039626b1fef3df978a7494abdc930481231c4aeb27d596b3deb0010000006b483045022100af3ab825b6be77e3ccf671ed" \
            "3e24e68cdb0679147cb209edf0c451a328a0d44f022011d0351b8840aee8ffd508f60525bd1358d17c11eca154a9ffeef259" \
            "e80058c5012103207ffec8e952f7cde8519da54a088b527fd36e26f7559faaef63b0e0aa9cbf50ffffffff02f00e5d3421bc" \
            "e5be9f3e9578a90af95f3608368166bf59c9af57df113dbd87070000006b483045022100eac9a2e91bcb345c41c4e5bc80f0" \
            "101ad580572f0a0150fb572ad94fc2b5a2360220544a589e2b8e423281e962722165c5cd26c7967e1cb9a7a08dd0ca16573c" \
            "08850121029fc0d84a36b075ac6b6cb1ab4399b3e57c6a6f8bb46929d304a6e1eb91e294a4ffffffff03889d5dcb93200afc" \
            "7a457088414c0d91e002ad798bce8884c19fa4f0a06124170000006b483045022100c8ece2ea3f5f87988a04b35844600ed3" \
            "eb917e6ee30b0c4d517253630f8247c802201373067f2bc0273ae37728d3298d4a550fcb26de8801eeafc7f2e7dc659136fd" \
            "0121031d6983e988faa1e1a9f324e1850acf567f078b901002717cc323521944151e5affffffff0437a659ec14af174598a0" \
            "7904ac3b63ebbb234dd85dfbfafa3a3fc0d1a8a2df000000006b4830450221008a04ae8609c6d9c543df6ba003240c2a7e44" \
            "16ed0cce3d75f1ed21df401dd44b02201182333871722208c7c1173961a6890e1c380027af93e17ad59114ee94f2430d0121" \
            "02e7fb5013b289968bfa64968a1f490e2027a69c2da0deb37c7cece59dd714bd70ffffffff0465cd6182f3e0a53ba065dfef" \
            "86e3278fff266f342ff2aeebe08b4b57b25616090000006b483045022100af26e425179e67317d7cd58c373268f52ba09b5b" \
            "b66a4f7f25d21c417e06bbae02202b2a59e58a6bf9cbe77c6e9f835e9c8c6ef5cbe928c68ddb1b8e4daeb655ff7501210322" \
            "1295f98de1b77fed3b02497f6f1b59f1f044b9c9f891b008eb8b2b14844f79ffffffff04797893338f0f4f0daa000a08741f" \
            "c69f0aea10a323e11dafedf9b32b434ea2060000006a473044022035d2170eb173abbf421523047ba03ac39a2fba1b2b1837" \
            "0c5d583b9b00397efe0220553b68d7eb42e5ccb3acf92777169ff41bbe692a631ff5f4be1f3910bb9d1eed0121026729782b" \
            "f7ec19b1e29e6762a9b1666733b07df4bcc7331d2bdfd40012b149b3ffffffff04797893338f0f4f0daa000a08741fc69f0a" \
            "ea10a323e11dafedf9b32b434ea2070000006b4830450221009d2d42693d62be2df3464e171487d4c9ce28e79db2b31c36b4" \
            "612c8c9846e22c022010d96de53c501b0a1bd32655ea0c759ddb063e8d2fa75019d4233724a9f7b116012103f5de1eb07142" \
            "cf53e786c54fcfca646871c46cd2c0ddf298ce7fb3fbd100f29dffffffff04797893338f0f4f0daa000a08741fc69f0aea10" \
            "a323e11dafedf9b32b434ea2090000006a47304402207713099c23424b2879f2eec762c4249e3cea88121dbe0a88162952b2" \
            "86eefb7c02207d79584ccc4f7324f1f7fbc5e108d19e1023cafe7517b4fa56feebd275885afb0121036d8bfb042b20f52239" \
            "62633f4570d61b6710b3ddbdef6990a2b8528afa338e71ffffffff04797893338f0f4f0daa000a08741fc69f0aea10a323e1" \
            "1dafedf9b32b434ea20a0000006b48304502210084ec384edaaedbd129cacd7f0ebb746cde6062efb0cb569d11ff97104b77" \
            "ec2c0220364904aeaafc2377f7ea9a59d7edc21c8b25d858ce6cf123092a81fdebea2bd60121033e5695bee4d4e1976073f6" \
            "53bbb0f98a18b7bb887866d7444a5f63aa4020a67affffffff04797893338f0f4f0daa000a08741fc69f0aea10a323e11daf" \
            "edf9b32b434ea2130000006b483045022100e599f91e834313e06eecf54bd8737f39f977072ce707f490c4c6fa2a7084757b" \
            "02202bceed3ba78cac33adc6bf351674dcd7e49485e887bc0cfc3e083287ab0284a80121030f5493805d2b998fd15f3b2ffc" \
            "53fae506ada1c80e0a51f3cab5d1db165f2921ffffffff04aceb35dd8b61af152b765c431050674b51ef5b06be776acf6c4a" \
            "0fde23273b0c0000006b483045022100ca00dc59ad9e5ebe71dc67965e25cea445e481fc5669caf773b7a95df9155d8a0220" \
            "0da84de4812bb615ad751e96786c225b108a2bb464b57be8aaaf0a1752754f410121023a450a82d99382e8b80eff9342915b" \
            "27766663e4013080d823403977c2b188d4ffffffff04aceb35dd8b61af152b765c431050674b51ef5b06be776acf6c4a0fde" \
            "23273b0d0000006a47304402201500f6d9a33e6d4a27b1463bc04afecbdc80a98a8f3e5453010bc5cd847527c2022003dbae" \
            "470b6cb96f0ca7ecd12df19fb9a6089a5f93dff5749377667e421ad323012103e14a31d48e9ae9686ddfdf558ff43f9d5fdb" \
            "758a0b7a31d35eda93cd2984bdadffffffff05613b4c9feef98a59781f6498d8403bd9a98bcfa1e9dd9ada696db2d203126a" \
            "060000006a473044022023fe0f86d5a3078a097c73ac2a0b38efc3007a2d431c2199342bd2285d26a0a90220504704af2054" \
            "fcbd30f5d138a5cd0b4d8a0ddd10a49dea170963e2cd448bfc6801210283fb2b2b6f57a6226f5044d9249e54cb69d6f449a7" \
            "d1314488896eadd76688b6ffffffff061997e3f378df15b99a4428d98e0937d649943bdd6eb0bca21932dfbce9fa8e230000" \
            "006b483045022100f90bc2b42a0cc954055a2490f39640253bdfc47111cebd0505bad2c5f34217a70220416d6d50e949908c" \
            "66863662e650cfe2b20c5bb27898d92f5b086f4e2aad847b0121023d43fc87abf1fdc33ce194befc22a2c60d660d28685db5" \
            "49ca277d6280abf9ccffffffff06f70ede936bb602b28f5e07486d15aa876a66ad06ae29730fe104c9dde1219b170000006b" \
            "483045022100f91519254a96aec957d7955103b66d1cc28403aef83606356a9033a8fc270f07022058d416b5cb985499110f" \
            "b7a7d6277332235dc2ecb015bdcbf43f4947b11b83c401210273c9100a43a803c39f14b4158a0a09aab58bc0ee2b7a550fa1" \
            "307f61851c5a58ffffffff06f8f0ed56add750233f806d75b325bd273a669b122fee21c97f1330bd96c357080000006b4830" \
            "450221008af3ff9858a318f4759bf8ef70ca583903660959da7d20b0297a06319be53d4202203815f92475e94b396a1e5ba8" \
            "1e3797657792aa1fd6154d0a9e99f76dafa73225012103d857cccfcd1c9170ef3cbc398dd97537fcd676089e050fd5b5abfa" \
            "46514f4814ffffffff071b852abfe20cc269a0815c1b1202f4cffcf7a28dfdb465bea44495f4693282000000006a47304402" \
            "200a3b6cb894c8eae4759075c7f6b83ade4b62704317d09554a276071c39c3020402207110b783122e6ed12ac24ab85cd738" \
            "df1d743fa7f3475c8d73e5f394756c8a8b0121038b40448a26218ddfcb8056748c9d5b5b54100ea2f0f75520fd65ed6bb5aa" \
            "8b4affffffff076870d19b2205488e8ccfc0bae5739890d854b6698acd6e892c0c8a1b24eea9250000006b48304502210085" \
            "69237d1fce23bb6d49bd7ec9e8c7afd11ad732ba66b8e81ac999bd16af575d022026fa14fa95ba694b56a8b80853c35e09c7" \
            "e4f8ce9d13c79ae1f9d803dc8613a3012103a07e5f842c8904262ac7c5eec1f7063dceb35e99000beaad9775ecc646ff9e80" \
            "ffffffff0817fae348f0f3d0ed95449ffec00bee36c8dfe0a524282c57fe432b341ed1910b0000006b483045022100b0a7ab" \
            "b951233d62cca3fada99028157d7647cdd34d876530b756abf04738ebf02204221a5f92f62978a6abafacabf0f805df5fbb6" \
            "9253e4357c3e279f9df098cbc1012103ec932903ecbd80140522e1fefaf58b55eb72ce104b4cf626a2e87c1abccb5095ffff" \
            "ffff08c26dcb4302677dcaafbe4f47c6f3a8e8b9920ed4d10e506ea120ce422819795d0000006a47304402204eea8ae7e750" \
            "96bcd630ae9502f4d609bfd5314a1c5c27b389f736c20ca1999902202494baa6b8b35c29c43079bbc5de1be09cb1d0910707" \
            "f216cf2f50abab7d5ff70121023ad7dcf3bd4c85faad438e36a9d51856b34ef0467848888f582a0d6b10f8d2ceffffffff09" \
            "9425832aed65937726b2cda6ed967a8f5a4cbb56ae275d5ec7760686b2c176020000006a47304402203673e3dde99876b514" \
            "d68e5ffb48cffda6a762ac397847a636d34f1e2ab8800b0220504a151c5b28fdfc31f1f392d552f37b6a5183081e97142efe" \
            "3865e37e22f14901210331165cfd51dacabfe378259bf69882309b7062afdcfdc2ed564ee046029decacffffffff0ac3d86f" \
            "ff937f07a979b2c29d03ff0f559363375085c085fdb1989f62334aa0000000006a47304402201c5551839868cc45b25074c2" \
            "e6ac79abe9ac0e09d3674c95ffe240b2c2948ea902201068b52fa283d5283457bd385910da81f58d6b1679dcc13235f1df38" \
            "376c2ac7012103c35cd8208eead7b6398a791d5928ca665e9c853902f74fbcbd10f450fcf2642bffffffff0b944d390507e5" \
            "d839788153239da4b94223af44e4c7a635dfd7238aceafd6e9000000006b483045022100b4bcd69b9a99fef4712608fec75b" \
            "a49238794ea42176b27a2051e91800a5e93e0220236a3dfbdeb5f86fd8391751fc0e23fc28e57ac8c1738971804f3868c598" \
            "c4310121024099223f13943bf13cd5fb32c0273374cb9a7a58dcde4cdf2c617cc356ccd31effffffff0c273ee309b6c1b917" \
            "f86f2a81955329a31d3516352bad6b100a2f4352d8e0b6000000006b4830450221009b1ce2ba9e2f7ceb95bea73895972035" \
            "a4b7bee3a96fbb81a7688eb1cf31faf2022040168a3c35e23d6b17839a05140ebcce9fc364432ea6bfc5db01c45c37427fdb" \
            "012102b40cd440d503a8c8c87037c00281f6ffc863cb102af874516bd66c21ff71e443ffffffff0e05269891eed63f70e680" \
            "0681f8b959b2ac3481cd9ec5bb29a396bcead75a42200000006b4830450221008a7f2d0fad4e2c70bc827c3cabd7e460befe" \
            "1e9e921aca028dd57f95b50e988c022061a54cd35307a98739f146b6f767fa83a1f2a96df95c9d2fbdd86199f349207b0121" \
            "038560eb7d2f439f660ba9c8e9174b32fbb10f0289a10c7f331c481c623a3e4121ffffffff0f7ab5d74afe8bb852aefeed62" \
            "749a5dfd3911805ff7d597cc7bc17d8d03778c080000006b483045022100e80f6e5a9303195ca965404e6e0ad0ad30ece711" \
            "60d8d81f0fac0ea76e08b1d20220672602c0bb3c8d2802bcd3f9e0ebfda2eb080c335eb7a56ef77337757554ea080121024a" \
            "c732d1eb3648be8dbd1f39a33121aeec36841240c8dda144b2c0ac02048629ffffffff11d97d059622b425fe8038949594c9" \
            "539cac83b4830656307f3bd1f3ce3c23a0010000006a47304402200e7a341a6aedb2b6752670624b42606629a7a409c62ba9" \
            "95c9d2be65ebdb82cc02200cc16f97b701417a555c92d7c18b5daf9c3aed6cbb54e9591cfef58ad2ed5948012103e6e8240c" \
            "4104d1cdf2bf412b58813d437a43557b634e4f70e5b4df55bf43f5f8ffffffff11da30f26aeefbca5c9a64edb7e89b24d959" \
            "6b9c6ef9822e810883e79b406267000000006b483045022100e96014041ff0545a1f3954f2520d913b381c341210122832d2" \
            "6c6569547c1af1022077d0304c8d60ef71237f0d85cb00bc21cc8d102234c8830d11bc6ad8081cfdeb012102db6450732288" \
            "0842c4d156b435589cea8f46236b1e2e6e334825754dbec0f50dffffffff1233b641322b5183261d4ad0ef25a2d1a0e7ff57" \
            "24420bfe0d03481e7b03674e020000006a47304402205ad31ff0754847aff40e5bae717bb037287b1f814c89cfe455ee3433" \
            "d539567f02206f770baf8b0f29aafd2b2ede4d8a092cd7e0ccc13b6fe204f46b9f1c240af834012103c6ed9efa214d221110" \
            "143e73a726ad3434fcbab5c71d3355a87247afb9991214ffffffff12bfce33b8ed4bf9138c9ff98e4105f64d216beab7fd97" \
            "d25ad0c010a078c0df000000006b483045022100e9395e429a7e477843256a7a60bc37625a606f3d45f4748b50da8fca8e32" \
            "450202204b447534203eb3b346469b543689c69fd56b32608f4cf844e23945987857aabd012102856127e26e893aac6c4c72" \
            "82ba68fee8812d3b4e1790440a8344402dfdd0eaffffffffff14e027818d9ce84574de620ff0074f98653629abc23671c619" \
            "26be6b691caae41e0000006b483045022100e7226a6e33f98ea2ab1e694989e91ac7b6e2a818ee3d407666b78798c6f9d18a" \
            "0220779b2ca7bc5623c97aba24024596d929201ec0bfeab495f9c0257fac3c5ba706012103aa656dac90ff3cb02e077e55a2" \
            "b5c0c4ba557b729634adb265888a2320c7fa2bffffffff1508df732dd31fd79797839b52352b3ce1a6a4397f9317afc80020" \
            "eb588285570a0000006b483045022100ef985e92c3a0c18d0b887ff6549fc161209ceaa612c3e1d9ac8a47653b893ba00220" \
            "1780bd423afd925e77d2bd84ef32f58f4e836d337bec0fb6727ff65a86b19d35012103921f83f2afbd3905f03034c06fe6a3" \
            "67218fe8330ff7ff91c34c41cc472869b5ffffffff151fb7b57e49ba9bc27de706ea05e86f143641b27a4bd2c451cdedc95c" \
            "4933180c0000006b4830450221008d008064829b818050f8a3231165d8f8e3bc36f6c5a68cfc800bea741e94b2bb0220302e" \
            "66a91a747ab7b5e1a935e6b61dba713afb1bb682443ce2fd22a458b7e99601210353afdd97b1de5846b22ad6751533f043ca" \
            "daa1fa6452cfa57438c232861b5200ffffffff15910b0124037e96146262e3c205b44b37e0b48f879596f4d83e743fd1af51" \
            "80010000006b483045022100e7355267b8e14884deebb3da3ffb97dd174089abca3057daac984451bd0da3d402206958b334" \
            "ef86e9cd8399422a19da7f24629d3ad40a4b882774d547582b344213012102b505ffbac2acc21e2862e11cefe3bd01831338" \
            "d3af529c8d19f3cae02f59f083ffffffff17615e4a4a6a3de9244802c42009f9c8481e20c76e134e299e4d2e8fc8f5f8c94d" \
            "0000006a47304402204a4c2c28bc7dc8c053070ff6a62170178428782be1cd71936001b12526b94dea022024bb94ca991dab" \
            "afeb67e73d062ff4042f676e6dbc15518f6851c53f5cfb5e5d012103ddc85b8d0d1e4a42943c8f592245308d58aa7094745f" \
            "c5f0f169de10e5158f41ffffffff1935d3413d82af1afd45685165a59c34a695c523a28d5fd3da50eeb4043df3eb2d000000" \
            "6a473044022050a173f1f36cedc27429a85c8435bb41229d799f00feac10467f82365a0bb16e022018c3b16ccc27ab025cb7" \
            "6d706d855db46347cdc96c4fe17edde26a3e18d8adbd0121028491b5eb8192dea95851b1282e0fae99ba9736aa5ea72d5f03" \
            "275786beec748cffffffff1935d3413d82af1afd45685165a59c34a695c523a28d5fd3da50eeb4043df3eb2e0000006a4730" \
            "440220160f12761a3a57bda29673bbf9f8b6acd3b50db20e0461e9b14fcd65f4e4b9b202205caae541929a2d5bf2d046ef63" \
            "89df8e622d9c96b4cee62ed6bfcc07bfa52551012102e9513b5c34dab9fe9cb1b06bfc72c9d9ce445d5761b9f5e4ceadad27" \
            "82e20b61ffffffff1976a23b687039a41ff450d1d76406194d8a57e28b3f7ba0f74385cc518561c7030000006b4830450221" \
            "00dde63a71f20fdc2fc23ed7f0cdc8bd0ed4972ec87b3dbeb82d074bf4fc7088e5022079488b4eaa7248ca501bba1b291156" \
            "5edec8af8670b2b952470be47e412dcfc101210224a98f02e5300e71f61d44a12a827e12740ea0851de5c66726ebbd8a924a" \
            "7e0dffffffff19846d3613021bf9ee87a1efe5360191b5497cc19d6fb8dd20adb8507a95e733090000006b483045022100b4" \
            "9d31f0261d6bc15fb88bc2616b0ffb89d613097d4584b6309d1f25ec0d69cc022076f5877cd4d328f934cb40738a54d78e8e" \
            "18c5cda0a66134f1095993a8a6fa4b0121028d57102861326c5172d67f5e404f9d5ac6b1be18f6362a9209808bcb5a6b024b" \
            "ffffffff19846d3613021bf9ee87a1efe5360191b5497cc19d6fb8dd20adb8507a95e7330a0000006a4730440220041495a3" \
            "c0f832509eb8508f1bdeee4930c4ad4fa1031005ed7d1b432639a8e202202317054c62322a6c8ac0f87c1ddccbc7929bbd5c" \
            "7400f59445c855539d47ad70012103332816130c1eded386dfe1941f4fab7ebc3557bcf81e9d2240f3ef8c5b2dfc41ffffff" \
            "ff19e23ed80a1adb6cf47f9a89f72fe23a33ad7bad78144f0d4de56eec8e4fa5b2300000006a473044022048ad7b3fe9a36f" \
            "812bca2b85397f89837495c5de3252a429a5609393e0b4d477022053ccd7213d884b8347afc89a2b9ab542277e0f28129025" \
            "0af7f8d22dddf0685a012103e02c12c5f3247b636bc0f4ffd0fdfb24e65b41646c56951050c78bfbf3377f89ffffffff1a03" \
            "8ddca5c41d5dc31864265d477c9a1acf5aeff239513fa039b57e58e5b694010000006a47304402201019b749fdc6970e7dc1" \
            "d5ad767eaed4005f59f60fc1416ca8796e7cb557906b022017605fe5fd2d9ff9c58ed08d2e9f0f21c6ec516f5514c6440921" \
            "f9d04f20a494012103d0e6edf2a3f479864e819e6de420722452d45972e44b96f1810c128b9cacef82ffffffff1a2b9e3b49" \
            "a86a06404518b50fad06872702fd0f16403df5cfb1ed9f2a41009a120000006a473044022009f27a7053ca4755d0ead62f0a" \
            "59372766ac14aaa9ac2c10efafdd72800cb4d4022072e3fca7e53e1af95f102d8a17f6021c6d76b6069d572801f80fa58439" \
            "d1a2e9012102f6044f14fd4b6d8023f2fc5b2dc7197e07564576b4c071ad780c8148189685adffffffff1a2b9e3b49a86a06" \
            "404518b50fad06872702fd0f16403df5cfb1ed9f2a41009a1c0000006a4730440220309b1175024befe7dffb36e19520b132" \
            "97f0ca37fb05a12319a8dca4196efa91022020139ade2fe3ec4650f1013b3b9b26093a133d4f69cddd45740b6250bef9a167" \
            "012103ba242e44c4dda1c8562576603b90e9ab1f34841bdb3e75a9b1e18d88c6b2cac0ffffffff1a42b09dd9bfbea72aed8c" \
            "44107e23ba928828a9b32e171f7833d5f4e48d59bd010000006b483045022100b239eb0a1111b2ed603cd29166a327510233" \
            "cb9a315ba5fdd46c3ccf13ad850e022001aeab0cf26f893acb3f5195e87ce860e25fbeb80fbd3aa4f096cc523b91a8e60121" \
            "03e3b7204ba02088d40fa6c918c9d9a0ac032c3fafcd8c50b7677c938ab6b64bd4ffffffff1a698fb040491f0f491d592218" \
            "966aa98c63e588c01276984efb8c1a3e629dc3010000006a47304402200f00eee7e72264d291d8a318cd2d0a94fca3907c10" \
            "df71d384644dd1bb1a5d8e022024bc0b4ab0aa71286812929018e2df44f3351a09fb3ca53299318c8a16604559012103b991" \
            "1f0cc9b3b501883303b9df90e30575fb85b9898cf6ddafe6d683827511ffffffffff1bba053a4e895bb2ce4c57afdfa7c0b4" \
            "00ee00bc105a9d61209a6231906b789b450000006b483045022100d5b3f3918ba2ca87a1171a906346609095bfcc714f56af" \
            "8cdbd3b120f956feeb02204db8e8d59319fda422a7dd50e67cef1398f07107662c78ff2a9a5bdd65ba9fa5012102dd150d19" \
            "b738e96e2bf14ea91182222a9706e6c9a3c26287df631ec022262dd4ffffffff1bbc3adb062ff491128b8639864387161f05" \
            "ce166cbba93b42b02b0474511ed4000000006a47304402201c1d1db0dae9c3861097ebd584d2c2f68404d0720f1ab299f482" \
            "3e36200a555a022067c9b86a830dad2511e38469b5b47838816c323ab38d56bb30d0cedb289eab950121036460bf7d8606c1" \
            "592b624be9bdf45824c02d7897744c4d0556b62fdbeb914b70ffffffff1c049fa7081d26c2440f6e9cbbd347434730f08d3b" \
            "48ff0061c0e4f728dbc4a7000000006b4830450221009ef6c82cf6abfa6339fc440be77891306c84219d2282624a1f955b91" \
            "91f78f20022021603d226d99acfa7c41629765d025a19a76c4fc4f21da08ffefc4236cf79f8f012102adcc9423a677f7bac5" \
            "75973a5187fa58a778e841b3b390e3fa611269dce2e38dffffffff1c2ed63be627dc6f03c0440576379246a3301ae7169482" \
            "7fda0010f67bad8e8a0d0000006a473044022042c7e4e670460550a6a405be05c67f20852ab329a0fd505cfe89070a87fd1d" \
            "0d02205a9c6eed3bcb3c3727f45347e8c463ee3847c88fbbe6e4ffb4fe7619cb4a9801012102d4711440734516a1f1e8cd49" \
            "8985b7622d7c9d72d3906e9c91309fac8537f0ccffffffff1c453b90d77a8e63c0dd863e1fed2bd8434c78b3701af4878159" \
            "88b81a8e39470a0000006b4830450221008c6c7c90b17e4f5569fc7fa620745aa6c459cacc4af14513a1090b59cae89b2e02" \
            "201aeff5b216e5b47400ac163acb5008d68a88ce950772d48d468ab2b622471bdb0121024b7f8147e2caedd2c625d68917ab" \
            "37ebed2b6f2e0ffb68deff678889a639d1ceffffffff1c4b2f0029f597c5310fcd4d2a284bb6c9859c04b7f45a63825d154b" \
            "1b0f8059270000006a47304402204e668c026c7169c2851c862e283a8d4569ee88766fe97d555f81d94c8aca379c02205c55" \
            "605aa619336684a0eca59d2c9d972ba992174dffb06ae52dc660a6df05ef01210206f2cf65674b11f34196d2c3f50d82f280" \
            "045498858040a0b966b8cd9d56e3dbffffffff1c78b4dc5c8e13ded6f02fe9ea78fd09caee0336d8948c28cfc5243f6405f8" \
            "e7340000006a473044022037f3b1c519fb00f729078769dd2ee6037d1890d80c7e8176fec69e462e752adc0220407bddf5a0" \
            "3f52c57b4c6dcd10dabe16c6dac9f29947a9544360a7da84f679550121039509a8c45a916a2e27abedaca12dbd28442a3abf" \
            "52b5e50065193689820aca78ffffffff1ccec36931ce98c54a60bfd071608f5989837ed2749b5d74c21f195b89ae1b560100" \
            "00006b483045022100f548e044bea3ba217096908c8bf6416c84bb74d6c4d8816f90f61fe5c8c1231a022014d0d389424922" \
            "6183ec8ea2e0f523d15c0dee36946172b92d0dcb30355f5e3b0121024406f2ba5cb2ea8acf596a9021157f980ccc9151abc4" \
            "321ee77ed005af33b283ffffffff1d23f56d1661676cf4a82ec524aff8955409b011601dd1bc5c18d9b44eff1cd106000000" \
            "6b483045022100f47c07cfee203f440a5a03601bc2401abdabeb324f596dc8461f256e2ae5429f022049499d980c48488b7f" \
            "6980b910ec5d9ca4abc021ddb6ceece91d36f20b43bfb7012102cd80e1c6af3bc60728ab586a5ee24eca4ace2cbb8c1df2e7" \
            "5b3c9e043af3e35dffffffff1d6d3d789ff529e4640e3e431ef69dd5ec07942499e694ac3d24cdb129cafc61300000006b48" \
            "3045022100d74326b982422c9d72c1e687a508bc30e30d2bdb4e56292d9b7ef6be3dd80c09022072a96d463c7320039f1c85" \
            "c722ab37d0246104ad928687949cfe20d84c3a548b0121028a3df868ad756cba93967b8f0f050ecf4043f5ab003584b6d9ac" \
            "5f332d1933ecffffffff1dc3e6bb5dcbc7b76c0fde3e46222eceee9c9bac8d6f197da688a4f44dd554d1000000006b483045" \
            "0221008f199613f5e8687278a0452a0d6b189f07c04b2738bb5fd10c7aa0eff84fc548022028a223848d18e0060ab4c73625" \
            "441282b78a33e2df264ccfcc7cfa908eea365601210388b4705e71a63a56d5743295d53da5463f460c4f2af1b2b836cb3d98" \
            "573b4b9bffffffff1dce769713116d4b77c97cad47ac9f4b622de520db2726bfc6845bda30fb87d6000000006b4830450221" \
            "00c2fee5d03afa7ee54110b3ad58e498d4288f0e3964bb4c4181f0a29c2a1b81680220079054da0e4c531cd4258e13bc335f" \
            "d8fcb35d6b63d5f031055b4e656965fff301210346174d4a8c8b97b7d6adf9e7914349960836ed672e0b8d8d8f96456e22eb" \
            "8587ffffffff1efb66370c1c46c10b8a64ada1be325e1a57e5a6d11db11a92b4e6c6153ec6532a0000006b483045022100b1" \
            "cfde44d83061399ee2d17255a6f85cf0bb06215cc86e815dd1e6adcc8ea07902207cbbda79537e8ae849a41fdfbb6e7f0f9f" \
            "1ff471662041e2ea535a09a09fc40701210348dbd13b24a1f5b69fd5b0e233646b00d005acfe7c2db88ffa017700af44bdd2" \
            "ffffffff1f3521a0cd4ba9a475af228f3c3643d05a2acbc68d427b477fb6ee522f0d65e3090000006b4830450221008e9821" \
            "bb1c1cf51ada24a6d9c92a4f79c7e36cf6cbcff1619c1144528c667edb02205c9c200da384180d3d9ccf52f90cdf59a5f843" \
            "eaa15921e45572d924188f4edd012103b39f7450ce81a1883d2ff90b8c3c5a37483be09f7088bea86bee6b6b07a1d0e3ffff" \
            "ffff20027f4ff555a42ed57890ef43a26c197d4e8bfb9ab7fa704a66c9ae6fc3a238230000006a4730440220319bdfe2e76d" \
            "b3f1cb7a676d76f0dd878ac8ed7f433c756b6f386fcbf07e97ff022046e64a0d6055b458635d3cbed00648d1353ffb7a61ea" \
            "cc3f8b3c3152fb280c8f012103878c510d691cf0a72b0ef1f3eb4a1efe29f01a24ce54b9a143620100b37272abffffffff20" \
            "5d1b7580b5536841ac5ff3d3a8d97ec8ee3106015106027b8df371ad30e95b000000006a473044022011e8965a98e5e82724" \
            "c5319e1593c00be25771e995b35f8f729822146a40a9af02202966f70774ec2fda967162bb80235dc6cf93bd62ca47f3f905" \
            "066d0c727deb5f012103266673efe79c3d7a2fe19aee8cb03bf9423f4f5a383a9bfb3c35c25e9958ac64ffffffff20674fbb" \
            "53a74a497697bf955cbab5136f7785dca41c410f1cdee118568b6a5a010000006b483045022100d7ae5b7883608b5e24a5a8" \
            "d0738c4d59e4ce73fe6dba6074437995e80baa07e702202e89dfc0b9f76f34e7242a0f5c55a628d36975c1dc3d6d8411169c" \
            "432fdd82f1012103c241dcdb878d85572cecadf3fe39199a907b72b2b67376733bc135e53ccba8f3ffffffff20ba6c3fd63f" \
            "4557f914e5113f1056379838542948b071b28b382d7880781861000000006a473044022003428fff3f033e4e66f4a31663b6" \
            "0d843fa05fba0b8879bdb34b503b08f5f9820220099e64ac924a5a5d0cb38d99072cca51b8da740787864ad657785e3c97d3" \
            "42e301210218147440a8664223a05d1e88795e73742fa3a8534a1a688427411e24b0ee2363ffffffff2126401e409a28a46d" \
            "83863cc53010bb18f43b0e41d627b2573665b200649fce3e0000006b483045022100b70ab671091ac9d4ae8366cb63f37224" \
            "81048d0032b362879de68f5f142c6e4c0220329c229c01d7b1ee597f75a7b4ed233a3b53614b0419fa416cd5bed2a434eb22" \
            "0121022e3166fd037aa0dde4113e25be6db58c98c084d41c77b6c57a19fdb746aadb52ffffffff21a5f42a8f1b594e050427" \
            "2e81ecaf3409414f6c754f6d6d001862ed59fdefd50a0000006b483045022100bf262fffb5a0295d62bd47b9ad9ec74f808e" \
            "8ac2dd8d2fe904f83fe81008d82a02203e5a39d55482a3aac085409156b7deb61ca6464717c3ad08f4f09f3f11609b540121" \
            "02beb68fc19987ca5933548820ac4ae0e317de57b977843bb085864df573fd11daffffffff21ab744fbeffb8a7f884cefb6d" \
            "7164d9624db30a694da83c0169384b9b62f76a0d0000006a47304402202f9095200bcbfac4a21ff8a39a169ea4b75488407a" \
            "995f411a362041d81783880220278f4e984dafe35adc3bfb4b24e6cacf6e632acc686efddc7374716fa8afb617012103be2a" \
            "51524c3b8e1252cc1f68c1edb79715b7a8d88c4a455684ef6d9151092c5effffffff21bfe20030922550f5beba1b75fb1250" \
            "b6da67c5dda185740ce03301d26d8ac8010000006b483045022100bbfb342e26a07b63ff0e778a13c145a721003bd7bfcb77" \
            "2a590799dcc2fb5de6022035b6cd3431e00282fa43da28323e417be0a31450d7e8b926f86d74754dcd760a01210250bb63e4" \
            "fd99058aa6a598070e444f14492130d8bc3945b57eb4d6f1c852318cffffffff22a83a3f775833bce0e426d32e96338c9ce3" \
            "a6f659f0c17dc7a35b568184fa5b010000006b4830450221008eb1540ad8eae4a09c194a7cdd0ddf74d250375e363a96700d" \
            "13f5242bf3e92e02203862a7dd53f3fd6812823e18d903a45b3f60a0a7dbd36c4e97787023271d739201210246f97a4262ef" \
            "7216c857091d486b982d4cd00b0d8a9d929de405ad2fc1120ae7ffffffff2326f47683c95c922ea9149cd0d19c4674de376d" \
            "f3f037b4e4e393ab6942fb72460000006a4730440220451129bf8ecba76381cc6784ef8c8965ce25071be70f0e415a38fb78" \
            "b252072102202bd2c319785e0f74fce2d48a677a24460484eca2aab393ac5351a46041d5dea601210349d79f9687d1d18839" \
            "8a984e1e7362d12809541783d6337c123d1145fc6bff73ffffffff2326f47683c95c922ea9149cd0d19c4674de376df3f037" \
            "b4e4e393ab6942fb725e0000006b483045022100a2ef8a211c034e5d7035906048c7eca61eed81d2ad51964103659348d0aa" \
            "de5d02205e285da45948a9a885afd70904038d12d09899328dd98a36e05cafa3937af25f0121034d0fc8fe4c7b090fbfb7c0" \
            "704f4366ede606be538b4211a597559d3eecb4da4affffffff23510c26ea81a2a45bfd172f5a6e37c0bb4b0603a2ff4f310a" \
            "5a78ffac983e89320000006a4730440220491bbcdea391a543c7607e2b6dae90f4a163865923fd22781064df002815b5ad02" \
            "2068efce83cef4729272e140ea68cb586f5fa2de026da3eef6f36ed8c39bcd6cb901210249fa1d14d8703534da46631561fd" \
            "0b054367ea0c6f1ee554344b978b7b29e95fffffffff2374f11805634d0c23ca548bb909095f8f34104292636bf2ebcf0665" \
            "ece59e700c0000006b48304502210098617821696203b740f2cdc75cbd64f5fb5e2df9d15313c80aa29d46583ed28e022042" \
            "89ad4f58079f4aa0ac716d06363f5d880f824aaedc2cd87c6a037acc4baefd0121024780d8ebb1d15913dd2253d234f9b7bb" \
            "60ae6364aaf492482f30ad5127dc91e3ffffffff23a0b0cc247c9e06d4c6f33dcfaaca5fb886caaf46532566dc27c2a68a34" \
            "a0d6010000006b483045022100bf7d058dce64fbae72641b04865ca1502e2f1218140ee03fdd73b3d63505636e022030de24" \
            "5bb0091d2581c0e354e8d5a0676a043e4cc60313f1e3003cea5c5507a8012103e6e8240c4104d1cdf2bf412b58813d437a43" \
            "557b634e4f70e5b4df55bf43f5f8ffffffff23ca20733eb7fb88576f445f7bb8c55ca65f0d96a1a2578ac35a0c959d3c0421" \
            "340000006a473044022001034b5a6aae9b3a9af6a92049c712242d03d821fd1d4edb7fea03a549f79b0f0220243cecf164a6" \
            "43efb9cf51039a7fca89a206c2eaf05afeb975a3ec0999279974012102fa58574eaee43ae08da9e1d5c7f19918007b915678" \
            "51cc891ffe40ee287cacd4ffffffff23eed40ebcea7989f26a7f1b371472c12d5be7ae4c6b0e3fea3da212ba0e5108100000" \
            "006b483045022100d3b7ddf23317b926a924f288294b8fcda312cd10a61e669e207c4dfd8351a9b502200d61fdbc94d3799f" \
            "d418e7a2723e0bb5b67dc132efd682832b55b45f791bea80012103abd89013829393207a7351fbdc7eb25fa04ac383d092a0" \
            "b246a26a22d1a32786ffffffff24ce91560deeba6677187ce29d1b8ddc8db9aa6a0109fe2f0a327ee22269ca11010000006a" \
            "473044022052088b180a92758765437e7bddf363869af990d2045fa0358b2cf2691869fffe02201b3bcb51833c5230e5edcd" \
            "1b80199a04fc099807a72ab6669d4a17923867b73f012103def8d4bcd6e9cfc121e37b5f142431ffb479cc57abd147839b29" \
            "347305f8bf48ffffffff25968e19a5d3724b4906a28111246030ca0ba59233fdeb88cee660ba1e772bc0360000006b483045" \
            "022100bec887d16bf8f8d95fc824deab0695dd11925b0aaa4ced57e4a60299518fc45c022002dbac507193ff75f1d443b2e7" \
            "cb0e108c9e6c0a020fa424746f133f49590a47012102a5d08a7d42b0ddf708e64d549760b68a3a1894b6851914166883b014" \
            "e14bb70cffffffff25febc51e88c82d12d55d40c855c7732b0951561af54bbe992dc703d0f7127a1120000006b4830450221" \
            "00fb71b679e1a03ab793cc215c2234e38aeaf4274e577c66f165594b624560e6bc02201fd1d480132901c92ef6bffc70ed20" \
            "55186771755649b9f00be8512c22322f10012103ec8c7a8b733f091b1996be3a678a4a7ee6d020aa00146aa61cca5e181cd1" \
            "c92fffffffff26a4bbd32fed7448f1e72b995fe225db601f7bd9bc04541afe2e3faab0854f170a0000006a473044022024b5" \
            "0f866dc660869a272f5fb98a268fcb5f4e2293b33771c9a5ab1fe8f8a2b10220100c481a825afc6c84911064bde22673b9a0" \
            "b169ec2910e6c87834f099bc82f201210266586c2f0d252aa2e50eea3e5a395574fcb5408ae7280e329b8e8911f5a56049ff" \
            "ffffff26a4bbd32fed7448f1e72b995fe225db601f7bd9bc04541afe2e3faab0854f170c0000006a4730440220385bab39a4" \
            "65431bb23035a6c427e17773d2339a4e2effb0e49ceb87d41b925e022024a0d9251a51f616a1677e9f5657460e109ceccc29" \
            "7a29e97fe77fbe5bad2f9d0121036b01ede91f6ea318a61d15037188f337d0bfa7d1db2e013870b89e12f16f09f1ffffffff" \
            "26cd4c1bd05535a60cdb5366d7055b1faf3f3406be071827572c3b74687bb0933d0000006b483045022100bf5928f14c8d26" \
            "5ec2df462f0884c2477b33c0021fc9e0b055025be9bdf3bd3a02204eedef727459a06b37bc66663294f430dd18560b910f16" \
            "a533115da2640fc0d10121039a0378bc3ae082642abf99218fd31f308f1aa7b8dec84c4ca47ec282ac13d460ffffffff27a4" \
            "e8335c7ed7d549c758f32b82439ee92764506023ec2183c85b5498a3eae2060000006b483045022100dc347d6713c85889d4" \
            "ee7a9f07df480304417f8d6c1da4e5673026b2595dac4a02204c3f7288a9f8052ec05eab8e9dc6d46997c377923fb03b6a84" \
            "3ebb8191ad74ec0121022ef9273cdcaa2c31f79ef431d96013098f10a3044a2637dcf1b5d42a9b71c6e7ffffffff28c9dc34" \
            "ad391f269c6a38b7576b00c195e0cd128ba1b2c67e329029a25daa9e0d0000006a473044022040aef412fa1be53a245b600c" \
            "a5ac8017376a796d2d56f6360ff212aa01e3599402204d6362828c38e95b37123371fd15eaed87654e7f0453a3dbcb676717" \
            "af2d56ad012102d5e48ba3bbc0dce4e2aff1066d13c3fd4d1a0fbbe7fe22e39fca692ce21e4a80ffffffff2a2ca129b5ee4b" \
            "02e5ce0ce8386f465c7e37036e85230c5738c511a0f7790ca8500000006b483045022100b3f70437e0ee2b8d1fc8f7cee9e9" \
            "20a8bbe3f80cea153a15741c9fc6f5453af502205f68f5b4ec982e2acea68969f1b00880a10294f7fec52b9c9516a66a745d" \
            "5d1d01210294d7c7d626a99b9164dd250c3077dde52717fbb911ddd5c4001de87be3ae5bbaffffffff2ac3bc7fd5cb57972c" \
            "6ef5b3ea3a2ebd42d4e64323252eebb12652cdd5dc05d0110000006a47304402204d6f513985a45b53eb4093a84e25e41a73" \
            "a4e6c126196d94de98b45c74ed9688022037a457970cb404c858a750ef8826f5376683ab186e393f90439b16363b0d8b5701" \
            "21029f4b05c7c3e1e6facfe655f7eeaf2597e00236f01a37b1655de35e64fb2dae04ffffffff564b4a6800000000001976a9" \
            "14e480eb7908c440f61a0e6a8b3aec1db50b2c5cf588ac582107000000000017a9141531f346c61679bdf63747ffaadaf2da" \
            "0696402487e03cc801000000001976a9145bd46ab304b231dd36f7a7c159666ecf5ed0be0988acaadd2403000000001976a9" \
            "1433221699726f1b39cb115d2ee29b923fad9dd29788ac6ea765000000000017a914b4200da0408f01666ecad3ede79fc525" \
            "b8fa6768879c2d0e00000000001976a914027960cd0cd19576be6e822b3e2a80ec178299e988ac809698000000000017a914" \
            "d4d1d5e6c1e5c95c6c45a1fda46b794e0272b89c8712714d00000000001976a914f34291cee1f7ef57b979361140e8f2f2a1" \
            "9f18a888ac404b4c00000000001976a914e0c9054410d37574b415d55e247538495bd9945f88ace0c35b050000000017a914" \
            "1da6c37c6148b956db4332492ba74b87b7ca25788780ee3600000000001976a9141aca70a6fcd037a2b97afd620941a940eb" \
            "362bee88ac59001610000000001976a9143e1c26ba4ab65ed9a4c9ba8f1e751a05f5635c1b88ac600d3477000000001976a9" \
            "140417e75c489a09d4a695bfd9d7249e9858fa871788ac8834c7010000000017a91431b4576d37322ce4ab3f80fddb878480" \
            "006f63e88768650f00000000001976a9142d6837591a7711f80d2c24bf2a283e7f1438d73188aca28f6100000000001976a9" \
            "145fe424595809f26d11f936e40d5213e761ddca3488ac3b7fd601000000001976a9146db28b906505e68b29531e93baae87" \
            "7f93b5427788ac20e27604000000001976a914a4e2683d4b532df23d09f4f6da081b3b01fdfc1788ac1097f3050000000017" \
            "a914bb3dad3b5d82944c2b658f6e8214a6472a656e6b87e0962a04000000001976a9144357e7904059ca11f513a50bbb531f" \
            "982ae2fbbb88ac60e27a000000000017a91492a567791e3f992e3ef48e26f945e0371c4f75a287d86081040000000017a914" \
            "77e120c2f8c768804eee5afacf7be1608022e7a2875e68bd00000000001976a914b18eb82ce95bebe2fc91d882dd6d679f97" \
            "c593c988acaf9b1200000000001976a914b70cd484b19170b6964a6f5805ce8721242ef78088acb0941101000000001976a9" \
            "14209b1e44aae6c02a78c12ba42c3ecfc10d8bea3a88aca0bb0d00000000001976a91474091936d823f751f522065911ebef" \
            "dd553ade4188ac6b4b3800000000001976a914b6104b773a664eed55cb6ebfab44332f19975d6d88ac60e316000000000019" \
            "76a91405cb008417e794dd11502526f59de541c307179f88ac36661d00000000001976a9149ed73d57eb2637acaeb742c23e" \
            "ece52cb715b62a88aceacd2d000000000017a914a2ea825594023f210146959e8a2077f632d90ad28736ec87040000000017" \
            "a9143efff5d06c0135ae7f5a9fa14ba31765313ef2998780c26700000000001976a91449bcb867a880a03b77b77cbcc3cbdb" \
            "fcc043753888ac20a10700000000001976a9149808542b849360606e82d2165413c6520cef9bf588ac6b7425000000000019" \
            "76a914c234d90ff84945b53bf1671469fce67a29e45e9888aca0bb0d00000000001976a9142b16f31807f435d7ec0e011d3d" \
            "79c3e883d8afe688ac7ff10900000000001976a9140f96e8d900da242b279f23df4611ee053cbdc48c88aca1504400000000" \
            "001976a914f9e34b3f3d59165c56dcb029c0ccbeb59e7cdd3588ac9ab776000000000017a91462060b7791a8025f4542082c" \
            "d923d74c625805e287fc4afe0a000000001976a9146c3b7b75e4dd5094318cdc986a8364726fa9154988acd5640701000000" \
            "001976a9147d6b7263feb31eef3e715c2c9b8abfdb2c2bfc9788ac3a0e4d00000000001976a914f64b5921d023cf863be357" \
            "fe3ad09b78b8f5688288ac1df1c901000000001976a9144f6df6ad28d44dcb4698b543bb304c08e726e5fa88acfd12c80000" \
            "0000001976a91420b7a410fd0fe3333f739d57698cf27485501c5688ac4253e8010000000017a9147f13f3fe38e20f1d3673" \
            "84bf544ff16dc74c89ee8740ea7000000000001976a91488b0c4aaf4912aa35d5656a2e95e9eb7d9a84f1388ac4a45040000" \
            "0000001976a91469017e45dbc0867c04251904e0057ad8dcd2fc3488ac958413000000000017a9149ae029f5cdded67bdde2" \
            "08934a1fe7399ae99f5d87693b6c00000000001976a9140525af196cddeb898b4488ef033e40fb770df87c88ac005a620200" \
            "0000001976a914b602794ede2eb96d2bc903d5775d11b60109a59488ac80f96200000000001976a914158f1ce6084072de6c" \
            "392595fc625b7278d1e19088ac0cf22300000000001976a9145fa0086daf0e0db6f5d611a259e24b1f745dd03d88ac79f611" \
            "000000000017a9149d397b074ef363d3be74e45d3794e550247725a387c0dd3e00000000001976a9144eedd56c9bebd4159c" \
            "b2fdc35d669f90ff29c5e188ac64a945040000000017a914188b945c713e6121de90521cf1a5a3337ba1a0c88775954f0000" \
            "0000001976a9149107b63ddea39d746953f5fd63ea5e63c5daaae888aca037a0000000000017a914a0ba6cf5228d63ccd0ad" \
            "1f02da7d1b9ae72b246e87e0fd1c000000000017a9145852d41f4720320296ca9a6741f120474ac19a0887703f2300000000" \
            "001976a914952c0e565704f7d7939070ea6ad09991d266286288ac60a62f010000000017a9142b42e2ed1632f8d2ed843407" \
            "6b3735341898b068872077fc02000000001976a91421a630014d30e6c5932288d4329192de5d28187488ac64314800000000" \
            "001976a914b6055fb3bc59d4024397a55414b202a7e889b60088ac3a695d00000000001976a914ef03abd2c21e0b9727400e" \
            "150b33890ac9d3df2e88ac94db4700000000001976a914883f2ccb7019c2bdb96672338484f9489146596788ac9df3d42800" \
            "0000001976a9142ec558200e8f6d781ba235af8e40e7f6c035e5c788acdf655100000000001976a91439f09f23df5771ff47" \
            "cc02d820ca59b26cdc97c688ac20402c00000000001976a914502599ba688ad8fbc3cf1dd68cf268aec6967ff688ac2052a6" \
            "00000000001976a9142ed2288261125390da0bce7d105d8f9b3a2775e288ac27b75011000000001976a91448c57dccafd1c9" \
            "1211d273fa0d6adf6bdba2e83488ac212fe400000000001976a914b6427b1d47f7cc8b131f8c1272b25318b1af8f8388ac20" \
            "d613000000000017a9140ed00cab3d38d85060f36f4ab2e76f89928610f08780841e00000000001976a914edeb95e234d036" \
            "53f699869ebfbe066ca1dc590e88ac54cc510a000000001976a914fc9f2d98d0672464add08bfa8a93cc71419f221888acf0" \
            "2b0700000000001976a9144c9484804a43ddf2f05442e79c6819874e258f2488ac80f0fa020000000017a914ffbbb2d749fc" \
            "446f2d3ec9202096129dd76e085e877c3f4400000000001976a914263b4f8f68485a8beb5efb3cc9073f2ab8cbf9f188ace0" \
            "0f9700000000001976a9142a145d5d67685371aa4256355a6eefe89cc1232388acbedf3f00000000001976a914721b3caaf8" \
            "b439692a4f21c93acab04cbe10e6c188ac0545bf06000000001976a9145dd6a8c44126addc3276737e9ff187271b6794a688" \
            "acab236d00000000001976a914446ba6dc85bf60745e1d303638822b52abf0179488ac0b022107000000001976a914542ed9" \
            "04e9b68955a8a38ad6d5798e94af43a7fd88ac8fb11f00000000001976a914b3e64d594d065d44958d21b6aef7c39e52629e" \
            "c388ac2e407a00000000001976a91483090cdca67c345f3e2fa52d1a99a7b3cf0d91a488ac2087b2000000000017a914bff9" \
            "82ce59f11d4f6c59c9a41560a1bd10521bf38780c267000000000017a9140526bae392f9c5574c458c8da1131d7989994f82" \
            "878a2b8600000000001976a914a9dc0d1398fef2dbc68a233c45c7710aff9682b888acf751bba3010000001976a914e71deb" \
            "e251bb26c7e757d9ae265da6e5d00f31b988ac00000000"
        t = Transaction.import_raw(rawtx)
        self.assertEqual(len(t.inputs), 201)
        self.assertEqual(len(t.outputs), 86)

    def test_transactions_import_raw_totals(self):
        raw_tx = "0100000003efdad76b8da190878c1de4c92fd4aaa0a287984171a4398c1140df11663cb84c010000006b483045022065db" \
                 "71606b84edc291eb2ec55e49ee2fd44afef8b20b4ef88fc2a01c2ba6e963022100dfb24228f2f80574d64a3a2964c5b3d0" \
                 "54c14f0bf18c409f72345331271b5020012102a1e806a0c19aaf32363eb19e91a901eafdfc513d13f632f4e2a39f3cb894" \
                 "ad27ffffffff670fa789f11df8b202f380ebc6b4f76fa312f6bfb11494811f00411d7bbb0ae0010000006b483045022100" \
                 "9b5fe2b2bff2a9801725351ae2a8eb410b10b6fecb44edb442ee750e6825f1a4022038e19b3b0e3a95b4a3952dde87efc0" \
                 "49d4a72a4424872ab768f7fb3220be4c1e0121032256cb5a8e6d3c9354da72369b939a35febb80d35e6afb50e6f348c20c" \
                 "6c6c05ffffffff52dd5a0965f2d36850f3d2ddeb1457cd72e1cd5a325656af44a3c6ba9f2d42fa010000006c4930460221" \
                 "008a9bf9a1ba9b4125ac9b8cf10423447ad8c7ede3414028237c4c0e0b3b3dc4fd0221009f94721c04b7d4eb33bb1aad61" \
                 "daf98b6ed05dfbf5e3225ae9b3afe24b8924d50121028b04194cb938044761bb93d3917abcce13f910a0500c08e61bdaaf" \
                 "5ea29b5ca0ffffffff02b0c39203000000001976a9148a81571528050b80099821ed0bc4e48ed33e5e4d88ac1f6db80a01" \
                 "0000001976a914963f47c50eaafd07c8b0a8a505c825216a4fee6d88ac00000000"
        t = Transaction.import_raw(raw_tx)
        self.assertEqual(t.output_total, 4534776015)
        self.assertEqual(t.size, 523)
        self.assertEqual(t.hash, '6961d06e4a921834bbf729a94d7ab423b18ddd92e5ce9661b7b871d852f1db74')
        self.assertEqual(repr(t), '<Transaction(input_count=3, output_count=2, status=new, network=bitcoin)>')
        self.assertEqual(str(t), '6961d06e4a921834bbf729a94d7ab423b18ddd92e5ce9661b7b871d852f1db74')

    def test_transaction_sendto_wrong_address(self):
        t = Transaction(network='bitcoin')
        self.assertRaisesRegexp(BKeyError, 'Network bitcoin not found in extracted networks*',
                                t.add_output, 100000, 'LTK1nK5TyGALmSup5SzhgkX1cnVQrC4cLd')

    def test_transaction_create_with_address_objects(self):
        ki = Key('5HusYj2b2x4nroApgfvaSfKYZhRbKFH41bVyPooymbC6KfgSXdD', compressed=False)
        txid = "81b4c832d70cb56ff957589752eb4125a4cab78a25a8fc52d6a09e5bd4404d48"
        ki.address()
        transaction_input = Input(prev_hash=txid, output_n=0, address=ki.address_obj)
        pkh = "c8e90996c7c6080ee06284600c684ed904d14c5c"
        addr = Address(hashed_data=pkh)
        transaction_output = Output(value=91234, address=addr)
        t = Transaction([transaction_input], [transaction_output])
        self.assertEqual(t.inputs[0].address, "1MMMMSUb1piy2ufrSguNUdFmAcvqrQF8M5")
        self.assertEqual(t.outputs[0].address, "1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa")

    def test_transaction_info(self):
        t = Transaction()
        t.add_input('6a20985f23805edd2938e5bd9f744d36ccb8be643de00b369b901ae0b3fea911a1dd', 0)
        t.add_output(1000000, '1MMMMSUb1piy2ufrSguNUdFmAcvqrQF8M5')
        t.update_totals()
        self.assertIsNone(t.info())

    def test_transaction_errors(self):
        self.assertRaisesRegexp(TransactionError, "Please specify a valid witness type: legacy or segwit",
                                Transaction, witness_type='error')


class TestTransactionsScripts(unittest.TestCase, CustomAssertions):

    def test_transaction_script_type_p2pkh(self):
        s = binascii.unhexlify('76a914af8e14a2cecd715c363b3a72b55b59a31e2acac988ac')
        self.assertEqual('p2pkh', script_deserialize(s)['script_type'])

    def test_transaction_script_type_p2pkh_2(self):
        s = to_bytes('76a914a13fdfc301c89094f5dc1089e61888794130e38188ac')
        self.assertEqual('p2pkh', script_deserialize(s)['script_type'])

    def test_transaction_script_type_p2sh(self):
        s = binascii.unhexlify('a914e3bdbeab033c7e03fd4cbf3a03ff14533260f3f487')
        self.assertEqual('p2sh', script_deserialize(s)['script_type'])

    def test_transaction_script_type_nulldata(self):
        s = binascii.unhexlify('6a20985f23805edd2938e5bd9f744d36ccb8be643de00b369b901ae0b3fea911a1dd')
        res = script_deserialize(s)
        self.assertEqual('nulldata', res['script_type'])
        self.assertEqual(b'20985f23805edd2938e5bd9f744d36ccb8be643de00b369b901ae0b3fea911a1dd',
                         binascii.hexlify(res['op_return']))

    def test_transaction_script_type_nulldata_2(self):
        s = binascii.unhexlify('6a')
        res = script_deserialize(s)
        self.assertEqual('nulldata', res['script_type'])
        self.assertEqual(b'', binascii.hexlify(res['op_return']))

    def test_transaction_script_type_multisig(self):
        s = '514104fcf07bb1222f7925f2b7cc15183a40443c578e62ea17100aa3b44ba66905c95d4980aec4cd2f6eb426d1b1ec45d76724f' \
            '26901099416b9265b76ba67c8b0b73d210202be80a0ca69c0e000b97d507f45b98c49f58fec6650b64ff70e6ffccc3e6d0052ae'
        res = script_deserialize(s)
        self.assertEqual('multisig', res['script_type'])
        self.assertEqual(2, res['number_of_sigs_n'])

    def test_transaction_script_type_multisig_2(self):
        s = binascii.unhexlify('5121032487c2a32f7c8d57d2a93906a6457afd00697925b0e6e145d89af6d3bca330162102308673d169'
                               '87eaa010e540901cc6fe3695e758c19f46ce604e174dac315e685a52ae')
        res = script_deserialize(s)
        self.assertEqual('multisig', res['script_type'])
        self.assertEqual(1, res['number_of_sigs_m'])

    def test_transaction_script_multisig_errors(self):
        s = binascii.unhexlify('51'
                               '4104fcf07bb1222f7925f2b7cc15183a40443c578e62ea17100aa3b44ba66905c95d4980aec4cd2f6eb426'
                               'd1b1ec45d76724f26901099416b9265b76ba67c8b0b73d'
                               '210202be80a0ca69c0e000b97d507f45b98c49f58fec6650b64ff70e6ffccc3e6d00'
                               '210202be80a0ca69c0e000b97d507f45b98c49f58fec6650b64ff70e6ffccc3e6d0052ae')
        self.assertRaisesRegexp(TransactionError, '3 signatures found, but 2 sigs expected',
                                script_deserialize, s)
        self.assertRaisesRegexp(TransactionError, 'Number of signatures to sign \(3\) is higher then actual amount '
                                                  'of signatures \(2\)', script_deserialize,
                                '532102d9d64770e0510c650cfaa0c05ba34f6faa35a18defcf9f2d493c4c225d93fbf221020c39c418c2'
                                '38ba876d09c4529bdafb2a1295c57ece923997ab693bf0a84189b852ae')

    def test_transaction_redeemscript_errors(self):
        exp_error = "Redeemscripts with more then 15 keys are non-standard and could result in locked up funds"
        keys = []
        for n in range(20):
            keys.append(HDKey().public_hex)
        self.assertRaisesRegexp(TransactionError, exp_error, serialize_multisig_redeemscript, keys)

    def test_transaction_script_type_multisig_empty_data(self):
        s = binascii.unhexlify('5123032487c2a32f7c8d57d2a93906a6457afd00697925b0e6e145d89af6d3bca330162102308673d169')
        data = script_deserialize(s)
        data_expected = {'script_type': '', 'keys': [], 'signatures': [], 'redeemscript': b'', 'locktime_cltv': None,
                         'locktime_csv': None, 'number_of_sigs_n': 1, 'number_of_sigs_m': 1}
        self.assertDictEqualExt(data, data_expected)

    def test_transaction_script_type_empty_unknown(self):
        self.assertEqual('Empty script', script_deserialize(b'')['result'])

    def test_transaction_script_type_string(self):
        # Locking script
        s = binascii.unhexlify('5121032487c2a32f7c8d57d2a93906a6457afd00697925b0e6e145d89af6d3bca330162102308673d169'
                               '87eaa010e540901cc6fe3695e758c19f46ce604e174dac315e685a52ae')
        os = "OP_1 032487c2a32f7c8d57d2a93906a6457afd00697925b0e6e145d89af6d3bca33016 " \
             "02308673d16987eaa010e540901cc6fe3695e758c19f46ce604e174dac315e685a OP_2 OP_CHECKMULTISIG"
        self.assertEqual(os, str(script_to_string(s)))
        # Signature unlocking script
        sig = '304402203359857b3bc3409c161a3b9570306bde53f21a15fcf3d3946d8ddfc94dd6ff35022024dc076c7014ee199831079cc0f' \
              'df5e55aeebee7e90f4d51a2d923cc57f9173a01'
        self.assertEqual(script_to_string(sig), sig)
        # Multisig redeemscript
        script = '52210294d7bf6363ab715168e812dd5b64d1f503ba707746b55535b7ee8afadd979c0e21024b68079ccf41b9df944f4aa37' \
                 '7a2431a8df6efd7d7939d1f4d4f17376dc3434d21028885aad1fe0ad25ba2d9a0917a415f035e83e2c1a149904006f2d1dd' \
                 '63676d0e53ae'
        script_string = 'OP_2 0294d7bf6363ab715168e812dd5b64d1f503ba707746b55535b7ee8afadd979c0e ' \
                        '024b68079ccf41b9df944f4aa377a2431a8df6efd7d7939d1f4d4f17376dc3434d ' \
                        '028885aad1fe0ad25ba2d9a0917a415f035e83e2c1a149904006f2d1dd63676d0e OP_3 OP_CHECKMULTISIG'
        self.assertEqual(script_to_string(script), script_string)

    def test_transaction_script_deserialize_sig_pk(self):
        spk = '493046022100cf4d7571dd47a4d47f5cb767d54d6702530a3555726b27b6ac56117f5e7808fe0221008cbb42233bb04d7f28a' \
              '715cf7c938e238afde90207e9d103dd9018e12cb7180e0141042daa93315eebbe2cb9b5c3505df4c6fb6caca8b75678609856' \
              '7550d4820c09db988fe9997d049d687292f815ccd6e7fb5c1b1a91137999818d17c73d0f80aef9'
        ds = script_deserialize(spk)
        self.assertEqual(ds['script_type'], 'sig_pubkey')
        self.assertEqual(ds['signatures'][0],
                         bytearray(b"0F\x02!\x00\xcfMuq\xddG\xa4\xd4\x7f\\\xb7g\xd5Mg\x02S\n5Urk\'\xb6\xacV"
                                   b"\x11\x7f^x\x08\xfe\x02!\x00\x8c\xbbB#;\xb0M\x7f(\xa7\x15\xcf|\x93\x8e#"
                                   b"\x8a\xfd\xe9\x02\x07\xe9\xd1\x03\xdd\x90\x18\xe1,\xb7\x18\x0e\x01"))
        self.assertEqual(ds['keys'][0],
                         bytearray(b'\x04-\xaa\x931^\xeb\xbe,\xb9\xb5\xc3P]\xf4\xc6\xfbl\xac\xa8\xb7Vx`\x98'
                                   b'VuP\xd4\x82\x0c\t\xdb\x98\x8f\xe9\x99}\x04\x9dhr\x92\xf8\x15\xcc\xd6'
                                   b'\xe7\xfb\\\x1b\x1a\x91\x13y\x99\x81\x8d\x17\xc7=\x0f\x80\xae\xf9'))
        # sig_pk with missing public key
        spk = '493046022100cf4d7571dd47a4d47f5cb767d54d6702530a3555726b27b6ac56117f5e7808fe0221008cbb42233bb04d7f28a' \
              '715cf7c938e238afde90207e9d103dd9018e12cb7180e0101'
        ds = script_deserialize(spk)
        self.assertEqual(ds['result'], 'Could not parse script, unrecognized script')

    def test_transaction_script_deserialize_sig_pk2(self):
        spk = '473044022034519a85fb5299e180865dda936c5d53edabaaf6d15cd1740aac9878b76238e002207345fcb5a62deeb8d9d80e5' \
              'b412bd24d09151c2008b7fef10eb5f13e484d1e0d01210207c9ece04a9b5ef3ff441f3aad6bb63e323c05047a820ab45ebbe6' \
              '1385aa7446'
        ds = script_deserialize(spk)
        self.assertEqual(ds['script_type'], 'sig_pubkey')
        self.assertEqual(
            to_hexstring(ds['signatures'][0]), '3044022034519a85fb5299e180865dda936c5d53edabaaf6d15cd1740aac9878b762'
                                               '38e002207345fcb5a62deeb8d9d80e5b412bd24d09151c2008b7fef10eb5f13e484d'
                                               '1e0d01')
        self.assertEqual(
            to_hexstring(ds['keys'][0]), '0207c9ece04a9b5ef3ff441f3aad6bb63e323c05047a820ab45ebbe61385aa7446')

    def test_transaction_deserialize_script_with_sizebyte(self):
        script_size_byte = b'\x16\x00\x14y\t\x19r\x18lD\x9e\xb1\xde\xd2+x\xe4\r\x00\x9b\xdf\x00\x89'
        script = b'\x00\x14y\t\x19r\x18lD\x9e\xb1\xde\xd2+x\xe4\r\x00\x9b\xdf\x00\x89'
        self.assertDictEqualExt(script_deserialize(script_size_byte), script_deserialize(script))

    def test_transaction_sign_uncompressed(self):
        ki = Key('cTuDU2P6AhB72ZrhHRnFTcZRoHdnoWkp7sSMPCBnrMG23nRNnjUX', network='dash_testnet', compressed=False)
        prev_tx = "5b5903a9e5f5a1fee68fbd597085969a36789dc5b5e397dad76a57c3fb7c232a"
        output_n = 0
        t = Transaction(network='dash_testnet')
        t.add_input(prev_hash=prev_tx, output_n=output_n, compressed=False)
        t.add_output(99900000, 'yUV8W2RmEbKZD8oD7YMeBNiydHWmormCDj')
        t.sign(ki.private_byte)
        self.assertTrue(t.verify())

    def test_transaction_p2pk_script(self):
        rawtx = '0100000001db1a1774240cb1bd39d6cd6df0c57d5624fd2bd25b8b1be471714ab00e1a8b5d00000000484730440220592ce8' \
                '5d3b79509499c9832699c591fc0fd92208bfe20c67d655497c388b3cc50220134e367276b285c35692bcfc832afdc5c27729' \
                '0a5e02c78f4c3f96f5a393f7cd01ffffffff0278270b0000000000232103b907bb026b78706e612df821c66c6d86b3881d45' \
                '382f359e92e7c3418cacb8edac0000000000000000226a2012a4aba1a3909f8ad69e2a9f1f0e90346b0fef1f9c5b373dc2ec' \
                '7be3f3e457b000000000'
        t = Transaction.import_raw(rawtx)
        self.assertEqual(t.inputs[0].script_type, 'signature')

    def test_transaction_locktime(self):
        # FIXME: Add more usefull unittests for locktime
        s = binascii.unhexlify('76a914af8e14a2cecd715c363b3a72b55b59a31e2acac988ac')
        s_cltv = script_add_locktime_cltv(10000, s)
        s_csv = script_add_locktime_csv(600000, s)
        self.assertIsNotNone(s_cltv)
        self.assertIsNotNone(s_csv)
        # Test deserialize locktime transactions
        rawtx = '0200000002f42e4ee59d33dffc39978bd6f7a1fdef42214b7de7d6d2716b2a5ae0a92fbb09000000006a473044022003ea734e54ddc00d4d681e2cac9ecbedb45d24af307aefbc55ecb005c5d2dc13022054d5a0fdb7a0c3ae7b161ffb654be7e89c84de06013d416f708f85afe11845a601210213692eb7eb74a0f86284890885629f2d0977337376868b033029ba49cc64765dfdffffff27a321a0e098276e3dce7aedf33a633db31bf34262bde3fe30106a327696a70a000000006a47304402207758c05e849310af174ad4d484cdd551d66244d4cf0b5bba84e94d59eb8d3c9b02203e005ef10ede62db1900ed0bc2c72c7edd83ef98a21a3c567b4c6defe8ffca06012103ab51db28d30d3ac99965a5405c3d473e25dff6447db1368e9191229d6ec0b635fdffffff029b040000000000001976a91406d66adea8ca6fcbb4a7a5f18458195c869f4b5488ac307500000000000017a9140614a615ee10d84a1e6d85ec1ff7fff527757d5987b0cc0800'
        t = Transaction.import_raw(rawtx)
        self.assertEqual(t.locktime, 576688)
        rawtx = '010000000159dc9ad3dc18cd76827f107a50fd96981e323aec7be4cbf982df176b9ab64f4900000000fd17014730440220797987a17ee28181a94437e20c60b9d8da8974e68f91f250c424b623f06aeea9022036faa2834da6f883078abc3dd2fb48c19fc17097aa5b87fa11d00385fd21740b0121025c8ee352e8b0d12aecd8b3d9ac3bd93cae1b2cc5de7ac56c2995ab506ac800bd206a9068119b30840206281418227f33f76c53c43fa59fad748d2954e6ecd595a94c8aa6140d424014e59608dae01e97700da0b53b3095a1af882102ef7f775819d4518c67c904201e30d4181190552f0026db94f93bfde557e23d1187632102ef7f775819d4518c67c904201e30d4181190552f0026db94f93bfde557e23d11ac670475f2df5cb17521025c8ee352e8b0d12aecd8b3d9ac3bd93cae1b2cc5de7ac56c2995ab506ac800bdac68feffffff011f000200000000001976a91436963a21b49f701acf03dd1e778ab5774017b53c88ac75f2df5c'
        t = Transaction.import_raw(rawtx)
        self.assertEqual(t.locktime, 1558180469)
        # Input level locktimes
        t = Transaction()
        t.add_input('f601e39f6b99b64fc2e98beb706ec7f14d114db7e61722c0313b0048df49453e', 0, locktime_cltv=10000)
        t.add_input('f601e39f6b99b64fc2e98beb706ec7f14d114db7e61722c0313b0048df494511', 0, locktime_csv=20000)
        t.add_input('f601e39f6b99b64fc2e98beb706ec7f14d114db7e61722c0313b0048df494522', 0,
                    locktime_csv=SEQUENCE_LOCKTIME_TYPE_FLAG+30000)
        t.add_input('f601e39f6b99b64fc2e98beb706ec7f14d114db7e61722c0313b0048df494533', 0,
                    locktime_csv=SEQUENCE_LOCKTIME_TYPE_FLAG+40000)
        self.assertIsNone(t.info())

    def test_transaction_get_unlocking_script_type(self):
        self.assertEqual(get_unlocking_script_type('p2pk'), 'signature')
        self.assertRaisesRegexp(TransactionError, "Unknown locking script type troep", get_unlocking_script_type,
                                'troep')

    def test_transaction_redeemscript(self):
        redeemscript = '524104a882d414e478039cd5b52a92ffb13dd5e6bd4515497439dffd691a0f12af9575fa349b5694ed3155b136f09e63975a1700c9f4d4df849323dac06cf3bd6458cd41046ce31db9bdd543e72fe3039a1f1c047dab87037c36a669ff90e28da1848f640de68c2fe913d363a51154a0c62d7adea1b822d05035077418267b1a1379790187410411ffd36c70776538d079fbae117dc38effafb33304af83ce4894589747aee1ef992f63280567f52f5ba870678b4ab4ff6c8ea600bd217870a8b4f1f09f3a8e8353ae'
        sd = script_deserialize('00c9' + redeemscript)
        self.assertEqual(to_hexstring(sd['redeemscript']), redeemscript)


class TestTransactionsMultisigSoroush(unittest.TestCase):
    # Source: Example from
    #   http://www.soroushjp.com/2014/12/20/bitcoin-multisig-the-hard-way-understanding-raw-multisignature-bitcoin-transactions/

    def setUp(self):
        key1 = '5JruagvxNLXTnkksyLMfgFgf3CagJ3Ekxu5oGxpTm5mPfTAPez3'
        key2 = '5JX3qAwDEEaapvLXRfbXRMSiyRgRSW9WjgxeyJQWwBugbudCwsk'
        key3 = '5JjHVMwJdjPEPQhq34WMUhzLcEd4SD7HgZktEh8WHstWcCLRceV'
        self.keylist = [key1, key2, key3]

    def test_transaction_multisig_redeemscript(self):
        redeemscript = serialize_multisig_redeemscript(self.keylist, 2, False)
        expected_redeemscript = \
            '524104a882d414e478039cd5b52a92ffb13dd5e6bd4515497439dffd691a0f12af9575fa349b5694ed3155b136f09e63975a1700' \
            'c9f4d4df849323dac06cf3bd6458cd41046ce31db9bdd543e72fe3039a1f1c047dab87037c36a669ff90e28da1848f640de68c2f' \
            'e913d363a51154a0c62d7adea1b822d05035077418267b1a1379790187410411ffd36c70776538d079fbae117dc38effafb33304' \
            'af83ce4894589747aee1ef992f63280567f52f5ba870678b4ab4ff6c8ea600bd217870a8b4f1f09f3a8e8353ae'
        self.assertEqual(to_hexstring(redeemscript), expected_redeemscript)
        self.assertEqual(serialize_multisig_redeemscript([]), b'')
        self.assertRaisesRegexp(TransactionError, "Argument public_key_list must be of type list",
                                serialize_multisig_redeemscript, 2)
        k = '02600ca766925ef97fbd4b38b8dc35714edc27e1a0d454268d592c369835f49584'
        self.assertEqual(to_hexstring(serialize_multisig_redeemscript([k])),
                         '512102600ca766925ef97fbd4b38b8dc35714edc27e1a0d454268d592c369835f4958451ae')
        # k = to_bytes(k)
        # print(to_hexstring(serialize_multisig_redeemscript([k])),
        #       '512102600ca766925ef97fbd4b38b8dc35714edc27e1a0d454268d592c369835f4958451ae')

    def test_transaction_multisig_p2sh_sign(self):
        t = Transaction()
        t.add_output(55600, '18tiB1yNTzJMCg6bQS1Eh29dvJngq8QTfx')
        t.add_input('02b082113e35d5386285094c2829e7e2963fa0b5369fb7f4b79c4c90877dcd3d', 0,
                    keys=[self.keylist[0], self.keylist[1], self.keylist[2]], script_type='p2sh_multisig',
                    sigs_required=2, compressed=False, sort=False)
        pk1 = Key(self.keylist[0]).private_byte
        pk2 = Key(self.keylist[2]).private_byte
        t.sign([pk1, pk2])
        self.assertTrue(t.verify())
        unlocking_script = t.inputs[0].unlocking_script
        unlocking_script_str = script_deserialize(unlocking_script)
        self.assertEqual(unlocking_script_str['script_type'], 'p2sh_multisig')
        self.assertEqual(len(unlocking_script_str['signatures']), 2)

    def test_transaction_multisig_p2sh_sign_separate(self):
        t = Transaction()
        t.add_output(55600, '18tiB1yNTzJMCg6bQS1Eh29dvJngq8QTfx')
        pubk0 = Key(self.keylist[0]).public()
        pubk2 = Key(self.keylist[2]).public()
        t.add_input('02b082113e35d5386285094c2829e7e2963fa0b5369fb7f4b79c4c90877dcd3d', 0,
                    keys=[pubk0, self.keylist[0], pubk2], script_type='p2sh_multisig',
                    sigs_required=2, compressed=False, sort=False)
        pk1 = Key(self.keylist[0]).private_byte
        pk2 = Key(self.keylist[2]).private_byte
        t.sign([pk1])
        t.sign([pk2])
        unlocking_script = t.inputs[0].unlocking_script
        unlocking_script_str = script_deserialize(unlocking_script)
        self.assertEqual(len(unlocking_script_str['signatures']), 2)


class TestTransactionsMultisig(unittest.TestCase):
    def setUp(self):
        self.pk1 = HDKey('tprv8ZgxMBicQKsPen95zTdorkDGPi4jHy9xBf4TdVxrB1wTJgSKCZbHpWhmaTGoRXHj2dJRcJQhRkV22Mz3uh'
                         'g9nThjGLAJKzrPuZXPmFUgQ42')
        self.pk2 = HDKey('tprv8ZgxMBicQKsPdhv4GxyNcfNK1Wka7QEnQ2c8DNdRL5z3hzf7ufUYNW14fgArjFvLtyg5xmPrkpx6oGBo2'
                         'dquPf5inH6Jg6h2D89nsQdY8Ga')
        self.pk3 = HDKey('tprv8ZgxMBicQKsPedw6MqKGBhVtpDTMpGqdUUrkurgvpAZxoEpn2SVJbUtArig6cnpxenVWs42FRB3wp5Lim'
                         'CAVsjLKHmAK1hB1fYJ8aUyzQeH')
        self.pk4 = HDKey('tprv8ZgxMBicQKsPefyc4C5BZwKRtBoNS8WA1to31B6QCxrrXY83FnWVALo3YKNuuisqbN9FUM245nZnXEQbf'
                         'uEemfBXy7CLD6abaXx24PotyQY')
        self.pk5 = HDKey('tprv8ZgxMBicQKsPdbyo59MRWqjXq3tTCS4PgJuFzJZvp8dBZz5HpQBw994LDS7ig8rsJcZwq6r3LghBeb82L'
                         'iYu6rL35dm3XiMMJjNoY8d6pqN')
        self.utxo_tbtcleft = 740000
        self.utxo_prev_tx = 'f601e39f6b99b64fc2e98beb706ec7f14d114db7e61722c0313b0048df49453e'
        self.utxo_output_n = 1

    def test_transaction_multisig_signature_redeemscript_mixup(self):
        pk1 = HDKey('tprv8ZgxMBicQKsPen95zTdorkDGPi4jHy9xBf4TdVxrB1wTJgSKCZbHpWhmaTGoRXHj2dJRcJQhRkV22Mz3uhg9nThjGLA'
                    'JKzrPuZXPmFUgQ42')
        pk2 = HDKey('tprv8ZgxMBicQKsPdhv4GxyNcfNK1Wka7QEnQ2c8DNdRL5z3hzf7ufUYNW14fgArjFvLtyg5xmPrkpx6oGBo2dquPf5inH6'
                    'Jg6h2D89nsQdY8Ga')
        redeemscript = b'522103b008ee001282efb523f68d494896f3072903e03b3fb91d16713c56bf79693a382102d43dcc8a5db03172ba' \
                       b'95c345bb2d478654853f311dc4b1cbd313e5a327f0e3ba52ae'

        # Create 2-of-2 multisig transaction with 1 input and 1 output
        t = Transaction(network='testnet')
        t.add_input('a2c226037d73022ea35af9609c717d98785906ff8b71818cd4095a12872795e7', 1,
                    [pk1.public_byte, pk2.public_byte], script_type='p2sh_multisig', sigs_required=2)
        t.add_output(900000, '2NEgmZU64NjiZsxPULekrFcqdS7YwvYh24r')
        print(to_hexstring(t.inputs[0].unlocking_script_unsigned))
        # Sign with private key and verify
        t.sign(pk1)
        t.sign(pk2)
        self.assertTrue(t.verify())

        # Now deserialize and check if redeemscript is still the same
        t2 = Transaction.import_raw(t.raw_hex(), network='testnet')
        self.assertEqual(binascii.hexlify(t2.inputs[0].redeemscript), redeemscript)

    def test_transaction_multisig_sign_3_of_5(self):
        t = Transaction(network='testnet')
        t.add_input(self.utxo_prev_tx, self.utxo_output_n,
                    [self.pk1.public_byte, self.pk2.public_byte, self.pk3.public_byte, self.pk4.public_byte,
                     self.pk5.public_byte], script_type='p2sh_multisig', sigs_required=3)

        t.add_output(100000, 'mi1Lxs5boL6nDM3teraP3moVfLXJXWrWSK')
        t.add_output(self.utxo_tbtcleft - 110000, '2Mt1veesS36nYspXhkMXYKGHRAbtEYF6b8W')

        t.sign(self.pk5)
        t.sign(self.pk2)
        t.sign(self.pk3.private_byte)

        self.assertTrue(t.verify())

    def test_transaction_multisig_sign_2_of_5_not_enough(self):
        t = Transaction(network='testnet')
        t.add_input(self.utxo_prev_tx, self.utxo_output_n,
                    [self.pk1.public_byte, self.pk2.public_byte, self.pk3.public_byte, self.pk4.public_byte,
                     self.pk5.public_byte], script_type='p2sh_multisig', sigs_required=3)

        t.add_output(100000, 'mi1Lxs5boL6nDM3teraP3moVfLXJXWrWSK')
        t.add_output(self.utxo_tbtcleft - 110000, '2Mt1veesS36nYspXhkMXYKGHRAbtEYF6b8W')

        t.sign(self.pk4)
        t.sign(self.pk1)

        self.assertFalse(t.verify())

    def test_transaction_multisig_sign_duplicate(self):
        t = Transaction(network='testnet')
        t.add_input(self.utxo_prev_tx, self.utxo_output_n,
                    [self.pk1.public_byte, self.pk2.public_byte, self.pk3.public_byte, self.pk4.public_byte,
                     self.pk5.public_byte], script_type='p2sh_multisig', sigs_required=3)

        t.add_output(100000, 'mi1Lxs5boL6nDM3teraP3moVfLXJXWrWSK')
        t.add_output(self.utxo_tbtcleft - 110000, '2Mt1veesS36nYspXhkMXYKGHRAbtEYF6b8W')

        t.sign(self.pk1)
        self.assertEqual(len(t.inputs[0].signatures), 1)
        t.sign(self.pk1)  # Sign again with same key
        self.assertEqual(len(t.inputs[0].signatures), 1)

    def test_transaction_multisig_sign_extra_sig(self):
        t = Transaction(network='testnet')
        t.add_input(self.utxo_prev_tx, self.utxo_output_n,
                    [self.pk1.public_byte, self.pk2.public_byte, self.pk3.public_byte, self.pk4.public_byte,
                     self.pk5.public_byte], script_type='p2sh_multisig', sigs_required=3)

        t.add_output(100000, 'mi1Lxs5boL6nDM3teraP3moVfLXJXWrWSK')
        t.add_output(self.utxo_tbtcleft - 110000, '2Mt1veesS36nYspXhkMXYKGHRAbtEYF6b8W')

        t.sign(self.pk1)
        t.sign(self.pk4)
        t.sign(self.pk2)
        t.sign(self.pk5)

        self.assertTrue(t.verify())

    def test_transaction_multisig_estimate_size(self):
        network = 'bitcoinlib_test'
        phrase1 = 'shop cloth bench traffic vintage security hour engage omit almost episode fragile'
        phrase2 = 'exclude twice mention orchard grit ignore display shine cheap exercise same apart'
        phrase3 = 'citizen obscure tribe index little welcome deer wine exile possible pizza adjust'
        prev_hash = '55d721dffa90208d8ab7ae3411c42db3e7de860f3a76ab18f7c237bf2390a666'
        pk1 = HDKey.from_passphrase(phrase1, network=network)
        pk2 = HDKey.from_passphrase(phrase2, network=network)
        pk3 = HDKey.from_passphrase(phrase3, network=network)

        t = Transaction(network=network)
        t.add_input(prev_hash, 0, [pk1.private_byte, pk2.public_byte, pk3.public_byte], script_type='p2sh_multisig',
                    sigs_required=2)
        t.add_output(10000, '22zkxRGNsjHJpqU8tSS7cahSZVXrz9pJKSs')
        self.assertEqual(t.estimate_size(), 337)

    def test_transaction_multisig_litecoin(self):
        network = 'litecoin'
        pk1 = HDKey(network=network)
        pk2 = HDKey(network=network)
        pk3 = HDKey(network=network)
        t = Transaction(network=network)
        t.add_input(self.utxo_prev_tx, self.utxo_output_n,
                    [pk1.public_byte, pk2.public_byte, pk3.public_byte],
                    script_type='p2sh_multisig', sigs_required=2)
        t.add_output(100000, 'LTK1nK5TyGALmSup5SzhgkX1cnVQrC4cLd')
        t.sign(pk1)
        self.assertFalse(t.verify())
        t.sign(pk3)
        self.assertTrue(t.verify())

    def test_transaction_multisig_dash(self):
        network = 'dash'
        pk1 = HDKey(network=network)
        pk2 = HDKey(network=network)
        pk3 = HDKey(network=network)
        t = Transaction(network=network)
        t.add_input(self.utxo_prev_tx, self.utxo_output_n,
                    [pk1.public_byte, pk2.public_byte, pk3.public_byte],
                    script_type='p2sh_multisig', sigs_required=2)
        t.add_output(100000, 'XwZcTpBnRRURenL7Jh9Z52XGTx1jhvecUt')
        t.sign(pk1)
        self.assertFalse(t.verify())
        t.sign(pk3)
        self.assertTrue(t.verify())


class TestTransactionsTimelocks(unittest.TestCase):

    def test_transaction_timelock(self):
        locktime = 1532291866  # Timestamp
        inputs = [
            Input('0b823fca26c706c838b41749c22d01b8605068a83accac3767eaf74870106d5c', 0)]
        outputs = [Output(9000, '1NsKdY663CutnDvcMJdeGawMZj4SsRXWgg')]
        t = Transaction(inputs, outputs, locktime=locktime)
        t2 = Transaction.import_raw(t.raw())
        self.assertEqual(t2.locktime, locktime)

    def test_transaction_relative_timelock(self):
        sequence = SEQUENCE_LOCKTIME_TYPE_FLAG + 1532291866  # Timestamp
        inputs = [
            Input('0b823fca26c706c838b41749c22d01b8605068a83accac3767eaf74870106d5c', 0, sequence=sequence)]
        outputs = [Output(9000, '1NsKdY663CutnDvcMJdeGawMZj4SsRXWgg')]
        t = Transaction(inputs, outputs)
        t2 = Transaction.import_raw(t.raw())
        self.assertEqual(t2.inputs[0].sequence, sequence)

    def test_transaction_locktime_cltv(self):
        # timelock = 533600
        # inputs = [
        #     Input('0b823fca26c706c838b41749c22d01b8605068a83accac3767eaf74870106d5c', 0, locktime_cltv=timelock)]
        # outputs = [Output(9000, '1NsKdY663CutnDvcMJdeGawMZj4SsRXWgg')]
        # t = Transaction(inputs, outputs)
        # TODO
        pass
        raw_tx = ''
        # print(t.raw_hex())
        # print(t.inputs[0].unlocking_script_unsigned)

    def test_transaction_cltv_error(self):
        # TODO
        pass

    def test_transaction_csv(self):
        # TODO
        pass


class TestTransactionsSegwit(unittest.TestCase, CustomAssertions):

    def test_transaction_segwit_deserialize_p2wsh(self):
        # Random segwit p2wsh transaction - bbff3196a5668f5d90a901056adcc8c6dbec2e7ba0b9721772ea45693f08ce81
        raw_tx = "01000000000101c2f54901df3f74e7999f505b629f5229a2cafcf8cc6325bb2a1f216748cb9fcb0200000000ffffffff03" \
                 "40a4b600000000001976a91437883c91fbfbd90330fadec0d1b38ee2e5de449488ac00735500000000001976a914c77d15" \
                 "052e9a8cce5cea9bb41e1edd6bd93dd8d988ac78bb9d0200000000220020701a8d401c84fb13e6baf169d59684e17abd9f" \
                 "a216c8cc5b9fc63d622ff8c58d0400473044022042f474d354a3d406b01748bdb08ff771abb85b2de6dc220956b342eca6" \
                 "c6ea00022030fce68b5db9ad760dfff39389a0e9c340f77fd95e9b256b01f2220192143f9e01483045022100b68f7f4848" \
                 "b145197cfd38a204e46a443646fe292d5c553184e8adc6b1ed14f802206c2548d8b9a4901ab18fc26c11d249e62e716500" \
                 "305a5152cd4ad1377a2286a1016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c" \
                 "2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fe" \
                 "e45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000"
        t = Transaction.import_raw(raw_tx)
        self.assertEqual(t.inputs[0].address, 'bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej')
        self.assertEqual(t.outputs[2].address, 'bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej')
        t.inputs[0].value = 61501176
        self.assertTrue(t.verify())

    def test_transaction_segwit_deserialize_p2wpkh(self):
        # Random segwit p2wpkh transaction - 299dab85f10c37c6296d4fb10eaa323fb456a5e7ada9adf41389c447daa9c0e4
        raw_tx = "02000000000101b99ef54dd7695be7574ac6fb4a6d1a2dd98cb4ec7ee53b06117754da424a4c440100000000ffffffff01" \
                 "12d62d1e00000000160014f922634ea00272421ffdb6f187935602159e17500247304402204c040218c1a5dc87e0ba3597" \
                 "06fbd0c9c36063fd89c6b4dd900e03cd69de7fd602204c7ebe180a072cc415ba3337dd66d259a4c7de2b563269a90e055f" \
                 "91898bcf590121025477b3e0aa2619e1ed61b7734b31369c156d9ff7fcbcdc1b7e3c79ed657aab0f00000000"
        t = Transaction.import_raw(raw_tx)
        self.assertEqual(t.inputs[0].address, 'bc1qpjnaav9yvane7qq3a7efq6nw229g6gh09jzlvc')
        self.assertEqual(t.outputs[0].address, 'bc1qly3xxn4qqfeyy8lakmcc0y6kqg2eu96srjzycu')
        t.inputs[0].value = 506323064
        self.assertTrue(t.verify())

    def test_transaction_segwit_p2wpkh(self):
        pk_input1 = 'bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866'
        pk_input2 = '619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9'
        pk1 = Key(pk_input1)
        pk2 = Key(pk_input2)
        output1_value_hexle = binascii.unhexlify('202cb20600000000')
        output2_value_hexle = binascii.unhexlify('9093510d00000000')
        output1_value = change_base(output1_value_hexle[::-1], 256, 10)
        output2_value = change_base(output2_value_hexle[::-1], 256, 10)

        inp_prev_tx1 = binascii.unhexlify('fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f')[::-1]
        inp_prev_tx2 = binascii.unhexlify('ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a')[::-1]
        inputs = [
            Input(inp_prev_tx1, 0, sequence=0xffffffee, keys=pk1, value=int(6.25 * 100000000)),
            Input(inp_prev_tx2, 1, witness_type='segwit', sequence=0xffffffff, keys=pk2, value=int(6 * 100000000)),
        ]
        outputs = [
            Output(output1_value, lock_script='76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac'),
            Output(output2_value, lock_script='76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac'),
        ]

        t = Transaction(inputs, outputs, witness_type='segwit', locktime=0x00000011)
        self.assertEqual(to_hexstring(t.signature_hash(1)),
                         'c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670')
        t.sign([pk1], 0)
        t.sign([pk2], 1)
        self.assertTrue(t.verify())
        t2 = Transaction.import_raw(t.raw())
        t2.inputs[0].value = int(6.25 * 100000000)
        t2.inputs[1].value = int(6 * 100000000)
        self.assertEqual(t2.inputs[0].prev_hash, inp_prev_tx1)
        self.assertEqual(t2.inputs[1].prev_hash, inp_prev_tx2)
        self.assertEqual(to_hexstring(t2.signature_hash(1)),
                         'c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670')

    def test_transactions_segwit_p2sh_p2wpkh(self):
        pk_input1 = 'eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf'
        pk1 = Key(pk_input1)
        output1_value_hexle = binascii.unhexlify('b8b4eb0b00000000')
        output2_value_hexle = binascii.unhexlify('0008af2f00000000')
        output1_value = change_base(output1_value_hexle[::-1], 256, 10)
        output2_value = change_base(output2_value_hexle[::-1], 256, 10)

        inp_prev_tx1 = binascii.unhexlify('db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477')[::-1]
        inputs = [
            Input(inp_prev_tx1, 1, sequence=0xfffffffe, keys=pk1, value=int(10 * 100000000),
                  script_type='p2sh_p2wpkh', encoding='base58'),
        ]
        outputs = [
            Output(output1_value, lock_script='76a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac'),
            Output(output2_value, lock_script='76a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac'),
        ]

        t = Transaction(inputs, outputs, witness_type='segwit', locktime=0x00000492)
        self.assertEqual(to_hexstring(t.signature_hash(0)),
                         '64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6')
        t.sign([pk1], 0)
        self.assertTrue(t.verify())
        t2 = Transaction.import_raw(t.raw())
        t2.inputs[0].value = int(10 * 100000000)
        self.assertEqual(to_hexstring(t2.signature_hash(0)),
                         '64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6')
        t2.sign([pk1], 0)
        self.assertTrue(t2.verify())
        self.assertEqual(t2.inputs[0].script_type, 'p2sh_p2wpkh')

    def test_transaction_segwit_p2wsh(self):
        key1 = Key('241e4ec8680a77404bfd8ec8618c5db99dcb6c3eadd913d28a5e85bf28a29d92')
        key2 = Key('36751e0bfcdee1509209f29edefaee6ce0f9dc1a7e46062740c68ae7879d08ba')
        prev_tx = 'b7053498280442bb6c792c0c8883e72ced2172ecb2e31499f4ea59c7ec275433'
        inputs = [
            Input(prev_tx, 1, sequence=0xffffffff, value=70626, keys=[key1.public_byte, key2.public_byte],
                  sigs_required=2, script_type='p2sh_multisig', witness_type='segwit', sort=True)
        ]
        outputs = [Output(63000, 'bc1qs5q679tac0uvfunt0gdwuymves5re7v7q8fntv', encoding='bech32')]
        t = Transaction(inputs, outputs, witness_type='segwit')
        t.sign(key1)
        t.sign(key2)
        self.assertTrue(t.verify())
        self.assertEqual(to_hexstring(t.signature_hash(0)),
                         'e671e16a05001059a87767057700a7cb935c30a90e0728b739f24dd0d55ebae8')
        t2 = Transaction.import_raw(t.raw())
        t2.inputs[0].value = 70626
        t2.verify()
        self.assertTrue(t2.verify())
        self.assertEqual(to_hexstring(t2.signature_hash(0)),
                         'e671e16a05001059a87767057700a7cb935c30a90e0728b739f24dd0d55ebae8')

    def test_transaction_segwit_p2sh_p2wsh(self):
        key1 = Key('241e4ec8680a77404bfd8ec8618c5db99dcb6c3eadd913d28a5e85bf28a29d92')
        key2 = Key('36751e0bfcdee1509209f29edefaee6ce0f9dc1a7e46062740c68ae7879d08ba')
        prev_tx = 'b7053498280442bb6c792c0c8883e72ced2172ecb2e31499f4ea59c7ec275433'
        inputs = [
            Input(prev_tx, 1, sequence=0xffffffff, value=70626, keys=[key1.public_byte, key2.public_byte],
                  sigs_required=2, script_type='p2sh_multisig', witness_type='p2sh-segwit', sort=True)
        ]
        outputs = [Output(65000, 'bc1qq3lc6h2nqju2z79ll0tursx8cf2xlj20cwefzzkmn43pnptmtk0sa68kvp', encoding='bech32'), ]
        t = Transaction(inputs, outputs, witness_type='segwit')
        t.sign(key1)
        t.sign(key2)
        self.assertTrue(t.verify())
        self.assertEqual(to_hexstring(t.signature_hash(0)),
                         '12ca412ed631d17d757a298f0d98e1b971d660b2e90a73b2ce6af3bb92ac342e')
        t2 = Transaction.import_raw(t.raw())
        t2.inputs[0].value = 70626
        self.assertTrue(t2.verify())
        self.assertEqual(to_hexstring(t2.signature_hash(0)),
                         '12ca412ed631d17d757a298f0d98e1b971d660b2e90a73b2ce6af3bb92ac342e')

    def test_transaction_segwit_addresses(self):
        pk = 'Ky4o5RNziUHUuDjUaAKuHnfMt2hRsX4y4itaGPGNMPDhR11faGtA'
        inp = Input('prev', 0, pk, script_type='p2sh_p2wpkh')
        self.assertEqual(inp.address, '3PkeUdqAddDPfzTniQeKQpeLqeuAMjFM8R')

        pk = 'KzfY4SCg56duLi1UTXbwUzaK1nQEF8gUvGLvwUDi7bYJvhMn3CFV'
        inp = Input('prev', 0, pk, encoding='bech32')
        self.assertEqual(inp.address, 'bc1qhzt298pr6tm23hqkd4akzr3cajpyt2wsnz8zr4')

    def test_transaction_segwit_importraw_litecoin(self):
        rawtx = '010000000001016768c8454c2d561957e13baabf9641382337f89e5854343895b46ab368bbd6350000000017160014d60b21' \
                '752adc62eb3117b0b2bd00b0126d8e0157ffffffff024aae8b060000000017a914d966f0e3e05e3ab1209524338ff61b32eb' \
                '2aa58887be5d9b00000000001600148ceebc8944c8bb2af9f6714d60c88860191032f302473044022025a38facc3e83e532a' \
                '6ad5a09ff2cc5e10bf1b09249169b233c5a3ffc21003de022031715687bc57778f7564924861a2d821b4eb6d15b1957ef895' \
                '5fd7d6f93df7bd0121034168c3df0c9db74c8159388b270a6dbb30778b8ac74e6b456ad1ebb8c4bb344f00000000'
        t = Transaction.import_raw(rawtx, network='litecoin')
        self.assertEqual(t.inputs[0].address, 'MLairbWquSaGqMF1cWJZSH7xU6iY8jZBi5')
        self.assertEqual(t.outputs[0].address, 'MTigBXDpqJTK12Lhmd8P8UPqDGe97zVgNW')
        self.assertEqual(t.outputs[0].value, 109817418)
        self.assertEqual(t.outputs[1].address, 'ltc1q3nhtez2yezaj470kw9xkpjygvqv3qvhn5sp469')
        self.assertEqual(t.outputs[1].value, 10182078)
        self.assertEqual(t.raw_hex(), rawtx)
        self.assertEqual(t.hash, '6bf265d81f235a995dfd433765dcee7da56786973234be2b8db4a156ac64b0e1')

    def test_transaction_segwit_redeemscript_bug(self):
        t = Transaction(
            [
                Input('eb58619551911bddfa2f7f077e2df6a55d74c881f3745d0bd491f28ee6e63163', 1,
                      script_type='p2sh_multisig',
                      keys=['0236ab0a160e381d2eb6f01119937d29e697b78ca8be115617db972e0d95cef6b7',
                            '038b46795c92b8c9a6b40644a082be367e740f09b581a8b8c26b71d4b39f5cd963',
                            '03f93f3a5633478ed3ab3ff9d2fe5ddeecb8e755fb267c9a3bc9d7242f58e4f258'],
                      unlocking_script_unsigned='52210236ab0a160e381d2eb6f01119937d29e697b78ca8be115617db972e0d95ce'
                                                'f6b721038b46795c92b8c9a6b40644a082be367e740f09b581a8b8c26b71d4b39f'
                                                '5cd9632103f93f3a5633478ed3ab3ff9d2fe5ddeecb8e755fb267c9a3bc9d7242f'
                                                '58e4f25853ae',
                      signatures=[
                          '8f9815521722a590bc3dcd888d8b9e417ac46e8cb87f76f427a3760732034aea61942674c0777fb9b65c1b39'
                          '75d5698c8d48c0ed86c92c8516190b507dda70fb'],
                      sigs_required=2, network='testnet', witness_type='segwit')
            ],
            [
                Output(15000, 'n2eMqTT929pb1RDNuqEnxdaLau1rxy3efi', script_type='p2pkh', network='testnet')
            ],
            network='testnet', witness_type='segwit')
        rawtx = t.raw()
        Transaction.import_raw(rawtx)
        self.assertEqual(rawtx, t.raw())