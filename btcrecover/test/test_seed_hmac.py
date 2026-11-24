"""Check address-loop HMAC state reuse against the standard HMAC library."""

import hashlib
import hmac
import struct
import unittest
from unittest import mock

from btcrecover.btcrseed import wallets


class TestAddressHmac(unittest.TestCase):
    def test_address_derivations_match_standard_hmac(self):
        for start, count in ((0, 1), (7, 2), (19, 5), (0, 20), (41, 100),
                             (2 ** 31 - 2, 2)):
            with self.subTest(start=start, count=count):
                root = hashlib.sha512(
                    f"address HMAC regression {start} {count}".encode()
                ).digest()
                parent_key = root[:32]
                parent_int = int.from_bytes(parent_key, "big")
                public_key = wallets.privkey_to_pubkey(parent_key)
                expected_keys = [parent_key]
                for index in range(start, start + count):
                    digest = hmac.new(
                        root[32:], public_key + struct.pack(">I", index),
                        hashlib.sha512,
                    ).digest()
                    child_int = (
                        int.from_bytes(digest[:32], "big") + parent_int
                    ) % wallets.GENERATOR_ORDER
                    expected_keys.append(child_int.to_bytes(32, "big"))

                wallet = wallets.WalletBIP32.__new__(wallets.WalletBIP32)
                wallet.checksinglexpubaddress = False
                wallet._chaincode = None
                wallet._known_hash160s = set()
                wallet._path_plan = [([], False, True, False, False)]
                wallet._address_start_index = start
                wallet._addrs_to_generate = count
                with mock.patch.object(
                    wallets, "privkey_to_pubkey",
                    wraps=wallets.privkey_to_pubkey,
                ) as derive_public:
                    self.assertFalse(wallet._verify_seed(root, salt=b""))

                actual_keys = [call.args[0]
                               for call in derive_public.call_args_list]
                self.assertEqual(expected_keys, actual_keys)


if __name__ == "__main__":
    unittest.main()
