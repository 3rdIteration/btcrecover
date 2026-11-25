"""BIP38 verification across native and bundled crypto backends."""

import hashlib
import pickle
import unittest
from unittest import mock

from btcrecover import aes_backends, crypto_backends
from btcrecover.btcrpass import wallets
from lib.cashaddress import base58
from lib.pyaes import AESModeOfOperationECB


def _double_sha256(value):
    return hashlib.sha256(hashlib.sha256(value).digest()).digest()


def _xor(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


class TestBIP38Backends(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference_pubkey = staticmethod(
            crypto_backends._make_purepython_backend()["privkey_to_pubkey"]
        )
        # Initialize the wallet's lazy helpers without adding a key fixture.
        encoded = base58.b58encode_check(b"\x01\x42\xe0" + bytes(36))
        cls.wallet = wallets.WalletBIP38(encoded)

    def _address_hash(self, secret, compressed):
        pubkey = self.reference_pubkey(secret, compressed=compressed)
        address = base58.b58encode_check(
            b"\x00" + wallets.hash160(pubkey)
        )
        return _double_sha256(address.encode("ascii"))[:4]

    @staticmethod
    def _wif(secret, compressed):
        suffix = b"\x01" if compressed else b""
        return base58.b58encode_check(b"\x80" + secret + suffix)

    @staticmethod
    def _non_ec_payload(secret, derived, address_hash):
        cipher = AESModeOfOperationECB(derived[32:])
        first = cipher.encrypt(_xor(secret[:16], derived[:16]))
        second = cipher.encrypt(_xor(secret[16:], derived[16:32]))
        return address_hash + first + second

    def test_non_ec_verification_and_compression(self):
        secret = hashlib.sha256(b"BIP38 backend round trip").digest()
        derived = hashlib.sha512(b"BIP38 derived bytes").digest()
        for compressed in (False, True):
            payload = self._non_ec_payload(
                secret, derived, self._address_hash(secret, compressed)
            )
            expected = self._wif(secret, compressed)
            for native in (True, False):
                with self.subTest(compressed=compressed, native=native):
                    pubkey = (crypto_backends.privkey_to_pubkey if native
                              else self.reference_pubkey)
                    with mock.patch.object(
                        wallets, "privkey_to_pubkey", pubkey
                    ), mock.patch.object(
                        aes_backends, "_HAS_CRYPTO",
                        native and aes_backends._HAS_CRYPTO,
                    ):
                        self.assertEqual(wallets.bip38decrypt_non_ec(
                            derived, payload, compressed, False,
                            network_prefix=b"\x00",
                        ), expected)
                        self.assertEqual(wallets.bip38decrypt_non_ec(
                            derived, payload, compressed, False,
                            outputlotsequence=True, network_prefix=b"\x00",
                        ), (expected, False, False))
                        self.assertFalse(wallets.bip38decrypt_non_ec(
                            derived, b"\xff" * 4 + payload[4:], compressed,
                            False, network_prefix=b"\x00",
                        ))

    def test_ec_verification_compression_and_lot_sequence(self):
        prefactor = hashlib.sha256(b"BIP38 prefactor").digest()
        entropy = hashlib.sha256(b"BIP38 owner entropy").digest()[:8]
        seed = hashlib.sha256(b"BIP38 seed material").digest()[:24]
        derived = hashlib.sha512(b"BIP38 EC derived bytes").digest()
        cipher = AESModeOfOperationECB(derived[32:])
        first = cipher.encrypt(_xor(seed[:16], derived[:16]))
        second = cipher.encrypt(_xor(first[8:] + seed[16:], derived[16:32]))
        for lot_sequence in (False, True):
            passfactor = (_double_sha256(prefactor + entropy) if lot_sequence
                          else prefactor)
            secret_int = (int.from_bytes(passfactor, "big")
                          * int.from_bytes(_double_sha256(seed), "big"))
            secret = (secret_int % crypto_backends.GROUP_ORDER_INT).to_bytes(
                32, "big"
            )
            for compressed in (False, True):
                payload = (self._address_hash(secret, compressed) + entropy
                           + first[:8] + second)
                for native in (True, False):
                    with self.subTest(
                        lot_sequence=lot_sequence, compressed=compressed,
                        native=native,
                    ):
                        pubkey = (crypto_backends.privkey_to_pubkey if native
                                  else self.reference_pubkey)
                        with mock.patch.object(
                            wallets, "privkey_to_pubkey", pubkey
                        ), mock.patch.object(
                            aes_backends, "_HAS_CRYPTO",
                            native and aes_backends._HAS_CRYPTO,
                        ):
                            self.assertEqual(wallets.prefactor_to_passpoint(
                                prefactor, lot_sequence, payload,
                            ), self.reference_pubkey(passfactor))
                            self.assertEqual(wallets.bip38decrypt_ec(
                                prefactor, derived, payload, compressed,
                                lot_sequence, network_prefix=b"\x00",
                            ), self._wif(secret, compressed))
                            self.assertFalse(wallets.bip38decrypt_ec(
                                prefactor, derived,
                                b"\xff" * 4 + payload[4:], compressed,
                                lot_sequence, network_prefix=b"\x00",
                            ))

    def test_invalid_private_scalars_are_rejected(self):
        derived = hashlib.sha512(b"BIP38 invalid scalar bytes").digest()
        for scalar in (0, crypto_backends.GROUP_ORDER_INT, 2 ** 256 - 1):
            secret = scalar.to_bytes(32, "big")
            payload = self._non_ec_payload(secret, derived, bytes(4))
            with self.subTest(scalar=scalar):
                with self.assertRaises(ValueError):
                    wallets.private_key_to_public_key(secret)
                with self.assertRaises(ValueError):
                    wallets.prefactor_to_passpoint(secret, False, bytes(36))
                self.assertFalse(wallets.bip38decrypt_non_ec(
                    derived, payload, True, False, network_prefix=b"\x00",
                ))
                self.assertEqual(wallets.bip38decrypt_non_ec(
                    derived, payload, True, False, outputlotsequence=True,
                    network_prefix=b"\x00",
                ), (False, False, False))
                self.assertFalse(wallets.bip38decrypt_ec(
                    secret, derived, bytes(36), True, False,
                    network_prefix=b"\x00",
                ))
        with self.assertRaises(ValueError):
            wallets.private_key_to_public_key(b"\x01")

    def test_wallet_load_and_unpickle_do_not_require_ecdsa(self):
        encoded = base58.b58encode_check(b"\x01\x42\xe0" + bytes(36))
        with mock.patch.dict("sys.modules", {"ecdsa": None}):
            wallet = wallets.WalletBIP38(encoded)
            restored = pickle.loads(pickle.dumps(wallet))
        self.assertEqual(restored.enc_privkey, wallet.enc_privkey)
        self.assertEqual(restored.has_compression_flag, True)


if __name__ == "__main__":
    unittest.main()
