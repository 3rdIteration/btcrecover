from lib.keccak import (
    Keccak256,
)
from lib.eth_hash.preimage import (
    BasePreImage,
)


def keccak256(prehash: bytes) -> bytes:
    return Keccak256(prehash).digest()


class preimage(BasePreImage):
    _hash = None

    def __init__(self, prehash) -> None:
        self._hash = Keccak256(prehash)

    def update(self, prehash) -> None:
        return self._hash.update(prehash)

    def digest(self) -> bytes:
        return self._hash.digest()

    def copy(self) -> 'preimage':
        dup = preimage(b'')
        dup._hash._state = self._hash._state[:]
        dup._hash._absorb_offset = self._hash._absorb_offset
        dup._hash._squeezing = self._hash._squeezing
        return dup
