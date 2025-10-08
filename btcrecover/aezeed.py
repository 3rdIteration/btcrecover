"""Utilities for working with aezeed mnemonics."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple

__all__ = [
    "DEFAULT_PASSPHRASE",
    "DecipheredCipherSeed",
    "InvalidMnemonicError",
    "InvalidPassphraseError",
    "decode_mnemonic",
    "mnemonic_to_bytes",
    "validate_mnemonic",
]

DEFAULT_PASSPHRASE = "aezeed"

EncipheredCipherSeedSize = 33
DecipheredCipherSeedSize = 19
SaltSize = 5
CipherTextExpansion = 4
BitsPerWord = 11
CipherSeedVersion = 0


class AezeedError(Exception):
    """Base class for aezeed errors."""


class InvalidMnemonicError(AezeedError):
    """Raised when the mnemonic words fail basic validation."""


class InvalidPassphraseError(AezeedError):
    """Raised when decryption fails due to an incorrect passphrase."""


@dataclass(frozen=True)
class DecipheredCipherSeed:
    entropy: bytes
    salt: bytes
    internal_version: int
    birthday: int


_CRC32C_POLY = 0x82F63B78


def _crc32c_table() -> List[int]:
    table: List[int] = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ _CRC32C_POLY
            else:
                crc >>= 1
        table.append(crc & 0xFFFFFFFF)
    return table


_CRC32C_TABLE = _crc32c_table()


def _crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc = _CRC32C_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return (~crc) & 0xFFFFFFFF


BLOCK_SIZE = 16
EXTRACTED_KEY_SIZE = 3 * BLOCK_SIZE


def _mk_block(size: int = BLOCK_SIZE) -> bytearray:
    return bytearray(size)


ZERO_BLOCK = _mk_block()


def _xor_bytes1x16(a: Sequence[int], b: Sequence[int], dst: bytearray) -> None:
    for i in range(BLOCK_SIZE):
        dst[i] = a[i] ^ b[i]


def _xor_bytes4x16(
    a: Sequence[int], b: Sequence[int], c: Sequence[int], d: Sequence[int], dst: bytearray
) -> None:
    for i in range(BLOCK_SIZE):
        dst[i] = a[i] ^ b[i] ^ c[i] ^ d[i]


def _xor_bytes(a: Sequence[int], b: Sequence[int], dst: bytearray) -> None:
    for i in range(len(dst)):
        dst[i] = a[i] ^ b[i]


def _uint32(i: int) -> int:
    return i & 0xFFFFFFFF


def _uint8(i: int) -> int:
    return i & 0xFF


def _extract_key(key: bytes) -> bytes:
    if len(key) == EXTRACTED_KEY_SIZE:
        return key
    return hashlib.blake2b(key, digest_size=EXTRACTED_KEY_SIZE).digest()


def _mult_block(x: int, src: Sequence[int], dst: bytearray) -> None:
    t = _mk_block()
    r = _mk_block()
    t[:] = src
    while x:
        if x & 1:
            _xor_bytes1x16(r, t, r)
        _double_block(t)
        x >>= 1
    dst[:] = r


def _double_block(p: bytearray) -> None:
    tmp = p[0]
    for i in range(15):
        p[i] = ((p[i] << 1) | (p[i + 1] >> 7)) & 0xFF
    p[15] = ((p[15] << 1) & 0xFE) ^ (0x87 if tmp & 0x80 else 0)


def _one_zero_pad(src: Sequence[int], size: int, dst: bytearray) -> None:
    dst[:] = b"\x00" * len(dst)
    if size:
        dst[:size] = src[:size]
    dst[size] = 0x80



TE0 = [
    0XC66363A5, 0XF87C7C84, 0XEE777799, 0XF67B7B8D, 0XFFF2F20D, 0XD66B6BBD, 0XDE6F6FB1, 0X91C5C554,
    0X60303050, 0X02010103, 0XCE6767A9, 0X562B2B7D, 0XE7FEFE19, 0XB5D7D762, 0X4DABABE6, 0XEC76769A,
    0X8FCACA45, 0X1F82829D, 0X89C9C940, 0XFA7D7D87, 0XEFFAFA15, 0XB25959EB, 0X8E4747C9, 0XFBF0F00B,
    0X41ADADEC, 0XB3D4D467, 0X5FA2A2FD, 0X45AFAFEA, 0X239C9CBF, 0X53A4A4F7, 0XE4727296, 0X9BC0C05B,
    0X75B7B7C2, 0XE1FDFD1C, 0X3D9393AE, 0X4C26266A, 0X6C36365A, 0X7E3F3F41, 0XF5F7F702, 0X83CCCC4F,
    0X6834345C, 0X51A5A5F4, 0XD1E5E534, 0XF9F1F108, 0XE2717193, 0XABD8D873, 0X62313153, 0X2A15153F,
    0X0804040C, 0X95C7C752, 0X46232365, 0X9DC3C35E, 0X30181828, 0X379696A1, 0X0A05050F, 0X2F9A9AB5,
    0X0E070709, 0X24121236, 0X1B80809B, 0XDFE2E23D, 0XCDEBEB26, 0X4E272769, 0X7FB2B2CD, 0XEA75759F,
    0X1209091B, 0X1D83839E, 0X582C2C74, 0X341A1A2E, 0X361B1B2D, 0XDC6E6EB2, 0XB45A5AEE, 0X5BA0A0FB,
    0XA45252F6, 0X763B3B4D, 0XB7D6D661, 0X7DB3B3CE, 0X5229297B, 0XDDE3E33E, 0X5E2F2F71, 0X13848497,
    0XA65353F5, 0XB9D1D168, 0X00000000, 0XC1EDED2C, 0X40202060, 0XE3FCFC1F, 0X79B1B1C8, 0XB65B5BED,
    0XD46A6ABE, 0X8DCBCB46, 0X67BEBED9, 0X7239394B, 0X944A4ADE, 0X984C4CD4, 0XB05858E8, 0X85CFCF4A,
    0XBBD0D06B, 0XC5EFEF2A, 0X4FAAAAE5, 0XEDFBFB16, 0X864343C5, 0X9A4D4DD7, 0X66333355, 0X11858594,
    0X8A4545CF, 0XE9F9F910, 0X04020206, 0XFE7F7F81, 0XA05050F0, 0X783C3C44, 0X259F9FBA, 0X4BA8A8E3,
    0XA25151F3, 0X5DA3A3FE, 0X804040C0, 0X058F8F8A, 0X3F9292AD, 0X219D9DBC, 0X70383848, 0XF1F5F504,
    0X63BCBCDF, 0X77B6B6C1, 0XAFDADA75, 0X42212163, 0X20101030, 0XE5FFFF1A, 0XFDF3F30E, 0XBFD2D26D,
    0X81CDCD4C, 0X180C0C14, 0X26131335, 0XC3ECEC2F, 0XBE5F5FE1, 0X359797A2, 0X884444CC, 0X2E171739,
    0X93C4C457, 0X55A7A7F2, 0XFC7E7E82, 0X7A3D3D47, 0XC86464AC, 0XBA5D5DE7, 0X3219192B, 0XE6737395,
    0XC06060A0, 0X19818198, 0X9E4F4FD1, 0XA3DCDC7F, 0X44222266, 0X542A2A7E, 0X3B9090AB, 0X0B888883,
    0X8C4646CA, 0XC7EEEE29, 0X6BB8B8D3, 0X2814143C, 0XA7DEDE79, 0XBC5E5EE2, 0X160B0B1D, 0XADDBDB76,
    0XDBE0E03B, 0X64323256, 0X743A3A4E, 0X140A0A1E, 0X924949DB, 0X0C06060A, 0X4824246C, 0XB85C5CE4,
    0X9FC2C25D, 0XBDD3D36E, 0X43ACACEF, 0XC46262A6, 0X399191A8, 0X319595A4, 0XD3E4E437, 0XF279798B,
    0XD5E7E732, 0X8BC8C843, 0X6E373759, 0XDA6D6DB7, 0X018D8D8C, 0XB1D5D564, 0X9C4E4ED2, 0X49A9A9E0,
    0XD86C6CB4, 0XAC5656FA, 0XF3F4F407, 0XCFEAEA25, 0XCA6565AF, 0XF47A7A8E, 0X47AEAEE9, 0X10080818,
    0X6FBABAD5, 0XF0787888, 0X4A25256F, 0X5C2E2E72, 0X381C1C24, 0X57A6A6F1, 0X73B4B4C7, 0X97C6C651,
    0XCBE8E823, 0XA1DDDD7C, 0XE874749C, 0X3E1F1F21, 0X964B4BDD, 0X61BDBDDC, 0X0D8B8B86, 0X0F8A8A85,
    0XE0707090, 0X7C3E3E42, 0X71B5B5C4, 0XCC6666AA, 0X904848D8, 0X06030305, 0XF7F6F601, 0X1C0E0E12,
    0XC26161A3, 0X6A35355F, 0XAE5757F9, 0X69B9B9D0, 0X17868691, 0X99C1C158, 0X3A1D1D27, 0X279E9EB9,
    0XD9E1E138, 0XEBF8F813, 0X2B9898B3, 0X22111133, 0XD26969BB, 0XA9D9D970, 0X078E8E89, 0X339494A7,
    0X2D9B9BB6, 0X3C1E1E22, 0X15878792, 0XC9E9E920, 0X87CECE49, 0XAA5555FF, 0X50282878, 0XA5DFDF7A,
    0X038C8C8F, 0X59A1A1F8, 0X09898980, 0X1A0D0D17, 0X65BFBFDA, 0XD7E6E631, 0X844242C6, 0XD06868B8,
    0X824141C3, 0X299999B0, 0X5A2D2D77, 0X1E0F0F11, 0X7BB0B0CB, 0XA85454FC, 0X6DBBBBD6, 0X2C16163A,
]

TE1 = [
    0XA5C66363, 0X84F87C7C, 0X99EE7777, 0X8DF67B7B, 0X0DFFF2F2, 0XBDD66B6B, 0XB1DE6F6F, 0X5491C5C5,
    0X50603030, 0X03020101, 0XA9CE6767, 0X7D562B2B, 0X19E7FEFE, 0X62B5D7D7, 0XE64DABAB, 0X9AEC7676,
    0X458FCACA, 0X9D1F8282, 0X4089C9C9, 0X87FA7D7D, 0X15EFFAFA, 0XEBB25959, 0XC98E4747, 0X0BFBF0F0,
    0XEC41ADAD, 0X67B3D4D4, 0XFD5FA2A2, 0XEA45AFAF, 0XBF239C9C, 0XF753A4A4, 0X96E47272, 0X5B9BC0C0,
    0XC275B7B7, 0X1CE1FDFD, 0XAE3D9393, 0X6A4C2626, 0X5A6C3636, 0X417E3F3F, 0X02F5F7F7, 0X4F83CCCC,
    0X5C683434, 0XF451A5A5, 0X34D1E5E5, 0X08F9F1F1, 0X93E27171, 0X73ABD8D8, 0X53623131, 0X3F2A1515,
    0X0C080404, 0X5295C7C7, 0X65462323, 0X5E9DC3C3, 0X28301818, 0XA1379696, 0X0F0A0505, 0XB52F9A9A,
    0X090E0707, 0X36241212, 0X9B1B8080, 0X3DDFE2E2, 0X26CDEBEB, 0X694E2727, 0XCD7FB2B2, 0X9FEA7575,
    0X1B120909, 0X9E1D8383, 0X74582C2C, 0X2E341A1A, 0X2D361B1B, 0XB2DC6E6E, 0XEEB45A5A, 0XFB5BA0A0,
    0XF6A45252, 0X4D763B3B, 0X61B7D6D6, 0XCE7DB3B3, 0X7B522929, 0X3EDDE3E3, 0X715E2F2F, 0X97138484,
    0XF5A65353, 0X68B9D1D1, 0X00000000, 0X2CC1EDED, 0X60402020, 0X1FE3FCFC, 0XC879B1B1, 0XEDB65B5B,
    0XBED46A6A, 0X468DCBCB, 0XD967BEBE, 0X4B723939, 0XDE944A4A, 0XD4984C4C, 0XE8B05858, 0X4A85CFCF,
    0X6BBBD0D0, 0X2AC5EFEF, 0XE54FAAAA, 0X16EDFBFB, 0XC5864343, 0XD79A4D4D, 0X55663333, 0X94118585,
    0XCF8A4545, 0X10E9F9F9, 0X06040202, 0X81FE7F7F, 0XF0A05050, 0X44783C3C, 0XBA259F9F, 0XE34BA8A8,
    0XF3A25151, 0XFE5DA3A3, 0XC0804040, 0X8A058F8F, 0XAD3F9292, 0XBC219D9D, 0X48703838, 0X04F1F5F5,
    0XDF63BCBC, 0XC177B6B6, 0X75AFDADA, 0X63422121, 0X30201010, 0X1AE5FFFF, 0X0EFDF3F3, 0X6DBFD2D2,
    0X4C81CDCD, 0X14180C0C, 0X35261313, 0X2FC3ECEC, 0XE1BE5F5F, 0XA2359797, 0XCC884444, 0X392E1717,
    0X5793C4C4, 0XF255A7A7, 0X82FC7E7E, 0X477A3D3D, 0XACC86464, 0XE7BA5D5D, 0X2B321919, 0X95E67373,
    0XA0C06060, 0X98198181, 0XD19E4F4F, 0X7FA3DCDC, 0X66442222, 0X7E542A2A, 0XAB3B9090, 0X830B8888,
    0XCA8C4646, 0X29C7EEEE, 0XD36BB8B8, 0X3C281414, 0X79A7DEDE, 0XE2BC5E5E, 0X1D160B0B, 0X76ADDBDB,
    0X3BDBE0E0, 0X56643232, 0X4E743A3A, 0X1E140A0A, 0XDB924949, 0X0A0C0606, 0X6C482424, 0XE4B85C5C,
    0X5D9FC2C2, 0X6EBDD3D3, 0XEF43ACAC, 0XA6C46262, 0XA8399191, 0XA4319595, 0X37D3E4E4, 0X8BF27979,
    0X32D5E7E7, 0X438BC8C8, 0X596E3737, 0XB7DA6D6D, 0X8C018D8D, 0X64B1D5D5, 0XD29C4E4E, 0XE049A9A9,
    0XB4D86C6C, 0XFAAC5656, 0X07F3F4F4, 0X25CFEAEA, 0XAFCA6565, 0X8EF47A7A, 0XE947AEAE, 0X18100808,
    0XD56FBABA, 0X88F07878, 0X6F4A2525, 0X725C2E2E, 0X24381C1C, 0XF157A6A6, 0XC773B4B4, 0X5197C6C6,
    0X23CBE8E8, 0X7CA1DDDD, 0X9CE87474, 0X213E1F1F, 0XDD964B4B, 0XDC61BDBD, 0X860D8B8B, 0X850F8A8A,
    0X90E07070, 0X427C3E3E, 0XC471B5B5, 0XAACC6666, 0XD8904848, 0X05060303, 0X01F7F6F6, 0X121C0E0E,
    0XA3C26161, 0X5F6A3535, 0XF9AE5757, 0XD069B9B9, 0X91178686, 0X5899C1C1, 0X273A1D1D, 0XB9279E9E,
    0X38D9E1E1, 0X13EBF8F8, 0XB32B9898, 0X33221111, 0XBBD26969, 0X70A9D9D9, 0X89078E8E, 0XA7339494,
    0XB62D9B9B, 0X223C1E1E, 0X92158787, 0X20C9E9E9, 0X4987CECE, 0XFFAA5555, 0X78502828, 0X7AA5DFDF,
    0X8F038C8C, 0XF859A1A1, 0X80098989, 0X171A0D0D, 0XDA65BFBF, 0X31D7E6E6, 0XC6844242, 0XB8D06868,
    0XC3824141, 0XB0299999, 0X775A2D2D, 0X111E0F0F, 0XCB7BB0B0, 0XFCA85454, 0XD66DBBBB, 0X3A2C1616,
]

TE2 = [
    0X63A5C663, 0X7C84F87C, 0X7799EE77, 0X7B8DF67B, 0XF20DFFF2, 0X6BBDD66B, 0X6FB1DE6F, 0XC55491C5,
    0X30506030, 0X01030201, 0X67A9CE67, 0X2B7D562B, 0XFE19E7FE, 0XD762B5D7, 0XABE64DAB, 0X769AEC76,
    0XCA458FCA, 0X829D1F82, 0XC94089C9, 0X7D87FA7D, 0XFA15EFFA, 0X59EBB259, 0X47C98E47, 0XF00BFBF0,
    0XADEC41AD, 0XD467B3D4, 0XA2FD5FA2, 0XAFEA45AF, 0X9CBF239C, 0XA4F753A4, 0X7296E472, 0XC05B9BC0,
    0XB7C275B7, 0XFD1CE1FD, 0X93AE3D93, 0X266A4C26, 0X365A6C36, 0X3F417E3F, 0XF702F5F7, 0XCC4F83CC,
    0X345C6834, 0XA5F451A5, 0XE534D1E5, 0XF108F9F1, 0X7193E271, 0XD873ABD8, 0X31536231, 0X153F2A15,
    0X040C0804, 0XC75295C7, 0X23654623, 0XC35E9DC3, 0X18283018, 0X96A13796, 0X050F0A05, 0X9AB52F9A,
    0X07090E07, 0X12362412, 0X809B1B80, 0XE23DDFE2, 0XEB26CDEB, 0X27694E27, 0XB2CD7FB2, 0X759FEA75,
    0X091B1209, 0X839E1D83, 0X2C74582C, 0X1A2E341A, 0X1B2D361B, 0X6EB2DC6E, 0X5AEEB45A, 0XA0FB5BA0,
    0X52F6A452, 0X3B4D763B, 0XD661B7D6, 0XB3CE7DB3, 0X297B5229, 0XE33EDDE3, 0X2F715E2F, 0X84971384,
    0X53F5A653, 0XD168B9D1, 0X00000000, 0XED2CC1ED, 0X20604020, 0XFC1FE3FC, 0XB1C879B1, 0X5BEDB65B,
    0X6ABED46A, 0XCB468DCB, 0XBED967BE, 0X394B7239, 0X4ADE944A, 0X4CD4984C, 0X58E8B058, 0XCF4A85CF,
    0XD06BBBD0, 0XEF2AC5EF, 0XAAE54FAA, 0XFB16EDFB, 0X43C58643, 0X4DD79A4D, 0X33556633, 0X85941185,
    0X45CF8A45, 0XF910E9F9, 0X02060402, 0X7F81FE7F, 0X50F0A050, 0X3C44783C, 0X9FBA259F, 0XA8E34BA8,
    0X51F3A251, 0XA3FE5DA3, 0X40C08040, 0X8F8A058F, 0X92AD3F92, 0X9DBC219D, 0X38487038, 0XF504F1F5,
    0XBCDF63BC, 0XB6C177B6, 0XDA75AFDA, 0X21634221, 0X10302010, 0XFF1AE5FF, 0XF30EFDF3, 0XD26DBFD2,
    0XCD4C81CD, 0X0C14180C, 0X13352613, 0XEC2FC3EC, 0X5FE1BE5F, 0X97A23597, 0X44CC8844, 0X17392E17,
    0XC45793C4, 0XA7F255A7, 0X7E82FC7E, 0X3D477A3D, 0X64ACC864, 0X5DE7BA5D, 0X192B3219, 0X7395E673,
    0X60A0C060, 0X81981981, 0X4FD19E4F, 0XDC7FA3DC, 0X22664422, 0X2A7E542A, 0X90AB3B90, 0X88830B88,
    0X46CA8C46, 0XEE29C7EE, 0XB8D36BB8, 0X143C2814, 0XDE79A7DE, 0X5EE2BC5E, 0X0B1D160B, 0XDB76ADDB,
    0XE03BDBE0, 0X32566432, 0X3A4E743A, 0X0A1E140A, 0X49DB9249, 0X060A0C06, 0X246C4824, 0X5CE4B85C,
    0XC25D9FC2, 0XD36EBDD3, 0XACEF43AC, 0X62A6C462, 0X91A83991, 0X95A43195, 0XE437D3E4, 0X798BF279,
    0XE732D5E7, 0XC8438BC8, 0X37596E37, 0X6DB7DA6D, 0X8D8C018D, 0XD564B1D5, 0X4ED29C4E, 0XA9E049A9,
    0X6CB4D86C, 0X56FAAC56, 0XF407F3F4, 0XEA25CFEA, 0X65AFCA65, 0X7A8EF47A, 0XAEE947AE, 0X08181008,
    0XBAD56FBA, 0X7888F078, 0X256F4A25, 0X2E725C2E, 0X1C24381C, 0XA6F157A6, 0XB4C773B4, 0XC65197C6,
    0XE823CBE8, 0XDD7CA1DD, 0X749CE874, 0X1F213E1F, 0X4BDD964B, 0XBDDC61BD, 0X8B860D8B, 0X8A850F8A,
    0X7090E070, 0X3E427C3E, 0XB5C471B5, 0X66AACC66, 0X48D89048, 0X03050603, 0XF601F7F6, 0X0E121C0E,
    0X61A3C261, 0X355F6A35, 0X57F9AE57, 0XB9D069B9, 0X86911786, 0XC15899C1, 0X1D273A1D, 0X9EB9279E,
    0XE138D9E1, 0XF813EBF8, 0X98B32B98, 0X11332211, 0X69BBD269, 0XD970A9D9, 0X8E89078E, 0X94A73394,
    0X9BB62D9B, 0X1E223C1E, 0X87921587, 0XE920C9E9, 0XCE4987CE, 0X55FFAA55, 0X28785028, 0XDF7AA5DF,
    0X8C8F038C, 0XA1F859A1, 0X89800989, 0X0D171A0D, 0XBFDA65BF, 0XE631D7E6, 0X42C68442, 0X68B8D068,
    0X41C38241, 0X99B02999, 0X2D775A2D, 0X0F111E0F, 0XB0CB7BB0, 0X54FCA854, 0XBBD66DBB, 0X163A2C16,
]

TE3 = [
    0X6363A5C6, 0X7C7C84F8, 0X777799EE, 0X7B7B8DF6, 0XF2F20DFF, 0X6B6BBDD6, 0X6F6FB1DE, 0XC5C55491,
    0X30305060, 0X01010302, 0X6767A9CE, 0X2B2B7D56, 0XFEFE19E7, 0XD7D762B5, 0XABABE64D, 0X76769AEC,
    0XCACA458F, 0X82829D1F, 0XC9C94089, 0X7D7D87FA, 0XFAFA15EF, 0X5959EBB2, 0X4747C98E, 0XF0F00BFB,
    0XADADEC41, 0XD4D467B3, 0XA2A2FD5F, 0XAFAFEA45, 0X9C9CBF23, 0XA4A4F753, 0X727296E4, 0XC0C05B9B,
    0XB7B7C275, 0XFDFD1CE1, 0X9393AE3D, 0X26266A4C, 0X36365A6C, 0X3F3F417E, 0XF7F702F5, 0XCCCC4F83,
    0X34345C68, 0XA5A5F451, 0XE5E534D1, 0XF1F108F9, 0X717193E2, 0XD8D873AB, 0X31315362, 0X15153F2A,
    0X04040C08, 0XC7C75295, 0X23236546, 0XC3C35E9D, 0X18182830, 0X9696A137, 0X05050F0A, 0X9A9AB52F,
    0X0707090E, 0X12123624, 0X80809B1B, 0XE2E23DDF, 0XEBEB26CD, 0X2727694E, 0XB2B2CD7F, 0X75759FEA,
    0X09091B12, 0X83839E1D, 0X2C2C7458, 0X1A1A2E34, 0X1B1B2D36, 0X6E6EB2DC, 0X5A5AEEB4, 0XA0A0FB5B,
    0X5252F6A4, 0X3B3B4D76, 0XD6D661B7, 0XB3B3CE7D, 0X29297B52, 0XE3E33EDD, 0X2F2F715E, 0X84849713,
    0X5353F5A6, 0XD1D168B9, 0X00000000, 0XEDED2CC1, 0X20206040, 0XFCFC1FE3, 0XB1B1C879, 0X5B5BEDB6,
    0X6A6ABED4, 0XCBCB468D, 0XBEBED967, 0X39394B72, 0X4A4ADE94, 0X4C4CD498, 0X5858E8B0, 0XCFCF4A85,
    0XD0D06BBB, 0XEFEF2AC5, 0XAAAAE54F, 0XFBFB16ED, 0X4343C586, 0X4D4DD79A, 0X33335566, 0X85859411,
    0X4545CF8A, 0XF9F910E9, 0X02020604, 0X7F7F81FE, 0X5050F0A0, 0X3C3C4478, 0X9F9FBA25, 0XA8A8E34B,
    0X5151F3A2, 0XA3A3FE5D, 0X4040C080, 0X8F8F8A05, 0X9292AD3F, 0X9D9DBC21, 0X38384870, 0XF5F504F1,
    0XBCBCDF63, 0XB6B6C177, 0XDADA75AF, 0X21216342, 0X10103020, 0XFFFF1AE5, 0XF3F30EFD, 0XD2D26DBF,
    0XCDCD4C81, 0X0C0C1418, 0X13133526, 0XECEC2FC3, 0X5F5FE1BE, 0X9797A235, 0X4444CC88, 0X1717392E,
    0XC4C45793, 0XA7A7F255, 0X7E7E82FC, 0X3D3D477A, 0X6464ACC8, 0X5D5DE7BA, 0X19192B32, 0X737395E6,
    0X6060A0C0, 0X81819819, 0X4F4FD19E, 0XDCDC7FA3, 0X22226644, 0X2A2A7E54, 0X9090AB3B, 0X8888830B,
    0X4646CA8C, 0XEEEE29C7, 0XB8B8D36B, 0X14143C28, 0XDEDE79A7, 0X5E5EE2BC, 0X0B0B1D16, 0XDBDB76AD,
    0XE0E03BDB, 0X32325664, 0X3A3A4E74, 0X0A0A1E14, 0X4949DB92, 0X06060A0C, 0X24246C48, 0X5C5CE4B8,
    0XC2C25D9F, 0XD3D36EBD, 0XACACEF43, 0X6262A6C4, 0X9191A839, 0X9595A431, 0XE4E437D3, 0X79798BF2,
    0XE7E732D5, 0XC8C8438B, 0X3737596E, 0X6D6DB7DA, 0X8D8D8C01, 0XD5D564B1, 0X4E4ED29C, 0XA9A9E049,
    0X6C6CB4D8, 0X5656FAAC, 0XF4F407F3, 0XEAEA25CF, 0X6565AFCA, 0X7A7A8EF4, 0XAEAEE947, 0X08081810,
    0XBABAD56F, 0X787888F0, 0X25256F4A, 0X2E2E725C, 0X1C1C2438, 0XA6A6F157, 0XB4B4C773, 0XC6C65197,
    0XE8E823CB, 0XDDDD7CA1, 0X74749CE8, 0X1F1F213E, 0X4B4BDD96, 0XBDBDDC61, 0X8B8B860D, 0X8A8A850F,
    0X707090E0, 0X3E3E427C, 0XB5B5C471, 0X6666AACC, 0X4848D890, 0X03030506, 0XF6F601F7, 0X0E0E121C,
    0X6161A3C2, 0X35355F6A, 0X5757F9AE, 0XB9B9D069, 0X86869117, 0XC1C15899, 0X1D1D273A, 0X9E9EB927,
    0XE1E138D9, 0XF8F813EB, 0X9898B32B, 0X11113322, 0X6969BBD2, 0XD9D970A9, 0X8E8E8907, 0X9494A733,
    0X9B9BB62D, 0X1E1E223C, 0X87879215, 0XE9E920C9, 0XCECE4987, 0X5555FFAA, 0X28287850, 0XDFDF7AA5,
    0X8C8C8F03, 0XA1A1F859, 0X89898009, 0X0D0D171A, 0XBFBFDA65, 0XE6E631D7, 0X4242C684, 0X6868B8D0,
    0X4141C382, 0X9999B029, 0X2D2D775A, 0X0F0F111E, 0XB0B0CB7B, 0X5454FCA8, 0XBBBBD66D, 0X16163A2C,
]


def _read_uint32_be(block: Sequence[int], offset: int) -> int:
    return int.from_bytes(bytes(block[offset:offset + 4]), "big")


def _write_uint32_be(block: bytearray, offset: int, value: int) -> None:
    block[offset:offset + 4] = value.to_bytes(4, "big")


class _AESRound:
    def __init__(self, key: bytes) -> None:
        words = [_read_uint32_be(key, 4 * i) for i in range(12)]
        self.aes10_key = [0] * (4 * 10)
        self.aes4_key = [0] * (4 * 4)
        self.aes10_key[0:12] = words
        self.aes10_key[12:24] = words
        self.aes10_key[24:36] = words
        self.aes10_key[36:40] = words[0:4]
        self.aes4_key[0:4] = words[4:8]
        self.aes4_key[4:8] = words[0:4]
        self.aes4_key[8:12] = words[8:12]

    def reset(self) -> None:
        for i in range(len(self.aes10_key)):
            self.aes10_key[i] = 0
        for i in range(len(self.aes4_key)):
            self.aes4_key[i] = 0

    def AES4(
        self,
        j: Sequence[int],
        i_vec: Sequence[int],
        l_vec: Sequence[int],
        src: Sequence[int],
        dst: bytearray,
    ) -> None:
        _xor_bytes4x16(j, i_vec, l_vec, src, dst)
        self.rounds(dst, 4)

    def AES10(self, l_vec: Sequence[int], src: Sequence[int], dst: bytearray) -> None:
        _xor_bytes1x16(src, l_vec, dst)
        self.rounds(dst, 10)

    def rounds(self, block: bytearray, rounds: int) -> None:
        keys = self.aes4_key if rounds == 4 else self.aes10_key
        s0 = _read_uint32_be(block, 0)
        s1 = _read_uint32_be(block, 4)
        s2 = _read_uint32_be(block, 8)
        s3 = _read_uint32_be(block, 12)

        for r in range(rounds):
            rk_off = r * 4
            t0 = (
                TE0[_uint8(s0 >> 24)]
                ^ TE1[_uint8(s1 >> 16)]
                ^ TE2[_uint8(s2 >> 8)]
                ^ TE3[_uint8(s3)]
                ^ keys[rk_off]
            )
            t1 = (
                TE0[_uint8(s1 >> 24)]
                ^ TE1[_uint8(s2 >> 16)]
                ^ TE2[_uint8(s3 >> 8)]
                ^ TE3[_uint8(s0)]
                ^ keys[rk_off + 1]
            )
            t2 = (
                TE0[_uint8(s2 >> 24)]
                ^ TE1[_uint8(s3 >> 16)]
                ^ TE2[_uint8(s0 >> 8)]
                ^ TE3[_uint8(s1)]
                ^ keys[rk_off + 2]
            )
            t3 = (
                TE0[_uint8(s3 >> 24)]
                ^ TE1[_uint8(s0 >> 16)]
                ^ TE2[_uint8(s1 >> 8)]
                ^ TE3[_uint8(s2)]
                ^ keys[rk_off + 3]
            )
            s0 = _uint32(t0)
            s1 = _uint32(t1)
            s2 = _uint32(t2)
            s3 = _uint32(t3)

        _write_uint32_be(block, 0, s0)
        _write_uint32_be(block, 4, s1)
        _write_uint32_be(block, 8, s2)
        _write_uint32_be(block, 12, s3)




class _AEZState:
    def __init__(self) -> None:
        self.I = [_mk_block(), _mk_block()]
        self.J = [_mk_block(), _mk_block(), _mk_block()]
        self.L = [_mk_block() for _ in range(8)]
        self.aes: _AESRound | None = None

    def reset(self) -> None:
        for buf in self.I + self.J + self.L:
            for i in range(len(buf)):
                buf[i] = 0
        if self.aes:
            self.aes.reset()

    def init(self, key: bytes) -> None:
        extracted = _extract_key(key)
        self.I[0][:] = extracted[0:16]
        _mult_block(2, self.I[0], self.I[1])
        self.J[0][:] = extracted[16:32]
        _mult_block(2, self.J[0], self.J[1])
        _mult_block(2, self.J[1], self.J[2])
        self.L[1][:] = extracted[32:48]
        _mult_block(2, self.L[1], self.L[2])
        _xor_bytes1x16(self.L[2], self.L[1], self.L[3])
        _mult_block(2, self.L[2], self.L[4])
        _xor_bytes1x16(self.L[4], self.L[1], self.L[5])
        _mult_block(2, self.L[3], self.L[6])
        _xor_bytes1x16(self.L[6], self.L[1], self.L[7])
        self.aes = _AESRound(extracted)

    def aez_hash(self, nonce: bytes | None, ad: Iterable[bytes], tau: int) -> bytearray:
        assert self.aes is not None
        buf = _mk_block()
        sum_block = _mk_block()
        I_tmp = _mk_block()
        J_tmp = _mk_block()
        buf[12:16] = _uint32(tau).to_bytes(4, "big")
        _xor_bytes1x16(self.J[0], self.J[1], J_tmp)
        self.aes.AES4(J_tmp, self.I[1], self.L[1], buf, sum_block)

        empty_nonce = not nonce
        n_bytes = len(nonce) if nonce else 0
        I_tmp[:] = self.I[1]
        offset = 0
        i = 1
        while n_bytes >= BLOCK_SIZE:
            block = nonce[offset:offset + BLOCK_SIZE]
            tmp = _mk_block()
            tmp[:BLOCK_SIZE] = block
            self.aes.AES4(self.J[2], I_tmp, self.L[i % 8], tmp, buf)
            _xor_bytes1x16(sum_block, buf, sum_block)
            offset += BLOCK_SIZE
            n_bytes -= BLOCK_SIZE
            if i % 8 == 0:
                _double_block(I_tmp)
            i += 1
        if n_bytes > 0 or empty_nonce:
            buf[:] = b"\x00" * BLOCK_SIZE
            if not empty_nonce and nonce is not None:
                buf[:n_bytes] = nonce[offset:offset + n_bytes]
            buf[n_bytes] = 0x80
            self.aes.AES4(self.J[2], self.I[0], self.L[0], buf, buf)
            _xor_bytes1x16(sum_block, buf, sum_block)

        for k, piece in enumerate(ad):
            empty_piece = not piece
            bytes_left = len(piece) if piece else 0
            I_tmp[:] = self.I[1]
            J_tmp2 = _mk_block()
            _mult_block(5 + k, self.J[0], J_tmp2)
            offset = 0
            i = 1
            while bytes_left >= BLOCK_SIZE:
                tmp_in = piece[offset:offset + BLOCK_SIZE]
                tmp = _mk_block()
                tmp[:BLOCK_SIZE] = tmp_in
                self.aes.AES4(J_tmp2, I_tmp, self.L[i % 8], tmp, buf)
                _xor_bytes1x16(sum_block, buf, sum_block)
                offset += BLOCK_SIZE
                bytes_left -= BLOCK_SIZE
                if i % 8 == 0:
                    _double_block(I_tmp)
                i += 1
            if bytes_left > 0 or empty_piece:
                buf[:] = b"\x00" * BLOCK_SIZE
                if not empty_piece and piece:
                    buf[:bytes_left] = piece[offset:offset + bytes_left]
                buf[bytes_left] = 0x80
                self.aes.AES4(J_tmp2, self.I[0], self.L[0], buf, buf)
                _xor_bytes1x16(sum_block, buf, sum_block)

        return sum_block

    def aez_prf(self, delta: Sequence[int], tau: int, dst: bytearray) -> None:
        assert self.aes is not None
        buf = _mk_block()
        ctr = _mk_block()
        off = 0
        remaining = tau
        while remaining >= BLOCK_SIZE:
            _xor_bytes1x16(delta, ctr, buf)
            self.aes.AES10(self.L[3], buf, buf)
            dst[off:off + BLOCK_SIZE] = buf
            for idx in range(15, -1, -1):
                ctr[idx] = (ctr[idx] + 1) & 0xFF
                if ctr[idx] != 0:
                    break
            off += BLOCK_SIZE
            remaining -= BLOCK_SIZE
        if remaining > 0:
            _xor_bytes1x16(delta, ctr, buf)
            self.aes.AES10(self.L[3], buf, buf)
            dst[off:off + remaining] = buf[:remaining]

    def encipher(self, delta: Sequence[int], data: bytes, dst: bytearray) -> None:
        if not data:
            return
        if len(data) < 32:
            self.aez_tiny(delta, data, 0, dst)
        else:
            self.aez_core(delta, data, 0, dst)

    def decipher(self, delta: Sequence[int], data: bytes, dst: bytearray) -> None:
        if not data:
            return
        if len(data) < 32:
            self.aez_tiny(delta, data, 1, dst)
        else:
            self.aez_core(delta, data, 1, dst)

    def aez_tiny(self, delta: Sequence[int], data: bytes, direction: int, dst: bytearray) -> None:
        assert self.aes is not None
        in_bytes = len(data)
        buf = bytearray(2 * BLOCK_SIZE)
        buf_view = memoryview(buf)
        L = _mk_block()
        R = _mk_block()
        tmp = _mk_block()
        mask = 0x00
        pad = 0x80
        idx_param = 7
        if in_bytes == 1:
            rounds = 24
        elif in_bytes == 2:
            rounds = 16
        elif in_bytes < BLOCK_SIZE:
            rounds = 10
        else:
            idx_param = 6
            rounds = 8

        left_len = (in_bytes + 1) // 2
        right_start = in_bytes // 2
        L[:left_len] = data[:left_len]
        R[:left_len] = data[right_start:right_start + left_len]
        if in_bytes & 1:
            half = in_bytes // 2
            for k in range(half):
                R[k] = ((R[k] << 4) | (R[k + 1] >> 4)) & 0xFF
            R[half] = (R[half] << 4) & 0xFF
            pad = 0x08
            mask = 0xF0

        if direction != 0:
            if in_bytes < BLOCK_SIZE:
                buf[:BLOCK_SIZE] = b"\x00" * BLOCK_SIZE
                buf[:in_bytes] = data
                buf[0] |= 0x80
                _xor_bytes1x16(delta, buf_view[:BLOCK_SIZE], buf_view[:BLOCK_SIZE])
                self.aes.AES4(ZERO_BLOCK, self.I[1], self.L[3], buf_view[:BLOCK_SIZE], tmp)
                L[0] ^= tmp[0] & 0x80
            j = rounds - 1
            step = -1
        else:
            j = 0
            step = 1

        for _ in range(rounds // 2):
            buf[:BLOCK_SIZE] = b"\x00" * BLOCK_SIZE
            buf[:left_len] = R[:left_len]
            mid_index = in_bytes // 2
            buf[mid_index] = (buf[mid_index] & mask) | pad
            _xor_bytes1x16(buf_view[:BLOCK_SIZE], delta, buf_view[:BLOCK_SIZE])
            buf[15] ^= j & 0xFF
            self.aes.AES4(ZERO_BLOCK, self.I[1], self.L[idx_param], buf_view[:BLOCK_SIZE], tmp)
            _xor_bytes1x16(L, tmp, L)

            buf[:BLOCK_SIZE] = b"\x00" * BLOCK_SIZE
            buf[:left_len] = L[:left_len]
            buf[mid_index] = (buf[mid_index] & mask) | pad
            _xor_bytes1x16(buf_view[:BLOCK_SIZE], delta, buf_view[:BLOCK_SIZE])
            buf[15] ^= (j + step) & 0xFF
            self.aes.AES4(ZERO_BLOCK, self.I[1], self.L[idx_param], buf_view[:BLOCK_SIZE], tmp)
            _xor_bytes1x16(R, tmp, R)
            j += step * 2

        half = in_bytes // 2
        buf[:half] = R[:half]
        buf[half:half + left_len] = L[:left_len]
        if in_bytes & 1:
            for k in range(in_bytes - 1, half, -1):
                buf[k] = ((buf[k] >> 4) | (buf[k - 1] << 4)) & 0xFF
            buf[half] = ((L[0] >> 4) & 0x0F) | (R[half] & 0xF0)

        dst[:in_bytes] = buf[:in_bytes]
        if in_bytes < BLOCK_SIZE and direction == 0:
            buf[in_bytes:BLOCK_SIZE] = b"\x00" * (BLOCK_SIZE - in_bytes)
            buf[0] |= 0x80
            _xor_bytes1x16(delta, buf_view[:BLOCK_SIZE], buf_view[:BLOCK_SIZE])
            self.aes.AES4(ZERO_BLOCK, self.I[1], self.L[3], buf_view[:BLOCK_SIZE], tmp)
            dst[0] ^= tmp[0] & 0x80

    def aez_core(self, delta: Sequence[int], data: bytes, direction: int, dst: bytearray) -> None:
        assert self.aes is not None
        in_bytes = len(data)
        frag_bytes = in_bytes % 32
        initial_bytes = in_bytes - frag_bytes - 32
        tmp = _mk_block()
        X = _mk_block()
        Y = _mk_block()
        S = _mk_block()
        input_bytes = bytearray(data)

        if in_bytes >= 64:
            self.aez_core_pass1(input_bytes, dst, X)

        tail = input_bytes[initial_bytes:]
        if frag_bytes >= BLOCK_SIZE:
            buf = _mk_block()
            buf[:BLOCK_SIZE] = tail[BLOCK_SIZE:BLOCK_SIZE * 2]
            self.aes.AES4(ZERO_BLOCK, self.I[1], self.L[4], buf, tmp)
            _xor_bytes1x16(X, tmp, X)
            padded = _mk_block()
            _one_zero_pad(tail[BLOCK_SIZE:], frag_bytes - BLOCK_SIZE, padded)
            self.aes.AES4(ZERO_BLOCK, self.I[1], self.L[5], padded, tmp)
            _xor_bytes1x16(X, tmp, X)
        elif frag_bytes > 0:
            padded = _mk_block()
            _one_zero_pad(tail, frag_bytes, padded)
            self.aes.AES4(ZERO_BLOCK, self.I[1], self.L[4], padded, tmp)
            _xor_bytes1x16(X, tmp, X)

        dst_tail = dst[in_bytes - 32:in_bytes]
        input_tail = input_bytes[in_bytes - 32:in_bytes]
        block1 = _mk_block()
        block1[:BLOCK_SIZE] = input_tail[:BLOCK_SIZE]
        block2 = _mk_block()
        block2[:BLOCK_SIZE] = input_tail[BLOCK_SIZE:BLOCK_SIZE * 2]
        self.aes.AES4(ZERO_BLOCK, self.I[1], self.L[(1 + direction) % 8], block2, tmp)
        first_dst = _mk_block()
        _xor_bytes4x16(X, block1, delta, tmp, first_dst)
        dst_tail[:BLOCK_SIZE] = first_dst
        tmp2 = _mk_block()
        self.aes.AES10(self.L[(1 + direction) % 8], first_dst, tmp2)
        second_dst = bytearray(block2)
        _xor_bytes1x16(second_dst, tmp2, second_dst)
        dst_tail[BLOCK_SIZE:BLOCK_SIZE * 2] = second_dst
        _xor_bytes1x16(first_dst, second_dst, S)

        if in_bytes >= 64:
            self.aez_core_pass2(input_bytes, dst, Y, S)

        dst_fragment = dst[initial_bytes:]
        input_fragment = input_bytes[initial_bytes:]
        if frag_bytes >= BLOCK_SIZE:
            tmp_block = _mk_block()
            self.aes.AES10(self.L[4], S, tmp_block)
            block = bytearray(input_fragment[:BLOCK_SIZE])
            _xor_bytes1x16(block, tmp_block, block)
            dst_fragment[:BLOCK_SIZE] = block
            self.aes.AES4(ZERO_BLOCK, self.I[1], self.L[4], block, tmp)
            _xor_bytes1x16(Y, tmp, Y)

            remaining = frag_bytes - BLOCK_SIZE
            tmp_block = _mk_block()
            self.aes.AES10(self.L[5], S, tmp_block)
            buf = bytearray(tmp_block)
            fragment = bytearray(input_fragment[BLOCK_SIZE:BLOCK_SIZE + remaining])
            for idx in range(remaining):
                buf[idx] ^= fragment[idx]
            dst_fragment[BLOCK_SIZE:BLOCK_SIZE + remaining] = buf[:remaining]
            buf[:] = b"\x00" * BLOCK_SIZE
            buf[:remaining] = dst_fragment[BLOCK_SIZE:BLOCK_SIZE + remaining]
            buf[remaining] = 0x80
            self.aes.AES4(ZERO_BLOCK, self.I[1], self.L[5], buf, tmp)
            _xor_bytes1x16(Y, tmp, Y)
            dst_fragment = dst_fragment[BLOCK_SIZE + remaining:]
            input_fragment = input_fragment[BLOCK_SIZE + remaining:]
        elif frag_bytes > 0:
            tmp_block = _mk_block()
            self.aes.AES10(self.L[4], S, tmp_block)
            buf = bytearray(tmp_block)
            fragment = bytearray(input_fragment[:frag_bytes])
            for idx in range(frag_bytes):
                buf[idx] ^= fragment[idx]
            dst_fragment[:frag_bytes] = buf[:frag_bytes]
            buf[:] = b"\x00" * BLOCK_SIZE
            buf[:frag_bytes] = dst_fragment[:frag_bytes]
            buf[frag_bytes] = 0x80
            self.aes.AES4(ZERO_BLOCK, self.I[1], self.L[4], buf, tmp)
            _xor_bytes1x16(Y, tmp, Y)
            dst_fragment = dst_fragment[frag_bytes:]
            input_fragment = input_fragment[frag_bytes:]

        dst_tail = dst[in_bytes - 32:in_bytes]
        second_half = bytearray(dst_tail[BLOCK_SIZE:BLOCK_SIZE * 2])
        tmp_block = _mk_block()
        self.aes.AES10(self.L[(2 - direction) % 8], second_half, tmp_block)
        first_half = bytearray(dst_tail[:BLOCK_SIZE])
        _xor_bytes1x16(first_half, tmp_block, first_half)
        dst_tail[:BLOCK_SIZE] = first_half
        self.aes.AES4(ZERO_BLOCK, self.I[1], self.L[(2 - direction) % 8], first_half, tmp)
        combined = _mk_block()
        _xor_bytes4x16(tmp, dst_tail[BLOCK_SIZE:BLOCK_SIZE * 2], delta, Y, combined)
        dst_tail[BLOCK_SIZE:BLOCK_SIZE * 2] = combined
        tmp_copy = bytearray(dst_tail[:BLOCK_SIZE])
        dst_tail[:BLOCK_SIZE] = combined
        dst_tail[BLOCK_SIZE:BLOCK_SIZE * 2] = tmp_copy

    def aez_core_pass1(self, input_bytes: bytearray, output: bytearray, X: bytearray) -> None:
        assert self.aes is not None
        tmp = _mk_block()
        I_tmp = _mk_block()
        I_tmp[:] = self.I[1]
        offset = 0
        remaining = len(input_bytes)
        i = 1
        while remaining >= 64:
            block1 = bytearray(input_bytes[offset + BLOCK_SIZE:offset + BLOCK_SIZE * 2])
            self.aes.AES4(self.J[0], I_tmp, self.L[i % 8], block1, tmp)
            first_out = bytearray(input_bytes[offset:offset + BLOCK_SIZE])
            _xor_bytes1x16(first_out, tmp, first_out)
            output[offset:offset + BLOCK_SIZE] = first_out

            self.aes.AES4(ZERO_BLOCK, self.I[0], self.L[0], first_out, tmp)
            second_out = bytearray(input_bytes[offset + BLOCK_SIZE:offset + BLOCK_SIZE * 2])
            _xor_bytes1x16(second_out, tmp, second_out)
            output[offset + BLOCK_SIZE:offset + BLOCK_SIZE * 2] = second_out
            _xor_bytes1x16(second_out, X, X)

            offset += 32
            remaining -= 32
            i += 1
            if i % 8 == 0:
                _double_block(I_tmp)

    def aez_core_pass2(self, input_bytes: bytearray, output: bytearray, Y: bytearray, S: bytearray) -> None:
        assert self.aes is not None
        tmp = _mk_block()
        I_tmp = _mk_block()
        I_tmp[:] = self.I[1]
        offset = 0
        remaining = len(input_bytes)
        i = 1
        while remaining >= 64:
            first_out = bytearray(output[offset:offset + BLOCK_SIZE])
            second_out = bytearray(output[offset + BLOCK_SIZE:offset + BLOCK_SIZE * 2])
            self.aes.AES4(self.J[1], I_tmp, self.L[i % 8], S, tmp)
            _xor_bytes1x16(first_out, tmp, first_out)
            _xor_bytes1x16(second_out, tmp, second_out)
            _xor_bytes1x16(first_out, Y, Y)

            self.aes.AES4(ZERO_BLOCK, self.I[0], self.L[0], second_out, tmp)
            _xor_bytes1x16(first_out, tmp, first_out)

            self.aes.AES4(self.J[0], I_tmp, self.L[i % 8], first_out, tmp)
            _xor_bytes1x16(second_out, tmp, second_out)

            temp = bytearray(first_out)
            first_out[:] = second_out
            second_out[:] = temp

            output[offset:offset + BLOCK_SIZE] = first_out
            output[offset + BLOCK_SIZE:offset + BLOCK_SIZE * 2] = second_out

            offset += 32
            remaining -= 32
            i += 1
            if i % 8 == 0:
                _double_block(I_tmp)


def _aez_decrypt(key: bytes, ad_list: Iterable[bytes], tau: int, ciphertext: bytes) -> bytes | None:
    state = _AEZState()
    state.reset()
    state.init(key)
    delta = state.aez_hash(None, list(ad_list), tau * 8)
    x = bytearray(len(ciphertext))
    if len(ciphertext) == tau:
        state.aez_prf(delta, tau, x)
        mismatch = 0
        for i in range(tau):
            mismatch |= x[i] ^ ciphertext[i]
        if mismatch != 0:
            return None
        return bytes()
    state.decipher(delta, ciphertext, x)
    mismatch = 0
    for i in range(tau):
        mismatch |= x[len(ciphertext) - tau + i]
    if mismatch != 0:
        return None
    return bytes(x[: len(ciphertext) - tau])


def mnemonic_to_bytes(words: Sequence[str], word_to_index: dict[str, int]) -> bytes:
    if len(words) != 24:
        raise InvalidMnemonicError("aezeed mnemonics must have 24 words")
    bits = 0
    bit_len = 0
    out = bytearray(EncipheredCipherSeedSize)
    pos = 0
    for word in words:
        try:
            idx = word_to_index[word]
        except KeyError as exc:
            raise InvalidMnemonicError(f"unknown word: {word}") from exc
        bits = (bits << BitsPerWord) | idx
        bit_len += BitsPerWord
        while bit_len >= 8:
            bit_len -= 8
            out[pos] = (bits >> bit_len) & 0xFF
            bits &= (1 << bit_len) - 1 if bit_len else 0
            pos += 1
    return bytes(out)


def validate_mnemonic(words: Sequence[str], word_to_index: dict[str, int]) -> bool:
    try:
        cipher_bytes = mnemonic_to_bytes(words, word_to_index)
    except InvalidMnemonicError:
        return False
    if cipher_bytes[0] != CipherSeedVersion:
        return False
    expected = int.from_bytes(cipher_bytes[-4:], "big")
    computed = _crc32c(cipher_bytes[: EncipheredCipherSeedSize - 4])
    return expected == computed


def _encode_ad(version: int, salt: bytes) -> bytes:
    return bytes([version]) + salt


def decode_mnemonic(
    words: Sequence[str],
    passphrase: str,
    word_to_index: dict[str, int],
) -> DecipheredCipherSeed:
    cipher_bytes = mnemonic_to_bytes(words, word_to_index)
    version = cipher_bytes[0]
    if version != CipherSeedVersion:
        raise InvalidMnemonicError("unsupported aezeed version")
    checksum = int.from_bytes(cipher_bytes[-4:], "big")
    computed = _crc32c(cipher_bytes[: EncipheredCipherSeedSize - 4])
    if checksum != computed:
        raise InvalidMnemonicError("checksum mismatch")
    salt = cipher_bytes[EncipheredCipherSeedSize - 4 - SaltSize : EncipheredCipherSeedSize - 4]
    ciphertext = cipher_bytes[1 : EncipheredCipherSeedSize - 4 - SaltSize]
    # LND always prefixes the default passphrase to user-supplied strings before
    # running scrypt.  Append the provided passphrase to the base constant so
    # recovery works for mnemonics created with custom passphrases.
    pass_bytes = (DEFAULT_PASSPHRASE + (passphrase or "")).encode("utf-8")
    key = hashlib.scrypt(pass_bytes, salt=salt, n=32768, r=8, p=1, dklen=32, maxmem=2_000_000_000)
    ad = _encode_ad(version, salt)
    plaintext = _aez_decrypt(key, [ad], CipherTextExpansion, ciphertext)
    if plaintext is None or len(plaintext) != DecipheredCipherSeedSize:
        raise InvalidPassphraseError("invalid passphrase")
    internal_version = plaintext[0]
    birthday = int.from_bytes(plaintext[1:3], "big")
    entropy = plaintext[3:]
    return DecipheredCipherSeed(entropy=bytes(entropy), salt=bytes(salt), internal_version=internal_version, birthday=birthday)

