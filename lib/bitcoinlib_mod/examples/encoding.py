# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#
#    EXAMPLES - Encoding helper methods
#
#    © 2017 September - 1200 Web Development <http://1200wd.com/>
#

from bitcoinlib.encoding import *

#
# Change Base conversion examples
#
examples = [
    ('4c52127a72fb42b82439ab18697dcfcfb96ac63ba8209833b2e29f2302b8993f45e743412d65c7a571da70259d4f6795e98af20e6e'
     '57603314a662a49c198199', 16, 256),
    ('LRzrûB¸$9«i}ÏÏ¹jÆ;¨ 3²â#¸?EçCA-eÇ¥qÚp%OgéònW`3¦b¤', 256, 16),
    # ('LRzrûB¸$9«i}ÏÏ¹jÆ;¨ 3²â#¸?EçCA-eÇ¥qÚp%OgéònW`3¦b¤', 16, 256),  # Test EncodingError
    ('L1odb1uUozbfK2NrsMyhJfvRsxGM2AxixgPL8vG9BUBnE6W1VyTX', 58, 16),
    ('FF', 16, 10),
    ('AF', 16, 2),
    (200, 10, 16, 2),
    (200, 10, 16, 4),
    ('thisisfunny', 32, 3),
    ('1LeNnaRtV52nNtZXvtw6PaGKpk46hU1Xmx', 58, 16),
    ('1LeNnaRtV52nNtZXvtw6PaGKpk46hU1Xmx', 58, 32),
    ('1LeNnaRtV52nNtZXvtw6PaGKpk46hU1Xmx', 58, 256),
    ('1LeNnaRtV52nNtZXvtw6PaGKpk46hU1Xmx', 58, 2048),
    ([b'\0', b'\x12', b'L'], 256, 16, 6),
    ("為 宋 暴 治 伯 及 灘 冶 忙 逃 湘 艇 例 讓 忠", 256, 16),
    (b'\x00\t\xc6\xe7\x11\x18\xd8\xf1+\xeck\\a\x88K5g|\n\n\xe3*\x02\x1f\x87', 256, 58),
    (b'\0', 256, 10),
    ("\x00\x01\tfw`\x06\x95=UgC\x9e^9\xf8j\r';\xee\xd6\x19g\xf6", 256, 58),
    (b'LR\x12zr\xfbB\xb8$9\xab\x18i}\xcf\xcf\xb9j\xc6;\xa8 \x983\xb2\xe2\x9f#\x02\xb8\x99?E\xe7CA-e\xc7\xa5q'
     b'\xdap%\x9dOg\x95\xe9\x8a\xf2\x0enW`3\x14\xa6b\xa4\x9c\x19\x81\x99', 256, 16),
]

print("\n=== Change base: convert from base N to base M ===")
for example in examples:
    print("\n>>> change_base%s     # Change from base%d to base%d" %
          (example, example[1], example[2]))
    print("%s" % change_base(*example))

#
# Address and Script conversion examples
#
print("\n=== Conversion of Bitcoin Addresses to Public Key Hashes ===")
addrs = ['12ooWd8Xag7hsgP9PBPnmyGe36VeUrpMSH', '1111111111111111111114oLvT2',
         '1QLbz7JHiBTspS962RLKV8GndWFwi5j6Qr']
for addr in addrs:
    print("Public Key Hash of address '%s' is '%s'" % (addr, addr_to_pubkeyhash(addr, True)))

print("\n=== From Public Key Hashes to address ===")
print(pubkeyhash_to_addr('13d215d212cd5188ae02c5635faabdc4d7d4ec91'))
print(pubkeyhash_to_addr('00' * 20))

print("\n=== Create PKH from redeemscript ===")
redeemscript = '5221023dd6aeaa2acb92cbea35820361e5fd07af10f4b01c985adec30848b424756a6c210381cd2bb2a38d939fa677a5dcc' \
               '981ee0630b32b956b2e6dc3e1c028e6d09db5a72103d2c6d31cabe4025c25879010465f501194b352823c553660d303adfa' \
               '9a26ad3c53ae'
print(to_hexstring(hash160(to_bytes(redeemscript))))

#
# Other type conversions and normalizations
#

der_signature = '3045022100f952ff1b290c54d8b9fd35573b50f1af235632c595bb2f10b34127fb82f66d18022068b59150f825a81032c' \
                '22ce2db091d6fd47294c9e2144fa0291949402e3003ce'
print("\n=== Convert DER encoded signature ===")
print(convert_der_sig(to_bytes(der_signature)))

print("\n=== Varbyte Int conversions ===")
print("Number 1000 as Varbyte Integer (hexstring): %s" % to_hexstring(int_to_varbyteint(1000)))
print("Converted back (3 is size in bytes: 1 size byte + integer in bytes): ", varbyteint_to_int(to_bytes('fde803')))

# Normalize data
print("\n=== Normalizations ===")
data = [
    u"guion cruz envío papel otoño percha hazaña salir joya gorra íntimo actriz",
    u'\u2167',
    u'\uFDFA',
    "あじわう　ちしき　たわむれる　おくさま　しゃそう　うんこう　ひてい　みほん　たいほ　てのひら　りこう　わかれる　かいすいよく　こもん　ねもと",
    '12345',
]

for dt in data:
    print("\nInput data", dt)
    print("Normalized unicode string (normalize_string): ", normalize_string(dt))
    print("Normalized variable (normalize_var): ", normalize_var(dt))


# Convert Bech32 address to Public key hash
address = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"
pkh = "0014751e76e8199196d454941c45d1b3a323f1433bd6"
pkh_converted = addr_bech32_to_pubkeyhash(address, prefix='bc', include_witver=True, as_hex=True)
print(pkh, " == ", pkh_converted)
addr = pubkeyhash_to_addr_bech32(pkh_converted, address[:2].lower())
