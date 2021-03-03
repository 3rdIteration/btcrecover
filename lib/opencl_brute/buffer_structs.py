#!/usr/bin/python3
# -*- coding: utf-8 -*-
'''
    Provides a class for filling in my buffer_structs_template.cl
'''

import os
import re

# Read the template in
template = ""
with open(os.path.join(os.path.dirname(__file__), "worker","generic","buffer_structs_template.cl"), "r") as rf:
    template = rf.read()

class buffer_structs:
    def __init__(self):
        self.code = ""
        self.wordSize = 4
        
    def setMaxBufferSizes(self, max_in_bytes, max_out_bytes, max_salt_bytes=32, max_ct_bytes=0, max_pwd_bytes=32):
        # Ensure each are a multiple of 4
        max_in_bytes += (-max_in_bytes % self.wordSize)
        max_out_bytes += (-max_out_bytes % self.wordSize)
        max_salt_bytes += (-max_salt_bytes % self.wordSize)
        max_pwd_bytes += (-max_pwd_bytes % self.wordSize)

        self.inBufferSize_bytes = max_in_bytes
        self.outBufferSize_bytes = max_out_bytes
        self.saltBufferSize_bytes = max_salt_bytes
        self.pwdBufferSize_bytes = max_pwd_bytes
        self.inBufferSize = (max_in_bytes + 3) // self.wordSize
        self.outBufferSize = (max_out_bytes + 3) // self.wordSize
        self.saltBufferSize = (max_salt_bytes + 3) // self.wordSize
        self.pwdBufferSize = (max_pwd_bytes + 3) // self.wordSize
        self.ctBufferSize_bytes = max_ct_bytes

    def specifyHashSizes(self, hashBlockSize_bits, hashDigestSize_bits):
        self.hashBlockSize_bits = hashBlockSize_bits
        self.hashDigestSize_bits = hashDigestSize_bits

    def setBufferSizesForHashing(self, hashMaxNumBlocks):
        self.setMaxBufferSizes(  ((self.hashBlockSize_bits + 7) // 8) * hashMaxNumBlocks,
                            (self.hashDigestSize_bits + 7) // 8,
                            0)

    def ceilToMult(self, n, k):
        return n + ((-n) % k)

    def fill_template(self):
        rep = { "<hashBlockSize_bits>": str(self.hashBlockSize_bits),
                "<hashDigestSize_bits>" : str(self.hashDigestSize_bits),
                "<inBufferSize_bytes>" : str(self.inBufferSize_bytes),
                "<outBufferSize_bytes>" : str(self.outBufferSize_bytes),
                "<saltBufferSize_bytes>" : str(self.saltBufferSize_bytes),
                "<pwdBufferSize_bytes>": str(self.pwdBufferSize_bytes),
                "<ctBufferSize_bytes>" : str(self.ctBufferSize_bytes),
                "<word_size>" : str(self.wordSize)
        }

        rep = dict((re.escape(k), v) for k, v in rep.items())
        pattern = re.compile("|".join(rep.keys()))
        self.code = pattern.sub(lambda m: rep[re.escape(m.group(0))], template)

    def specifyMD5(self, max_in_bytes=128, max_salt_bytes=32, dklen=0, max_ct_bytes=0):
        self.specifyHashSizes(512, 128)
        maxNumBlocks = 3
        self.wordSize = 4
        self.setBufferSizesForHashing(maxNumBlocks)
        max_out_bytes = self.hashDigestSize_bits // 8
        if dklen!=0:
            # Adjust output size to be a multiple of the digest
            max_out_bytes = self.ceilToMult(dklen, (self.hashDigestSize_bits // 8))
        self.setMaxBufferSizes(max_in_bytes, max_out_bytes, max_salt_bytes, max_ct_bytes)
        self.fill_template()
        return max_out_bytes

    def specifySHA1(self, max_in_bytes=128, max_salt_bytes=32, dklen=0, max_ct_bytes=0):
        self.specifyHashSizes(512,160)
        maxNumBlocks = 3
        self.wordSize = 4
        self.setBufferSizesForHashing(maxNumBlocks)
        max_out_bytes = self.hashDigestSize_bits // 8
        if dklen!=0:
            # Adjust output size to be a multiple of the digest
            max_out_bytes = self.ceilToMult(dklen, (self.hashDigestSize_bits // 8))
        self.setMaxBufferSizes(max_in_bytes, max_out_bytes, max_salt_bytes, max_ct_bytes)
        self.fill_template()
        return max_out_bytes

    def specifySHA2(self, hashDigestSize_bits=256, max_in_bytes=128, max_salt_bytes=32, dklen=0, max_ct_bytes=0):
        assert hashDigestSize_bits in [224,256,384,512]
        hashBlockSize_bits = 512
        if hashDigestSize_bits >= 384:
            hashBlockSize_bits = 1024
        self.specifyHashSizes(hashBlockSize_bits, hashDigestSize_bits)
        if hashDigestSize_bits==512:
            maxNumBlocks = 2
            self.wordSize = 8
        else:
            maxNumBlocks = 3
            self.wordSize = 4
        self.setBufferSizesForHashing(maxNumBlocks)
        max_out_bytes = self.hashDigestSize_bits // 8
        if dklen!=0:
            # Adjust output size to be a multiple of the digest
            max_out_bytes = self.ceilToMult(dklen, (self.hashDigestSize_bits // 8))

        self.setMaxBufferSizes(max_in_bytes, max_out_bytes, max_salt_bytes, max_ct_bytes)
        #bufStructs.setMaxBufferSizes(128, (bufStructs.hashDigestSize_bits * 2) // 8, 128)
        self.fill_template()
        return max_out_bytes

    ## sha3 not worth the fuss until I write the .cl's