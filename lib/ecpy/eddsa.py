# Copyright 2016 Cedric Mesnil <cedric.mesnil@ubinity.com>, Ubinity SAS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


#python 2 compatibility
from builtins import int,pow

import binascii
from ecpy.curves import Curve,Point
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.formatters import decode_sig, encode_sig
import hashlib

class EDDSA:
    """EDDSA signer implemenation according to:
    
     - IETF `draft-irtf-cfrg-eddsa-05 <https://tools.ietf.org/html/draft-irtf-cfrg-eddsa-05>`_.

    Args:
      hasher (hashlib): callable constructor returning an object with update(), digest() interface. Example: hashlib.sha256,  hashlib.sha512...
      fmt (str): in/out signature format. See  :mod:`ecpy.formatters`.
    """
        
    def __init__(self, hasher, hash_len = None, fmt="EDDSA"):
        self._hasher = hasher
        self._hash_len = hash_len
        self.fmt = fmt
        pass


    @staticmethod
    def get_public_key(pv_key, hasher = hashlib.sha512, hash_len=None) :
        """ Returns the public key corresponding to this private key 
        
        This method compute the public key according to draft-irtf-cfrg-eddsa-05.
        
        The hash parameter shall be the same as the one used for signing and
        verifying.
        
        Args:
            hasher (hashlib): callable constructor returning an object with update(), digest() interface. Example: hashlib.sha256,  hashlib.sha512...
            pv_key (ecpy.keys.ECPrivateKey): key to use for signing

        Returns:
           ECPublicKey : public key
        """
        a,A,h = EDDSA._get_materials(pv_key, hasher, hash_len)
        return ECPublicKey(A)

    @staticmethod
    def _get_materials(pv_key, hasher = hashlib.sha512, hash_len=None) :
        """ Returns the internal private scalar a(int), the public point A(ECPoint) = a.B and the 
            signature prefix h(bytes)
        
        The hash parameter shall be the same as the one used for signing and
        verifying.
        
        Args:
            hasher (hashlib): callable constructor returning an object with update(), digest() interface. Example: hashlib.sha256,  hashlib.sha512...
            pv_key (ecpy.keys.ECPrivateKey): key to use for signing

        Returns:
           ECPrivateKey : internal private key
        """
        curve = pv_key.curve
        B     = curve.generator
        n     = curve.order
        size  = curve._coord_size()
        
        k = pv_key.d.to_bytes(size,'big')
        hasher = hasher()
        hasher.update(k)
        if hash_len:
            h = hasher.digest(hash_len)
        else :
            h = hasher.digest()

        #retrieve encoded pub key
        
        if curve.name == 'Ed25519':
            a = bytearray(h[:32])
            h = h[32:]
            a[0]  &= 0xF8
            a[31] = (a[31] &0x7F) | 0x40
        elif curve.name == 'Ed448':
            a = bytearray(h[:57])
            h = h[57:]
            a[0]  &= 0xFC; 
            a[56]  = 0;
            a[55] |= 0x80;
        elif curve.name == 'Ed521':
            a = bytearray(h[:66])
            h = h[66:]
            a[0] &= 0xFC
            a[65]  = 0
            a[65] |= 0x80
        else :
            assert False, '%s not supported'%curve.name
        
        a = bytes(a)
        a = int.from_bytes(a,'little')
        A = a * B
       
        return a,A,h

    def sign(self, msg, pv_key):
        """ Signs a message.

        Args:
            msg (bytes)                    : the message to sign
            pv_key (ecpy.keys.ECPrivateKey): key to use for signing
        """
        return self._do_sign(msg, pv_key)

    
    def _do_sign(self,msg,pv_key):
        curve = pv_key.curve
        B     = curve.generator
        n     = curve.order
        size = curve._coord_size()
              
        a, A, prefix = EDDSA._get_materials(pv_key, self._hasher, self._hash_len)
        eA = curve.encode_point(A)
        #compute R
        hasher = self._hasher()
        if curve.name =='Ed448':         
            hasher.update(b'SigEd448\x00\x00')
            hasher.update(prefix)
            hasher.update(msg)
            r = hasher.digest(self._hash_len)
        elif curve.name == 'Ed521':
            hasher.update(b'SigEd521\x00\x00')
            hasher.update(prefix)
            hasher.update(msg)
            r = hasher.digest(self._hash_len)
        elif curve.name =='Ed25519':  
            hasher.update(prefix)
            hasher.update(msg)
            r = hasher.digest()
        else :
            assert False, '%s not supported'%curve.name

        r = int.from_bytes(r,'little')
        r = r % n
        R = r*B
        eR = curve.encode_point(R)
              
        #compute S
        hasher = self._hasher()
        if curve.name =='Ed448':  
            hasher.update(b'SigEd448\x00\x00')
            hasher.update(eR)
            hasher.update(eA)
            hasher.update(msg)
            H_eR_eA_m = hasher.digest(self._hash_len)
        elif curve.name =='Ed521':
            hasher.update(b'SigEd521\x00\x00')
            hasher.update(eR)
            hasher.update(eA)
            hasher.update(msg)
            H_eR_eA_m = hasher.digest(self._hash_len)
        elif  curve.name =='Ed25519':  
            hasher.update(eR)
            hasher.update(eA)
            hasher.update(msg)
            H_eR_eA_m = hasher.digest()
        else:
            assert False, '%s not supported'%curve.name

        i = int.from_bytes(H_eR_eA_m, 'little')
        S = (r + i*a)%n
        
        #S = S.to_bytes(size,'little')

        #return eR+S
        eR = int.from_bytes(eR,'little')
        sig = encode_sig(eR,S,self.fmt,size)
        return sig
    
    def verify(self,msg,sig,pu_key):
        """ Verifies a message signature.                

        Args:
            msg (bytes)                   : the message to verify the signature
            sig (bytes)                   : signature to verify
            pu_key (ecpy.keys.ECPublicKey): key to use for verifying
        """
        curve = pu_key.curve
        n     = curve.order
        size  = curve._coord_size()

        eR,S = decode_sig(sig, self.fmt)

        #left
        eR = eR.to_bytes(size,'little')
        R  = curve.decode_point(eR)
        
        hasher = self._hasher()
        eA = curve.encode_point(pu_key.W)
        if curve.name =='Ed448':
            hasher.update(b'SigEd448\x00\x00')
            hasher.update(eR)
            hasher.update(eA)
            hasher.update(msg)
            h = hasher.digest(self._hash_len)
        elif curve.name == 'Ed521':
            hasher.update(b'SigEd521\x00\x00')
            hasher.update(eR)
            hasher.update(eA)
            hasher.update(msg)
            h = hasher.digest(self._hash_len)
        elif curve.name == 'Ed25519':
            hasher.update(eR)
            hasher.update(eA)
            hasher.update(msg)
            h = hasher.digest()
        else:
            assert False, '%s not supported'%curve.name
    
        h = int.from_bytes(h,'little')
        h = h%n
        A = pu_key.W        
        left  = R+h*A

        #right
        right = S*curve.generator
        
        return left == right


    
if __name__ == "__main__":
    try:
        ### EDDSA
        cv     = Curve.get_curve('Ed25519')

        # public key
        # x: 74ad28205b4f384bc0813e6585864e528085f91fb6a5096f244ae01e57de43ae
        # y: 0c66f42af155cdc08c96c42ecf2c989cbc7e1b4da70ab7925a8943e8c317403d


        pu_key = ECPublicKey(Point(0x74ad28205b4f384bc0813e6585864e528085f91fb6a5096f244ae01e57de43ae,
                                   0x0c66f42af155cdc08c96c42ecf2c989cbc7e1b4da70ab7925a8943e8c317403d,
                                   cv))
        # private key
        # s: 0x4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
        pv_key = ECPrivateKey(0x4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb,
                              cv)

        pu = EDDSA.get_public_key(pv_key)
        assert(pu.W == pu_key.W);
        

        # sig:
        # 0x92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da
        # 0x085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00
        expected_sig = int(0x92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00)
        expected_sig  = expected_sig.to_bytes(64,'big')
        
        #msg:
        # 72
        msg  = int(0x72)
        msg  = msg.to_bytes(1,'big')

        signer = EDDSA(hashlib.sha512)
        sig = signer.sign(msg,pv_key)
        assert(sig == expected_sig)
        assert(signer.verify(msg,sig,pu_key))





        ### EDDSA
        cv     = Curve.get_curve('Ed25519')

        # public key
        # x: d96878efcfac114929db551927623e574bb552517b0ac585774ae0f1ebf3619
        # y: 2fad0cf5e2bb0303c5074ca3e6aa0a487b27b7577a012176da6983ee85d95ce0

        pu_key = ECPublicKey(Point(0xd96878efcfac114929db551927623e574bb552517b0ac585774ae0f1ebf3619,
                                   0x2fad0cf5e2bb0303c5074ca3e6aa0a487b27b7577a012176da6983ee85d95ce0,
                                   cv))
        # private key
        # s: 5bb7dd30fb4ece686a55faa14e346c08ad81c48c2ebe859a548c101a3dcd360e
        pv_key = ECPrivateKey(0x5bb7dd30fb4ece686a55faa14e346c08ad81c48c2ebe859a548c101a3dcd360e,
                              cv)

        pu = EDDSA.get_public_key(pv_key)
        assert(pu.W == pu_key.W);
        

        # sig:
        # 477dedac6d8332708e00a7c06ceeda54f2086ba73e71e8988b3760ccd23e0c44
        # 08cf09c22ef497328579f6178e8a2a4d611d0c6cce0c684f958d150c5daf4902
        expected_sig = int(0x477dedac6d8332708e00a7c06ceeda54f2086ba73e71e8988b3760ccd23e0c4408cf09c22ef497328579f6178e8a2a4d611d0c6cce0c684f958d150c5daf4902 )
        expected_sig  = expected_sig.to_bytes(64,'big')
        
        #msg:
        # 72
        msg  = int(0xe8898b646cc2274b5daf7fb6e30f738b24203604d7849391056d0fe8093f6693)
        msg  = msg.to_bytes(32,'big')

        signer = EDDSA(hashlib.sha512)
        sig = signer.sign(msg,pv_key)
        assert(sig == expected_sig)
        assert(signer.verify(msg,sig,pu_key))
        

        ### EDDSA
        cv     = Curve.get_curve('Ed25519')

        # public key
        # x: 74ad28205b4f384bc0813e6585864e528085f91fb6a5096f244ae01e57de43ae
        # y: 0c66f42af155cdc08c96c42ecf2c989cbc7e1b4da70ab7925a8943e8c317403d


        pu_key = ECPublicKey(Point(0x74ad28205b4f384bc0813e6585864e528085f91fb6a5096f244ae01e57de43ae,
                                   0x0c66f42af155cdc08c96c42ecf2c989cbc7e1b4da70ab7925a8943e8c317403d,
                                   cv))
        # private key
        # s: 0x4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
        pv_key = ECPrivateKey(0x4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb,
                              cv)

        pu = EDDSA.get_public_key(pv_key)
        assert(pu.W == pu_key.W);
        

        # sig:
        # 
        # 
        expected_sig = int(0xa2ce8472cf883cca5f98ca76d5834831d9d121a755c00daa385d0bac145203269e572a3d1f221af1b1ca6feaae05141a9aa9d6990163a85ab8690da44c056d0f)
        expected_sig  = expected_sig.to_bytes(64,'big')
        
        #msg:
        # 72
        msg  = int(0xe8898b646cc2274b5daf7fb6e30f738b24203604d7849391056d0fe8093f669338b24203604d7849391056d0fe8093f6693e8898b646cc2274b5daf7fb6e30f7)
        msg  = msg.to_bytes(64,'big')

        signer = EDDSA(hashlib.sha512)
        sig = signer.sign(msg,pv_key)
        assert(signer.verify(msg,sig,pu_key))
        assert(sig == expected_sig)

        
        ### EDDSA
        cv     = Curve.get_curve('Ed521')

        # public key
        x = 0x16b159d5e880d2849165dec4d95d69051129baa1f8c23b2c95284c142d122f1bb96048547b30d2f2df430d36d40190ca86b8ef266a72b3034c4d03fe83d5b1b9c4e
        y = 0x6cd6658b0e2a6100d1487507ac3c0f1b52677b2eb31074aebd5bdede3775d3e6447f7f714d2740d0ba46e67aedcc4c3f37410c47a26cf79077dbc3f9cb0c8700fb

        pu_key = ECPublicKey(Point(x, y, cv))

        # private key
        s = 0xa0d4d2ea5090b09a5d05ddf8c10d72e3a4b5c435fbff6d3a5f775cfe837f158fcf4e04b3d70713b71e834f3bec2442ef4c5c8a1ffb6f2f81dec330226ffe2f46a285
        pv_key = ECPrivateKey(s, cv)

        pu = EDDSA.get_public_key(pv_key, hashlib.shake_256, hash_len=132)
        assert(pu.W == pu_key.W)

        # sig:
        # 
        expected_sig = int(0xc2fb4f7d03dd31f25753b9972aeb650ac3632eef945e7f94e426a865bb95e66241149c7eed24d98fed2ee8b9ef949b83ba556d045b72df6e6b8b9026414b26463d0088d2ed5ea88fcc6b2f343d308209dacd5fadadac352d497d2049831eca3536e7be5a7faef56d6c6786c60415e0febee8a45f9971ae4872e0b6cf09cc0a9407342000)
        expected_sig  = expected_sig.to_bytes(132,'big')

        # msg:
        # Message for Ed521 signing
        msg = b'Message for Ed521 signing'
        signer = EDDSA(hashlib.shake_256, hash_len=132)
        sig = signer.sign(msg,pv_key)

        assert(signer.verify(msg,sig,pu_key))
        assert(sig == expected_sig)

        ### EDDSA with x509 Digital Certificate
        cv     = Curve.get_curve('Ed521')

        # public key
        x = 0x23edddd64369863618296219add6d6dcafae3cc8e5666a6b6a1fea1d9cf92552c6836f51bfb872884cde1cc45837f7390b47f7e7e4c9722327ba09b5a97a88028
        y = 0x12ce0b0c0eeac8418dc8639f628c183ed1523b2c71d4090f8e5c44c90e07cbaceb17ef077af8e120fb0350243780f61007cbd158de2f2d28d7295f135195afd6a9b

        pu_key = ECPublicKey(Point(x, y, cv))

        # sig:
        # 
        sig = int(0xa7e7f16597a9b70f9e6437de6e85239def223d68263cf49b3b8575e49a34d23bb79de2f3e59ecba4b5358e0eaea575b4645a6e420ff88632fe8725b0fe3ee92a510116969cba3cdc6c7b644d50efa27908dbceef807b180ec1e7e63c5badf058ea97112fbba153e3d672552c1ff49c754fdc1b891e470cfdd058fd788da6f98fa8e73200)
        sig  = sig.to_bytes(132,'big')

        # msg:
        # tbs certificate
        msg = int(0x308202bfa003020102020900e4ac9a3346c92509300c060a2b0601040182dc2c0201308197310b300906035504061302425231133011060355040a0c0a4943502d42726173696c313d303b060355040b0c34496e7374697475746f204e6163696f6e616c206465205465636e6f6c6f67696120646120496e666f726d6163616f202d204954493134303206035504030c2b4175746f72696461646520436572746966696361646f7261205261697a2042726173696c65697261207637301e170d3138313232383133343733355a170d3338313232383132303033355a308197310b300906035504061302425231133011060355040a0c0a4943502d42726173696c313d303b060355040b0c34496e7374697475746f204e6163696f6e616c206465205465636e6f6c6f67696120646120496e666f726d6163616f202d204954493134303206035504030c2b4175746f72696461646520436572746966696361646f7261205261697a2042726173696c656972612076373053300c060a2b0601040182dc2c02010343009b6afd5a1935f195728dd2f2e28d15bd7c00610f78430235b00f128eaf77f07eb1ceba7ce0904cc4e5f890401dc7b22315ed83c128f63986dc1884aceec0b0e02c01a381f53081f2304e0603551d200447304530430605604c010100303a303806082b06010505070201162c687474703a2f2f61637261697a2e69637062726173696c2e676f762e62722f44504361637261697a2e706466303f0603551d1f043830363034a032a030862e687474703a2f2f61637261697a2e69637062726173696c2e676f762e62722f4c435261637261697a76372e63726c301f0603551d2304183016801475513119e1c71321873e415fa31be67bfdb0d9c8301d0603551d0e0416041475513119e1c71321873e415fa31be67bfdb0d9c8300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106)
        msg  = msg.to_bytes(707,'big')

        signer = EDDSA(hashlib.shake_256, hash_len=132)

        assert(signer.verify(msg,sig,pu_key))

        ##OK!
        print("All internal assert OK!")
    finally:
        pass


