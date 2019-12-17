# SPAE Single Pass Authenticated Encryption
# Sebastien Riou, November 18th 2018

import sys
import binascii
from Crypto.Cipher import AES

class SpaeCipher(object):
    """Single Pass Authenticated Encryption. Supports only byte level padding."""

    BLOCKSIZE=16

    def __init__(self, key, nonce, decrypt, CSPAE):
        self.__nonce=nonce
        self.__key=key
        self.__decrypt=decrypt
        self.__mbuf = b''
        self.__abuf = b''
        self.__obuf = b''
        self.__mlen = 0
        self.__alen = 0
        self.__at = self.intToBlock(0)
        self.__finalized=False
        if CSPAE:
            self.__ct = self.cipher_enc(self.xor(key[:self.BLOCKSIZE],nonce),key)
            self.__pt = self.xor(self.xor(key[:self.BLOCKSIZE],nonce),self.__ct)
            self.__cipher = self.get_cipher(key)
        else:
            self.__ct = self.cipher_enc(key[:self.BLOCKSIZE],key)
            self.__pt = self.xor(key[:self.BLOCKSIZE],self.__ct)
            self.__cipher = self.get_cipher(self.xor(key,nonce))

    @staticmethod
    def bytesAsHex(block, end="\n"):
        out=""
        for b in block:
            out += "%02X"%b
        out += end
        return out

    @staticmethod
    def printBytesAsHex(block, end="\n"):
        print(SpaeCipher.bytesAsHex(block,end),end="")


    def addMessage(self, raw):
        self.__mbuf += raw
        self.__mlen += len(raw)
        self.__consume_mbuf()

    def addAuthData(self, raw):
        #print('raw       ',binascii.hexlify(raw))
        self.__abuf += raw
        self.__alen += len(raw)
        self.__consume_abuf()

    def __consume_mbuf(self):
        if self.__decrypt:
            #don't process last block as it may be the tag
            minSize = 2 * SpaeCipher.BLOCKSIZE
        else:
            minSize = SpaeCipher.BLOCKSIZE
        while len(self.__mbuf) >= minSize:
            b = self.__mbuf[ : SpaeCipher.BLOCKSIZE]
            self.__mbuf = self.__mbuf[SpaeCipher.BLOCKSIZE : ]
            self.__updateMT(b)

    def __updateMT(self,b):
        if self.__decrypt:
            b = self.__dcore(b)
        else:
            b = self.__ecore(b)
        self.__obuf += b

    def __consume_abuf(self):
        while len(self.__abuf) >= SpaeCipher.BLOCKSIZE:
            b = self.__abuf[ : SpaeCipher.BLOCKSIZE]
            self.__abuf = self.__abuf[SpaeCipher.BLOCKSIZE : ]
            self.__updateAT(b)

    def __updateAT(self,b):
        self.__at = self.cipher_enc(self.xor(b,self.__at),self.__key) #use always the static key here
        #print('ai        ',binascii.hexlify(b))
        #print('at        ',binascii.hexlify(self.__at))

    def getOutput(self):
        assert(False == self.__decrypt)
        o = self.__obuf
        self.__obuf = b''
        return o

    @staticmethod
    def get_cipher(key):
        return AES.new(key, AES.MODE_ECB)

    @staticmethod
    def cipher_enc(din,key):
        return SpaeCipher.get_cipher(key).encrypt(din)

    @staticmethod
    def xor(a,b):
        d=len(a)-len(b)
        if d>0:
            b=b+bytes(d)
        if d<0:
            a=a+bytes(-d)
        return bytes([ (x ^ y) for (x,y) in zip(a, b) ])

    @staticmethod
    def betole(a):
        return bytes(reversed(a))

    @staticmethod
    def inv(a):
        return bytes([ (x ^ 0xFF) for x in a ])

    @staticmethod
    def intToBlock(a):
        return binascii.unhexlify(format(a, '032x'))

    @staticmethod
    def shift(a,b):
        aInt = int.from_bytes(a, byteorder='big', signed=False)
        return SpaeCipher.intToBlock(aInt << b)

    @staticmethod
    def RR32(a):
        """little endian RR32: block is considered as 16 bytes in little endian order"""
        aInt = int.from_bytes(a, byteorder='big', signed=False)
        return SpaeCipher.intToBlock(((aInt & 0xFFFFFFFFFFFFFFFFFFFFFFFF) << 32)|(aInt >> 96))

    @staticmethod
    def HSWAP(block):
        return block[8:16]+block[0:8]

    def __dcore(self,c):
        i1 = self.xor(self.__ct,c)
        i0 = self.__cipher.decrypt(i1)
        p = self.xor(self.__pt,i0)
        self.__ct = self.xor(self.__ct,self.__pt)
        self.__pt = self.xor(p,i1)
        return p

    def __ecore(self,p):
        i0 = self.xor(self.__pt,p)
        i1 = self.__cipher.encrypt(i0)
        c = self.xor(self.__ct,i1)
        self.__ct = self.xor(self.__ct,self.__pt)
        self.__pt = self.xor(p,i1)
        return c

    def __computeTag(self,mlen,alen):
        if self.__decrypt:
            mlen -= 128
            self.__mlen -= 16
        BLOCKSIZE = self.BLOCKSIZE*8
        ct = SpaeCipher.HSWAP(self.__ct)
        if 0==self.__mlen:
            tag = self.inv(self.__key[:self.BLOCKSIZE])
            tt = self.__pt
        else:
            tag = self.xor(self.__pt,ct)
            tt = self.__ct
        tag = self.xor(tag,self.__at)
        #print('mt        ',binascii.hexlify(self.__mt))
        #print('mt+at     ',binascii.hexlify(tag))
        #print('mpadlen=',mpadlen)
        #print('apadlen=',apadlen)
        mpadinfo = mlen & ((1<<64)-1)
        apadinfo = alen & ((1<<64)-1)
        mpadinfo32 = mlen & ((1<<32)-1)
        apadinfo32 = alen & ((1<<32)-1)
        apadinfo_swap = (apadinfo>>32)^((apadinfo & 0xFFFFFFFF)<<32)
        padinfo = ((apadinfo_swap ^ mpadinfo)<<64) ^ (apadinfo32<<32) ^ mpadinfo32
        padInfo = self.intToBlock(padinfo)
        padInfo = self.betole(padInfo)
        #print('mpadlen=',mpadlen)
        #print('apadlen=',apadlen)
        #print('padinfo   ',binascii.hexlify(padInfo))
        tag = self.xor(tag,padInfo)
        tag = self.__cipher.encrypt(tag)
        tag = self.xor(tag,tt)
        #print('final tag ',binascii.hexlify(tag))
        return tag


    @staticmethod
    def SPAE(key,nonce,decrypt):
        return SpaeCipher(key,nonce,decrypt,False)

    @staticmethod
    def CSPAE(key,nonce,decrypt):
        return SpaeCipher(key,nonce,decrypt,True)

    @staticmethod
    def SPAE_enc(key,nonce,message,associatedData):
        aead = SpaeCipher.SPAE(key,nonce,False)
        return aead.enc(message,associatedData)

    @staticmethod
    def SPAE_dec(key,nonce,message,associatedData,mlen=0,alen=0):
        aead = SpaeCipher.SPAE(key,nonce,True)
        return aead.dec(message,associatedData,mlen,alen)

    @staticmethod
    def CSPAE_enc(key,nonce,message,associatedData):
        aead = SpaeCipher.CSPAE(key,nonce,False)
        return aead.enc(message,associatedData)

    @staticmethod
    def CSPAE_dec(key,nonce,message,associatedData,mlen=0,alen=0):
        aead = SpaeCipher.CSPAE(key,nonce,True)
        return aead.dec(message,associatedData,mlen,alen)

    def enc(self,message,associatedData):
        self.addMessage(message)
        self.addAuthData(associatedData)
        return self.finalize()

    def dec(self,message,associatedData,mlen=0,alen=0):
        if 0==mlen:
            mlen = len(message) - 16
        if 0==alen:
            alen = len(associatedData)
        self.addMessage(message)
        self.addAuthData(associatedData)
        return self.finalize(mlen,alen)

    def finalize(self,mlen=0,alen=0):
        assert(False == self.__finalized)
        BLOCKSIZE = self.BLOCKSIZE*8

        if self.__decrypt:
            if 0==mlen:
                mlen = self.__mlen
            if 0==alen:
                alen = self.__alen
        else:
            mlen = self.__mlen
            alen = self.__alen

        mlen = mlen * 8
        alen = alen * 8
        m = (mlen + BLOCKSIZE -1) // BLOCKSIZE
        a = (alen + BLOCKSIZE -1) // BLOCKSIZE
        mpadlen = m * BLOCKSIZE - mlen
        apadlen = a * BLOCKSIZE - alen

        #print('m=',m)
        #print('a=',a)
        #print('mpadlen=',mpadlen)
        #print('apadlen=',apadlen)

        if self.__decrypt:
            assert 0 == ((len(self.__mbuf)*8) % BLOCKSIZE)
        else:
            #pad message with zeroes
            for i in range(0,mpadlen//8):
                self.__mbuf += binascii.unhexlify(b'00')

        #pad associated data with zeroes
        for i in range(0,apadlen//8):
            self.__abuf += binascii.unhexlify(b'00')

        self.__consume_mbuf()
        self.__consume_abuf()
        tag = self.__computeTag(mlen,alen)

        if self.__decrypt:
            providedTag=self.__mbuf
            if tag != providedTag:
                print('provided tag ',binascii.hexlify(providedTag))
                print('tag          ',binascii.hexlify(tag))
                raise ValueError('authentication tags different')
            #trunc output according to PADINFO
            self.__obuf = self.__obuf[:mlen//8]
        else:
            self.__obuf += tag
        self.__finalized = True
        #print('out          ',binascii.hexlify(self.__obuf))
        o = self.__obuf
        self.__obuf = b''
        self.__mt = b''
        self.__at = b''
        self.__mbuf = b''
        self.__abuf = b''
        return o

def SPAE_selftest():
    mode = "SPAE "
    #self test
    key = binascii.unhexlify(b'00000000000000000000000000000001')
    nonce = binascii.unhexlify(b'00000000000000000000000000000002')
    message  = binascii.unhexlify(b'')
    associatedData  = binascii.unhexlify(b'')
    print(mode,"m=%s,a=%s"%(len(message)//16,len(associatedData)//16))
    encrypted00=SpaeCipher.SPAE_enc(key,nonce,message,associatedData)
    assert(encrypted00==binascii.unhexlify(b'6b52a86d2741165af5ad9b4694d978e7'))
    p=SpaeCipher.SPAE_dec(key,nonce,encrypted00,associatedData)
    assert(p==binascii.unhexlify(b''))

    message  = binascii.unhexlify(b'')
    associatedData += binascii.unhexlify(b'00000000000000000000000000000006')
    print(mode,"m=%s,a=%s"%(len(message)//16,len(associatedData)//16))
    encrypted01=SpaeCipher.SPAE_enc(key,nonce,message,associatedData)
    assert(encrypted01==binascii.unhexlify(b'79f6ed9901a721c7a164b938a78235b2'))
    p=SpaeCipher.SPAE_dec(key,nonce,encrypted01,associatedData)
    assert(p==binascii.unhexlify(b''))

    message += binascii.unhexlify(b'00000000000000000000000000000003')
    associatedData  = binascii.unhexlify(b'')
    print(mode,"m=%s,a=%s"%(len(message)//16,len(associatedData)//16))
    encrypted10=SpaeCipher.SPAE_enc(key,nonce,message,associatedData)
    assert(encrypted10==binascii.unhexlify(b'731bdd384f415c11081d08ecdc3efe5db1b909f8b08f0bab507c5dcef1e9227b'))
    p=SpaeCipher.SPAE_dec(key,nonce,encrypted10,associatedData)
    assert(p==binascii.unhexlify(b'00000000000000000000000000000003'))

    message += binascii.unhexlify(b'00000000000000000000000000000004')
    print(mode,"m=%s,a=%s"%(len(message)//16,len(associatedData)//16))
    encrypted20=SpaeCipher.SPAE_enc(key,nonce,message,associatedData)
    assert(encrypted20==binascii.unhexlify(b'731bdd384f415c11081d08ecdc3efe5d0c5b1fb684058f90977a7725a71938b82d0baa4ba1295b6895d05e60454baa9b'))
    p=SpaeCipher.SPAE_dec(key,nonce,encrypted20,associatedData)
    assert(p==binascii.unhexlify(b'0000000000000000000000000000000300000000000000000000000000000004'))

    message += binascii.unhexlify(b'00000000000000000000000000000005')
    print(mode,"m=%s,a=%s"%(len(message)//16,len(associatedData)//16))
    encrypted30=SpaeCipher.SPAE_enc(key,nonce,message,associatedData)
    assert(encrypted30==binascii.unhexlify(b'731bdd384f415c11081d08ecdc3efe5d0c5b1fb684058f90977a7725a71938b8a82247dc3bd0dfba194bd1b58b698d108f3dd7aad83031a97eafae7b0f8d2be4'))
    p=SpaeCipher.SPAE_dec(key,nonce,encrypted30,associatedData)
    assert(p==binascii.unhexlify(b'000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005'))

    associatedData += binascii.unhexlify(b'00000000000000000000000000000006')
    print(mode,"m=%s,a=%s"%(len(message)//16,len(associatedData)//16))
    encrypted31=SpaeCipher.SPAE_enc(key,nonce,message,associatedData)
    assert(encrypted31==binascii.unhexlify(b'731bdd384f415c11081d08ecdc3efe5d0c5b1fb684058f90977a7725a71938b8a82247dc3bd0dfba194bd1b58b698d10cc96e9da55b0a032e23214fdf7cd05cf'))
    p=SpaeCipher.SPAE_dec(key,nonce,encrypted31,associatedData)
    assert(p==binascii.unhexlify(b'000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005'))

    associatedData += binascii.unhexlify(b'00000000000000000000000000000007')
    print(mode,"m=%s,a=%s"%(len(message)//16,len(associatedData)//16))
    encrypted32=SpaeCipher.SPAE_enc(key,nonce,message,associatedData)
    assert(encrypted32==binascii.unhexlify(b'731bdd384f415c11081d08ecdc3efe5d0c5b1fb684058f90977a7725a71938b8a82247dc3bd0dfba194bd1b58b698d103c7c90a6e62ca4197f7a4aeb8a404d3b'))
    p=SpaeCipher.SPAE_dec(key,nonce,encrypted32,associatedData)
    assert(p==binascii.unhexlify(b'000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005'))

    associatedData += binascii.unhexlify(b'00000000000000000000000000000008')
    print(mode,"m=%s,a=%s"%(len(message)//16,len(associatedData)//16))
    encrypted33=SpaeCipher.SPAE_enc(key,nonce,message,associatedData)
    assert(encrypted33==binascii.unhexlify(b'731bdd384f415c11081d08ecdc3efe5d0c5b1fb684058f90977a7725a71938b8a82247dc3bd0dfba194bd1b58b698d1096429c516be08eeb28a721f41bd6a965'))
    p=SpaeCipher.SPAE_dec(key,nonce,encrypted33,associatedData)
    assert(p==binascii.unhexlify(b'000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005'))

    message2 = message[:32] + binascii.unhexlify(b'09')
    associatedData2 = associatedData[:32] + binascii.unhexlify(b'0A0B')
    print(mode,"m=3,a=3 padded")
    encrypted33pad=SpaeCipher.SPAE_enc(key,nonce,message2,associatedData2)
    assert(encrypted33pad==binascii.unhexlify(b'731bdd384f415c11081d08ecdc3efe5d0c5b1fb684058f90977a7725a71938b8b3db1fae57b13d105d1c5e5e9d1dfac4a444e1b1b447fa20297451181793013c'))
    p=SpaeCipher.SPAE_dec(key,nonce,encrypted33pad,associatedData2,33,34)
    assert(p==binascii.unhexlify(b'000000000000000000000000000000030000000000000000000000000000000409'))

    #try online API encryption
    aead = SpaeCipher.SPAE(key,nonce,False)
    aead.addMessage(binascii.unhexlify(b'00000000000000000000000000000003'))
    assert(aead.getOutput()==binascii.unhexlify(b'731bdd384f415c11081d08ecdc3efe5d'))
    aead.addMessage(binascii.unhexlify(b'00000000000000000000000000000004'))
    assert(aead.getOutput()==binascii.unhexlify(b'0c5b1fb684058f90977a7725a71938b8'))
    aead.addMessage(binascii.unhexlify(b'09'))
    assert(aead.getOutput()==binascii.unhexlify(b''))
    aead.addAuthData(binascii.unhexlify(b'00000000000000000000000000000006000000000000000000000000000000070a0b'))
    assert(aead.finalize()==binascii.unhexlify(b'b3db1fae57b13d105d1c5e5e9d1dfac4a444e1b1b447fa20297451181793013c'))

    #decryption
    aead = SpaeCipher.SPAE(key,nonce,True)
    aead.addMessage(binascii.unhexlify(b'731b'))
    aead.addMessage(binascii.unhexlify(b'dd384f415c11081d08ecdc3efe5d0c5b'))
    aead.addMessage(binascii.unhexlify(b'1fb684058f90977a7725a71938b8'))
    aead.addMessage(binascii.unhexlify(b'b3db1fae57b13d105d1c5e5e9d1dfac4'))
    aead.addMessage(binascii.unhexlify(b'a444e1b1b447fa20297451181793013c'))
    aead.addAuthData(binascii.unhexlify(b'00000000000000'))
    aead.addAuthData(binascii.unhexlify(b'000000000000000006000000000000000000000000000000070a0b'))
    p=aead.finalize(33,34)
    assert(p==binascii.unhexlify(b'000000000000000000000000000000030000000000000000000000000000000409'))

    gen_supercop_testvectors_SPAE()


def CSPAE_selftest():
    mode = "CSPAE "
    #self test
    key = binascii.unhexlify(b'00000000000000000000000000000001')
    nonce = binascii.unhexlify(b'00000000000000000000000000000002')
    message  = binascii.unhexlify(b'')
    associatedData  = binascii.unhexlify(b'')
    print(mode,"m=%s,a=%s"%(len(message)//16,len(associatedData)//16))
    encrypted00=SpaeCipher.CSPAE_enc(key,nonce,message,associatedData)
    assert(encrypted00==binascii.unhexlify(b'ea8a4809b96ea6a0eef3415e1fa189cf'))
    p=SpaeCipher.CSPAE_dec(key,nonce,encrypted00,associatedData)
    assert(p==binascii.unhexlify(b''))

    message  = binascii.unhexlify(b'')
    associatedData += binascii.unhexlify(b'00000000000000000000000000000006')
    print(mode,"m=%s,a=%s"%(len(message)//16,len(associatedData)//16))
    encrypted01=SpaeCipher.CSPAE_enc(key,nonce,message,associatedData)
    assert(encrypted01==binascii.unhexlify(b'c40bdbc3af60cbcaad5ee52e24f9245a'))
    p=SpaeCipher.CSPAE_dec(key,nonce,encrypted01,associatedData)
    assert(p==binascii.unhexlify(b''))

    message += binascii.unhexlify(b'00000000000000000000000000000003')
    associatedData  = binascii.unhexlify(b'')
    print(mode,"m=%s,a=%s"%(len(message)//16,len(associatedData)//16))
    encrypted10=SpaeCipher.CSPAE_enc(key,nonce,message,associatedData)
    assert(encrypted10==binascii.unhexlify(b'af06863bfe5ab6f4d07ef32afba1bae914e0579d57fa9906daf89b867bd15764'))
    p=SpaeCipher.CSPAE_dec(key,nonce,encrypted10,associatedData)
    assert(p==binascii.unhexlify(b'00000000000000000000000000000003'))

    message += binascii.unhexlify(b'00000000000000000000000000000004')
    print(mode,"m=%s,a=%s"%(len(message)//16,len(associatedData)//16))
    encrypted20=SpaeCipher.CSPAE_enc(key,nonce,message,associatedData)
    assert(encrypted20==binascii.unhexlify(b'af06863bfe5ab6f4d07ef32afba1bae993d554b47b4b6561e7295ff3c95df96408f0eba01d225c5d749e3ceaeafe9a42'))
    p=SpaeCipher.CSPAE_dec(key,nonce,encrypted20,associatedData)
    assert(p==binascii.unhexlify(b'0000000000000000000000000000000300000000000000000000000000000004'))

    message += binascii.unhexlify(b'00000000000000000000000000000005')
    print(mode,"m=%s,a=%s"%(len(message)//16,len(associatedData)//16))
    encrypted30=SpaeCipher.CSPAE_enc(key,nonce,message,associatedData)
    assert(encrypted30==binascii.unhexlify(b'af06863bfe5ab6f4d07ef32afba1bae993d554b47b4b6561e7295ff3c95df964ab01b1cc3d600c0d40878a652aa0ed80193d00a175460d158640c8aa8ee988ec'))
    p=SpaeCipher.CSPAE_dec(key,nonce,encrypted30,associatedData)
    assert(p==binascii.unhexlify(b'000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005'))

    associatedData += binascii.unhexlify(b'00000000000000000000000000000006')
    print(mode,"m=%s,a=%s"%(len(message)//16,len(associatedData)//16))
    encrypted31=SpaeCipher.CSPAE_enc(key,nonce,message,associatedData)
    assert(encrypted31==binascii.unhexlify(b'af06863bfe5ab6f4d07ef32afba1bae993d554b47b4b6561e7295ff3c95df964ab01b1cc3d600c0d40878a652aa0ed80c3a63118bc49b39a1cd38197700514b8'))
    p=SpaeCipher.CSPAE_dec(key,nonce,encrypted31,associatedData)
    assert(p==binascii.unhexlify(b'000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005'))

    associatedData += binascii.unhexlify(b'00000000000000000000000000000007')
    print(mode,"m=%s,a=%s"%(len(message)//16,len(associatedData)//16))
    encrypted32=SpaeCipher.CSPAE_enc(key,nonce,message,associatedData)
    assert(encrypted32==binascii.unhexlify(b'af06863bfe5ab6f4d07ef32afba1bae993d554b47b4b6561e7295ff3c95df964ab01b1cc3d600c0d40878a652aa0ed80c71220423d5807f7ef9ea11a93ae4793'))
    p=SpaeCipher.CSPAE_dec(key,nonce,encrypted32,associatedData)
    assert(p==binascii.unhexlify(b'000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005'))

    associatedData += binascii.unhexlify(b'00000000000000000000000000000008')
    print(mode,"m=%s,a=%s"%(len(message)//16,len(associatedData)//16))
    encrypted33=SpaeCipher.CSPAE_enc(key,nonce,message,associatedData)
    assert(encrypted33==binascii.unhexlify(b'af06863bfe5ab6f4d07ef32afba1bae993d554b47b4b6561e7295ff3c95df964ab01b1cc3d600c0d40878a652aa0ed80da5deef5cacac26683490473e5818351'))
    p=SpaeCipher.CSPAE_dec(key,nonce,encrypted33,associatedData)
    assert(p==binascii.unhexlify(b'000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005'))

    message2 = message[:32] + binascii.unhexlify(b'09')
    associatedData2 = associatedData[:32] + binascii.unhexlify(b'0A0B')
    print(mode,"m=3,a=3 padded")
    encrypted33pad=SpaeCipher.CSPAE_enc(key,nonce,message2,associatedData2)
    assert(encrypted33pad==binascii.unhexlify(b'af06863bfe5ab6f4d07ef32afba1bae993d554b47b4b6561e7295ff3c95df96436950fa28e90434306e0521860afa0006f413b364cbb7c4344e22deb33246142'))
    p=SpaeCipher.CSPAE_dec(key,nonce,encrypted33pad,associatedData2,33,34)
    assert(p==binascii.unhexlify(b'000000000000000000000000000000030000000000000000000000000000000409'))

    #try online API encryption
    aead = SpaeCipher.CSPAE(key,nonce,False)
    aead.addMessage(binascii.unhexlify(b'00000000000000000000000000000003'))
    assert(aead.getOutput()==binascii.unhexlify(b'af06863bfe5ab6f4d07ef32afba1bae9'))
    aead.addMessage(binascii.unhexlify(b'00000000000000000000000000000004'))
    assert(aead.getOutput()==binascii.unhexlify(b'93d554b47b4b6561e7295ff3c95df964'))
    aead.addMessage(binascii.unhexlify(b'09'))
    assert(aead.getOutput()==binascii.unhexlify(b''))
    aead.addAuthData(binascii.unhexlify(b'00000000000000000000000000000006000000000000000000000000000000070a0b'))
    assert(aead.finalize()==binascii.unhexlify(b'36950fa28e90434306e0521860afa0006f413b364cbb7c4344e22deb33246142'))

    #decryption
    aead = SpaeCipher.CSPAE(key,nonce,True)
    aead.addMessage(binascii.unhexlify(b'af06'))
    aead.addMessage(binascii.unhexlify(b'863bfe5ab6f4d07ef32afba1bae993d5'))
    aead.addMessage(binascii.unhexlify(b'54b47b4b6561e7295ff3c95df964'))
    aead.addMessage(binascii.unhexlify(b'36950fa28e90434306e0521860afa000'))
    aead.addMessage(binascii.unhexlify(b'6f413b364cbb7c4344e22deb33246142'))
    aead.addAuthData(binascii.unhexlify(b'00000000000000'))
    aead.addAuthData(binascii.unhexlify(b'000000000000000006000000000000000000000000000000070a0b'))
    p=aead.finalize(33,34)
    assert(p==binascii.unhexlify(b'000000000000000000000000000000030000000000000000000000000000000409'))

    gen_supercop_testvectors_CSPAE()

def gen_supercop_testvectors_SPAE():
    # supercop test vectors
    key = binascii.unhexlify(b'000102030405060708090A0B0C0D0E0F')
    nonce = binascii.unhexlify(b'000102030405060708090A0B0C0D0E0F')
    message = binascii.unhexlify(b'')
    associatedData = binascii.unhexlify(b'')
    out = SpaeCipher.SPAE_enc(key,nonce,message,associatedData)
    print(binascii.hexlify(out))
    assert(out==binascii.unhexlify(b'6873c8555b0be7b123898eb60160c281'))

    message = binascii.unhexlify(b'000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F')
    associatedData = binascii.unhexlify(b'000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E')
    out = SpaeCipher.SPAE_enc(key,nonce,message,associatedData)
    print(binascii.hexlify(out))
    assert(out==binascii.unhexlify(b'9f7562a92c45ee0719ef6b65865543606694ea7d72de55cffdfdc0c440093097bac00f359b2637a0670a452c377e46ba'))

    associatedData = binascii.unhexlify(b'000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F')
    out = SpaeCipher.SPAE_enc(key,nonce,message,associatedData)
    print(binascii.hexlify(out))
    assert(out==binascii.unhexlify(b'9f7562a92c45ee0719ef6b65865543606694ea7d72de55cffdfdc0c440093097e90d7cee5a31cc31d9675ae9de2515c7'))

def gen_supercop_testvectors_CSPAE():
    # supercop test vectors
    key = binascii.unhexlify(b'000102030405060708090A0B0C0D0E0F')
    nonce = binascii.unhexlify(b'000102030405060708090A0B0C0D0E0F')
    message = binascii.unhexlify(b'')
    associatedData = binascii.unhexlify(b'')
    print(binascii.hexlify(SpaeCipher.CSPAE_enc(key,nonce,message,associatedData)))

    message = binascii.unhexlify(b'000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F')
    associatedData = binascii.unhexlify(b'000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E')
    out = SpaeCipher.CSPAE_enc(key,nonce,message,associatedData)
    print(binascii.hexlify(out))
    assert(out==binascii.unhexlify(b'9f7562a92c45ee0719ef6b65865543606694ea7d72de55cffdfdc0c440093097bac00f359b2637a0670a452c377e46ba'))

    associatedData = binascii.unhexlify(b'000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F')
    out = SpaeCipher.CSPAE_enc(key,nonce,message,associatedData)
    print(binascii.hexlify(out))
    assert(out==binascii.unhexlify(b'9f7562a92c45ee0719ef6b65865543606694ea7d72de55cffdfdc0c440093097e90d7cee5a31cc31d9675ae9de2515c7'))


if __name__ == "__main__":
    print("self test needs update")
    #gen_supercop_testvectors_SPAE()
    #SPAE_selftest()
    #SPAE_selftest()
    #CSPAE_selftest()
