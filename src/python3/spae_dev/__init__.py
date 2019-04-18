# SPAE Single Pass Authenticated Encryption
# Sebastien Riou, November 18th 2018

import sys
import binascii
from Crypto.Cipher import AES

class SpaeCipher(object):
    """Single Pass Authenticated Encryption, development version"""

    __verbose = 0
    __log_internal_secrets = 0
    __skip_hswap = 0
    CSPAE=False
    CST0=binascii.unhexlify(b'243f6a8885a308d313198a2e03707344')
    CST1=binascii.unhexlify(b'a4093822299f31d0082efa98ec4e6c89')
    NULL=binascii.unhexlify(b'00000000000000000000000000000000')
    internal_secrets = []

    @staticmethod
    def verbose(enable=None):
        if enable is not None:
            SpaeCipher.__verbose = enable
        return SpaeCipher.__verbose

    @staticmethod
    def log_internal_secrets(enable=None):
        if enable is not None:
            SpaeCipher.__log_internal_secrets = enable
        return SpaeCipher.__log_internal_secrets

    @staticmethod
    def skip_hswap(enable=None):
        if enable is not None:
            SpaeCipher.__skip_hswap = enable
        return SpaeCipher.__skip_hswap

    @staticmethod
    def __log_secret(secret_val):
        if SpaeCipher.__log_internal_secrets:
            if secret_val != SpaeCipher.NULL:
                SpaeCipher.internal_secrets.append(secret_val)

    @staticmethod
    def __print(msg,data=""):
        if SpaeCipher.__verbose:
            if data:
                print(msg,binascii.hexlify(data))
            else:
                print(msg)

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


    @staticmethod
    def SPAE_enc(key,nonce,message,associatedData):
        enc = SpaeCipher(key,nonce,0)
        enc.addMessage(message)
        enc.addAuthData(associatedData)
        encrypted = enc.finalize(len(message),len(associatedData))
        return encrypted

    @staticmethod
    def SPAE_dec(key,nonce,message,associatedData,mlen=0,alen=0):
        enc = SpaeCipher(key,nonce,1)
        enc.addMessage(message)
        enc.addAuthData(associatedData)
        encrypted = enc.finalize(len(message),len(associatedData))
        return encrypted

    def __init__(self, key, nonce, decrypt):
        SpaeCipher.internal_secrets = []
        self.blockSize = 16
        if decrypt:
            op = "decryption"
        else:
            op = "encryption"
        if SpaeCipher.CSPAE:
            self.__print("CSPAE - %s"%op)
        else:
            self.__print("SPAE - %s"%op)
        self.__print("key                = ",key)
        self.__print("nonce              = ",nonce)
        self.nonce=nonce
        self.key=key
        SpaeCipher.__log_secret(key)
        #self.mt0 = self.cipher_dec(key,key)
        #self.mt0 = self.cipher_enc(self.intToBlock(0),key)
        #self.at0 = key
        self.at0 = self.intToBlock(0)
        self.decrypt=decrypt
        self.mbuf = b''
        self.abuf = b''

        if SpaeCipher.CSPAE:
            self.ct0 = self.cipher_enc(self.xor(key,nonce),key)
            #self.mt0 = self.xor(nonce,self.cipher_enc(self.xor(key,nonce),key))
            self.mt0 = self.xor(self.xor(key,nonce),self.cipher_enc(self.xor(key,nonce),key))
            self.kn = key
        else:
            #self.ct0 = key
            #self.ct0 = self.xor(self.CST0,key)
            #self.ct0 = self.xor(nonce,self.cipher_enc(key,key))
            #self.ct0 = self.xor(nonce,self.cipher_enc(key,key))
            #self.ct0 = self.xor(key,self.cipher_enc(key,key))
            self.ct0 = self.cipher_enc(key,key)
            self.mt0 = self.xor(key,self.cipher_enc(key,key))
            #self.mt0 = self.cipher_enc(key,key)
            #self.mt0 = key
            #self.mt0 = swap64(self.mt0)
            self.kn = self.xor(key,nonce)
        self.cipher = self.get_cipher(self.kn)
        SpaeCipher.__log_secret(self.ct0)
        SpaeCipher.__log_secret(self.mt0)
        SpaeCipher.__log_secret(self.kn)
        self.first = True

    def addMessage(self, raw):
        self.mbuf += raw

    def addAuthData(self, raw):
        self.abuf += raw

    @staticmethod
    def get_cipher(key):
        return AES.new(key, AES.MODE_ECB)

    @staticmethod
    def cipher_enc(din,key):
        SpaeCipher.__print("aes key            = ",key)
        SpaeCipher.__print("aes din            = ",din)
        dout = SpaeCipher.get_cipher(key).encrypt(din)
        SpaeCipher.__print("aes dout           = ",dout)
        return dout

    @staticmethod
    def cipher_dec(din,key):
        return SpaeCipher.get_cipher(key).decrypt(din)

    @staticmethod
    def xor(a,b):
        return bytes([ (x ^ y) for (x,y) in zip(a, b) ])

    @staticmethod
    def betole(a):
        return bytes(reversed(a))

    @staticmethod
    def inv(a):
        return bytes([ (x ^ 0xFF) for x in a ])

    @staticmethod
    def intToBlock(a):
        x = format(a, '032x')
        return binascii.unhexlify(x)

    @staticmethod
    def blockToInt(a):
        aInt = int.from_bytes(a, byteorder='big', signed=False)
        return aInt

    @staticmethod
    def shift(a,b):
        aInt = int.from_bytes(a, byteorder='big', signed=False)
        return SpaeCipher.intToBlock(aInt << b)

    @staticmethod
    def RR32_be(a):
        aInt = SpaeCipher.blockToInt(a)
        return SpaeCipher.intToBlock((aInt >> 32)|((aInt & 0xFFFFFFFF) << 96))

    @staticmethod
    def RR32(a):
        """little endian RR32: block is considered as 16 bytes in little endian order"""
        aInt = SpaeCipher.blockToInt(a)
        return SpaeCipher.intToBlock(((aInt & 0xFFFFFFFFFFFFFFFFFFFFFFFF) << 32)|(aInt >> 96))

    def xex(self,tweak,dat):
        return self.xor(tweak,self.cipher.encrypt(self.xor(tweak,dat)))

    def xdx(self,tweak,dat):
        return self.xor(tweak,self.cipher.decrypt(self.xor(tweak,dat)))

    def ecore_oo_ko(self,tweak,dat):
        c = self.xor(tweak,self.cipher.encrypt(self.xor(tweak,dat)))
        s = self.xor(dat,c)
        return c, s

    def dcore_oo_ko(self,tweak,dat):
        p = self.xor(tweak,self.cipher.decrypt(self.xor(tweak,dat)))
        s = self.xor(dat,p)
        return p, s

    def ecore_ii_ko(self,tweak,dat):
        i0 = self.xor(tweak,dat)
        i1 = self.cipher.encrypt(i0)
        s = self.xor(i0,i1)
        c = self.xor(tweak,i1)
        return c, s

    def dcore_ii_ko(self,tweak,dat):
        i0 = self.xor(tweak,dat)
        i1 = self.cipher.decrypt(i0)
        s = self.xor(i0,i1)
        p = self.xor(tweak,i1)
        return p, s

    def ecore_oi(self,tweak,dat):
        i0 = self.xor(tweak,dat)
        i1 = self.cipher.encrypt(i0)
        c = self.xor(tweak,i1)
        s = self.xor(dat,i1)
        return c, s

    def dcore_oi(self,tweak,dat):
        i0 = self.xor(tweak,dat)
        i1 = self.cipher.decrypt(i0)
        p = self.xor(tweak,i1)
        s = self.xor(i0,p)
        return p, s

    def ecore_io(self,tweak,dat):
        i0 = self.xor(tweak,dat)
        i1 = self.cipher.encrypt(i0)
        c = self.xor(tweak,i1)
        s = self.xor(i0,c)
        return c, s

    def dcore_io(self,tweak,dat):
        i0 = self.xor(tweak,dat)
        i1 = self.cipher.decrypt(i0)
        s = self.xor(dat,i1)
        p = self.xor(tweak,i1)
        return p, s

    def ecore_09(self,pt,ct,dat):
        i0 = self.xor(pt,dat)
        i1 = self.cipher.encrypt(i0)
        c = self.xor(ct,i1)
        pt = i1
        ct = dat
        return pt, ct, c

    def dcore_09(self,pt,ct,dat):
        i1 = self.xor(ct,dat)
        i0 = self.cipher.decrypt(i1)
        p = self.xor(pt,i0)
        pt = i1
        ct = p
        return pt, ct, p

    def ecore_new(self,pt,ct,p):
        i0 = self.xor(pt,p)
        i1 = i0 #self.xor(ct,i0)
        i2 = self.cipher.encrypt(i1)
        i3 = self.xor(pt,i2)
        c = self.xor(ct,i3)
        pt = self.xor(i0,i3)
        ct = self.xor(ct,pt)
        SpaeCipher.__log_secret(pt)
        SpaeCipher.__log_secret(ct)
        SpaeCipher.__log_secret(i0)
        SpaeCipher.__log_secret(i1)
        SpaeCipher.__log_secret(i2)
        SpaeCipher.__log_secret(i3)
        return pt, ct, c

    def dcore_new(self,pt,ct,c):
        i3 = self.xor(ct,c)
        i2 = self.xor(pt,i3)
        i1 = self.cipher.decrypt(i2)
        i0 = i1 #self.xor(ct,i1)
        p = self.xor(pt,i0)
        pt = self.xor(i0,i3)
        ct = self.xor(ct,pt)
        return pt, ct, p

    def ecore_12b(self,pt,ct,p):
        i0 = self.xor(pt,p)
        i1 = i0 #self.xor(ct,i0)
        i2 = self.cipher.encrypt(i1)
        i3 = self.xor(pt,i2)
        c = self.xor(ct,i3)
        pt = self.xor(p,i2)
        ct = self.xor(ct,pt)
        SpaeCipher.__log_secret(pt)
        SpaeCipher.__log_secret(ct)
        SpaeCipher.__log_secret(i0)
        SpaeCipher.__log_secret(i1)
        SpaeCipher.__log_secret(i2)
        SpaeCipher.__log_secret(i3)
        return pt, ct, c

    def dcore_12b(self,pt,ct,c):
        if self.first:
            i3 = self.xor(ct,c)
            i2 = self.xor(pt,i3)
            i1 = self.cipher.decrypt(i2)
            i0 = i1 #self.xor(ct,i1)
            p = self.xor(pt,i0)
            pt = self.xor(p,i2)
            self.first = False
        else:
            #optimized version for subsequent blocks: one xor less
            i2 = self.xor(ct,c)
            i1 = self.cipher.decrypt(i2)
            i0 = i1 #self.xor(ct,i1)
            p = self.xor(pt,i0)
            ct = self.xor(ct,pt)
            pt = self.xor(p,i2)
        return pt, ct, p

    def ecore_12c(self,pt,ct,p):
        i0 = self.xor(pt,p)
        i1 = i0 #self.xor(ct,i0)
        i2 = self.cipher.encrypt(i1)
        #i3 = self.xor(pt,i2)
        c = self.xor(ct,i2)
        ct = self.xor(ct,pt)
        pt = self.xor(p,i2)
        SpaeCipher.__log_secret(pt)
        SpaeCipher.__log_secret(ct)
        SpaeCipher.__log_secret(i0)
        SpaeCipher.__log_secret(i1)
        SpaeCipher.__log_secret(i2)
        #SpaeCipher.__log_secret(i3)
        return pt, ct, c

    def dcore_12c(self,pt,ct,c):
        i2 = self.xor(ct,c)
        i1 = self.cipher.decrypt(i2)
        i0 = i1 #self.xor(ct,i1)
        p = self.xor(pt,i0)
        ct = self.xor(ct,pt)
        pt = self.xor(p,i2)
        return pt, ct, p

    def ecore_12a_ko(self,pt,ct,p):
        i0 = self.xor(pt,p)
        i1 = i0 #self.xor(ct,i0)
        i2 = self.cipher.encrypt(i1)
        i3 = self.xor(pt,i2)
        c = self.xor(ct,i3)
        ct = self.xor(ct,pt)
        pt = self.xor(p,i2)
        SpaeCipher.__log_secret(pt)
        SpaeCipher.__log_secret(ct)
        SpaeCipher.__log_secret(i0)
        SpaeCipher.__log_secret(i1)
        SpaeCipher.__log_secret(i2)
        SpaeCipher.__log_secret(i3)
        return pt, ct, c

    def dcore_12a_ko(self,pt,ct,c):
        i3 = self.xor(ct,c)
        i2 = self.xor(pt,i3)
        i1 = self.cipher.decrypt(i2)
        i0 = i1 #self.xor(ct,i1)
        p = self.xor(pt,i0)
        pt = self.xor(p,i2)
        ct = self.xor(ct,pt)
        return pt, ct, p

    def ecore(self,pt,ct,p):
        return self.ecore_12c(pt,ct,p)

    def dcore(self,pt,ct,c):
        return self.dcore_12c(pt,ct,c)

    @staticmethod
    def hswap(b):
        if SpaeCipher.__skip_hswap:
            return b
        return swap64(b)

    def __computeTag(self,lastPT,lastCT,mlen,alen):
        BLOCKSIZE = self.blockSize*8
        a = (alen+BLOCKSIZE-1) // BLOCKSIZE
        if 0==a:
            #tag = self.intToBlock(0)
            tag = self.at0
        else:
            #tag = self.inv(self.mt0)
            #tag = self.mt0
            #tag = self.intToBlock(0)
            #tag = self.cipher_enc(self.mt0,self.mt0) #self.mt0 is original key so this is static no matter the nonce
            tag = self.at0
            for i in range(0,a):
                ai = self.abuf[i*self.blockSize:(i+1)*self.blockSize]
                tag = self.cipher_enc(self.xor(ai,tag),self.key) #use always the static key here
                self.__print("               AT%d = "%(i+1),tag)
                SpaeCipher.__log_secret(tag)
        if 0==mlen:
            MT = self.intToBlock(0)
            TT = self.intToBlock(0)
            #MT = SpaeCipher.hswap(lastCT)
                #TT = self.intToBlock(0)
                #TT = lastCT
                #TT = lastPT
            MT = self.inv(self.key)
            TT = lastPT
        else:
            MT = self.xor(lastPT,SpaeCipher.hswap(lastCT))
            TT = lastCT
            SpaeCipher.__log_secret(TT)
        SpaeCipher.__log_secret(MT)
        self.__print("                MT = ",MT)
        tag = self.xor(tag,MT)
        SpaeCipher.__log_secret(tag)
        m = (mlen+BLOCKSIZE-1) // BLOCKSIZE
        mpadinfo = mlen & ((1<<64)-1)
        apadinfo = alen & ((1<<64)-1)
        mpadinfo32 = mlen & ((1<<32)-1)
        apadinfo32 = alen & ((1<<32)-1)
        apadinfo_swap = (apadinfo>>32)^((apadinfo & 0xFFFFFFFF)<<32)
        padinfo = ((apadinfo_swap ^ mpadinfo)<<64) ^ (apadinfo32<<32) ^ mpadinfo32
        padInfo = self.intToBlock(padinfo)
        padInfo = self.betole(padInfo)
        self.__print("                IT = ",tag)
        self.__print("           PADINFO = ",padInfo)
        tag = self.xor(tag,padInfo)
        SpaeCipher.__log_secret(tag)

        SpaeCipher.__print("aes key            = ",self.kn)
        SpaeCipher.__print("aes din            = ",tag)
        tag = self.cipher.encrypt(tag)
        SpaeCipher.__print("aes dout           = ",tag)

        SpaeCipher.__log_secret(tag)
        tag = self.xor(tag,TT)
        self.__print("authentication tag = ",tag)
        return tag

    def finalize(self,mlen,alen):
        BLOCKSIZE = self.blockSize*8

        mlen = mlen * 8
        alen = alen * 8
        m = (mlen + BLOCKSIZE -1) // BLOCKSIZE
        a = (alen + BLOCKSIZE -1) // BLOCKSIZE
        if self.decrypt:
            assert 0 == ((len(self.mbuf)*8) % BLOCKSIZE)

        self.__print("message            = ",self.mbuf[0:m*self.blockSize])
        self.__print("associated data    = ",self.abuf)

        #pad message with zeroes
        for i in range(len(self.mbuf),m*self.blockSize):
            self.mbuf += binascii.unhexlify(b'00')

        #pad associated data with zeroes
        for i in range(len(self.abuf),a*self.blockSize):
            self.abuf += binascii.unhexlify(b'00')

        pt = self.mt0
        ct = self.ct0
        #ct = self.intToBlock(0)
        self.__print("               PT0 = ",pt)
        self.__print("               CT0 = ",ct)
        out=b''
        if self.decrypt:
            providedTag=self.mbuf[m*self.blockSize:(m+1)*self.blockSize]
            self.mbuf = self.mbuf[:m*self.blockSize]
            for i in range(0,m):
                c = self.mbuf[(i)*self.blockSize:(i+1)*self.blockSize]
                pt,ct,p = self.dcore(pt,ct,c)
                out += p
                self.__print("               P%d  = "%i,p)
                self.__print("               C%d  = "%i,c)
                self.__print("               PT%d = "%(i+1),pt)
                self.__print("               CT%d = "%(i+1),ct)
            tag = self.__computeTag(pt,ct,mlen,alen)
            self.__print("provided tag       = ",providedTag)
            if tag != providedTag:
                raise ValueError('authentication tags different')
            out = out[:mlen//8]
        else:
            for i in range(0,m):
                p = self.mbuf[i*self.blockSize:(i+1)*self.blockSize]
                pt,ct,c = self.ecore(pt,ct,p)
                out += c
                self.__print("               P%d  = "%i,p)
                self.__print("               C%d  = "%i,c)
                self.__print("               PT%d = "%(i+1),pt)
                self.__print("               CT%d = "%(i+1),ct)
            tag = self.__computeTag(pt,ct,mlen,alen)
            out += tag
            if(SpaeCipher.__log_internal_secrets):
                if self.key == SpaeCipher.NULL:
                    print("WARNING: key is null, skip checks on internal variables")
                else:
                    lastp = self.intToBlock(0)
                    lastc = self.intToBlock(0)
                    for i in range(0,m):
                        p = self.mbuf[i*self.blockSize:(i+1)*self.blockSize]
                        if p in SpaeCipher.internal_secrets:
                            SpaeCipher.verbose(1)
                            self.__print("exposed secret =",p)
                            raise ValueError('plaintext equal internal secret')
                        c = out[i*self.blockSize:(i+1)*self.blockSize]
                        if c in SpaeCipher.internal_secrets:
                            SpaeCipher.verbose(1)
                            self.__print("exposed secret =",c)
                            raise ValueError('ciphertext equal internal secret')
                        pxc = self.xor(p,c)
                        if pxc in SpaeCipher.internal_secrets:
                            SpaeCipher.verbose(1)
                            self.__print("exposed secret =",pxc)
                            raise ValueError('plaintext xor ciphertext equal internal secret')
                        pxlp = self.xor(p,lastp)
                        if pxlp in SpaeCipher.internal_secrets:
                            SpaeCipher.verbose(1)
                            self.__print("exposed secret =",pxlp)
                            raise ValueError('last 2 plaintext xor equal internal secret')
                        cxlc = self.xor(c,lastc)
                        if cxlc in SpaeCipher.internal_secrets:
                            SpaeCipher.verbose(1)
                            self.__print("exposed secret =",cxlc)
                            raise ValueError('last 2 ciphertext xor equal internal secret')
                        cxlp = self.xor(c,lastp)
                        if pxlp in SpaeCipher.internal_secrets:
                            SpaeCipher.verbose(1)
                            self.__print("exposed secret =",cxlp)
                            raise ValueError('cxlp equal internal secret')
                        pxlc = self.xor(p,lastc)
                        if pxlc in SpaeCipher.internal_secrets:
                            SpaeCipher.verbose(1)
                            self.__print("exposed secret =",pxlc)
                            raise ValueError('pxlc equal internal secret')
                        pxlcxlp = self.xor(pxlc,lastp)
                        if pxlcxlp in SpaeCipher.internal_secrets:
                            SpaeCipher.verbose(1)
                            self.__print("exposed secret =",pxlcxlp)
                            raise ValueError('pxlcxlp equal internal secret')
                        cxlcxlp = self.xor(cxlc,lastp)
                        if pxlcxlp in SpaeCipher.internal_secrets:
                            SpaeCipher.verbose(1)
                            self.__print("exposed secret =",cxlcxlp)
                            raise ValueError('cxlcxlp equal internal secret')
                        pxcxlp = self.xor(pxlp,c)
                        if pxcxlp in SpaeCipher.internal_secrets:
                            SpaeCipher.verbose(1)
                            self.__print("exposed secret =",pxcxlp)
                            raise ValueError('pxcxlp equal internal secret')
                        pxcxlc = self.xor(cxlc,p)
                        if pxcxlc in SpaeCipher.internal_secrets:
                            SpaeCipher.verbose(1)
                            self.__print("exposed secret =",pxcxlc)
                            raise ValueError('pxcxlc equal internal secret')
                        lastp = p
                        lastc = c

        self.__print("out                = ",out)
        return out

def printBlock(msg,data=""):
    print(msg,binascii.hexlify(data))

def getCipher(key,nonce,decrypt):
    return SpaeCipher(key,nonce,decrypt)

def swap64(block):
    return block[8:16]+block[0:8]

def core_benchmark(n):
    key = binascii.unhexlify(b'00000000000000000000000000000001')
    nonce = binascii.unhexlify(b'00000000000000000000000000000000')
    enc = getCipher(key,nonce,0)
    mt = enc.mt0
    pt = mt
    ct = enc.ct0
    #ct = mt
    #ct = xor2(ct,binascii.unhexlify(b'55555555555555555555555555555555'))
    #ct = xor2(ct,binascii.unhexlify(b'02000000000000000000000000000000'))
    #ct = xor2(mt,binascii.unhexlify(b'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'))
    #pt = enc.cipher.encrypt(pt)
    #io = binascii.unhexlify(b'00000000000000000000000000000000')
    io = binascii.unhexlify(b'55555555555555555555555555555555')
    printBlock("kn :",enc.kn)
    for i in range(0,n):
        printBlock("io :",io)
        printBlock("pt :",pt)
        printBlock("ct :",ct)
        pt,ct,io = enc.ecore(pt,ct,io)
        print("\n")
    printBlock("core benchmark %d : "%n,io)


def core_benchmark_ct0pt0_equal(n):
    key = binascii.unhexlify(b'00000000000000000000000000000001')
    nonce = binascii.unhexlify(b'00000000000000000000000000000000')
    enc = getCipher(key,nonce,0)
    mt = enc.mt0
    pt = mt
    ct = mt
    #ct = mt
    #ct = xor2(ct,binascii.unhexlify(b'55555555555555555555555555555555'))
    #ct = xor2(ct,binascii.unhexlify(b'02000000000000000000000000000000'))
    #ct = xor2(mt,binascii.unhexlify(b'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'))
    #pt = enc.cipher.encrypt(pt)
    #io = binascii.unhexlify(b'00000000000000000000000000000000')
    io = binascii.unhexlify(b'55555555555555555555555555555555')
    printBlock("kn :",enc.kn)
    for i in range(0,n):
        printBlock("io :",io)
        printBlock("pt :",pt)
        printBlock("ct :",ct)
        pt,ct,io = enc.ecore(pt,ct,io)
        print("\n")
    printBlock("core benchmark ct0=pt0, %d : "%n,io)

def benchmark(n):
    key = binascii.unhexlify(b'00000000000000000000000000000001')
    nonce = binascii.unhexlify(b'00000000000000000000000000000000')
    associatedData = binascii.unhexlify(b'')
    io = binascii.unhexlify(b'00000000000000000000000000000000')
    for i in range(0,n):
        io = enc(key,nonce,io,associatedData)[0:16]
        printBlock("io :",io)
    printBlock("benchmark %d : "%n,io)


def enc(key,nonce,message,associatedData):
    enc = getCipher(key,nonce,0)
    enc.addMessage(message)
    enc.addAuthData(associatedData)
    encrypted = enc.finalize(len(message),len(associatedData))
    return encrypted

def dec(key,nonce,message,associatedData,mlen=0,alen=0):
    dec = getCipher(key,nonce,1)
    dec.addMessage(message)
    dec.addAuthData(associatedData)
    if 0==mlen:
        mlen = len(message) - 16
    if 0==alen:
        alen = len(associatedData)

    decrypted = dec.finalize(mlen,alen)
    #print("INFO: decryption completed without error")
    return decrypted

def decExpectException(key,nonce,message,associatedData):
    try:
        decrypted=dec(key,nonce,message,associatedData)
        print("ERROR: Expected exception did not happen")
        printBlock("ERROR: decrypted=",decrypted)
        exit(-1)
    except ValueError:
        #print("INFO: Expected exception happened")
        return

def testNullMessage(key):
    #SpaeCipher.verbose(1)
    nonce = binascii.unhexlify(b'00'*1*16)
    encrypted = enc(key,nonce,b'',b'')
    decrypted = dec(key,nonce,encrypted,b'')
    assert(decrypted==b'')
    fault = binascii.unhexlify(b'01'+b'00'*15)
    nonce2 = SpaeCipher.xor(nonce,fault)
    encrypted2 = enc(key,nonce2,b'',b'')
    encrypted3 = SpaeCipher.xor(encrypted,fault)
    assert(encrypted[0:16]!=encrypted2[0:16])
    key2 = SpaeCipher.xor(key,fault)
    decExpectException(key,nonce2,encrypted,b'')
    decExpectException(key,nonce,encrypted2,b'')
    decExpectException(key,nonce,encrypted3,b'')
    decExpectException(key2,nonce ,encrypted,b'')
    decExpectException(key2,nonce2,encrypted,b'')
    decExpectException(key2,nonce ,encrypted2,b'')
    decExpectException(key2,nonce2,encrypted2,b'')

def testSingleBlock(key):
    message = binascii.unhexlify(b'00'*1*16)
    nonce = binascii.unhexlify(b'00'*1*16)
    encrypted = enc(key,nonce,message,b'')
    decrypted = dec(key,nonce,encrypted,b'')
    assert(decrypted==message)
    assert(encrypted[0:16] != encrypted[16:32])
    fault = binascii.unhexlify(b'01'+b'00'*15)
    nonce2 = SpaeCipher.xor(nonce,fault)
    message2 = SpaeCipher.xor(message,fault)
    encrypted2 = enc(key,nonce2,message,b'')
    encrypted3 = enc(key,nonce,message2,b'')
    encrypted4 = enc(key,nonce2,message2,b'')
    assert(encrypted[0:16]!=encrypted2[0:16])
    assert(encrypted[0:16]!=encrypted3[0:16])
    assert(encrypted[0:16]!=encrypted4[0:16])
    assert(encrypted[16:32]!=encrypted2[16:32])
    assert(encrypted[16:32]!=encrypted3[16:32])
    assert(encrypted[16:32]!=encrypted4[16:32])
    key2 = SpaeCipher.xor(key,fault)
    decExpectException(key2,nonce ,encrypted,b'')
    decExpectException(key2,nonce2,encrypted,b'')
    decExpectException(key2,nonce ,encrypted2,b'')
    decExpectException(key2,nonce2,encrypted2,b'')
    decExpectException(key2,nonce ,encrypted3,b'')
    decExpectException(key2,nonce2,encrypted3,b'')
    decExpectException(key2,nonce ,encrypted4,b'')
    decExpectException(key2,nonce2,encrypted4,b'')

def test3_3(key):
    message = binascii.unhexlify(b'00'*1*16)
    message += binascii.unhexlify(b'00'*1*16)
    message += binascii.unhexlify(b'00'*1*16)
    associatedData = binascii.unhexlify(b'00'*1*16)
    associatedData += binascii.unhexlify(b'00'*1*16)
    associatedData += binascii.unhexlify(b'00'*1*16)

    nonce = binascii.unhexlify(b'00'*1*16)
    encrypted=enc(key,nonce,message,associatedData)
    assert(encrypted[ 0:16]!=encrypted[16:32])
    assert(encrypted[ 0:16]!=encrypted[32:48])
    assert(encrypted[ 0:16]!=encrypted[48:64])
    assert(encrypted[16:32]!=encrypted[32:48])
    assert(encrypted[16:32]!=encrypted[48:64])
    assert(encrypted[32:48]!=encrypted[48:64])

    dec(key,nonce,encrypted,associatedData)

    fault = binascii.unhexlify(b'01'+b'00'*(1*16-1))
    nonce2 = SpaeCipher.xor(nonce,fault)
    fault = binascii.unhexlify(b'01'+b'00'*(3*16-1))
    associatedData2 = SpaeCipher.xor(associatedData,fault)
    fault = binascii.unhexlify(b'01'+b'00'*(4*16-1))
    encrypted2 = SpaeCipher.xor(encrypted,fault)

    decExpectException(key,nonce ,encrypted ,associatedData2)
    decExpectException(key,nonce ,encrypted2,associatedData )
    decExpectException(key,nonce2,encrypted ,associatedData )
    decExpectException(key,nonce2,encrypted2,associatedData )
    decExpectException(key,nonce2,encrypted ,associatedData2)
    decExpectException(key,nonce ,encrypted2,associatedData2)
    decExpectException(key,nonce2,encrypted2,associatedData2)

    encryptedC1C0C2 = encrypted[16:32] + encrypted[0:16] + encrypted[32:]
    decExpectException(key,nonce,encryptedC1C0C2,associatedData)

def test5(key):
    message = binascii.unhexlify(b'00'*5*16)
    nonce = binascii.unhexlify(b'00'*1*16)
    associatedData=b''
    encrypted=enc(key,nonce,message,associatedData)
    dec(key,nonce,encrypted,associatedData)
    encryptedSwapped = encrypted[16:32] + encrypted[0:16] + encrypted[32:]
    decExpectException(key,nonce,encryptedSwapped,associatedData)
    encryptedSwapped = encrypted[32:48] + encrypted[16:32] + encrypted[0:16] + encrypted[48:]
    decExpectException(key,nonce,encryptedSwapped,associatedData)
    encryptedSwapped = encrypted[48:64] + encrypted[32:48] + encrypted[16:32] + encrypted[0:16] + encrypted[64:]
    decExpectException(key,nonce,encryptedSwapped,associatedData)
    encryptedSwapped = encrypted[16:32] + encrypted[0:16] + encrypted[48:64] + encrypted[32:48] +encrypted[64:]
    decExpectException(key,nonce,encryptedSwapped,associatedData)

def swapBlocks(message,nSwap):
    out = b''
    out += message[nSwap*16:]
    for i in range(0,nSwap):
        out = message[i*16:(i+1)*16] + out
    return out

def corruptBlock(message,n):
    fault = binascii.unhexlify(b'01'+b'00'*(1*16-1))
    out = b''
    out += message[0:n*16]
    out += SpaeCipher.xor(message[n*16:(n+1)*16],fault)
    out += message[(n+1)*16:]
    return out

def testSwapCorrupt(key,m=64,a=64):
    message = binascii.unhexlify(b'00'*m*16)
    nonce = binascii.unhexlify(b'00'*1*16)
    associatedData=binascii.unhexlify(b'00'*a*16)
    encrypted=enc(key,nonce,message,associatedData)
    dec(key,nonce,encrypted,associatedData)
    for i in range(2,len(message)//16):
        #print("swap blocks ",i)
        decExpectException(key,nonce,swapBlocks(encrypted,i),associatedData)
    for i in range(0,len(message)//16):
        #print("corrupt message block ",i)
        decExpectException(key,nonce,corruptBlock(encrypted,i),associatedData)
    for i in range(0,len(associatedData)//16):
        #print("corrupt associated data block ",i)
        decExpectException(key,nonce,encrypted,corruptBlock(associatedData,i))

def xor2(a,b):
    return SpaeCipher.xor(a,b)

def intToBlock(a):
    return SpaeCipher.intToBlock(a)

def checkEqual(a,b):
    if(a!=b):
        print("ERROR: mismatch")
        printBlock("a=",a)
        printBlock("b=",b)
        assert(a==b)


def refTestVector(key=binascii.unhexlify(b'00000000000000000000000000000001'),startlst="[listing]",endlst=""):
    SpaeCipher.verbose(1)
    nonce = binascii.unhexlify(b'00000000000000000000000000000002')
    message  = binascii.unhexlify(b'')
    associatedData  = binascii.unhexlify(b'')
    print("\n%s"%startlst,"\nm=%s,a=%s"%(len(message)//16,len(associatedData)//16))
    SpaeCipher.verbose(1)
    encrypted00=enc(key,nonce,message,associatedData)
    SpaeCipher.verbose(0)
    dec(key,nonce,encrypted00,associatedData)

    message  = binascii.unhexlify(b'')
    associatedData += binascii.unhexlify(b'00000000000000000000000000000006')
    print(endlst,"\n%s"%startlst,"\nm=%s,a=%s"%(len(message)//16,len(associatedData)//16))
    SpaeCipher.verbose(1)
    encrypted01=enc(key,nonce,message,associatedData)
    SpaeCipher.verbose(0)
    dec(key,nonce,encrypted01,associatedData)

    message += binascii.unhexlify(b'00000000000000000000000000000003')
    associatedData  = binascii.unhexlify(b'')
    print(endlst,"\n%s"%startlst,"\nm=%s,a=%s"%(len(message)//16,len(associatedData)//16))
    SpaeCipher.verbose(1)
    encrypted10=enc(key,nonce,message,associatedData)
    SpaeCipher.verbose(0)
    dec(key,nonce,encrypted10,associatedData)

    message += binascii.unhexlify(b'00000000000000000000000000000004')
    print(endlst,"\n%s"%startlst,"\nm=%s,a=%s"%(len(message)//16,len(associatedData)//16))
    SpaeCipher.verbose(1)
    encrypted20=enc(key,nonce,message,associatedData)
    SpaeCipher.verbose(0)
    dec(key,nonce,encrypted20,associatedData)

    message += binascii.unhexlify(b'00000000000000000000000000000005')
    print(endlst,"\n%s"%startlst,"\nm=%s,a=%s"%(len(message)//16,len(associatedData)//16))
    SpaeCipher.verbose(1)
    encrypted30=enc(key,nonce,message,associatedData)
    SpaeCipher.verbose(0)
    dec(key,nonce,encrypted30,associatedData)

    associatedData += binascii.unhexlify(b'00000000000000000000000000000006')
    print(endlst,"\n%s"%startlst,"\nm=%s,a=%s"%(len(message)//16,len(associatedData)//16))
    SpaeCipher.verbose(1)
    encrypted31=enc(key,nonce,message,associatedData)
    SpaeCipher.verbose(0)
    dec(key,nonce,encrypted31,associatedData)

    associatedData += binascii.unhexlify(b'00000000000000000000000000000007')
    print(endlst,"\n%s"%startlst,"\nm=%s,a=%s"%(len(message)//16,len(associatedData)//16))
    SpaeCipher.verbose(1)
    encrypted32=enc(key,nonce,message,associatedData)
    SpaeCipher.verbose(0)
    dec(key,nonce,encrypted32,associatedData)

    associatedData += binascii.unhexlify(b'00000000000000000000000000000008')
    print(endlst,"\n%s"%startlst,"\nm=%s,a=%s"%(len(message)//16,len(associatedData)//16))
    SpaeCipher.verbose(1)
    encrypted33=enc(key,nonce,message,associatedData)
    dec(key,nonce,encrypted33,associatedData)

    message2 = message[:32] + binascii.unhexlify(b'09')
    associatedData2 = associatedData[:32] + binascii.unhexlify(b'0A0B')
    print(endlst,"\n%s"%startlst,"\nm=3,a=3 padded")
    SpaeCipher.verbose(1)
    encrypted33pad=enc(key,nonce,message2,associatedData2)
    dec(key,nonce,encrypted33pad,associatedData2,33,34)
    print(endlst)
    gen_supercop_testvectors(enc,startlst,endlst)

    #now do it manually
    #Ek=AES.new(key, AES.MODE_ECB)
    #if SpaeCipher.CSPAE:
    #    #MT0 = xor2(nonce,Ek.encrypt(xor2(nonce,Ek.encrypt(key))))
    #    #MT0 = xor2(nonce,Ek.encrypt(xor2(nonce,key)))
    #    MT0 = xor2(xor2(nonce,key),Ek.encrypt(xor2(nonce,key)))
    #    #printBlock("MT0=",MT0)
    #    Ekn=Ek
    #else:
    #    MT0 = xor2(key,Ek.encrypt(key))
    #    Ekn=AES.new(xor2(key,nonce), AES.MODE_ECB)
    #P0 = message[0:16]
    #C0 = xor2(MT0,Ekn.encrypt(xor2(MT0,P0)))
    #MT1 = xor2(P0,Ekn.encrypt(xor2(C0,P0)))
    #P1 = message[16:32]
    #C1 = xor2(MT1,Ekn.encrypt(xor2(MT1,P1)))
    #MT2 = xor2(P1,Ekn.encrypt(xor2(C1,P1)))
    #P2 = message[32:48]
    #C2 = xor2(MT2,Ekn.encrypt(xor2(MT2,P2)))
    #MT3 = xor2(P2,Ekn.encrypt(xor2(C2,P2)))
    #PADINFO = intToBlock(0)
    #AT0 = intToBlock(0)
    #IT = xor2(AT0,MT0)
    #Tag= xor2(IT,Ekn.encrypt(xor2(IT,PADINFO)))
    #expected=Tag
    #checkEqual(expected,encrypted00)
    #IT = xor2(AT0,MT1)
    #Tag= xor2(IT,Ekn.encrypt(xor2(IT,PADINFO)))
    #expected=C0+Tag
    #assert(expected==encrypted10)
    #IT = xor2(AT0,MT2)
    #Tag= xor2(IT,Ekn.encrypt(xor2(IT,PADINFO)))
    #expected=C0+C1+Tag
    #assert(expected==encrypted20)
    #IT = xor2(AT0,MT3)
    #Tag= xor2(IT,Ekn.encrypt(xor2(IT,PADINFO)))
    #expected=C0+C1+C2+Tag
    #assert(expected==encrypted30)
    #A0 = associatedData[0:16]
    #AT1 = Ek.encrypt(xor2(AT0,A0))
    #IT = xor2(AT1,MT0)
    #Tag= xor2(IT,Ekn.encrypt(xor2(IT,PADINFO)))
    #expected=Tag
    #assert(expected==encrypted01)
    #IT = xor2(AT1,MT3)
    #Tag= xor2(IT,Ekn.encrypt(xor2(IT,PADINFO)))
    #expected=C0+C1+C2+Tag
    #assert(expected==encrypted31)
    #A1 = associatedData[16:32]
    #AT2 = Ek.encrypt(xor2(AT1,A1))
    #IT = xor2(AT2,MT3)
    #Tag= xor2(IT,Ekn.encrypt(xor2(IT,PADINFO)))
    #expected=C0+C1+C2+Tag
    #checkEqual(expected,encrypted32)
    #A2 = associatedData[32:48]
    #AT3 = Ek.encrypt(xor2(AT2,A2))
    #IT = xor2(AT3,MT3)
    #Tag= xor2(IT,Ekn.encrypt(xor2(IT,PADINFO)))
    #expected=C0+C1+C2+Tag
    #checkEqual(expected,encrypted33)
    #P2_2 = message2[32:33] + intToBlock(0)
    #P2_2 = P2_2[0:16]
    #C2_2 = xor2(MT2,Ekn.encrypt(xor2(MT2,P2_2)))
    #MT3_2 = xor2(P2_2,Ekn.encrypt(xor2(C2,P2_2)))
    #A2_2 = associatedData2[32:34] + intToBlock(0)
    #A2_2 = A2_2[0:16]
    #AT3_2 = Ek.encrypt(xor2(AT2,A2_2))
    #IT = xor2(AT3_2,MT3_2)
    #PADINFO = SpaeCipher.betole(intToBlock(((15*8)<<64)|(14*8)))
    #Tag= xor2(IT,Ekn.encrypt(xor2(IT,PADINFO)))
    #expected=C0+C1+C2_2+Tag
    #checkEqual(expected,encrypted33pad)

def gen_supercop_testvectors(enc_func,startlst="[listing]",endlst=""):
    log = SpaeCipher.log_internal_secrets()
    SpaeCipher.log_internal_secrets(0)
    # supercop test vectors
    key = binascii.unhexlify(b'000102030405060708090A0B0C0D0E0F')
    nonce = binascii.unhexlify(b'000102030405060708090A0B0C0D0E0F')
    message = binascii.unhexlify(b'')
    associatedData = binascii.unhexlify(b'')
    print("\n%s"%startlst)
    out = enc_func(key,nonce,message,associatedData)
    if not SpaeCipher.verbose():
        print(binascii.hexlify(out))
    #if False==SpaeCipher.CSPAE:
    #    assert(out==binascii.unhexlify(b'6873C8555B0BE7B123898EB60160C281'))

    message = binascii.unhexlify(b'000102030405060708090A0B0C0D0E0F')
    associatedData = binascii.unhexlify(b'000102030405060708090A0B0C0D0E0F')
    print(endlst,"\n%s"%startlst)
    out = enc_func(key,nonce,message,associatedData)
    if not SpaeCipher.verbose():
        print(binascii.hexlify(out))

    message = binascii.unhexlify(b'000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F')
    associatedData = binascii.unhexlify(b'000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E')
    print(endlst,"\n%s"%startlst)
    out = enc_func(key,nonce,message,associatedData)
    if not SpaeCipher.verbose():
        print(binascii.hexlify(out))
    #if False==SpaeCipher.CSPAE:
    #    assert(out==binascii.unhexlify(b'9F7460AA2840E80011E6616E8A584D6F153E297FEE84C10C1EA5BB036C843851E47D25A4723C185B13CCC5FC4961B3BD'))

    associatedData = binascii.unhexlify(b'000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F')
    print(endlst,"\n%s"%startlst)
    out = enc_func(key,nonce,message,associatedData)
    if not SpaeCipher.verbose():
        print(binascii.hexlify(out))
    #if False==SpaeCipher.CSPAE:
    #    assert(out==binascii.unhexlify(b'9F7460AA2840E80011E6616E8A584D6F153E297FEE84C10C1EA5BB036C843851D2A87560C6E3989602A2F907CCB06414'))
    SpaeCipher.log_internal_secrets(log)
    print(endlst)

def nonceReuseAttack(key=binascii.unhexlify(b'00000000000000000000000000000000')):
    """attempt a nonce reuse to check if any trivial relationship pop up"""
    nonce = binascii.unhexlify(b'00000000000000000000000000000000')
    message  = binascii.unhexlify(b'00000000000000000000000000000000')
    encrypted = enc(key,nonce,message,b'')
    decrypted = dec(key,nonce,encrypted,b'')
    assert(decrypted==message)

    message2  = binascii.unhexlify(b'ffffffffffffffffffffffffffffffff')
    encrypted2 = enc(key,nonce,message2,b'')
    decrypted2 = dec(key,nonce,encrypted2,b'')
    assert(decrypted2==message2)

    Pxor = xor2(message,message2)
    Cxor = xor2(encrypted[0:16],encrypted2[0:16])
    Tag_xor = xor2(encrypted[16:],encrypted2[16:])
    delta = xor2(Tag_xor,Cxor)
    assert(Pxor!=Cxor)
    assert(Pxor!=Tag_xor)
    assert(Pxor!=delta)
    assert(Cxor!=Tag_xor)

def adaptative_chosen_plaintext(key = binascii.unhexlify(b'00000000000000000000000000000001')):
    SpaeCipher.verbose(0)
    nonce = binascii.unhexlify(b'00000000000000000000000000000000')
    message = binascii.unhexlify(b'00000000000000000000000000000000')
    for i in range(0,16):
        c = enc(key,nonce,message,b'')
        message = message + c[i*16:(i+1)*16]
    SpaeCipher.verbose(1)
    enc(key,nonce,message,b'')
    SpaeCipher.verbose(0)
    return message

def tag_null_vs_c(key = binascii.unhexlify(b'00000000000000000000000000000001')):
    n=10
    skip = SpaeCipher.skip_hswap()
    SpaeCipher.skip_hswap(1)
    log = SpaeCipher.log_internal_secrets()
    SpaeCipher.log_internal_secrets(1)
    message = adaptative_chosen_plaintext(key)[0:n*16]
    secrets = SpaeCipher.internal_secrets
    #for s in secrets:
    #    print("secreta=",binascii.hexlify(s))
    nonce = binascii.unhexlify(b'00000000000000000000000000000000')
    SpaeCipher.verbose(1)
    tag_null = enc(key,nonce,b'',b'')
    SpaeCipher.verbose(0)

    assert(tag_null not in secrets)

    for i in range(0,n):
        delta = xor2(tag_null,message[i*16:(i+1)*16])
        #print("delta=",binascii.hexlify(delta))
        assert(delta not in secrets)

    for i in range(0,n):
        delta = xor2(message[i*16:(i+1)*16],message[(i+1)*16:(i+2)*16])
        assert(delta not in secrets)
        delta = xor2(delta,tag_null)
        assert(delta not in secrets)

    for i in range(0,n):
        delta = xor2(message[i*16:(i+1)*16],message[(i+2)*16:(i+3)*16])
        assert(delta not in secrets)
        delta = xor2(delta,tag_null)
        assert(delta not in secrets)
    SpaeCipher.skip_hswap(skip)
    SpaeCipher.log_internal_secrets(log)


def all_tests(key = binascii.unhexlify(b'00000000000000000000000000000001')):
    testNullMessage(key)
    nonceReuseAttack(key)
    testSingleBlock(key)
    test3_3(key)
    test5(key)
    testSwapCorrupt(key)
    #refTestVector(key)



if __name__ == "__main__":
    latex_startlst="""\\begin{lstlisting}"""
    latex_endlst="""\\end{lstlisting}"""

    tag_null_vs_c();
    SpaeCipher.verbose(0)
    SpaeCipher.log_internal_secrets(1)
    all_tests(binascii.unhexlify(b'6694ea7d72de55cffdfdc0c440093097'))
    adaptative_chosen_plaintext(binascii.unhexlify(b'6694ea7d72de55cffdfdc0c440093097'))
    SpaeCipher.log_internal_secrets(0)
    all_tests()
    gen_supercop_testvectors(enc)
    SpaeCipher.verbose(1)
    refTestVector(startlst=latex_startlst,endlst=latex_endlst)
    SpaeCipher.verbose(0)

    SpaeCipher.CSPAE = True
    SpaeCipher.log_internal_secrets(1)
    all_tests(binascii.unhexlify(b'6694ea7d72de55cffdfdc0c440093097'))
    adaptative_chosen_plaintext(binascii.unhexlify(b'6694ea7d72de55cffdfdc0c440093097'))
    SpaeCipher.log_internal_secrets(0)
    all_tests()
    SpaeCipher.verbose(1)
    refTestVector(startlst=latex_startlst,endlst=latex_endlst)
    SpaeCipher.verbose(0)
    SpaeCipher.CSPAE = False
    #adaptative_chosen_plaintext(binascii.unhexlify(b'55555555555555555555555555555555'))
    #benchmark(16)
    #SpaeCipher.verbose(1)
    #enc(SpaeCipher.NULL,SpaeCipher.NULL,binascii.unhexlify(b'11'),b'')
    #enc(SpaeCipher.NULL,SpaeCipher.NULL,b'',binascii.unhexlify(b'2233'))
    #enc(SpaeCipher.NULL,SpaeCipher.NULL,binascii.unhexlify(b'11'),binascii.unhexlify(b'2233'))
