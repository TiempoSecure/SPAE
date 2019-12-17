from spae_aes import SpaeCipher
import sys
import binascii

key = binascii.unhexlify(b'00000000000000000000000000000001')
nonce = binascii.unhexlify(b'00000000000000000000000000000002')
message  = binascii.unhexlify(b'')
associatedData  = binascii.unhexlify(b'')
print("m=%s,a=%s"%(len(message)//16,len(associatedData)//16))
encrypted00=SpaeCipher.SPAE_enc(key,nonce,message,associatedData)
assert(encrypted00==binascii.unhexlify(b'6b52a86d2741165af5ad9b4694d978e7'))
p=SpaeCipher.SPAE_dec(key,nonce,encrypted00,associatedData)
assert(p==binascii.unhexlify(b''))
print("INFO: SPAE test pass")
