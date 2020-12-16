from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
import binascii

import sys
 
key = b'abcdefghijklmnop'
 
cipher = AES.new(key, AES.MODE_ECB)

string = b'12345678123456781234567812345678123456781234567812345678'

msg=cipher.encrypt(pad(string, 16))

msg = binascii.hexlify(msg).upper()
 
decipher = AES.new(key, AES.MODE_ECB)
print(unpad(decipher.decrypt(binascii.unhexlify(msg)), 16))
