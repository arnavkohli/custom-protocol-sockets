from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

import sys
 
key = b'abcdefghijklmnop'
 
cipher = AES.new(key, AES.MODE_ECB)

string = b'12345678123456781234567812345678123456781234567812345678'

msg=cipher.encrypt(pad(string, 16))

 
decipher = AES.new(key, AES.MODE_ECB)
print(hex(unpad(decipher.decrypt(msg), 16)))
