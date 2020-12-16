from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time, hashlib, binascii

def validate_username(username, db):
	return username in db

def get_value_off_header(key, header):
	return header.split(f"{key}=")[-1].split(";")[0]

def extract_headers(payload):
	s = payload.split("}")
	return s[0][1:], s[-1]

def hash(val):
	return hashlib.sha256(val.encode()).hexdigest()

def to_hex(val):
	return int(str(val), 16)

def extract(complete):
	return complete.rsplit("||", 1)

def validate_payload(payload):
	payload, h_payload = extract(payload)
	return hash(payload) == h_payload

def data_encrypt(text, key):
	cipher = AES.new(key.encode(), AES.MODE_ECB)
	return binascii.hexlify(cipher.encrypt(pad(text.encode(), 16))).decode()

def data_decrypt(text, key):
	decipher = AES.new(key.encode(), AES.MODE_ECB)
	return unpad(decipher.decrypt(binascii.unhexlify(text)), 16).decode()

def validate_time_stamp(ts):
	current = int(time.time())
	if current <= ts + 90:
		return True
	return False

# x------x Reference x------x

def DataEnc(PText, K):
	cipher = AES.new(K, AES.MODE_ECB)
	return cipher.encrypt(PText)

def DataDec(Ctext, K):
	decipher = AES.new(K, AES.MODE_ECB)
	return decipher.decrypt(Ctext)

def VerifyUserCreds(username, pwd, db):
	if username in db and db[username] == pwd:
		return True
	return False

def isTimeAcceptable(TS):
	current = int(time.time())
	if TS <=  + 90:
		return True
	return False

def isReqRefresh(TS):
	return isTimeAcceptable(TS)

def isResponseValid(n1, n1_):
	if n1 == n1_:
		return True
	return False

def isHashEqual(H_Value, UnH_Value):
	if H_Value == hash(UnH_Value):
		return True
	return False

def VerifyDID(DID, N, X):
	if DID ^ N == X:
		return True
	return False
