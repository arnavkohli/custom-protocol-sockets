#!/usr/bin/env python3

import socket, time, random, hashlib
from func import *
from db import *


HOST = '127.0.0.1' 
PORT = 65432

NOUNCE = 1234567812345678

KEY_D1_AS = "abcdefghijklmnop"
V1 = to_hex(hash(hash(KEY_D1_AS)))
KEY_D2_AS = "ponmlkjihgfedcba"
V2 = to_hex(hash(hash(KEY_D2_AS)))

db = MySQLDB(host=HOST, user="root", passwd="password", database="stock_features")

DEVICES = {
	1 : db.get_device_by_id(id=1),
	2 : db.get_device_by_id(id=2)
}    

def listen(conn):
	while True:
		data = conn.recv(1024)
		if not data:
			continue
		else:
			return data
# x-----------------------------x-----------------------------x
def second_payload(random_number, label, key):
	BASE_HEADER = "{RD=1;AS=1;PRONUM=1;MESSNUM=2}"
	hashed_random_number = to_hex(hash(random_number))
	hashed_label = to_hex(hash(label))
	n1 = hashed_random_number ^ hashed_label
	hashed_n1 = hash(str(n1))
	encrypted_payload = data_encrypt(f"{n1}||{hashed_n1}", key=key)
	return BASE_HEADER + encrypted_payload, n1

def is_proof_verified(n1, random_number, label, key):
	hashed_random_number = to_hex(hash(random_number))
	hashed_label = to_hex(hash(label))
	hashed_v1 = to_hex(hash(key))

	proof = int(n1) ^ hashed_label ^ hashed_v1
	verProof = hashed_random_number ^ hashed_v1

	return proof == verProof

def fourth_payload(username, key):
	BASE_HEADER = "{RD=1;AS=1;PRONUM=1;MESSNUM=4}"
	encrypted_payload = data_encrypt(f"{username}||{hash(username)}", key=key)
	return BASE_HEADER + encrypted_payload

def protocol_one(data, conn):
	global V1, V2

	random_number = str(1)

	# Process payload 1
	headers_1, encrypted_payload_1 = extract_headers(data.decode())
	# Retrieve label and key using 
	label = get_value_off_header("LABEL", headers_1)
	# print (DEVICES.get(int(get_value_off_header("SD", headers_1))))
	key = DEVICES.get(int(get_value_off_header("SD", headers_1))).get("shared_key")

	# Decrypt Payload 1
	# print (encrypted_payload_1.encode())
	payload_1 = data_decrypt(encrypted_payload_1, key=key)
	time_stamp = int(payload_1.split("||")[-2])

	if not validate_time_stamp(time_stamp):
		print ("[ERROR] Time stamp not verified. Request expired!")
		return

	if not validate_payload(payload_1):
		print ("[ERROR] Payload 1 integrity check failed!")
		return 
	email = extract(payload_1)[0].split("||")[0]
	if email in db.get_existing_emails("users"):
		conn.sendall(f"[ERROR] Email already in use!".encode())
		return

	password = extract(payload_1)[0].split("||")[1]
	#username = hash(label)[:8]
	username = hash(email)[:8]

	# Prepare payload 2 and send
	payload_2, n1 = second_payload(random_number, label, key)
	conn.sendall(payload_2.encode())
	print ("[SERVER] Payload 2 sent!")

	data = listen(conn)
	headers_3, encrypted_payload_3 = extract_headers(data.decode())
	payload_3 = data_decrypt(encrypted_payload_3, key=key)
	if not validate_payload(payload_3):
		print ("[ERROR] Payload 3 integrity check failed!")
		return 
	print ("[SERVER] Payload 3 integrity verified!")
	if is_proof_verified(n1, random_number, label, key):
		print (f"[SERVER] Proof Verified! {username} registered!")
		db.insert_data({"username" : username, "password" : hash(password), "email" : email, "label" : label}, table="users")

		# Prepare paylaod 4 and send
		payload_4 = fourth_payload(username, key=key)
		conn.sendall(payload_4.encode())
		print ("[SERVER] Payload 4 sent!")

# x-----------------------------x-----------------------------x

def sec_second_payload(random_number, label, key1, key2):
	HEADERS = "{SD=1;AS=1;PRONUM=2;MESSNUM=2}"
	hashed_random_number = to_hex(hash(random_number))
	hashed_label = to_hex(hash(label))
	n2 = hashed_random_number ^ hashed_label
	hashed_n2 = to_hex(hash(str(n2)))

	n3 = hashed_random_number ^ hashed_n2
	encrypted_n3 = data_encrypt(str(n3), key=key2)

	payload_2 = f"{n2}||{encrypted_n3}"
	hashed_payload_2 = hash(payload_2)
	complete_payload = f"{payload_2}||{hashed_payload_2}"
	encrypted_complete_payload = data_encrypt(complete_payload, key=key1)

	return HEADERS + encrypted_complete_payload

def protocol_second(data, conn):
	global V1, V2

	random_number = str(1)

	# Process payload 1
	headers_1, encrypted_payload_1 = extract_headers(data.decode())
	# Retrieve label and key using 
	label = get_value_off_header("LABEL", headers_1)
	key = DEVICES.get(int(get_value_off_header("SD", headers_1))).get("shared_key")

	payload_1 = data_decrypt(encrypted_payload_1, key=key)
	username = payload_1.split("||")[0]
	time_stamp = int(payload_1.split("||")[-2])

	if not validate_payload(payload_1):
		print ("[ERROR] Payload 1 integrity check failed!")
		return 

	if not validate_time_stamp(time_stamp):
		print ("[ERROR] Time stamp not verified. Request expired!")
		return

	if not validate_username(username, db.get("username", "users")):
		conn.sendall(f"[ERROR] Username {username} is not valid!".encode())
		conn.close()
		exit("Connection Closed.")

	pwd = db.get_pwd_of_user(username=username, table="users")

	payload_2 = sec_second_payload(random_number=random_number, label=label, key1=KEY_D1_AS, key2=KEY_D2_AS)
	conn.sendall(payload_2.encode())

	data = listen(conn)
	headers_5, encrypted_payload_5 = extract_headers(data.decode())
	payload_5 = data_decrypt(encrypted_payload_5, key=KEY_D1_AS)
	ver_proof_2 = to_hex(hash(random_number)) ^ V1 | to_hex(hash(pwd))
	p2 = int(payload_5.split("||")[0])
	encrypted_ds2_response = payload_5.split("||")[2]
	ds2_response = data_decrypt(encrypted_ds2_response, key=KEY_D2_AS)

	
	if not ver_proof_2 == p2:
		print ("[ERROR] Ver_Proof_2 != P2")
		return

	if not validate_payload(ds2_response):
		print ("[ERROR] DS2 response integrity check failed!")
		return

	p3 = int(ds2_response.split("||")[0])

	ver_proof_3 = to_hex(hash(random_number)) ^ V2 | to_hex(hash(pwd))
 
	if not ver_proof_3 == p3:
		print ("[ERROR] Ver_Proof_3 != P3")
		return

	print ("[SERVER] Generating Session Key...")

	session_key = str(random.randint(100000,1000000))
	session_key = hash(session_key)[:16]
	hashed_session_key = hash(session_key)
	final_payload = f"{session_key}||{hashed_session_key}"
	encrypted_payload = data_encrypt(final_payload, key=KEY_D1_AS)
	conn.sendall(encrypted_payload.encode())
	print ("[SERVER] Sent Session Key!")
	


def run_server(host, port):
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
	    server.bind((HOST, PORT))
	    server.listen()
	    conn, addr = server.accept()
	    with conn:
	        print('Connected by', addr)
	        while True:
	            # Determine protocol number using headers

	            data = listen(conn)
	            if 'ERROR' in data.decode():
	                print (data.decode())
	                exit("Connection closed.")
	            headers, p = extract_headers(data.decode())
	            pronum = get_value_off_header("PRONUM", headers)
	            
	            if pronum == "1":
	            	protocol_one(data, conn)
	            elif pronum == "2":
	            	protocol_second(data, conn)

run_server(HOST, PORT)





