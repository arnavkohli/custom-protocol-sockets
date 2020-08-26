#!/usr/bin/env python3

import socket, time, hashlib
from func import *

BASE_HEADER = "{RD=1;LABEL=label;PRONUM=1;MESSNUM=1}"

HOST = '127.0.0.1' 
PORT = 65432

DEVICES = {
	1 : {
		"key" : "abcdefghijklmnop",
		"label" : "label"
	}
}    

def listen(conn):
	while True:
		data = conn.recv(1024)
		if not data:
			continue
		else:
			return data

def second_payload(random_number, label):
	hashed_random_number = to_hex(hash(random_number))
	hashed_label = to_hex(hash(label))
	n1 = hashed_random_number ^ hashed_label
	hashed_n1 = hash(str(n1))
	return BASE_HEADER + f"{n1}||{hashed_n1}", n1

def is_proof_verified(n1, random_number, label, key):
	hashed_random_number = to_hex(hash(random_number))
	hashed_label = to_hex(hash(label))
	hashed_v1 = to_hex(hash(key))

	proof = int(n1) ^ hashed_label ^ hashed_v1
	verProof = hashed_random_number ^ hashed_v1

	return proof == verProof

def fourth_payload(username):
	return BASE_HEADER + f"{username}||{hash(username)}"

def protocol_one(data, conn):
	random_number = str(1)

	# Process payload 1
	headers_1, encrypted_payload_1 = extract_headers(data.decode())
	# Retrieve label and key using 
	label = get_value_off_header("LABEL", headers_1)
	key = DEVICES.get(int(get_value_off_header("SD", headers_1))).get("key")

	# Decrypt Payload 1
	# print (encrypted_payload_1.encode())
	payload_1 = encrypted_payload_1
	time_stamp = int(payload_1.split("||")[-2])

	if not validate_time_stamp(time_stamp):
		print ("[ERROR] Time stamp not verified. Request expired!")
		return

	if not validate_payload(payload_1):
		print ("[ERROR] Payload 1 integrity check failed!")
		return 

	print ("[SERVER] Payload 1 integrity verified!")
	username = extract(payload_1)[0].split("||")[0]

	# Prepare payload 2 and send
	payload_2, n1 = second_payload(random_number, label)
	conn.sendall(payload_2.encode())
	print ("[SERVER] Payload 2 sent!")

	data = listen(conn)
	headers_3, payload_3 = extract_headers(data.decode())
	if not validate_payload(payload_3):
		print ("[ERROR] Payload 3 integrity check failed!")
		return 
	print ("[SERVER] Payload 3 integrity verified!")
	if is_proof_verified(n1, random_number, label, key):
		print (f"[SERVER] Proof Verified! {username} registered!")

		# Prepare paylaod 4 and send
		payload_4 = fourth_payload(username)
		conn.sendall(payload_4.encode())
		print ("[SERVER] Payload 4 sent!")




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

	            # determine_protocol(data)

	            protocol_one(data, conn)

run_server(HOST, PORT)





