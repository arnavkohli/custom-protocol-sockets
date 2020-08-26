#!/usr/bin/env python3

import socket, time, hashlib
from func import *

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

LINE = "X" + "-"*20 + "X"

# U = "asma@gmail.com"
# P = "AAAA1111"
label = "label"
v1 = "abcdefghijklmnop"

BASE_HEADER = "{SD=1;LABEL=label;PRONUM=1;MESSNUM=1}"

# TS = int(time.time())

def first_payload(username, password):
	TS = int(time.time())
	payload = f"{username}||{password}||{TS}"
	h_payload = hash(payload)
	encrypted_payload = f"{payload}||{h_payload}"
	return BASE_HEADER + encrypted_payload

def third_payload(n1, label, username):
	hashed_label = to_hex(hash(label))
	hashed_v1 = to_hex(hash(v1))

	proof1 = (n1 ^ hashed_label) ^ hashed_v1
	payload = f"{proof1}||{username}"
	hashed_payload = hash(payload)
	return BASE_HEADER + f"{payload}||{hashed_payload}"

def listen(conn):
	while True:
		data = conn.recv(1024)
		if not data:
			continue
		else:
			return data

def protocol_one(client):
    '''
         User registation protocol.
    '''
    U = "asma@gmail.com"
    P = "AAAA1111"
    # username = input("[PROMPT] Please enter username: ")
    # password = input("[PROMPT] Please enter password: ")
    username = U
    password = P

    # Prepare payload 1 and send
    payload_1 = first_payload(username, password)
    client.sendall(payload_1.encode())
    print ("[CLIENT] Sent Payload 1!")


    # Listen for payload 2
    data = listen(client)
    headers_2, payload_2 = extract_headers(data.decode())
    if not validate_payload(payload_2):
        print ("[ERROR] Payload 2 integrity check failed!")
        return 
    print ("[CLIENT] Payload 2 integrity verified!")

    # Extract N1
    n1 = int(extract(payload_2)[0].split("||")[0])

    # Prepare payload 3 and send
    payload_3 = third_payload(n1, label, username)
    client.sendall(payload_3.encode())
    print ("[CLIENT] Payload 3 sent!")

    data = listen(client)
    headers_4, payload_4 = extract_headers(data.decode())
    if not validate_payload(payload_4):
        print ("[ERROR] Payload 4 integrity check failed!") 
        return
    print ("[CLIENT] Payload 4 integrity verified!")

    username = extract(payload_4)[0].split("||")[0]
    print (f"[CLIENT] {username} is active!")


def run_client(host, port):
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
	    client.connect((HOST, PORT))

	    while True:
	        protocol_number = int(input(f"{LINE}\n[PROMPT] Options:\n1. First Protocol\n2. Second Protocol\n3. Third Protocol\nEnter Option: "))
	        if protocol_number == 1:
	        	protocol_one(client)
	        elif protocol_number == 2:
	        	pass
	        elif protocol_number == 3:
	        	pass
	        else:
	        	print ("[ERROR] Invalid input. Please try again")
	        	continue
run_client(HOST, PORT)






print('Received', repr(data))