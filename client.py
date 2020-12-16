#!/usr/bin/env python3

import socket, time, hashlib
from func import *
from db import *

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

LINE = "X" + "-"*20 + "X"

NOUNCE = 1234567812345678

LABEL = "label"
# v1 = "abcdefghijklmnop"
KEY_D1_D2 = "5678901056789010"
KEY_D2_AS = "ponmlkjihgfedcba"
KEY_D1_AS = "abcdefghijklmnop"
V1 = hash(hash(KEY_D1_AS))
V2 = hash(hash(KEY_D2_AS))

db = MySQLDB(host=HOST, user="root", passwd="password", database="stock_features")

# x------------------------------x------------------------------x
#                         First Protocol
# x------------------------------x------------------------------x

def first_payload(username, password):
    '''
        Protocol One, first Payload.
    '''
    HEADER = "{SD=1;LABEL=label;PRONUM=1;MESSNUM=1}"
    TS = int(time.time())
    payload = f"{username}||{password}||{TS}"
    h_payload = hash(payload)
    encrypted_payload = data_encrypt(f"{payload}||{h_payload}", key=KEY_D1_AS)
    return HEADER + encrypted_payload

def third_payload(n1, label, username):
    '''
        Protocol One, third Payload.
    '''
    HEADER = "{SD=1;LABEL=label;PRONUM=1;MESSNUM=1}"
    hashed_label = to_hex(hash(label))
    hashed_v1 = to_hex(hash(KEY_D1_AS))
    proof1 = (n1 ^ hashed_label) ^ hashed_v1
    payload = f"{proof1}||{username}"
    h_payload = hash(payload)
    encrypted_payload = data_encrypt(f"{payload}||{h_payload}", key=KEY_D1_AS)
    return HEADER + encrypted_payload

def listen(conn):
    '''
        Function to listen for data.
    '''
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
    global V1, V2
    username = input("[PROMPT] Please enter username: ")
    password = input("[PROMPT] Please enter password: ")

    # Prepare payload 1 and send
    payload_1 = first_payload(username, password)
    client.sendall(payload_1.encode())
    print ("[CLIENT] Sent Payload 1!")


    # Listen for payload 2
    data = listen(client)
    if 'ERROR' in data.decode():
        print (data.decode())
        return

    headers_2, encrypted_payload_2 = extract_headers(data.decode())
    payload_2 = data_decrypt(encrypted_payload_2, key=KEY_D1_AS)
    if not validate_payload(payload_2):
        print ("[ERROR] Payload 2 integrity check failed!")
        return 
    print ("[CLIENT] Payload 2 integrity verified!")

    # Extract N1
    n1 = int(extract(payload_2)[0].split("||")[0])

    # Prepare payload 3 and send
    payload_3 = third_payload(n1, LABEL, username)
    client.sendall(payload_3.encode())
    print ("[CLIENT] Payload 3 sent!")

    data = listen(client)
    headers_4, encrypted_payload_4 = extract_headers(data.decode())
    payload_4 = data_decrypt(encrypted_payload_4, key=KEY_D1_AS)
    if not validate_payload(payload_4):
        print ("[ERROR] Payload 4 integrity check failed!") 
        return
    print ("[CLIENT] Payload 4 integrity verified!")

    username = extract(payload_4)[0].split("||")[0]
    print (f"[CLIENT] {username} is active!")


# x------------------------------x------------------------------x
#                        Second Protocol
# x------------------------------x------------------------------x

def sec_first_payload(username):
    HEADERS = "{SD=1;LABEL=label;PRONUM=2;MESSNUM=1}"
    TS = int(time.time())
    payload = f"{username}||{TS}"
    h_payload = hash(payload)
    encrypted_payload = data_encrypt(f"{payload}||{h_payload}", key=KEY_D1_AS)
    return HEADERS + encrypted_payload

def sec_third_payload(payload_2, label, key):
    HEADERS = "{SD=1;RD=2;PRONUM=2;MESSNUM=1}"
    payload_3 = f"{payload_2}||{label}"
    hashed_payload_3 = hash(payload_3)
    complete_payload = f"{payload_3}||{hashed_payload_3}"
    encrypted_payload = data_encrypt(complete_payload, key=key)
    return HEADERS + encrypted_payload

def protocol_second(client):
    '''
        Imports from Client Side DB
    '''
    global V1, V2
    username = input("[PROMPT] Please enter username: ")
    if not validate_username(username, db.get("username", "users")):
        client.sendall(f"[ERROR] Username {username} is not valid!".encode())
        client.close()
        exit("Connection Closed.")
    #PU = input("[PROMPT] Please enter password: ")
    PU = db.get_pwd_of_user(username, "users")

    payload_1 = sec_first_payload(username)
    client.sendall(payload_1.encode())

    # Listen for payload 2
    data = listen(client)
    if 'ERROR' in data.decode():
        print (data.decode())
        client.close()
        exit("Connection Closed.")

    headers_2, encrypted_payload_2 = extract_headers(data.decode())
    payload_2 = data_decrypt(encrypted_payload_2, key=KEY_D1_AS)

    n2 = int(payload_2.split("||")[0])
    if not validate_payload(payload_2):
        print ("[ERROR] Payload 2 integrity check failed!") 
        return

    payload_3 = sec_third_payload(payload_2, LABEL, KEY_D1_D2)

    # x-----------x Simulation with D2 x-----------x

    headers_3, encrypted_payload_3 = extract_headers(payload_3)
    payload_3 = data_decrypt(encrypted_payload_3, key=KEY_D1_D2)

    if not validate_payload(payload_3):
        print ("[ERROR] Payload 3 integrity check failed!") 
        return

    encrypted_n3 = payload_3.split("||")[1]
    n3 = data_decrypt(encrypted_n3, key=KEY_D2_AS)

    hashed_n2 = to_hex(hash(payload_3.split("||")[0]))
    k = int(n3) ^ int(hashed_n2)
    payload_4 = k ^ to_hex(V2) | to_hex(hash(PU))
    hashed_payload_4 = hash(str(payload_4))
    encrypted_payload_4 = data_encrypt(f"{payload_4}||{hashed_payload_4}", key=KEY_D2_AS)
    # x-----------x End with D2 x-----------x

    z = int(n2) ^ to_hex(hash(LABEL))
    p2 = int(z) ^ to_hex(V1) | to_hex(hash(PU))
    #p2 = int(z) ^ V1 | to_hex(hash(PU))

    d1_response = f"{p2}||{1}"
    hashed_d1_response = hash(d1_response)

    # 2.5
    payload_5 = f"{d1_response}||{encrypted_payload_4}"
    header_5 = "{SD=1;LABEL=label;PRONUM=2;MESSNUM=1}"
    encrypted_payload_5 = data_encrypt(payload_5, key=KEY_D1_AS)
    payload_5 = header_5 + encrypted_payload_5
    client.sendall(encrypted_payload_5.encode())

    data = listen(client)
    encrypted_final_payload = data.decode()
    final_payload = data_decrypt(encrypted_final_payload, key=KEY_D1_AS)
    if not validate_payload(final_payload):
        print ("[ERROR] Final payload integrity check failed!") 
        return

    session_key = final_payload.split("||")[0]

    print (f"[CLIENT] Recieved Session Key: {session_key}")




def run_client(host, port):
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
	    client.connect((HOST, PORT))

	    while True:
	        protocol_number = int(input(f"{LINE}\n[PROMPT] Options:\n1. New User\n2. Registered User\nEnter Option: "))
	        if protocol_number == 1:
	        	protocol_one(client)
	        elif protocol_number == 2:
	        	protocol_second(client)
	        elif protocol_number == 3:
	        	pass
	        else:
	        	print ("[ERROR] Invalid input. Please try again")
	        	continue

run_client(HOST, PORT)