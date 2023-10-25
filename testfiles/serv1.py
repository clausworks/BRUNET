# echo-server.py

import socket
import sys

HOST = "10.0.0.2"
PORT = 2345  # Port to listen on (non-privileged ports are > 1023)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        while True:
            data = conn.recv(1024)
            sys.stdout.buffer.write(data);
            if not data:
                break
            #conn.sendall(data)
