import socket

HOST = "10.0.0.2"  # The server's hostname or IP address
PORT = 2345  # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(input().encode())
    #data = s.recv(1024)

#print(f"Received {data!r}")
