import socket
import sys
import random
import time

# Input file is redirected from stdin

HOST = sys.argv[1]
PORT = int(sys.argv[2])

if (sys.argv[3] == 'nodelay'):
    delay = False
else:
    delay = True
    DELAY_POW = int(sys.argv[3])

random.seed(5) # constant seed for consistent values

done_sending = False
done_receiving = False

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    while not (done_sending and done_receiving):
        if not done_sending:
            pow_nbytes = random.randrange(1, 10)
            nbytes = 2**pow_nbytes
            outdata = sys.stdin.buffer.read(nbytes)
            if len(outdata) == 0:
                done_sending = True
                s.shutdown(socket.SHUT_WR)
                #print('done sending')
            else:
                #print(f'sending {len(outdata)} bytes')
                s.sendall(outdata)
        if not done_receiving:
            indata = s.recv(nbytes)
            if (len(indata) == 0):
                done_receiving = True
                #print('done receiving')
            else:
                sys.stdout.buffer.write(indata)
                #print(f'received {len(indata)} bytes')
        if delay:
            t = random.randrange(1, 10) * (10 ** DELAY_POW)
            time.sleep(t)
