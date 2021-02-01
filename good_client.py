from socket import *
#from scapy import *
import thread


def data_collector(HOST ,BUFSIZE):
    global sock
    while 1:
        data = sock.recv(BUFSIZE)
        print data
        if data[0] == ':':
            sock.close()
            sock = socket(AF_INET , SOCK_STREAM)
            sock.connect((HOST, int(data[1:])))
            print "changed port"
            
BUFSIZE = 1024
HOST = '10.0.0.5'
PORT = 55672
ADDR = (HOST , PORT)

sock = socket(AF_INET , SOCK_STREAM)
sock.connect(ADDR)
print "connected"
thread.start_new_thread(data_collector , (HOST, BUFSIZE))
while 1:
    data = raw_input("--->> ")
    if not data:
        print 'closing....'
        break
    sock.send(data)


sock.close()
