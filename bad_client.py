from scapy.all import *
import random as rnd
import  sys
import time
if sys.stdout != sys.__stdout__:
    sys.stdout = sys.__stdout__


HOST = '10.0.0.5'
PORT = 55672
ADDR = (HOST , PORT)
for i in range(10):
    dport_rnd = rnd.randint(1,65535)
    send((IP(dst = HOST, src = '10.0.0.8')/TCP(dport = PORT ,sport =  dport_rnd, flags = 'S')))
    time.sleep(2)


