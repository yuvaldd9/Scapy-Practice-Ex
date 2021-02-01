"""
SERVER
author - Yuval Didi
black list
ip : warning - level
levels:

0 - suspect
1 - blocked

"""
import random as rnd
import sys , os
from scapy.all import *
import re 
import sqlite3 as lite

if sys.stdout != sys.__stdout__:
    sys.stdout = sys.__stdout__


#database functions - start
def create_db(dir_name):
    """
    this function, create the database if it does not exist
    """
    if not os.path.isfile(dir_name):
        f = open(dir_name, 'w')
        conn = lite.connect(blackListPath)
        cursor = conn.cursor()
        cursor.execute(''' CREATE TABLE blackList(id INTEGER PRIMARY KEY,
                Ip TEXT, level INTEGER) ''')
        conn.commit()
        f.close()
def loadBlackList(blackListPath):
    """
    this function returns dictionary of the database
    """
    blackList = {}
    try:
        conn = lite.connect(blackListPath)
    except lite.Error, e:
        print "Error %s" % blackListPath
        sys.exit(1)
    finally:
        if conn:
            print "opened black list successfully"
            cursor = conn.cursor()
            cursor.execute(''' SELECT * FROM blackList ''')
            for row in cursor:
                blackList[row[1]] = (int(row[0]),int(row[2]))
    return blackList
def addToBlackList(blackList , blackListPath, ip):
    try:
        conn = lite.connect(blackListPath)
    except lite.Error, e:
        print "Error %s" % blackListPath
        sys.exit(1)
    finally:
        if conn:
            print "opened black list successfully"
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO blackList(ip, level)
                        VALUES(?,?)''', (ip , 0))
            new_id = [int(i[0]) for i in (cursor.execute('''SELECT id FROM blackList WHERE Ip = ?''', (ip,)))][0]
            print new_id
            conn.commit()
    print ip, "added to black"       
    blackList[ip] = ((new_id),0)
    return blackList
def changeValueInBlackList(blackList, blackListPath, ip):
    """
    change the tag of the suspected client to blocked client 
    """
    try:
        conn = lite.connect(blackListPath)
    except lite.Error, e:
        print "Error %s" % blackListPath
        sys.exit(1)
    finally:
        if conn:
            print "opened black list successfully"
            cursor = conn.cursor()
            cursor.execute('''UPDATE blackList SET level = ? WHERE id = ?''', (1 , blackList[ip][0]))
            conn.commit()
    blackList[ip] = (blackList[ip][0], 1)
    return blackList
def manage_black_list(blackList, blackListPath , ip): 
    """
    this function does the logic of the database
    """
    if ip in blackList.keys():
        if  blackList[ip][1] == 1:
            return blackList
        blackList = changeValueInBlackList(blackList , blackListPath, ip)
    else:
        blackList = addToBlackList(blackList , blackListPath, ip)
    return blackList
#database functions - end
def manage_client_data(next_seq , next_ack, ip):
    """
    this function follow our clients connection data
    """
    global OUR_CLIENTS
    OUR_CLIENTS[ip] = (OUR_CLIENTS[ip][0],OUR_CLIENTS[ip][1],next_seq, next_ack, OUR_CLIENTS[ip][4])
    print "updated....",OUR_CLIENTS[ip]
#connection - start
def collect_data_tcp_packet(pkt):
    """
    returns dictionary of the useful data of the packets the server recieve
    """
    data = {"src" : pkt[0][1].src , "id" : pkt[0][1].id , "dst":pkt[0][1].dst ,"dport" : pkt[0][2].dport ,\
            "sport" : pkt[0][2].sport,"data": str(pkt["TCP"].payload), "flags" : pkt[0][2].flags , \
             "seq" : pkt[0][2].seq , "ack" : pkt[0][2].ack , "len": len(pkt["TCP"].payload)}
    return data
def seq_ack_managemet(data_pkt, is_syn_ack = False, is_fin_ack = False):
    """
    calculate the  seq,ack values
    """
    if is_syn_ack:
        return (rnd.randint(2**30, (2**32-1)), data_pkt["seq"]+1)
    if is_fin_ack:
        return (data_pkt["ack"] , data_pkt["seq"] +1)
    return (data_pkt["ack"] , data_pkt["seq"] + data_pkt["len"])
def send_syn_ack(data_pkt):
    """
    reply  syn_ack
    """
    next_seq, next_ack = seq_ack_managemet(data_pkt, True)
    pkt = IP(dst = data_pkt["src"], src = data_pkt["dst"])/TCP(dport = data_pkt["sport"] ,sport = data_pkt["dport"], flags = 'SA' , seq = next_seq ,ack = next_ack)
    send(pkt)
    print 'sent syn/ack to ', data_pkt["src"], "port ", data_pkt["dport"], "seq ", next_seq, "ack ", next_ack    
def send_fin_ack(data_pkt):
    next_seq, next_ack = seq_ack_managemet(data_pkt,False,True)
    pkt = IP(dst = data_pkt["src"], src = data_pkt["dst"])/TCP(dport = data_pkt["sport"] ,sport = data_pkt["dport"], flags = 'A' , seq = next_seq ,ack = next_ack)
    send(pkt)
    print 'sent syn/ack to ', data_pkt["src"], "port ", data_pkt["dport"], "seq ", next_seq, "ack ", next_ack    
def send_ack(data_pkt):
    """
    reply ack to the client message, returns the seq,ack values for the echo reply
    """
    next_seq, next_ack = seq_ack_managemet(data_pkt)
    ack_pkt = IP(dst = data_pkt["src"], src = data_pkt["dst"])/TCP(dport = data_pkt["sport"] ,sport = data_pkt["dport"], flags = 'A' , seq = next_seq ,ack = next_ack)
    send(ack_pkt)
    manage_client_data(next_seq,next_ack, data_pkt["src"])
    print 'sent ack to ', data_pkt["src"], "port ", data_pkt["dport"], "seq ", next_seq, "ack ", next_ack
    return next_seq, next_ack#return the seq ack values for the echo reply
def send_reset(data_pkt):
    """
    send reset to the blocked clients
    """
    next_seq, next_ack = seq_ack_managemet(data_pkt)
    pkt = IP(dst = data_pkt["src"], src = data_pkt["dst"])/TCP(dport = data_pkt["sport"] ,sport = data_pkt["dport"], flags = 'R' , seq = next_seq ,ack = next_ack)
    send(pkt)
    print 'sent reset to ', data_pkt["src"], "port ", data_pkt["dport"], "seq ", next_seq, "ack ", next_ack
def echo(data_pkt):
    """
    reply echo
    """
    next_seq, next_ack = send_ack(data_pkt)
    echo_pkt = IP(dst = data_pkt["src"], src = data_pkt["dst"])/TCP(dport = data_pkt["sport"] ,sport = data_pkt["dport"], flags = 'AP', seq = next_seq ,ack = next_ack)/(data_pkt["data"])
    sr1(echo_pkt)
    manage_client_data(next_ack, next_seq + len((data_pkt["data"])), data_pkt["src"])
    print "echo ",data_pkt["data"] ,"to...", data_pkt["src"], "port ", data_pkt["dport"]
def change_port_alert(clients, PORT):
    """
    send the alert :NEXT_PORT to all of the good clients
    """
    for ip in clients.keys():
        print ip
        if clients[ip][1]:
            alert_pkt = IP(dst = ip, src = '10.0.0.5')/TCP(dport = clients[ip][4] ,sport = (PORT - 1), flags = 'AP', seq = clients[ip][3] ,ack =  clients[ip][2])/(":"+str(PORT))
            send(alert_pkt)
            
#connection - end
def custom_action(pkt):
    global blackListPath
    global OUR_CLIENTS
    global PORT
    global blackList
    
    if pkt[0][2].dport == PORT:
        data_pkt = collect_data_tcp_packet(pkt)
        print OUR_CLIENTS
        #check if the client is blocked
        if data_pkt["src"] in blackList.keys() and blackList[data_pkt["src"]][1] == 1:
            print "changing port now!!!"
            send_reset(data_pkt)
            PORT += 1
            change_port_alert(OUR_CLIENTS, PORT)
            OUR_CLIENTS = {}
        #check if the client started tcp handsake
        elif data_pkt["flags"] == 2:#syn
            print "syn"
            #check if the client is suspected and sent again - he will be tagged as blocked
            if data_pkt["src"] in OUR_CLIENTS.keys() and data_pkt["src"] in blackList.keys():
                blacklist = manage_black_list(blackList, blackListPath , data_pkt["src"])
                del OUR_CLIENTS[data_pkt["src"]]
            #check if the client send syn again - he will be tagged as suspected
            elif data_pkt["src"] in OUR_CLIENTS.keys():
                blacklist = manage_black_list(blackList, blackListPath , data_pkt["src"])
                send_syn_ack(data_pkt)
            #if new client
            else:
                OUR_CLIENTS[data_pkt["src"]] = (True , False)
                send_syn_ack(data_pkt)
        #check if the client sent ack
        elif data_pkt["flags"] == 16:#ack
            #check if the ack is for the handshake
            if data_pkt["src"] in OUR_CLIENTS.keys() and OUR_CLIENTS[data_pkt["src"]][0]:
                OUR_CLIENTS[data_pkt["src"]] = (False , True, data_pkt["seq"], data_pkt["ack"], data_pkt["sport"])
            else:
                manage_client_data(data_pkt["seq"], data_pkt["ack"], data_pkt["src"])
        #if the client sent reset:
        elif data_pkt["flags"] == 'RA':
            print 'closing ', data_pkt["src"]
            if data_pkt["src"] in OUR_CLIENTS.keys() and OUR_CLIENTS[data_pkt["src"]][1]:
                del OUR_CLIENTS[data_pkt["src"]]
        #if the client sent fin packet - in my network the socket sent always reset but it's should work:
        elif data_pkt["flags"] == 'F':
            print 'closing ', data_pkt["src"]
            if data_pkt["src"] in OUR_CLIENTS.keys() and OUR_CLIENTS[data_pkt["src"]][1]:
                send_fin_ack(data_pkt)
                del OUR_CLIENTS[data_pkt["src"]]
        #if the client sent regular message
        elif data_pkt["src"] in OUR_CLIENTS.keys() and data_pkt["flags"] == 'AP':
            print 'echo'
            if  OUR_CLIENTS[data_pkt["src"]][1]:
                print 'echo'
                echo(data_pkt)

blackListPath = r"C:\Users\yuval\Desktop\School\Cyber\Real Ex7\blackList.db"
PORT = 55672
create_db(blackListPath)
blackList = loadBlackList(blackListPath)
OUR_CLIENTS = {}
while 1:
    sniff(filter = "tcp",count = 1,prn = custom_action)