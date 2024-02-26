import argparse
import ctypes
import getpass
import socket
import ssl
import struct
import time
import requests, os
from requests.auth import HTTPDigestAuth
import urllib3
from websockets.sync.client import connect as ws_connect
from websockets.sync.client import ClientConnection
import threading

sol=[0x10, 0x00, 0x00, 0x00, 0x53, 0x4F, 0x4C, 0x20]
empty_kerb = [0x13, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]
# Putty support
putty="putty"
putty_opts="-telnet"
# message sequence
amtseq=1        

def start_putty(addr: str):
    time.sleep(1)
    os.system(putty+" "+putty_opts+" "+addr+" >/dev/null 2>&1")

def send_keepalive(con: ClientConnection):
    global amtseq
    try:
        msg = bytearray([0x2B, 0x00, 0x00, 0x00])
        msg.extend(amtseq.to_bytes(4,'little'))
        con.send(bytearray(msg))
        #print("Keepalive seq: ", amtseq)
        amtseq+=1
        t = threading.Timer(2,send_keepalive,[con])
        t.start()
    except Exception as e:
        pass


def shuffle_ws_to_socket(con1: ClientConnection, con2: socket.socket):
    leftover = ''
    while(True):
        try:
            data = con1.recv()
            if len(data)==0:
                break
            if leftover!='':
                data = leftover+data
            if data[0]==0x2a and len(data)>9:
                l = int.from_bytes(data[8:10],'little')
                cs = 10 + l
                if len(data)>=cs:
                    con2.send(data[10:cs])                    
                    leftover=''
                else:
                    leftover=data[0:]
                    
        except Exception as e:
            #print("Exception at ws->cl")
            #print(e)
            break
    # try cleanup
    try:
        con1.close()
    except:
        pass
    try:
        con2.close()
    except:
        pass

def shuffle_socket_to_ws(con1: socket.socket, con2: ClientConnection):
    global amtseq
    while(True):
        try:
            data = con1.recv(8192)
            payload=''
            l = len(data)
            if l==0:
                break
            if l==2 and data[0]==13 and data[1]==10:                
                payload=data[0:1]
                l-=1
            else:
                payload=data
            msg = bytearray([0x28, 0x00, 0x00, 0x00])
            msg.extend(amtseq.to_bytes(4,'little'))
            msg.extend(len(payload).to_bytes(2,'little'))
            msg.extend(payload[0:l])
            con2.send(msg)
            amtseq+=1
        except Exception as e:
            #print("Exception at cl->ws")
            #print(e)
            break
    # try cleanup
    try:
        con1.close()
    except:
        pass
    try:
        con2.close()
    except:
        pass


if __name__=="__main__":
    parser = argparse.ArgumentParser(
        prog="amtsol.py",
        description="Intel AMT SOL PuTTY launcher"
    )
    parser.add_argument(
        'host',help="AMT Hostname"
    )
    parser.add_argument(
        '-u','--user',help="AMT Username",default="admin"
    )
    parser.add_argument(
        '-s','--tls',help="Use TLS", action="store_true"
    )
    parser.add_argument(
        '-k','--insecure',help="Skip Verify TLS", action="store_true"
    )
    parser.add_argument(
        '-p','--password',help="AMT Password",default=""
    )

    args = parser.parse_args()
    amt_password = ""
    if args.password !="":
        amt_password = str(args.password)
    else:
        amt_password = getpass.getpass()
    
    if amt_password=="":
        print("Password required.")

    # create tcp port listening incoming connection
    tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_server.bind(('127.0.0.1',0))
    addr = tcp_server.getsockname()
    telnet_addr = "-P "+str(addr[1])+" "+str(addr[0])
    tcp_server.listen()
    # Start Putty delayed by 1 second
    th_putty = threading.Thread(target=start_putty, args=[telnet_addr])
    th_putty.start()

    client_socket, ret_addr = tcp_server.accept()
    # connect AMT Redirection
    host= args.host
    port = 16992
    if args.tls:
        port +=1
    # establish initial HTTP(s) Digest auth
    session = requests.Session()
    session.auth = auth=HTTPDigestAuth(args.user,amt_password)
    if args.tls and args.insecure:
        session.verify = False
        urllib3.disable_warnings()

    auth_url = "http://"+host+":"+str(port)+"/index.htm"
    if args.tls:
        auth_url = "https://"+host+":"+str(port)+"/index.htm"
    next_header=""
    try:
        resp = session.get(auth_url)
        next_header = session.auth.build_digest_header("GET","/ws-redirection")
    except Exception as e:
        client_socket.close()
        print(e)
        exit(-1)
    
    #print(next_header)
    # Establish websocket to /ws-redirection
    url="ws://"+host+":"+str(port)+"/ws-redirection"
    ssl_context = None
    if args.tls:
        url="wss://"+host+":"+str(port)+"/ws-redirection"
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.options =0x4 |ssl.OP_NO_COMPRESSION| ssl.OP_NO_TICKET |ssl.OP_CIPHER_SERVER_PREFERENCE
        ssl_context.check_hostname=False
        ssl_context.verify_mode = ssl.VerifyMode.CERT_NONE
        ssl_context.verify_flags = ssl.VERIFY_X509_TRUSTED_FIRST
        cipher_string ="TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-CCM8:ECDHE-ECDSA-AES256-CCM:ECDHE-ECDSA-AES128-CCM8:ECDHE-ECDSA-AES128-CCM:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-CCM8:DHE-RSA-AES256-CCM:DHE-RSA-AES128-CCM8:DHE-RSA-AES128-CCM:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-CCM8:AES256-CCM:AES128-CCM8:AES128-CCM:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA"
        ciphers = ssl_context.set_ciphers(cipher_string)        

    ws_connect:ClientConnection 
    try:
        websocket = ws_connect(uri=url,additional_headers={"Authorization": next_header}, ssl_context=ssl_context)
        # the following transaction is not checked, just formality 
        websocket.send(bytearray(sol))
        incoming = websocket.recv()
        websocket.send(bytearray(empty_kerb))
        incoming = websocket.recv()
        serial_setting = bytearray([0x20,0x00,0x00,0x00])
        serial_setting.extend(amtseq.to_bytes(4,'little'))
        
        _MaxTxBuffer = 10000
        _TxTimeout = 100
        _TxOverflowTimeout = 0
        _RxTimeout = 10000
        _RxFlushTimeout = 100
        _Heartbeat = 0
        _ZeroInt = 0
                                
        serial_setting.extend(_MaxTxBuffer.to_bytes(2,'little')) # MaxTXBuffer=10000
        serial_setting.extend(_TxTimeout.to_bytes(2,'little')) # TXTimeout=100
        serial_setting.extend(_TxOverflowTimeout.to_bytes(2, 'little')) # TXOverflowTimeout=100
        serial_setting.extend(_RxTimeout.to_bytes(2,'little')) # RXTimeout=10000
        serial_setting.extend(_RxFlushTimeout.to_bytes(2,'little')) # RXFlushTimeout=100
        serial_setting.extend(_Heartbeat.to_bytes(2,'little')) # Hearbeat=0
        serial_setting.extend(_ZeroInt.to_bytes(4,'little')) 
        amtseq+=1
        websocket.send(bytes(serial_setting))
        incoming = websocket.recv()
        from_socket = client_socket.recv(8192)
        if from_socket[0]==0xff:
            # send terminal options
            term_options = [0xff,0xfb,0x01,0xff,0xfd,0x03,0xff,0xfb,0x03]
            client_socket.send(bytearray(term_options))
    except Exception as e:
        print(e)
        exit(-1)

    try:
        th1 = threading.Thread(target=shuffle_socket_to_ws, args=(client_socket,websocket))
        th1.start()
        th2 = threading.Thread(target=shuffle_ws_to_socket, args=(websocket,client_socket))
        th2.start()
        # fire a self rearming timer
        timer_ka = threading.Timer(2,send_keepalive,[websocket])
        timer_ka.start()
        th1.join()
        th2.join()
        websocket.close()
        client_socket.close()
    except Exception as e:
        print(e)
    
    try:
        th_putty.join()
    except:
        pass