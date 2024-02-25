import argparse
import getpass
import socket
import ssl
import time
import requests, os
from requests.auth import HTTPDigestAuth
import urllib3
from websockets.sync.client import connect as ws_connect
from websockets.sync.client import ClientConnection
import threading

kvm=[0x10, 0x01, 0x00, 0x00, 0x4b, 0x56, 0x4d, 0x52]
empty_kerb = [0x13, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]
direct = [0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
# Tiger VNC Viewer support
vncviewer="vncviewer"
vnc_opts="-PreferredEncoding=ZRLE -LowColorLevel=2 -NoJPEG -AutoSelect=0 -FullColor=0"        

def start_vncviewer(addr: str):
    time.sleep(1)
    os.system(vncviewer+" "+vnc_opts+" "+addr+" >/dev/null 2>&1")

def shuffle_ws_to_socket(con1: ClientConnection, con2: socket.socket):
    while(True):
        try:
            data = con1.recv()
            con2.sendall(data)
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
    while(True):
        try:
            data = con1.recv(8192)
            con2.send(bytearray(data))
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
        prog="amtkvm.py",
        description="Intel AMT KVM vncviewer"
    )
    parser.add_argument(
        'host',help="AMT Hostname"
    )
    parser.add_argument(
        '-u','--user',help="Use TLS",default="admin"
    )
    parser.add_argument(
        '-s','--tls',help="Use TLS", action="store_true"
    )
    parser.add_argument(
        '-k','--insecure',help="Skip Verify TLS", action="store_true"
    )
    parser.add_argument(
        '-p','--password',help="Password",default=""
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
    tcp_server.bind(('',0))
    addr = tcp_server.getsockname()
    vnc_addr = str(addr[0])+"::"+str(addr[1])
    tcp_server.listen()
    # Start VNC Viewer delayed by 1 second
    th_vnc = threading.Thread(target=start_vncviewer, args=[vnc_addr])
    th_vnc.start()

    client_socket, ret_addr = tcp_server.accept()
    # connect AMT KVM
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
    resp = session.get(auth_url)
    next_header = session.auth.build_digest_header("GET","/ws-redirection")
    
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
        cipher_string ="TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA"
        ciphers = ssl_context.set_ciphers(cipher_string)        

    websocket = ws_connect(uri=url,additional_headers={"Authorization": next_header}, ssl_context=ssl_context)
    # the following transaction is not checked, just formality 
    websocket.send(bytearray(kvm))
    incoming = websocket.recv()
    websocket.send(bytearray(empty_kerb))
    incoming = websocket.recv()
    websocket.send(bytearray(direct))
    incoming = websocket.recv()
    # send any attached RFB mesage sent with the direct 8 bytes response
    client_socket.sendall(incoming[8:])
    try:
        th1 = threading.Thread(target=shuffle_socket_to_ws, args=(client_socket,websocket))
        th1.start()
        th2 = threading.Thread(target=shuffle_ws_to_socket, args=(websocket,client_socket))
        th2.start()        
        th1.join()
        th2.join()
        websocket.close()
        client_socket.close()
    except Exception as e:
        print(e)
    
    try:
        th_vnc.join()
    except:
        pass