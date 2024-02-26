import socket
import ssl
import sys


if __name__== "__main__":
    args = sys.argv
    if len(args)!=2:
        print(args[0]+" host:port")
        exit(-1)
    addr = args[1].split(":",2)
    if len(addr)!=2:
        print(args[0]+" host:port")
        exit(-1)
    port = 0
    try:
        port = int(addr[1])
    except:
        print("Port is not an integer")
        exit(1)

    client = socket.create_connection((addr[0],port))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.options =0x4 |ssl.OP_NO_COMPRESSION| ssl.OP_NO_TICKET |ssl.OP_CIPHER_SERVER_PREFERENCE
    ctx.check_hostname=False
    ctx.verify_mode = ssl.VerifyMode.CERT_NONE
    ctx.verify_flags = ssl.VERIFY_X509_TRUSTED_FIRST
    cipher_string ="TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-CCM8:ECDHE-ECDSA-AES256-CCM:ECDHE-ECDSA-AES128-CCM8:ECDHE-ECDSA-AES128-CCM:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-CCM8:DHE-RSA-AES256-CCM:DHE-RSA-AES128-CCM8:DHE-RSA-AES128-CCM:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-CCM8:AES256-CCM:AES128-CCM8:AES128-CCM:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA"
    ciphers = ctx.set_ciphers(cipher_string)
    try:
        tlsclient = ctx.wrap_socket(client)
        der = tlsclient.getpeercert(binary_form=True) 
        pem = ssl.DER_cert_to_PEM_cert(der)
        print(pem)
    except Exception as e:
        print(e)
