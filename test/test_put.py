import sys
sys.path.append("../")

import pyws
import requests
import os
import json
import uuid
from lxml import etree
from io import StringIO, BytesIO
from requests.auth import HTTPDigestAuth

if __name__ == '__main__':
    wsobj="AMT_GeneralSettings"
    if len(sys.argv)==2:
        wsobj = sys.argv[1]

    hostname = os.getenv("AMT_HOSTNAME")
    if hostname == None:
        print("Hostname is not found")
        exit()
    user = os.getenv("AMT_USERNAME")
    if user==None:
        user="admin"
    
    password = os.getenv("AMT_PASSWORD")
    if password == None:
        print("Please set AMT_PASSWORD env")
        exit()
    w = pyws.WsmanMessage(mode="AMT")
    msg = w.Get(wsobj, "uuid:"+str(uuid.uuid4()))
    #print(msg)
    url = "http://"+hostname+":16992/wsman"
    resp = requests.post(url,data=msg,auth=HTTPDigestAuth(user,password)) 
    #print(str(resp.content))

    doc = etree.fromstring(resp.content)
    xmlresp=etree.tostring(doc,pretty_print=True).decode()
    obj = w.xmlToSimpleMap(xmlresp)
    body = None
    try:
        body=obj["Envelope"]["Body"]
    except KeyError:
        print("Body not found")
        exit()

    print(json.dumps(body,indent=3))
    body[wsobj]["HostName"] = "provonuc"
    msg = w.Put(wsobj,"uuid:"+str(uuid.uuid4()),body)
    print(msg)
    resp2 = requests.post(url,data=msg,auth=HTTPDigestAuth(user,password)) 
    print(str(resp2.content))

    doc = etree.fromstring(resp2.content)
    xmlresp=etree.tostring(doc,pretty_print=True).decode()
    obj = w.xmlToSimpleMap(xmlresp)
    print(json.dumps(obj,indent=3))
    if type(doc) is type(etree.Element("a")):
        print("Element tree")
    else:
        print("Not element tree")


