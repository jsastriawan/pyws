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
    wsobj="AMT_MessageLog"
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
    msg = w.Exec(wsobj,"PositionToFirstRecord","uuid:"+str(uuid.uuid4()),None)
    print(msg)
    url = "http://"+hostname+":16992/wsman"
    resp = requests.post(url,data=msg,auth=HTTPDigestAuth(user,password)) 
    #print(str(resp.content))

    doc = etree.fromstring(resp.content)
    xmlresp=etree.tostring(doc,pretty_print=True).decode()
    obj = w.xmlToSimpleMap(xmlresp)
    print(json.dumps(obj,indent=3))
    iterid = None
    try:
        iterid=obj["Envelope"]["Body"]["PositionToFirstRecord_OUTPUT"]["IterationIdentifier"]
    except KeyError as e:
        print(e)
        exit()
    
    input = {
        "IterationIdentifier": iterid,
        "MaxReadRecords": 10
    }
    msg = w.Exec(wsobj,"GetRecords","uuid:"+str(uuid.uuid4()),input)
    print(msg)
    resp = requests.post(url,data=msg,auth=HTTPDigestAuth(user,password)) 
    #print(str(resp.content))

    doc = etree.fromstring(resp.content)
    xmlresp=etree.tostring(doc,pretty_print=True).decode()
    obj = w.xmlToSimpleMap(xmlresp)
    print(json.dumps(obj,indent=3))
    

