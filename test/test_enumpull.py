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
from collections import OrderedDict,abc

if __name__ == '__main__':
    wsobj="CIM_SoftwareIdentity"
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
    sess = requests.Session()
    sess.auth = HTTPDigestAuth(user,password)
    msg = w.Enum(wsobj, "uuid:"+str(uuid.uuid4()))
    #print(msg)
    url = "http://"+hostname+":16992/wsman"
    resp = sess.post(url,data=msg) 
    #print(str(resp.content))

    doc = etree.fromstring(resp.content)
    xmlresp=etree.tostring(doc,pretty_print=True).decode()
    obj = w.xmlToSimpleMap(xmlresp)
    #print(json.dumps(obj,indent=3))
    
    ctx = None
    try:
        ctx=obj["Envelope"]["Body"]["EnumerateResponse"]["EnumerationContext"]        
    except KeyError:
        pass
    
    items = OrderedDict()
    items[wsobj]= []
    end_enum = False
    while end_enum == False:
        msg = w.Pull(wsobj,"uuid:"+str(uuid.uuid4()),ctx)
        #print(msg)
        resp = sess.post(url,data=msg) 
        #print(str(resp.content))

        doc = etree.fromstring(resp.content)
        xmlresp=etree.tostring(doc,pretty_print=True).decode()
        obj = w.xmlToSimpleMap(xmlresp)
        try:
            temp1 = obj["Envelope"]["Body"]["PullResponse"]["Items"]
            for k1,v1 in temp1.items():
                if isinstance(v1,list):
                    for v2 in v1:
                        items[wsobj].append(v2)
                else:
                    items[wsobj].append(v1)
            
        except KeyError:
            pass

        try:
            # check if there us EndOfSequence
            eos = obj["Envelope"]["Body"]["PullResponse"]["EndOfSequence"]
            end_enum = True
            break
        except KeyError:
            pass

        try:
            ctx=obj["Envelope"]["Body"]["EnumerateResponse"]["EnumerationContext"]        
        except KeyError:
            pass
    

    print(json.dumps(items,indent=3))
        
