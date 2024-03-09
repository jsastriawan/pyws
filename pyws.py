import copy
import hashlib
import re
import ssl
from requests.auth import HTTPDigestAuth
import uuid
from lxml import etree
from collections import OrderedDict,abc
import urllib3, requests
from urllib3.util.ssl_ import create_urllib3_context
from requests.adapters import HTTPAdapter
import pem

import requests

class WsmanMessage:
    _actionGet = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"
    _actionPut = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Put"
    _actionDelete = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"
    _actionEnumerate = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
    _actionPull = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull"
    _ns_prefix = {
        "AMT": "http://intel.com/wbem/wscim/1/amt-schema/1/",
        "CIM": "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/",
        "IPS": "http://intel.com/wbem/wscim/1/ips-schema/1/",
        }
    _nsmap = {}

    def __init__(self, mode="AMT"):
        self._nsmap={"xsd":"http://www.w3.org/2001/XMLSchema",
                     "a":"http://schemas.xmlsoap.org/ws/2004/08/addressing", 
                     "w":"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"}
    

    def _getFullUrl(self, obj):
        pfx = obj[:3]
        try:
            return self._ns_prefix[pfx]+obj
        except KeyError:
            return ""
    
    def Get(self, obj, id, selector=None):
        msg = etree.Element("Envelope",nsmap=self._nsmap,xmlns="http://www.w3.org/2003/05/soap-envelope")
        
        header = etree.Element("Header")
        # add action header
        action = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/08/addressing","Action"))
        action.attrib["mustUnderstand"]="true"
        action.text = self._actionGet
        header.append(action)
        dest = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/08/addressing","To"))
        dest.text = "/wsman"
        header.append(dest)
        resuri = etree.Element(etree.QName("http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd","ResourceURI"))
        resuri.text = self._getFullUrl(obj)
        header.append(resuri)
        mesgid = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/08/addressing","MessageID"))
        mesgid.text = str(id)
        header.append(mesgid)
        replyto = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/08/addressing","ReplyTo"))
        address = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/08/addressing","Address"))
        address.text = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
        replyto.append(address)
        header.append(replyto)
        optimeout = etree.Element(etree.QName("http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd","OperationTimeout"))
        optimeout.text = "PT60S"
        header.append(optimeout)
        if selector!=None:
            header.append(selector)
        body = etree.Element("Body")
        
        msg.append(header)
        msg.append(body)
        
        doc = etree.ElementTree(msg)
        
        return etree.tostring(doc, pretty_print=True, xml_declaration=True, encoding="utf-8").decode()
    
    def Put(self, obj, id, data, selector=None):
        nsmap = self._nsmap
        uri = self._getFullUrl(obj)
        nsmap["r"]= uri
        msg = etree.Element("Envelope",nsmap=nsmap,xmlns="http://www.w3.org/2003/05/soap-envelope")

        header = etree.Element("Header")
        # add action header
        action = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/08/addressing","Action"))
        action.attrib["mustUnderstand"]="true"
        action.text = self._actionPut
        header.append(action)
        dest = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/08/addressing","To"))
        dest.text = "/wsman"
        header.append(dest)
        resuri = etree.Element(etree.QName("http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd","ResourceURI"))
        resuri.text = self._getFullUrl(obj)
        header.append(resuri)
        mesgid = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/08/addressing","MessageID"))
        mesgid.text = str(id)
        header.append(mesgid)
        replyto = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/08/addressing","ReplyTo"))
        address = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/08/addressing","Address"))
        address.text = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
        replyto.append(address)
        header.append(replyto)
        optimeout = etree.Element(etree.QName("http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd","OperationTimeout"))
        optimeout.text = "PT60S"
        header.append(optimeout)
        if selector!=None:
            header.append(selector)
        body = etree.Element("Body")
        
        msg.append(header)
        # convert data to XML
        putobj = etree.Element(etree.QName(uri,obj))
        for k in data[obj]:
            el = etree.Element(etree.QName(uri,k))
            # assuming simple scalar value
            if data[obj][k]!=None:
                if isinstance(data[obj][k], bool):
                    # make sure it is 'true' or 'false'
                    el.text=str(data[obj][k]).lower()
                elif type(data[obj][k]) is type(etree.Element("a")):
                    # if we have an etree.Element type, just append it. 
                    # It may have its own custom namespace representing a complex entity
                    el.append(data[obj][k])
                else:
                    el.text=str(data[obj][k])
            putobj.append(el)

        body.append(putobj)
        msg.append(body)
        
        doc = etree.ElementTree(msg)
        return etree.tostring(doc, pretty_print=True, xml_declaration=True, encoding="utf-8").decode()

    def Exec(self, obj, method, id, input, selector=None):
        nsmap = self._nsmap
        uri = self._getFullUrl(obj)
        nsmap["r"]= uri
        msg = etree.Element("Envelope",nsmap=nsmap,xmlns="http://www.w3.org/2003/05/soap-envelope")

        header = etree.Element("Header")
        # add action header
        action = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/08/addressing","Action"))
        action.attrib["mustUnderstand"]="true"
        action.text = uri + "/" + method
        header.append(action)
        dest = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/08/addressing","To"))
        dest.text = "/wsman"
        header.append(dest)
        resuri = etree.Element(etree.QName("http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd","ResourceURI"))
        resuri.text = self._getFullUrl(obj)
        header.append(resuri)
        mesgid = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/08/addressing","MessageID"))
        mesgid.text = str(id)
        header.append(mesgid)
        replyto = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/08/addressing","ReplyTo"))
        address = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/08/addressing","Address"))
        address.text = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
        replyto.append(address)
        header.append(replyto)
        optimeout = etree.Element(etree.QName("http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd","OperationTimeout"))
        optimeout.text = "PT60S"
        header.append(optimeout)
        if selector!=None:
            header.append(selector)
        body = etree.Element("Body")
        
        msg.append(header)
        # convert data to XML
        inputobj = etree.Element(etree.QName(uri,method+"_INPUT"))
        if input!=None:
            for k in input:
                el = etree.Element(etree.QName(uri,k))
                # assuming simple scalar value
                if input[k]!=None:
                    if isinstance(input[k], bool):
                        # make sure it is 'true' or 'false'
                        el.text=str(input[k]).lower()
                    else:
                        el.text=str(input[k])
                inputobj.append(el)

        body.append(inputobj)
        msg.append(body)
        
        doc = etree.ElementTree(msg)
        return etree.tostring(doc, pretty_print=True, xml_declaration=True, encoding="utf-8").decode()

    def Enum(self, obj, id, selector=None):
        nsmap = self._nsmap
        nsmap["n"]="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
        msg = etree.Element("Envelope",nsmap=nsmap,xmlns="http://www.w3.org/2003/05/soap-envelope")

        header = etree.Element("Header")
        # add action header
        action = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/08/addressing","Action"))
        action.attrib["mustUnderstand"]="true"
        action.text = self._actionEnumerate
        header.append(action)
        dest = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/08/addressing","To"))
        dest.text = "/wsman"
        header.append(dest)
        resuri = etree.Element(etree.QName("http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd","ResourceURI"))
        resuri.text = self._getFullUrl(obj)
        header.append(resuri)
        mesgid = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/08/addressing","MessageID"))
        mesgid.text = str(id)
        header.append(mesgid)
        replyto = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/08/addressing","ReplyTo"))
        address = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/08/addressing","Address"))
        address.text = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
        replyto.append(address)
        header.append(replyto)
        optimeout = etree.Element(etree.QName("http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd","OperationTimeout"))
        optimeout.text = "PT60S"
        header.append(optimeout)
        if selector!=None:
            header.append(selector)
        
        body = etree.Element("Body")
        enum = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/09/enumeration","Enumerate"))
        body.append(enum)

        msg.append(header)
        msg.append(body)
        doc = etree.ElementTree(msg)
        return etree.tostring(doc, pretty_print=True, xml_declaration=True, encoding="utf-8").decode()
    
    def Pull(self, obj, id, enumctx="0",selector=None):
        nsmap = self._nsmap
        nsmap["n"]="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
        msg = etree.Element("Envelope",nsmap=nsmap,xmlns="http://www.w3.org/2003/05/soap-envelope")

        header = etree.Element("Header")
        # add action header
        action = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/08/addressing","Action"))
        action.attrib["mustUnderstand"]="true"
        action.text = self._actionPull
        header.append(action)
        dest = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/08/addressing","To"))
        dest.text = "/wsman"
        header.append(dest)
        resuri = etree.Element(etree.QName("http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd","ResourceURI"))
        resuri.text = self._getFullUrl(obj)
        header.append(resuri)
        mesgid = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/08/addressing","MessageID"))
        mesgid.text = str(id)
        header.append(mesgid)
        replyto = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/08/addressing","ReplyTo"))
        address = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/08/addressing","Address"))
        address.text = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
        replyto.append(address)
        header.append(replyto)
        optimeout = etree.Element(etree.QName("http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd","OperationTimeout"))
        optimeout.text = "PT60S"
        header.append(optimeout)
        if selector!=None:
            header.append(selector)
        
        
        body = etree.Element("Body")
        pull = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/09/enumeration","Pull"))
        ec = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/09/enumeration","EnumerationContext"))
        ec.text = enumctx
        me = etree.Element(etree.QName("http://schemas.xmlsoap.org/ws/2004/09/enumeration","MaxElements"))
        me.text = "999"
        pull.append(ec)
        pull.append(me)
        body.append(pull)
        
        msg.append(header)
        msg.append(body)
        doc = etree.ElementTree(msg)
        return etree.tostring(doc, pretty_print=True, xml_declaration=True, encoding="utf-8").decode()

    @staticmethod
    def parseNumber(value):
        try:
            fl_val = float(re.sub('[^.\-\d]', '', value))
            int_val = int(value) 
            if str(int_val)  == value:
                return int_val
            else:
                return fl_val
        except ValueError:
            return value
    
    @staticmethod    
    def realobject(s):
        if s !=None and  s.strip()!="":
            if s.strip().lower()=="true":
                return True
            elif s.strip().lower()=="false":
                return False
            else:
                return WsmanMessage.parseNumber(s)
        else:
            if s == None:
                return None
            return ""

    @staticmethod
    def elementToMap(el):
        od = OrderedDict()
        tag = etree.QName(el.tag).localname
        if len(el.getchildren())>0:            
            for c in el:
                ctag = etree.QName(c.tag).localname
                if od.get(ctag)!=None:
                    if isinstance(od[ctag],list)==False:
                        t = od[ctag]
                        od[ctag] = [t]
                    
                    if c.text!=None:
                        t = c.text.strip()
                        if t!="":
                            od[ctag].append(WsmanMessage.realobject(c.text))
                        else:
                            od[ctag].append(WsmanMessage.elementToMap(c))
                    else:
                        if len(c.getchildren())>0:
                            od[ctag].append(WsmanMessage.elementToMap(c))
                        else:
                            od[ctag].append(None)
                else:                    
                    if c.text!=None:
                        t = c.text.strip()
                        if t!="":
                            od[ctag]=WsmanMessage.realobject(c.text)
                        else:
                            od[ctag]=WsmanMessage.elementToMap(c)
                    else:
                        if len(c.getchildren())>0:
                            od[ctag]=WsmanMessage.elementToMap(c)
                        else:
                            od[ctag]=None
        else:
            od[tag] = el.text
        return od

    @staticmethod
    def xmlToSimpleMap(xml):
        od = OrderedDict()
        doc = etree.fromstring(xml)
        if doc==None:
            return od
        tag = etree.QName(doc.tag).localname
        od[tag]=OrderedDict()
        for c in doc:
            ctag = etree.QName(c.tag).localname
            od[tag][ctag]= WsmanMessage.elementToMap(c)
        return od


class CustomSslContextHttpAdapter(HTTPAdapter):
        fingerprint = None
        def __init__(self, fingerprint=None, **kwargs):
            self.fingerprint = fingerprint

            super().__init__(**kwargs)

        """"Transport adapter" that allows us to use a custom ssl context object with the requests."""
        def init_poolmanager(self, connections, maxsize, block=False):
            ctx = create_urllib3_context()
            ctx.load_default_certs()
            ctx.options |= 0x4  # ssl.OP_LEGACY_SERVER_CONNECT
            if self.fingerprint!=None:            
                self.poolmanager = urllib3.PoolManager(ssl_context=ctx, assert_fingerprint=self.fingerprint)
            else :
                self.poolmanager = urllib3.PoolManager(ssl_context=ctx)

class WsmanClient:
    session = None
    message = None
    url = ""
    cert=None

    def getFingerprint(self):
        try:
            if self.cert==None:
                return None
            obj = pem.parse_file(self.cert)
            dc = ssl.PEM_cert_to_DER_cert(obj[0])
            sh = hashlib.sha1().update(dc).digest()
            fp = sh.hexdigest()
            return fp
        except:
            pass
        return None
    
    def __init__(self, host, username="admin",password="",tls=False, insecure=True, cert=None, endpoint="/wsman") -> None:
        self.session = requests.Session()
        self.session.auth = HTTPDigestAuth(username,password)
        if tls==False:
            self.url= "http://"+host+":16992"+endpoint
        else:
            self.url = "https://"+host+":16993"+endpoint
            self.cert = cert
            fingerprint = self.getFingerprint()
            adapter = CustomSslContextHttpAdapter(fingerprint=fingerprint)
            self.session.mount(self.url,adapter=adapter)
            self.session.verify= (not insecure)
            urllib3.disable_warnings()
            if insecure!=True:
                self.session.verify = cert

        self.message = WsmanMessage()        

    def Get(self, wsobj, selector=None):
        od = None
        msg = self.message.Get(wsobj,"uuid:"+str(uuid.uuid4()))
        resp = self.session.post(self.url,data=msg)
        doc = etree.fromstring(resp.content)
        xmlresp=etree.tostring(doc,pretty_print=True).decode()
        obj = WsmanMessage.xmlToSimpleMap(xmlresp)
        try:
            od = obj["Envelope"]["Body"]
        except KeyError:
            pass

        return od
    
    def EnumPull(self, wsobj, selector=None):
        items = OrderedDict()
        msg = self.message.Enum(wsobj,"uuid:"+str(uuid.uuid4()))
        resp = self.session.post(self.url,data=msg)
        doc = etree.fromstring(resp.content)
        xmlresp=etree.tostring(doc,pretty_print=True).decode()
        obj = WsmanMessage.xmlToSimpleMap(xmlresp)
        ctx = None
        try:
            ctx=obj["Envelope"]["Body"]["EnumerateResponse"]["EnumerationContext"]        
        except KeyError:
            pass

        items[wsobj]= []
        end_enum = False
        while end_enum == False:
            msg = self.message.Pull(wsobj,"uuid:"+str(uuid.uuid4()),ctx)
            resp = self.session.post(self.url,data=msg) 
            doc = etree.fromstring(resp.content)
            xmlresp=etree.tostring(doc,pretty_print=True).decode()
            obj = WsmanMessage.xmlToSimpleMap(xmlresp)
            #print(json.dumps(obj,indent=3))
            try:
                temp1 = obj["Envelope"]["Body"]["PullResponse"]["Items"]
                if temp1=="":
                    end_enum=True
                    break
                for k1,v1 in temp1.items():
                    if isinstance(v1,abc.Sequence):
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

        return items

    def BulkPull(self, obj_arr):
        items = OrderedDict()

        if obj_arr==None or isinstance(obj_arr,list)==False:
            return items
        
        for wsobj in obj_arr:
            
            if isinstance(wsobj, str)==False:
                continue
            
            if wsobj.endswith("[]"):
                obj = wsobj.strip("[]")
                temp = self.EnumPull(obj)
                try:
                    items[obj]= temp[obj]
                except KeyError:
                    print("Unable to pull "+obj)
                    pass
            else:
                temp = self.Get(wsobj)
                try:
                    items[wsobj]= temp[wsobj]
                except KeyError:
                    print("Unable to get "+obj)
                    pass
        
        return items
