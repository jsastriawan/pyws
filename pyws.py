import copy
import json
import re
from requests.auth import HTTPDigestAuth
import uuid
from lxml import etree
import collections
from collections import OrderedDict,abc

import requests

class WsmanMessage:
    _envelope = None
    _actionGet = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"
    _actionDelete = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"
    _actionEnumerate = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
    _actionPull = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull"
    _ns_prefix = {
        "AMT": "http://intel.com/wbem/wscim/1/amt-schema/1/",
        "CIM": "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/",
        "IPS": "http://intel.com/wbem/wscim/1/ips-schema/1/",
        }

    def __init__(self, mode="AMT"):
        self._envelope = etree.Element("Envelope",nsmap={"xsd":"http://www.w3.org/2001/XMLSchema",
                                                         "a":"http://schemas.xmlsoap.org/ws/2004/08/addressing", 
                                                         "w":"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"},
                                                         xmlns="http://www.w3.org/2003/05/soap-envelope")        
    

    def _getFullUrl(self, obj):
        pfx = obj[:3]
        return self._ns_prefix[pfx]+obj
    
    def Get(self, obj, id, selector=None):
        msg = copy.deepcopy(self._envelope)
        
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
    
    def Enum(self, obj, id, selector=None):
        msg = copy.deepcopy(self._envelope)
        
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
        msg = copy.deepcopy(self._envelope)
        
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
        pull = etree.Element("Pull",xmlns="http://schemas.xmlsoap.org/ws/2004/09/enumeration")
        ec = etree.Element("EnumerationContext")
        ec.text = enumctx
        me = etree.Element("MaxElements")
        me.text = "999"
        pull.append(ec)
        pull.append(me)
        body.append(pull)
        
        msg.append(header)
        msg.append(body)
        doc = etree.ElementTree(msg)
        return etree.tostring(doc, pretty_print=True, xml_declaration=True, encoding="utf-8").decode()

    def parseNumber(self,value):
        try:
            fl_val = float(re.sub('[^.\-\d]', '', value))
            int_val = int(value) 
            if str(int_val)  == value:
                return int_val
            else:
                return fl_val
        except ValueError:
            return value
        
    def realobject(self, s):
        if s !=None and  s.strip()!="":
            if s.strip().lower()=="true":
                return True
            elif s.strip().lower()=="false":
                return False
            else:
                return self.parseNumber(s)
        else:
            return ""

    def elementToMap(self,el):
        od = OrderedDict()
        tag = etree.QName(el.tag).localname
        if len(el.getchildren())>0:            
            for c in el:
                ctag = etree.QName(c.tag).localname
                if od.get(ctag)!=None:
                    if isinstance(od[ctag],list):
                        od[ctag].append(self.elementToMap(c))
                    else:
                        t = od[ctag]
                        od[ctag] = [t]
                else:                    
                    if c.text!=None:
                        t = c.text.strip()
                        if t!="":
                            od[ctag]=self.realobject(c.text)
                        else:
                            od[ctag]=self.elementToMap(c)
                    else:
                        if len(c.getchildren())>0:
                            od[ctag]=self.elementToMap(c)
                        else:
                            od[ctag]=""
        else:
            od[tag] = el.text
        return od

    def xmlToSimpleMap(self,xml):
        od = OrderedDict()
        doc = etree.fromstring(xml)
        if doc==None:
            return od
        tag = etree.QName(doc.tag).localname
        od[tag]=OrderedDict()
        for c in doc:
            ctag = etree.QName(c.tag).localname
            od[tag][ctag]= self.elementToMap(c)
        return od

class WsmanClient:
    session = None
    message = None
    url = ""

    def __init__(self, host, username="admin",password="",tls=False, insecure=True, endpoint="/wsman") -> None:
        self.session = requests.Session()
        self.session.auth = HTTPDigestAuth(username,password)
        if tls==False:
            self.url= "http://"+host+":16992"+endpoint
        else:
            self.url = "https://"+host+":16993"+endpoint
        self.message = WsmanMessage()        

    def Get(self, wsobj, selector=None):
        od = None
        msg = self.message.Get(wsobj,"uuid:"+str(uuid.uuid4()))
        resp = self.session.post(self.url,data=msg)
        doc = etree.fromstring(resp.content)
        xmlresp=etree.tostring(doc,pretty_print=True).decode()
        obj = self.message.xmlToSimpleMap(xmlresp)
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
        obj = self.message.xmlToSimpleMap(xmlresp)
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
            obj = self.message.xmlToSimpleMap(xmlresp)
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