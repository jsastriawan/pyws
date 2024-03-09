import json
import sys
sys.path.append("../")

import pyws

if __name__=='__main__':
    w = pyws.WsmanMessage()
    s = ""
    with open("../test_data/resp.xml") as f:
        s = f.read()
    od = w.xmlToSimpleMap(s)
    print(json.dumps(od,indent=3))
    