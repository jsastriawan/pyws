import sys
sys.path.append("../")

import pyws

if __name__=='__main__':
    w = pyws.Wsman()
    s = ""
    with open("../test_data/resp.xml") as f:
        s = f.read()
    od = w.xmlToSimpleMap(s)

    