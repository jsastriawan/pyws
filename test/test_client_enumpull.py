import json
import sys
sys.path.append("../")

import pyws
import os

if __name__ == '__main__':
    wsobj="CIM_SettingData"
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
    cl = pyws.WsmanClient(host=hostname,username=user,password=password)
    res = cl.EnumPull(wsobj=wsobj)
    print(json.dumps(res,indent=3))