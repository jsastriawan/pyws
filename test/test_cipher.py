from urllib3.util.ssl_ import create_urllib3_context

ctx = create_urllib3_context()
ctx.load_default_certs()
ch = ctx.get_ciphers()
chnames=[]
for v in ch:
    chnames.append(v["name"])
print(":".join(chnames))
            