import hcadecrypt

with open(r"doc\vo_adv_1001011_000.hca","rb") as f:
    data = f.read()

mainkey = 0x000000000030D9E8
subkey  = 0x5F3F

out = hcadecrypt.decrypt(data, mainkey, subkey)

with open("1.hca","wb") as f:
    f.write(out)

print("Success")