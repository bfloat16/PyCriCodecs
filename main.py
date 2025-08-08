from PyCriCodecs.acb import ACB
from PyCriCodecs.awb import AWB

input_file = r"doc\vo_adv_0000011"
acbObj = ACB(f"{input_file}.acb")

if len(acbObj._payload) != 1:
    raise ValueError()

if acbObj._payload[0]['AwbFile'][1] == b'':
    awbObj = AWB(f"{input_file}.awb")
else:
    awbObj = AWB(acbObj._payload[0]['AwbFile'][1])

a = acbObj.extract()
awbObj.extract(a, "./EXP")