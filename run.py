import os
from PyCriCodecs.acb import ACB
from PyCriCodecs.awb import AWB

input_file= r"vo_adv_0000011"
acbObj = ACB(f"{input_file}.acb")

awbObj = AWB()
a = acbObj.extract()
pass