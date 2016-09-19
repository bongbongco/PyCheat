from engine.common.process import *
from engine.common.logger import *
from engine.debugger import *

import time

p = Process(ProcessName="Pika")
v = logger()

def handler(obj):

     reg = obj.DbgShowAllReg()
     context = obj.DbgShowContext()

     dump = p.read_bytes(context['EIP'], 0x20)
     result = p.winapi.Distorm3Decoder(context['EIP'], dump)
     for (offset, size, instruction, hexdump) in result:
          v.log(message="\t%s: %-20s %s" % (p.get_symbolic_name(offset), hexdump, instruction))

     target = context['ESI'] + 0x3C
     v.log( message = "\tData Address Before : %.08X %.08X" %(target, p.read(target, maxlen=0x4)) )

     time.sleep(5.0)

     p.write_bytes(target, "\x0F")
     v.log( message = "\tData Address After  : %.08X %.08X" %(target, p.read(target, maxlen=0x4)) )

     return DBG_CONTINUE

hd = debugger(v, p)
hd.Attach()

hd.BpHwSet(0x00403C4A, 1, HW_EXECUTE, restore = True, callback = handler)
hd.Run()
