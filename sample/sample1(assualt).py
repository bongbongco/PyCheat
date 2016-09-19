from engine.common.process import *
from engine.common.logger import *
from engine.pattern import *

p = Process(ProcessName="ac_client")
v = logger()

mw = Pattern(v, p)

player_init = "C7 40 04 64 00 00 00 89 48 08 88 48 18 BA 01 00 00 00 89 50 14 89 48 6C"
mw_result =[x for x in mw.mem_search(player_init, ftype="byte", end_offset=0x00600000, start_offset=0x00400000)]
v.log(message = "Find Player Structure : %s" %mw_result[0])

dump = p.read_bytes(int(mw_result[0]), 0x150)
result = p.winapi.Distorm3Decoder(int(mw_result[0]), dump)
for (offset, size, instruction, hexdump) in result:
    #v.log(message="\t%s: %-20s %s" % (p.get_symbolic_name(offset), hexdump, instruction))

    if instruction == "MOV [EAX+0x64], ECX":
        v.log(message="\tGrenade Count : 0x%.12X" %(offset))
        p.write_bytes(offset, "\xC7\x40\x64\x00\x01\x00\x00\x90\x90\x90\x90\x90")


gun_pattern = "51 8B CE FF D2 8B 46 0C 0F BF 88 0A 01 00 00 8B 56 18 89 0A 8B 76 14 FF 0E"
mw_result =[x for x in mw.mem_search(gun_pattern, ftype="byte", end_offset=0x00600000, start_offset=0x00400000)]
v.log(message = "Find Rifle Decrease Code Pattern : %s" %mw_result[0])

dump = p.read_bytes(int(mw_result[0]), 0x1E)
result = p.winapi.Distorm3Decoder(int(mw_result[0]), dump)
for (offset, size, instruction, hexdump) in result:
    v.log(message="\t%s: %-20s %s" % (p.get_symbolic_name(offset), hexdump, instruction))

    if instruction == "DEC DWORD [ESI]":
        v.log(message="\tDEC DWORD [ESI] -> NOP (0x%.12X)" %(offset))
        p.write_bytes(offset, "\x90\x90")

bomb_pattern = "51 89 46 28 89 44 24 0C E8 ?? ?? ?? ?? 8B 56 08 8B 1D AC 9E 50 00 52 E8 ?? ?? ?? ?? 8B 46 14 FF 08"
mw_result =[x for x in mw.mem_search(bomb_pattern, ftype="byte", end_offset=0x00600000, start_offset=0x00400000)]
v.log(message = "Find Bomb Decrease Code Pattern : %s" %mw_result[0])

dump = p.read_bytes(int(mw_result[0]), 0x50)
result = p.winapi.Distorm3Decoder(int(mw_result[0]), dump)
for (offset, size, instruction, hexdump) in result:
    v.log(message="\t%s: %-20s %s" % (p.get_symbolic_name(offset), hexdump, instruction))

    if instruction == "DEC DWORD [EAX]":
        v.log(message="\tDEC DWORD [EAX] -> NOP (0x%.12X)" %(offset))
        p.write_bytes(offset, "\x90\x90")


