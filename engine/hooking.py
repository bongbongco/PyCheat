"""
name        : hooking.py
author      : hakbaby
function    : other process's memory copy & paste and modulation
"""

from common.process import *
from common.logger import *

LARGE_INTEGER = c_longlong

class Hooking:

	def __init__(self, v, process):

		self.v = v
		self.process = process

	def Memcpy(self, lpBaseAddress, Size):

		CopyToBinary = self.process.read(lpBaseAddress, type='binary', maxlen=Size)

		if CopyToBinary:
		    AllocationAddress = self.process.winapi.VirtualAllocEx(Size)

		if AllocationAddress is not 0:
			self.process.write(AllocationAddress, CopyToBinary,  type = 'binary')

		return AllocationAddress


	def SetHook(self, TargetAddress, CopyAddress, Size):

		self.v.log(message = "Copy Address : %.12X" %(TargetAddress))
		ChangeAddress = self.process.winapi.Memcpy(TargetAddress, Size)
		self.v.log(message = "Alloc Address : %.12X" %(ChangeAddress))

		if self.process.winapi.targettype == True:

			jmpaddress = "%.16X" %(ChangeAddress)

			jmpBytes = []
			jmpBytes.append(chr(0xFF))
			jmpBytes.append(chr(0x25))
			jmpBytes.append(chr(0x00))
			jmpBytes.append(chr(0x00))
			jmpBytes.append(chr(0x00))
			jmpBytes.append(chr(0x00))


			for i in range(len(jmpaddress), 0, -2):
			    jmpBytes.append(chr(int(jmpaddress[i-2:i], 16)))
			jmpBytes.append(chr(0x90))
			binary = ''.join(jmpBytes)

			self.process.write(TargetAddress, lpBuffer,  type = 'bytes')

		else:

			jmpaddress = (ChangeAddress - TargetAddress -5) & 0xffffffff
			jmpaddress = "%08X" %(struct.unpack("<I", struct.pack(">I", jmpaddress))[0])

			jmpBytes = []
			jmpBytes.append(chr(0xE9))

			for i in range(0,len(jmpaddress), 2):
			    jmpBytes.append(chr(int(jmpaddress[i:i+2], 16)))
			jmpBytes.append(chr(0x90))
			binary = ''.join(jmpBytes)

			self.process.write(TargetAddress, binary,  type = 'bytes')