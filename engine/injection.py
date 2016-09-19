"""
name        : injection.py
author      : hakbaby
function    : other process memory injected DLL
"""

from common.process import *
from common.logger import *

class Injection:

	def __init__(self, v, process):

		self.v = v
		self.process = process

	def DLLInjection(self, path):

		lpAddress = self.process.winapi.VirtualAllocEx(size=0x1024)
		self.process.winapi.DLLWriteProcessMemory(lpAddress, path)

		lpLoadLibraryA = self.process.winapi.GetProcAddress("kernel32.dll", "LoadLibraryA")
		lpThread = self.process.winapi.CreateRemoteThread(lpLoadLibraryA, lpAddress) 

