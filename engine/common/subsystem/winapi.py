"""
name        : winapi.py
author      : hakbaby
function    : wrapper class
"""

from define import *

import x86
import x64
import wow64

class WindowsAPI:

	def __init__(self, ProcessName=None):

		self.sourcetype = maxsize > 2**32

		process = self.FindProcess(ProcessName)
		if process is not None:
			self.ProcessName = process.ImageName.Buffer
			self.ProcessId = process.UniqueProcessId
			self.ProcessHandle = windll.kernel32.OpenProcess( PROCESS_ALL_ACCESS, False, self.ProcessId )

		self.targettype = self.IsWow64Process(self.ProcessHandle)

		if self.sourcetype is True and self.targettype is True:
			self.subsystem = x64.SubsystemX64()

		if self.sourcetype is True and self.targettype is False:
			self.subsystem = wow64.SubsystemWOW64()

		if self.sourcetype is False and self.targettype is False:
			self.subsystem = x86.SubsystemX86()

		self.ProcessPath = self.subsystem.GetModuleFileNameEx(self.ProcessHandle, 0)

	def IsWow64Process(self, hProcess):

		try:
			Wow64Process = wintypes.BOOL(0)
			windll.kernel32.IsWow64Process(self.ProcessHandle, byref(Wow64Process))
			wow64 = False if bool(Wow64Process) else True
		except AttributeError:
			wow64 = False

		return wow64


	def FindProcess(self, TargetName):

		LengthReturn = c_ulong()
		BufferSystemInformation = create_string_buffer(0x1024)

		ntstatus = windll.ntdll.NtQuerySystemInformation(SystemProcessInformation, BufferSystemInformation, 0x1024, byref(LengthReturn))

		if ntstatus != STATUS_INFO_LENGTH_MISMATCH:
			BufferSystemInformation = create_string_buffer(LengthReturn.value)
			ntstatus = windll.ntdll.NtQuerySystemInformation(SystemProcessInformation, BufferSystemInformation, LengthReturn.value, None)

		process = cast(BufferSystemInformation, POINTER(PROCESS_INFORMATION_BLOCK)).contents

		while process.NextEntryOffset:

			if process.ImageName.Buffer is not None and process.ImageName.Buffer.find(TargetName) > -1:
				return process

			process = cast(addressof(process) + process.NextEntryOffset, POINTER(PROCESS_INFORMATION_BLOCK)).contents

		return None


	def EnumProcessThread(self):

		thread_list = []

		LengthReturn = c_ulong()
		BufferSystemInformation = create_string_buffer(0x1024)

		ntstatus = windll.ntdll.NtQuerySystemInformation(SystemProcessInformation, BufferSystemInformation, 0x1024, byref(LengthReturn))

		if ntstatus != STATUS_INFO_LENGTH_MISMATCH:
			BufferSystemInformation = create_string_buffer(LengthReturn.value)
			ntstatus = windll.ntdll.NtQuerySystemInformation(SystemProcessInformation, BufferSystemInformation, LengthReturn.value, None)

		process = cast(BufferSystemInformation, POINTER(self.subsystem.PROCESS_INFORMATION_BLOCK)).contents

		while process.NextEntryOffset:
			if process.UniqueProcessId == self.ProcessId:
				for i in range(0, process.NumberOfThreads):
					try:
						#print process.th[i].ClientID.UniqueThread
						thread_list.append(process.th[i].ClientID.UniqueThread)
					except Exception as e:
						#print e
						pass

			process = cast(addressof(process) + process.NextEntryOffset, POINTER(self.subsystem.PROCESS_INFORMATION_BLOCK)).contents

		return thread_list

	def EnumProcessModule(self):

		return self.subsystem.EnumModules(self.ProcessHandle)

	def GetModuleFileNameEx(self, hModule=0):

		return self.subsystem.GetModuleFileNameEx(self.ProcessHandle, hModule)

	def ReadProcessMemory(self, hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead):

		return self.subsystem.ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)

	def VirtualAllocEx(self, size):

		return self.subsystem.VirtualAllocEx(self.ProcessHandle, size)

	def VirtualQueryEx(self, lpAddress):

		return self.subsystem.VirtualQueryEx(self.ProcessHandle, lpAddress)

	def VirtualProtectEx(self, lpAddress, size=0x400, permission=PAGE_EXECUTE_READWRITE):

		return self.subsystem.VirtualProtectEx(self.ProcessHandle, lpAddress, size, permission)

	def WriteProcessMemory(self, lpBaseAddress, buffer, nSize, lpNumberOfBytesWritten):

		self.subsystem.WriteProcessMemory(self.ProcessHandle, lpBaseAddress, buffer, nSize, lpNumberOfBytesWritten)

	def Distorm3Decoder(self, address, data):

		return self.subsystem.Distorm3Decoder(address, data)

	def GetExportFunction(self, DLLBaseAddress, DLLFunctionName):

		import pefile

		DLLPE = pefile.PE(self.GetModuleFileNameEx(DLLBaseAddress))
		for exp in DLLPE.DIRECTORY_ENTRY_EXPORT.symbols:
			if exp.name.find(DLLFunctionName) > -1:
				return DLLBaseAddress + exp.address

	def GetThreadContext(self, thread_id=None, hThread=None):

		if hThread is None:
			hThread = windll.kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)

		return self.subsystem.GetThreadContext(hThread)

	def SetThreadContext(self, context, hThread = None, thread_id = 0):

		if hThread is None:
			hThread = windll.kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)

		self.subsystem.SetThreadContext(hThread, context)

	def DebugActiveProcess(self):

		return windll.kernel32.DebugActiveProcess(self.ProcessId)

	def DebugActiveProcessStop(self):

		return windll.kernel32.DebugActiveProcessStop(self.ProcessId)

	def WaitForDebugEvent(self, debug_event):

		return windll.kernel32.WaitForDebugEvent(byref(debug_event), INFINITE)

	def ContinueDebugEvent(self, debug_event, continue_status):

		return windll.kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status)

	def OpenThread(self, thread_id):

		return windll.kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)

	def Memcpy(self, lpBaseAddress, size):

		lpBuffer = create_string_buffer(size)
		bytesread = c_uint32(0)
		self.subsystem.ReadProcessMemory(self.ProcessHandle, lpBaseAddress, lpBuffer, size, bytesread)
		
		AllocAddress = self.VirtualAllocEx(size)

		data = lpBuffer.raw
		length = len(data)
		bytesread = c_uint32(0)
		lpBuffer = create_string_buffer(data[bytesread.value:])

		self.VirtualProtectEx(AllocAddress, size)
		self.subsystem.WriteProcessMemory(self.ProcessHandle, AllocAddress, lpBuffer, length, byref(bytesread))

		return AllocAddress

	def OpenProcess(self, pid):

		return windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

	def CloseHandle(self, handle):

		return windll.kernel32.CloseHandle(handle)

	def DLLWriteProcessMemory(self, address, data):

		return self.subsystem.DLLWriteProcessMemory(self.ProcessHandle, address, data)

	def GetProcAddress(self, ModuleName, lpProcName):

		"""
		FARPROC WINAPI GetProcAddress(
		  _In_ HMODULE hModule,
		  _In_ LPCSTR  lpProcName
		);
		"""

		return windll.kernel32.GetProcAddress( windll.kernel32.GetModuleHandleA(ModuleName), lpProcName )


	def CreateRemoteThread(self, lpStartAddress, lpParameter):

		return self.subsystem.CreateRemoteThread(self.ProcessHandle, lpStartAddress, lpParameter)
