"""
name        : debugger.py
author      : hakbaby
function    : other process's debugging (hardware breakpoint)
"""

from common.process import *
from common.util import *

class Callback:

	def __init__(self, callback_type = None, description = '', callback = None):

		self.callback_type = callback_type
		self.description  = description
		self.callback = callback

class HardwareBreakpoint:

	def __init__(self, address=None, length=0, hw_type=0, description='', restore=True, callback=None):

		self.address = address
		self.length = length
		self.hw_type = hw_type
		self.description = description
		self.restore = restore
		self.callback = callback

class debugger:

	def __init__(self, v, process):

		self.process = process
		self.v = v

		self.m_pid = 0
		self.m_process = None
		self.m_peb = None
		self.m_thread = None

		self.m_debug_event = None
		self.m_context = None
		self.m_debugger_active = True
		self.m_callbacks = {}

		self.m_page_size = 0
		self.m_tebs = {} 

		self.first_breakpoint = True
		self.m_breakpoints = {}
		self.m_restore_breakpoint = None

		self.m_hardware_breakpoints = {}

		self.m_memory_breakpoints = {}

		self.m_page_guard = set()

		self.m_exception_address = None

		system_info = SYSTEM_INFO()
		windll.kernel32.GetSystemInfo(byref(system_info))

		self.m_page_size = system_info.dwPageSize

		self.v.log('System info page size: %d' % self.m_page_size)

	def Attach(self):

		self.m_pid = self.process.ProcessId
		self.m_process = self.process.ProcessHandle

		self.process.winapi.DebugActiveProcess()
		self.SetDebuggerActive(True)

		return self

	def Detach(self):

		self.BpDelAll()

		self.process.winapi.DebugActiveProcessStop()
		self.SetDebuggerActive(False)

		return self

	def SetDebuggerActive(self, True_or_False):

		self.v.log("SetDebuggerActive(%d)" % True_or_False)

		self.m_debugger_active = True_or_False

	def Run(self):

		self.DebugEventLoop()

	def DebugEventLoop(self):

		while self.m_debugger_active:
			
			if CALLBACK_DEBUG_EVENT in self.m_callbacks.keys():
				self.v.log('callback to CALLBACK_DEBUG_EVENT')

				self.m_callbacks[CALLBACK_DEBUG_EVENT].callback(self)

			self._DebugEventLoop()

		self.process.winapi.CloseHandle(self.m_process)

	def _DebugEventLoop(self):

		debug_status = DBG_CONTINUE
		debug_event = DEBUG_EVENT()

		if self.process.winapi.WaitForDebugEvent(debug_event):

			self.m_process = self.process.winapi.OpenProcess(debug_event.dwProcessId)
			self.m_context = self.GetThreadContext(thread_id=debug_event.dwThreadId)
			self.m_debug_event  = debug_event

			self.m_exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress

			if debug_event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT:
				debug_status = self.CreateProcessDebugEvent()

			elif debug_event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT:
				debug_status = self.CreateThreadDebugEvent()

			elif debug_event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
				debug_status = self.ExitProcessDebugEvent()
				self.Detach()

			elif debug_event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT:
				debug_status = self.ExitThreadDebugEvent()

			elif debug_event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT:
				debug_status = self.LoadDllDebugEvent()

			elif debug_event.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT:
				debug_status = self.UnLoadDllDebugEvent()

			elif debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
				exception_code = debug_event.u.Exception.ExceptionRecord.ExceptionCode

				if exception_code == EXCEPTION_BREAKPOINT:
					debug_status = self.ExceptionBreakpoint()
				elif exception_code == EXCEPTION_SINGLE_STEP:
					debug_status = self.ExceptionSingleStep()
				elif exception_code == EXCEPTION_GUARD_PAGE:
					debug_status = self.ExceptionGuardPage()

			self.process.winapi.ContinueDebugEvent(debug_event, debug_status)


	def CreateProcessDebugEvent(self):

		dbg_status = DBG_CONTINUE

		if CREATE_PROCESS_DEBUG_EVENT in self.m_callbacks.keys():
			self.v.log('callback to CreateProcessDebugEvent')

			self.m_callbacks[CREATE_PROCESS_DEBUG_EVENT].callback(self)

		return dbg_status

	def CreateThreadDebugEvent(self):

		dbg_status = DBG_CONTINUE
		
		if CREATE_THREAD_DEBUG_EVENT in self.m_callbacks.keys():
			self.v.log('callback to CreateThreadDebugEvent')

			self.m_callbacks[CREATE_THREAD_DEBUG_EVENT].callback(self)

		return dbg_status

	def ExitProcessDebugEvent(self):

		dbg_status = DBG_CONTINUE
		
		if EXIT_PROCESS_DEBUG_EVENT in self.m_callbacks.keys():
			self.v.log('callback to ExitProcessDebugEvent')

			self.m_callbacks[EXIT_PROCESS_DEBUG_EVENT].callback(self)

		return dbg_status

	def ExitThreadDebugEvent(self):

		dbg_status = DBG_CONTINUE
		
		if EXIT_THREAD_DEBUG_EVENT in self.m_callbacks.keys():
			self.v.log('callback to ExitThreadDebugEvent')

			self.m_callbacks[EXIT_THREAD_DEBUG_EVENT].callback(self)

		return dbg_status

	def LoadDllDebugEvent(self):

		dbg_status = DBG_CONTINUE		

		if LOAD_DLL_DEBUG_EVENT in self.m_callbacks.keys():
			self.v.log('callback to LoadDllDebugEvent')

			self.m_callbacks[LOAD_DLL_DEBUG_EVENT].callback(self)

		return dbg_status

	def UnLoadDllDebugEvent(self):

		dbg_status = DBG_CONTINUE		

		if UNLOAD_DLL_DEBUG_EVENT in self.m_callbacks.keys():
			self.v.log('callback to UnLoadDllDebugEvent')

			self.m_callbacks[UNLOAD_DLL_DEBUG_EVENT].callback(self)

		return dbg_status

	def ExceptionBreakpoint(self):

		dbg_status = DBG_CONTINUE

		if self.BpIsBelongToOurs(self.m_exception_address):

			self.WriteProcessMemory(self.m_exception_address, self.m_breakpoints[self.m_exception_address].original_byte)

			self.m_context.Eip -= 1
			self.SetRegister('EIP', self.m_exception_address)

			if self.m_breakpoints[self.m_exception_address].restore:
				self.m_restore_breakpoint = self.m_breakpoints[self.m_exception_address]
				self.SingleStep()

			dbg_status = DBG_CONTINUE

			if self.m_breakpoints[self.m_exception_address].callback:
				self.v.log('bp in 0x%08x callback ' % self.m_exception_address)

				dbg_status = self.m_breakpoints[self.m_exception_address].callback(self)
			else:
				dbg_status = DBG_CONTINUE
			
			if self.m_exception_address in self.m_breakpoints:
				del self.m_breakpoints[self.m_exception_address]

		if EXCEPTION_BREAKPOINT in self.m_callbacks.keys():
			self.CrumbsLog('callback to ExceptionBreakpoint')

			self.m_callbacks[EXCEPTION_BREAKPOINT].callback(self)

		return dbg_status

	def ExceptionSingleStep(self):

		self.v.log('ExceptionSingleStep in')

		dbg_status = DBG_CONTINUE

		if self.m_restore_breakpoint != None:
			if type(self.m_restore_breakpoint) is Breakpoint:
				self.v.log('restore breakpoint in 0x%08x' % self.m_restore_breakpoint.address)

				self.BpSet(self.m_restore_breakpoint.address
						   , self.m_restore_breakpoint.description
						   , self.m_restore_breakpoint.restore
						   , self.m_restore_breakpoint.callback)
			elif type(self.m_restore_breakpoint) is HardwareBreakpoint:
				self.v.log('restore breakpoint in 0x%08x' % self.m_restore_breakpoint.address)

				self.BpHwSet(self.m_restore_breakpoint.address
							 , self.m_restore_breakpoint.length+1
							 , self.m_restore_breakpoint.hw_type
							 , self.m_restore_breakpoint.description
							 , self.m_restore_breakpoint.restore
							 , self.m_restore_breakpoint.callback)

			elif type(self.m_restore_breakpoint) is not None:
				self.v.log('restore VirtualProtect in 0x%08x' % self.m_restore_breakpoint)

				mbi = self.process.winapi.VirtualQueryEx(self.m_restore_breakpoint)
				self.process.winapi.VirtualProtectEx(mbi.BaseAddress, 1, mbi.Protect | PAGE_GUARD)

			self.m_restore_breakpoint = None
			dbg_status = DBG_CONTINUE

		if not self.m_context.Dr6 & (1 << 14):

			hit_hardware_breakpoint = None
			if self.m_context.Dr6 & 0x1 and 0 in self.m_hardware_breakpoints.keys():
				hit_hardware_breakpoint = 0
			elif self.m_context.Dr6 & 0x2 and 1 in self.m_hardware_breakpoints.keys():
				hit_hardware_breakpoint = 1
			elif self.m_context.Dr6 & 0x4 and 2 in self.m_hardware_breakpoints.keys():
				hit_hardware_breakpoint = 2
			elif self.m_context.Dr6 & 0x8 and 3 in self.m_hardware_breakpoints.keys():
				shit_hardware_breakpoint = 3

			if hit_hardware_breakpoint in (0, 1, 2, 3):

				if self.m_hardware_breakpoints[hit_hardware_breakpoint].hw_type == HW_EXECUTE:

					for thread_id in self.process.winapi.EnumProcessThread():
						context = self.GetThreadContext(thread_id=thread_id)

						context.Dr7 &= ~(1 << (hit_hardware_breakpoint * 2))

						self.SetThreadContext(context, thread_id = thread_id)

					if self.m_hardware_breakpoints[hit_hardware_breakpoint].restore:
						self.SingleStep()
						self.m_restore_breakpoint  = self.m_hardware_breakpoints[hit_hardware_breakpoint]

					dbg_status = DBG_CONTINUE

					if self.m_hardware_breakpoints[hit_hardware_breakpoint].callback:
						self.v.log('bphw in 0x%08x callback ' % self.m_exception_address)

						dbg_status = self.m_hardware_breakpoints[hit_hardware_breakpoint].callback(self)
					else:
						dbg_status = DBG_CONTINUE

					if hit_hardware_breakpoint in self.m_hardware_breakpoints:
						del self.m_hardware_breakpoints[hit_hardware_breakpoint]
				else:

					if self.m_hardware_breakpoints[hit_hardware_breakpoint].callback:
						self.v.log('bphw in 0x%08x callback ' % self.m_exception_address)

						dbg_status = self.m_hardware_breakpoints[hit_hardware_breakpoint].callback(self)
					else:
						dbg_status = DBG_CONTINUE

		if EXCEPTION_SINGLE_STEP in self.m_callbacks.keys():
			self.v.log('callback to ExceptionSingleStep')

			dbg_status = self.m_callbacks[EXCEPTION_SINGLE_STEP].callback(self)

		self.v.log('ExceptionSingleStep out')
		return dbg_status

	def ExceptionGuardPage(self):

		dbg_status = DBG_CONTINUE
		
		write_violation   = self.m_debug_event.u.Exception.ExceptionRecord.ExceptionInformation[0]
		violation_address = self.m_debug_event.u.Exception.ExceptionRecord.ExceptionInformation[1]

		mbi = self.process.winapi.VirtualQueryEx(violation_address)

		if mbi.BaseAddress not in self.m_page_guard:
			self.v.log('ExceptionGuardPage DBG_EXCEPTION_NOT_HANDLED out')
			return DBG_EXCEPTION_NOT_HANDLED

		mem_breakpoint_hit = self.BpIsBelongToOursMem(violation_address)

		if mem_breakpoint_hit: #and write_violation == self.m_memory_breakpoints[mem_breakpoint_hit]:
			dbg_status = self.m_memory_breakpoints[mem_breakpoint_hit].callback(self)
			if mem_breakpoint_hit in self.m_memory_breakpoints.keys() and self.m_memory_breakpoints[mem_breakpoint_hit].restore:

				self.SingleStep()
				self.m_restore_breakpoint = violation_address
		else:
			self.SingleStep()
			self.m_restore_breakpoint = violation_address
			dbg_status = DBG_CONTINUE
		
		if EXCEPTION_GUARD_PAGE in self.m_callbacks.keys():
			self.CrumbsLog('callback to ExceptionGuardPage')

			dbg_status = self.m_callbacks[EXCEPTION_GUARD_PAGE].callback(self)

		#if mem_breakpoint_hit in self.m_memory_breakpoints.keys():
		#	del self.m_memory_breakpoints[mem_breakpoint_hit]

		return dbg_status
		
	def BpSet(self, address, description = '', restore = True, callback = None):

		if type(address) is list:
			for addr in address:
				BpSet(addr, description, restore, handler)
			return self
			
		self.v.log('BpSet: 0x%08x' % address)

		if address not in self.m_breakpoints:

			original_byte = self.ReadProcessMemory(address, 1)

			self.process.winapi.WriteProcessMemory(address, b'\xCC')
			self.m_breakpoints[address] = Breakpoint(address
													, original_byte
													, description
													, restore
													, callback)

		return self

	def BpDel(self, address):

		if type(address) is list:
			for addr in address:
				BpDel(addr)
			return self

		self.v.log('BpDel: 0x%08x' % address)

		if address in self.m_breakpoints:
			self.process.winapi.WriteProcessMemory(address, self.m_breakpoints[address].original_byte)

			del self.m_breakpoints[address]

		self.m_restore_breakpoint = None

		return self

	def BpHwSet(self, address, length, hw_type = 0, description = '', restore = True, callback = None):

		self.v.log('BpHwSet in')

		if type(address) is list:
			for addr in address:
				BpHwSet(addr, length, hw_type, description, restore, callback)

		self.v.log('BpHwSet: 0x%08x' % address)

		if length not in (1, 2, 4):
			print 'BpHwSet length(%d) Error ' % length

		length -= 1

		if hw_type not in (HW_EXECUTE, HW_WRITE, HW_ACCESS):
			print 'BpHwSet hw_type(%d) Error ' % hw_type

		if 0 not in self.m_hardware_breakpoints.keys():
			free_dr_reg = 0
		elif 1 not in self.m_hardware_breakpoints.keys():
			free_dr_reg = 1
		elif 2 not in self.m_hardware_breakpoints.keys():
			free_dr_reg = 2
		elif 3 not in self.m_hardware_breakpoints.keys():
			free_dr_reg = 3
		else:
			print ' No free dr register'

		self.m_hardware_breakpoints[free_dr_reg] = HardwareBreakpoint(address
																	  , length
																	  , hw_type
																	  , description
																	  , restore
																	  , callback)

		for thread_id in self.process.winapi.EnumProcessThread():
			context = self.GetThreadContext(thread_id = thread_id) 

			if free_dr_reg == 0:
				context.Dr0 = address
			elif free_dr_reg == 1:
				context.Dr1 = address
			elif free_dr_reg == 2:
				context.Dr2 = address
			elif free_dr_reg == 3:
				context.Dr3 = address

			context.Dr7 |= 1 << (free_dr_reg * 2)

			context.Dr7 |= hw_type << (free_dr_reg * 4 + 16)
			context.Dr7 |= length << (free_dr_reg * 4 + 18)

			self.SetThreadContext(context, thread_id = thread_id)


	def BpHwDel(self, address):

		print hex(self.m_hardware_breakpoints[0].address)

		if type(address) is list:
			for addr in address:
				BpHwDel(addr)
			return self

		self.v.log('BpHwDel: 0x%08x' % address)

		if 0 in self.m_hardware_breakpoints.keys() and address == self.m_hardware_breakpoints[0].address:

			del_bphw_hit = 0
		elif 1 in self.m_hardware_breakpoints.keys() and address == self.m_hardware_breakpoints[1].address:

			del_bphw_hit = 1
		elif 2 in self.m_hardware_breakpoints.keys() and address == self.m_hardware_breakpoints[2].address:

			del_bphw_hit = 2
		elif 3 in self.m_hardware_breakpoints.keys() and address == self.m_hardware_breakpoints[3].address:

			del_bphw_hit = 3
		else:
			self.v.log('BpHwDel out')
			return self

		print "what the"
		print del_bphw_hit

		for thread_id in self.process.winapi.EnumProcessThread():
			context = self.GetThreadContext(thread_id=thread_id)

			context.Dr7 &= ~(1 << (del_bphw_hit * 2)) 

			self.SetThreadContext(context, thread_id = thread_id)

			del self.m_hardware_breakpoints[del_bphw_hit]

		self.m_restore_breakpoint = None

		return self

	def BpMemSet(self, address, size, mem_type = MEM_PRIVATE, description = '', restore = True, callback = None):

		if self.BpIsBelongToOursMem(address):
			self.v.log('BpMemSet alread yexists')
			self.v.log('BpMemSet out', False)
			return self


		mbi = self.process.winapi.VirtualQueryEx(address)

		mem_base = mbi.BaseAddress
		last_address = address + size

		while mem_base <= last_address:
			self.v.log('BpMemSet: 0x%08x' % mem_base)

			self.process.winapi.VirtualProtectEx(mem_base, 1, mbi.Protect | PAGE_GUARD)
			self.m_page_guard.add(mem_base)

			mem_base += self.m_page_size

		self.m_memory_breakpoints[address] = MemoryBreakpoint(address
															  , size
															  , mem_type
															  , restore
															  , description
															  , callback)

		return self

	def BpMemDel(self, address):

		if address in self.m_memory_breakpoints.keys():
			mbi = self.VirtualQuery(address)
			mem_base = mbi.BaseAddress
			last_address = address + self.m_memory_breakpoints[address].size

			while mem_base <= last_address: 
				self.v.log('BpMemDel: 0x%08x' % mem_base)

				self.process.winapi.VirtualProtectEx(mem_base, 1, mbi.Protect & ~PAGE_GUARD)
				self.m_page_guard.remove(mem_base)

				mem_base += self.m_page_size

			del self.m_memory_breakpoints[address]

		return self

	def SingleStep(self):

		context = self.GetThreadContext(thread_handle=self.m_thread)
		context.EFlags |= 0x100

		self.SetThreadContext(context)

	"""

	def SingleStepOver(self):

		code, opcode, length = self.Diasm(self.m_exception_address)

		if re.match('call', code.decode()):
			self.BpSet(self.m_exception_address + length, restore = False)
		else:
			self.SingleStep()

		self.CrumbsLog('SingleStepOver out', False)

	"""

	def BpIsBelongToOurs(self, check_address):

		if check_address in self.m_breakpoints.keys():
			self.v.log('BpBelongToOurs out')
			return True
		else:
			self.v.log('BpBelongToOurs out')
			return False

	def BpIsBelongToOursMem(self, check_address):

		for address in self.m_memory_breakpoints.keys():
			size = self.m_memory_breakpoints[address].size
			if address <= check_address <= address + size:
				self.v.log('BpIsBelongToOursMem out')
				return address
			else:
				self.v.log('BpIsBelongToOursMem out')
				return False

	def DbgShowAllReg(self):

		for thread_id in self.process.winapi.EnumProcessThread():

			context = self.GetThreadContext(thread_id=thread_id)

			context_data = {}
			context_data['EIP'] = context.Eip
			context_data['DR0'] = context.Dr0
			context_data['DR1'] = context.Dr1
			context_data['DR2'] = context.Dr2
			context_data['DR3'] = context.Dr3
			context_data['DR7'] = context.Dr7

			self.v.log("\tEIP(%.08X) DR0(%.08X) DR1(%.08X) DR2(%.08X) DR3(%.08X) DR7(%.08X)" %(context.Eip, context.Dr0, context.Dr1, context.Dr2, context.Dr3, context.Dr7))
			break

		return context_data

	def BpDelAll(self):

		self.v.log('BpDelAll!!!')
		try:
			for bpAddr in self.m_breakpoints.keys():
				self.BpDel(bpAddr)
		except:
			pass

		return self

	def DbgShowContext(self, context = None):

		if not context:
			context = self.m_context

		context_data = {}
		context_data['EIP'] = context.Eip
		context_data['EAX'] = context.Eax
		context_data['ECX'] = context.Ecx
		context_data['EDX'] = context.Edx
		context_data['EBX'] = context.Ebx
		context_data['ESI'] = context.Esi
		context_data['EDI'] = context.Edi
		context_data['EBP'] = context.Ebp
		context_data['ESP'] = context.Esp

		self.v.log("\tESI(%.08X) EDI(%.08X) EBP(%.08X) ESP(%.08X) EAX(%.08X) ECX(%.08X) EDX(%.08X) EBX(%.08X)" %(context.Esi, context.Edi, context.Ebp, context.Esp, context.Eax, context.Ecx, context.Edx, context.Ebx))

		return context_data

	def SetRegister(self, register, value):

		self.v.log('set %s: %08x' % (register, value))

		register = register.upper()
		if register not in ('EAX', 'ECX', 'EDX', 'EBX', 'ESI', 'EDI', 'ESP', 'EBP', 'EIP'):
			raise ShowException('SetRegister(%s, 0x%08x)' % (register, value))

		context = self.GetThreadContext(thread_handle=self.m_thread)

		if register == 'EAX': context.Eax = value
		elif register == 'ECX': context.Ecx = value
		elif register == 'EDX': context.Edx = value
		elif register == 'EBX': context.Ebx = value
		elif register == 'ESI': context.Esi = value
		elif register == 'EDI': context.Edi = value
		elif register == 'EBP': context.Ebp = value
		elif register == 'ESP': context.Esp = value
		elif register == 'EIP': context.Eip = value

		self.SetThreadContext(context)

		return self

	def SetCallBack(self, callback_type, description = '', callback = None):

		self.m_callbacks[callback_type] = Callback(callback_type
												   , description
												   , callback)

	def GetThreadContext(self, thread_handle = None, thread_id = None):

		if not thread_handle and not thread_id:
			h_thread = self.m_thread

		elif not thread_handle:
			h_thread = self.process.winapi.OpenThread(thread_id)

		elif not thread_id:
			h_thread = thread_handle

		context = self.process.winapi.GetThreadContext(hThread=h_thread)

		return context

	def SetThreadContext(self, context, thread_handle = None, thread_id = None):

		if not thread_handle and not thread_id:
			h_thread = self.m_thread

		elif not thread_handle:
			h_thread = self.process.winapi.OpenThread(thread_id)

		elif not thread_id:
			h_thread = thread_handle

		self.process.winapi.SetThreadContext(context, hThread=h_thread)		


