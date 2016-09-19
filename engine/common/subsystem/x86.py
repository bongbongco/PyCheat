"""
name        : x86.py
author      : hakbaby
function    : subsystem x86
"""

from define import *

class VM_COUNTERS (Structure):

    _fields_ = [
        ('PeakVirtualSize',              POINTER(c_ulong)),
        ('VirtualSize',                  POINTER(c_ulong)),
        ('PageFaultCount',               POINTER(c_ulong)),
        ('PeakWorkingSetSize',           POINTER(c_ulong)),
        ('WorkingSetSize',               POINTER(c_ulong)),
        ('QuotaPeakPagedPoolUsage',      POINTER(c_ulong)),
        ('QuotaPagedPoolUsage',          POINTER(c_ulong)),
        ('QuotaPeakNonPagedPoolUsage',   POINTER(c_ulong)),
        ('QuotaNonPagedPoolUsage',       POINTER(c_ulong)),
        ('PageFileUsage',                POINTER(c_ulong)),
        ('PeakPageFileUsage',            POINTER(c_ulong))
   ]

class PROCESS_INFORMATION_BLOCK(Structure):

    _fields_ = [
        ('NextEntryOffset',              c_ulong),
        ('NumberOfThreads',              c_ulong),
        ('Reserved1',                    c_ARRAY(LARGE_INTEGER, 3)),
        ('CreateTime',                   LARGE_INTEGER),
        ('UserTime',                     LARGE_INTEGER),
        ('KernelTime',                   LARGE_INTEGER),
        ('ImageName',                    UNICODE_STRING),
        ('BasePriority',                 c_long),
        ('UniqueProcessId',              wintypes.HANDLE),
        ('InheritedFromUniqueProcessId', wintypes.HANDLE),
        ('HandleCount',                  c_ulong),
        ('Reserved2',                    c_byte * 4),
        ('VirtualMemoryCounters',        VM_COUNTERS),
        ('PeakPagefileUsage',            c_ulong),
        ('PrivatePageCount',             c_ulong),
        ('IoCounters',                   IO_COUNTERS),
        ('th',                           c_ARRAY(SYSTEM_THREAD_INFORMATION, 10))
    ]

class LDR_DATA_TABLE_ENTRY (Structure):

    _fields_ = [
        ("InLoadOrderLinks", 			LIST_ENTRY),
        ("InMemoryOrderLinks", 			LIST_ENTRY),
        ("InInitializationOrderLinks", 	LIST_ENTRY),
        ("DllBase", 					c_void_p),
        ("EntryPoint",	 				c_void_p),
        ("SizeOfImage", 				c_ulong),
        ("FullDllName", 				UNICODE_STRING),
        ("BaseDllName", 				UNICODE_STRING),
    ]

"""
dt _PEB_LDR_DATA
ntdll!_PEB_LDR_DATA
+000 ulong 		Length
+004 boolean 	Initialized
+008 pvoid 		SsHandle
+00c LIST_ENTRY InLoadOrderModuleList
+014 LIST_ENTRY InMemoryOrderModuleList
+01C LIST_ENTRY InInitializationOrderModuleList
"""
class PEB_LDR_DATA(Structure):

    _fields_ = [
        ("Length",                          		c_ulong),
        ("Initialized",                     		c_ubyte),
        ("SsHandle",                        		c_void_p),
        ("InLoadOrderModuleList",           		LIST_ENTRY),
        ("InMemoryOrderModuleList",         		LIST_ENTRY),
        ("InInitializationOrderModuleList", 		LIST_ENTRY)
    ]


"""
struct _PEB (sizeof=488)
+000 byte InheritedAddressSpace
+001 byte ReadImageFileExecOptions
+002 byte BeingDebugged
+003 byte SpareBool
+004 void *Mutant
+008 void *ImageBaseAddress
+00c struct _PEB_LDR_DATA *Ldr
"""
class PEB32(Structure):

    _fields_ = [
        ("InheritedAddressSpace",     	c_byte),
        ("ReadImageFileExecOptions",  	c_byte),
        ("BeingDebugged",  				c_byte),
        ("SpareBool",             		c_byte),
        ("Mutant",             			c_void_p),
        ("ImageBaseAddress",            c_void_p), 
        ("Ldr",                    		c_void_p)
    ]

class PROCESS_BASIC_INFORMATION( Structure ):

    _fields_ = [
        ('Reserved1',      				c_void_p),
        ('PebBaseAddress',  			c_void_p),
        ('Reserved2',    				c_void_p*2),
        ('UniqueProcessId',    			c_void_p),# ULONG_PTR
        ("Reserved3", 					c_void_p)
    ]

class MEMORY_BASIC_INFORMATION32(Structure):

    _fields_ = [
        ("BaseAddress",         c_ulong),
        ("AllocationBase",      c_ulong),
        ("AllocationProtect",   c_ulong),
        ("RegionSize",          c_ulong),
        ("State",               c_ulong),
        ("Protect",             c_ulong),
        ("Type",                c_ulong)
    ]


#I386 Debugger
ARCH_I386                   = "i386"
EXCEPTION_READ_FAULT        = 0     # exception caused by a read
EXCEPTION_WRITE_FAULT       = 1     # exception caused by a write
EXCEPTION_EXECUTE_FAULT     = 8     # exception caused by an instruction fetch
CONTEXT_i386                = 0x00010000    # this assumes that i386 and
CONTEXT_i486                = 0x00010000    # i486 have identical context records
CONTEXT_CONTROL             = (CONTEXT_i386 | 0x00000001L) # SS:SP, CS:IP, FLAGS, BP
CONTEXT_INTEGER             = (CONTEXT_i386 | 0x00000002L) # AX, BX, CX, DX, SI, DI
CONTEXT_SEGMENTS            = (CONTEXT_i386 | 0x00000004L) # DS, ES, FS, GS
CONTEXT_FLOATING_POINT      = (CONTEXT_i386 | 0x00000008L) # 387 state
CONTEXT_DEBUG_REGISTERS     = (CONTEXT_i386 | 0x00000010L) # DB 0-3,6,7
CONTEXT_EXTENDED_REGISTERS  = (CONTEXT_i386 | 0x00000020L) # cpu specific extensions
CONTEXT_FULL                = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS)
CONTEXT_ALL                 = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS)
SIZE_OF_80387_REGISTERS     = 80
MAXIMUM_SUPPORTED_EXTENSION = 512

class FLOATING_SAVE_AREA(Structure):

    _pack_ = 1
    _fields_ = [
        ('ControlWord',     c_uint32),
        ('StatusWord',      c_uint32),
        ('TagWord',         c_uint32),
        ('ErrorOffset',     c_uint32),
        ('ErrorSelector',   c_uint32),
        ('DataOffset',      c_uint32),
        ('DataSelector',    c_uint32),
        ('RegisterArea',    c_ubyte * SIZE_OF_80387_REGISTERS),
        ('Cr0NpxState',     c_uint32),
    ]

    _integer_members = ('ControlWord', 'StatusWord', 'TagWord', 'ErrorOffset', 'ErrorSelector', 'DataOffset', 'DataSelector', 'Cr0NpxState')

    @classmethod
    def from_dict(cls, fsa):
        'Instance a new structure from a Python dictionary.'
        fsa = dict(fsa)
        s = cls()
        for key in cls._integer_members:
            setattr(s, key, fsa.get(key))
        ra = fsa.get('RegisterArea', None)
        if ra is not None:
            for index in xrange(0, SIZE_OF_80387_REGISTERS):
                s.RegisterArea[index] = ra[index]
        return s

    def to_dict(self):
        'Convert a structure into a Python dictionary.'
        fsa = dict()
        for key in self._integer_members:
            fsa[key] = getattr(self, key)
        ra = [ self.RegisterArea[index] for index in xrange(0, SIZE_OF_80387_REGISTERS) ]
        ra = tuple(ra)
        fsa['RegisterArea'] = ra
        return fsa

PFLOATING_SAVE_AREA         = POINTER(FLOATING_SAVE_AREA)
LPFLOATING_SAVE_AREA        = PFLOATING_SAVE_AREA

class CONTEXT(Structure):

    arch = ARCH_I386

    _pack_ = 1
    _fields_ = [

        ('ContextFlags',        c_uint32),

        ('Dr0',                 c_uint32),
        ('Dr1',                 c_uint32),
        ('Dr2',                 c_uint32),
        ('Dr3',                 c_uint32),
        ('Dr6',                 c_uint32),
        ('Dr7',                 c_uint32),

        ('FloatSave',           FLOATING_SAVE_AREA),

        ('SegGs',               c_uint32),
        ('SegFs',               c_uint32),
        ('SegEs',               c_uint32),
        ('SegDs',               c_uint32),

        ('Edi',                 c_uint32),
        ('Esi',                 c_uint32),
        ('Ebx',                 c_uint32),
        ('Edx',                 c_uint32),
        ('Ecx',                 c_uint32),
        ('Eax',                 c_uint32),

        ('Ebp',                 c_uint32),
        ('Eip',                 c_uint32),
        ('SegCs',               c_uint32),         # MUST BE SANITIZED
        ('EFlags',              c_uint32),         # MUST BE SANITIZED
        ('Esp',                 c_uint32),
        ('SegSs',               c_uint32),

        ('ExtendedRegisters',   c_ubyte * MAXIMUM_SUPPORTED_EXTENSION),
    ]

    _ctx_debug   = ('Dr0',  'Dr1',  'Dr2',  'Dr3',   'Dr6', 'Dr7')
    _ctx_segs    = ('SegGs','SegFs','SegEs','SegDs', )
    _ctx_int     = ('Edi',  'Esi',  'Ebx',  'Edx',   'Ecx', 'Eax')
    _ctx_ctrl    = ('Ebp',  'Eip',  'SegCs','EFlags','Esp', 'SegSs')

    @classmethod
    def from_dict(cls, ctx):
        'Instance a new structure from a Python dictionary.'
        ctx = Context(ctx)
        s = cls()
        ContextFlags = ctx['ContextFlags']
        setattr(s, 'ContextFlags', ContextFlags)
        if (ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS:
            for key in s._ctx_debug:
                setattr(s, key, ctx[key])
        if (ContextFlags & CONTEXT_FLOATING_POINT) == CONTEXT_FLOATING_POINT:
            fsa = ctx['FloatSave']
            s.FloatSave = FLOATING_SAVE_AREA.from_dict(fsa)
        if (ContextFlags & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS:
            for key in s._ctx_segs:
                setattr(s, key, ctx[key])
        if (ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER:
            for key in s._ctx_int:
                setattr(s, key, ctx[key])
        if (ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL:
            for key in s._ctx_ctrl:
                setattr(s, key, ctx[key])
        if (ContextFlags & CONTEXT_EXTENDED_REGISTERS) == CONTEXT_EXTENDED_REGISTERS:
            er = ctx['ExtendedRegisters']
            for index in xrange(0, MAXIMUM_SUPPORTED_EXTENSION):
                s.ExtendedRegisters[index] = er[index]
        return s

    def to_dict(self):
        'Convert a structure into a Python native type.'
        ctx = Context()
        ContextFlags = self.ContextFlags
        ctx['ContextFlags'] = ContextFlags
        if (ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS:
            for key in self._ctx_debug:
                ctx[key] = getattr(self, key)
        if (ContextFlags & CONTEXT_FLOATING_POINT) == CONTEXT_FLOATING_POINT:
            ctx['FloatSave'] = self.FloatSave.to_dict()
        if (ContextFlags & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS:
            for key in self._ctx_segs:
                ctx[key] = getattr(self, key)
        if (ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER:
            for key in self._ctx_int:
                ctx[key] = getattr(self, key)
        if (ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL:
            for key in self._ctx_ctrl:
                ctx[key] = getattr(self, key)
        if (ContextFlags & CONTEXT_EXTENDED_REGISTERS) == CONTEXT_EXTENDED_REGISTERS:
            er = [ self.ExtendedRegisters[index] for index in xrange(0, MAXIMUM_SUPPORTED_EXTENSION) ]
            er = tuple(er)
            ctx['ExtendedRegisters'] = er
        return ctx

PCONTEXT                = POINTER(CONTEXT)
LPCONTEXT               = PCONTEXT

class Context(dict):

    arch = CONTEXT.arch

    def __get_pc(self):
        return self['Eip']
    def __set_pc(self, value):
        self['Eip'] = value
    pc = property(__get_pc, __set_pc)

    def __get_sp(self):
        return self['Esp']
    def __set_sp(self, value):
        self['Esp'] = value
    sp = property(__get_sp, __set_sp)

    def __get_fp(self):
        return self['Ebp']
    def __set_fp(self, value):
        self['Ebp'] = value
    fp = property(__get_fp, __set_fp)


class _LDT_ENTRY_BYTES_(Structure):
    _pack_ = 1
    _fields_ = [
        ('BaseMid',         c_ubyte),
        ('Flags1',          c_ubyte),
        ('Flags2',          c_ubyte),
        ('BaseHi',          c_ubyte),
    ]

class _LDT_ENTRY_BITS_(Structure):
    _pack_ = 1
    _fields_ = [
        ('BaseMid',         c_uint32,  8),
        ('Type',            c_uint32,  5),
        ('Dpl',             c_uint32,  2),
        ('Pres',            c_uint32,  1),
        ('LimitHi',         c_uint32,  4),
        ('Sys',             c_uint32,  1),
        ('Reserved_0',      c_uint32,  1),
        ('Default_Big',     c_uint32,  1),
        ('Granularity',     c_uint32,  1),
        ('BaseHi',          c_uint32,  8),
    ]

class _LDT_ENTRY_HIGHWORD_(Union):
    _pack_ = 1
    _fields_ = [
        ('Bytes',           _LDT_ENTRY_BYTES_),
        ('Bits',            _LDT_ENTRY_BITS_),
    ]

class LDT_ENTRY(Structure):
    _pack_ = 1
    _fields_ = [
        ('LimitLow',        c_uint16),
        ('BaseLow',         c_uint16),
        ('HighWord',        _LDT_ENTRY_HIGHWORD_),
    ]

PLDT_ENTRY               = POINTER(LDT_ENTRY)
LPLDT_ENTRY              = PLDT_ENTRY

class SubsystemX86:

    def __init__(self):

        self.PROCESS_INFORMATION_BLOCK = PROCESS_INFORMATION_BLOCK

    def GetModuleFileNameEx(self, hProcess, hModule=0):

        """
        DWORD WINAPI GetModuleFileNameEx(
          _In_     HANDLE  hProcess,
          _In_opt_ HMODULE hModule,
          _Out_    LPTSTR  lpFilename,
          _In_     DWORD   nSize
        );
        """

        _GetModuleFileNameExA = windll.psapi.GetModuleFileNameExA
        _GetModuleFileNameExA.argtypes = [ wintypes.HANDLE, wintypes.HMODULE, c_char_p, c_uint32 ]

        nSize = 0x400
        while True:

            lpFilename = create_string_buffer("", nSize)
            nCopied = _GetModuleFileNameExA(hProcess, hModule, lpFilename, nSize)

            if nCopied == 0:
                raise WinError()
            if nCopied < (nSize-1):
                break

            nSize = nSize + 0x400

        return lpFilename.value

    def ReadProcessMemory(self, hProcess, address, buffer, bytes, bytesread):

        """
        BOOL WINAPI ReadProcessMemory(
          _In_  HANDLE  hProcess,
          _In_  LPCVOID lpBaseAddress,
          _Out_ LPVOID  lpBuffer,
          _In_  SIZE_T  nSize,
          _Out_ SIZE_T  *lpNumberOfBytesRead
        );
        """

        _ReadProcessMemory = windll.kernel32.ReadProcessMemory
        _ReadProcessMemory.argtypes = [ wintypes.HANDLE, c_void_p, c_void_p, c_uint32, POINTER(c_uint32) ]

        return  _ReadProcessMemory(hProcess, address, buffer, bytes, byref(bytesread))

    def EnumModules(self, hProcess):

        modules = []

        ProcessInformationLength = sizeof(PROCESS_BASIC_INFORMATION)
        ProcessInformation = create_string_buffer(ProcessInformationLength)
        ReturnLength = c_ulong(0)

        ntstatus = windll.ntdll.NtQueryInformationProcess(hProcess, ProcessBasicInformation, ProcessInformation, ProcessInformationLength, byref(ReturnLength))
        pbi = cast(ProcessInformation, POINTER(PROCESS_BASIC_INFORMATION)).contents

        peb = PEB32()

        bytesread = c_ulong(0)
        self.ReadProcessMemory(hProcess, pbi.PebBaseAddress, byref(peb), sizeof(peb), bytesread)

        ldr = PEB_LDR_DATA()
        self.ReadProcessMemory(hProcess, peb.Ldr, byref(ldr), sizeof(ldr), bytesread)

        StartFlinkAddress = ldr.InLoadOrderModuleList.Flink

        moduledata = LDR_DATA_TABLE_ENTRY()
        self.ReadProcessMemory(hProcess, StartFlinkAddress, byref(moduledata), sizeof(moduledata), bytesread)
        modules.append(moduledata)

        while True:

            address = moduledata.InLoadOrderLinks.Flink
 
            moduledata = LDR_DATA_TABLE_ENTRY()
            self.ReadProcessMemory(hProcess, address, byref(moduledata), sizeof(moduledata), bytesread)

            if address == StartFlinkAddress:
                break

            if moduledata.DllBase is not None:
                modules.append(moduledata)
                
        return modules

    def VirtualAllocEx(self, hProcess, size):

        """
        LPVOID WINAPI VirtualAllocEx(
          _In_     HANDLE hProcess,
          _In_opt_ LPVOID lpAddress,
          _In_     SIZE_T dwSize,
          _In_     DWORD  flAllocationType,
          _In_     DWORD  flProtect
        );
        """

        _VirtualAllocEx = windll.kernel32.VirtualAllocEx
        _VirtualAllocEx.argtypes = [ wintypes.HANDLE, c_void_p, c_uint32, c_uint32, c_uint32]
        _VirtualAllocEx.restype = c_uint32

        return _VirtualAllocEx(hProcess, None, size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)

    def VirtualQueryEx(self, hProcess, lpAddress):

        """
        SIZE_T WINAPI VirtualQueryEx(
          _In_     HANDLE                    hProcess,
          _In_opt_ LPCVOID                   lpAddress,
          _Out_    PMEMORY_BASIC_INFORMATION lpBuffer,
          _In_     SIZE_T                    dwLength
        );
        """

        mbi = MEMORY_BASIC_INFORMATION32()

        _VirtualQueryEx = windll.kernel32.VirtualQueryEx
        _VirtualQueryEx.argtypes = [ wintypes.HANDLE, c_uint32, c_void_p, c_uint32 ]

        _VirtualQueryEx(hProcess, lpAddress, byref(mbi), sizeof(mbi))
        return mbi

    def VirtualProtectEx(self, hProcess, lpAddress, size=0x400, permission=PAGE_EXECUTE_READWRITE):

        """
        BOOL WINAPI VirtualProtect(
          _In_  LPVOID lpAddress,
          _In_  SIZE_T dwSize,
          _In_  DWORD  flNewProtect,
          _Out_ PDWORD lpflOldProtect
        );
        """

        _VirtualProtectEx = windll.kernel32.VirtualProtectEx 
        _VirtualProtectEx.argtypes = [ wintypes.HANDLE, c_void_p, c_uint32, c_uint32, POINTER(c_uint32)]
        
        old_protect = c_uint32(0)

        _VirtualProtectEx(hProcess, lpAddress, size, permission, byref(old_protect))
        return old_protect.value
		    

    def WriteProcessMemory(self, hProcess, lpBaseAddress, buffer, nSize, lpNumberOfBytesWritten):

		"""
		BOOL WINAPI WriteProcessMemory(
		  _In_  HANDLE  hProcess,
		  _In_  LPVOID  lpBaseAddress,
		  _In_  LPCVOID lpBuffer,
		  _In_  SIZE_T  nSize,
		  _Out_ SIZE_T  *lpNumberOfBytesWritten
		);
		"""

		_WriteProcessMemory = windll.kernel32.WriteProcessMemory
		_WriteProcessMemory.argtypes = [ wintypes.HANDLE, c_void_p, c_void_p, c_uint32, c_void_p ]

		self.VirtualProtectEx(hProcess, lpBaseAddress)
		_WriteProcessMemory(hProcess, lpBaseAddress, byref(buffer), nSize, lpNumberOfBytesWritten)

    def DLLWriteProcessMemory(self, hProcess, lpBaseAddress, data):

        _DLLWriteProcessMemory = windll.kernel32.WriteProcessMemory
        _DLLWriteProcessMemory.argtypes = [ wintypes.HANDLE, c_void_p, c_void_p, c_uint32, POINTER(c_uint32)]

        self.VirtualProtectEx(hProcess, lpBaseAddress)

        count = c_uint32(0)
        length = len(data)
        lpBuffer = create_string_buffer(data[count.value:])

        _DLLWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, length, byref(count))


    def CreateRemoteThread(self, hProcess, lpStartAddress, lpParameter):

        """
        HANDLE WINAPI CreateRemoteThread(
          _In_  HANDLE                 hProcess,
          _In_  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
          _In_  SIZE_T                 dwStackSize,
          _In_  LPTHREAD_START_ROUTINE lpStartAddress,
          _In_  LPVOID                 lpParameter,
          _In_  DWORD                  dwCreationFlags,
          _Out_ LPDWORD                lpThreadId
        );
        @return : threadId 
        """

        _CreateRemoteThread = windll.kernel32.CreateRemoteThread
        _CreateRemoteThread.argtypes = [ wintypes.HANDLE, POINTER(SECURITY_ATTRIBUTES), c_uint32, c_void_p, c_void_p, c_uint32, POINTER(c_uint32) ]

        threadId = c_uint32(0)
        _CreateRemoteThread ( hProcess, None, 0, lpStartAddress, lpParameter, 0, byref(threadId))

        return threadId

    def Distorm3Decoder(self, address, data):

        """
        @package :  Distorm3
        """
        import distorm3
        return distorm3.DecodeGenerator(address, data, distorm3.Decode32Bits)

    def GetThreadContext(self, hThread):

        """
        BOOL WINAPI GetThreadContext(
          __in     HANDLE hThread,
          __inout  LPCONTEXT lpContext
        );
        """

        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS | CONTEXT_i386

        windll.kernel32.GetThreadContext(hThread, byref(context))
        return context

    def SetThreadContext(self, hThread, context):

        """
        BOOL WINAPI SetThreadContext(
          _In_       HANDLE  hThread,
          _In_ const CONTEXT *lpContext
        );
        """

        windll.kernel32.SetThreadContext(hThread, byref(context))