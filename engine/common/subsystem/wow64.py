"""
name        : wow64.py
author      : hakbaby
function    : subsystem wow64
"""

from define import *

class LIST_ENTRY(Structure):
    _fields_ = [
        ("Flink",   c_void_p),     # POINTER(LIST_ENTRY)
        ("Blink",   c_void_p),     # POINTER(LIST_ENTRY)
]

class LIST_ENTRY32(Structure):
    _fields_ = [
        ("Flink",   c_uint32),     # POINTER(LIST_ENTRY)
        ("Blink",   c_uint32),     # POINTER(LIST_ENTRY)
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

class LDR_DATA_TABLE_ENTRY32 (Structure):
    _fields_ = [
    ("InLoadOrderLinks",            LIST_ENTRY32),
    ("InMemoryOrderLinks",          LIST_ENTRY32),
    ("InInitializationOrderLinks",  LIST_ENTRY32),
    ("DllBase",                     c_uint32),
    ("EntryPoint",                  c_uint32),
    ("SizeOfImage",                 c_ulong),
    ("FullDllName",                 UNICODE_STRING),
    ("BaseDllName",                 UNICODE_STRING),
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

class PEB_LDR_DATA32(Structure):

  _fields_ = [
      ("Length",                                c_ulong),
      ("Initialized",                           c_ubyte),
      ("SsHandle",                              c_uint32),
      ("InLoadOrderModuleList",                 LIST_ENTRY32),
      ("InMemoryOrderModuleList",               LIST_ENTRY32),
      ("InInitializationOrderModuleList",       LIST_ENTRY32)
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

class PROCESS_EXTENDED_BASIC_INFORMATION( Structure ):
        _fields_ = [
        ('size',                   c_uint32),
        ('BasicInfo',              PROCESS_BASIC_INFORMATION),
        ('Flags',                  c_ulong),
        ('IsProtectedProcess',     c_ulong),
        ('IsWow64Process',         c_ulong),
        ('IsProcessDeleting',      c_ulong),
        ('IsCrossSessionCreate',   c_ulong),
        ('IsFrozen',               c_ulong),
        ('IsBackground',           c_ulong),
        ('IsStronglyNamed',        c_ulong),
        ('SpareBits',              c_ulong),
    ]

"""class MEMORY_BASIC_INFORMATION32(Structure):
    _fields_ = [
        ("BaseAddress",         c_void_p),
        ("AllocationBase",      c_void_p),
        ("AllocationProtect",   c_uint32),
        ("RegionSize",          c_ulonglong),
        ("State",               c_uint32),
        ("Protect",             c_uint32),
        ("Type",                c_uint32)
    ]"""

class MEMORY_BASIC_INFORMATION64(Structure):
    _fields_ = [
        ("BaseAddress",         c_uint64),
        ("AllocationBase",      c_uint64),
        ("AllocationProtect",   c_uint32),
        ("__alignment1",        c_uint32),
        ("RegionSize",          c_uint64),
        ("State",               c_uint32),
        ("Protect",             c_uint32),
        ("Type",                c_uint32),
        ("__alignment2",        c_uint32)
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


ARCH_I386                           = "i386"
WOW64_CS32                          = 0x23
WOW64_CONTEXT_i386                  = 0x00010000L
WOW64_CONTEXT_i486                  = 0x00010000L
WOW64_CONTEXT_CONTROL               = (WOW64_CONTEXT_i386 | 0x00000001L)
WOW64_CONTEXT_INTEGER               = (WOW64_CONTEXT_i386 | 0x00000002L)
WOW64_CONTEXT_SEGMENTS              = (WOW64_CONTEXT_i386 | 0x00000004L)
WOW64_CONTEXT_FLOATING_POINT        = (WOW64_CONTEXT_i386 | 0x00000008L)
WOW64_CONTEXT_DEBUG_REGISTERS       = (WOW64_CONTEXT_i386 | 0x00000010L)
WOW64_CONTEXT_EXTENDED_REGISTERS    = (WOW64_CONTEXT_i386 | 0x00000020L)
WOW64_CONTEXT_FULL                  = (WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER | WOW64_CONTEXT_SEGMENTS)
WOW64_CONTEXT_ALL                   = (WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER | WOW64_CONTEXT_SEGMENTS | WOW64_CONTEXT_FLOATING_POINT | WOW64_CONTEXT_DEBUG_REGISTERS | WOW64_CONTEXT_EXTENDED_REGISTERS)
SIZE_OF_80387_REGISTERS     = 80
MAXIMUM_SUPPORTED_EXTENSION = 512
WOW64_SIZE_OF_80387_REGISTERS       = 80
WOW64_MAXIMUM_SUPPORTED_EXTENSION   = 512

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

PFLOATING_SAVE_AREA = POINTER(FLOATING_SAVE_AREA)
LPFLOATING_SAVE_AREA = PFLOATING_SAVE_AREA


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

PCONTEXT = POINTER(CONTEXT)
LPCONTEXT = PCONTEXT

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

PLDT_ENTRY = POINTER(LDT_ENTRY)
LPLDT_ENTRY = PLDT_ENTRY

class WOW64_FLOATING_SAVE_AREA (FLOATING_SAVE_AREA):
    pass

class WOW64_CONTEXT (CONTEXT):
    pass

class WOW64_LDT_ENTRY (LDT_ENTRY):
    pass

PWOW64_FLOATING_SAVE_AREA   = POINTER(WOW64_FLOATING_SAVE_AREA)
PWOW64_CONTEXT              = POINTER(WOW64_CONTEXT)
PWOW64_LDT_ENTRY            = POINTER(WOW64_LDT_ENTRY)

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
      ('PeakPageFileUsage',            POINTER(c_ulong)),
      ('Reserved',                     c_ulonglong),
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
      ('th',                           c_ARRAY(SYSTEM_THREAD_INFORMATION, 10)),
   ]

class SubsystemWOW64:

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
        _GetModuleFileNameExA.argtypes = [ wintypes.HANDLE, wintypes.HMODULE, POINTER(c_char), c_uint32 ]

        name = create_string_buffer(0x400)
        _GetModuleFileNameExA(hProcess, hModule, name, sizeof(name))
        return name.value

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

        pebAddr = c_void_p(0)
        ReturnLength = c_ulong(0)

        ntstatus = windll.ntdll.NtQueryInformationProcess(hProcess, ProcessWow64Information, byref(pebAddr), sizeof(pebAddr), byref(ReturnLength))

        pAddress = pebAddr.value + 0xC
        pebPtr = c_uint32(0)
        bytesread = c_ulong(0)
        self.ReadProcessMemory(hProcess, pAddress, byref(pebPtr), sizeof(pebPtr), bytesread)

        peb = PEB_LDR_DATA32()
        self.ReadProcessMemory(hProcess, pebPtr.value, byref(peb), sizeof(peb), bytesread)

        StartFlinkAddress = peb.InLoadOrderModuleList.Flink

        moduledata = LDR_DATA_TABLE_ENTRY32()
        self.ReadProcessMemory(hProcess, StartFlinkAddress, byref(moduledata), sizeof(moduledata), bytesread)
        modules.append(moduledata)

        while True:

            address = moduledata.InLoadOrderLinks.Flink
 
            moduledata = LDR_DATA_TABLE_ENTRY32()
            self.ReadProcessMemory(hProcess, address, byref(moduledata), sizeof(moduledata), bytesread)

            if address == StartFlinkAddress:
                break

            if moduledata.DllBase != 0:
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

        mbi = MEMORY_BASIC_INFORMATION64()
    
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
        old_permissions = c_uint32()

        _VirtualProtectEx(hProcess, lpAddress, size, permission, byref(old_permissions)) 
            

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
        
        context = WOW64_CONTEXT()
        context.ContextFlags = WOW64_CONTEXT_ALL | WOW64_CONTEXT_i386

        windll.kernel32.Wow64GetThreadContext(hThread, byref(context))
        return context

    def SetThreadContext(self, hThread, context):

        """
        BOOL WINAPI SetThreadContext(
          _In_       HANDLE  hThread,
          _In_ const CONTEXT *lpContext
        );
        """

        windll.kernel32.Wow64SetThreadContext(hThread, byref(context))
