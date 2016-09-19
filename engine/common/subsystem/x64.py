"""
name        : x64.py
author      : hakbaby
function    : subsystem x64
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

class LDR_DATA_TABLE_ENTRY (Structure):

    _fields_ = [
        ("InLoadOrderLinks", 				LIST_ENTRY),
        ("InMemoryOrderLinks", 				LIST_ENTRY),
        ("InInitializationOrderLinks", 		LIST_ENTRY),
        ("DllBase", 						c_void_p),
        ("EntryPoint",	 					c_void_p),
        ("SizeOfImage", 					c_ulong),
        ("FullDllName", 					UNICODE_STRING),
        ("BaseDllName", 					UNICODE_STRING),
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
class PEB64(Structure):

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

ARCH_AMD64                  = "amd64"
EXCEPTION_READ_FAULT        = 0     # exception caused by a read
EXCEPTION_WRITE_FAULT       = 1     # exception caused by a write
EXCEPTION_EXECUTE_FAULT     = 8     # exception caused by an instruction fetch
CONTEXT_AMD64               = 0x00100000
CONTEXT_CONTROL             = (CONTEXT_AMD64 | 0x1L)
CONTEXT_INTEGER             = (CONTEXT_AMD64 | 0x2L)
CONTEXT_SEGMENTS            = (CONTEXT_AMD64 | 0x4L)
CONTEXT_FLOATING_POINT      = (CONTEXT_AMD64 | 0x8L)
CONTEXT_DEBUG_REGISTERS     = (CONTEXT_AMD64 | 0x10L)
CONTEXT_MMX_REGISTERS       = CONTEXT_FLOATING_POINT
CONTEXT_FULL                = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)
CONTEXT_ALL                 = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS)
CONTEXT_XSTATE              = (CONTEXT_AMD64 | 0x20L)
CONTEXT_EXCEPTION_ACTIVE    = 0x8000000
CONTEXT_SERVICE_ACTIVE      = 0x10000000
CONTEXT_EXCEPTION_REQUEST   = 0x40000000
CONTEXT_EXCEPTION_REPORTING = 0x80000000
INITIAL_MXCSR               = 0x1f80            # initial MXCSR value
INITIAL_FPCSR               = 0x027f            # initial FPCSR value

class M128A(Structure):
    _fields_ = [
        ("Low",     c_uint64),
        ("High",    c_uint64)
    ]

PM128A                      = POINTER(M128A)

class XMM_SAVE_AREA32(Structure):
    _pack_ = 1
    _fields_ = [
        ('ControlWord',     c_uint16),
        ('StatusWord',      c_uint16),
        ('TagWord',         c_ubyte),
        ('Reserved1',       c_ubyte),
        ('ErrorOpcode',     c_uint16),
        ('ErrorOffset',     c_uint32),
        ('ErrorSelector',   c_uint16),
        ('Reserved2',       c_uint16),
        ('DataOffset',      c_uint64),
        ('DataSelector',    c_uint16),
        ('Reserved3',       c_uint16),
        ('MxCsr',           c_uint64),
        ('MxCsr_Mask',      c_uint64),
        ('FloatRegisters',  M128A * 8),
        ('XmmRegisters',    M128A * 16),
        ('Reserved4',       c_ubyte * 96),
    ]

    def from_dict(self):
        raise NotImplementedError()

    def to_dict(self):
        d = dict()
        for name, type in self._fields_:
            if name in ('FloatRegisters', 'XmmRegisters'):
                d[name] = tuple([ (x.LowPart + (x.HighPart << 64)) for x in getattr(self, name) ])
            elif name == 'Reserved4':
                d[name] = tuple([ chr(x) for x in getattr(self, name) ])
            else:
                d[name] = getattr(self, name)
        return d

LEGACY_SAVE_AREA_LENGTH = sizeof(XMM_SAVE_AREA32)

PXMM_SAVE_AREA32 = POINTER(XMM_SAVE_AREA32)
LPXMM_SAVE_AREA32 = PXMM_SAVE_AREA32

class _CONTEXT_FLTSAVE_STRUCT(Structure):
    _fields_ = [
        ('Header',                  M128A * 2),
        ('Legacy',                  M128A * 8),
        ('Xmm0',                    M128A),
        ('Xmm1',                    M128A),
        ('Xmm2',                    M128A),
        ('Xmm3',                    M128A),
        ('Xmm4',                    M128A),
        ('Xmm5',                    M128A),
        ('Xmm6',                    M128A),
        ('Xmm7',                    M128A),
        ('Xmm8',                    M128A),
        ('Xmm9',                    M128A),
        ('Xmm10',                   M128A),
        ('Xmm11',                   M128A),
        ('Xmm12',                   M128A),
        ('Xmm13',                   M128A),
        ('Xmm14',                   M128A),
        ('Xmm15',                   M128A),
    ]

    def from_dict(self):
        raise NotImplementedError()

    def to_dict(self):
        d = dict()
        for name, type in self._fields_:
            if name in ('Header', 'Legacy'):
                d[name] = tuple([ (x.Low + (x.High << 64)) for x in getattr(self, name) ])
            else:
                x = getattr(self, name)
                d[name] = x.Low + (x.High << 64)
        return d

class _CONTEXT_FLTSAVE_UNION(Union):
    _fields_ = [
        ('flt',                     XMM_SAVE_AREA32),
        ('xmm',                     _CONTEXT_FLTSAVE_STRUCT),
    ]

    def from_dict(self):
        raise NotImplementedError()

    def to_dict(self):
        d = dict()
        d['flt'] = self.flt.to_dict()
        d['xmm'] = self.xmm.to_dict()
        return d

class CONTEXT(Structure):
    arch = ARCH_AMD64

    _pack_ = 16
    _fields_ = [

        # Register parameter home addresses.
        ('P1Home',                  c_uint64),
        ('P2Home',                  c_uint64),
        ('P3Home',                  c_uint64),
        ('P4Home',                  c_uint64),
        ('P5Home',                  c_uint64),
        ('P6Home',                  c_uint64),

        # Control flags.
        ('ContextFlags',            c_uint32),
        ('MxCsr',                   c_uint32),

        # Segment Registers and processor flags.
        ('SegCs',                   c_uint16),
        ('SegDs',                   c_uint16),
        ('SegEs',                   c_uint16),
        ('SegFs',                   c_uint16),
        ('SegGs',                   c_uint16),
        ('SegSs',                   c_uint16),
        ('EFlags',                  c_uint32),

        # Debug registers.
        ('Dr0',                     c_uint64),
        ('Dr1',                     c_uint64),
        ('Dr2',                     c_uint64),
        ('Dr3',                     c_uint64),
        ('Dr6',                     c_uint64),
        ('Dr7',                     c_uint64),

        # Integer registers.
        ('Rax',                     c_uint64),
        ('Rcx',                     c_uint64),
        ('Rdx',                     c_uint64),
        ('Rbx',                     c_uint64),
        ('Rsp',                     c_uint64),
        ('Rbp',                     c_uint64),
        ('Rsi',                     c_uint64),
        ('Rdi',                     c_uint64),
        ('R8',                      c_uint64),
        ('R9',                      c_uint64),
        ('R10',                     c_uint64),
        ('R11',                     c_uint64),
        ('R12',                     c_uint64),
        ('R13',                     c_uint64),
        ('R14',                     c_uint64),
        ('R15',                     c_uint64),

        # Program counter.
        ('Rip',                     c_uint64),

        # Floating point state.
        ('FltSave',                 _CONTEXT_FLTSAVE_UNION),

        # Vector registers.
        ('VectorRegister',          M128A * 26),
        ('VectorControl',           c_uint64),

        # Special debug control registers.
        ('DebugControl',            c_uint64),
        ('LastBranchToRip',         c_uint64),
        ('LastBranchFromRip',       c_uint64),
        ('LastExceptionToRip',      c_uint64),
        ('LastExceptionFromRip',    c_uint64),
    ]

    _others = ('P1Home', 'P2Home', 'P3Home', 'P4Home', 'P5Home', 'P6Home', \
               'MxCsr', 'VectorRegister', 'VectorControl')
    _control = ('SegSs', 'Rsp', 'SegCs', 'Rip', 'EFlags')
    _integer = ('Rax', 'Rcx', 'Rdx', 'Rbx', 'Rsp', 'Rbp', 'Rsi', 'Rdi', \
                'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15')
    _segments = ('SegDs', 'SegEs', 'SegFs', 'SegGs')
    _debug = ('Dr0', 'Dr1', 'Dr2', 'Dr3', 'Dr6', 'Dr7', \
              'DebugControl', 'LastBranchToRip', 'LastBranchFromRip', \
              'LastExceptionToRip', 'LastExceptionFromRip')
    _mmx = ('Xmm0', 'Xmm1', 'Xmm2', 'Xmm3', 'Xmm4', 'Xmm5', 'Xmm6', 'Xmm7', \
          'Xmm8', 'Xmm9', 'Xmm10', 'Xmm11', 'Xmm12', 'Xmm13', 'Xmm14', 'Xmm15')

    # XXX TODO
    # Convert VectorRegister and Xmm0-Xmm15 to pure Python types!

    @classmethod
    def from_dict(cls, ctx):
        'Instance a new structure from a Python native type.'
        ctx = Context(ctx)
        s = cls()
        ContextFlags = ctx['ContextFlags']
        s.ContextFlags = ContextFlags
        for key in cls._others:
            if key != 'VectorRegister':
                setattr(s, key, ctx[key])
            else:
                w = ctx[key]
                v = (M128A * len(w))()
                i = 0
                for x in w:
                    y = M128A()
                    y.High = x >> 64
                    y.Low = x - (x >> 64)
                    v[i] = y
                    i += 1
                setattr(s, key, v)
        if (ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL:
            for key in cls._control:
                setattr(s, key, ctx[key])
        if (ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER:
            for key in cls._integer:
                setattr(s, key, ctx[key])
        if (ContextFlags & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS:
            for key in cls._segments:
                setattr(s, key, ctx[key])
        if (ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS:
            for key in cls._debug:
                setattr(s, key, ctx[key])
        if (ContextFlags & CONTEXT_MMX_REGISTERS) == CONTEXT_MMX_REGISTERS:
            xmm = s.FltSave.xmm
            for key in cls._mmx:
                y = M128A()
                y.High = x >> 64
                y.Low = x - (x >> 64)
                setattr(xmm, key, y)
        return s

    def to_dict(self):
        'Convert a structure into a Python dictionary.'
        ctx = Context()
        ContextFlags = self.ContextFlags
        ctx['ContextFlags'] = ContextFlags
        for key in self._others:
            if key != 'VectorRegister':
                ctx[key] = getattr(self, key)
            else:
                ctx[key] = tuple([ (x.Low + (x.High << 64)) for x in getattr(self, key) ])
        if (ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL:
            for key in self._control:
                ctx[key] = getattr(self, key)
        if (ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER:
            for key in self._integer:
                ctx[key] = getattr(self, key)
        if (ContextFlags & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS:
            for key in self._segments:
                ctx[key] = getattr(self, key)
        if (ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS:
            for key in self._debug:
                ctx[key] = getattr(self, key)
        if (ContextFlags & CONTEXT_MMX_REGISTERS) == CONTEXT_MMX_REGISTERS:
            xmm = self.FltSave.xmm.to_dict()
            for key in self._mmx:
                ctx[key] = xmm.get(key)
        return ctx

PCONTEXT = POINTER(CONTEXT)
LPCONTEXT = PCONTEXT

class Context(dict):
    """
    Register context dictionary for the amd64 architecture.
    """

    arch = CONTEXT.arch

    def __get_pc(self):
        return self['Rip']
    def __set_pc(self, value):
        self['Rip'] = value
    pc = property(__get_pc, __set_pc)

    def __get_sp(self):
        return self['Rsp']
    def __set_sp(self, value):
        self['Rsp'] = value
    sp = property(__get_sp, __set_sp)

    def __get_fp(self):
        return self['Rbp']
    def __set_fp(self, value):
        self['Rbp'] = value
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

PLDT_ENTRY = POINTER(LDT_ENTRY)
LPLDT_ENTRY = PLDT_ENTRY

class SubsystemX64:

    def __init__(self):

        self.PROCESS_INFORMATION_BLOCK = PROCESS_INFORMATION_BLOCK
        self.PEB = PEB64

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
        _GetModuleFileNameExA.argtypes = [ wintypes.HANDLE, wintypes.HMODULE, POINTER(c_char), c_uint64 ]

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
        _ReadProcessMemory.argtypes = [ wintypes.HANDLE, c_void_p, c_void_p, c_uint32, POINTER(c_uint64) ]

        return  _ReadProcessMemory(hProcess, address, buffer, bytes, byref(bytesread))

    def EnumModules(self, hProcess):

        modules = []

        ProcessInformationLength = sizeof(PROCESS_BASIC_INFORMATION)
        ProcessInformation = create_string_buffer(ProcessInformationLength)
        ReturnLength = c_ulong(0)

        ntstatus = windll.ntdll.NtQueryInformationProcess(hProcess, ProcessBasicInformation, ProcessInformation, ProcessInformationLength, byref(ReturnLength))
        pbi = cast(ProcessInformation, POINTER(PROCESS_BASIC_INFORMATION)).contents
        
        peb = PEB64()

        bytesread = c_uint64(0)
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
        _VirtualAllocEx.argtypes = [ wintypes.HANDLE, c_void_p, c_uint64, c_uint64, c_uint64]
        _VirtualAllocEx.restype = c_uint64

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
        _VirtualQueryEx.argtypes = [ wintypes.HANDLE, c_uint64, c_void_p, c_uint64 ]

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
        _VirtualProtectEx.argtypes = [ wintypes.HANDLE, c_void_p, c_uint64, c_uint64, POINTER(c_uint64)]
        old_permissions = c_uint64()

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
        _WriteProcessMemory.argtypes = [ wintypes.HANDLE, c_void_p, c_void_p, c_uint64, c_void_p ]

        self.VirtualProtectEx(hProcess, lpBaseAddress)
        _WriteProcessMemory(hProcess, lpBaseAddress, byref(buffer), nSize, lpNumberOfBytesWritten)

    def DLLWriteProcessMemory(self, hProcess, lpBaseAddress, data):

        _DLLWriteProcessMemory = windll.kernel32.WriteProcessMemory
        _DLLWriteProcessMemory.argtypes = [ wintypes.HANDLE, c_void_p, c_void_p, c_uint64, POINTER(c_uint32)]

        self.VirtualProtectEx(hProcess, lpBaseAddress)

        count = c_uint64(0)
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
        _CreateRemoteThread.argtypes = [ wintypes.HANDLE, POINTER(SECURITY_ATTRIBUTES), c_uint64, c_void_p, c_void_p, c_uint64, POINTER(c_uint64) ]

        threadId = c_uint32(0)
        _CreateRemoteThread ( hProcess, None, 0, lpStartAddress, lpParameter, 0, byref(threadId))

        return threadId


    def Distorm3Decoder(self, address, data):

        """
        @package :  Distorm3

        """
        import distorm3
        return distorm3.DecodeGenerator(address, data, distorm3.Decode64Bits)

    def GetThreadContext(self, hThread, threadId):

        """
        BOOL WINAPI GetThreadContext(
          __in     HANDLE hThread,
          __inout  LPCONTEXT lpContext
        );
        """

        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS | CONTEXT_AMD64

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
