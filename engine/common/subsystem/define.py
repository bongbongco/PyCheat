"""
name        : define.py
author      : hakbaby
function    : header/like precompile 
"""

from sys import platform, maxsize, exit

from ctypes import windll
from ctypes import wintypes 
from ctypes import (POINTER, Structure, Union, addressof, byref, cast, create_unicode_buffer, create_string_buffer, c_bool, c_char, c_ubyte, c_byte, c_short, c_int, c_uint16, c_uint32, c_uint64, c_long, c_longlong, c_ulong, c_ulonglong, c_ushort, c_void_p, c_char_p, c_wchar_p, c_size_t, sizeof)
from ctypes import ARRAY as c_ARRAY
from ctypes import WinError

import struct

PYTHONIS64BIT				           = maxsize > 2**32
MAX_BUFFER 					           = 1024
NULL 						               = 0
TOKEN_QUERY                    = 8
TOKEN_ADJUST_PRIVILEGES        = 32
PROCESS_CREATE_THREAD          = 0x0002
PROCESS_VM_OPERATION           = 0x0008
PROCESS_VM_READ                = 0x0010
PROCESS_VM_WRITE               = 0x0020
PROCESS_DUP_HANDLE             = 0x0040
PROCESS_SET_INFORMATION        = 0x0200
PROCESS_QUERY_INFORMATION      = 0x0400
PROCESS_ALL_ACCESS             = 0x1f0fff
MEM_PRIVATE                    = 0x01000000
MEM_COMMIT                     = 0x1000
MEM_FREE                       = 0x10000
MEM_RESERVE                    = 0x2000
PAGE_CAN_NOT_CHANGE			       = 0x13 #PAGE_NOACCESS|PAGE_READONLY|PAGE_EXECUTE
PAGE_EXECUTE_READ 			       = 0x20
PAGE_EXECUTE_READWRITE         = 0x40
ObjectBasicInformation         = 0
ObjectNameInformation          = 1
ObjectTypeInformation          = 2
ObjectAllTypesInformation      = 3
ObjectHandleInformation        = 4
STATUS_SUCCESS                 = 0x00000000
STATUS_INFO_LENGTH_MISMATCH    = 0xc0000004
STATUS_BUFFER_OVERFLOW         = 0x80000005
SystemHandleInformation        = 16
STANDARD_RIGHTS_REQUIRED       = 0x000f0000
DBG_CONTINUE                   = 0x00010002
#DBG_EXCEPTION_NOT_HANDLED      = 0x00010001
DBG_CONTROL_C                  = 0x40010005
DBG_CONTROL_BREAK              = 0x40010008
INFINITE                       = 0xFFFFFFFF
CONTEXT_i386                   = 0x00010000
CONTEXT_CONTROL                = 0x00000001
CONTEXT_INTEGER                = 0x00000002
CONTEXT_SEGMENTS               = 0x00000004
CONTEXT_FLOATING_POINT         = 0x00000008
CONTEXT_DEBUG_REGISTERS        = 0x00000010
CONTEXT_EXTENDED_REGISTERS     = 0x00000020
CONTEXT_FULL                   = 0x00000007
CW_USEDEFAULT                  = -0x80000000
STARTF_USESIZE                 = 2
DEBUG_PROCESS                  = 1
NORMAL_PRIORITY_CLASS          = 0x20
EXCEPTION_DEBUG_EVENT          = 1
CREATE_THREAD_DEBUG_EVENT      = 2
CREATE_PROCESS_DEBUG_EVENT     = 3
EXIT_THREAD_DEBUG_EVENT        = 4
EXIT_PROCESS_DEBUG_EVENT       = 5
LOAD_DLL_DEBUG_EVENT           = 6
UNLOAD_DLL_DEBUG_EVENT         = 7
OUTPUT_DEBUG_STRING_EVENT      = 8
CREATE_SUSPENDED               = 4
PAGE_READWRITE                 = 4
STATUS_WAIT_0                    = 0    
STATUS_ABANDONED_WAIT_0          = 128    
STATUS_USER_APC                  = 192    
STATUS_TIMEOUT                   = 258    
STATUS_PENDING                   = 259    
STATUS_SEGMENT_NOTIFICATION      = 1073741829    
STATUS_GUARD_PAGE_VIOLATION      = -2147483647    
STATUS_DATATYPE_MISALIGNMENT     = -2147483646    
STATUS_BREAKPOINT                = -2147483645    
STATUS_SINGLE_STEP               = -2147483644    
STATUS_ACCESS_VIOLATION          = -1073741819    
STATUS_IN_PAGE_ERROR             = -1073741818    
STATUS_INVALID_HANDLE            = -1073741816    
STATUS_NO_MEMORY                 = -1073741801    
STATUS_ILLEGAL_INSTRUCTION       = -1073741795    
STATUS_NONCONTINUABLE_EXCEPTION  = -1073741787    
STATUS_INVALID_DISPOSITION       = -1073741786    
STATUS_ARRAY_BOUNDS_EXCEEDED     = -1073741684    
STATUS_FLOAT_DENORMAL_OPERAND    = -1073741683    
STATUS_FLOAT_DIVIDE_BY_ZERO      = -1073741682    
STATUS_FLOAT_INEXACT_RESULT      = -1073741681    
STATUS_FLOAT_INVALID_OPERATION   = -1073741680    
STATUS_FLOAT_OVERFLOW            = -1073741679    
STATUS_FLOAT_STACK_CHECK         = -1073741678    
STATUS_FLOAT_UNDERFLOW           = -1073741677    
STATUS_INTEGER_DIVIDE_BY_ZERO    = -1073741676    
STATUS_INTEGER_OVERFLOW          = -1073741675    
STATUS_PRIVILEGED_INSTRUCTION    = -1073741674    
STATUS_STACK_OVERFLOW            = -1073741571    
STATUS_CONTROL_C_EXIT            = -1073741510    
EXCEPTION_ACCESS_VIOLATION          = STATUS_ACCESS_VIOLATION
EXCEPTION_DATATYPE_MISALIGNMENT     = STATUS_DATATYPE_MISALIGNMENT
EXCEPTION_BREAKPOINT                = STATUS_BREAKPOINT
EXCEPTION_SINGLE_STEP               = STATUS_SINGLE_STEP
EXCEPTION_ARRAY_BOUNDS_EXCEEDED     = STATUS_ARRAY_BOUNDS_EXCEEDED
EXCEPTION_FLT_DENORMAL_OPERAND      = STATUS_FLOAT_DENORMAL_OPERAND
EXCEPTION_FLT_DIVIDE_BY_ZERO        = STATUS_FLOAT_DIVIDE_BY_ZERO
EXCEPTION_FLT_INEXACT_RESULT        = STATUS_FLOAT_INEXACT_RESULT
EXCEPTION_FLT_INVALID_OPERATION     = STATUS_FLOAT_INVALID_OPERATION
EXCEPTION_FLT_OVERFLOW              = STATUS_FLOAT_OVERFLOW
EXCEPTION_FLT_STACK_CHECK           = STATUS_FLOAT_STACK_CHECK
EXCEPTION_FLT_UNDERFLOW             = STATUS_FLOAT_UNDERFLOW
EXCEPTION_INT_DIVIDE_BY_ZERO        = STATUS_INTEGER_DIVIDE_BY_ZERO
EXCEPTION_INT_OVERFLOW              = STATUS_INTEGER_OVERFLOW
EXCEPTION_PRIV_INSTRUCTION          = STATUS_PRIVILEGED_INSTRUCTION
EXCEPTION_IN_PAGE_ERROR             = STATUS_IN_PAGE_ERROR
EXCEPTION_ILLEGAL_INSTRUCTION       = STATUS_ILLEGAL_INSTRUCTION
EXCEPTION_NONCONTINUABLE_EXCEPTION  = STATUS_NONCONTINUABLE_EXCEPTION
EXCEPTION_STACK_OVERFLOW            = STATUS_STACK_OVERFLOW
EXCEPTION_INVALID_DISPOSITION       = STATUS_INVALID_DISPOSITION
EXCEPTION_GUARD_PAGE                = STATUS_GUARD_PAGE_VIOLATION
EXCEPTION_INVALID_HANDLE            = STATUS_INVALID_HANDLE
CONTROL_C_EXIT                      = STATUS_CONTROL_C_EXIT
LIST_MODULES_ALL                    = 3
PE_POINTER_OFFSET                   = 0x3c
PE_SIZEOF_OF_OPTIONAL_HEADER_OFFSET = 0x14
PE_SIZEOF_NT_HEADER                 = 0x18
PE_NUM_OF_SECTIONS_OFFSET           = 0x06
IMAGE_SIZEOF_SECTION_HEADER         = 40
PE_SECTION_NAME_SIZE                = 0x08
PE_SECTION_VOFFSET_OFFSET           = 0x0c
PE_SECTION_SIZE_OF_RAW_DATA_OFFSET  = 0x10
PE_OPTIONAL_HEADER_TYPE             = 0x18
PE_PLUS_EXTRA_BYTES                 = 0x10
PE_RVA_OFFSET                       = 0x78
PE_RVA_SIZE                         = 0x7c
RVA_NUM_PROCS_OFFSET                = 0x14
RVA_NUM_PROCS_NAMES_OFFSET          = 0x18
RVA_PROCS_ADDRESSES_OFFSET          = 0x1c
RVA_PROCS_NAMES_OFFSET              = 0x20
RVA_PROCS_ORDINALS_OFFSET           = 0x24
PE_MAGIC                            = 'PE'
EXE_MAGIC                           = 'MZ'
OPTIONAL_HEADER_MAGIC               = '\x0b\x01'
ROM_OPTIONAL_HEADER_MAGIC           = '\x07\x01'
#SYSTEM_PROCESS_INFORMATION          = 5
#PROCESS_BASIC_INFORMATION           = 0
FILE_MAP_READ                       = 4
FILE_MAP_WRITE                      = 2
FILE_MAP_EXECUTE                    = 0x20
BOOL 								                = wintypes.BOOL


LIST_MODULES_32BIT          = 0x01
LIST_MODULES_64BIT          = 0x02
LIST_MODULES_ALL            = 0x03

THREAD_ALL_ACCESS = 0x001F03FF


PAGE_EXECUTE_READWRITE = 64
PAGE_EXECUTE_READ = 32
PAGE_READONLY = 2
PAGE_READWRITE = 4
PAGE_NOCACHE = 512
PAGE_WRITECOMBINE = 1024
PAGE_GUARD = 256

MEM_COMMIT = 4096
MEM_FREE = 65536
MEM_RESERVE = 8192

GENERIC_READ                = 0x80000000
GENERIC_WRITE               = 0x40000000
OPEN_EXISTING               = 3
FILE_FLAG_OVERLAPPED        = 0x40000000

CALLBACK_DEBUG_EVENT          = 0xDDDDDDDD
EXCEPTION_DEBUG_EVENT         = 1
CREATE_THREAD_DEBUG_EVENT     = 2
CREATE_PROCESS_DEBUG_EVENT    = 3
EXIT_THREAD_DEBUG_EVENT       = 4
EXIT_PROCESS_DEBUG_EVENT      = 5
LOAD_DLL_DEBUG_EVENT          = 6
UNLOAD_DLL_DEBUG_EVENT        = 7
OUTPUT_DEBUG_STRING_EVENT     = 8
RIP_EVENT                     = 9

DBG_CONTINUE                  = 0x00010002
DBG_TERMINATE_THREAD          = 0x40010003
DBG_TERMINATE_PROCESS         = 0x40010004
DBG_CONTROL_C                 = 0x40010005
DBG_CONTROL_BREAK             = 0x40010008
DBG_EXCEPTION_NOT_HANDLED     = 0x80010001
INFINITE                      = 0xFFFFFFFF  #Infinite timeout

STATUS_ACCESS_VIOLATION       = 0xC0000005
EXCEPTION_ACCESS_VIOLATION    = STATUS_ACCESS_VIOLATION
STATUS_BREAKPOINT             = 0x80000003
EXCEPTION_BREAKPOINT          = STATUS_BREAKPOINT
STATUS_GUARD_PAGE_VIOLATION   = 0x80000001
EXCEPTION_GUARD_PAGE          = STATUS_GUARD_PAGE_VIOLATION
STATUS_SINGLE_STEP            = 0x80000004
EXCEPTION_SINGLE_STEP         = STATUS_SINGLE_STEP


"""
NtQuerySystemInformation/SYSTEM_INFORMATION_CLASS
http://www.informit.com/articles/article.aspx?p=22442&seqNum=4
"""
SystemBasicInformation                  = 1     # 0x002C
SystemProcessorInformation              = 2     # 0x000C
SystemPerformanceInformation            = 3     # 0x0138
SystemTimeInformation                   = 4     # 0x0020
SystemPathInformation                   = 5     # not implemented
SystemProcessInformation                = 5    # 0x00F8 + per process
SystemCallInformation                   = 7     # 0x0018 + (n * 0x0004)
SystemConfigurationInformation          = 8     # 0x0018
SystemProcessorCounters                 = 9     # 0x0030 per cpu
SystemGlobalFlag                        = 10    # 0x0004
SystemInfo10                            = 11    # not implemented
SystemModuleInformation                 = 12    # 0x0004 + (n * 0x011C)
SystemLockInformation                   = 13    # 0x0004 + (n * 0x0024)
SystemInfo13                            = 14    # not implemented
SystemPagedPoolInformation              = 15    # checked build only
SystemNonPagedPoolInformation           = 16    # checked build only
SystemHandleInformation                 = 17    # 0x0004 + (n * 0x0010)
SystemObjectInformation                 = 18    # 0x0038+ + (n * 0x0030+)
SystemPagefileInformation               = 19    # 0x0018+ per page file
SystemInstemulInformation               = 20    # 0x0088
SystemInfo20                            = 21    # invalid info class
SystemCacheInformation                  = 22    # 0x0024
SystemPoolTagInformation                = 23    # 0x0004 + (n * 0x001C)
SystemProcessorStatistics               = 24    # 0x0000, or 0x0018 per cpu
SystemDpcInformation                    = 25    # 0x0014
SystemMemoryUsageInformation1           = 26    # checked build only
SystemLoadImage                         = 27    # 0x0018, set mode only
SystemUnloadImage                       = 28    # 0x0004, set mode only
SystemTimeAdjustmentInformation         = 29    # 0x000C, 0x0008 writeable
SystemMemoryUsageInformation2           = 30    # checked build only
SystemInfo30                            = 31    # checked build only
SystemInfo31                            = 32    # checked build only
SystemCrashDumpInformation              = 33    # 0x0004
SystemExceptionInformation              = 34    # 0x0010
SystemCrashDumpStateInformation         = 35    # 0x0008
SystemDebuggerInformation               = 36    # 0x0002
SystemThreadSwitchInformation           = 37    # 0x0030
SystemRegistryQuotaInformation          = 38    # 0x000C
SystemLoadDriver                        = 39    # 0x0008, set mode only
SystemPrioritySeparationInformation     = 40    # 0x0004, set mode only
SystemInfo40                            = 41    # not implemented
SystemInfo41                            = 42    # not implemented
SystemInfo42                            = 43    # invalid info class
SystemInfo43                            = 44    # invalid info class
SystemTimeZoneInformation               = 45    # 0x00AC
SystemLookasideInformation              = 46    # n * 0x0020
# info classes specific to Windows 2000
# WTS = Windows Terminal Server
SystemSetTimeSlipEvent                  = 47    # set mode only
SystemCreateSession                     = 48    # WTS, set mode only
SystemDeleteSession                     = 49    # WTS, set mode only
SystemInfo49                            = 50    # invalid info class
SystemRangeStartInformation             = 51    # 0x0004
SystemVerifierInformation               = 52    # 0x0068
SystemAddVerifier                       = 53    # set mode only
SystemSessionProcessesInformation       = 54    # WTS

"""
NtQueryInformationProcess/PROCESS_INFORMATION_CLASS
http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Process/PROCESS_INFORMATION_CLASS.html
"""
ProcessBasicInformation             = 0
ProcessQuotaLimits                  = 1
ProcessIoCounters                   = 2
ProcessVmCounters                   = 3
ProcessTimes                        = 4
ProcessBasePriority                 = 5
ProcessRaisePriority                = 6
ProcessDebugPort                    = 7
ProcessExceptionPort                = 8
ProcessAccessToken                  = 9
ProcessLdtInformation               = 10
ProcessLdtSize                      = 11
ProcessDefaultHardErrorMode         = 12
ProcessIoPortHandlers               = 13
ProcessPooledUsageAndLimits         = 14
ProcessWorkingSetWatch              = 15
ProcessUserModeIOPL                 = 16
ProcessEnableAlignmentFaultFixup    = 17
ProcessPriorityClass                = 18
ProcessWx86Information              = 19
ProcessHandleCount                  = 20
ProcessAffinityMask                 = 21
ProcessPriorityBoost                = 22

ProcessWow64Information             = 26
ProcessImageFileName                = 27

class SECURITY_ATTRIBUTES(Structure):

    """
    http://msdn.microsoft.com/en-us/library/windows/desktop/aa379560(v=vs.85).aspx
    """
    _fields_ = [
      ("nLength",               c_ulong),
      ("lpSecurityDescriptor",  c_void_p),
      ("bInheritHandle",        BOOL)
    ]

class LARGE_INTEGER_UNION(Structure):
   _fields_ = [
      ('LowPart',  c_long),
      ('HighPart', c_ulong),
   ]

class LARGE_INTEGER(Union):
   _fields_ = [
      ('u1', LARGE_INTEGER_UNION),
      ('u2', LARGE_INTEGER_UNION),
      ('QuadPart', c_longlong),
   ]

class UNICODE_STRING(Structure):
    _fields_ = [
        ("Length",          c_ushort),
        ("MaximumLength",   c_ushort),
        ("Buffer",          c_wchar_p),
    ]

class FILETIME(Structure):
   _fields_ = [('dwLowDateTime',c_ulong),
            ('dwHighDateTime',c_ulong),]

class CLIENT_ID(Structure):
    _fields_ = [
     ("UniqueProcess",                 c_void_p),
     ("UniqueThread",                  c_void_p)
   ]   

class VM_COUNTERS (Structure):

	is_64bit = maxsize > 2**32
	if is_64bit == True:

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

	else:
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
	   ]

class IO_COUNTERS(Structure):
    _fields_ = [
      ('ReadOperationCount',           c_ulonglong),
      ('WriteOperationCount',          c_ulonglong),
      ('OtherOperationCount',          c_ulonglong),
      ('ReadTransferCount',            c_ulonglong),
      ('WriteTransferCount',           c_ulonglong),
      ('OtherTransferCount',           c_ulonglong) 
   ]

class SYSTEM_THREAD_INFORMATION(Structure):
   _fields_ = [
      ('KernelTime',                   LARGE_INTEGER),
      ('UserTime',                     LARGE_INTEGER),
      ('CreateTime',                   LARGE_INTEGER),
      ('WaitTime',                     c_ulong),
      ('StartAddress',                 c_void_p),
      ('ClientID',                     CLIENT_ID),
      ('Priority',                     c_long),
      ('BasePriority',                 c_long),
      ('ContextSw',                    c_ulong),
      ('tstate',                       c_ulong),
      ('WaitReason',                   c_ulong)
   ]

class PROCESS_INFORMATION_BLOCK(Structure):
   _fields_ = [
      ('NextEntryOffset',              c_ulong),
      ('NumberOfThreads',              c_ulong),
      #('WorkingSetPrivateSize',        c_ulonglong),
      #('HardFaultCount',               c_ulong),
      #('NumberOfThreadsHighWaterMarks',c_ulong),
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

class VM_COUNTERS32 (Structure):
  
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
   ]

class PROCESS_INFORMATION_BLOCK32(Structure):
   _fields_ = [
      ('NextEntryOffset',              c_ulong),
      ('NumberOfThreads',              c_ulong),
      #('WorkingSetPrivateSize',        c_ulonglong),
      #('HardFaultCount',               c_ulong),
      #('NumberOfThreadsHighWaterMarks',c_ulong),
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
      ('VirtualMemoryCounters',        VM_COUNTERS32),
      ('PeakPagefileUsage',            c_ulong),
      ('PrivatePageCount',             c_ulong),
      ('IoCounters',                   IO_COUNTERS),
      ('th',                           c_ARRAY(SYSTEM_THREAD_INFORMATION, 10)),
   ]

"""class PROCESS_BASIC_INFORMATION(Structure):

	_fields_ = [

		('Reserved1', 					c_void_p),
		('PebBaseAddress', 				c_void_p),
		('Reserved2', 					c_void_p),
		('UniqueProcessId', 			POINTER(c_ulong)),
		('Reserved3', 					c_void_p),
	]"""

class PROCESS_BASIC_INFORMATION( Structure ):
    _fields_ = [
            ('ExitStatus',      c_void_p),
            ('PebBaseAddress',  c_void_p),
            ('AffinityMask',    c_void_p),
            ('BasePriority',    c_void_p),
            ('UniqueProcessId', c_void_p),
            ('InheritedFromUniqueProcessId', c_void_p)]
 
"""
typedef struct _LIST_ENTRY {
   struct _LIST_ENTRY *Flink;
   struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, *RESTRICTED_POINTER PRLIST_ENTRY;
"""
class LIST_ENTRY(Structure):
    _fields_ = [
        ("Flink",   c_void_p),     # POINTER(LIST_ENTRY)
        ("Blink",   c_void_p),     # POINTER(LIST_ENTRY)
]

"""
 typedef struct _LDR_MODULE
{
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID BaseAddress;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;
"""
class LDR_MODULE(Structure):
    _fields_ = [
        ("InLoadOrderModuleList",           LIST_ENTRY),
        ("InMemoryOrderModuleList",         LIST_ENTRY),
        ("InInitializationOrderModuleList", LIST_ENTRY),
        ("BaseAddress",                     c_void_p),
        ("EntryPoint",                      c_void_p),
        ("SizeOfImage",                     c_ulong),
        ("FullDllName",                     UNICODE_STRING),
        ("BaseDllName",                     UNICODE_STRING),
        ("Flags",                           c_ulong),
        ("LoadCount",                       c_short),
        ("TlsIndex",                        c_short),
        ("HashTableEntry",                  LIST_ENTRY),
        ("TimeDateStamp",                   c_ulong),
]



class STARTUPINFO(Structure):
    _fields_ = [
        ("cb",                  c_uint32),
        ("lpReserved",          POINTER(c_char)),
        ("lpDesktop",           POINTER(c_char)),
        ("lpTitle",             POINTER(c_char)),
        ("dwX",                 c_uint32),
        ("dwY",                 c_uint32),
        ("dwXSize",             c_uint32),
        ("dwYSize",             c_uint32),
        ("dwXCountChars",       c_uint32),
        ("dwYCountChars",       c_uint32),
        ("dwFillAttribute",     c_uint32),
        ("dwFlags",             c_uint32),
        ("wShowWindow",         c_ushort),
        ("cbReserved2",         c_ushort),
        ("lpReserved2",         POINTER(c_ubyte)),
        ("hStdInput",           wintypes.HANDLE),
        ("hStdOutput",          wintypes.HANDLE),
        ("hStdError",           wintypes.HANDLE)
    ]

class PROCESS_INFORMATION(Structure):
    """see:
    http://msdn.microsoft.com/en-us/library/windows/desktop/ms684873(v=vs.85).aspx
    """
    _fields_ = [
      ("hProcess",            wintypes.HANDLE),
      ("hThread",             wintypes.HANDLE),
      ("dwProcessId",         c_uint32),
      ("dwThreadId",          c_uint32)
    ]


class SYSTEM_INFO(Structure):
    _fields_ =[
        ('dwOemId',                     c_uint32),
        ('dwPageSize',                  c_uint32),
        ('lpMinimumApplicationAddress', c_void_p),
        ('lpMaximumApplicationAddress', c_void_p),
        ('dwActiveProcessorMask',       c_uint32),
        ('dwNumberOfProcessors',        c_uint32),
        ('dwProcessorType',             c_uint32),
        ('dwAllocationGranularity',     c_uint32),
        ('wProcessorLevel',             c_ushort),
        ('wProcessorRevision',          c_ushort),
    ]

class MEMORY_BASIC_INFORMATION32(Structure):
    _fields_ = [
        ("BaseAddress",         c_void_p),
        ("AllocationBase",      c_void_p),
        ("AllocationProtect",   c_uint32),
        ("RegionSize",          c_ulonglong),
        ("State",               c_uint32),
        ("Protect",             c_uint32),
        ("Type",                c_uint32)
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

class LDR_DATA_TABLE_ENTRY_BASE(Structure):

  _fields_ = [
      ("InLoadOrderLinks",                 LIST_ENTRY),
      ("InMemoryOrderLinks",               LIST_ENTRY),
      ("InInitializationOrderLinks",       LIST_ENTRY),
      ("DllBase",                          c_uint32),
      ("EntryPoint",                       c_uint32),
      ("SizeOfImage",                      c_ulong),
      ("FullDllName",                      UNICODE_STRING),
      ("BaseDllName",                      UNICODE_STRING),
      ("Flags",                            c_ulong),
      ("LoadCount",                        c_ushort),
      ("TlsIndex",                         c_ushort),
      ("LoadCount",                        LIST_ENTRY),
      ("LoadCount",                        c_ulong),
      ("LoadCount",                        c_uint32),
      ("LoadCount",                        c_uint32)
  ]

class PEB_LDR_DATA(Structure):
  """
  +0x000 Length                          : ULONG
  +0x004 Initialized                     : BOOLEAN
  +0x008 SsHandle                        : HANDLE
  +0x00c InLoadOrderModuleList           : LIST_ENTRY
  +0x014 InMemoryOrderModuleList         : LIST_ENTRY
  +0x01C InInitializationOrderModuleList : _LIST_ENTRY

  typedef struct _PEB_LDR_DATA {
      ULONG Length;
      BOOLEAN Initialized;
      HANDLE SsHandle;
      LIST_ENTRY InLoadOrderModuleList;
      LIST_ENTRY InMemoryOrderModuleList;
      LIST_ENTRY InInitializationOrderModuleList;
      PVOID EntryInProgress;
      BOOLEAN ShutdownInProgress;
      HANDLE ShutdownThreadId;
  } PEB_LDR_DATA, *PPEB_LDR_DATA;

  struct _PEB_LDR_DATA2
  {
      unsigned long Length;
      unsigned char Initialized;
      T SsHandle;
      _LIST_ENTRY_T<T> InLoadOrderModuleList;
      _LIST_ENTRY_T<T> InMemoryOrderModuleList;
      _LIST_ENTRY_T<T> InInitializationOrderModuleList;
      T EntryInProgress;
      unsigned char ShutdownInProgress;
      T ShutdownThreadId;
  };

  """
  _fields_ = [
      ("Length",                          c_ulong),
      ("Initialized",                     c_ubyte),
      ("SsHandle",                        c_void_p),
      ("InLoadOrderModuleList",           LIST_ENTRY),
      ("InMemoryOrderModuleList",         LIST_ENTRY),
      ("InInitializationOrderModuleList", LIST_ENTRY)
]

class PEB(Structure):
  """
  +0x000 InheritedAddressSpace    : UChar
  +0x001 ReadImageFileExecOptions : UChar
  +0x002 BeingDebugged            : UChar
  +0x003 SpareBool                : UChar
  +0x004 Mutant                   : Ptr32 Void
  +0x008 ImageBaseAddress         : Ptr32 Void
  +0x00c Ldr                      : Ptr32 _PEB_LDR_DATA
  +0x010 processparameter

  typedef struct _PEB {
      BYTE Reserved1[2];
      BYTE BeingDebugged;
      BYTE Reserved2[1];
      PVOID Reserved3[2];
      PPEB_LDR_DATA Ldr;
      PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
      PVOID Reserved4[3];
      PVOID AtlThunkSListPtr;
      PVOID Reserved5;
      ULONG Reserved6;
      PVOID Reserved7;
      ULONG Reserved8;
      ULONG AtlThunkSListPtr32;
      PVOID Reserved9[45];
      BYTE Reserved10[96];
      PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
      BYTE Reserved11[128];
      PVOID Reserved12[1];
      ULONG SessionId;
  } PEB, *PPEB;
  """
  _fields_ = [
        ("InheritedAddressSpace",     c_byte),
        ("ReadImageFileExecOptions",  c_byte),
        ("BeingDebugged",             c_byte),
        ("SpareBool",                 c_byte),
        ("Mutant",                    c_void_p),
        ("ImageBaseAddress",          c_void_p),
        ("Ldr",                       PEB_LDR_DATA),
]



# Hardware breakpoint conditions
HW_ACCESS                      = 0x00000003
HW_EXECUTE                     = 0x00000000
HW_WRITE                       = 0x00000001

# Constants
DEBUG_PROCESS         = 0x00000001
CREATE_NEW_CONSOLE    = 0x00000010
PROCESS_ALL_ACCESS    = 0x001F0FFF
INFINITE              = 0xFFFFFFFF
DBG_CONTINUE          = 0x00010002


# Debug event constants
EXCEPTION_DEBUG_EVENT      =    0x1
CREATE_THREAD_DEBUG_EVENT  =    0x2
CREATE_PROCESS_DEBUG_EVENT =    0x3
EXIT_THREAD_DEBUG_EVENT    =    0x4
EXIT_PROCESS_DEBUG_EVENT   =    0x5
LOAD_DLL_DEBUG_EVENT       =    0x6
UNLOAD_DLL_DEBUG_EVENT     =    0x7
OUTPUT_DEBUG_STRING_EVENT  =    0x8
RIP_EVENT                  =    0x9

# debug exception codes.
EXCEPTION_ACCESS_VIOLATION     = 0xC0000005
EXCEPTION_BREAKPOINT           = 0x80000003
EXCEPTION_GUARD_PAGE           = 0x80000001


# debug event 
# UINT_PTR c_ulong

# When the dwDebugEventCode is evaluated
class EXCEPTION_RECORD(Structure):
    pass
EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode",        c_ulong),
    ("ExceptionFlags",       c_ulong),
    ("ExceptionRecord",      POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress",     c_void_p),
    ("NumberParameters",     c_ulong),
    ("ExceptionInformation", c_ulong * 15),
    ]
# Exceptions
class EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [
        ("ExceptionRecord",    EXCEPTION_RECORD),
        ("dwFirstChance",      c_ulong),
        ]
# it populates this union appropriately
class DEBUG_EVENT_UNION(Union):
    _fields_ = [
        ("Exception",         EXCEPTION_DEBUG_INFO),
#        ("CreateThread",      CREATE_THREAD_DEBUG_INFO),
#        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
#        ("ExitThread",        EXIT_THREAD_DEBUG_INFO),
#        ("ExitProcess",       EXIT_PROCESS_DEBUG_INFO),
#        ("LoadDll",           LOAD_DLL_DEBUG_INFO),
#        ("UnloadDll",         UNLOAD_DLL_DEBUG_INFO),
#        ("DebugString",       OUTPUT_DEBUG_STRING_INFO),
#        ("RipInfo",           RIP_INFO),
        ]  
# DEBUG_EVENT describes a debugging event
# that the debugger has trapped
class DEBUG_EVENT(Structure):
    _fields_ = [
        ("dwDebugEventCode", c_ulong),
        ("dwProcessId",      c_ulong),
        ("dwThreadId",       c_ulong),
        ("u",                DEBUG_EVENT_UNION),
        ]
