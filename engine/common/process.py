"""
name        : process.py
author      : hakbaby
function    : access other process's memory and read/write
"""

from subsystem.winapi import *
from address import *

import os

def type_unpack(type):
    """ return the struct and the len of a particular type """
    type = type.lower()
    s = None
    l = None
    if type == 'short':
        s = 'h'
        l = 2
    elif type == 'ushort':
        s = 'H'
        l = 2
    elif type == 'int':
        s = 'i'
        l = 4
    elif type == 'uint':
        s = 'I'
        l = 4
    elif type == 'long':
        s = 'l'
        l = 4
    elif type == 'ulong':
        s = 'L'
        l = 4
    elif type == 'float':
        s = 'f'
        l = 4
    elif type == 'double':
        s = 'd'
        l = 8
    else:
        raise TypeError('Unknown type %s' % type)
    return ('<' + s, l)

class ProcessException(Exception):
    pass

class Process(object):
    
    """Accessing Target Process"""

    def __init__(self, ProcessName=None):

        self.winapi = WindowsAPI(ProcessName)
        self.ProcessName = self.winapi.ProcessName
        self.ProcessId = self.winapi.ProcessId
        self.ProcessHandle = self.winapi.ProcessHandle

    def PELoad(self):

        self.PEInfo = pefile.PE(self.winapi.GetModuleFileNameEx())

    def write_bytes(self, address, data):
        address = int(address)
        buffer = create_string_buffer(data)
        sizeWriten = c_ulong(0)
        bufferSize = sizeof(buffer) - 1
        _address = address
        _length = bufferSize + 1
        try:
            old_protect = self.winapi.VirtualProtectEx(_address, _length, PAGE_EXECUTE_READWRITE)
        except:
            pass

        res = self.winapi.WriteProcessMemory(address, buffer, bufferSize, byref(sizeWriten))
        try:
            self.winapi.VirtualProtectEx(_address, _length, old_protect)
        except:
            pass

        return res

    def write_binary(self, address, data):

        if self.winapi.targettype == False:
            count = c_uint32(0)
        else:
            count = c_uint64(0)

        length = len(data)
        lpBuffer = create_string_buffer(data[count.value:])

        self.winapi.VirtualProtectEx(address, size=0x10) # Why not used "PAGE_EXECUTE_READWRITE"

        res = self.winapi.WriteProcessMemory(address, lpBuffer, length, byref(count))
        return res

    def read_bytes(self, address, bytes = 4):
    	#print bytes
        address = int(address)
        buffer = create_string_buffer(bytes)

        if self.winapi.targettype == False:
        	bytesread = c_uint32(0)
        else:
        	bytesread = c_uint64(0)

        data = ''
        length = bytes
        _address = address
        _length = length
        while length:

            if not self.winapi.ReadProcessMemory(self.ProcessHandle, address, buffer, bytes, bytesread):
                if bytesread.value:
                    data += buffer.raw[:bytesread.value]
                    length -= bytesread.value
                    address += bytesread.value
                if not len(data):
                    raise ProcessException('Error %s in ReadProcessMemory(%08x, %d, read=%d)' % (win32api.GetLastError(),
                     address,
                     length,
                     bytesread.value))
                return data
            data += buffer.raw[:bytesread.value]
            length -= bytesread.value
            address += bytesread.value

        return data

    def read_binary(self, address, size = 4):

        lpBuffer = create_string_buffer(size)

        if self.winapi.targettype == False:
            bytesread = c_uint32(0)
        else:
            bytesread = c_uint64(0)

        self.winapi.ReadProcessMemory(self.ProcessHandle, address, lpBuffer, size, bytesread)

        return lpBuffer.raw

    def read(self, address, type = 'uint', maxlen = 50):
 
        if type == 's' or type == 'string':
            s = self.read_bytes(int(address), bytes=maxlen)
            news = ''
            for c in s:
                if c == '\x00':
                    return news
                news += c

            raise ProcessException('string > maxlen')
        elif type == 'binary':
            return self.read_binary(address, maxlen)
        else:
            #print maxlen
            if type == 'bytes' or type == 'b':
                return self.read_bytes(int(address), bytes=maxlen)
            s, l = type_unpack(type)
            return struct.unpack(s, self.read_bytes(int(address), bytes=l))[0]

    def write(self, address, data, type = 'uint'):

        if type == 'binary':
            return self.write_binary(address, data)

        elif type != 'bytes':
            s, l = type_unpack(type)
            return self.write_bytes(int(address), struct.pack(s, data))

        else:
            return self.write_bytes(int(address), data)

    def get_symbolic_name(self, address):

        for module in self.winapi.EnumProcessModule():
            if int(module.DllBase) <= int(address) < int(module.DllBase + module.SizeOfImage):
                filename = os.path.basename(self.winapi.GetModuleFileNameEx(module.DllBase))
                return '%s+0x%08X' % (filename, int(address) - module.DllBase)

        return '0x%08X' % int(address)

    def getInstruction(self, address, data):
        """
        using distorm3
        """
        try:
            data = self.read_bytes(int(address), 32)
        except:
            return 'Unable to disassemble at %08x' % address

        return self.winapi.Distorm3Decoder(address, data)
