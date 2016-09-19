"""
name        : pattern.py
author      : hakbaby
function    : pattern scan (string, byte and bytes)
"""

from common.address import *
from common.process import *

import binascii
import struct
import re

class Pattern(object):

    def __init__(self, logger, process, end_offset = None, start_offset = None):

        self.process = process
        self.logger = logger

        sysinfo = SYSTEM_INFO()
        windll.kernel32.GetSystemInfo(byref(sysinfo))

        if end_offset:
            self.end_offset = end_offset
        else:
            if self.process.winapi.targettype == False: 
                self.end_offset=0x7FFFFFFF
            else:
                self.end_offset = sysinfo.lpMaximumApplicationAddress
        if start_offset:
            self.start_offset = start_offset
        else:
            self.start_offset = sysinfo.lpMinimumApplicationAddress

    def re_to_unicode(self, s):
        newstring = ''
        for c in s:
            newstring += re.escape(c) + '\\x00'
        return newstring

    def Address(self, value, default_type = 'uint'):
        return Address(value, process=self.process, default_type=default_type)

    def search_address(self, address):
        address = int(address)
        for m in self.process.list_modules():
            for addr in self.mem_search(address, ftype='ulong', start_offset=m.modBaseAddr, end_offset=m.modBaseSize):
                logger.debug('found module %s => addr %s' % (m.szModule, addr))

    def umem_replace(self, regex, replace):
        """ like search_replace_mem but works with unicode strings """
        regex = self.re_to_unicode(regex)
        replace = replace.encode('utf-16-le')
        return self.mem_replace(re.compile(regex, re.UNICODE), replace)

    def mem_replace(self, regex, replace):
        """ search memory for a pattern and replace all found occurrences """
        allWritesSucceed = True
        for start_offset in self.mem_search(regex, ftype='re'):
            if self.process.write_bytes(start_offset, replace) == 1:
                logger.debug('Write at offset %s succeeded !' % start_offset)
            else:
                allWritesSucceed = False
                logger.debug('Write at offset %s failed !' % start_offset)

        return allWritesSucceed

    def umem_search(self, regex):
        regex = self.re_to_unicode(regex)
        for i in self.mem_search(str(regex), ftype='re'):
            yield i

    def pattern_search(self, data, offset, binary):

        for i in range(0, len(binary)):
            if binary[i] != 'x' and binary[i] != int(binascii.b2a_hex(str(data[i+offset])), 16):
                return False

        return True

    def group_search(self, group, start_offset = None, end_offset = None):
        regex = ''
        for value, type in group:
            if type == 'f' or type == 'float':
                f = struct.pack('<f', float(value))
                regex += '..' + f[2:4]
            else:
                logger.debug('unknown type checking')

        return self.mem_search(regex, ftype='re', start_offset=start_offset, end_offset=end_offset)

    def search_address(self, addr):
        a = '%08X' % addr
        logger.debug('searching address %s' % a)
        regex = ''
        for i in range(len(a) - 2, -1, -2):
            regex += binascii.unhexlify(a[i:i + 2])

        return self.mem_search(re.escape(regex), ftype='re')

    def mem_search(self, value, ftype = 'match', protec = PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ, start_offset = None, end_offset = None, multiple=False):
        ftype = ftype.lower().strip()
        if type(value) is list:
            ftype = 'group'
        if ftype == 're':
            if type(value) is str:
                regex = re.compile(value)
            else:
                regex = value
        if start_offset is None:
            offset = self.start_offset
        else:
            offset = start_offset
        if end_offset is None:
            end_offset = self.end_offset
        if ftype == 'float':
            structtype, structlen = type_unpack(ftype)
        elif ftype == 'byte':
            protec = PAGE_EXECUTE_READ | PAGE_READONLY
            index = 0
            value_byte = []
            while True:
                if index >= len(value):
                    break
                if value[index] == ' ':
                    index += 1
                if (value[index] =='?') and (value[index+1] =='?'):
                    index += 2
                    value_byte.append('x')
                    continue
                value_byte.append(int(value[index]+value[index+1], 16))
                index += 2

        elif ftype != 'match' and ftype != 'group' and ftype != 're':
            structtype, structlen = type_unpack(ftype)
            value = struct.pack(structtype, value)

        while True:

            if offset >= end_offset:
                break
            totalread = 0
            mbi = self.process.winapi.VirtualQueryEx(offset)
            offset = mbi.BaseAddress
            chunk = mbi.RegionSize
            protect = mbi.Protect
            state = mbi.State

            if state & MEM_FREE or state & MEM_RESERVE:
                offset += chunk
                continue
            if protec:
                if not protect & protec or protect & PAGE_NOCACHE or protect & PAGE_WRITECOMBINE or protect & PAGE_GUARD:
                    offset += chunk
                    continue
            b = ''

            try:
                b = self.process.read_bytes(offset, chunk)
                totalread = len(b)
            except Exception as e:
                print ">>>", e
                offset += chunk
                continue

            if b:

                if ftype == 're':
                    duplicates_cache = set()
                    for res in regex.findall(b):
                        index = b.find(res)
                        while index != -1:
                            soffset = offset + index
                            if soffset not in duplicates_cache:
                                duplicates_cache.add(soffset)
                                yield self.Address(soffset, 'bytes')
                            index = b.find(res, index + len(res))

                elif ftype == 'float':
                    for index in range(0, len(b)):
                        try:
                            tmpval = struct.unpack(structtype, b[index:index + 4])[0]
                            if int(value) == int(tmpval):
                                soffset = offset + index
                                yield self.Address(soffset, 'float')
                        except Exception as e:
                            pass

                elif ftype == 'byte':
                    for index in range(0, len(b)):
                        try:
                            if self.pattern_search(b, index, value_byte) == True:
                                soffset = offset + index
                                if multiple == False:
                                    yield self.Address(soffset, 'bytes')
                                    return 
                                else:
                                    yield self.Address(soffset, 'bytes')
                        except Exception as e:
                            print e
                            pass

                else:
                    index = b.find(value)
                    while index != -1:
                        soffset = offset + index
                        #print soffset
                        yield self.Address(soffset, 'bytes')
                        index = b.find(value, index + 1)

            offset += totalread