"""
name        : address.py
author      : hakbaby
function    : manage read address
"""

from subsystem.define import *

import subsystem.x86
import subsystem.x64
import subsystem.wow64

def hex_dump(data, addr = 0, prefix = '', ftype = 'bytes'):

    dump = prefix
    slice = ''
    if ftype != 'bytes':
        structtype, structlen = type_unpack(ftype)
        for i in range(0, len(data), structlen):
            if addr % 16 == 0:
                dump += ' '
                for char in slice:
                    if ord(char) >= 32 and ord(char) <= 126:
                        dump += char
                    else:
                        dump += '.'

                dump += '\n%s%08X: ' % (prefix, addr)
                slice = ''
            tmpval = 'NaN'
            try:
                packedval = data[i:i + structlen]
                tmpval = struct.unpack(structtype, packedval)[0]
            except Exception as e:
                print e

            if tmpval == 'NaN':
                dump += '{:<15} '.format(tmpval)
            elif ftype == 'float':
                dump += '{:<15.4f} '.format(tmpval)
            else:
                dump += '{:<15} '.format(tmpval)
            addr += structlen

    else:
        for byte in data:
            if addr % 16 == 0:
                dump += ' '
                for char in slice:
                    if ord(char) >= 32 and ord(char) <= 126:
                        dump += char
                    else:
                        dump += '.'

                dump += '\n%s%08X: ' % (prefix, addr)
                slice = ''
            dump += '%02X ' % ord(byte)
            slice += byte
            addr += 1

    remainder = addr % 16
    if remainder != 0:
        dump += '   ' * (16 - remainder) + ' '
    for char in slice:
        if ord(char) >= 32 and ord(char) <= 126:
            dump += char
        else:
            dump += '.'

    return dump + '\n'


class AddressException(Exception):
    pass

class Address(object):

    def __init__(self, value, process, default_type = 'uint'):
        self.value = int(value)
        self.process = process
        self.default_type = default_type
        self.symbolic_name = None

    def read(self, type = None, maxlen = None):
        if maxlen is None:
            try:
                int(type)
                maxlen = int(type)
                type = None
            except:
                pass

        if not type:
            type = self.default_type
        if not maxlen:
            return self.process.read(self.value, type=type)
        else:
            return self.process.read(self.value, type=type, maxlen=maxlen)

    def write(self, data, type = None):
        if not type:
            type = self.default_type
        return self.process.write(self.value, data, type=type)

    def symbol(self):
        return self.process.get_symbolic_name(self.value)

    def get_instruction(self):
        return self.process.get_instruction(self.value)

    def dump(self, ftype = 'bytes', size = 512, before = 32):
        buf = self.process.read_bytes(self.value - before, size)
        print utils.hex_dump(buf, self.value - before, ftype=ftype)

    def __nonzero__(self):
        return self.value is not None and self.value != 0

    def __add__(self, other):
        return Address(self.value + int(other), self.process, self.default_type)

    def __sub__(self, other):
        return Address(self.value - int(other), self.process, self.default_type)

    def __repr__(self):
        if not self.symbolic_name:
            self.symbolic_name = self.symbol()
        return str('<Addr: %s' % self.symbolic_name + '>')

    def __str__(self):
        if not self.symbolic_name:
            self.symbolic_name = self.symbol()
        return str('<Addr: %s' % self.symbolic_name + ' : "%s" (%s)>' % (str(self.read()).encode('string_escape'), self.default_type))

    def __int__(self):
        return int(self.value)

    def __hex__(self):
        return hex(self.value)

    def __get__(self, instance, owner):
        return self.value

    def __set__(self, instance, value):
        self.value = int(value)

    def __lt__(self, other):
        return self.value < int(other)

    def __le__(self, other):
        return self.value <= int(other)

    def __eq__(self, other):
        return self.value == int(other)

    def __ne__(self, other):
        return self.value != int(other)

    def __gt__(self, other):
        return self.value > int(other)

    def __ge__(self, other):
        return self.value >= int(other)

