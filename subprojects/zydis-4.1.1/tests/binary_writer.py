#!/usr/bin/env python3
from struct import pack


class BinaryWriter(object):

    def __init__(self):
        self.data = b''

    def _write_internal(self, fmt, val):
        self.data += pack(fmt, val)
        return self

    def write_uint8(self, val):
        return self._write_internal('<B', val)

    def write_uint16(self, val):
        return self._write_internal('<H', val)

    def write_uint32(self, val):
        return self._write_internal('<L', val)

    def write_uint64(self, val):
        return self._write_internal('<Q', val)

    def write_int8(self, val):
        return self._write_internal('<b', val)

    def write_int16(self, val):
        return self._write_internal('<h', val)

    def write_int32(self, val):
        return self._write_internal('<l', val)

    def write_int64(self, val):
        return self._write_internal('<q', val)

    def write_bytes(self, data):
        self.data += bytes(data)
        return self

    def write_padding(self, size, padding_byte=b'\x00'):
        self.write_bytes(padding_byte * size)

    def get_data(self):
        return self.data
