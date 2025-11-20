#!/usr/bin/env python3
from struct import unpack


class BinaryReader(object):

    def __init__(self, data):
        self.data = data
        self.cursor = 0

    def _check_eof(self, size):
        if self.cursor + size > len(self.data):
            raise EOFError('Attempted to read past the end of internal data buffer')

    def _read_internal(self, fmt, size):
        self._check_eof(size)
        data_to_unpack = self.data[self.cursor:self.cursor + size]
        self.cursor += size
        return unpack(fmt, data_to_unpack)[0]

    def read_uint8(self):
        return self._read_internal('<B', 1)

    def read_uint16(self):
        return self._read_internal('<H', 2)

    def read_uint32(self):
        return self._read_internal('<L', 4)

    def read_uint64(self):
        return self._read_internal('<Q', 8)

    def read_int8(self):
        return self._read_internal('<b', 1)

    def read_int16(self):
        return self._read_internal('<h', 2)

    def read_int32(self):
        return self._read_internal('<l', 4)

    def read_int64(self):
        return self._read_internal('<q', 8)

    def read_bytes(self, size=-1):
        if size < 0:
            data = self.data[self.cursor:]
        else:
            self._check_eof(size)
            data = self.data[self.cursor:self.cursor + size]

        self.cursor += len(data)
        return data
