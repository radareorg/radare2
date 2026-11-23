#!/usr/bin/env python3
"""Exercise ext2 forensic APIs with compact images and damaged metadata."""
import ctypes as C
import gzip
import os
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
SUFFIX = 'dylib' if sys.platform == 'darwin' else 'so'
fs = C.CDLL(str(os.environ.get('R2_FS_LIB', ROOT / f'libr/fs/libr_fs.{SUFFIX}')))

class Binding(C.Structure):
    _fields_ = [('init', C.c_int)] + [(name, C.c_void_p) for name in (
        'io', 'desc_use', 'desc_get', 'desc_info', 'desc_size', 'open',
        'open_at', 'close', 'read_at')]

class File(C.Structure):
    _fields_ = [('name', C.c_void_p), ('path', C.c_void_p), ('off', C.c_uint64),
                ('id', C.c_uint64), ('size', C.c_uint64), ('flags', C.c_uint32),
                ('type', C.c_char), ('data', C.c_void_p)]

class Range(C.Structure):
    _fields_ = [('logical', C.c_uint64), ('physical', C.c_uint64),
                ('size', C.c_uint64), ('flags', C.c_uint32)]

Callback = C.CFUNCTYPE(C.c_bool, C.POINTER(Range), C.c_void_p)
ReadAt = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_uint64, C.c_void_p, C.c_int)

def api(name, result, *args):
    func = getattr(fs, name)
    func.restype, func.argtypes = result, args
    return func

new = api('r_fs_new', C.c_void_p)
free = api('r_fs_free', None, C.c_void_p)
mount = api('r_fs_mount', C.c_void_p, C.c_void_p, C.c_char_p, C.c_char_p, C.c_uint64)
open_id = api('r_fs_open_id', C.c_void_p, C.c_void_p, C.c_char_p, C.c_uint64, C.c_uint32)
open_file = api('r_fs_open', C.c_void_p, C.c_void_p, C.c_char_p, C.c_bool)
read = api('r_fs_read', C.c_int, C.c_void_p, C.c_void_p, C.c_uint64, C.c_int)
close = api('r_fs_close', None, C.c_void_p, C.c_void_p)
free_file = api('r_fs_file_free', None, C.c_void_p)
extents = api('r_fs_extents', C.c_int, C.c_void_p, Callback, C.c_void_p)
original = gzip.decompress((ROOT / 'test/bins/fs/ext2-forensic/recovery.img.gz').read_bytes())


def check(label, change=None, wanted=1, prefix=18432, conflict=False, flags=2, verify_data=True, delta=0, expected_data=None):
    image = bytearray(original)
    table = struct.unpack_from('<I', image, 2048 + 8)[0] * 1024
    inode = table + 12 * 128
    first = struct.unpack_from('<I', image, inode + 40)[0]
    indirect = struct.unpack_from('<I', image, inode + 88)[0]
    if change:
        change(image, table, inode, first, indirect)
    image = bytearray(delta) + image
    buffer = (C.c_ubyte * len(image)).from_buffer(image)
    @ReadAt
    def read_at(_, offset, destination, length):
        if offset > len(image) or length < 0 or length > len(image) - offset:
            return -1
        C.memmove(destination, C.addressof(buffer) + offset, length)
        return length
    filesystem = new()
    binding = Binding.from_address(filesystem)
    binding.init = 1
    binding.read_at = C.cast(read_at, C.c_void_p).value
    handle = None
    try:
        assert mount(filesystem, b'ext2', b'/ext2', delta)
        handle = open_id(filesystem, b'/ext2', 13, flags)
        assert handle
        runs = []
        @Callback
        def collect(pointer, _):
            item = pointer.contents
            runs.append((item.logical, item.physical, item.size, item.flags))
            return True
        assert extents(handle, collect, None) == wanted, label
        assert sum(item[2] for item in runs) == prefix, (label, runs)
        assert bool(File.from_address(handle).flags & 8) == conflict, label
        if flags & 1:
            assert File.from_address(handle).flags & 2
            assert all(item[3] & 32 for item in runs)
        assert all(item[1] == 0xffffffffffffffff or item[1] >= delta for item in runs)
        if prefix:
            assert read(filesystem, handle, 0, prefix) == prefix, label
            if verify_data:
                assert C.string_at(File.from_address(handle).data, prefix) == (expected_data if expected_data is not None else b'Recover ext2 data\n' * 1024)[:prefix]
        if wanted == -1:
            assert read(filesystem, handle, prefix, 1) == -1, label
        print('PASS:', label)
    finally:
        if handle:
            close(filesystem, handle)
            free_file(handle)
        free(filesystem)

check('retained direct and indirect data')
check('live inode ownership despite a clear allocation bit',
      lambda image, table, inode, first, indirect: struct.pack_into('<I', image, table + 11 * 128 + 40, first),
      wanted=-1, prefix=0, conflict=True)
check('out of range indirect pointer preserves direct prefix',
      lambda image, table, inode, first, indirect: struct.pack_into('<I', image, inode + 88, 512),
      wanted=-1, prefix=12288)

check('self-referential indirect map preserves the direct prefix',
      lambda image, table, inode, first, indirect: struct.pack_into('<I', image, indirect * 1024, indirect),
      wanted=-1, prefix=12288)


def set_bit(image, bitmap, index, value=True):
    byte, mask = bitmap * 1024 + index // 8, 1 << (index % 8)
    image[byte] = (image[byte] | mask) if value else (image[byte] & ~mask)

check('allocated deleted data is rejected',
      lambda image, table, inode, first, indirect: set_bit(image, struct.unpack_from('<I', image, 2048)[0], first - 1),
      wanted=-1, prefix=0, conflict=True)
check('reused indirect block retains only the direct prefix',
      lambda image, table, inode, first, indirect: struct.pack_into('<I', image, table + 11 * 128 + 40, indirect),
      wanted=-1, prefix=12288, conflict=True)

def cleared_inode_bit(image, table, inode, first, indirect):
    struct.pack_into('<I', image, table + 11 * 128 + 40, first)
    set_bit(image, struct.unpack_from('<I', image, 2052)[0], 11, False)

check('live inode ownership survives a cleared inode bitmap bit', cleared_inode_bit,
      wanted=-1, prefix=0, conflict=True)
check('cleared indirect pointers are not asserted to be sparse holes',
      lambda image, table, inode, first, indirect: struct.pack_into('<I', image, inode + 88, 0),
      wanted=-1, prefix=12288)
check('explicit contiguous recovery is marked heuristic', flags=3, verify_data=False)
check('recovery physical offsets include the mount delta', delta=4096)
check('inode recovery remains available with a damaged root directory',
      lambda image, table, inode, first, indirect: struct.pack_into('<H', image,
          struct.unpack_from('<I', image, table + 128 + 40)[0] * 1024 + 4, 0))


def fast_link(image, table, inode, first, indirect):
    struct.pack_into('<H', image, inode, 0xa1ff)
    struct.pack_into('<I', image, inode + 4, 4)
    struct.pack_into('<I', image, inode + 28, 0)
    image[inode + 40:inode + 100] = b'live' + bytes(56)

check('deleted fast symlink target is recovered from its inode', fast_link, prefix=4, expected_data=b'live')

check('repeated data blocks stop at the first duplicate',
      lambda image, table, inode, first, indirect: struct.pack_into('<I', image, inode + 44, first),
      wanted=-1, prefix=1024)


def check_sparse(source=None, wanted_size=0x100000011, tail=None):
    image = bytearray(source if source is not None else gzip.decompress((ROOT / 'test/bins/fs/ext2-large/large.img.gz').read_bytes()))
    buffer = (C.c_ubyte * len(image)).from_buffer(image)
    reads = []
    @ReadAt
    def read_at(_, offset, destination, length):
        reads.append((offset, length))
        if offset > len(image) or length < 0 or length > len(image) - offset:
            return -1
        C.memmove(destination, C.addressof(buffer) + offset, length)
        return length
    filesystem = new()
    binding = Binding.from_address(filesystem)
    binding.init = 1
    binding.read_at = C.cast(read_at, C.c_void_p).value
    handle = None
    try:
        assert mount(filesystem, b'ext2', b'/ext2', 0)
        handle = open_id(filesystem, b'/ext2', 13, 2) if source is not None else open_file(filesystem, b'/ext2/large', False)
        assert handle
        runs = []
        @Callback
        def collect(pointer, _):
            item = pointer.contents
            runs.append((item.logical, item.physical, item.size, item.flags))
            return True
        reads.clear()
        assert extents(handle, collect, None) == 1
        assert sum(item[2] for item in runs) == wanted_size
        assert any(item[1] == 0xffffffffffffffff and item[3] & 64 for item in runs)
        assert len(reads) < 100, len(reads)
        assert sum(item[1] for item in reads) < 32768, reads
        if tail:
            offset, expected = tail
            assert read(filesystem, handle, offset, len(expected)) == len(expected)
            assert C.string_at(File.from_address(handle).data, len(expected)) == expected
        print('PASS:', 'triple indirect deleted sparse data' if source is not None else 'sparse extents above 4 GiB skip empty indirect subtrees')
    finally:
        if handle:
            close(filesystem, handle)
            free_file(handle)
        free(filesystem)

check_sparse()

triple = bytearray(original)
table = struct.unpack_from('<I', triple, 2056)[0] * 1024
inode = table + 12 * 128
first = struct.unpack_from('<I', triple, inode + 40)[0]
triple_offset = (12 + 256 + 256 * 256) * 1024
struct.pack_into('<I', triple, inode + 4, triple_offset + 1024)
struct.pack_into('<I', triple, inode + 28, 8)
triple[inode + 40:inode + 100] = bytes(60)
struct.pack_into('<I', triple, inode + 96, 400)
for block, next_block in ((400, 401), (401, 402), (402, first)):
    triple[block * 1024:(block + 1) * 1024] = bytes(1024)
    struct.pack_into('<I', triple, block * 1024, next_block)
check_sparse(triple, triple_offset + 1024, (triple_offset, b'Recover ext2 data\n'))

ranges = api('r_fs_ranges', C.c_int, C.c_void_p, C.c_char_p, C.c_uint32, Callback, C.c_void_p)
dir_list = api('r_fs_dir', C.c_void_p, C.c_void_p, C.c_char_p, C.c_uint64, C.c_int)
list_length = api('r_list_length', C.c_int, C.c_void_p)
list_n = api('r_list_get_n', C.c_void_p, C.c_void_p, C.c_int)
list_free = api('r_list_free', None, C.c_void_p)


def check_inspection(label, change, flags, wanted, expected):
    image = bytearray(original)
    change(image)
    buffer = (C.c_ubyte * len(image)).from_buffer(image)
    @ReadAt
    def read_at(_, offset, destination, length):
        if offset > len(image) or length < 0 or length > len(image) - offset:
            return -1
        C.memmove(destination, C.addressof(buffer) + offset, length)
        return length
    filesystem = new()
    binding = Binding.from_address(filesystem)
    binding.init = 1
    binding.read_at = C.cast(read_at, C.c_void_p).value
    try:
        assert mount(filesystem, b'ext2', b'/ext2', 0)
        found = []
        @Callback
        def collect(pointer, _):
            item = pointer.contents
            found.append((item.logical, item.physical, item.size, item.flags))
            return True
        assert ranges(filesystem, b'/ext2', flags, collect, None) == wanted
        assert found == expected, (label, found)
        entries = dir_list(filesystem, b'/ext2', 0, 2)
        assert entries and list_length(entries) == 1
        entry = File.from_address(list_n(entries, 0))
        assert entry.id == 13 and C.string_at(entry.name) == b'inode-13'
        list_free(entries)
        print('PASS:', label)
    finally:
        free(filesystem)

check_inspection('allocated blocks without live owners are orphan ranges',
                 lambda image: set_bit(image, struct.unpack_from('<I', image, 2048)[0], 499),
                 4, 1, [(500 * 1024, 500 * 1024, 1024, 6)])

def mark_bad(image):
    table = struct.unpack_from('<I', image, 2056)[0] * 1024
    struct.pack_into('<I', image, table + 28, 2)
    struct.pack_into('<I', image, table + 40, 500)

check_inspection('bad block inode classifies bad storage', mark_bad,
                 8, 1, [(500 * 1024, 500 * 1024, 1024, 8)])
check_inspection('unreadable allocation bitmap reports unknown storage',
                 lambda image: struct.pack_into('<I', image, 2048, 0),
                 16, -1, [(1024, 1024, 511 * 1024, 16)])
