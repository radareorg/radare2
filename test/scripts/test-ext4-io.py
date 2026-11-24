#!/usr/bin/env python3
"""Check native ext4 recovery, allocation claims and damaged metadata."""
import ctypes as C
import gzip
import os
from pathlib import Path
import struct
import subprocess
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
read = api('r_fs_read', C.c_int, C.c_void_p, C.c_void_p, C.c_uint64, C.c_int)
close = api('r_fs_close', None, C.c_void_p, C.c_void_p)
free_file = api('r_fs_file_free', None, C.c_void_p)
extents = api('r_fs_extents', C.c_int, C.c_void_p, Callback, C.c_void_p)
ranges = api('r_fs_ranges', C.c_int, C.c_void_p, C.c_char_p, C.c_uint32, Callback, C.c_void_p)
dir_list = api('r_fs_dir', C.c_void_p, C.c_void_p, C.c_char_p, C.c_uint64, C.c_int)
list_length = api('r_list_length', C.c_int, C.c_void_p)
list_n = api('r_list_get_n', C.c_void_p, C.c_void_p, C.c_int)
list_free = api('r_list_free', None, C.c_void_p)
original = gzip.decompress((ROOT / 'test/bins/fs/ext4-forensic/recovery.img.gz').read_bytes())
expected = b''.join(bytes([65 + i]) * 1024 if not i % 2 else bytes(1024) for i in range(13))


def u16(data, offset):
    return struct.unpack_from('<H', data, offset)[0]


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def put16(data, offset, value):
    struct.pack_into('<H', data, offset, value)


def put32(data, offset, value):
    struct.pack_into('<I', data, offset, value)


def crc(seed, data):
    for byte in data:
        seed ^= byte
        for _ in range(8):
            seed = (seed >> 1) ^ (0x82f63b78 if seed & 1 else 0)
    return seed


def seed(image):
    return u32(image, 1024 + 624) if u32(image, 1120) & 0x2000 else crc(0xffffffff, image[1128:1144])


def inode_offset(image, number):
    per_group = u32(image, 1064)
    descriptor = 2048 + (number - 1) // per_group * 64
    table = u32(image, descriptor + 8) | (u32(image, descriptor + 40) << 32)
    return table * 1024 + (number - 1) % per_group * 256


def inode_seed(image, number):
    return crc(crc(seed(image), struct.pack('<I', number)), image[inode_offset(image, number) + 100:inode_offset(image, number) + 104])


def inode_checksum(image, number):
    offset = inode_offset(image, number)
    put16(image, offset + 124, 0)
    put16(image, offset + 130, 0)
    value = crc(inode_seed(image, number), image[offset:offset + 256])
    put16(image, offset + 124, value & 65535)
    put16(image, offset + 130, value >> 16)


def descriptor_checksum(image, group):
    offset = 2048 + group * 64
    put16(image, offset + 30, 0)
    value = crc(crc(seed(image), struct.pack('<I', group)), image[offset:offset + 64])
    put16(image, offset + 30, value & 65535)


def bitmap_set(image, block, allocated=True):
    group, index = divmod(block - 1, 1024)
    descriptor = 2048 + group * 64
    offset = u32(image, descriptor) * 1024
    byte, mask = offset + index // 8, 1 << (index % 8)
    image[byte] = (image[byte] | mask) if allocated else (image[byte] & ~mask)
    checksum = crc(seed(image), image[offset:offset + 128])
    put16(image, descriptor + 24, checksum & 65535)
    put16(image, descriptor + 56, checksum >> 16)
    descriptor_checksum(image, group)


def extent_checksum(image):
    inode = inode_offset(image, 13)
    block = u32(image, inode + 56)
    tail = block * 1024 + 12 + u16(image, block * 1024 + 4) * 12
    put32(image, tail, crc(inode_seed(image, 13), image[block * 1024:tail]))


class Image:
    def __init__(self, image, delta=0, aliases=()):
        self.image = bytearray(delta) + image
        self.buffer = (C.c_ubyte * len(self.image)).from_buffer(self.image)
        self.reads = []
        @ReadAt
        def read_at(_, offset, destination, length):
            self.reads.append((offset, length))
            for first, source, size in aliases:
                if first <= offset < first + size:
                    offset = source + offset - first
                    break
            if offset > len(self.image) or length < 0 or length > len(self.image) - offset:
                return -1
            C.memmove(destination, C.addressof(self.buffer) + offset, length)
            return length
        self.callback = read_at
        self.fs = new()
        binding = Binding.from_address(self.fs)
        binding.init = 1
        binding.read_at = C.cast(read_at, C.c_void_p).value
        assert mount(self.fs, b'ext2', b'/ext4', delta)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        free(self.fs)

    def listing(self, number):
        entries = dir_list(self.fs, b'/ext4', number, 2)
        try:
            return [(File.from_address(list_n(entries, i)).id,
                     C.string_at(File.from_address(list_n(entries, i)).name))
                    for i in range(list_length(entries))] if entries else []
        finally:
            list_free(entries)


def collect_call(call):
    found = []
    @Callback
    def collect(pointer, _):
        item = pointer.contents
        found.append((item.logical, item.physical, item.size, item.flags))
        return True
    return call(collect), found


def check(label, change=None, wanted=1, prefix=13312, conflict=False, number=13, flags=2, data=None, delta=0, aliases=()):
    image = bytearray(original)
    if change:
        change(image)
    with Image(image, delta, aliases) as disk:
        handle = open_id(disk.fs, b'/ext4', number, flags)
        assert handle, label
        try:
            status, runs = collect_call(lambda cb: extents(handle, cb, None))
            assert status == wanted, (label, status, runs)
            assert sum(item[2] for item in runs) == prefix, (label, runs)
            assert bool(File.from_address(handle).flags & 8) == conflict, label
            if prefix:
                assert read(disk.fs, handle, 0, prefix) == prefix, label
                assert C.string_at(File.from_address(handle).data, prefix) == (data if data is not None else expected)[:prefix], label
            if wanted == -1:
                assert read(disk.fs, handle, prefix, 1) == -1, label
            assert all(item[1] == 0xffffffffffffffff or item[1] >= delta for item in runs)
            print('PASS:', label)
        finally:
            close(disk.fs, handle)
            free_file(handle)

check('deleted external extent tree with sparse holes')
result = subprocess.run([os.environ.get('R2', str(ROOT / 'binr/radare2/radare2')),
                         '-Nq', '-c', 'mgx /root 13 -',
                         'gzip://' + str(ROOT / 'test/bins/fs/ext4-forensic/recovery.img.gz')],
                        env=dict(os.environ, R2_NOPLUGINS='1'), capture_output=True, check=True, timeout=20)
assert not result.stderr and result.stdout == expected, result.stderr
print('PASS: mgx streams the complete deleted file including binary sparse holes')
check('mount delta is included in physical extents', delta=4096)
check('damaged root directory keeps inode recovery available',
      lambda image: put16(image, u32(image, inode_offset(image, 2) + 60) * 1024 + 4, 0))


def checksum_seed_feature(image):
    value = seed(image)
    put32(image, 1120, u32(image, 1120) | 0x2000)
    put32(image, 1024 + 624, value)
    put32(image, 2044, crc(0xffffffff, image[1024:2044]))

check('explicit ext4 metadata checksum seed', checksum_seed_feature)


def crc16(value, data):
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0xa001 if value & 1 else 0)
    return value


def legacy_checksums(image):
    put32(image, 1124, (u32(image, 1124) & ~0x400) | 16)
    for group in range(8):
        offset = 2048 + group * 64
        value = crc16(crc16(65535, image[1128:1144]), struct.pack('<I', group))
        value = crc16(crc16(value, image[offset:offset + 30]), image[offset + 32:offset + 64])
        put16(image, offset + 30, value)

check('legacy ext4 group checksums and lazy bitmaps', legacy_checksums)


def short_descriptors(image):
    descriptors = [image[2048 + group * 64:2048 + group * 64 + 32] for group in range(8)]
    put32(image, 1120, u32(image, 1120) & ~128)
    put16(image, 1278, 0)
    for group, descriptor in enumerate(descriptors):
        offset = 2048 + group * 32
        image[offset:offset + 32] = descriptor
        put16(image, offset + 30, 0)
        value = crc(crc(seed(image), struct.pack('<I', group)), image[offset:offset + 32])
        put16(image, offset + 30, value & 65535)
    put32(image, 2044, crc(0xffffffff, image[1024:2044]))

check('ext4 extents with 32-byte descriptors and truncated bitmap checksums', short_descriptors)

check('unwritten live extents return zeroes', number=14, flags=0, prefix=4096,
      data=b'Live ext4 file\n' + bytes(4096 - 15))


def poison_unwritten(image):
    inode = inode_offset(image, 14)
    block = u32(image, inode + 72)
    image[block * 1024:(block + 3) * 1024] = b'X' * 3072

check('unwritten physical bytes never leak into logical reads', poison_unwritten,
      number=14, flags=0, prefix=4096, data=b'Live ext4 file\n' + bytes(4096 - 15))


def retained_block(image):
    inode = inode_offset(image, 13)
    tree = u32(image, inode + 56)
    return u32(image, tree * 1024 + 20)

check('reused deleted data is rejected', lambda image: bitmap_set(image, retained_block(image)),
      wanted=-1, prefix=0, conflict=True)
check('reused extent index is rejected', lambda image: bitmap_set(image, u32(image, inode_offset(image, 13) + 56)),
      wanted=-1, prefix=0, conflict=True)


def live_owner(image):
    put32(image, inode_offset(image, 12) + 60, retained_block(image))
    inode_checksum(image, 12)

check('live ownership overrides cleared allocation bits', live_owner, wanted=-1, prefix=0, conflict=True)


def corrupt_tree(image):
    image[u32(image, inode_offset(image, 13) + 56) * 1024 + 20] ^= 1

check('bad extent checksum cannot recover data', corrupt_tree, wanted=-1, prefix=0)


def overlap(image):
    tree = u32(image, inode_offset(image, 13) + 56) * 1024
    put32(image, tree + 24, 0)
    extent_checksum(image)

check('overlapping logical extents are rejected', overlap, wanted=-1, prefix=0)


def alias(image):
    tree = u32(image, inode_offset(image, 13) + 56) * 1024
    put32(image, tree + 32, u32(image, tree + 20))
    extent_checksum(image)

check('duplicate physical extents retain only the safe prefix', alias, wanted=-1, prefix=1024)


def corrupt_bitmap(image):
    image[u32(image, 2048) * 1024] ^= 1

check('invalid block bitmap checksum cannot authorize recovery', corrupt_bitmap, wanted=-1, prefix=0)

with Image(bytearray(original)) as disk:
    assert disk.listing(0) == [(13, b'inode-13')]
    assert disk.listing(2) == [(13, b'vanished')]
    status, runs = collect_call(lambda cb: ranges(disk.fs, b'/ext4', 1 | 2, cb, None))
    assert status == 1
    assert sum(item[2] for item in runs) == len(original) - 1024
    assert any(u16(original, 2048 + group * 64 + 18) & 2 for group in range(8))
    assert all(item[3] in (1, 2) for item in runs)
    status, orphans = collect_call(lambda cb: ranges(disk.fs, b'/ext4', 4, cb, None))
    assert status == 1 and not orphans, orphans
    print('PASS: deleted names, inode carving, lazy flex group bitmaps and ownership ranges')

image = bytearray(original)
image[inode_offset(image, 12) + 4] ^= 1
with Image(image) as disk:
    assert disk.listing(0) == [(13, b'inode-13')]
    print('PASS: inode carving continues after a damaged neighboring inode')

image = bytearray(original)
image[inode_offset(image, 13) + 4] ^= 1
with Image(image) as disk:
    assert not open_id(disk.fs, b'/ext4', 13, 2)
    assert not disk.listing(0)
    print('PASS: corrupted inode checksum is excluded from recovery and carving')

for label, change in [('bitmap', corrupt_bitmap), ('descriptor', lambda image: image.__setitem__(2048, image[2048] ^ 1))]:
    image = bytearray(original)
    change(image)
    with Image(image) as disk:
        status, runs = collect_call(lambda cb: ranges(disk.fs, b'/ext4', 16, cb, None))
        assert status == -1 and runs and runs[0][0] == 1024 and runs[0][2] >= 1024 * 1024, (label, status, runs)
        assert all(item[3] == 16 for item in runs)
        if label == 'bitmap':
            assert runs == [(1024, 1024, 1024 * 1024, 16)]
        print('PASS:', 'bad ' + label + ' reports unknown allocation ranges')

# Advertise a sparse disk above 4 TiB, mapping its relocated inode table and data
# through read_at instead of checking a multi-gigabyte fixture into testbins.
image = bytearray(original)
old_table, data_block = u32(image, 2056), retained_block(image)
high_table, high_data = (1 << 32) + 100, (1 << 32) + 300
inode = inode_offset(image, 12)
put32(image, inode + 60, high_data & 0xffffffff)
put16(image, inode + 58, high_data >> 32)
inode_checksum(image, 12)
put32(image, 2056, high_table & 0xffffffff)
put32(image, 2088, high_table >> 32)
descriptor_checksum(image, 0)
put32(image, 1024 + 336, 1)
put32(image, 1024 + 1020, crc(0xffffffff, image[1024:2044]))
high_group, index = divmod(high_data - 1, 1024)
bitmap = bytearray(1024)
bitmap[index // 8] |= 1 << (index % 8)
descriptor = bytearray(original[2048:2112])
put32(descriptor, 0, (high_data + 1) & 0xffffffff)
put32(descriptor, 32, (high_data + 1) >> 32)
put16(descriptor, 18, 0)
value = crc(seed(image), bitmap[:128])
put16(descriptor, 24, value & 65535)
put16(descriptor, 56, value >> 16)
put16(descriptor, 30, 0)
put16(descriptor, 30, crc(crc(seed(image), struct.pack('<I', high_group)), descriptor) & 65535)
descriptor_offset = len(image)
image.extend(descriptor)
bitmap_offset = len(image)
image.extend(bitmap)
with Image(image, aliases=[(high_table * 1024, old_table * 1024, 4096),
                          (high_data * 1024, data_block * 1024, 1024),
                          (2048 + high_group * 64, descriptor_offset, 64),
                          ((high_data + 1) * 1024, bitmap_offset, 1024)]) as disk:
    handle = open_id(disk.fs, b'/ext4', 12, 0)
    assert handle
    try:
        assert read(disk.fs, handle, 0, 15) == 15
        assert C.string_at(File.from_address(handle).data, 15) == b'A' * 15
        assert File.from_address(handle).off == high_data * 1024
        status, runs = collect_call(lambda cb: extents(handle, cb, None))
        assert status == 1 and runs == [(0, high_data * 1024, 15, 2)]
        print('PASS: 64-bit inode tables, bitmap addresses and physical extent ownership')
    finally:
        close(disk.fs, handle)
        free_file(handle)

image = bytearray(original)
inode = inode_offset(image, 13)
tree = u32(image, inode + 56) * 1024
last = (1 << 22) + 1
put32(image, tree + 12 + 6 * 12, last)
put32(image, inode + 4, 2048)
put32(image, inode + 108, 1)
extent_checksum(image)
inode_checksum(image, 13)
with Image(image) as disk:
    handle = open_id(disk.fs, b'/ext4', 13, 2)
    assert handle
    try:
        disk.reads.clear()
        status, runs = collect_call(lambda cb: extents(handle, cb, None))
        assert status == 1 and sum(item[2] for item in runs) == (1 << 32) + 2048
        assert len(disk.reads) < 300 and sum(item[1] for item in disk.reads) < 512000, (len(disk.reads), sum(item[1] for item in disk.reads))
        for offset, payload in ((last * 1024, b'M' * 1024), ((1 << 32) - 1024, bytes(1024))):
            assert read(disk.fs, handle, offset, 1024) == 1024
            assert C.string_at(File.from_address(handle).data, 1024) == payload
        print('PASS: deleted sparse extents above 4 GiB skip holes and allow random reads')
    finally:
        close(disk.fs, handle)
        free_file(handle)


def huge_file_units(image):
    inode = inode_offset(image, 13)
    put32(image, inode + 32, u32(image, inode + 32) | 0x40000)
    put32(image, inode + 28, 8)
    inode_checksum(image, 13)

check('huge file block accounting preserves proven sparse holes', huge_file_units)

image = bytearray(original)
root = inode_offset(image, 2)
put32(image, root + 32, u32(image, root + 32) | 0x1000)
inode_checksum(image, 2)
with Image(image) as disk:
    assert not disk.listing(2)
    print('PASS: directory index payload is excluded from deleted name carving')

with Image(bytearray(original)) as disk:
    handle = open_id(disk.fs, b'/ext4', 13, 2)
    assert handle
    try:
        @Callback
        def stop(pointer, _):
            return False
        assert extents(handle, stop, None) == 0
        assert read(disk.fs, handle, 0, 1024) == 1024
        assert C.string_at(File.from_address(handle).data, 1024) == b'A' * 1024
        print('PASS: stopped extent callbacks do not truncate a later recovery read')
    finally:
        close(disk.fs, handle)
        free_file(handle)
