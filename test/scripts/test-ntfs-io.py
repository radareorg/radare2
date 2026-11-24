#!/usr/bin/env python3
"""Exercise NTFS MFT and stream recovery, mapping pairs, allocation claims and damaged records."""
import ctypes as C
import gzip
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SUFFIX = 'dylib' if sys.platform == 'darwin' else 'so'
fs = C.CDLL(str(os.environ.get('R2_FS_LIB', ROOT / f'libr/fs/libr_fs.{SUFFIX}')))
FIXTURES = ROOT / 'test/bins/fs/ntfs-forensic'
INFO = json.loads((FIXTURES / 'manifest.json').read_text())
ORIGINAL = gzip.decompress((FIXTURES / 'recovery.img.gz').read_bytes())
IDS = INFO['ids']
CLUSTER, SECTOR, RECORD = INFO['cluster'], INFO['sector'], INFO['record_size']
EXPECTED = b'Recover NTFS data\n' * 1024

class Binding(C.Structure):
    _fields_ = [('init', C.c_int)] + [(name, C.c_void_p) for name in (
        'io', 'desc_use', 'desc_get', 'desc_info', 'desc_size', 'open', 'open_at', 'close', 'read_at')]

class File(C.Structure):
    _fields_ = [('name', C.c_void_p), ('path', C.c_void_p), ('off', C.c_uint64),
                ('id', C.c_uint64), ('size', C.c_uint64), ('flags', C.c_uint32),
                ('type', C.c_char), ('data', C.c_void_p)]

class Range(C.Structure):
    _fields_ = [('logical', C.c_uint64), ('physical', C.c_uint64), ('size', C.c_uint64), ('flags', C.c_uint32)]

Callback = C.CFUNCTYPE(C.c_bool, C.POINTER(Range), C.c_void_p)
ReadAt = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_uint64, C.c_void_p, C.c_int)


def api(name, result, *args):
    function = getattr(fs, name)
    function.restype, function.argtypes = result, args
    return function

new = api('r_fs_new', C.c_void_p)
free = api('r_fs_free', None, C.c_void_p)
mount = api('r_fs_mount', C.c_void_p, C.c_void_p, C.c_char_p, C.c_char_p, C.c_uint64)
open_id = api('r_fs_open_id', C.c_void_p, C.c_void_p, C.c_char_p, C.c_uint64, C.c_uint32)
open_path = api('r_fs_open', C.c_void_p, C.c_void_p, C.c_char_p, C.c_bool)
read = api('r_fs_read', C.c_int, C.c_void_p, C.c_void_p, C.c_uint64, C.c_int)
close = api('r_fs_close', None, C.c_void_p, C.c_void_p)
free_file = api('r_fs_file_free', None, C.c_void_p)
extents = api('r_fs_extents', C.c_int, C.c_void_p, Callback, C.c_void_p)
ranges = api('r_fs_ranges', C.c_int, C.c_void_p, C.c_char_p, C.c_uint32, Callback, C.c_void_p)
dir_list = api('r_fs_dir', C.c_void_p, C.c_void_p, C.c_char_p, C.c_uint64, C.c_int)
list_length = api('r_list_length', C.c_int, C.c_void_p)
list_n = api('r_list_get_n', C.c_void_p, C.c_void_p, C.c_int)
list_free = api('r_list_free', None, C.c_void_p)


def u16(data, offset):
    return struct.unpack_from('<H', data, offset)[0]


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def u64(data, offset):
    return struct.unpack_from('<Q', data, offset)[0]


def put16(data, offset, value):
    struct.pack_into('<H', data, offset, value)


def put32(data, offset, value):
    struct.pack_into('<I', data, offset, value)


def get_record(image, number):
    offset = INFO['record_offsets'][str(number)]
    record = bytearray(image[offset:offset + RECORD])
    usa = u16(record, 4)
    for index in range(1, u16(record, 6)):
        assert record[index * SECTOR - 2:index * SECTOR] == record[usa:usa + 2]
        record[index * SECTOR - 2:index * SECTOR] = record[usa + index * 2:usa + index * 2 + 2]
    return record


def store_record(image, number, record):
    record = bytearray(record)
    usa = u16(record, 4)
    for index in range(1, u16(record, 6)):
        record[usa + index * 2:usa + index * 2 + 2] = record[index * SECTOR - 2:index * SECTOR]
        record[index * SECTOR - 2:index * SECTOR] = record[usa:usa + 2]
    offset = INFO['record_offsets'][str(number)]
    image[offset:offset + RECORD] = record


def attributes(record):
    offset = u16(record, 20)
    while u32(record, offset) != 0xffffffff:
        length = u32(record, offset + 4)
        assert length >= 24
        yield offset, record[offset:offset + length]
        offset += length


def data_attribute(record, kind=0x80, named=False):
    return next((offset, attr) for offset, attr in attributes(record) if u32(attr, 0) == kind and bool(attr[9]) == named)


def runs(attr):
    vcn, lcn, offset = u64(attr, 16), 0, u16(attr, 32)
    result = []
    while attr[offset]:
        count_size, delta_size = attr[offset] & 15, attr[offset] >> 4
        offset += 1
        count = int.from_bytes(attr[offset:offset + count_size], 'little')
        offset += count_size
        if delta_size:
            lcn += int.from_bytes(attr[offset:offset + delta_size], 'little', signed=True)
        offset += delta_size
        result.append((vcn * CLUSTER, lcn * CLUSTER if delta_size else None, count * CLUSTER))
        vcn += count
    return result


def bitmap_set(image, number, allocated=True, mft=False):
    record_id, kind = (0, 0xb0) if mft else (6, 0x80)
    record = get_record(image, record_id)
    offset, attr = data_attribute(record, kind)
    index, mask = number // 8, 1 << (number % 8)
    if attr[8]:
        logical, physical, size = next(run for run in runs(attr) if run[0] <= index < run[0] + run[2])
        address = physical + index - logical
        image[address] = (image[address] | mask) if allocated else (image[address] & ~mask)
    else:
        address = offset + u16(attr, 20) + index
        record[address] = (record[address] | mask) if allocated else (record[address] & ~mask)
        store_record(image, record_id, record)


def change_data(image, number, change):
    record = get_record(image, number)
    offset, attr = data_attribute(record)
    change(record, offset, attr)
    store_record(image, number, record)


def collect_call(call):
    result = []
    @Callback
    def collect(pointer, _):
        item = pointer.contents
        result.append((item.logical, item.physical, item.size, item.flags))
        return True
    return call(collect), result


class Image:
    def __init__(self, image, delta=0, aliases=(), mounted=True):
        self.image = bytearray(delta) + image
        self.buffer = (C.c_ubyte * len(self.image)).from_buffer(self.image)
        self.reads = []
        @ReadAt
        def read_at(_, offset, destination, length):
            self.reads.append((offset, length))
            for start, original, size in aliases:
                if start <= offset < start + size:
                    offset = original + offset - start
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
        assert bool(mount(self.fs, b'ntfs', b'/ntfs', delta)) == mounted

    def __enter__(self):
        return self

    def __exit__(self, *args):
        free(self.fs)

    def listing(self, number=0xffffffffffffffff, view=2):
        items = dir_list(self.fs, b'/ntfs', number, view)
        result = []
        try:
            for index in range(list_length(items) if items else 0):
                item = File.from_address(list_n(items, index))
                result.append((item.id, C.string_at(item.name), item.size, item.flags))
            return result
        finally:
            list_free(items)


def check(label, change=None, number=None, flags=2, wanted=1, prefix=None, conflict=False, expected=None, delta=0, raw=False):
    image = bytearray(ORIGINAL)
    if change:
        change(image)
    number = IDS['vanished.bin'] if number is None else number
    expected = EXPECTED if expected is None else expected
    prefix = len(expected) if prefix is None else prefix
    with Image(image, delta) as disk:
        handle = open_id(disk.fs, b'/ntfs', number, flags)
        assert handle, label
        try:
            status, found = collect_call(lambda cb: extents(handle, cb, None))
            assert status == wanted and sum(item[2] for item in found) == prefix, (label, status, found)
            assert bool(File.from_address(handle).flags & 8) == conflict, (label, File.from_address(handle).flags)
            if prefix:
                assert read(disk.fs, handle, 0, prefix) == prefix, label
                assert C.string_at(File.from_address(handle).data, prefix) == expected[:prefix], label
            if prefix < File.from_address(handle).size and wanted == -1:
                assert read(disk.fs, handle, prefix, 1) == -1
            if raw:
                for logical, physical, length, state in found:
                    assert disk.image[physical:physical + length] == expected[logical:logical + length], (label, found)
            print('PASS:', label)
        finally:
            close(disk.fs, handle)
            free_file(handle)


check('deleted fragmented mapping pairs include backward LCN deltas', raw=True)
check('deleted resident bytes preserve update-sequence fixups', number=IDS['inline.txt'],
      expected=b'Resident NTFS recovery\n' * 16, raw=True)
check('physical mappings include the mount delta', delta=4096, raw=True)
check('uninitialized bytes never expose stale physical contents', number=IDS['unwritten.bin'], flags=0,
      expected=b'Initialized NTFS\n' + bytes(1024 - 17))

first = INFO['deleted_runs'][0][1]
check('allocated deleted data is rejected', lambda image: bitmap_set(image, first), wanted=-1, prefix=0, conflict=True)
check('reused later clusters retain the readable prefix', lambda image: bitmap_set(image, first + 2),
      wanted=-1, prefix=2 * CLUSTER, conflict=True)


def live_owner(image, clear_flag=False, clear_bit=False):
    number = IDS['live.txt']
    record = get_record(image, number)
    offset, old = data_attribute(record)
    attr = bytearray(80)
    put32(attr, 0, 0x80)
    put32(attr, 4, len(attr))
    attr[8] = 1
    struct.pack_into('<QQH', attr, 16, 0, 0, 64)
    struct.pack_into('<QQQ', attr, 40, CLUSTER, 15, 15)
    attr[64:69] = bytes((0x21, 1)) + first.to_bytes(2, 'little') + bytes(1)
    used = u32(record, 24)
    tail = record[offset + len(old):used]
    record[offset:offset + len(attr) + len(tail)] = attr + tail
    put32(record, 24, offset + len(attr) + len(tail))
    if clear_flag:
        put16(record, 22, u16(record, 22) & ~1)
    store_record(image, number, record)
    if clear_bit:
        bitmap_set(image, number, False, mft=True)

check('live file ownership overrides a cleared allocation bit', live_owner, wanted=-1, prefix=0, conflict=True)
check('in-use records retain ownership with a clear MFT bitmap bit',
      lambda image: live_owner(image, clear_bit=True), wanted=-1, prefix=0, conflict=True)
check('allocated MFT entries retain ownership with a cleared in-use flag',
      lambda image: live_owner(image, clear_flag=True), wanted=-1, prefix=0, conflict=True)


def second_run(image, value):
    def change(record, offset, attr):
        start = u16(attr, 32)
        second = start + 1 + (attr[start] & 15) + (attr[start] >> 4)
        record[offset + second] = value
    change_data(image, IDS['vanished.bin'], change)

check('invalid mapping pair widths retain the first run', lambda image: second_run(image, 0x19),
      wanted=-1, prefix=INFO['deleted_runs'][0][0] * CLUSTER)


def duplicate_run(image):
    def change(record, offset, attr):
        start = u16(attr, 32)
        second = start + 1 + (attr[start] & 15) + (attr[start] >> 4)
        record[offset + second + 2] = 0
    change_data(image, IDS['vanished.bin'], change)

check('zero LCN deltas represent occupied runs, never sparse holes', duplicate_run,
      wanted=-1, prefix=INFO['deleted_runs'][0][0] * CLUSTER, conflict=True)


def broken_live_fixup(image):
    offset = INFO['record_offsets'][str(IDS['live.txt'])]
    image[offset + SECTOR - 1] ^= 1

check('unknown live record ownership refuses checked recovery', broken_live_fixup, wanted=-1, prefix=0)


def attribute_list(image):
    record = get_record(image, IDS['live.txt'])
    used = u32(record, 24)
    record[used - 8:used - 8 + 32] = bytes(32)
    put32(record, used - 8, 0x20)
    put32(record, used - 4, 24)
    put16(record, used - 8 + 20, 24)
    put32(record, used - 8 + 24, 0xffffffff)
    put32(record, 24, used + 24)
    store_record(image, IDS['live.txt'], record)

check('unresolved attribute lists cannot establish complete ownership', attribute_list, wanted=-1, prefix=0)


def dirty_volume(image):
    record = get_record(image, 3)
    offset, attr = data_attribute(record, 0x70)
    value = offset + u16(attr, 20)
    put16(record, value + 10, u16(record, value + 10) | 1)
    store_record(image, 3, record)

check('dirty volume allocation metadata cannot authorize recovery', dirty_volume, wanted=-1, prefix=0)

with Image(bytearray(ORIGINAL)) as disk:
    deleted = disk.listing()
    assert {row[0] for row in deleted} == {IDS['vanished.bin'], IDS['inline.txt']}
    assert {row[0] for row in disk.listing(0)} == {IDS['vanished.bin'], IDS['inline.txt']}
    handle = open_id(disk.fs, b'/ntfs', IDS['sparse.bin'], 0)
    assert handle
    try:
        disk.reads.clear()
        status, found = collect_call(lambda cb: extents(handle, cb, None))
        assert status == 1 and sum(item[2] for item in found) == (1 << 32) + CLUSTER
        assert len(found) == 3 and found[1][1] == 0xffffffffffffffff and found[1][3] & 64
        assert len(disk.reads) < 5, disk.reads
        for offset, payload in ((0, b'A' * 16), ((1 << 32) - 8, bytes(8) + b'Z' * 8), ((1 << 32) + CLUSTER - 8, b'Z' * 8)):
            assert read(disk.fs, handle, offset, len(payload)) == len(payload)
            assert C.string_at(File.from_address(handle).data, len(payload)) == payload
        print('PASS: sparse mappings above 4 GiB skip holes and preserve random reads and EOF')
    finally:
        close(disk.fs, handle)
        free_file(handle)
    handle = open_path(disk.fs, b'/ntfs/LIVE.TXT', False)
    assert handle and C.string_at(File.from_address(handle).name) == b'LIVE.TXT'
    close(disk.fs, handle)
    free_file(handle)
    status, found = collect_call(lambda cb: ranges(disk.fs, b'/ntfs', 1 | 2, cb, None))
    assert status == 1 and sum(item[2] for item in found) == (len(ORIGINAL) // SECTOR - 1) * SECTOR
    status, orphan = collect_call(lambda cb: ranges(disk.fs, b'/ntfs', 4, cb, None))
    assert status == 1 and not orphan, orphan
    print('PASS: MFT discovery, case-insensitive lookup and allocation ownership ranges')

image = bytearray(ORIGINAL)
bitmap_set(image, first, True)
with Image(image) as disk:
    status, found = collect_call(lambda cb: ranges(disk.fs, b'/ntfs', 4, cb, None))
    assert status == 1 and found == [(first * CLUSTER, first * CLUSTER, CLUSTER, 6)], found
    print('PASS: allocated unowned clusters are reported as orphans')

image = bytearray(ORIGINAL)
record = get_record(image, IDS['vanished.bin'])
put16(record, 22, u16(record, 22) | 1)
store_record(image, IDS['vanished.bin'], record)
bitmap_set(image, IDS['vanished.bin'], True, mft=True)
with Image(image) as disk:
    assert not open_id(disk.fs, b'/ntfs', IDS['vanished.bin'], 2)
    print('PASS: reused MFT records cannot be opened for deleted recovery')

image = bytearray(ORIGINAL)
record = get_record(image, IDS['vanished.bin'])
offset, attr = data_attribute(record, 0x30)
value = offset + u16(attr, 20)
struct.pack_into('<Q', record, value, (u64(record, value) & 0xffffffffffff) | (0xabcd << 48))
store_record(image, IDS['vanished.bin'], record)
with Image(image) as disk:
    assert IDS['vanished.bin'] not in {row[0] for row in disk.listing()}
    found = {row[0]: row for row in disk.listing(0)}
    assert found[IDS['vanished.bin']][3] & 8
    print('PASS: parent sequence mismatches do not attach deleted names to reused directories')

r2 = os.environ.get('R2', str(ROOT / 'binr/radare2/radare2'))
result = subprocess.run([r2, '-Nq', '-c', 'mgx /root 65 -', 'gzip://' + str(FIXTURES / 'recovery.img.gz')],
                        env=dict(os.environ, R2_NOPLUGINS='1'), capture_output=True, timeout=20, check=True)
assert result.stdout == EXPECTED and not result.stderr, result.stderr
print('PASS: mgx streams the complete deleted NTFS file')


def bitmap_uninitialized(image):
    change_data(image, 6, lambda record, offset, attr: struct.pack_into('<Q', record, offset + 56, 0))

check('uninitialized allocation bitmap bytes never authorize recovery', bitmap_uninitialized, wanted=-1, prefix=0)


def bitmap_sparse(image):
    def change(record, offset, attr):
        start = u16(attr, 32)
        count_size = attr[start] & 15
        record[offset + start] = count_size
        record[offset + start + 1 + count_size] = 0
    change_data(image, 6, change)

check('sparse allocation bitmap runs are unknown rather than free', bitmap_sparse, wanted=-1, prefix=0)
image = bytearray(ORIGINAL)
bitmap_sparse(image)
with Image(image) as disk:
    status, found = collect_call(lambda cb: ranges(disk.fs, b'/ntfs', 16, cb, None))
    assert status == -1 and found == [(0, 0, len(ORIGINAL) - SECTOR, 16)], found
    status, found = collect_call(lambda cb: ranges(disk.fs, b'/ntfs', 1, cb, None))
    assert status == -1 and not found
    print('PASS: invalid bitmap ranges stay unknown and never appear as free space')

image = bytearray(ORIGINAL)
record = get_record(image, 0)
offset, attr = data_attribute(record, 0xb0)
if attr[8]:
    struct.pack_into('<Q', record, offset + 56, 0)
else:
    put32(record, offset + 16, 0)
store_record(image, 0, record)
with Image(image) as disk:
    assert not open_id(disk.fs, b'/ntfs', IDS['vanished.bin'], 2)
    print('PASS: missing initialized MFT bitmap bits prevent deleted recovery')


def replace_attr(record, offset, attr):
    previous, used = u32(record, offset + 4), u32(record, 24)
    tail = bytes(record[offset + previous:used])
    new_used = offset + len(attr) + len(tail)
    assert new_used <= len(record)
    record[offset:new_used] = attr + tail
    record[new_used:] = bytes(len(record) - new_used)
    put32(record, 24, new_used)


def mapping_pairs(values):
    result, previous = bytearray(), 0
    for count, cluster in values:
        count_size = max(1, (count.bit_length() + 7) // 8)
        delta_size, delta = 0, b''
        if cluster is not None:
            relative = cluster - previous
            delta_size = next(size for size in range(1, 9) if -(1 << (size * 8 - 1)) <= relative < (1 << (size * 8 - 1)))
            delta = relative.to_bytes(delta_size, 'little', signed=True)
            previous = cluster
        result.append((delta_size << 4) | count_size)
        result.extend(count.to_bytes(count_size, 'little'))
        result.extend(delta)
    return result + bytes(1)

image = bytearray(ORIGINAL)
record = get_record(image, 8)
offset, old = data_attribute(record, named=True)
maximum = (len(ORIGINAL) - SECTOR) // CLUSTER
encoded = mapping_pairs([(first, None), (1, first), (maximum - first - 1, None)])
start = u16(old, 32)
attr = bytearray(old[:start]) + encoded
attr.extend(bytes((-len(attr)) % 8))
put32(attr, 4, len(attr))
replace_attr(record, offset, attr)
store_record(image, 8, record)
with Image(image) as disk:
    status, found = collect_call(lambda cb: ranges(disk.fs, b'/ntfs', 8, cb, None))
    assert status == 1 and found == [(first * CLUSTER, first * CLUSTER, CLUSTER, 8)], found
    print('PASS: the named BadClus stream identifies bad physical clusters')

# Keep the backing image small while relocating a live run above the 32-bit LCN boundary.
image = bytearray(ORIGINAL)
high = (1 << 32) + 128
struct.pack_into('<Q', image, 40, high + 1024)
record = get_record(image, IDS['unwritten.bin'])
offset, attr = data_attribute(record)
old_physical = runs(attr)[0][1]
start = u16(attr, 32)
encoded = mapping_pairs([(2, high)])
replacement = bytearray(attr[:start]) + encoded
replacement.extend(bytes((-len(replacement)) % 8))
put32(replacement, 4, len(replacement))
replace_attr(record, offset, replacement)
store_record(image, IDS['unwritten.bin'], record)
record = get_record(image, 6)
offset, attr = data_attribute(record)
bitmap_physical = runs(attr)[0][1]
bitmap_size = (high + 1024 + 7) // 8
bitmap_clusters = (bitmap_size + CLUSTER - 1) // CLUSTER
encoded = mapping_pairs([(bitmap_clusters, bitmap_physical // CLUSTER)])
start = u16(attr, 32)
replacement = bytearray(attr[:start]) + encoded
replacement.extend(bytes((-len(replacement)) % 8))
put32(replacement, 4, len(replacement))
struct.pack_into('<Q', replacement, 24, bitmap_clusters - 1)
struct.pack_into('<QQQ', replacement, 40, bitmap_clusters * CLUSTER, bitmap_size, bitmap_size)
replace_attr(record, offset, replacement)
store_record(image, 6, record)
page = high // 8 // 4096 * 4096
extra = bytearray(4096)
for bit in (high, high + 1):
    extra[bit // 8 - page] |= 1 << (bit % 8)
extra_offset = len(image)
image.extend(extra)
with Image(image, aliases=[(high * CLUSTER, old_physical, 2 * CLUSTER),
                          (bitmap_physical + page, extra_offset, len(extra))]) as disk:
    handle = open_id(disk.fs, b'/ntfs', IDS['unwritten.bin'], 0)
    assert handle
    try:
        status, found = collect_call(lambda cb: extents(handle, cb, None))
        assert status == 1 and found == [(0, high * CLUSTER, 17, 2), (17, high * CLUSTER + 17, 1007, 130)], found
        assert read(disk.fs, handle, 0, 1024) == 1024
        assert C.string_at(File.from_address(handle).data, 1024) == b'Initialized NTFS\n' + bytes(1007)
        print('PASS: 64-bit LCN offsets and high allocation bitmap pages are not truncated')
    finally:
        close(disk.fs, handle)
        free_file(handle)


def named_owner(image):
    record = get_record(image, IDS['live.txt'])
    name = 'secret'.encode('utf-16le')
    encoded = mapping_pairs([(1, first)])
    start = (64 + len(name) + 7) & ~7
    attr = bytearray(start) + encoded
    attr.extend(bytes((-len(attr)) % 8))
    put32(attr, 0, 0x80)
    put32(attr, 4, len(attr))
    attr[8], attr[9] = 1, len(name) // 2
    put16(attr, 10, 64)
    put16(attr, 32, start)
    struct.pack_into('<QQQ', attr, 40, CLUSTER, CLUSTER, CLUSTER)
    attr[64:64 + len(name)] = name
    used = u32(record, 24)
    record[used - 8:used - 8 + len(attr) + 8] = attr + struct.pack('<II', 0xffffffff, 0)
    put32(record, 24, used + len(attr))
    store_record(image, IDS['live.txt'], record)

check('named data streams protect their physical clusters from deleted recovery', named_owner,
      wanted=-1, prefix=0, conflict=True)


def hidden_mft_owner(image):
    record = get_record(image, 0)
    put16(record, 22, u16(record, 22) & ~1)
    store_record(image, 0, record)
    bitmap_set(image, 0, False, mft=True)
    mft_cluster = INFO['mft_runs'][0][1] // CLUSTER
    bitmap_set(image, mft_cluster, False)
    def change(record, offset, attr):
        start = u16(attr, 32)
        assert attr[start] >> 4 == 2
        record[offset + start + 2:offset + start + 4] = mft_cluster.to_bytes(2, 'little')
    change_data(image, IDS['vanished.bin'], change)

check('MFT bootstrap storage stays protected despite cleared metadata allocation bits', hidden_mft_owner,
      wanted=-1, prefix=0, conflict=True)

image = bytearray(ORIGINAL)
record = get_record(image, IDS['vanished.bin'])
offset, attr = data_attribute(record, 0x30)
value = offset + u16(attr, 20)
put16(record, value + 66, 0xd800)
store_record(image, IDS['vanished.bin'], record)
with Image(image) as disk:
    assert IDS['vanished.bin'] not in {row[0] for row in disk.listing()}
    entries = {row[0]: row for row in disk.listing(0)}
    assert entries[IDS['vanished.bin']][1] == b'mft-65'
    print('PASS: invalid UTF-16 names preserve name-independent MFT discovery')

image = bytearray(ORIGINAL)
image[510:512] = bytes(2)
check('damaged boot signatures retain bounded MFT recovery', lambda target: target.__setitem__(slice(510, 512), bytes(2)))

image = bytearray(ORIGINAL)
record = get_record(image, 5)
for offset, attr in attributes(record):
    if u32(attr, 0) == 0x90:
        put32(record, offset, 0x100)
store_record(image, 5, record)
with Image(image) as disk:
    assert {row[0] for row in disk.listing()} == {IDS['inline.txt'], IDS['vanished.bin']}
    print('PASS: damaged root directory indexes do not prevent deleted MFT discovery')

for field, value in ((11, 0), (13, 0), (64, 0), (64, 128), (68, 0), (68, 128)):
    image = bytearray(ORIGINAL)
    if field == 11:
        put16(image, field, value)
    else:
        image[field] = value
    with Image(image, mounted=False):
        pass
print('PASS: invalid geometry is rejected before unsafe legacy block-size shifts')

# Relocate the entire fragmented MFT above 2 TiB without adding a large fixture.
image = bytearray(ORIGINAL)
record = get_record(image, 0)
offset, old = data_attribute(record)
base = INFO['mft_runs'][0][1] // CLUSTER
shift = (1 << 32) - base + 256
relocated = [(size // CLUSTER, physical // CLUSTER + shift) for logical, physical, size in INFO['mft_runs']]
start = u16(old, 32)
replacement = bytearray(old[:start]) + mapping_pairs(relocated)
replacement.extend(bytes((-len(replacement)) % 8))
put32(replacement, 4, len(replacement))
replace_attr(record, offset, replacement)
store_record(image, 0, record)
struct.pack_into('<Q', image, 48, relocated[0][1])
struct.pack_into('<Q', image, 40, relocated[0][1] + 4096)
aliases = [((physical // CLUSTER + shift) * CLUSTER, physical, size) for logical, physical, size in INFO['mft_runs']]
with Image(image, aliases=aliases) as disk:
    handle = open_id(disk.fs, b'/ntfs', IDS['inline.txt'], 2)
    assert handle
    try:
        status, found = collect_call(lambda cb: extents(handle, cb, None))
        assert status == 1 and len(found) == 3 and all(item[1] > (1 << 41) for item in found)
        assert read(disk.fs, handle, 0, 368) == 368
        assert C.string_at(File.from_address(handle).data, 368) == b'Resident NTFS recovery\n' * 16
        print('PASS: 64-bit MFT bootstrap offsets and resident fixup source locations survive relocation')
    finally:
        close(disk.fs, handle)
        free_file(handle)

image = bytearray(ORIGINAL)
change_data(image, 0, lambda record, offset, attr: record.__setitem__(offset + u16(attr, 32), 0x19))
with Image(image, mounted=False):
    pass
print('PASS: malformed MFT mapping pairs are not sent to the legacy decoder')

record = get_record(image, 0)
used = u32(record, 24)
record[used - 8:used - 8 + 32] = bytes(32)
put32(record, used - 8, 0x20)
put32(record, used - 4, 24)
put16(record, used - 8 + 20, 24)
put32(record, used - 8 + 24, 0xffffffff)
put32(record, 24, used + 24)
store_record(image, 0, record)
with Image(image, mounted=False):
    pass
print('PASS: attribute lists do not hide malformed MFT mapping pairs')

image = bytearray(ORIGINAL)
record = get_record(image, IDS['unwritten.bin'])
offset, attr = data_attribute(record)
struct.pack_into('<Q', record, offset + 24, (1 << 64) - 1)
struct.pack_into('<QQQ', record, offset + 40, 0, 0, 0)
record[offset + u16(attr, 32)] = 0
store_record(image, IDS['unwritten.bin'], record)
with Image(image) as disk:
    handle = open_path(disk.fs, b'/ntfs/unwritten.bin', False)
    assert handle
    try:
        assert File.from_address(handle).size == 0
        assert collect_call(lambda cb: extents(handle, cb, None)) == (1, [])
        assert read(disk.fs, handle, 0, 1) == 0
    finally:
        close(disk.fs, handle)
        free_file(handle)
print('PASS: empty nonresident data streams preserve zero length and EOF')


def set_attributes(record, values):
    start = u16(record, 20)
    payload = b''.join(values) + struct.pack('<II', 0xffffffff, 0)
    assert start + len(payload) <= RECORD
    record[start:] = payload + bytes(RECORD - start - len(payload))
    put32(record, 24, start + len(payload))
    put16(record, 40, max((u16(value, 14) for value in values), default=0) + 1)


def resident_attribute(kind, value, instance, name=b''):
    start = (24 + len(name) + 7) & ~7
    attr = bytearray(start) + value
    attr.extend(bytes((-len(attr)) % 8))
    put32(attr, 0, kind)
    put32(attr, 4, len(attr))
    attr[9] = len(name) // 2
    put16(attr, 10, 24 if name else 0)
    put16(attr, 14, instance)
    put32(attr, 16, len(value))
    put16(attr, 20, start)
    attr[24:24 + len(name)] = name
    return attr


def segment(attr, start, values, first=False):
    result = bytearray(attr[:u16(attr, 32)]) + mapping_pairs(values)
    result.extend(bytes((-len(result)) % 8))
    put32(result, 4, len(result))
    struct.pack_into('<QQ', result, 16, start, start + sum(count for count, _ in values) - 1)
    if not first:
        struct.pack_into('<QQQ', result, 40, 0, 0, 0)
    return result


def list_entry(number, record, attr):
    name = bytes(attr[u16(attr, 10):u16(attr, 10) + attr[9] * 2]) if attr[9] else b''
    length = (26 + len(name) + 7) & ~7
    reference = number | (u16(record, 16) << 48)
    result = bytearray(struct.pack('<IHBBQQH', u32(attr, 0), length, attr[9], 26 if name else 0,
                                   u64(attr, 16) if attr[8] else 0, reference, u16(attr, 14))) + name
    result.extend(bytes(length - len(result)))
    return result


def extension_record(image, base, number, values):
    record = get_record(image, base)
    struct.pack_into('<Q', record, 32, base | (u16(record, 16) << 48))
    put16(record, 16, 9)
    put32(record, 44, number)
    set_attributes(record, values)
    store_record(image, number, record)
    bitmap_set(image, number, bool(u16(record, 22) & 1), mft=True)
    return record


def attribute_list_image(image, base, values, extensions, nonresident=False):
    record = get_record(image, base)
    entries = [(value, base, record) for value in values]
    for number, attributes_ in extensions:
        extended = extension_record(image, base, number, attributes_)
        entries.extend((value, number, extended) for value in attributes_)
    entries.sort(key=lambda item: (u32(item[0], 0), bytes(item[0][u16(item[0], 10):u16(item[0], 10) + item[0][9] * 2]),
                                   u64(item[0], 16) if item[0][8] else 0))
    payload = b''.join(list_entry(number, record_, value) for value, number, record_ in entries)
    if nonresident:
        clusters = (len(payload) + CLUSTER - 1) // CLUSTER
        encoded = mapping_pairs([(1, 16000 + index * 2) for index in range(clusters)])
        attr = bytearray(64) + encoded
        attr.extend(bytes((-len(attr)) % 8))
        put32(attr, 0, 0x20)
        put32(attr, 4, len(attr))
        attr[8] = 1
        put16(attr, 14, 100)
        struct.pack_into('<Q', attr, 24, clusters - 1)
        put16(attr, 32, 64)
        struct.pack_into('<QQQ', attr, 40, clusters * CLUSTER, len(payload), len(payload))
        for index in range(clusters):
            cluster = 16000 + index * 2
            data = payload[index * CLUSTER:(index + 1) * CLUSTER]
            image[cluster * CLUSTER:cluster * CLUSTER + len(data)] = data
            bitmap_set(image, cluster, bool(u16(record, 22) & 1))
    else:
        attr = resident_attribute(0x20, payload, 100)
    set_attributes(record, sorted(values + [attr], key=lambda value: u32(value, 0)))
    store_record(image, base, record)


def split_deleted(image, nonresident=False):
    number = IDS['vanished.bin']
    record = get_record(image, number)
    _, old = data_attribute(record)
    values = [value for _, value in attributes(record) if u32(value, 0) != 0x80]
    physical = INFO['deleted_runs']
    values.append(segment(old, 0, physical[:1], first=True))
    extension1 = segment(old, physical[0][0], physical[1:2])
    extension2 = segment(old, physical[0][0] + physical[1][0], physical[2:])
    attribute_list_image(image, number, values, [(24, [extension1]), (25, [extension2])], nonresident)


check('resident attribute lists reconstruct three deleted data segments', split_deleted, raw=True)
check('nonresident attribute lists reconstruct deleted data segments', lambda image: split_deleted(image, True), raw=True)


def moved_resident(image, number=None):
    number = IDS['inline.txt'] if number is None else number
    record = get_record(image, number)
    _, value = data_attribute(record)
    values = [value for _, value in attributes(record) if u32(value, 0) != 0x80]
    padding = resident_attribute(0x40, bytes(256), 10)
    attribute_list_image(image, number, values, [(24, [padding, value])])

check('resident data in extension records maps original fixup bytes', moved_resident,
      number=IDS['inline.txt'], expected=b'Resident NTFS recovery\n' * 16, raw=True)
check('resolved live attribute lists permit checked recovery', lambda image: moved_resident(image, IDS['live.txt']))


def reused_resident_extension(image):
    moved_resident(image)
    bitmap_set(image, 24, True, mft=True)

check('reused resident extension records refuse recovery', reused_resident_extension,
      number=IDS['inline.txt'], wanted=-1, prefix=0, conflict=True)


def damaged_extension(image, change):
    split_deleted(image)
    record = get_record(image, 24)
    change(record)
    store_record(image, 24, record)

check('stale extension sequence references preserve the base data prefix',
      lambda image: damaged_extension(image, lambda record: put16(record, 16, 10)), wanted=-1, prefix=6144)
check('foreign base record references preserve the base data prefix',
      lambda image: damaged_extension(image, lambda record: struct.pack_into('<Q', record, 32, 64 | (1 << 48))),
      wanted=-1, prefix=6144)
check('reused base sequences reject old extension records',
      lambda image: damaged_extension(image, lambda record: struct.pack_into('<Q', record, 32, IDS['vanished.bin'] | (12 << 48))),
      wanted=-1, prefix=6144)
check('missing attribute instances reject foreign extension contents',
      lambda image: damaged_extension(image, lambda record: put16(record, u16(record, 20) + 14, 77)),
      wanted=-1, prefix=6144)
check('mismatched lowest VCN values reject extension mappings',
      lambda image: damaged_extension(image, lambda record: struct.pack_into('<Q', record, u16(record, 20) + 16, 13)),
      wanted=-1, prefix=6144)
check('an in-use extension cannot supply deleted file contents',
      lambda image: damaged_extension(image, lambda record: put16(record, 22, 1)), wanted=-1, prefix=6144)


def edit_list(image, change):
    split_deleted(image)
    record = get_record(image, IDS['vanished.bin'])
    offset, attr = data_attribute(record, 0x20)
    start = offset + u16(attr, 20)
    entries = []
    end = start + u32(attr, 16)
    while start < end:
        entries.append(start)
        start += u16(record, start + 4)
    change(record, entries)
    store_record(image, IDS['vanished.bin'], record)

check('truncated attribute list entries retain only the validated prefix',
      lambda image: edit_list(image, lambda record, entries: put16(record, entries[-1] + 4, 8)),
      wanted=-1, prefix=12288)
check('duplicate list references cannot duplicate file mappings',
      lambda image: edit_list(image, lambda record, entries: record.__setitem__(slice(entries[-1], entries[-1] + 32), record[entries[-2]:entries[-2] + 32])),
      wanted=-1, prefix=12288)
check('attribute list name mismatches cannot select an unnamed stream',
      lambda image: edit_list(image, lambda record, entries: record.__setitem__(entries[-1] + 6, 1)),
      wanted=-1, prefix=12288)


def extension_cycle(image):
    split_deleted(image)
    record = get_record(image, 24)
    values = [value for _, value in attributes(record)]
    values.insert(0, resident_attribute(0x20, bytes(32), 99))
    set_attributes(record, values)
    store_record(image, 24, record)

check('extension attribute-list cycles terminate without following links', extension_cycle, wanted=-1, prefix=6144)


def extension_name(image):
    number = IDS['vanished.bin']
    record = get_record(image, number)
    values = [value for _, value in attributes(record) if u32(value, 0) != 0x30]
    _, name = data_attribute(record, 0x30)
    attribute_list_image(image, number, values, [(24, [name])])

image = bytearray(ORIGINAL)
extension_name(image)
with Image(image) as disk:
    found = {row[0]: row for row in disk.listing()}
    assert found[IDS['vanished.bin']][1] == b'vanished.bin'
    assert not open_id(disk.fs, b'/ntfs', 24, 0)
    print('PASS: extension filenames attach to their base IDs and extension IDs cannot open independently')


def split_mft(image, nonresident=False):
    bitmap_set(image, 24, True, mft=True)
    bitmap_set(image, 40, True, mft=True)
    record = get_record(image, 0)
    _, old = data_attribute(record)
    count = sum(size for _, _, size in INFO['mft_runs']) // CLUSTER
    assert count == 150
    values = [value for _, value in attributes(record) if u32(value, 0) != 0x80]
    values.append(segment(old, 0, [(50, 32)], first=True))
    attribute_list_image(image, 0, values, [(24, [segment(old, 50, [(50, 3000)])]),
                                           (40, [segment(old, 100, [(50, 3200)])])], nonresident)
    for index in range(50, count):
        bitmap_set(image, 32 + index, False)
    for cluster in list(range(3000, 3050)) + list(range(3200, 3250)):
        bitmap_set(image, cluster, True)
    original = bytes(image)
    image[3000 * CLUSTER:3050 * CLUSTER] = original[(32 + 50) * CLUSTER:(32 + 100) * CLUSTER]
    image[3200 * CLUSTER:3250 * CLUSTER] = original[(32 + 100) * CLUSTER:(32 + 150) * CLUSTER]

check('fragmented MFT bootstrapping progressively resolves extension records', split_mft, raw=True)
check('fragmented MFT bootstrapping supports nonresident attribute lists', lambda image: split_mft(image, True), raw=True)


def external_mft_bitmap(image):
    bitmap_set(image, 24, True, mft=True)
    record = get_record(image, 0)
    values = [value for _, value in attributes(record) if u32(value, 0) != 0xb0]
    _, bitmap = data_attribute(record, 0xb0)
    attribute_list_image(image, 0, values, [(24, [bitmap])])

check('MFT allocation bitmaps can reside in extension records', external_mft_bitmap)


def split_volume_bitmap(image):
    record = get_record(image, 6)
    _, old = data_attribute(record)
    logical, physical, size = runs(old)[0]
    assert not logical and size > CLUSTER
    values = [value for _, value in attributes(record) if u32(value, 0) != 0x80]
    values.append(segment(old, 0, [(1, physical // CLUSTER)], first=True))
    attribute_list_image(image, 6, values, [(24, [segment(old, 1, [(size // CLUSTER - 1, physical // CLUSTER + 1)])])])

check('volume allocation bitmaps reconstruct continuation segments', split_volume_bitmap)


def long_named_list(image):
    number = IDS['live.txt']
    record = get_record(image, number)
    values = [value for _, value in attributes(record)]
    named = resident_attribute(0x80, b'named', 20, ('é' * 240).encode('utf-16le'))
    attribute_list_image(image, number, values, [(24, [named])], True)

check('fragmented nonresident lists read Unicode names across cluster boundaries', long_named_list)


def reused_list(image):
    split_deleted(image, True)
    bitmap_set(image, 16000, True)

check('reused nonresident attribute-list storage retains only base-record data', reused_list,
      wanted=-1, prefix=6144, conflict=True)


def owned_list(image):
    split_deleted(image, True)
    record = get_record(image, IDS['live.txt'])
    _, original = data_attribute(get_record(image, IDS['vanished.bin']))
    value = segment(original, 0, [(1, 16000)], first=True)
    struct.pack_into('<QQQ', value, 40, CLUSTER, CLUSTER, CLUSTER)
    offset, _ = data_attribute(record)
    replace_attr(record, offset, value)
    store_record(image, IDS['live.txt'], record)

check('live ownership protects attribute-list storage despite clear allocation bits', owned_list,
      wanted=-1, prefix=6144, conflict=True)


def unknown_list_bitmap(image):
    split_deleted(image, True)
    change_data(image, 6, lambda record, offset, attr: struct.pack_into('<Q', record, offset + 56, 512))

check('unknown attribute-list allocation retains the independently known prefix', unknown_list_bitmap,
      wanted=-1, prefix=6144)


def external_named_owner(image):
    number = IDS['live.txt']
    record = get_record(image, number)
    name = 'secret'.encode('utf-16le')
    start = (64 + len(name) + 7) & ~7
    value = bytearray(start) + mapping_pairs([(1, first)])
    value.extend(bytes((-len(value)) % 8))
    put32(value, 0, 0x80)
    put32(value, 4, len(value))
    value[8], value[9] = 1, len(name) // 2
    put16(value, 10, 64)
    put16(value, 14, 11)
    put16(value, 32, start)
    struct.pack_into('<QQQ', value, 40, CLUSTER, CLUSTER, CLUSTER)
    value[64:64 + len(name)] = name
    attribute_list_image(image, number, [value for _, value in attributes(record)], [(24, [value])])

check('named attributes in extension records protect live data ownership', external_named_owner,
      wanted=-1, prefix=0, conflict=True)


def broken_extension_fixup(image):
    split_deleted(image)
    image[INFO['record_offsets']['24'] + SECTOR - 1] ^= 1

check('damaged extension fixups preserve the valid base mapping', broken_extension_fixup, wanted=-1, prefix=6144)

image = bytearray(ORIGINAL)
record = get_record(image, IDS['sparse.bin'])
_, original = data_attribute(record)
values = [value for _, value in attributes(record) if u32(value, 0) != 0x80]
values.append(segment(original, 0, INFO['sparse_runs'][:1], first=True))
attribute_list_image(image, IDS['sparse.bin'], values,
                     [(24, [segment(original, 1, INFO['sparse_runs'][1:2])]),
                      (25, [segment(original, (1 << 32) // CLUSTER, INFO['sparse_runs'][2:])])])
with Image(image) as disk:
    handle = open_path(disk.fs, b'/ntfs/sparse.bin', False)
    assert handle
    try:
        status, found = collect_call(lambda cb: extents(handle, cb, None))
        assert status == 1 and len(found) == 3 and found[1][3] == 64
        assert read(disk.fs, handle, (1 << 32) - 2, 4) == 4
        assert C.string_at(File.from_address(handle).data, 4) == b'\0\0ZZ'
    finally:
        close(disk.fs, handle)
        free_file(handle)
print('PASS: attribute-list continuations preserve sparse mappings above four GiB')

image = bytearray(ORIGINAL)
split_mft(image)
image[INFO['record_offsets']['24'] + SECTOR - 1] ^= 1
with Image(image) as disk:
    handle = open_id(disk.fs, b'/ntfs', 0, 0)
    assert handle
    try:
        status, found = collect_call(lambda cb: extents(handle, cb, None))
        assert status == -1 and sum(row[2] for row in found) == 50 * CLUSTER
        assert collect_call(lambda cb: ranges(disk.fs, b'/ntfs', 4, cb, None))[0] == -1
    finally:
        close(disk.fs, handle)
        free_file(handle)
print('PASS: incomplete fragmented MFT maps retain inspection and refuse orphan claims')


def moved_nonresident(image):
    number = IDS['vanished.bin']
    record = get_record(image, number)
    values = [value for _, value in attributes(record) if u32(value, 0) != 0x80]
    _, data = data_attribute(record)
    attribute_list_image(image, number, values, [(24, [data])])

check('nonresident data can start entirely in an extension record', moved_nonresident, raw=True)


def reused_data_extension(image):
    split_deleted(image)
    bitmap_set(image, 25, True, mft=True)

check('allocated extension records protect their nonresident data runs', reused_data_extension,
      wanted=-1, prefix=12288, conflict=True)


def discontinuous_segment(image, start):
    def change(record):
        offset = u16(record, 20)
        struct.pack_into('<QQ', record, offset + 16, start, start + 11)
    damaged_extension(image, change)
    record = get_record(image, IDS['vanished.bin'])
    offset, attr = data_attribute(record, 0x20)
    entry = offset + u16(attr, 20)
    while entry < offset + u16(attr, 20) + u32(attr, 16):
        if (u64(record, entry + 16) & 0xffffffffffff) == 24:
            struct.pack_into('<Q', record, entry + 8, start)
        entry += u16(record, entry + 4)
    store_record(image, IDS['vanished.bin'], record)

check('logical gaps between valid continuation records stop recovery', lambda image: discontinuous_segment(image, 13),
      wanted=-1, prefix=6144)
check('overlapping valid continuation records stop recovery', lambda image: discontinuous_segment(image, 11),
      wanted=-1, prefix=6144)

image = bytearray(ORIGINAL)
split_deleted(image)
bitmap_set(image, first + 5, True)
with Image(image) as disk:
    handle = open_id(disk.fs, b'/ntfs', IDS['vanished.bin'], 2 | 4)
    assert handle
    try:
        status, found = collect_call(lambda cb: extents(handle, cb, None))
        assert status == -1 and sum(row[2] for row in found) == len(EXPECTED) - CLUSTER
        assert found[0][0] == 0 and found[0][2] == 5 * CLUSTER
        assert found[-1][0] + found[-1][2] == len(EXPECTED)
        assert read(disk.fs, handle, 0, len(EXPECTED)) == 5 * CLUSTER
        assert read(disk.fs, handle, 5 * CLUSTER, 1) == -1
    finally:
        close(disk.fs, handle)
        free_file(handle)
print('PASS: deleted-data salvage spans continuation records while reads retain the checked prefix')


def named_attribute(attr, name, instance=40):
    name = name.encode('utf-16le') if isinstance(name, str) else name
    if not attr[8]:
        start = u16(attr, 20)
        return resident_attribute(u32(attr, 0), bytes(attr[start:start + u32(attr, 16)]), instance, name)
    start = (64 + len(name) + 7) & ~7
    result = bytearray(attr[:64]) + name + bytes(start - 64 - len(name)) + attr[u16(attr, 32):]
    result.extend(bytes((-len(result)) % 8))
    put32(result, 4, len(result))
    result[9] = len(name) // 2
    put16(result, 10, 64)
    put16(result, 14, instance)
    put16(result, 32, start)
    return result


def add_named(image, number, name, payload=None, only=False):
    record = get_record(image, number)
    _, original = data_attribute(record)
    instance = max(u16(value, 14) for _, value in attributes(record)) + 1
    value = named_attribute(original, name, instance) if payload is None else resident_attribute(0x80, payload, instance, name.encode('utf-16le'))
    values = [value for _, value in attributes(record) if not only or u32(value, 0) not in (0x30, 0x80)]
    set_attributes(record, values + [value])
    store_record(image, number, record)


def stream_listing(disk, number=None, path=None, view=7):
    listing = dir_list(disk.fs, path or b'/ntfs', number if number is not None else 0xffffffffffffffff, view)
    try:
        return [(C.string_at(File.from_address(list_n(listing, index)).name),
                 File.from_address(list_n(listing, index)).id,
                 File.from_address(list_n(listing, index)).size,
                 File.from_address(list_n(listing, index)).flags)
                for index in range(list_length(listing) if listing else 0)]
    finally:
        list_free(listing)


def ads_id(disk, owner, name):
    return next(number for label, number, _, _ in stream_listing(disk, owner) if label == b'ads:' + name.encode())


def stream_payload(disk, selector, payload, flags=0, status=1, prefix=None, conflict=False, raw=False):
    handle = open_path(disk.fs, selector, False) if isinstance(selector, bytes) else open_id(disk.fs, b'/ntfs', selector, flags)
    assert handle, selector
    prefix = len(payload) if prefix is None else prefix
    try:
        state, found = collect_call(lambda cb: extents(handle, cb, None))
        assert state == status and sum(row[2] for row in found) == prefix, (selector, state, found)
        assert bool(File.from_address(handle).flags & 8) == conflict
        if prefix:
            assert read(disk.fs, handle, 0, len(payload)) == prefix
            assert C.string_at(File.from_address(handle).data, prefix) == payload[:prefix]
        if prefix < File.from_address(handle).size:
            assert read(disk.fs, handle, prefix, 1) == -1
        else:
            assert read(disk.fs, handle, prefix, 1) == 0
        if raw:
            for logical, physical, size, state in found:
                assert disk.image[physical:physical + size] == payload[logical:logical + size]
        return found
    finally:
        close(disk.fs, handle)
        free_file(handle)


image = bytearray(ORIGINAL)
add_named(image, 64, 'proof', b'live stream\n')
add_named(image, 65, 'history')
with Image(image) as disk:
    rows = stream_listing(disk, path=b'/ntfs/live.txt/..namedfork')
    assert [(name, size) for name, _, size, _ in rows] == [(b'data', 15), (b'ads:proof', 12)]
    stream_payload(disk, b'/ntfs/live.txt/..namedfork/data', b'Live NTFS file\n')
    stream_payload(disk, b'/ntfs/live.txt/..namedfork/ads:proof', b'live stream\n', raw=True)
    stream_payload(disk, ads_id(disk, 65, 'history'), EXPECTED, flags=2, raw=True)
    reads = len(disk.reads)
    assert stream_listing(disk, 64) == rows
    assert len(disk.reads) == reads
print('PASS: named resident and fragmented streams enumerate and recover through existing paths and IDs without rescanning')

image = bytearray(ORIGINAL)
add_named(image, 64, 'proof', b'cached stream')
with Image(image) as disk:
    number = ads_id(disk, 64, 'proof')
    record = get_record(disk.image, 64)
    put16(record, 16, u16(record, 16) + 1)
    store_record(disk.image, 64, record)
    assert not open_id(disk.fs, b'/ntfs', number, 0)
print('PASS: cached stream IDs cannot reopen a backing MFT record with a changed sequence')

image = bytearray(ORIGINAL)
add_named(image, 64, 'data', b'named data')
add_named(image, 64, 'empty', b'')
add_named(image, 64, 'é😀%/:\\', b'escaped')
record = get_record(image, 64)
set_attributes(record, [value for _, value in attributes(record)] +
               [resident_attribute(0x80, b'surrogate', 41, b'\x00\xd8')])
store_record(image, 64, record)
with Image(image) as disk:
    stream_payload(disk, b'/ntfs/live.txt/..namedfork/data', b'Live NTFS file\n')
    stream_payload(disk, b'/ntfs/live.txt/..namedfork/ads:data', b'named data')
    stream_payload(disk, b'/ntfs/live.txt/..namedfork/ads:empty', b'')
    stream_payload(disk, '/ntfs/live.txt/..namedfork/ads:é😀%25%2F%3A%5C'.encode(), b'escaped')
    stream_payload(disk, b'/ntfs/live.txt/..namedfork/ads:%uD800', b'surrogate')
    assert not open_path(disk.fs, b'/ntfs/live.txt/..namedfork/ads:missing', False)
    assert not dir_list(disk.fs, b'/ntfs/live.txt/..namedfork/ads:missing', 0xffffffffffffffff, 7)
    assert not open_id(disk.fs, b'/ntfs', (1 << 62) + 99999, 0)
    assert not open_id(disk.fs, b'/ntfs', (1 << 63) | (1 << 62), 0)
print('PASS: stream namespaces distinguish reserved names, empty data, Unicode and escaped separators and reject unknown selectors')

image = bytearray(ORIGINAL)
add_named(image, 65, 'only', b'anonymous stream', only=True)
with Image(image) as disk:
    assert any(number == 65 and name == b'mft-65' for number, name, _, _ in disk.listing(0))
    rows = stream_listing(disk, 65)
    assert [row[0] for row in rows] == [b'ads:only']
    stream_payload(disk, rows[0][1], b'anonymous stream', flags=2, raw=True)
print('PASS: nameless deleted records with only alternate data streams remain discoverable without inventing an unnamed stream')

image = bytearray(ORIGINAL)
record = get_record(image, 5)
values = [value for _, value in attributes(record)]
set_attributes(record, values + [resident_attribute(0x80, b'directory ADS', 40, 'proof'.encode('utf-16le'))])
store_record(image, 5, record)
with Image(image) as disk:
    assert [row[0] for row in stream_listing(disk, path=b'/ntfs/..namedfork')] == [b'ads:proof']
    stream_payload(disk, b'/ntfs/..namedfork/ads:proof', b'directory ADS', raw=True)
print('PASS: directories expose named data streams without changing ordinary child enumeration')

image = bytearray(ORIGINAL)
add_named(image, 65, 'directory', b'deleted directory ADS')
record = get_record(image, 65)
put16(record, 22, 2)
set_attributes(record, [value for _, value in attributes(record) if u32(value, 0) != 0x80 or value[9]])
store_record(image, 65, record)
with Image(image) as disk:
    assert not stream_listing(disk, 65)
    rows = stream_listing(disk, 65, path=b'/ntfs/..namedfork')
    assert [row[0] for row in rows] == [b'ads:directory']
    stream_payload(disk, rows[0][1], b'deleted directory ADS', flags=2, raw=True)
print('PASS: explicit fork-directory selection exposes deleted directory streams by owner ID')

image = bytearray(ORIGINAL)
add_named(image, 64, 'proof', b'linked ADS')
record = get_record(image, 64)
_, value = data_attribute(record, 0x30)
start = u16(value, 20)
payload = bytearray(value[start:start + u32(value, 16)])
name = 'alias.txt'.encode('utf-16le')
payload[64] = len(name) // 2
payload[66:] = name
set_attributes(record, [value for _, value in attributes(record)] + [resident_attribute(0x30, payload, 41)])
store_record(image, 64, record)
with Image(image) as disk:
    assert stream_listing(disk, path=b'/ntfs/alias.txt/..namedfork') == stream_listing(disk, path=b'/ntfs/live.txt/..namedfork')
    stream_payload(disk, b'/ntfs/alias.txt/..namedfork/ads:proof', b'linked ADS', raw=True)
print('PASS: hard-link aliases share the owning record streams and their snapshot IDs')


def split_named(image, nonresident=False):
    split_deleted(image, nonresident)
    for number in (65, 24, 25):
        record = get_record(image, number)
        values = [named_attribute(value, 'history') if u32(value, 0) == 0x80 else value
                  for _, value in attributes(record) if u32(value, 0) != 0x20]
        if number == 65:
            base_values = values
        else:
            if number == 24:
                extension1 = values
            else:
                extension2 = values
    attribute_list_image(image, 65, base_values, [(24, extension1), (25, extension2)], nonresident)


for nonresident in (False, True):
    image = bytearray(ORIGINAL)
    split_named(image, nonresident)
    with Image(image) as disk:
        stream_payload(disk, ads_id(disk, 65, 'history'), EXPECTED, flags=2, raw=True)
print('PASS: named data continuations reconstruct across resident and fragmented nonresident attribute lists')

image = bytearray(ORIGINAL)
split_named(image, True)
bitmap_set(image, 16000, True)
with Image(image) as disk:
    stream_payload(disk, ads_id(disk, 65, 'history'), EXPECTED, flags=2, status=-1, prefix=6144, conflict=True)
print('PASS: reused named-stream attribute-list storage preserves only the independently retained base prefix')

image = bytearray(ORIGINAL)
split_named(image)
record = get_record(image, 24)
put16(record, 16, 10)
store_record(image, 24, record)
with Image(image) as disk:
    rows = stream_listing(disk, 65)
    assert rows[0][3] & 4
    stream_payload(disk, ads_id(disk, 65, 'history'), EXPECTED, flags=2, status=-1, prefix=6144)
print('PASS: stale named-stream extension references retain a partial inspected mapping without selecting unrelated records')

image = bytearray(ORIGINAL)
record = get_record(image, 66)
_, value = data_attribute(record)
values = [value for _, value in attributes(record) if u32(value, 0) != 0x80]
named = named_attribute(value, 'resident')
padding = resident_attribute(0x40, bytes(256), 10)
attribute_list_image(image, 66, values, [(24, [padding, named])])
with Image(image, delta=4096) as disk:
    found = stream_payload(disk, ads_id(disk, 66, 'resident'), b'Resident NTFS recovery\n' * 16, flags=2, raw=True)
    assert len(found) >= 3
bitmap_set(image, 24, True, mft=True)
with Image(image) as disk:
    stream_payload(disk, ads_id(disk, 66, 'resident'), b'Resident NTFS recovery\n' * 16,
                   flags=2, status=-1, prefix=0, conflict=True)
print('PASS: named resident extension values map update-sequence bytes with mount offsets and refuse reused extension records')

image = bytearray(ORIGINAL)
add_named(image, 67, 'huge')
add_named(image, 68, 'uninitialized')
with Image(image) as disk:
    number = ads_id(disk, 67, 'huge')
    handle = open_id(disk.fs, b'/ntfs', number, 0)
    assert handle
    try:
        assert File.from_address(handle).size == 4294967808
        state, found = collect_call(lambda cb: extents(handle, cb, None))
        assert state == 1 and any(row[1] == 0xffffffffffffffff and row[3] & 64 for row in found)
        assert read(disk.fs, handle, 4294967296, 512) == 512
        assert C.string_at(File.from_address(handle).data, 512) == b'Z' * 512
    finally:
        close(disk.fs, handle)
        free_file(handle)
    stream_payload(disk, b'/ntfs/unwritten.bin/..namedfork/ads:uninitialized', b'Initialized NTFS\n' + bytes(1007))
print('PASS: alternate streams preserve 64-bit sparse mappings and zero uninitialized logical contents')

image = bytearray(ORIGINAL)
add_named(image, 65, 'history')
bitmap_set(image, first + 5, True)
with Image(image) as disk:
    number = ads_id(disk, 65, 'history')
    stream_payload(disk, number, EXPECTED, flags=2, status=-1, prefix=5 * CLUSTER, conflict=True)
    handle = open_id(disk.fs, b'/ntfs', number, 2 | 4)
    assert handle
    try:
        state, found = collect_call(lambda cb: extents(handle, cb, None))
        assert state == -1 and sum(row[2] for row in found) == len(EXPECTED) - CLUSTER
        assert read(disk.fs, handle, 0, len(EXPECTED)) == 5 * CLUSTER
    finally:
        close(disk.fs, handle)
        free_file(handle)
    assert not stream_listing(disk, 65, view=1)
    assert not open_id(disk.fs, b'/ntfs', ads_id(disk, 8, '$Bad'), 2)
print('PASS: named-stream recovery stops at reuse while salvage inspection retains later recoverable runs and respects visibility')

image = bytearray(ORIGINAL)
add_named(image, 65, 'duplicate', b'first')
record = get_record(image, 65)
set_attributes(record, [value for _, value in attributes(record)] +
               [resident_attribute(0x80, b'second', 41, 'duplicate'.encode('utf-16le'))])
store_record(image, 65, record)
with Image(image) as disk:
    rows = stream_listing(disk, 65)
    assert next(row[3] for row in rows if row[0] == b'ads:duplicate') & 12 == 12
    stream_payload(disk, ads_id(disk, 65, 'duplicate'), b'first', flags=2, status=-1, prefix=0, conflict=True)
print('PASS: duplicate named stream identities remain inspectable but cannot authorize checked recovery')

for flags in (1, 0x4000):
    image = bytearray(ORIGINAL)
    add_named(image, 65, 'unsupported')
    record = get_record(image, 65)
    offset, _ = data_attribute(record, named=True)
    put16(record, offset + 12, flags)
    store_record(image, 65, record)
    with Image(image) as disk:
        handle = open_id(disk.fs, b'/ntfs', ads_id(disk, 65, 'unsupported'), 0)
        assert handle
        try:
            assert collect_call(lambda cb: extents(handle, cb, None)) == (-2, [])
            assert read(disk.fs, handle, 0, 1) == -1
        finally:
            close(disk.fs, handle)
            free_file(handle)
print('PASS: compressed and encrypted alternate streams expose metadata without claiming unsupported recovery')
