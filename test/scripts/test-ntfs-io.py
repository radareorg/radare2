#!/usr/bin/env python3
"""Exercise NTFS MFT recovery, mapping pairs, allocation claims and damaged records."""
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
