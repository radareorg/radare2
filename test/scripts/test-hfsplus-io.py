#!/usr/bin/env python3
"""Check HFS+/HFSX allocation, historical names, hard links, forks and checked recovery."""
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
FIXTURES = ROOT / 'test/bins/fs/hfsplus-forensic'
MANIFEST = json.loads((FIXTURES / 'manifest.json').read_text())
INFO = MANIFEST['hfsplus']
ORIGINAL = gzip.decompress((FIXTURES / 'hfsplus.img.gz').read_bytes())
IDS = INFO['ids']
BLOCK, NODE = INFO['block_size'], INFO['node_size']
EXPECTED = b'D' * BLOCK + b'E' * BLOCK

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
    return struct.unpack_from('>H', data, offset)[0]


def u32(data, offset):
    return struct.unpack_from('>I', data, offset)[0]


def u64(data, offset):
    return struct.unpack_from('>Q', data, offset)[0]


def put16(data, offset, value):
    struct.pack_into('>H', data, offset, value)


def put32(data, offset, value):
    struct.pack_into('>I', data, offset, value)


def value_offset(image, name='vanished.bin'):
    location = INFO['deleted_locations'][name] if name in INFO['deleted_locations'] else INFO[name + '_location']
    start = INFO['catalog'] + location
    return start + u16(image, start) + 2


def bitmap_set(image, block, allocated=True):
    offset, mask = INFO['bitmap'] + block // 8, 128 >> (block % 8)
    image[offset] = image[offset] | mask if allocated else image[offset] & ~mask


def collect_call(call):
    result = []
    @Callback
    def collect(pointer, _):
        item = pointer.contents
        result.append((item.logical, item.physical, item.size, item.flags))
        return True
    return call(collect), result


class Image:
    def __init__(self, image, delta=0, aliases=(), failed=(), mounted=True):
        self.image = bytearray(delta) + image
        self.buffer = (C.c_ubyte * len(self.image)).from_buffer(self.image)
        self.reads = []
        @ReadAt
        def read_at(_, offset, destination, length):
            self.reads.append((offset, length))
            if length < 0 or any(offset < end and start < offset + length for start, end in failed):
                return -1
            for start, original, size in aliases:
                if start <= offset < start + size:
                    offset = original + offset - start
                    break
            if offset > len(self.image) or length > len(self.image) - offset:
                return -1
            C.memmove(destination, C.addressof(self.buffer) + offset, length)
            return length
        self.callback = read_at
        self.fs = new()
        binding = Binding.from_address(self.fs)
        binding.init = 1
        binding.read_at = C.cast(read_at, C.c_void_p).value
        assert bool(mount(self.fs, b'hfsplus', b'/hfs', delta)) == mounted

    def __enter__(self):
        return self

    def __exit__(self, *args):
        free(self.fs)

    def listing(self, number=0xffffffffffffffff, view=2):
        items = dir_list(self.fs, b'/hfs', number, view)
        try:
            return [(File.from_address(list_n(items, index)).id,
                     C.string_at(File.from_address(list_n(items, index)).name),
                     File.from_address(list_n(items, index)).flags)
                    for index in range(list_length(items) if items else 0)]
        finally:
            list_free(items)


def check(label, change=None, name='vanished.bin', expected=EXPECTED, prefix=None,
          wanted=1, conflict=False, delta=0, failed=()):
    image = bytearray(ORIGINAL)
    if change:
        change(image)
    prefix = len(expected) if prefix is None else prefix
    with Image(image, delta, failed=failed) as disk:
        handle = open_id(disk.fs, b'/hfs', IDS[name], 2)
        assert handle, label
        try:
            declared = File.from_address(handle).size
            status, found = collect_call(lambda cb: extents(handle, cb, None))
            assert status == wanted and sum(item[2] for item in found) == prefix, (label, status, found)
            assert bool(File.from_address(handle).flags & 8) == conflict, (label, File.from_address(handle).flags)
            assert File.from_address(handle).size == declared
            if prefix:
                assert read(disk.fs, handle, 0, prefix) == prefix, label
                assert C.string_at(File.from_address(handle).data, prefix) == expected[:prefix], label
                for logical, physical, length, state in found:
                    assert disk.image[physical:physical + length] == expected[logical:logical + length], label
            if prefix < declared and wanted == -1:
                assert read(disk.fs, handle, prefix, 1) == -1, label
            print('PASS:', label)
        finally:
            close(disk.fs, handle)
            free_file(handle)


check('free catalog nodes retain fragmented deleted file mappings')
check('allocated catalog leaf slack retains deleted file data', name='slack.txt', expected=b'Deleted from catalog slack\n')
check('deleted directory children remain discoverable by directory record ID', name='child.txt', expected=b'child\n')
check('extent mappings include nonzero mount offsets', delta=4096)
check('allocated first data blocks refuse recovery', lambda image: bitmap_set(image, 110), wanted=-1, prefix=0, conflict=True)
check('allocated later blocks retain the readable prefix', lambda image: bitmap_set(image, 112), wanted=-1, prefix=512, conflict=True)

with Image(bytearray(ORIGINAL)) as disk:
    root = {name: number for number, name, flags in disk.listing()}
    assert set(root) == {b'gone', b'slack.txt', b'vanished.bin'}
    assert disk.listing(IDS['gone']) == [(IDS['child.txt'], b'child.txt', 3)]
    assert {number for number, _, _ in disk.listing(0)} == set(IDS.values())
    print('PASS: deleted enumeration preserves location IDs, directories and name-independent scanning')
    handle = open_path(disk.fs, b'/hfs/fragmented.bin', False)
    assert handle
    try:
        status, found = collect_call(lambda cb: extents(handle, cb, None))
        assert status == 1 and len(found) == 9
        assert read(disk.fs, handle, 0, 9 * BLOCK) == 9 * BLOCK
        assert C.string_at(File.from_address(handle).data, 9 * BLOCK) == b''.join(bytes([65 + index]) * BLOCK for index in range(9))
        assert read(disk.fs, handle, 9 * BLOCK, 1) == 0
        print('PASS: live data forks follow the extents overflow tree and preserve EOF')
    finally:
        close(disk.fs, handle)
        free_file(handle)
    status, found = collect_call(lambda cb: ranges(disk.fs, b'/hfs', 2 | 1 | 8, cb, None))
    assert status == 1 and sum(row[2] for row in found) == len(ORIGINAL)
    assert all(a[0] + a[2] == b[0] for a, b in zip(found, found[1:]))
    assert collect_call(lambda cb: ranges(disk.fs, b'/hfs', 4, cb, None)) == (1, [(126 * BLOCK, 126 * BLOCK, BLOCK, 6)])
    assert collect_call(lambda cb: ranges(disk.fs, b'/hfs', 8, cb, None)) == (1, [(124 * BLOCK, 124 * BLOCK, BLOCK, 8)])
    print('PASS: allocation ranges cover the volume and separate bad blocks and allocated orphans')
    before = len(disk.reads)
    assert disk.listing() and disk.listing()
    assert len(disk.reads) == before
    print('PASS: mounted catalog evidence is cached without repeated metadata scans')


def map_first(image, block):
    put32(image, value_offset(image) + 88 + 16, block)
    bitmap_set(image, block, False)

for block, label in ((80, 'live data'), (120, 'resource forks'), (122, 'attribute forks'),
                     (98, 'live overflow extents'), (68, 'startup metadata'),
                     (69, 'journal info'), (70, 'journal storage'), (2, 'volume headers'),
                     (254, 'alternate volume headers'), (20, 'catalog metadata'),
                     (4, 'overflow metadata'), (3, 'allocation metadata'), (124, 'bad blocks')):
    check(label + ' protect storage despite cleared allocation bits',
          lambda image, block=block: map_first(image, block), wanted=-1, prefix=0, conflict=True)

check('unmounted-state inconsistencies refuse checked recovery',
      lambda image: put32(image, 1028, u32(image, 1028) & ~(1 << 8)), wanted=-1, prefix=0)
check('boot-volume inconsistencies refuse checked recovery',
      lambda image: put32(image, 1028, u32(image, 1028) | (1 << 11)), wanted=-1, prefix=0)


def journal_checksum(image, little=False):
    start = 70 * BLOCK
    struct.pack_into('<I' if little else '>I', image, start + 36, 0)
    value = 0
    for byte in image[start:start + 44]:
        value = ((value << 8) ^ (value + byte)) & 0xffffffff
    struct.pack_into('<I' if little else '>I', image, start + 36, (~value) & 0xffffffff)


def pending_journal(image):
    struct.pack_into('>Q', image, 70 * BLOCK + 16, 1024)
    journal_checksum(image)

check('pending journal transactions refuse current free-data recovery', pending_journal, wanted=-1, prefix=0)
check('journal checksum corruption refuses checked recovery',
      lambda image: put32(image, 70 * BLOCK + 36, 0), wanted=-1, prefix=0)
check('external journal state cannot establish current ownership',
      lambda image: put32(image, 69 * BLOCK, 2), wanted=-1, prefix=0)


def little_journal(image):
    struct.pack_into('<IIQQQIII', image, 70 * BLOCK, 0x4a4e4c78, 0x12345678, 512, 512, 4 * BLOCK, 512, 0, 512)
    journal_checksum(image, True)

check('empty journals validate in either byte order', little_journal)

check('invalid catalog child cycles refuse ownership claims',
      lambda image: put32(image, INFO['catalog'] + NODE + 14 + 2 + 6 + len('Forensic') * 2, 1),
      wanted=-1, prefix=0)
check('reachable leaves with clear B-tree allocation bits remain protected',
      lambda image: image.__setitem__(INFO['catalog'] + 248, 0xc0), wanted=-1, prefix=0)
check('mismatched catalog leaf counts refuse ownership claims',
      lambda image: put32(image, INFO['catalog'] + 20, 999), wanted=-1, prefix=0)
check('looped catalog sibling links refuse ownership claims',
      lambda image: put32(image, INFO['catalog'] + 2 * NODE, 2), wanted=-1, prefix=0)
check('reused CNIDs refuse deleted recovery',
      lambda image: put32(image, value_offset(image) + 8, 20), wanted=-1, prefix=0, conflict=True)


def duplicate_extent(image):
    put32(image, value_offset(image) + 88 + 24, 110)

check('overlapping retained physical extents stop recovery', duplicate_extent, wanted=-1, prefix=512, conflict=True)
check('damaged later extents retain the validated prefix',
      lambda image: put32(image, value_offset(image) + 88 + 24, 300), wanted=-1, prefix=512)


def truncated_fork(image):
    offset = value_offset(image) + 88
    struct.pack_into('>Q', image, offset, 1536)
    put32(image, offset + 12, 3)

check('missing overflow mappings preserve declared size and readable bytes', truncated_fork, wanted=-1, prefix=1024)
check('unknown allocation bytes never become free data', wanted=-1, prefix=0,
      failed=[(INFO['bitmap'], INFO['bitmap'] + 32)])
with Image(bytearray(ORIGINAL), failed=[(INFO['bitmap'], INFO['bitmap'] + 32)]) as disk:
    status, found = collect_call(lambda cb: ranges(disk.fs, b'/hfs', 1, cb, None))
    assert status == -1 and not found
    status, found = collect_call(lambda cb: ranges(disk.fs, b'/hfs', 16, cb, None))
    assert status == -1 and found and all(row[3] == 16 for row in found)
print('PASS: unreadable allocation bitmaps emit unknown ranges rather than free ranges')

for name in ('hfsx', 'hfsplus-4k', 'wrapped'):
    image = bytearray(gzip.decompress((FIXTURES / (name + '.img.gz')).read_bytes()))
    info = MANIFEST[name]
    with Image(image, delta=2048) as disk:
        assert {number for number, _, _ in disk.listing(0)} == set(info['ids'].values())
        handle = open_id(disk.fs, b'/hfs', info['ids']['vanished.bin'], 2)
        assert handle
        try:
            status, found = collect_call(lambda cb: extents(handle, cb, None))
            block = info['block_size']
            assert status == 1 and sum(row[2] for row in found) == 2 * block
            assert found[0][1] == 2048 + info.get('embedded_offset', 0) + 110 * block
            assert read(disk.fs, handle, 0, 2 * block) == 2 * block
            assert C.string_at(File.from_address(handle).data, 2 * block) == b'D' * block + b'E' * block
        finally:
            close(disk.fs, handle)
            free_file(handle)
        handle = open_path(disk.fs, b'/hfs/LIVE.TXT', False)
        assert bool(handle) == (name != 'hfsx')
        if handle:
            close(disk.fs, handle)
            free_file(handle)
    print('PASS:', name, 'uses the correct geometry, case policy, wrapper and physical offsets')

image = bytearray(ORIGINAL)
bitmap_set(image, 110, True)
with Image(image) as disk:
    handle = open_id(disk.fs, b'/hfs', IDS['vanished.bin'], 2 | 4)
    assert handle
    try:
        assert collect_call(lambda cb: extents(handle, cb, None)) == (-1, [(512, 112 * BLOCK, 512, 1)])
        assert read(disk.fs, handle, 0, 1) == -1
        assert File.from_address(handle).size == 1024
    finally:
        close(disk.fs, handle)
        free_file(handle)
print('PASS: deleted-data salvage exposes later free extents while extraction retains the safe prefix')

with Image(bytearray(ORIGINAL)) as disk:
    handle = open_id(disk.fs, b'/hfs', IDS['vanished.bin'], 2)
    assert handle
    try:
        calls = []
        @Callback
        def stop(pointer, _):
            calls.append(pointer.contents.physical)
            return False
        assert extents(handle, stop, None) == 0 and len(calls) == 1
        assert read(disk.fs, handle, 0, 1024) == 1024
    finally:
        close(disk.fs, handle)
        free_file(handle)
print('PASS: callback cancellation does not install an incomplete recovery plan')


def append_free_overflow(image, ambiguous=False):
    block = BLOCK
    start = INFO['overflow']
    struct.pack_into('>Q', image, 1024 + 192, 3 * NODE)
    put32(image, 1024 + 192 + 12, 3 * NODE // block)
    struct.pack_into('>II', image, 1024 + 192 + 24, 150, NODE // block)
    put32(image, start + 36, 3)
    put32(image, start + 40, 1)
    for cluster in range(150, 150 + NODE // block):
        bitmap_set(image, cluster, True)
    node = bytearray(NODE)
    struct.pack_into('>bBH', node, 8, -1, 1, 2 if ambiguous else 1)
    offset = 14
    for index in range(2 if ambiguous else 1):
        entry = bytearray(struct.pack('>HBBII', 10, 0, 0, 30, 8)) + bytearray(64)
        struct.pack_into('>II', entry, 12, 148 + index, 1)
        node[offset:offset + len(entry)] = entry
        put16(node, NODE - (index + 1) * 2, offset)
        offset += len(entry)
    put16(node, NODE - ((2 if ambiguous else 1) + 1) * 2, offset)
    image[150 * block:150 * block + NODE] = node
    offset = value_offset(image) + 88
    image[offset:offset + 80] = bytes(80)
    struct.pack_into('>Q', image, offset, 9 * block)
    put32(image, offset + 12, 9)
    for index in range(8):
        struct.pack_into('>II', image, offset + 16 + index * 8, 130 + index * 2, 1)
    for index, cluster in enumerate([130 + index * 2 for index in range(8)] + [148]):
        image[cluster * block:(cluster + 1) * block] = bytes([97 + index]) * block

extended_data = b''.join(bytes([97 + index]) * BLOCK for index in range(9))
check('unique retained overflow records extend deleted fork mappings', append_free_overflow, expected=extended_data)
check('ambiguous retained overflow records preserve only the inline prefix',
      lambda image: append_free_overflow(image, True), expected=extended_data, wanted=-1, prefix=8 * BLOCK)


def modern_folder_count(image):
    node = INFO['catalog'] + 2 * NODE
    offset = node + u16(image, node + NODE - 2)
    value = offset + u16(image, offset) + 2
    put32(image, value + 84, 1)

check('modern folder-count fields do not invalidate live catalog ownership', modern_folder_count)


def special_entry(image):
    put16(image, value_offset(image, 'live') + 42, 0o20600)

check('special live files still protect resource-fork storage', special_entry)

image = bytearray(ORIGINAL)
image[value_offset(image) + 41] |= 0x20
with Image(image) as disk:
    handle = open_id(disk.fs, b'/hfs', IDS['vanished.bin'], 2)
    assert handle
    try:
        assert collect_call(lambda cb: extents(handle, cb, None))[0] == -2
        assert read(disk.fs, handle, 0, 1) == -1
    finally:
        close(disk.fs, handle)
        free_file(handle)
print('PASS: compressed data is reported as unsupported rather than a complete raw recovery')

image = bytearray(gzip.decompress((FIXTURES / 'hfsplus-4k.img.gz').read_bytes()))
info = MANIFEST['hfsplus-4k']
block, high = info['block_size'], 0x40000000
value = info['catalog'] + info['live_location']
value += u16(image, value) + 2
put32(image, value + 88 + 16, high)
put32(image, 1024 + 44, high + 256)
with Image(image, aliases=[(high * block, 80 * block, block)]) as disk:
    handle = open_path(disk.fs, b'/hfs/live.txt', False)
    assert handle
    try:
        status, found = collect_call(lambda cb: extents(handle, cb, None))
        assert status == -1 and found == [(0, high * block, 15, 16)]
        assert read(disk.fs, handle, 0, 15) == 15
        assert C.string_at(File.from_address(handle).data, 15) == b'Live HFS+ file\n'
    finally:
        close(disk.fs, handle)
        free_file(handle)
print('PASS: physical file offsets above four TiB remain 64-bit even when allocation is unknown')

image = bytearray(ORIGINAL)
value = value_offset(image, 'live') + 88
length = (1 << 32) + BLOCK
struct.pack_into('>Q', image, value, length)
put32(image, value + 12, length // BLOCK)
struct.pack_into('>II', image, value + 16, 1000, length // BLOCK)
put32(image, 1024 + 44, 1000 + length // BLOCK + 10)
with Image(image, aliases=[(1000 * BLOCK + (1 << 32), 80 * BLOCK, BLOCK)]) as disk:
    handle = open_path(disk.fs, b'/hfs/live.txt', False)
    assert handle
    try:
        assert File.from_address(handle).size == length
        assert read(disk.fs, handle, 1 << 32, 15) == 15
        assert C.string_at(File.from_address(handle).data, 15) == b'Live HFS+ file\n'
        assert read(disk.fs, handle, length, 1) == 0
    finally:
        close(disk.fs, handle)
        free_file(handle)
print('PASS: large logical files preserve sizes, seeks and EOF above four GiB')


def invalid_live_name(image):
    location = INFO['catalog'] + INFO['live_location']
    put16(image, location + 8, 0xd800)

check('unrepresentable live names preserve current ownership and checked recovery', invalid_live_name)
image = bytearray(ORIGINAL)
invalid_live_name(image)
with Image(image) as disk:
    assert (20, b'live.txt', 2) in disk.listing(view=1)
print('PASS: unrepresentable live names recover through matching catalog threads')


def catalog_map_node(image):
    catalog = INFO['catalog']
    image[128 * BLOCK:] = bytes(len(image) - 128 * BLOCK)
    descriptor = 1024 + 272
    struct.pack_into('>Q', image, descriptor, 20 * NODE)
    put32(image, descriptor + 12, 20 * NODE // BLOCK)
    struct.pack_into('>II', image, descriptor + 24, 128, 128)
    put32(image, catalog, 19)
    put32(image, catalog + 36, 20)
    put32(image, catalog + 40, 16)
    put16(image, catalog + NODE - 8, 250)
    image[catalog + 248:catalog + 250] = b'\xe0\0'
    for block in range(128, 256):
        bitmap_set(image, block, True)
    start = 128 * BLOCK + 15 * NODE
    node = bytearray(NODE)
    struct.pack_into('>bBH', node, 8, 2, 0, 1)
    node[14] = 0x10
    put16(node, NODE - 2, 14)
    put16(node, NODE - 4, NODE - 4)
    image[start:start + NODE] = node

check('B-tree allocation maps follow additional map nodes', catalog_map_node)
check('damaged free-node descriptors do not erase retained catalog evidence',
      lambda image: image.__setitem__(INFO['catalog'] + 3 * NODE + 8, 0x7f))
check('malformed free catalog keys do not affect other deleted entries',
      lambda image: put16(image, INFO['catalog'] + INFO['deleted_locations']['vanished.bin'], 65535),
      name='slack.txt', expected=b'Deleted from catalog slack\n')

with Image(bytearray(ORIGINAL), failed=[(112 * BLOCK, 113 * BLOCK)]) as disk:
    handle = open_id(disk.fs, b'/hfs', IDS['vanished.bin'], 2)
    assert handle
    try:
        assert read(disk.fs, handle, 0, 1024) == 512
        assert C.string_at(File.from_address(handle).data, 512) == EXPECTED[:512]
        assert read(disk.fs, handle, 512, 1) == -1
        assert File.from_address(handle).size == 1024
    finally:
        close(disk.fs, handle)
        free_file(handle)
print('PASS: physical read errors retain the available prefix without changing declared file size')


def missing_attribute_tail(image):
    offset = INFO['attributes'] + NODE + 14
    value = offset + u16(image, offset) + 2
    put32(image, value + 8 + 12, 2)

check('missing attribute continuation records refuse complete ownership', missing_attribute_tail,
      wanted=-1, prefix=0)


def attribute_continuation(image):
    start = INFO['attributes'] + NODE
    first = start + 14
    key_length = u16(image, first) + 2
    value = first + key_length
    struct.pack_into('>Q', image, value + 8, BLOCK + 9)
    put32(image, value + 8 + 12, 2)
    record = bytearray(image[first:first + key_length]) + struct.pack('>II', 0x30, 0) + bytes(64)
    put32(record, 8, 1)
    struct.pack_into('>II', record, key_length + 8, 123, 1)
    offset = u16(image, start + NODE - 4)
    image[start + offset:start + offset + len(record)] = record
    put16(image, start + 10, 2)
    put16(image, start + NODE - 6, offset + len(record))
    put32(image, INFO['attributes'] + 20, 2)
    bitmap_set(image, 123, True)

check('complete attribute continuation records establish ownership', attribute_continuation)


def owned_attribute_tail(image):
    attribute_continuation(image)
    map_first(image, 123)

check('attribute continuation extents protect their data despite clear allocation bits', owned_attribute_tail,
      wanted=-1, prefix=0, conflict=True)


def extra_attribute_tail(image):
    attribute_continuation(image)
    first = INFO['attributes'] + NODE + 14
    value = first + u16(image, first) + 2
    struct.pack_into('>Q', image, value + 8, 9)
    put32(image, value + 8 + 12, 1)

check('unexpected live attribute continuations refuse complete ownership', extra_attribute_tail,
      wanted=-1, prefix=0)


def duplicate_attribute_tail(image):
    attribute_continuation(image)
    start = INFO['attributes'] + NODE
    first, end = u16(image, start + NODE - 4), u16(image, start + NODE - 6)
    record = bytes(image[start + first:start + end])
    image[start + end:start + end + len(record)] = record
    put16(image, start + 10, 3)
    put16(image, start + NODE - 8, end + len(record))
    put32(image, INFO['attributes'] + 20, 3)

check('duplicate live attribute continuations refuse complete ownership', duplicate_attribute_tail,
      wanted=-1, prefix=0)

NAMES = gzip.decompress((FIXTURES / 'names-forks.img.gz').read_bytes())
NINFO = MANIFEST['names-forks']


def catalog_address(image, logical):
    offset = 1024 + 272
    for index in range(8):
        block, count = struct.unpack_from('>II', image, offset + 16 + index * 8)
        size = count * BLOCK
        if logical < size:
            return block * BLOCK + logical
        logical -= size
    raise AssertionError('catalog offset outside mapped extents')


def names_value(image, cnid=None, name=None):
    logical = NINFO['live_locations'][str(cnid)] if cnid is not None else NINFO['deleted_locations'][name]
    start = catalog_address(image, logical)
    return start + u16(image, start) + 2


def named_streams(disk, owner=None, path=None, view=7):
    listing = dir_list(disk.fs, path or b'/hfs', owner if owner is not None else 0xffffffffffffffff, view)
    try:
        return [(C.string_at(File.from_address(list_n(listing, index)).name),
                 File.from_address(list_n(listing, index)).id,
                 File.from_address(list_n(listing, index)).size,
                 File.from_address(list_n(listing, index)).flags)
                for index in range(list_length(listing) if listing else 0)]
    finally:
        list_free(listing)


def check_payload(disk, selector, expected, flags=0, status=1, prefix=None, conflict=False):
    handle = open_path(disk.fs, selector, False) if isinstance(selector, bytes) else open_id(disk.fs, b'/hfs', selector, flags)
    assert handle, selector
    prefix = len(expected) if prefix is None else prefix
    try:
        state, found = collect_call(lambda cb: extents(handle, cb, None))
        assert state == status and sum(row[2] for row in found) == prefix, (selector, state, found)
        assert bool(File.from_address(handle).flags & 8) == conflict
        if prefix:
            assert read(disk.fs, handle, 0, len(expected)) == prefix
            assert C.string_at(File.from_address(handle).data, prefix) == expected[:prefix]
        if prefix < File.from_address(handle).size:
            assert read(disk.fs, handle, prefix, 1) == -1
        return found
    finally:
        close(disk.fs, handle)
        free_file(handle)


with Image(bytearray(NAMES)) as disk:
    check_payload(disk, b'/hfs/linked.txt', b'Hard link contents\n')
    check_payload(disk, b'/hfs/linked-again.txt', b'Hard link contents\n')
    check_payload(disk, b'/hfs/linked.txt/..namedfork/rsrc', b'Linked resource\n')
    check_payload(disk, b'/hfs/linked.txt/..namedfork/xattr:user.linked', b'linked attr\n')
    print('PASS: hard links resolve data, resource forks and attributes through the validated backing inode')
    check_payload(disk, b'/hfs/linked-dir/inside.txt', b'directory child\n')
    check_payload(disk, b'/hfs/linked-dir/../linked.txt', b'Hard link contents\n')
    assert named_streams(disk, path=b'/hfs/linked-dir', view=1)[0][0] == b'inside.txt'
    print('PASS: directory hard links preserve traversal and logical parent navigation')
    for path, payload in ((b'/hfs/CAF\xc3\x89.TXT', b'unicode\n'), ('/hfs/CA\u200dFÉ.TXT'.encode(), b'unicode\n'),
                          ('/hfs/ΑΘΗΝΑ'.encode(), b'greek\n'),
                          ('/hfs/가.txt'.encode(), b'hangul\n'), (b'/hfs/percent%25%2Ffile', b'escaped\n')):
        check_payload(disk, path, payload)
    print('PASS: fixed HFS+ Unicode folding, canonical decomposition, Hangul and escaped names match correctly')
    for path, expected in ((b'/hfs/live.txt/..namedfork/rsrc', b'resource'),
                           (b'/hfs/live.txt/..namedfork/xattr:demo', b'attribute'),
                           (b'/hfs/live.txt/..namedfork/xattr:com.example.inline', b'inline attr\n'),
                           (b'/hfs/live.txt/..namedfork/xattr:com.example.fragmented', b'X' * 512 + b'Y' * 88)):
        check_payload(disk, path, expected)
    print('PASS: live resource forks and inline or fragmented external attributes use ordinary file reads')
    assert not open_path(disk.fs, b'/hfs/live.txt/..namedfork/missing', False)
    assert not dir_list(disk.fs, b'/hfs/live.txt/..namedfork/missing', 0xffffffffffffffff, 7)
    print('PASS: unknown fork names do not expose another stream or a directory listing')
    streams = named_streams(disk, NINFO['ids']['vanished.bin'])
    by_name = {}
    for name, number, size, flags in streams:
        by_name.setdefault(name, []).append(number)
    check_payload(disk, by_name[b'xattr:user.deleted'][0], b'old attribute\n', flags=2)
    found = check_payload(disk, by_name[b'xattr:user.inline'][0], b'deleted inline\n', flags=2)
    assert all(row[3] == 2 for row in found)
    check_payload(disk, by_name[b'xattr:user.big'][0], b'G' * 512 + b'H' * 188, flags=2)
    check_payload(disk, by_name[b'xattr:user.history'][0], b'one\n', flags=2)
    check_payload(disk, by_name[b'xattr:user.history'][1], b'two\n', flags=2)
    print('PASS: retained inline and nonresident attributes recover distinct versions by stream ID')
    removed = named_streams(disk, path=b'/hfs/live.txt/..namedfork', view=2)
    assert len(removed) == 1 and removed[0][0] == b'xattr:user.removed'
    check_payload(disk, removed[0][1], b'removed attr\n', flags=2)
    print('PASS: deleted attributes of a surviving file remain explicitly heuristic recoveries')
    check_payload(disk, NINFO['ids']['unlinked.txt'], b'Recovered linked file\n', flags=2)
    linked = named_streams(disk, NINFO['ids']['unlinked.txt'])
    resource = next(number for name, number, _, _ in linked if name == b'rsrc')
    check_payload(disk, resource, b'Recovered resource\n', flags=2)
    check_payload(disk, NINFO['ids']['removed-but-linked.txt'], b'Hard link contents\n', flags=2,
                  status=-1, prefix=0, conflict=True)
    print('PASS: deleted hard links recover freed backing forks and refuse current live inode data')
    child = named_streams(disk, NINFO['ids']['lost-dir'])
    assert [item[0] for item in child] == [b'child.txt']
    check_payload(disk, NINFO['ids']['lost-dir/child.txt'], b'lost child\n', flags=2)
    assert not named_streams(disk, NINFO['ids']['old-a']) and not named_streams(disk, NINFO['ids']['old-b'])
    print('PASS: retained directory threads restore ancestry while ambiguous parent versions remain unattached')
    thread = open_id(disk.fs, b'/hfs', NINFO['ids']['thread-only.txt'], 2)
    assert thread
    try:
        assert collect_call(lambda cb: extents(thread, cb, None)) == (-1, [])
        assert read(disk.fs, thread, 0, 1) == -1
    finally:
        close(disk.fs, thread)
        free_file(thread)
    print('PASS: thread-only file names cannot masquerade as recoverable empty files')
    orphan = next(row for row in named_streams(disk, 0, view=2) if row[0] == b'cnid-999:xattr:user.orphan')
    check_payload(disk, orphan[1], b'orphan attr\n', flags=2)
    print('PASS: name-independent discovery exposes retained orphan attributes with recoverable inline values')

image = bytearray(NAMES)
put16(image, 1024, 0x4858)
put16(image, 1026, 5)
image[NINFO['catalog'] + 51] = 0xbc
with Image(image) as disk:
    check_payload(disk, '/hfs/Café.txt'.encode(), b'unicode\n')
    assert not open_path(disk.fs, '/hfs/CAFÉ.TXT'.encode(), False)
    assert not open_path(disk.fs, '/hfs/Ca\u200dfé.txt'.encode(), False)
print('PASS: HFSX binary matching preserves canonical normalization and case sensitivity')

image = bytearray(NAMES)
value = names_value(image, 22)
put32(image, value + 12, u32(image, value + 12) + 1)
with Image(image) as disk:
    assert not open_path(disk.fs, b'/hfs/linked.txt', False)
    check_payload(disk, b'/hfs/linked-again.txt', b'Hard link contents\n')
    check_payload(disk, NINFO['ids']['vanished.bin'], EXPECTED, flags=2, status=-1, prefix=0)
print('PASS: invalid hard-link creation references never expose empty placeholders or authorize recovery')

image = bytearray(NAMES)
start = catalog_address(image, NINFO['live_locations']['24'])
put32(image, start + 2, 41)
with Image(image) as disk:
    assert not dir_list(disk.fs, b'/hfs', 24, 7)
    check_payload(disk, NINFO['ids']['vanished.bin'], EXPECTED, flags=2, status=-1, prefix=0)
print('PASS: directory hard-link cycles terminate and invalidate ownership completeness')

image = bytearray(NAMES)
bitmap_set(image, 136, True)
with Image(image) as disk:
    resource = next(number for name, number, _, _ in named_streams(disk, NINFO['ids']['unlinked.txt']) if name == b'rsrc')
    check_payload(disk, resource, b'Recovered resource\n', flags=2, status=-1, prefix=0, conflict=True)
print('PASS: reused deleted resource-fork blocks refuse recovery')

image = bytearray(NAMES)
bitmap_set(image, 148, True)
with Image(image) as disk:
    big = next(number for name, number, _, _ in named_streams(disk, NINFO['ids']['vanished.bin']) if name == b'xattr:user.big')
    check_payload(disk, big, b'G' * 512 + b'H' * 188, flags=2, status=-1, prefix=512, conflict=True)
print('PASS: partially reused attribute continuations retain only the checked prefix')
