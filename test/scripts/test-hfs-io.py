#!/usr/bin/env python3
"""Check Classic HFS catalog recovery, allocation and slack without platform tools."""
import ctypes as C
import gzip
import json
import os
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
SUFFIX = 'dylib' if sys.platform == 'darwin' else 'so'
fs = C.CDLL(str(os.environ.get('R2_FS_LIB', ROOT / f'libr/fs/libr_fs.{SUFFIX}')))
FIXTURES = ROOT / 'test/bins/fs/hfs-forensic'
MANIFEST = json.loads((FIXTURES / 'manifest.json').read_text())
INFO = MANIFEST['hfs']
ORIGINAL = gzip.decompress((FIXTURES / 'hfs.img.gz').read_bytes())
IDS = INFO['ids']
BLOCK, NODE = INFO['block'], 512
EXPECTED = b'D' * BLOCK + b'E' * BLOCK + b'F' * BLOCK + b'G' * 17

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


def value_offset(image, name='vanished.bin', info=INFO):
    location = info['catalog'] + info['locations'][name]
    return location + ((image[location] + 2) & ~1)


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
        assert bool(mount(self.fs, b'hfs', b'/hfs', delta)) == mounted

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


def stream_rows(disk, owner=None, path=None, view=7):
    listing = dir_list(disk.fs, path or b'/hfs', owner if owner is not None else 0xffffffffffffffff, view)
    try:
        return [(C.string_at(File.from_address(list_n(listing, index)).name),
                 File.from_address(list_n(listing, index)).id,
                 File.from_address(list_n(listing, index)).size,
                 File.from_address(list_n(listing, index)).flags)
                for index in range(list_length(listing) if listing else 0)]
    finally:
        list_free(listing)


def payload(disk, selector, expected, flags=0, status=1, prefix=None, conflict=False, raw=True):
    handle = open_path(disk.fs, selector, False) if isinstance(selector, bytes) else open_id(disk.fs, b'/hfs', selector, flags)
    assert handle, selector
    prefix = len(expected) if prefix is None else prefix
    try:
        declared = File.from_address(handle).size
        state, found = collect_call(lambda cb: extents(handle, cb, None))
        assert state == status and sum(row[2] for row in found) == prefix, (selector, state, found)
        assert bool(File.from_address(handle).flags & 8) == conflict, (selector, File.from_address(handle).flags)
        if prefix:
            assert read(disk.fs, handle, 0, len(expected)) == prefix
            assert C.string_at(File.from_address(handle).data, prefix) == expected[:prefix]
        assert File.from_address(handle).size == declared
        if prefix < declared:
            assert read(disk.fs, handle, prefix, 1) == -1
        elif status == 1:
            assert read(disk.fs, handle, prefix, 1) == 0
        if raw:
            for logical, physical, size, _ in found:
                assert disk.image[physical:physical + size] == expected[logical:logical + size]
        return found
    finally:
        close(disk.fs, handle)
        free_file(handle)


def check(label, change=None, name='vanished.bin', expected=EXPECTED, status=1, prefix=None, conflict=False, delta=0, failed=()):
    image = bytearray(ORIGINAL)
    if change:
        change(image)
    with Image(image, delta=delta, failed=failed) as disk:
        payload(disk, IDS[name], expected, flags=2, status=status, prefix=prefix, conflict=conflict)
    print('PASS:', label)


check('free catalog nodes recover retained names and fragmented data through extent overflow records')
check('allocated catalog leaf slack retains recoverable deleted files', name='slack.txt', expected=b'Catalog slack recovery\n')
check('deleted directory children recover by catalog-location ID', name='child.txt', expected=b'child\n')
check('retained directory threads restore child ancestry', name='lost-child', expected=b'lost child\n')
check('physical mappings include mount deltas', delta=4096)
check('allocated first blocks reject checked extraction', lambda image: bitmap_set(image, 104), status=-1, prefix=0, conflict=True)
check('allocated later blocks preserve only the checked prefix', lambda image: bitmap_set(image, 108), status=-1, prefix=2 * BLOCK, conflict=True)

with Image(bytearray(ORIGINAL)) as disk:
    found = {name: number for number, name, _ in disk.listing(0)}
    assert set(found) == {b'vanished.bin', b'gone', b'child.txt', b'slack.txt', b'thread-only', b'lost-dir', b'lost-child'}
    assert disk.listing(IDS['gone'])[0][1] == b'child.txt'
    assert disk.listing(IDS['lost-dir'])[0][1] == b'lost-child'
    handle = open_id(disk.fs, b'/hfs', IDS['thread-only'], 2)
    assert handle
    try:
        assert collect_call(lambda cb: extents(handle, cb, None)) == (-1, [])
        assert read(disk.fs, handle, 0, 1) == -1
    finally:
        close(disk.fs, handle)
        free_file(handle)
    print('PASS: thread-only names preserve evidence without fabricating file mappings')
    payload(disk, b'/hfs/LIVE.TXT', b'Live HFS file\n')
    payload(disk, '/hfs/CAFÉ'.encode(), b'MacRoman\n')
    payload(disk, b'/hfs/fragmented.bin', b'A' * BLOCK + b'B' * BLOCK + b'C' * BLOCK + b'D' * BLOCK)
    payload(disk, b'/hfs/empty', b'')
    print('PASS: native live reads preserve MacRoman case equivalence, empty forks and fragmented mappings')
    payload(disk, b'/hfs/live.txt/..namedfork/rsrc', b'resource\n')
    resource = next(number for name, number, _, _ in stream_rows(disk, IDS['vanished.bin']) if name == b'rsrc')
    payload(disk, resource, b'deleted resource\n', flags=2)
    print('PASS: live and deleted resource forks use the same mapped and checked reads')
    slack = next(number for name, number, _, _ in stream_rows(disk, IDS['vanished.bin']) if name == b'data-slack')
    payload(disk, slack, b'G' * (BLOCK - 17), flags=2)
    print('PASS: deleted fork slack exposes retained physical bytes under the same ownership checks')
    expected = b'L' * (BLOCK - len(b'Live HFS file\n')) + b'S' * BLOCK
    payload(disk, b'/hfs/live.txt/..namedfork/data-slack', expected)
    payload(disk, b'/hfs/live.txt/..namedfork/rsrc-slack', b'R' * (BLOCK - len(b'resource\n')))
    print('PASS: data and resource slack include clump preallocation without extending ordinary EOF')
    expected = b''.join(ORIGINAL[INFO['catalog'] + start:INFO['catalog'] + start + size] for start, size in INFO['catalog_slack'])
    found = payload(disk, b'/hfs/..namedfork/catalog-slack', expected)
    assert len(found) == len(INFO['catalog_slack'])
    print('PASS: catalog slack reports exact physical regions and retains discarded directory evidence')
    for mask, number in ((4, 96), (8, 94)):
        state, found = collect_call(lambda cb: ranges(disk.fs, b'/hfs', mask, cb, None))
        offset = INFO['allocation'] + number * BLOCK
        assert state == 1 and found == [(offset, offset, BLOCK, 6 if mask == 4 else 8)], found
    print('PASS: orphan and bad-block maps protect all live forks and metadata')
    state, found = collect_call(lambda cb: ranges(disk.fs, b'/hfs', 1, cb, None))
    assert state == 1 and found and min(row[1] for row in found) == INFO['allocation']
    assert max(row[1] + row[2] for row in found) <= INFO['allocation'] + 128 * BLOCK
    assert all(row[1] >= INFO['allocation'] and row[3] == 1 for row in found)
    print('PASS: free ranges exclude boot blocks, MDBs and the volume bitmap')
    reads = len(disk.reads)
    disk.listing(0)
    stream_rows(disk, path=b'/hfs/live.txt/..namedfork')
    assert len(disk.reads) == reads
    print('PASS: repeated catalog and fork discovery reuse cached metadata')

image = bytearray(ORIGINAL)
image[INFO['catalog'] + INFO['locations']['vanished.bin'] + 6] = 0
with Image(image) as disk:
    assert (IDS['vanished.bin'], b'vanished.bin', 3) in disk.listing(0)
    payload(disk, IDS['vanished.bin'], EXPECTED, flags=2)
print('PASS: retained file threads recover cleared catalog names without losing valid fork mappings')

image = bytearray(ORIGINAL)
image[INFO['catalog'] + INFO['locations']['vanished.bin'] + 6] = 0
image[INFO['catalog'] + INFO['locations']['name-thread'] + 8 + 14] = 0
with Image(image) as disk:
    assert any(number == IDS['vanished.bin'] and name == b'cnid-30' and flags & 4 for number, name, flags in disk.listing(0))
print('PASS: missing filename evidence retains an explicit partial CNID placeholder')

image = bytearray(ORIGINAL)
start = INFO['catalog'] + INFO['locations']['22']
image[start + 7:start + 11] = b'p%/X'
with Image(image) as disk:
    payload(disk, b'/hfs/p%25%2FX', b'MacRoman\n')
    assert not open_path(disk.fs, b'/hfs/not-present', False)
print('PASS: classic path escaping preserves raw percent and slash bytes without losing filename identity')

image = bytearray(ORIGINAL)
bitmap_set(image, 110, True)
with Image(image) as disk:
    slack = next(number for name, number, _, _ in stream_rows(disk, IDS['vanished.bin']) if name == b'data-slack')
    payload(disk, slack, b'G' * (BLOCK - 17), flags=2, status=-1, prefix=0, conflict=True)
print('PASS: reused deleted slack refuses extraction instead of exposing another owner bytes')

image = bytearray(ORIGINAL)
image[INFO['catalog'] + INFO['locations']['vanished.bin'] + 6] = 0
put32(image, INFO['catalog'] + INFO['locations']['thread-only'] + 2, 30)
with Image(image) as disk:
    assert any(number == IDS['vanished.bin'] and name == b'cnid-30' and flags & 4 for number, name, flags in disk.listing(0))
print('PASS: conflicting retained threads do not fabricate an original filename')

check('live CNID reuse prevents recovering an older catalog identity',
      lambda image: put32(image, value_offset(image) + 20, 20), status=-1, prefix=0, conflict=True)
check('duplicate physical extents stop at the first unambiguous fragment',
      lambda image: put16(image, value_offset(image) + 78, 104), status=-1, prefix=BLOCK, conflict=True)
check('unreachable allocated catalog nodes prevent complete ownership claims',
      lambda image: image.__setitem__(INFO['catalog'] + 248, image[INFO['catalog'] + 248] | 4), status=-1, prefix=0)
check('invalid active B-tree offset tables retain bounded discovery without authorizing recovery',
      lambda image: put16(image, INFO['catalog'] + 3 * NODE - 2, 8), status=-1, prefix=0)


def redirect(image, block):
    put16(image, value_offset(image) + 74, block)
    bitmap_set(image, block, False)


for number, label in ((80, 'live data'), (81, 'allocated file slack'), (90, 'resource forks'), (12, 'catalog metadata'), (94, 'bad blocks')):
    check(label + ' protect storage despite cleared allocation bits', lambda image, number=number: redirect(image, number),
          status=-1, prefix=0, conflict=True)

check('dirty volumes retain inspection but refuse complete recovery', lambda image: put16(image, 1024 + 10, 0), status=-1, prefix=0)
check('non-integral physical EOF never invents a complete allocation map',
      lambda image: put32(image, value_offset(image) + 30, 4 * BLOCK - 1), status=-1, prefix=0)


def missing_overflow(image):
    start = INFO['overflow'] + 2 * NODE
    image[start:start + NODE] = bytes(NODE)


check('missing retained overflow mappings preserve the known data prefix', missing_overflow, status=-1, prefix=3 * BLOCK)


def duplicate_overflow(image):
    start = INFO['overflow'] + 2 * NODE
    record = bytearray(image[start + 14:start + 34])
    put16(record, 8, 112)
    image[start + 34:start + 54] = record
    put16(image, start + 10, 2)
    put16(image, start + NODE - 6, 54)


check('conflicting retained overflow versions preserve only unambiguous mappings', duplicate_overflow, status=-1, prefix=3 * BLOCK)
with Image(bytearray(ORIGINAL), failed=((INFO['allocation'] + 108 * BLOCK, INFO['allocation'] + 109 * BLOCK),)) as disk:
    handle = open_id(disk.fs, b'/hfs', IDS['vanished.bin'], 2)
    assert handle
    try:
        assert read(disk.fs, handle, 0, len(EXPECTED)) == 2 * BLOCK
        assert File.from_address(handle).size == len(EXPECTED)
        assert read(disk.fs, handle, 2 * BLOCK, 1) == -1
    finally:
        close(disk.fs, handle)
        free_file(handle)
print('PASS: physical I/O failures preserve the readable prefix and declared size')

with Image(bytearray(ORIGINAL), failed=((INFO['bitmap'], INFO['bitmap'] + 16),)) as disk:
    status, found = collect_call(lambda cb: ranges(disk.fs, b'/hfs', 16, cb, None))
    assert status == -1 and found == [(INFO['allocation'], INFO['allocation'], 94 * BLOCK, 16),
                                      (INFO['allocation'] + 95 * BLOCK, INFO['allocation'] + 95 * BLOCK, 33 * BLOCK, 16)], found
    assert collect_call(lambda cb: ranges(disk.fs, b'/hfs', 1, cb, None)) == (-1, [])
    payload(disk, IDS['vanished.bin'], EXPECTED, flags=2, status=-1, prefix=0)
print('PASS: unreadable allocation bitmaps report unknown space and never authorize recovery')

for field, value in ((0, 0), (20, 0), (20, 513), (28, 0), (124, 0x482b)):
    image = bytearray(ORIGINAL)
    (put32 if field == 20 else put16)(image, 1024 + field, value)
    with Image(image, mounted=False):
        pass
print('PASS: invalid classic geometry and HFS+ wrappers are rejected before legacy parsing')

for field in (14, 18):
    image = bytearray(ORIGINAL)
    put16(image, 1024 + field, 0)
    with Image(image) as disk:
        handle = open_path(disk.fs, b'/hfs/live.txt', False)
        assert handle
        try:
            assert collect_call(lambda cb: extents(handle, cb, None)) == (-2, [])
            assert read(disk.fs, handle, 0, 14) == 14
            assert C.string_at(File.from_address(handle).data, 14) == b'Live HFS file\n'
        finally:
            close(disk.fs, handle)
            free_file(handle)
        assert collect_call(lambda cb: ranges(disk.fs, b'/hfs', 1, cb, None)) == (-2, [])
        assert not open_id(disk.fs, b'/hfs', IDS['vanished.bin'], 2)
print('PASS: incomplete allocation geometry preserves ordinary reads without claiming forensic maps or recovery')

info = MANIFEST['hfs-1536']
image = bytearray(gzip.decompress((FIXTURES / 'hfs-1536.img.gz').read_bytes()))
with Image(image, delta=4096) as disk:
    expected = b'D' * info['block'] + b'E' * info['block'] + b'F' * info['block'] + b'G' * 17
    payload(disk, info['ids']['vanished.bin'], expected, flags=2)
    payload(disk, b'/hfs/live.txt/..namedfork/data-slack', b'L' * (info['block'] - 14) + b'S' * info['block'])
    state, found = collect_call(lambda cb: ranges(disk.fs, b'/hfs', 4, cb, None))
    offset = info['allocation'] + 96 * info['block']
    assert state == 1 and found == [(offset, 4096 + offset, info['block'], 6)]
print('PASS: non-power-of-two allocation blocks and non-aligned allocation origins map correctly')
