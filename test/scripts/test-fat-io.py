#!/usr/bin/env python3

import ctypes as C
import gzip
import os
from pathlib import Path
import struct
import sys


ROOT = Path(__file__).resolve().parents[2]
SUFFIX = "dylib" if sys.platform == "darwin" else "so"
LIBRARY = os.environ.get("R2_FS_LIB", ROOT / f"libr/fs/libr_fs.{SUFFIX}")
fs = C.CDLL(str(LIBRARY))

# Only the prefixes needed to bind image IO and inspect a read buffer.
class Binding(C.Structure):
    _fields_ = [("init", C.c_int)] + [(name, C.c_void_p) for name in (
        "io", "desc_use", "desc_get", "desc_info", "desc_size", "open",
        "open_at", "close", "read_at")]


class File(C.Structure):
    _fields_ = [("name", C.c_void_p), ("path", C.c_void_p),
                ("off", C.c_uint64), ("id", C.c_uint64),
                ("flags", C.c_uint32), ("size", C.c_uint32),
                ("type", C.c_char), ("data", C.c_void_p)]


class Range(C.Structure):
    _fields_ = [("logical", C.c_uint64), ("physical", C.c_uint64),
                ("size", C.c_uint64), ("flags", C.c_uint32)]


RangeCallback = C.CFUNCTYPE(C.c_bool, C.POINTER(Range), C.c_void_p)


def api(name, result, *arguments):
    function = getattr(fs, name)
    function.restype, function.argtypes = result, arguments
    return function


new = api("r_fs_new", C.c_void_p)
free = api("r_fs_free", None, C.c_void_p)
mount = api("r_fs_mount", C.c_void_p, C.c_void_p, C.c_char_p, C.c_char_p, C.c_uint64)
open_file = api("r_fs_open", C.c_void_p, C.c_void_p, C.c_char_p, C.c_bool)
read = api("r_fs_read", C.c_int, C.c_void_p, C.c_void_p, C.c_uint64, C.c_int)
close = api("r_fs_close", None, C.c_void_p, C.c_void_p)
free_file = api("r_fs_file_free", None, C.c_void_p)
extents = api("r_fs_extents", C.c_int, C.c_void_p, RangeCallback, C.c_void_p)
open_id = api("r_fs_open_id", C.c_void_p, C.c_void_p, C.c_char_p, C.c_uint64, C.c_uint32)
find = api("r_fs_find_off", C.c_void_p, C.c_void_p, C.c_char_p, C.c_uint64, C.c_int)
list_length = api("r_list_length", C.c_int, C.c_void_p)
list_free = api("r_list_free", None, C.c_void_p)
ReadAt = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_uint64, C.c_void_p, C.c_int)

image = bytearray(gzip.decompress((ROOT / "test/bins/fs/fat/fat32.img.gz").read_bytes()))
sector = struct.unpack_from("<H", image, 11)[0]
reserved = struct.unpack_from("<H", image, 14)[0]
fat_sectors = struct.unpack_from("<I", image, 36)[0]
active = struct.unpack_from("<H", image, 40)[0] & 15
fat = (reserved + active * fat_sectors) * sector
data = (reserved + image[16] * fat_sectors) * sector
cluster_size = image[13] * sector
root = data + (struct.unpack_from("<I", image, 44)[0] - 2) * cluster_size
start, count = 100, 60000
for cluster in range(start, start + count):
    struct.pack_into("<I", image, fat + cluster * 4,
                     cluster + 1 if cluster + 1 < start + count else 0x0fffffff)
struct.pack_into("<H", image, root + 26, start)
struct.pack_into("<I", image, root + 28, count * cluster_size)
physical = data + (start - 2) * cluster_size
image[physical] = ord("P")
image[physical + cluster_size - 1:physical + cluster_size + 1] = b"YZ"
buffer = (C.c_ubyte * len(image)).from_buffer(image)
reads = []


@ReadAt
def read_at(_, address, destination, length):
    reads.append((address, length))
    if length < 0 or address > len(image) or length > len(image) - address:
        return -1
    C.memmove(destination, C.addressof(buffer) + address, length)
    return length


filesystem = new()
assert filesystem
binding = Binding.from_address(filesystem)
binding.init = 1
binding.read_at = C.cast(read_at, C.c_void_p).value
handle = None
try:
    assert mount(filesystem, b"fat", b"/fat", 0)
    handle = open_file(filesystem, b"/fat/live.txt", False)
    assert handle and File.from_address(handle).size == count * cluster_size
    reads.clear()
    assert read(filesystem, handle, 0, 1) == 1
    assert C.string_at(File.from_address(handle).data, 1) == b"P"
    assert reads == [(physical, 1)], reads
    print("FAT32 60,000-cluster file: 1-byte prefix uses one IO call and one byte")

    reads.clear()
    assert read(filesystem, handle, cluster_size - 1, 2) == 2
    assert C.string_at(File.from_address(handle).data, 2) == b"YZ"
    assert len(reads) <= 3 and sum(length for _, length in reads) < 8192, reads
    assert read(filesystem, handle, 0, 1) == 1
    assert C.string_at(File.from_address(handle).data, 1) == b"P"

    runs = []

    @RangeCallback
    def collect_range(pointer, _):
        item = pointer.contents
        runs.append((item.logical, item.physical, item.size, item.flags))
        return True

    reads.clear()
    assert extents(handle, collect_range, None) == 1
    assert runs == [(0, physical, count * cluster_size, 2)], runs
    assert sum(length for _, length in reads) < count * 4 + 8192, reads
    print("FAT32 extent enumeration reads the large file's FAT chain once")

    reads.clear()
    paths = find(filesystem, b"/fat", data + 8 * cluster_size + 1, 2)
    assert paths and list_length(paths) == 1
    list_free(paths)
    assert sum(length for _, length in reads) < 65536, reads
    print("Deleted offset lookup avoids repeated live-ownership scans")
    close(filesystem, handle)
    free_file(handle)
    handle = None

    handle = open_id(filesystem, b"/fat", root + 288, 2)
    assert handle
    calls = []

    @RangeCallback
    def stop_range(pointer, _):
        calls.append(pointer.contents.size)
        return False

    assert extents(handle, stop_range, None) == 0
    assert len(calls) == 1
    assert read(filesystem, handle, cluster_size, 1) == 1
    assert C.string_at(File.from_address(handle).data, 1) == b"r"
    close(filesystem, handle)
    free_file(handle)
    handle = None

    handle = open_id(filesystem, b"/fat", root + 288, 2)
    assert handle
    contents = []

    @RangeCallback
    def read_range(pointer, _):
        item = pointer.contents
        result = read(filesystem, handle, item.logical, 1)
        contents.append((result, C.string_at(File.from_address(handle).data, 1)))
        return True

    reads.clear()
    assert extents(handle, read_range, None) == 1
    assert contents == [(1, b"C"), (1, b"r")], contents
    assert sum(length for _, length in reads) < count * 4 + 65536, reads
    close(filesystem, handle)
    free_file(handle)
    handle = None

    for next_cluster, expected in ((start, cluster_size * 2), (0x0ffffff7, cluster_size)):
        target = start + 1 if next_cluster == start else start
        struct.pack_into("<I", image, fat + target * 4, next_cluster)
        handle = open_file(filesystem, b"/fat/live.txt", False)
        assert handle
        assert read(filesystem, handle, 0, cluster_size * 3) == expected
        assert File.from_address(handle).flags & 4
        assert read(filesystem, handle, expected, 1) == -1
        assert read(filesystem, handle, 0, 1) == 1
        close(filesystem, handle)
        free_file(handle)
        handle = None
    print("FAT32 damaged and cyclic chains retain only their readable prefixes")
finally:
    if handle:
        close(filesystem, handle)
        free_file(handle)
    free(filesystem)
