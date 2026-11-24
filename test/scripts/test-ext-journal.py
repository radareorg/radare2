#!/usr/bin/env python3
"""Verify JBD/JBD2 recovery against compact journal images and damaged records."""
import gzip
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'test/bins/fs/ext-journal'
R2 = os.environ.get('R2', str(ROOT / 'binr/radare2/radare2'))
MANIFEST = json.loads((FIXTURES / 'manifest.json').read_text())
ENVIRONMENT = dict(os.environ, R2_NOPLUGINS='1')


def crc32c(data):
    value = 0xffffffff
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82f63b78 if value & 1 else 0)
    return value


def run(path, commands, expected_warning=None):
    result = subprocess.run([R2, '-Nq', '-c', 'e log.level=0;' + commands, 'gzip://' + str(path)],
                            env=ENVIRONMENT, capture_output=True, timeout=20, check=True)
    if expected_warning is None:
        assert not result.stderr, result.stderr
    else:
        assert expected_warning in result.stderr and b'ERROR' not in result.stderr, result.stderr
    return result.stdout


def recompute(image, info, logical, commit=False):
    mapping = info['journal']
    block = mapping[str(logical)] * 1024
    uuid = image[mapping['0'] * 1024 + 48:mapping['0'] * 1024 + 64]
    offset = 16 if commit else 1020
    struct.pack_into('>I', image, block + offset, 0)
    struct.pack_into('>I', image, block + offset, crc32c(uuid + image[block:block + 1024]))


with tempfile.TemporaryDirectory(prefix='r2-journal-') as directory:
    temp = Path(directory)
    for name in ('ext3', 'ext3-crc', 'ext4-v2', 'ext4-v3'):
        path = FIXTURES / (name + '.img.gz')
        info = MANIFEST[name]
        entries = json.loads(run(path, 'm:ext2 journalj /root'))
        assert [row['sequence'] for row in entries] == [99, 100, 101, 102, 102], (name, entries)
        assert entries[-1]['kind'] == 'revoke' and entries[-1]['revoked']
        assert entries[-2]['revoked'] and not entries[0]['revoked']
        assert all(row['checksummed'] == (name != 'ext3' and not (name == 'ext3-crc' and row['kind'] == 'revoke')) for row in entries)
        versions = json.loads(run(path, 'm:ext2 journal-inodesj /root'))
        assert any(row['inode'] == 13 and row['sequence'] == 100 and row['size'] == 28 for row in versions), versions
        assert json.loads(run(path, 'm:ext2 journal-inodesj /root 99')) == []
        inode = json.loads(run(path, 'm:ext2 journal-inodej /root 100 13'))
        assert inode['size'] == 28 and inode['links'] == 1 and inode['dtime'] == 0, inode
        assert inode['flags'] == (0x80000 if info['ext4'] else 0)
        assert run(path, 'm:ext2 journal-recover /root 100 13 -') == b'Deleted through the journal\n'
        payload = run(path, 'm:ext2 journal /root 101 3500 -')
        assert payload == struct.pack('>I', 0xc03b3998) + b'ESCAPED\n' + bytes(1012)
        assert run(path, 'm:ext2 journal /root 102 3501 -') == b''
        assert run(path, 'm:ext2 journal /root 103 3502 -') == b''
        assert run(path, 'm:ext2 journal-recover /root 103 13 -') == b''
        raw_inode = run(path, 'm:ext2 journal-inode /root 100 13 -')
        assert len(raw_inode) == info['inode_size']
        assert struct.unpack_from('<I', raw_inode, 4)[0] == 28
        print('PASS:', name, 'commits, inode history, file data, escapes and revokes')

    wrap = FIXTURES / 'ext4-wrap.img.gz'
    entries = json.loads(run(wrap, 'm:ext2 journalj /root'))
    assert len(entries) == 1 and entries[0]['sequence'] == 0xffffffff, entries
    payload = run(wrap, 'm:ext2 journal /root 0xffffffff 3500 -')
    assert payload == struct.pack('>I', 0xc03b3998) + b'WRAPPED\n' + bytes(1012)
    print('PASS: journal transaction crosses the ring boundary')
    revoked_wrap = FIXTURES / 'ext4-wrap-revoke.img.gz'
    entries = json.loads(run(revoked_wrap, 'm:ext2 journalj /root'))
    assert len(entries) == 2 and all(item['revoked'] for item in entries), entries
    assert run(revoked_wrap, 'm:ext2 journal /root 0xffffffff 3500 -') == b''
    print('PASS: revocations preceding a wrapped transaction are reconciled before export')

    info = MANIFEST['ext4-v3']
    source = gzip.decompress((FIXTURES / 'ext4-v3.img.gz').read_bytes())
    for label, logical, byte in [('descriptor checksum', 4, 80), ('data checksum', 5, 100),
                                  ('commit checksum', 6, 100), ('superblock checksum', 0, 100)]:
        image = bytearray(source)
        image[info['journal'][str(logical)] * 1024 + byte] ^= 1
        path = temp / 'damaged.img.gz'
        path.write_bytes(gzip.compress(image, mtime=0))
        assert run(path, 'm:ext2 journal-inodej /root 100 13') == b'', label
        assert run(path, 'm:ext2 journal-recover /root 100 13 -') == b'', label
        print('PASS:', label, 'rejects damaged history')

    image = bytearray(source)
    revoke = info['journal']['12'] * 1024
    struct.pack_into('>Q', image, revoke + 16, info['victim_block'])
    recompute(image, info, 12)
    path = temp / 'revoked.img.gz'
    path.write_bytes(gzip.compress(image, mtime=0))
    assert run(path, 'm:ext2 journal-recover /root 102 13 -') == b''
    assert run(path, f"m:ext2 journal /root 99 {info['victim_block']} -").startswith(b'Deleted through the journal\n')
    print('PASS: later revocation blocks reconstructed file data, preserving explicit older versions')

    image = bytearray(source)
    for logical in (1, 2, 3):
        offset = info['journal'][str(logical)] * 1024
        image[offset:offset + 1024] = bytes(1024)
    path = temp / 'metadata-only.img.gz'
    path.write_bytes(gzip.compress(image, mtime=0))
    assert json.loads(run(path, 'm:ext2 journal-inodej /root 100 13'))['size'] == 28
    assert run(path, 'm:ext2 journal-recover /root 100 13 -') == b''
    print('PASS: metadata-only history never substitutes current image file data')

    image = bytearray(source)
    inode_block = info['journal']['5'] * 1024
    inode_start = inode_block + info['inode_offset'] % 1024
    struct.pack_into('<H', image, inode_start + 56, 0x8001)
    uuid = image[info['journal']['0'] * 1024 + 48:info['journal']['0'] * 1024 + 64]
    descriptor = info['journal']['4'] * 1024
    checksum = crc32c(uuid + struct.pack('>I', 100) + image[inode_block:inode_block + 1024])
    struct.pack_into('>I', image, descriptor + 24, checksum)
    recompute(image, info, 4)
    path = temp / 'unwritten.img.gz'
    path.write_bytes(gzip.compress(image, mtime=0))
    assert run(path, 'm:ext2 journal-recover /root 100 13 -') == bytes(28)
    print('PASS: unwritten extents recover logical zeros')
    image = bytearray(source)
    struct.pack_into('<I', image, inode_start + 4, 2048)
    struct.pack_into('<H', image, inode_start + 56, 2)
    checksum = crc32c(uuid + struct.pack('>I', 100) + image[inode_block:inode_block + 1024])
    struct.pack_into('>I', image, descriptor + 24, checksum)
    recompute(image, info, 4)
    path = temp / 'partial.img.gz'
    path.write_bytes(gzip.compress(image, mtime=0))
    result = run(path, 'm:ext2 journal-recover /root 100 13 -')
    assert result == b'Deleted through the journal\n' + bytes(996), len(result)
    print('PASS: missing journal data preserves the verified file prefix')

    prefixed = temp / 'prefixed.img.gz'
    prefixed.write_bytes(gzip.compress(bytes(4096) + source, mtime=0))
    result = run(prefixed, 'm /journal ext2 4096;m:ext2 journal-recover /journal 100 13 -')
    assert result == b'Deleted through the journal\n'
    print('PASS: internal journal recovery honors nonzero filesystem offsets')

    for name in ('ext3-crc', 'ext4-v2'):
        info_other = MANIFEST[name]
        image = bytearray(gzip.decompress((FIXTURES / (name + '.img.gz')).read_bytes()))
        image[info_other['journal']['5'] * 1024 + 100] ^= 1
        path = temp / (name + '-bad.img.gz')
        path.write_bytes(gzip.compress(image, mtime=0))
        assert run(path, 'm:ext2 journal-recover /root 100 13 -') == b''
        print('PASS:', name, 'rejects corrupted transaction data')

    image = bytearray(source)
    for descriptor_logical, payload_logical, commit_logical, sequence in ((1, 2, 3, 0xffffffff), (4, 5, 6, 0)):
        descriptor_offset = info['journal'][str(descriptor_logical)] * 1024
        payload_offset = info['journal'][str(payload_logical)] * 1024
        commit_offset = info['journal'][str(commit_logical)] * 1024
        struct.pack_into('>I', image, descriptor_offset + 8, sequence)
        checksum = crc32c(uuid + struct.pack('>I', sequence) + image[payload_offset:payload_offset + 1024])
        struct.pack_into('>I', image, descriptor_offset + 24, checksum)
        recompute(image, info, descriptor_logical)
        struct.pack_into('>I', image, commit_offset + 8, sequence)
        recompute(image, info, commit_logical, commit=True)
    path = temp / 'sequence-wrap.img.gz'
    path.write_bytes(gzip.compress(image, mtime=0))
    assert run(path, 'm:ext2 journal-recover /root 0 13 -') == b'Deleted through the journal\n'
    print('PASS: historical block selection handles transaction sequence wraparound')

    for feature in (0x20, 0x80):
        image = bytearray(source)
        super_offset = info['journal']['0'] * 1024
        value = struct.unpack_from('>I', image, super_offset + 40)[0]
        struct.pack_into('>I', image, super_offset + 40, value | feature)
        struct.pack_into('>I', image, super_offset + 252, 0)
        struct.pack_into('>I', image, super_offset + 252, crc32c(image[super_offset:super_offset + 1024]))
        path = temp / 'unsupported.img.gz'
        path.write_bytes(gzip.compress(image, mtime=0))
        assert run(path, 'm:ext2 journalj /root') == b''
        print('PASS: unsupported journal feature is rejected', hex(feature))

    image = bytearray(source)
    table = info['inode_offset'] - 12 * info['inode_size']
    struct.pack_into('<H', image, table + info['inode_size'] + 40, 0)
    path = temp / 'damaged-root.img.gz'
    path.write_bytes(gzip.compress(image, mtime=0))
    assert run(path, 'm:ext2 journal-recover /root 100 13 -',
               expected_warning=b'Damaged ext3/ext4 directory metadata') == b'Deleted through the journal\n'
    print('PASS: journal recovery remains available with a damaged ext4 root directory')
    for name in ('ext3-metadata', 'ext4-metadata'):
        path = FIXTURES / (name + '.img.gz')
        command = 'm:ext2 journal-recover /root 100 13 -'
        assert run(path, command) == b''
        assert run(path, command + ' journal') == b''
        assert run(path, 'e log.level=3;' + command + ' free',
                   expected_warning=b'Heuristic recovery uses current free-space bytes') == b'Deleted through the journal\n'
        destination = temp / 'recovered-file'
        run(path, f'm:ext2 journal-recover /root 100 13 {destination} free')
        assert destination.read_bytes() == b'Deleted through the journal\n'
        print('PASS:', name, 'combines historical inode metadata with unowned free data')

    info = MANIFEST['ext4-v3']
    source = gzip.decompress((FIXTURES / 'ext4-metadata.img.gz').read_bytes())
    inode_size = info['inode_size']
    current_inode = info['inode_offset']
    historical_inode = info['journal']['5'] * 1024 + current_inode % 1024
    victim = info['victim_block']
    filesystem_uuid = source[1128:1144]
    inode_table = current_inode - 12 * inode_size

    def fs_inode_checksum(image, offset, number=13):
        struct.pack_into('<H', image, offset + 124, 0)
        struct.pack_into('<H', image, offset + 130, 0)
        checksum = crc32c(filesystem_uuid + struct.pack('<I', number) + image[offset + 100:offset + 104] + image[offset:offset + inode_size])
        struct.pack_into('<H', image, offset + 124, checksum & 65535)
        struct.pack_into('<H', image, offset + 130, checksum >> 16)

    def historical_checksum(image):
        fs_inode_checksum(image, historical_inode)
        payload = info['journal']['5'] * 1024
        descriptor = info['journal']['4'] * 1024
        value = crc32c(filesystem_uuid + struct.pack('>I', 100) + image[payload:payload + 1024])
        struct.pack_into('>I', image, descriptor + 24, value)
        recompute(image, info, 4)

    def fs_bitmap_set(image, number, is_inode=False):
        descriptor = 2048
        bitmap = struct.unpack_from('<I', image, descriptor + (4 if is_inode else 0))[0] * 1024
        index = number - 1
        image[bitmap + index // 8] |= 1 << (index % 8)
        size = struct.unpack_from('<I', image, 1064 if is_inode else 1056)[0] // 8
        checksum = crc32c(filesystem_uuid + image[bitmap:bitmap + size])
        struct.pack_into('<H', image, descriptor + (26 if is_inode else 24), checksum & 65535)
        struct.pack_into('<H', image, descriptor + (58 if is_inode else 56), checksum >> 16)
        struct.pack_into('<H', image, descriptor + 30, 0)
        struct.pack_into('<H', image, descriptor + 30, crc32c(filesystem_uuid + bytes(4) + image[descriptor:descriptor + 64]) & 65535)

    def check_free(label, image, expected=b'', sequence=100, delta=0):
        path = temp / 'free-space.img.gz'
        path.write_bytes(gzip.compress(bytes(delta) + image, mtime=0))
        prefix = f'm /journal ext2 {delta};' if delta else ''
        mountpoint = '/journal' if delta else '/root'
        command = prefix + f'm:ext2 journal-recover {mountpoint} {sequence} 13 - free'
        assert run(path, command) == expected, label
        print('PASS:', label)

    image = bytearray(source)
    fs_bitmap_set(image, victim)
    check_free('allocated current data is never substituted', image)

    image = bytearray(source)
    fs_bitmap_set(image, 13, is_inode=True)
    check_free('allocated current inode excludes free-space fallback', image)

    image = bytearray(source)
    struct.pack_into('<I', image, current_inode + 100, 1)
    fs_inode_checksum(image, current_inode)
    check_free('inode generation changes exclude free-space fallback', image)

    image = bytearray(source)
    live_inode = inode_table + 11 * inode_size
    struct.pack_into('<I', image, live_inode + 60, victim)
    fs_inode_checksum(image, live_inode, 12)
    check_free('live ownership overrides a cleared current block bit', image)

    image = bytearray(source)
    bitmap = struct.unpack_from('<I', image, 2048)[0] * 1024
    image[bitmap] ^= 1
    check_free('bad allocation checksum cannot authorize free-space reads', image)

    image = bytearray(source)
    image[historical_inode + 4] ^= 1
    # Keep the journal transaction valid while breaking the ext4 inode checksum.
    payload = info['journal']['5'] * 1024
    descriptor = info['journal']['4'] * 1024
    struct.pack_into('>I', image, descriptor + 24,
                     crc32c(filesystem_uuid + struct.pack('>I', 100) + image[payload:payload + 1024]))
    recompute(image, info, 4)
    check_free('bad historical inode checksum prevents reconstruction', image)

    image = bytearray(source)
    descriptor = info['journal']['7'] * 1024
    struct.pack_into('>I', image, descriptor + 12, victim)
    recompute(image, info, 7)
    check_free('later committed writes exclude current free bytes', image)

    image = bytearray(source)
    revoke = info['journal']['12'] * 1024
    struct.pack_into('>Q', image, revoke + 16, victim)
    recompute(image, info, 12)
    check_free('later revocations exclude current free bytes', image)
    check_free('revoked versions are never replaced with current free bytes', image, sequence=102)

    def lengthen(image, count):
        struct.pack_into('<I', image, historical_inode + 4, count * 1024)
        struct.pack_into('<I', image, historical_inode + 28, count * 2)
        struct.pack_into('<H', image, historical_inode + 56, count)
        historical_checksum(image)

    image = bytearray(gzip.decompress((FIXTURES / 'ext4-v3.img.gz').read_bytes()))
    lengthen(image, 2)
    fs_bitmap_set(image, victim)
    image[victim * 1024:(victim + 1) * 1024] = b'X' * 1024
    image[(victim + 1) * 1024:(victim + 2) * 1024] = b'Z' * 1024
    check_free('journal bytes take precedence when free bytes fill missing file blocks', image,
               b'Deleted through the journal\n' + bytes(996) + b'Z' * 1024)

    image = bytearray(source)
    lengthen(image, 3)
    fs_bitmap_set(image, victim + 1)
    check_free('reused later blocks preserve the verified recovered prefix', image,
               b'Deleted through the journal\n' + bytes(996))

    destination = temp / 'partial-recovery'
    run(temp / 'free-space.img.gz', f'm:ext2 journal-recover /root 100 13 {destination} free')
    assert destination.read_bytes() == b'Deleted through the journal\n' + bytes(996)
    print('PASS: partial file output retains only its verified readable prefix')

    tree_block = 3490
    image = bytearray(source)
    image[historical_inode + 40:historical_inode + 100] = bytes(60)
    struct.pack_into('<HHHHI', image, historical_inode + 40, 0xf30a, 1, 4, 1, 0)
    struct.pack_into('<IIHH', image, historical_inode + 52, 0, tree_block, 0, 0)
    struct.pack_into('<I', image, historical_inode + 28, 4)
    node = bytearray(1024)
    struct.pack_into('<HHHHI', node, 0, 0xf30a, 1, 84, 0, 0)
    struct.pack_into('<IHHI', node, 12, 0, 1, 0, victim)
    generation = image[historical_inode + 100:historical_inode + 104]
    struct.pack_into('<I', node, 1020, crc32c(filesystem_uuid + struct.pack('<I', 13) + generation + node[:1020]))
    image[tree_block * 1024:(tree_block + 1) * 1024] = node
    historical_checksum(image)
    check_free('surviving free extent leaves reconstruct historical inode maps', image, b'Deleted through the journal\n')
    check_free('free extent reconstruction honors mount offsets', image, b'Deleted through the journal\n', delta=4096)

    allocated_tree = bytearray(image)
    fs_bitmap_set(allocated_tree, tree_block)
    check_free('allocated extent leaves are not treated as historical metadata', allocated_tree)
    damaged_tree = bytearray(image)
    damaged_tree[tree_block * 1024 + 20] ^= 1
    check_free('extent node checksums bind free metadata to its historical inode', damaged_tree)

    image = bytearray(source)
    struct.pack_into('<H', image, historical_inode + 56, 0x8001)
    historical_checksum(image)
    fs_bitmap_set(image, victim)
    check_free('historical unwritten extents yield zeros without reading current data', image, bytes(28))

    info3 = MANIFEST['ext3']
    image = bytearray(gzip.decompress((FIXTURES / 'ext3-metadata.img.gz').read_bytes()))
    inode3 = info3['journal']['5'] * 1024 + info3['inode_offset'] % 1024
    image[inode3 + 40:inode3 + 100] = bytes(60)
    struct.pack_into('<I', image, inode3 + 4, 13 * 1024)
    struct.pack_into('<I', image, inode3 + 28, 4)
    struct.pack_into('<I', image, inode3 + 88, tree_block)
    image[tree_block * 1024:(tree_block + 1) * 1024] = bytes(1024)
    struct.pack_into('<I', image, tree_block * 1024, info3['victim_block'])
    check_free('ext3 free indirect maps retain proven sparse holes', image,
               bytes(12 * 1024) + b'Deleted through the journal\n' + bytes(996))

    image = bytearray(source)
    # Mark the current allocation layout as requiring journal replay.
    struct.pack_into('<I', image, 1120, struct.unpack_from('<I', image, 1120)[0] | 4)
    struct.pack_into('<I', image, 2044, crc32c(image[1024:2044]))
    check_free('uncheckpointed allocation maps cannot authorize free-space recovery', image)

    image = bytearray(source)
    # Later transaction 101 becomes sequence 0 after the selected 0xffffffff.
    for descriptor_logical, payload_logical, commit_logical, sequence in ((4, 5, 6, 0xffffffff), (7, 8, 9, 0)):
        descriptor_offset = info['journal'][str(descriptor_logical)] * 1024
        payload_offset = info['journal'][str(payload_logical)] * 1024
        commit_offset = info['journal'][str(commit_logical)] * 1024
        struct.pack_into('>I', image, descriptor_offset + 8, sequence)
        if not sequence:
            struct.pack_into('>I', image, descriptor_offset + 12, victim)
        checksum = crc32c(filesystem_uuid + struct.pack('>I', sequence) + image[payload_offset:payload_offset + 1024])
        struct.pack_into('>I', image, descriptor_offset + 24, checksum)
        recompute(image, info, descriptor_logical)
        struct.pack_into('>I', image, commit_offset + 8, sequence)
        recompute(image, info, commit_logical, commit=True)
    check_free('later writes across sequence wraparound exclude current free data', image, sequence=0xffffffff)

    image = bytearray(source)
    super_offset = info['journal']['0'] * 1024
    struct.pack_into('>I', image, super_offset + 28, 4)
    struct.pack_into('>I', image, super_offset + 252, 0)
    struct.pack_into('>I', image, super_offset + 252, crc32c(image[super_offset:super_offset + 1024]))
    check_free('active journal logs exclude free-space reads even with a clean filesystem flag', image)
