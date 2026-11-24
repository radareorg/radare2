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
