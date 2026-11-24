#!/usr/bin/env python3
"""Verify historical journal names, path ancestry and inode-version associations."""
import gzip
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'test/bins/fs/ext-journal'
MANIFEST = json.loads((FIXTURES / 'names-manifest.json').read_text())
R2 = os.environ.get('R2', str(ROOT / 'binr/radare2/radare2'))
ENVIRONMENT = dict(os.environ, R2_NOPLUGINS='1')


def crc32c(data):
    value = 0xffffffff
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82f63b78 if value & 1 else 0)
    return value


def u16(image, offset):
    return struct.unpack_from('<H', image, offset)[0]


def u32(image, offset):
    return struct.unpack_from('<I', image, offset)[0]


def put16(image, offset, value):
    struct.pack_into('<H', image, offset, value)


def put32(image, offset, value):
    struct.pack_into('<I', image, offset, value)


def run(path, commands):
    result = subprocess.run([R2, '-Nq', '-c', 'e log.level=0;' + commands, 'gzip://' + str(path)],
                            env=ENVIRONMENT, capture_output=True, timeout=20, check=True)
    assert not result.stderr, result.stderr
    return result.stdout


def listing(path, sequence=200, inode=None, prefix='', mount='/root'):
    suffix = '' if inode is None else ' ' + str(inode)
    return json.loads(run(path, prefix + f'm:ext2 journal-namesj {mount} {sequence}' + suffix))


def paths(rows):
    return {row['path'] for row in rows if not row['deleted']}


with tempfile.TemporaryDirectory(prefix='r2-journal-names-') as directory:
    temp = Path(directory)
    for name in ('ext3-names', 'ext4-names'):
        path = FIXTURES / (name + '.img.gz')
        rows = listing(path)
        assert {'/archive', '/archive/nested', '/archive/second.txt', '/archive/nested/report.txt', '/archive/symlink'} <= paths(rows)
        assert all(row['heuristic'] and not row['conflict'] for row in rows)
        assert not any('/current' in (row['path'] or '') for row in rows)
        targets = listing(path, inode=13)
        assert paths(targets) == {'/archive/second.txt', '/archive/nested/report.txt'}
        assert all(row['inode_sequence'] == 200 and row['generation'] == 0 for row in targets if not row['deleted'])
        assert all(row['inode_sequence'] is None for row in targets if row['deleted'])
        assert any(row['name'] == 'gone' and row['deleted'] for row in rows)
        assert not any(row['path'].startswith('/archive/symlink/') for row in rows if row['path'])
        assert run(path, 'm:ext2 journal-recover /root 200 13 -') == b'Deleted through the journal\n'
        newer = listing(path, 201, 13)
        assert paths(newer) == {'/archive/second.txt', '/archive/nested/renamed.txt'}
        assert any(row['path'] == '/archive/nested/report.txt' and row['deleted'] and row['inode_sequence'] is None for row in newer)
        assert any(row['block_sequence'] == 201 and row['inode_sequence'] == 200 for row in newer if not row['deleted'])
        print('PASS:', name, 'historical paths, hard links, renames, slack names and linked inode recovery')

    info = MANIFEST['ext4-names']
    source = gzip.decompress((FIXTURES / 'ext4-names.img.gz').read_bytes())
    mapping = info['journal']
    snapshots = info['snapshots']
    uuid = source[1128:1144]
    table = info['inode_offset'] - 12 * info['inode_size']

    def journal_offset(logical):
        return mapping[str(logical)] * 1024

    def payload_offset(block, sequence=200):
        return journal_offset(snapshots[str(sequence)]['payloads'][str(block)])

    def fs_inode_offset(number):
        absolute = table + (number - 1) * info['inode_size']
        return payload_offset(absolute // 1024) + absolute % 1024

    def journal_checksum(image, sequence=200):
        snapshot = snapshots[str(sequence)]
        descriptor = journal_offset(snapshot['descriptor'])
        offset = descriptor + 12
        for index, logical in enumerate(snapshot['payloads'].values()):
            block = journal_offset(logical)
            value = crc32c(uuid + struct.pack('>I', sequence) + image[block:block + 1024])
            struct.pack_into('>I', image, offset + 12, value)
            offset += 16 + (16 if not index else 0)
        struct.pack_into('>I', image, descriptor + 1020, 0)
        struct.pack_into('>I', image, descriptor + 1020, crc32c(uuid + image[descriptor:descriptor + 1024]))

    def inode_checksum(image, number):
        offset = fs_inode_offset(number)
        put16(image, offset + 124, 0)
        put16(image, offset + 130, 0)
        value = crc32c(uuid + struct.pack('<I', number) + image[offset + 100:offset + 104] + image[offset:offset + info['inode_size']])
        put16(image, offset + 124, value & 65535)
        put16(image, offset + 130, value >> 16)
        journal_checksum(image)

    def directory_checksum(image, number, sequence=200):
        offset = payload_offset(info['directories'][str(number)], sequence)
        inode = fs_inode_offset(number)
        value = crc32c(uuid + struct.pack('<I', number) + image[inode + 100:inode + 104] + image[offset:offset + 1012])
        put32(image, offset + 1020, value)
        journal_checksum(image, sequence)

    def find_entry(image, number, name, sequence=200):
        start = payload_offset(info['directories'][str(number)], sequence)
        offset = 0
        while offset + 8 <= 1024:
            size = u16(image, start + offset + 4)
            length = image[start + offset + 6]
            if image[start + offset + 8:start + offset + 8 + length] == name:
                return start + offset
            assert size >= 8 and not size % 4
            offset += size
        raise AssertionError(name)

    path = temp / 'names.img.gz'

    def save(image, delta=0):
        path.write_bytes(gzip.compress(bytes(delta) + image, mtime=0))
        return path

    def revoke(image, block, sequence=202):
        logical = snapshots['201']['commit'] + 1
        header, commit = bytearray(1024), bytearray(1024)
        struct.pack_into('>III', header, 0, 0xc03b3998, 5, sequence)
        struct.pack_into('>IQ', header, 12, 24, block)
        struct.pack_into('>I', header, 1020, crc32c(uuid + header))
        struct.pack_into('>III', commit, 0, 0xc03b3998, 2, sequence)
        struct.pack_into('>I', commit, 16, crc32c(uuid + commit))
        image[journal_offset(logical):journal_offset(logical) + 1024] = header
        image[journal_offset(logical + 1):journal_offset(logical + 1) + 1024] = commit

    image = bytearray(source)
    revoke(image, info['directories']['2'])
    rows = listing(save(image), 202, 13)
    assert rows and all(row['path'] is None for row in rows)
    assert {'second.txt', 'renamed.txt'} <= {row['name'] for row in rows}
    print('PASS: revoked ancestors leave surviving names keyed by parent inode without guessed paths')

    image = bytearray(source)
    put16(image, fs_inode_offset(2), 0)
    inode_checksum(image, 2)
    rows = listing(save(image), inode=13)
    assert rows and all(row['path'] is None for row in rows)
    print('PASS: missing historical root inode is never replaced with its current version')

    image = bytearray(source)
    revoke(image, info['directories']['15'])
    rows = listing(save(image), 202, 13)
    assert paths(rows) == {'/archive/second.txt'}
    assert not any(row['directory'] == 15 for row in rows)
    print('PASS: revoked directory leaves are excluded while unrelated names remain available')

    image = bytearray(source)
    offset = find_entry(image, 15, b'report.txt')
    image[offset + 8] ^= 1
    journal_checksum(image)
    rows = listing(save(image), inode=13)
    assert paths(rows) == {'/archive/second.txt'}
    print('PASS: directory checksums reject altered historical names in an otherwise valid journal transaction')

    image = bytearray(source)
    offset = payload_offset(info['directories']['15'])
    put16(image, offset + 4, 7)
    directory_checksum(image, 15)
    rows = listing(save(image), inode=13)
    assert paths(rows) == {'/archive/second.txt'}
    print('PASS: malformed directory record lengths retain unrelated readable names')

    image = bytearray(source)
    root = find_entry(image, 2, b'archive')
    put32(image, root, 12)
    directory_checksum(image, 2)
    child = find_entry(image, 15, b'report.txt')
    put32(image, child, 14)
    image[child + 7] = 2
    directory_checksum(image, 15)
    rows = listing(save(image), inode=13)
    assert rows and all(row['path'] is None for row in rows if not row['deleted'])
    print('PASS: cyclic historical ancestry terminates with unresolved paths')

    image = bytearray(source)
    root = find_entry(image, 2, b'live')
    put32(image, root, 14)
    image[root + 7] = 2
    directory_checksum(image, 2)
    rows = listing(save(image))
    assert all(row['path'] is None and row['conflict'] for row in rows if row['inode'] == 14)
    assert all(row['path'] is None for row in rows if row['inode'] == 13 and not row['deleted'])
    print('PASS: directories with multiple parent names do not acquire an arbitrary path')

    image = bytearray(source)
    duplicate = find_entry(image, 14, b'symlink')
    image[duplicate + 6] = 10
    image[duplicate + 8:duplicate + 18] = b'second.txt'
    directory_checksum(image, 14)
    rows = listing(save(image))
    duplicates = [row for row in rows if row['name'] == 'second.txt' and not row['deleted']]
    assert len(duplicates) == 2 and all(row['conflict'] and row['path'] is None for row in duplicates)
    print('PASS: duplicate directory names are reported as conflicting evidence')

    image = bytearray(source)
    offset = find_entry(image, 15, b'report.txt')
    filename = b'caf\xc3\xa9\n"\x1bxx'
    image[offset + 6] = len(filename)
    image[offset + 8:offset + 8 + len(filename)] = filename
    directory_checksum(image, 15)
    rows = listing(save(image), inode=13)
    row = next(row for row in rows if row['directory'] == 15)
    assert row['name'] == filename.decode() and row['path'] == '/archive/nested/' + filename.decode()
    text = run(path, 'm:ext2 journal-names /root 200 13')
    assert len(text.splitlines()) == 3 and b'\x1b' not in text and b'\\n' in text
    print('PASS: JSON preserves UTF-8 and controls while text output escapes terminal characters')

    image = bytearray(source)
    image[fs_inode_offset(13) + 4] ^= 1
    journal_checksum(image)
    rows = listing(save(image), inode=13)
    assert paths(rows) == {'/archive/second.txt', '/archive/nested/report.txt'}
    assert all(row['inode_sequence'] is None and row['generation'] is None for row in rows)
    print('PASS: damaged inode versions cannot claim historical directory names')

    image = bytearray(source)
    put32(image, fs_inode_offset(13) + 100, 42)
    inode_checksum(image, 13)
    inode_block = (table + 12 * info['inode_size']) // 1024
    payload = payload_offset(inode_block)
    newer = bytes(image[payload:payload + 1024])
    image[payload:payload + 1024] = source[payload:payload + 1024]
    journal_checksum(image)
    # Commit only the newer inode table, retaining the older directory data.
    logical = snapshots['201']['commit'] + 1
    descriptor, commit = bytearray(1024), bytearray(1024)
    struct.pack_into('>III', descriptor, 0, 0xc03b3998, 1, 202)
    checksum = crc32c(uuid + struct.pack('>I', 202) + newer)
    struct.pack_into('>IIII', descriptor, 12, inode_block, 8, 0, checksum)
    descriptor[28:44] = uuid
    struct.pack_into('>I', descriptor, 1020, crc32c(uuid + descriptor))
    struct.pack_into('>III', commit, 0, 0xc03b3998, 2, 202)
    struct.pack_into('>I', commit, 16, crc32c(uuid + commit))
    for index, data in enumerate((descriptor, newer, commit)):
        offset = journal_offset(logical + index)
        image[offset:offset + 1024] = data
    rows = listing(save(image), 202, 13)
    row = next(row for row in rows if row['name'] == 'renamed.txt')
    assert row['inode_sequence'] is None and row['generation'] is None
    print('PASS: a newer inode generation is not attached to an older directory name')

    image = bytearray(source)
    for old_sequence, new_sequence in ((200, 0xffffffff), (201, 0)):
        snapshot = snapshots[str(old_sequence)]
        descriptor = journal_offset(snapshot['descriptor'])
        commit = journal_offset(snapshot['commit'])
        struct.pack_into('>I', image, descriptor + 8, new_sequence)
        offset = descriptor + 12
        for index, logical in enumerate(snapshot['payloads'].values()):
            payload = journal_offset(logical)
            checksum = crc32c(uuid + struct.pack('>I', new_sequence) + image[payload:payload + 1024])
            struct.pack_into('>I', image, offset + 12, checksum)
            offset += 16 + (16 if not index else 0)
        struct.pack_into('>I', image, descriptor + 1020, 0)
        struct.pack_into('>I', image, descriptor + 1020, crc32c(uuid + image[descriptor:descriptor + 1024]))
        struct.pack_into('>I', image, commit + 8, new_sequence)
        struct.pack_into('>I', image, commit + 16, 0)
        struct.pack_into('>I', image, commit + 16, crc32c(uuid + image[commit:commit + 1024]))
    rows = listing(save(image), 0, 13)
    assert paths(rows) == {'/archive/second.txt', '/archive/nested/renamed.txt'}
    assert all(row['inode_sequence'] == 0xffffffff for row in rows if not row['deleted'])
    print('PASS: historical names and inode associations handle transaction sequence wraparound')

    rows = listing(save(source, 4096), prefix='m /journal ext2 4096;', mount='/journal', inode=13)
    assert paths(rows) == {'/archive/second.txt', '/archive/nested/report.txt'}
    print('PASS: historical names honor nonzero mount offsets')

    for arguments in ('202', '1/0', '-1', '200 0', '200 1/0', '200 -1', '200 4294967296'):
        assert run(FIXTURES / 'ext4-names.img.gz', 'm:ext2 journal-namesj /root ' + arguments) == b''
    assert listing(FIXTURES / 'ext4-names.img.gz', inode=42) == []
    print('PASS: missing transactions, invalid numeric arguments and unknown inode filters are handled')

    image = bytearray(source)
    inode = fs_inode_offset(15)
    put32(image, inode + 32, u32(image, inode + 32) | 0x1000)
    inode_checksum(image, 15)
    rows = listing(save(image), inode=13)
    assert not any(row['directory'] == 15 for row in rows)
    print('PASS: directory index payload cannot masquerade as historical filenames')

    info3 = MANIFEST['ext3-names']
    image = bytearray(gzip.decompress((FIXTURES / 'ext3-names.img.gz').read_bytes()))
    table3 = info3['inode_offset'] - 12 * info3['inode_size']
    absolute = table3 + 13 * info3['inode_size']
    payload = info3['snapshots']['200']['payloads'][str(absolute // 1024)]
    inode = info3['journal'][str(payload)] * 1024 + absolute % 1024
    put32(image, inode + 40, info3['directories']['15'])
    rows = listing(save(image), inode=13)
    assert all(row['path'] is None and row['conflict'] for row in rows if not row['deleted'])
    print('PASS: overlapping historical directory block ownership remains ambiguous')
