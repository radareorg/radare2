#!/usr/bin/env python3
"""Exercise the CLI with generated ELF/Mach-O files, without external fixtures."""
import os
from pathlib import Path
import struct
import sys
import subprocess
import tempfile

RABIN2 = os.environ.get('RABIN2', 'rabin2')


def patch(data, name, success=True, args=()):
    with tempfile.TemporaryDirectory(prefix='rabin-addlib-') as directory:
        source = Path(directory) / 'input'
        output = Path(directory) / 'output'
        source.write_bytes(data)
        result = subprocess.run([RABIN2, *args, '-O', 'a/l/' + name, '-o', str(output), str(source)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert source.read_bytes() == data, 'input changed with -o'
        assert (result.returncode == 0) == success, result.stderr.decode(errors='replace')
        if success:
            return output.read_bytes()
        assert not output.exists(), 'failed operation produced an output'
        result = subprocess.run([RABIN2, *args, '-O', 'a/l/' + name, str(source)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert result.returncode != 0 and source.read_bytes() == data, 'failure changed input'


def elf(bits, endian, sections=False):
    word = 'Q' if bits == 64 else 'I'
    ehsize, phsize, shsize = (64, 56, 64) if bits == 64 else (52, 32, 40)
    pack = lambda fmt, *values: struct.pack(endian + fmt, *values)
    base, dynoff, stroff = 0x10000, 0x200, 0x300
    names = b'\0liboriginal.so\0'
    dynamic = b''.join(pack(word * 2, tag, value) for tag, value in
                       [(1, 1), (5, base + stroff), (10, len(names)), (0, 0)])
    data = bytearray(0x500)
    ident = b'\x7fELF' + bytes([2 if bits == 64 else 1, 1 if endian == '<' else 2, 1]) + bytes(9)
    header = ident + pack('HHI' + word * 3 + 'IHHHHHH', 3, 62 if bits == 64 else 3, 1,
                          0, ehsize, 0x380 if sections else 0, 0, ehsize, phsize, 2,
                          shsize, 3 if sections else 0, 0)
    data[:ehsize] = header
    def phdr(kind, offset, addr, filesz, memsz, flags, alignment):
        return (pack('IIQQQQQQ', kind, flags, offset, addr, addr, filesz, memsz, alignment)
                if bits == 64 else pack('IIIIIIII', kind, offset, addr, addr, filesz, memsz, flags, alignment))
    data[ehsize:ehsize + phsize] = phdr(1, 0, base, len(data), 0x2000, 6, 0x1000)
    data[ehsize + phsize:ehsize + 2 * phsize] = phdr(2, dynoff, base + dynoff, len(dynamic), len(dynamic), 6, bits // 8)
    data[dynoff:dynoff + len(dynamic)] = dynamic
    data[stroff:stroff + len(names)] = names
    if sections:
        def shdr(kind, offset, size, link, entsize):
            return pack('II' + word * 4 + 'II' + word * 2,
                        0, kind, 3, base + offset, offset, size, link, 0, bits // 8, entsize)
        data[0x380 + shsize:0x380 + 2 * shsize] = shdr(6, dynoff, len(dynamic), 2, bits // 4)
        data[0x380 + 2 * shsize:0x380 + 3 * shsize] = shdr(3, stroff, len(names), 0, 0)
    return data


def check_elf(data, name, bits, endian):
    word = 'Q' if bits == 64 else 'I'
    unpack = lambda fmt, offset: struct.unpack_from(endian + fmt, data, offset)
    phoff = unpack(word, 32 if bits == 64 else 28)[0]
    phsize, phnum = unpack('HH', 54 if bits == 64 else 42)
    headers = []
    for index in range(phnum):
        fields = unpack('IIQQQQQQ' if bits == 64 else 'IIIIIIII', phoff + index * phsize)
        if bits == 32:
            fields = (fields[0], fields[6], *fields[1:6], fields[7])
        headers.append(fields)
    assert phnum >= 4 and headers[0][0] == 6
    load = headers[-1]
    assert load[0] == 1 and load[2] % load[7] == load[3] % load[7]
    assert load[3] >= 0x12000 and load[2] + load[5] == len(data)
    def v2p(addr):
        for h in headers:
            if h[0] == 1 and h[3] <= addr < h[3] + h[5]:
                return h[2] + addr - h[3]
        raise AssertionError('unmapped address')
    dyn = next(h for h in headers if h[0] == 2)
    assert v2p(dyn[3]) == dyn[2]
    entries = [unpack(word * 2, off) for off in range(dyn[2], dyn[2] + dyn[5], bits // 4)]
    assert entries[-1] == (0, 0)
    strings = v2p(dict(entries)[5])
    names = [data[strings + value:].split(b'\0', 1)[0] for tag, value in entries if tag == 1]
    assert names == [b'liboriginal.so', name.encode()], names
    shoff = unpack(word, 40 if bits == 64 else 32)[0]
    if shoff:
        shsize = 64 if bits == 64 else 40
        for index, expected in [(1, dyn[2]), (2, strings)]:
            addr, offset, length = unpack(word * 3, shoff + index * shsize + (16 if bits == 64 else 12))
            assert v2p(addr) == offset == expected and length > 0


def macho(bits, endian, padding=256, signed=False):
    pack = lambda fmt, *values: struct.pack(endian + fmt, *values)
    hsize, segsize, secsize = (32, 72, 80) if bits == 64 else (28, 56, 68)
    word = 'Q' if bits == 64 else 'I'
    sizeofcmds = segsize + secsize + (16 if signed else 0)
    textoff = hsize + sizeofcmds + padding
    filesize = textoff + 32
    segment = pack('II16s' + word * 4 + 'IIII', 0x19 if bits == 64 else 1,
                   segsize + secsize, b'__TEXT', 0x10000, filesize, 0, filesize, 7, 5, 1, 0)
    section = pack('16s16s' + word * 2 + 'I' * (8 if bits == 64 else 7),
                   b'__text', b'__TEXT', 0x10000 + textoff, 32, textoff, 2, 0, 0, 0,
                   *([0] * (3 if bits == 64 else 2)))
    header = pack('IIIIIII', 0xfeedfacf if bits == 64 else 0xfeedface,
                  0x1000007 if bits == 64 else 7, 3, 2, 2 if signed else 1, sizeofcmds, 0)
    if bits == 64:
        header += bytes(4)
    commands = segment + section
    if signed:
        commands += pack('IIII', 0x1d, 16, filesize, 16)
    return bytearray(header + commands + bytes(padding) + b'TEXT' * 8 + (b'SIGN' * 4 if signed else b''))


def check_macho(original, data, name, bits, endian):
    ncmds, size = struct.unpack_from(endian + 'II', data, 16)
    oldn, oldsize = struct.unpack_from(endian + 'II', original, 16)
    at = (32 if bits == 64 else 28) + oldsize
    cmd, length, nameoff, timestamp, current, compat = struct.unpack_from(endian + 'IIIIII', data, at)
    assert cmd == 12 and ncmds == oldn + 1 and size == oldsize + length
    assert length % (8 if bits == 64 else 4) == 0 and nameoff == 24
    assert timestamp == current == compat == 0
    assert data[at + nameoff:at + nameoff + len(name) + 1] == name.encode() + b'\0'
    assert data[:16] == original[:16] and data[24:at] == original[24:at]
    assert data[at + length:] == original[at + length:] and len(data) == len(original)


def main():
    if len(sys.argv) > 1:
        for sample in sys.argv[1:]:
            original = Path(sample).read_bytes()
            bits = 64 if original[:4] == bytes.fromhex('cffaedfe') else 32
            name = '@rpath/FridaGadget.dylib'
            added = patch(original, name)
            check_macho(original, added, name, bits, '<')
            assert patch(added, name) == added, 'duplicate changed chained pointers'
        print('Mach-O payloads preserved')
        return
    patch(b'not an executable', 'gadget.so', False)
    thin = macho(32, '<')
    fat = struct.pack('>7I', 0xcafebabe, 1, 7, 3, 0x1000, len(thin), 12)
    fat += bytes(0x1000 - len(fat)) + thin
    patch(fat, 'gadget.dylib', False, ('-a', 'x86'))
    for bits in (32, 64):
        for endian in ('<', '>'):
            for sections in (False, True):
                original = elf(bits, endian, sections)
                name = 'lib/path/libfridagadget.so'
                added = patch(original, name)
                check_elf(added, name, bits, endian)
                assert added[0x200:0x380] == original[0x200:0x380], 'existing ELF data changed'
                assert patch(added, name) == added, 'ELF duplicate modified file'
                assert patch(original, 'liboriginal.so') == original
                patch(original, '', False)
                broken = original[:]
                dynamic = 0x200 + 3 * (bits // 4)
                struct.pack_into(endian + ('Q' if bits == 64 else 'I'), broken, dynamic, 1)
                patch(broken, name, False)
                broken = original[:]
                struct.pack_into(endian + ('Q' if bits == 64 else 'I'), broken,
                                 0x200 + bits // 8, 0x100000)
                patch(broken, name, False)
            for signed in (False, True):
                original = macho(bits, endian, signed=signed)
                for name in ('a.dylib', '@executable_path/Frameworks/VeryLongFridaGadgetName.dylib'):
                    added = patch(original, name)
                    check_macho(original, added, name, bits, endian)
                    assert patch(added, name) == added, 'Mach-O duplicate modified file'
                patch(original, '', False)
            original = macho(bits, endian, padding=0)
            patch(original, 'gadget.dylib', False)
            original[-32:] = bytes(32)
            patch(original, 'gadget.dylib', False)
            patch(macho(bits, endian, padding=8), 'long/library/path.dylib', False)
            original = macho(bits, endian)
            hsize = 32 if bits == 64 else 28
            original[hsize + struct.unpack_from(endian + 'I', original, 20)[0]] = 1
            patch(original, 'gadget.dylib', False)
            struct.pack_into(endian + 'I', original, hsize + 4, 0)
            patch(original, 'gadget.dylib', False)
    print('ELF and Mach-O addlib checks passed')


if __name__ == '__main__':
    main()
