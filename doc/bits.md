# Non-octet units

Some architectures do not store code in 8-bit bytes: cLEMENCy uses 9-bit
bytes and 27-bit words, Epson E0C62 uses 12-bit instructions and other cores
use 25-bit words. Their images come in two layouts:

* **unpacked**: each unit lives in the smallest integer container holding it
  (1, 2, 4 or 8 bytes). A 12-bit word takes two bytes and the top nibble is
  zero. This is what disassemblers and emulators want to read.
* **packed**: units are concatenated as a bit stream without padding. 6144
  12-bit words take 9216 bytes instead of 12288.

## Endianness

A single `le`/`be` choice describes both the stream and the containers:

| endian | stream                                     | containers  |
| ------ | ------------------------------------------ | ----------- |
| `le`   | starts at the lsb of the first byte        | little endian |
| `be`   | starts at the msb of the first byte        | big endian  |

For the 12-bit words `0xabc` and `0xdef`:

| endian | packed     | unpacked      |
| ------ | ---------- | ------------- |
| `le`   | `bc fa de` | `bc 0a ef 0d` |
| `be`   | `ab cd ef` | `0a bc 0d ef` |

To mix them, swap the containers separately, for example with
`rax2 -S < in | rax2 -esb 16`.

## rax2

`-p <bits>` packs and `-P <bits>` unpacks stdin into stdout. They are little
endian unless `-e` is given.

```sh
rax2 -p 12 < p1.bin > p1.packed      # 12288 -> 9216 bytes
rax2 -P 12 < p1.packed > p1.bin      # and back
rax2 -eP 9 < clemency.bin > out.bin  # be 9-bit stream into be16 units
```

Packing fails when a container holds a value wider than the unit size.

## bits:// io plugin

`bits://<bits>[le|be]/<path>` opens a packed file and exposes it unpacked, so
any tool sees the container layout without converting the file:

```sh
r2 -a e0c62 -b 16 bits://12/roms/p1.packed
r2 -w bits://9be//abs/path/to/image.bin
```

The translation only applies to that source; other files, maps and the
address space are unchanged. Reads unpack on the fly, writes are truncated to
the unit size and saved back to the packed file on close when it was opened
for writing. Trailing bits that do not fill a whole unit are not exposed.
r2tama runs unchanged on `bits://12/p1.packed` because it sees the same 12288
byte image as with the unpacked ROM.

## API

`libr/include/r_util/r_mem.h` provides:

* `r_mem_get_bits` / `r_mem_set_bits`: read or write one unit at any bit offset
* `r_mem_pack_bits` / `r_mem_unpack_bits`: convert whole buffers
* `r_mem_bits_unit`: container size in bytes for a unit size

## Address units

Every r2 address is a byte address. Word addressed architectures convert word
addresses in the arch plugin, like E0C62 where the reset vector at word
`0x100` is `pc=0x200`. `RIO.addrbytes` and `RArchConfig.addrbytes` describe how
many bytes one address unit takes, but they are always 1: there is no eval
variable for them since `asm.addrbytes` was removed, and only some disassembly
and analysis loops honor them. Supporting word addresses needs io to translate
units into byte offsets and the core to scale seeks, hexdumps, searches,
flags and section sizes by `addrbytes`.
