# Epson E0C62

The `e0c62` architecture provides assembly, disassembly, instruction analysis,
ESIL and pseudo syntax for the Epson E0C62 family of 4-bit microcontrollers,
built around the E0C6200/6200A core CPU (later renamed S1C62/S1C6200; MAME calls
it `e0c6200`).
Select it with `-a e0c62 -b 16`. Enable pseudo output with `e asm.pseudo=true`,
and use `aod mnemonic` to read an instruction description.

Instructions are 12-bit words stored in little-endian 16-bit containers. Radare2
uses byte addresses, so each instruction occupies two bytes and program word
addresses are multiplied by two. Branch operands retain the encoded 8-bit word
offset; `pset` selects the bank and page for the following branch. Assembly accepts
the disassembler's syntax, decimal or hexadecimal immediates, and optional `#`
immediate prefixes.

Execution starts at bank 0, page 1, step 0 (`0x200`), and the interrupt vectors
are steps 1 to 15 of page 1 in each bank (`0x202`-`0x21e` and `0x2202`-`0x221e`).
Start analysis of raw ROM dumps there, for example `af @ 0x200`. Analysis cannot
see a preceding `pset`, so `jp` and `call` targets assume the current page.
ESIL follows `pset` exactly: `np` holds the selected page and `pn` the address of
the branch it applies to, so emulation can start at any address.

Data memory is separate from program memory. ESIL maps each data nibble to one
byte starting at `0x10000`. The operands `mx` and `my` access data through X and Y;
pseudo output renders them as `[x]` and `[y]`. Index post-increments wrap the low
eight bits while preserving the page nibble.

The generic instruction set includes `slp` (`0xff9`, stored as `f9 0f`), which
stops the CPU and oscillator. It is supported by devices such as E0C6011, but is
unavailable on E0C6S46 and E0C6S48. The plugin does not restrict instructions by
device model. ESIL sets `halted` for both `halt` and `slp`, and additionally sets
`sleeping` for `slp`; it does not model oscillator timing, peripherals or interrupt
wakeup.

References: [E0C6200/6200A Core CPU Manual](https://download.epson-europe.com/pub/electronics-de/asmic/4bit/60family/62core_e.pdf)
and [E0C6011 Technical Manual](https://download.epson.eu/pub/electronics-de/asmic/4bit/60family/technicalmanual/tm_6011.pdf).

Regression tests: `test/db/asm/e0c62_16`, `test/db/anal/e0c62`, `test/db/esil/e0c62`
and `test/db/cmd/cmd_pseudo_e0c62`.
