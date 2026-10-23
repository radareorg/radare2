# ARM / AArch64 endian

AArch64 (A64) instructions are **always little-endian** in memory, regardless
of the target's data byte order. This is fixed by the ARMv8-A architecture
(DDI 0487, §E1.3) — there is no big-endian instruction mode and no `SETEND`
equivalent. A "big-endian" AArch64 binary (ELF `EI_DATA = ELFDATA2MSB`) is the
BE8 model: data is BE, instructions remain LE within each 4-byte word.

In r2 this means `cfg.bigendian` (auto-set from the ELF header on load) only
affects data reads and display (`pxw`, `pxq`, struct fields). For instruction
decoding on AArch64 it is ignored — the value is always LE.

## AArch64 backends (`asm.arch=arm`, `bits=64`)

| Plugin    | File                                | BE8 handling                                                                 |
|-----------|-------------------------------------|------------------------------------------------------------------------------|
| `arm`     | `libr/arch/p/arm/cs/arm64.c`        | **Default.** Capstone backend. Forces `CS_MODE_LITTLE_ENDIAN` for `bits==64`. |
| `arm.gnu` | `libr/arch/p/arm/plugin_gnu.c`      | GNU binutils backend. `aarch64-dis.c` hard-codes `endian_code = BFD_ENDIAN_LITTLE`; instruction stream is always LE regardless of `cfg.bigendian`. |
| `arm.v35` | `libr/arch/p/arm/plugin_v35.c`      | Vector35 backend (optional, not in default builds). Declares LE-only; will not accept a BE config cleanly. |
| `arm.nz`  | `libr/arch/p/arm/plugin.c`          | Custom assembler — `.encode` only, no `.decode`. Not relevant for disassembly. |

## AArch32 (`bits` is 16 or 32)

AArch32 is different: BE32 (legacy, ARMv5-) has big-endian instruction
words and follows `cfg.bigendian`; BE8 AArch32 (ARMv6+) has LE instructions
and BE data. For ELF, `EF_ARM_BE8` in `e_flags` is exposed through `asm.abi`,
and the ARM decoders use it to decode instructions as little-endian while
leaving `cfg.bigendian` unchanged for data reads.
