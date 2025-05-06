/* radare2 - MIT - Copyright 2021-2022 - pancake, keegan, Plan 9 Foundation */

#ifndef P9BIN_H
#define P9BIN_H

#include <r_util.h>

R_PACKED(
struct plan9_exec {
	ut32 magic;
	ut32 text;
	ut32 data;
	ut32 bss;
	ut32 syms;
	ut32 entry;
	ut32 spsz;
	ut32 pcsz;
});

typedef struct r_bin_plan9_obj_t {
	struct plan9_exec header;
	// can indicate an extended header (for 64-bit binaries)
	ut64 header_size;
	// use this instead of the one in the header
	ut64 entry;
	bool is_kernel;
	// pc quantization per arch
	ut64 pcq;
} RBinPlan9Obj;

/* Flag for extended header. This means that an additional 64-bit integer follows
 * the standard header which specifies the 64-bit entrypoint. */
#define HDR_MAGIC 0x00008000

#define	_MAGIC(flags, b) ((flags) | ((((4 * (b)) + 0) * (b)) + 7))

#define	MAGIC_68020 _MAGIC(0, 8)

#define	MAGIC_INTEL_386 _MAGIC(0, 11)
#define	MAGIC_AMD64 _MAGIC(HDR_MAGIC, 26)

#define	MAGIC_SPARC _MAGIC(0, 13)
#define	MAGIC_SPARC64 _MAGIC(0, 25)

#define	MAGIC_MIPS_3000BE _MAGIC(0, 16)
#define	MAGIC_MIPS_4000BE _MAGIC(0, 18)
#define	MAGIC_MIPS_4000LE _MAGIC(0, 22)
#define	MAGIC_MIPS_3000LE _MAGIC(0, 24)

#define	MAGIC_ARM _MAGIC(0, 20)
#define	MAGIC_ARM64 _MAGIC(HDR_MAGIC, 28)

#define	MAGIC_PPC _MAGIC(0, 21)
#define	MAGIC_PPC64 _MAGIC(HDR_MAGIC, 27)

/* Retired, and subsequently unsupported, architectures. */
#define	MAGIC_INTEL_960 _MAGIC(0, 12)
#define	MAGIC_ATT_DSP_3210 _MAGIC(0, 17)
#define	MAGIC_AMD_29000 _MAGIC(0, 19)
#define	MAGIC_DEC_ALPHA _MAGIC(0, 23)

#define KERNEL_MASK 0xffff800000000000ULL

/* Reads four bytes from b. */
bool r_bin_p9_get_arch(RBuffer * R_NONNULL b, const char ** R_NONNULL arch, int * R_NONNULL bits, int * R_NONNULL big_endian);

#endif
