/* radare - LGPL - Copyright 2016 - damo22 */

#if LIL_ENDIAN
#define CFG_BIGENDIANHOST "false"
#else
#define CFG_BIGENDIANHOST "true"
#endif

/* this default will change when the endianness is set */
#define CFG_BIGENDIANTARGET CFG_BIGENDIANHOST

#define BIGENDIAN(x)                 \
	(( (!strcmp(x, "8051"))      \
	|| (!strcmp(x, "avr"))       \
	|| (!strcmp(x, "h8300"))     \
	|| (!strcmp(x, "hppa"))      \
	|| (!strcmp(x, "java"))      \
	|| (!strcmp(x, "lanai"))     \
	|| (!strcmp(x, "lm32"))      \
	|| (!strcmp(x, "m68k"))      \
	|| (!strcmp(x, "m68k.cs"))   \
	|| (!strcmp(x, "propeller")) \
	|| (!strcmp(x, "sparc"))     \
	|| (!strcmp(x, "sparc.gnu")) \
	|| (!strcmp(x, "sysz"))      \
	))

#define DUALENDIAN(x)                 \
	(( (!strcmp(x, "arc"))        \
	|| (!strcmp(x, "arm"))        \
	|| (!strcmp(x, "arm.as"))     \
	|| (!strcmp(x, "arm.gnu"))    \
	|| (!strcmp(x, "arm.winedbg"))\
	|| (!strcmp(x, "mips"))       \
	|| (!strcmp(x, "mips.gnu"))   \
	|| (!strcmp(x, "ppc"))        \
	|| (!strcmp(x, "ppc.gnu"))    \
	|| (!strcmp(x, "riscv"))      \
	|| (!strcmp(x, "sh"))         \
	|| (!strcmp(x, "sh"))         \
	|| (!strcmp(x, "tms320"))     \
	|| (!strcmp(x, "xtensa"))     \
	))

#define LITTLEENDIAN(x)             \
	(( (!strcmp(x, "6502"))     \
	|| (!strcmp(x, "cr16"))     \
	|| (!strcmp(x, "cris"))     \
	|| (!strcmp(x, "csr"))      \
	|| (!strcmp(x, "dalvik"))   \
	|| (!strcmp(x, "dcpu16"))   \
	|| (!strcmp(x, "ebc"))      \
	|| (!strcmp(x, "gb"))       \
	|| (!strcmp(x, "msp430"))   \
	|| (!strcmp(x, "nios2"))    \
	|| (!strcmp(x, "rar"))      \
	|| (!strcmp(x, "snes"))     \
	|| (!strcmp(x, "tricore"))  \
	|| (!strcmp(x, "v810"))     \
	|| (!strcmp(x, "v850"))     \
	|| (!strcmp(x, "vax"))      \
	|| (!strcmp(x, "x86"))      \
	|| (!strcmp(x, "x86.as"))   \
	|| (!strcmp(x, "x86.nasm")) \
	|| (!strcmp(x, "x86.nz"))   \
	|| (!strcmp(x, "x86.olly")) \
	|| (!strcmp(x, "x86.tab"))  \
	|| (!strcmp(x, "x86.udis")) \
	|| (!strcmp(x, "xcore"))    \
	|| (!strcmp(x, "z80"))      \
	|| (!strcmp(x, "z80.cr"))   \
	))

#define ENDIANNEUTRAL(x)            \
	(( (!strcmp(x, "bf"))       \
	|| (!strcmp(x, "i4004"))    \
	|| (!strcmp(x, "i8080"))    \
	|| (!strcmp(x, "lh5801"))   \
	|| (!strcmp(x, "malbolge")) \
	|| (!strcmp(x, "mcs96"))    \
	|| (!strcmp(x, "pic18c"))   \
	|| (!strcmp(x, "spc700"))   \
	|| (!strcmp(x, "ws"))       \
	))

// helper macro
#define IS_MISMATCHED_ENDIAN(x) \
	(  (  CFG_BIGENDIANHOST && (!BIGENDIAN(x) ||  LITTLEENDIAN(x))) \
	|| ( !CFG_BIGENDIANHOST && ( BIGENDIAN(x) || !LITTLEENDIAN(x))) \
	)

// set dual and neutral endian to same as host, otherwise detect endian
#define IS_BIG_ENDIAN_TARGET(x)                                         \
	(( BIGENDIAN(x) || !LITTLEENDIAN(x) )                           \
	|| ( CFG_BIGENDIANHOST ?  (ENDIANNEUTRAL(x) || DUALENDIAN(x))   \
			       : !(ENDIANNEUTRAL(x) || DUALENDIAN(x)) ) \
	)

