#ifndef _INCLUDE_R_BIN_MACH0_SPECS_H_
#define _INCLUDE_R_BIN_MACH0_SPECS_H_

typedef int integer_t;

// NOTE(eddyb) the following have been slightly modified to work under radare.

#include "mach0_defines.h"

// HACK(eddyb) everything below is from the old mach0_specs.h, should replace
// with proper original definitions.

#undef MACH0_

#if R_BIN_MACH064
#define MACH0_(name) name##_64
#else
#define MACH0_(name) name
#endif

#define R_BIN_MACH0_SYMBOL_TYPE_EXT 0
#define R_BIN_MACH0_SYMBOL_TYPE_LOCAL 1

struct x86_thread_state32 {
	ut32	eax;
	ut32	ebx;
	ut32	ecx;
	ut32	edx;
	ut32	edi;
	ut32	esi;
	ut32	ebp;
	ut32	esp;
	ut32	ss;
	ut32	eflags;
	ut32	eip;
	ut32	cs;
	ut32	ds;
	ut32	es;
	ut32	fs;
	ut32	gs;
};

struct x86_thread_state64 {
	ut64	rax;
	ut64	rbx;
	ut64	rcx;
	ut64	rdx;
	ut64	rdi;
	ut64	rsi;
	ut64	rbp;
	ut64	rsp;
	ut64	r8;
	ut64	r9;
	ut64	r10;
	ut64	r11;
	ut64	r12;
	ut64	r13;
	ut64	r14;
	ut64	r15;
	ut64	rip;
	ut64	rflags;
	ut64	cs;
	ut64	fs;
	ut64	gs;
};

#define X86_THREAD_STATE32	1
#define X86_THREAD_STATE64	4

struct ppc_thread_state32 {
	ut32 srr0;  /* Instruction address register (PC) */
	ut32 srr1;	/* Machine state register (supervisor) */
	ut32 r0;
	ut32 r1;
	ut32 r2;
	ut32 r3;
	ut32 r4;
	ut32 r5;
	ut32 r6;
	ut32 r7;
	ut32 r8;
	ut32 r9;
	ut32 r10;
	ut32 r11;
	ut32 r12;
	ut32 r13;
	ut32 r14;
	ut32 r15;
	ut32 r16;
	ut32 r17;
	ut32 r18;
	ut32 r19;
	ut32 r20;
	ut32 r21;
	ut32 r22;
	ut32 r23;
	ut32 r24;
	ut32 r25;
	ut32 r26;
	ut32 r27;
	ut32 r28;
	ut32 r29;
	ut32 r30;
	ut32 r31;

	ut32 cr;    /* Condition register */
	ut32 xer;	/* User's integer exception register */
	ut32 lr;	/* Link register */
	ut32 ctr;	/* Count register */
	ut32 mq;	/* MQ register (601 only) */

	ut32 vrsave;	/* Vector Save Register */
};

struct ppc_thread_state64 {
	ut64 srr0;  /* Instruction address register (PC) */
	ut64 srr1;  /* Machine state register (supervisor) */
	ut64 r0;
	ut64 r1;
	ut64 r2;
	ut64 r3;
	ut64 r4;
	ut64 r5;
	ut64 r6;
	ut64 r7;
	ut64 r8;
	ut64 r9;
	ut64 r10;
	ut64 r11;
	ut64 r12;
	ut64 r13;
	ut64 r14;
	ut64 r15;
	ut64 r16;
	ut64 r17;
	ut64 r18;
	ut64 r19;
	ut64 r20;
	ut64 r21;
	ut64 r22;
	ut64 r23;
	ut64 r24;
	ut64 r25;
	ut64 r26;
	ut64 r27;
	ut64 r28;
	ut64 r29;
	ut64 r30;
	ut64 r31;

	ut32 cr;			/* Condition register */
	ut64 xer;		/* User's integer exception register */
	ut64 lr;		/* Link register */
	ut64 ctr;		/* Count register */

	ut32 vrsave;		/* Vector Save Register */
};

struct arm_thread_state32 {
	ut32 r0;
	ut32 r1;
	ut32 r2;
	ut32 r3;
	ut32 r4;
	ut32 r5;
	ut32 r6;
	ut32 r7;
	ut32 r8;
	ut32 r9;
	ut32 r10;
	ut32 r11;
	ut32 r12;
	ut32 r13;
	ut32 r14;
	ut32 r15;
	ut32 r16;   /* Apple's thread_state has this 17th reg, bug?? */
};

struct arm_thread_state64 {
	ut64 x[29];
	ut64 fp;
	ut64 lr;
	ut64 sp;
	ut64 pc;
	ut32 cpsr;
};

/* Cache header */

struct cache_header {
	char version[16];
	ut32 baseaddroff; //mappingOffset
	ut32 mappingCount;
	ut32 startaddr;
	ut32 numlibs;
	ut64 dyldaddr;
	ut64 codeSignatureOffset;
	ut64 codeSignatureSize;
	ut64 slideInfoOffset;
	ut64 slideInfoSize;
	ut64 localSymbolsOffset;
	ut64 localSymbolsSize;
};

// dupe?
typedef struct {
	char     magic[16];
	uint32_t mappingOffset;
	uint32_t mappingCount;
	uint32_t imagesOffset;
	uint32_t imagesCount;
	uint64_t dyldBaseAddress;
	uint64_t codeSignatureOffset;
	uint64_t codeSignatureSize;
	uint64_t slideInfoOffset;
	uint64_t slideInfoSize;
	uint64_t localSymbolsOffset;
	uint64_t localSymbolsSize;
	uint8_t  uuid[16];
	uint64_t cacheType;
	uint32_t branchPoolsOffset;
	uint32_t branchPoolsCount;
	uint64_t accelerateInfoAddr;
	uint64_t accelerateInfoSize;
	uint64_t imagesTextOffset;
	uint64_t imagesTextCount;
} cache_hdr_t;

typedef struct {
	uint8_t uuid[16];
	uint64_t loadAddress;
	uint32_t textSegmentSize;
	uint32_t pathOffset;
} cache_text_info_t;

typedef struct {
	uint64_t address;
	uint64_t size;
	uint64_t fileOffset;
	uint32_t maxProt;
	uint32_t initProt;
} cache_map_t;

typedef struct {
	uint64_t address;
	uint64_t modTime;
	uint64_t inode;
	uint32_t pathFileOffset;
	uint32_t pad;
} cache_img_t;

typedef struct {
	uint32_t version;
	uint32_t page_size;
	uint32_t page_starts_count;
	uint32_t padding;
	uint64_t auth_value_add;
} cache_slide3_t;

typedef struct {
	uint32_t version;
	uint32_t page_size;
	uint32_t page_starts_offset;
	uint32_t page_starts_count;
	uint32_t page_extras_offset;
	uint32_t page_extras_count;
	uint64_t delta_mask;
	uint64_t value_add;
} cache_slide2_t;

typedef struct {
	uint32_t version;
	uint32_t toc_offset;
	uint32_t toc_count;
	uint32_t entries_offset;
	uint32_t entries_count;
	uint32_t entries_size;
} cache_slide1_t;

typedef struct {
	uint32_t version;
	uint32_t imageExtrasCount;
	uint32_t imagesExtrasOffset;
	uint32_t bottomUpListOffset;
	uint32_t dylibTrieOffset;
	uint32_t dylibTrieSize;
	uint32_t initializersOffset;
	uint32_t initializersCount;
	uint32_t dofSectionsOffset;
	uint32_t dofSectionsCount;
	uint32_t reExportListOffset;
	uint32_t reExportCount;
	uint32_t depListOffset;
	uint32_t depListCount;
	uint32_t rangeTableOffset;
	uint32_t rangeTableCount;
	uint64_t dyldSectionAddr;
} cache_accel_t;

typedef struct {
	uint64_t exportsTrieAddr;
	uint64_t weakBindingsAddr;
	uint32_t exportsTrieSize;
	uint32_t weakBindingsSize;
	uint32_t dependentsStartArrayIndex;
	uint32_t reExportsStartArrayIndex;
} cache_imgxtr_t;

typedef struct {
	uint32_t nlistOffset;
	uint32_t nlistCount;
	uint32_t stringsOffset;
	uint32_t stringsSize;
	uint32_t entriesOffset;
	uint32_t entriesCount;
} cache_locsym_info_t;

typedef struct {
	uint32_t dylibOffset;
	uint32_t nlistStartIndex;
	uint32_t nlistCount;
} cache_locsym_entry_t;

typedef struct {
	uint64_t address;
	uint64_t size;
	uint64_t fileOffset;
	uint64_t slideInfoOffset;
	uint64_t slideInfoSize;
	uint64_t unknown;
	uint32_t maxProt;
	uint32_t initProt;
} cache_mapping_slide;

#define DYLD_CACHE_SLIDE_PAGE_ATTRS 0xC000
#define DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA 0x8000
#define DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE 0x4000
#define DYLD_CACHE_SLIDE_PAGE_ATTR_END 0x8000
#define DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE 0xFFFF
#endif
