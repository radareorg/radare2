#include <r_bin.h>
#include <r_types.h>

#ifndef _INCLUDE_R_BIN_CORESYMBOLICATION_H
#define _INCLUDE_R_BIN_CORESYMBOLICATION_H

typedef struct r_coresym_cache_element_hdr_t {
	ut32 version;
	ut32 size;
	ut32 n_segments;
	ut32 n_sections;
	ut32 n_symbols;
	ut32 n_lined_symbols;
	ut32 n_line_info;
	ut32 f;
	ut32 g;
	ut32 h;
	ut32 file_name_off;
	ut32 version_off;
	ut32 k;
	ut8 uuid[16];
	ut32 cputype;
	ut32 cpusubtype;
	ut32 o;
	ut32 strings_off;
	ut32 p;
} RCoreSymCacheElementHdr;

typedef struct r_coresym_cache_element_segment_t {
	ut64 paddr;
	ut64 vaddr;
	ut64 size;
	ut64 vsize;
	char *name;
} RCoreSymCacheElementSegment;

typedef struct r_coresym_cache_element_section_t {
	ut64 paddr;
	ut64 vaddr;
	ut64 size;
	char *name;
} RCoreSymCacheElementSection;

typedef struct r_coresym_cache_element_flc_t {
	char *file;
	ut32 line;
	ut32 col;
} RCoreSymCacheElementFLC;

typedef struct r_coresym_cache_element_line_info_t {
	ut32 paddr;
	ut32 size;
	RCoreSymCacheElementFLC flc;
} RCoreSymCacheElementLineInfo;

typedef struct r_coresym_cache_element_symbol_t {
	ut32 paddr;
	ut32 size;
	ut32 unk1;
	char *name;
	char *mangled_name;
	st32 unk2;
} RCoreSymCacheElementSymbol;

typedef struct r_coresym_cache_element_lined_symbol_t {
	RCoreSymCacheElementSymbol sym;
	RCoreSymCacheElementFLC flc;
} RCoreSymCacheElementLinedSymbol;

typedef struct r_coresym_cache_element_t {
	RCoreSymCacheElementHdr *hdr;
	char *file_name;
	char *binary_version;
	RCoreSymCacheElementSegment *segments;
	RCoreSymCacheElementSection *sections;
	RCoreSymCacheElementSymbol *symbols;
	RCoreSymCacheElementLinedSymbol *lined_symbols;
	RCoreSymCacheElementLineInfo *line_info;
} RCoreSymCacheElement;

R_API RCoreSymCacheElement *r_coresym_cache_element_new(RBinFile *bf, RBuffer *buf, ut64 off, int bits, R_OWN char * file_name);
R_API void r_coresym_cache_element_free(RCoreSymCacheElement *element);
R_API ut64 r_coresym_cache_element_pa2va(RCoreSymCacheElement *element, ut64 pa);

#endif
