/* radare - LGPL - 2018 - rkx1209 */

#ifndef _NXO_H
#define _NXO_H

typedef struct {
	ut32 unused;
	ut32 mod_memoffset;
	ut64 padding;
} NXOStart;

typedef struct {
	ut32 magic;
	ut32 dynamic;
	ut32 bss_start;
	ut32 bss_end;
	ut32 unwind_start;
	ut32 unwind_end;
	ut32 mod_object;
} MODHeader;

typedef struct {
	ut64 next;
	ut64 prev;
	ut64 relplt;
	ut64 reldyn;
	ut64 base;
	ut64 dynamic;
	ut64 is_rela;
	ut64 relplt_size;
	ut64 init;
	ut64 fini;
	ut64 bucket;
	ut64 chain;
	ut64 strtab;
	ut64 symtab;
	ut64 strtab_size;
	ut64 got;
	ut64 reladyn_size;
	ut64 reldyn_size;
	ut64 relcount;
	ut64 relacount;
	ut64 nchain;
	ut64 nbucket;
	ut64 got_value;
} MODObject;

typedef struct {
	ut32 mod_offset;
	ut32 text_offset;
	ut32 text_size;
	ut32 ro_offset;
	ut32 ro_size;
	ut32 data_offset;
	ut32 data_size;
	ut32 bss_size;
} MODMeta;

typedef struct {
	ut32 *strings;
	RList *methods_list;
	RList *imports_list;
	RList *classes_list;
} RBinNXOObj;

void parseMod(RBuffer *buf, RBinNXOObj *bin, ut32 mod0, ut64 baddr);
const char *fileType(const ut8 *buf);

#endif
