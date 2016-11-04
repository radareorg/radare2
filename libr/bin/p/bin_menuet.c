/* radare2 - LGPL - Copyright 2016 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#define MENUET_VERSION(x) x[7]

static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

#if 0
        db      'MENUET00'           ; 8 byte id
        dd      38                   ; required os
        dd      START                ; program start
        dd      I_END                ; image size
        dd      0x100000             ; reguired amount of memory
        dd      0x00000000           ; reserved=no extended header

        org     0x0
        db      'MENUET01'              ; 8 byte id
        dd      1                       ; header version
        dd      START                   ; program start
        dd      I_END                   ; program image size
        dd      0x1000                  ; required amount of memory
        dd      0x1000                  ; esp
        dd      0, 0                    ; no parameters, no path

         0 db 'MENUET02'
         8 dd 0x01
        12 dd __start
        16 dd __iend
        20 dd __bssend
        24 dd __stack
        28 dd __cmdline
        32 dd __pgmname
        36 dd 0x0; tls map
        40 dd __idata_start; секция .import
        44 dd __idata_end
        48 dd main

        db 'MENUET02'
        dd 1
        dd start
        dd i_end
        dd mem
        dd mem
        dd cmdline
        dd path
        dd 0

#endif

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static int check_bytes(const ut8 *buf, ut64 length) {
	if (buf && length >= 32 && !memcmp (buf, "MENUET0", 7)) {
		switch (buf[7]) {
		case '0':
		case '1':
		case '2':
			return true;
		}
		eprintf ("Unsupported MENUET version header\n");
	}
	return false;
}

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	return (void*)(size_t)check_bytes (buf, sz);
}

static int load(RBinFile *arch) {
	return check (arch);
}

static ut64 baddr(RBinFile *arch) {
	return 0; // 0x800000;
}

static ut64 menuetEntry (const ut8 *buf, int buf_size) {
	switch (MENUET_VERSION(buf)) {
	case '0': return r_read_ble32 (buf + 12, false);
	case '1': return r_read_ble32 (buf + 12, false);
	case '2': return r_read_ble32 (buf + 44, false);
	}
	return UT64_MAX;
}

static RList* entries(RBinFile *arch) {
	RList* ret;
	ut8 buf[64] = {0};
	RBinAddr *ptr = NULL;
	const int buf_size = R_MIN (sizeof (buf), r_buf_size (arch->buf));

	r_buf_read_at (arch->buf, 0, buf, buf_size);
	ut64 entry = menuetEntry (buf, buf_size);
	if (entry == UT64_MAX) {
		return NULL;
	}
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;
	if ((ptr = R_NEW0 (RBinAddr))) {
		ptr->paddr = r_read_ble32 (buf + 12, false);
		ptr->vaddr = ptr->paddr + baddr (arch);
		r_list_append (ret, ptr);
	}
	return ret;
}

static RList* sections(RBinFile *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	ut8 buf[64] = {0};
	const int buf_size = R_MIN (sizeof (buf), r_buf_size (arch->buf));

	r_buf_read_at (arch->buf, 0, buf, buf_size);
	if (!arch->o->info) {
		return NULL;
	}

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	// add text segment
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	strncpy (ptr->name, "text", R_BIN_SIZEOF_STRINGS);
	ptr->size = r_read_ble32 (buf + 16, false);
	ptr->vsize = ptr->size + (ptr->size % 4096);
	ptr->paddr = r_read_ble32 (buf + 12, false);
	ptr->vaddr = ptr->paddr + baddr (arch);
	ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP; // r-x
	ptr->add = true;
	r_list_append (ret, ptr);

	if (MENUET_VERSION(buf)) {
		/* add data section */
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}
		strncpy (ptr->name, "idata", R_BIN_SIZEOF_STRINGS);
		const ut32 idata_start = r_read_ble32 (buf + 40, false);
		const ut32 idata_end = r_read_ble32 (buf + 44, false);
		ptr->size = idata_end - idata_start;
		ptr->vsize = ptr->size + (ptr->size % 4096);
		ptr->paddr = r_read_ble32 (buf + 40, false);
		ptr->vaddr = ptr->paddr + baddr (arch);
		ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_MAP; // r--
		ptr->add = true;
		r_list_append (ret, ptr);
	}

	return ret;
}

static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (ret) {
		ret->file = strdup (arch->file);
		ret->bclass = strdup ("program");
		ret->rclass = strdup ("menuet");
		ret->os = strdup ("MenuetOS");
		ret->arch = strdup ("x86");
		ret->machine = strdup (ret->arch);
		ret->subsystem = strdup ("kolibri");
		ret->type = strdup ("EXEC");
		ret->bits = 32;
		ret->has_va = true;
		ret->big_endian = 0;
		ret->dbg_info = 0;
		ret->dbg_info = 0;
	}
	return ret;
}

static ut64 size(RBinFile *arch) {
	ut8 buf[4] = {0};
	if (!arch->o->info) {
		arch->o->info = info (arch);
	}
	if (!arch->o->info) {
		return 0;
	}
	r_buf_read_at (arch->buf, 16, buf, 4);
	return (ut64)r_read_ble32 (buf, false);
}

#if !R_BIN_P9

/* inspired in http://www.phreedom.org/solar/code/tinype/tiny.97/tiny.asm */
static RBuffer* create(RBin* bin, const ut8 *code, int codelen, const ut8 *data, int datalen) {
	RBuffer *buf = r_buf_new ();
#define B(x,y) r_buf_append_bytes(buf,(const ut8*)x,y)
#define D(x) r_buf_append_ut32(buf,x)
	B ("MENUET01", 8);
	D (1); // header version
	D (32); // program start
	D (0x1000); // program image size
	D (0x1000); // ESP
	D (0); // no parameters
	D (0); // no path
	B (code, codelen);
	return buf;
}

RBinPlugin r_bin_plugin_menuet = {
	.name = "menuet",
	.desc = "Menuet/KolibriOS bin plugin",
	.license = "LGPL3",
	.load = &load,
	.load_bytes = &load_bytes,
	.size = &size,
	.check = &check,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.entries = &entries,
	.sections = &sections,
	.info = &info,
	.create = &create,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_menuet,
	.version = R2_VERSION
};
#endif
#endif
