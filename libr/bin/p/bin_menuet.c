/* radare2 - LGPL - Copyright 2016-2019 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#define MENUET_VERSION(x) x[7]

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

static bool check_buffer(RBuffer *b) {
	ut8 buf[8];
	if (r_buf_read_at (b, 0, buf, sizeof (buf)) != sizeof (buf)) {
		return false;
	}
	if (r_buf_size (b) >= 32 && !memcmp (buf, "MENUET0", 7)) {
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

static bool load_buffer (RBinFile *bf, void **bin_obj, RBuffer *b, ut64 loadaddr, Sdb *sdb){
	return check_buffer (b);
}

static ut64 baddr(RBinFile *bf) {
	return 0; // 0x800000;
}

static ut64 menuetEntry(const ut8 *buf, int buf_size) {
	switch (MENUET_VERSION(buf)) {
	case '0': return r_read_ble32 (buf + 12, false);
	case '1': return r_read_ble32 (buf + 12, false);
	case '2': return r_read_ble32 (buf + 44, false);
	}
	return UT64_MAX;
}

static RList* entries(RBinFile *bf) {
	RList* ret;
	ut8 buf[64] = {0};
	RBinAddr *ptr = NULL;
	const int buf_size = R_MIN (sizeof (buf), r_buf_size (bf->buf));

	r_buf_read_at (bf->buf, 0, buf, buf_size);
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
		ptr->vaddr = ptr->paddr + baddr (bf);
		r_list_append (ret, ptr);
	}
	return ret;
}

static RList* sections(RBinFile *bf) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	ut8 buf[64] = {0};
	const int buf_size = R_MIN (sizeof (buf), r_buf_size (bf->buf));

	r_buf_read_at (bf->buf, 0, buf, buf_size);
	if (!bf->o->info) {
		return NULL;
	}

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	// add text segment
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("text");
	ptr->size = r_read_ble32 (buf + 16, false);
	ptr->vsize = ptr->size + (ptr->size % 4096);
	ptr->paddr = r_read_ble32 (buf + 12, false);
	ptr->vaddr = ptr->paddr + baddr (bf);
	ptr->perm = R_PERM_RX; // r-x
	ptr->add = true;
	r_list_append (ret, ptr);

	if (MENUET_VERSION(buf)) {
		/* add data section */
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}
		ptr->name = strdup ("idata");
		const ut32 idata_start = r_read_ble32 (buf + 40, false);
		const ut32 idata_end = r_read_ble32 (buf + 44, false);
		ptr->size = idata_end - idata_start;
		ptr->vsize = ptr->size + (ptr->size % 4096);
		ptr->paddr = r_read_ble32 (buf + 40, false);
		ptr->vaddr = ptr->paddr + baddr (bf);
		ptr->perm = R_PERM_R; // r--
		ptr->add = true;
		r_list_append (ret, ptr);
	}

	return ret;
}

static RBinInfo* info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (ret) {
		ret->file = strdup (bf->file);
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

static ut64 size(RBinFile *bf) {
	ut8 buf[4] = {0};
	if (!bf->o->info) {
		bf->o->info = info (bf);
	}
	if (!bf->o->info) {
		return 0;
	}
	r_buf_read_at (bf->buf, 16, buf, 4);
	return (ut64)r_read_ble32 (buf, false);
}

#if !R_BIN_P9

/* inspired in http://www.phreedom.org/solar/code/tinype/tiny.97/tiny.asm */
static RBuffer* create(RBin* bin, const ut8 *code, int codelen, const ut8 *data, int datalen, RBinArchOptions *opt) {
	RBuffer *buf = r_buf_new ();
#define B(x,y) r_buf_append_bytes(buf,(const ut8*)(x),y)
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
	.load_buffer = &load_buffer,
	.size = &size,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.entries = &entries,
	.sections = &sections,
	.info = &info,
	.create = &create,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_menuet,
	.version = R2_VERSION
};
#endif
#endif
