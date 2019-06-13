/* radare2 - LGPL - Copyright 2017-2018 - rkx1209 */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <r_io.h>
#include <r_cons.h>
#include "nxo/nxo.h"
#ifdef R_MESON_VERSION
#include <lz4.h>
#else
#include "../../../shlr/lz4/lz4.c"
#endif

#define NSO_OFF(x) r_offsetof (NSOHeader, x)
#define NSO_OFFSET_MODMEMOFF r_offsetof (NXOStart, mod_memoffset)

// starting at 0
typedef struct {
	ut32 magic;	// NSO0
	ut32 pad0;	// 4
	ut32 pad1;	// 8
	ut32 pad2;	// 12
	ut32 text_memoffset;	// 16
	ut32 text_loc;	// 20
	ut32 text_size;	// 24
	ut32 pad3;	// 28
	ut32 ro_memoffset;	// 32
	ut32 ro_loc;	// 36
	ut32 ro_size;	// 40
	ut32 pad4;	// 44
	ut32 data_memoffset;	// 48
	ut32 data_loc;	// 52
	ut32 data_size;	// 56
	ut32 bss_size;	// 60
} NSOHeader;

static uint32_t decompress(const ut8 *cbuf, ut8 *obuf, int32_t csize, int32_t usize) {
	if (csize < 0 || usize < 0 || !cbuf || !obuf) {
		return -1;
	}
	return LZ4_decompress_safe ((const char*)cbuf, (char*)obuf, (uint32_t) csize, (uint32_t) usize);
}

static ut64 baddr(RBinFile *bf) {
	return 0x8000000;
}

static bool check_buffer(RBuffer *b) {
	if (r_buf_size (b) >= 0x20) {
		ut8 magic[4];
		if (r_buf_read_at (b, 0, magic, sizeof (magic)) != 4) {
			return false;
		}
		return fileType (magic) != NULL;
	}
	return false;
}

static RBinNXOObj *nso_new () {
	RBinNXOObj *bin = R_NEW0 (RBinNXOObj);
	if (bin) {
		bin->methods_list = r_list_newf ((RListFree)free);
		bin->imports_list = r_list_newf ((RListFree)free);
		bin->classes_list = r_list_newf ((RListFree)free);
	}
	return bin;
}

static bool load_bytes(RBinFile *bf, void **bin_obj, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	eprintf ("load_bytes in bin.nso must die\n");
	RBin *rbin = bf->rbin;
	ut32 toff = readLE32 (bf->buf, NSO_OFF (text_memoffset));
	ut32 tsize = readLE32 (bf->buf, NSO_OFF (text_size));
	ut32 rooff = readLE32 (bf->buf, NSO_OFF (ro_memoffset));
	ut32 rosize = readLE32 (bf->buf, NSO_OFF (ro_size));
	ut32 doff = readLE32 (bf->buf, NSO_OFF (data_memoffset));
	ut32 dsize = readLE32 (bf->buf, NSO_OFF (data_size));
	ut64 total_size = tsize + rosize + dsize;
	RBuffer *newbuf = r_buf_new_empty (total_size);
	ut64 ba = baddr (bf);
	ut8 *tmp = NULL;

	if (rbin->iob.io && !(rbin->iob.io->cached & R_PERM_W)) {
		eprintf ("Please add \'-e io.cache=true\' option to r2 command. This is required to decompress the code.\n");
		goto fail;
	}
	/* Decompress each sections */
	tmp = R_NEWS (ut8, tsize);
	if (!tmp) {
		goto fail;
	}
	if (decompress (buf + toff, tmp, rooff - toff, tsize) != tsize) {
		eprintf ("decompression failure\n");
		goto fail;
	}
	r_buf_write_at (newbuf, 0, tmp, tsize);
	R_FREE (tmp);

	tmp = R_NEWS (ut8, rosize);
	if (!tmp) {
		goto fail;
	}
	if (decompress (buf + rooff, tmp, doff - rooff, rosize) != rosize) {
		eprintf ("decompression2 failure\n");
		goto fail;
	}
	r_buf_write_at (newbuf, tsize, tmp, rosize);
	R_FREE (tmp);

	tmp = R_NEWS (ut8, dsize);
	if (!tmp) {
		goto fail;
	}
	if (decompress (buf + doff, tmp, r_buf_size (bf->buf) - doff, dsize) != dsize) {
		eprintf ("decompression3 failure\n");
		goto fail;
	}
	r_buf_write_at (newbuf, tsize + rosize, tmp, dsize);
	R_FREE (tmp);

	/* Load unpacked binary */
	const ut8 *tmpbuf = r_buf_data (newbuf, &total_size);
	r_io_write_at (rbin->iob.io, ba, tmpbuf, total_size);
	ut32 modoff = readLE32 (newbuf, NSO_OFFSET_MODMEMOFF);
	RBinNXOObj *bin = nso_new ();
	eprintf ("MOD Offset = 0x%"PFMT64x"\n", (ut64)modoff);
	parseMod (newbuf, bin, modoff, ba);
	r_buf_free (newbuf);
	*bin_obj = bin;
	return true;
fail:
	free (tmp);
	r_buf_free (newbuf);
	*bin_obj = NULL;
	return false;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	r_return_val_if_fail (bf && buf, NULL);
	const ut64 la = bf->loadaddr;
	ut64 sz = 0;
	const ut8 *bytes = r_buf_data (buf, &sz);
	return load_bytes (bf, bin_obj, bytes, sz, la, bf->sdb);
}

static RBinAddr *binsym(RBinFile *bf, int type) {
	return NULL; // TODO
}

static RList *entries(RBinFile *bf) {
	RList *ret;
	RBinAddr *ptr = NULL;
	RBuffer *b = bf->buf;
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;
	if ((ptr = R_NEW0 (RBinAddr))) {
		ptr->paddr = readLE32 (b, NSO_OFF (text_memoffset));
		ptr->vaddr = readLE32 (b, NSO_OFF (text_loc)) + baddr (bf);
		r_list_append (ret, ptr);
	}
	return ret;
}

static Sdb *get_sdb(RBinFile *bf) {
	Sdb *kv = sdb_new0 ();
	sdb_num_set (kv, "nso_start.offset", 0, 0);
	sdb_num_set (kv, "nso_start.size", 16, 0);
	sdb_set (kv, "nso_start.format", "xxq unused mod_memoffset padding", 0);
	sdb_num_set (kv, "nso_header.offset", 0, 0);
	sdb_num_set (kv, "nso_header.size", 0x40, 0);
	sdb_set (kv, "nso_header.format", "xxxxxxxxxxxx magic unk size unk2 text_offset text_size ro_offset ro_size data_offset data_size bss_size unk3", 0);
	sdb_ns_set (bf->sdb, "info", kv);
	return kv;
}

static RList *sections(RBinFile *bf) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	RBuffer *b = bf->buf;
	if (!bf->o->info) {
		return NULL;
	}
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;

	ut64 ba = baddr (bf);

	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("header");
	ptr->size = readLE32 (b, NSO_OFF (text_memoffset));
	ptr->vsize = readLE32 (b, NSO_OFF (text_memoffset));
	ptr->paddr = 0;
	ptr->vaddr = 0;
	ptr->perm = R_PERM_R;
	ptr->add = false;
	r_list_append (ret, ptr);

	// add text segment
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("text");
	ptr->vsize = readLE32 (b, NSO_OFF (text_size));
	ptr->size = ptr->vsize;
	ptr->paddr = readLE32 (b, NSO_OFF (text_memoffset));
	ptr->vaddr = readLE32 (b, NSO_OFF (text_loc)) + ba;
	ptr->perm = R_PERM_RX;	// r-x
	ptr->add = true;
	r_list_append (ret, ptr);

	// add ro segment
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("ro");
	ptr->vsize = readLE32 (b, NSO_OFF (ro_size));
	ptr->size = ptr->vsize;
	ptr->paddr = readLE32 (b, NSO_OFF (ro_memoffset));
	ptr->vaddr = readLE32 (b, NSO_OFF (ro_loc)) + ba;
	ptr->perm = R_PERM_R;	// r--
	ptr->add = true;
	r_list_append (ret, ptr);

	// add data segment
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("data");
	ptr->vsize = readLE32 (b, NSO_OFF (data_size));
	ptr->size = ptr->vsize;
	ptr->paddr = readLE32 (b, NSO_OFF (data_memoffset));
	ptr->vaddr = readLE32 (b, NSO_OFF (data_loc)) + ba;
	ptr->perm = R_PERM_RW;
	ptr->add = true;
	eprintf ("BSS Size 0x%08"PFMT64x "\n", (ut64)
		readLE32 (bf->buf, NSO_OFF (bss_size)));
	r_list_append (ret, ptr);
	return ret;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ut8 magic[4];
	if (r_buf_read_at (bf->buf, NSO_OFF (magic), magic, sizeof (magic)) != sizeof (magic)) {
		free (ret);
		return NULL;
	}

	const char *ft = fileType (magic);
	if (!ft) {
		ft = "nso";
	}
	ret->file = strdup (bf->file);
	ret->rclass = strdup (ft);
	ret->os = strdup ("switch");
	ret->arch = strdup ("arm");
	ret->machine = strdup ("Nintendo Switch");
	ret->subsystem = strdup (ft);
	ret->bclass = strdup ("program");
	ret->type = strdup ("EXEC (executable file)");
	ret->bits = 64;
	ret->has_va = true;
	ret->has_lit = true;
	ret->big_endian = false;
	ret->dbg_info = 0;
	return ret;
}

#if !R_BIN_NSO

RBinPlugin r_bin_plugin_nso = {
	.name = "nso",
	.desc = "Nintendo Switch NSO0 binaries",
	.license = "MIT",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.get_sdb = &get_sdb,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_nso,
	.version = R2_VERSION
};
#endif
#endif
