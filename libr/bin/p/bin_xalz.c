/* radare2 - LGPL - Copyright 2022 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <r_io.h>
#include <r_cons.h>
#define R_BIN_PE64 1
#include "../i/private.h"
#include "pe/pe.h"

static bool check_buffer(RBinFile *bf, RBuffer *b) {
	if (r_buf_size (b) >= 0x20) {
		ut8 magic[4];
		if (r_buf_read_at (b, 0, magic, sizeof (magic)) != 4) {
			return false;
		}
		return !memcmp (magic, "XALZ", 4);
	}
	return false;
}

static bool load_bytes(RBinFile *bf, void **bin_obj, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	if (sz < 32) {
		return false;
	}
	// ut32 off = r_buf_read_le32_at (bf->buf, 4); // unnecessary
	ut32 osz = r_buf_read_le32_at (bf->buf, 8);
	int consumed = 0;
	int outsize = 0;
	ut8 *obuf = r_inflate_lz4 ((const ut8*)buf + 0xc, (uint32_t) sz - 0xc, &consumed, &outsize);
	if (obuf) {
		if (outsize != osz) {
			eprintf ("Unexpected decompression size\n");
			// something wrong happend
		}
		RBuffer *ob = bf->buf;
		RBuffer *nb = r_buf_new_with_pointers (obuf, outsize, false);
		bf->buf = nb;
		bf->o = r_bin_object_new (bf, &r_bin_plugin_pe, 0,0,0,0);
		RBinPlugin *pe = &r_bin_plugin_pe;
		if (!pe->load_buffer (bf, bin_obj, nb, loadaddr, sdb)) {
			free (obuf);
			r_buf_free (nb);
			bf->buf = ob;
			return false;
		}
		pe->info (bf);
		struct Pe64_r_bin_pe_obj_t *res = *bin_obj;
		// info is not suposed to be set in here, but meh :D see bobj.c and grep for '"info"', same for bin_pe.inc
		sdb_ns_set (sdb, "info", res->kv);
		// hack the pointers in a very ugly way
		// memcpy (&r_bin_plugin_xalz, &r_bin_plugin_pe, sizeof (RBinPlugin));
		r_buf_free (ob);
		return true;
	}
	eprintf ("Decompression failed\n");
	return false;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	r_return_val_if_fail (bf && buf, false);
	const ut64 la = bf->loadaddr;
	ut64 sz = 0;
	const ut8 *bytes = r_buf_data (buf, &sz);
	return load_bytes (bf, bin_obj, bytes, sz, la, bf->sdb);
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (ret) {
		ret->file = strdup (bf->file);
		ret->rclass = strdup ("pe"); // XALZ"
		ret->os = strdup ("xamarin");
		ret->arch = strdup ("dotnet");
		ret->machine = strdup (".NET");
		ret->subsystem = strdup ("xamarin");
		ret->bclass = strdup ("program");
		ret->type = strdup ("LIBRARY");
		ret->bits = 64;
		ret->has_va = true;
		ret->has_lit = true;
		ret->big_endian = false;
		ret->dbg_info = false;
	}
	return ret;
}

// whats returned here goes into bin/cur/info/
static Sdb* get_sdb(RBinFile *bf) {
	RBinObject *o = bf? bf->o: NULL;
	return o? o->kv: NULL;
}

#if !R_BIN_XALZ

RBinPlugin r_bin_plugin_xalz = {
	.name = "xalz",
	.desc = "Xamarin LZ4 Compressed Library",
	.license = "MIT",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.get_sdb = &get_sdb,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_xalz,
	.version = R2_VERSION
};
#endif
#endif
