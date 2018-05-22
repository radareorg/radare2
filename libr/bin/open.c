/* radare2 - LGPL - Copyright 2018 - pancake */

#include <r_bin.h>

R_API RBinOptions *r_bin_options_new (ut64 offset, ut64 baddr, int rawstr) {
	RBinOptions *bo = R_NEW0 (RBinOptions);
	if (bo) {
		bo->offset = offset;
		bo->baseaddr = baddr;
		bo->rawstr = rawstr;
	}
	return bo;
}

R_API void r_bin_options_free(RBinOptions *bo) {
	free (bo->name);
	free (bo);
}

R_API int r_bin_open(RBin *bin, const char *filename, RBinOptions *bo) {
	ut64 baddr = 0LL;
	int iofd = -1, rawstr = 0;
	if (bo) {
		baddr = bo->baseaddr;
		iofd = bo->iofd;
		rawstr = bo->rawstr;
	}
	if (r_bin_load (bin, filename, baddr, 0, 0, iofd, rawstr)) {
		int id = bin->cur->id;
		r_id_storage_set (bin->ids, bin->cur, id);
		return id;
	}
	return -1;
}

R_API RBinFile *r_bin_get_file (RBin *bin, int bd) {
	return r_id_storage_take (bin->ids, bd);
}

R_API bool r_bin_close(RBin *bin, int bd) {
	RBinFile *bf = r_bin_get_file (bin, bd);
	if (bf) {
		// file_free removes the fd already.. maybe its unnecessary
		r_id_storage_delete (bin->ids, bd);
		r_bin_file_free (bf);
	}
	return false;
}

#if 0
// usage example

var bin = new RBin ();
int fd = bin.open("/bin/ls", null);
var binfile = bin.get_file(fd);
binfile.symbols.foreach(sym => {
  print(sym.name);
});
bin.close(fd);
// binfile is invalid here

int bd = bin->cur;
r_list_foreach (r_bin_list (bin, bd, R_BIN_REQ_SYMBOLS), iter, sym) {
	eprintf ("Symbol: %s\n", sym->name);
}

bool cb(void *user, void *data) {
}
r_bin_foreach (bin, bd, R_BIN_REQ_SYMBOLS, cb, user);
#if 0
// TODO: rename to r_bin_cmd() to match r2 commands ?
// TODO: use this api in r2
// TODO: add queryf api (or cmdf)
R_API bool r_bin_query(RBin *bin, const char *query) {
	bool ret = false;
	char *q = strdup (query);
	const char *at = strchr (q, '@');
	if (at) {
		*at++ = 0;
	}
	if (!strcmp (q, "s")) {
		// symbols
		ret = true;
	} else {
		eprintf ("Unknown command\n");
	}
	return ret;
	// r_bin_query (bin, "o@0x8048080"); // return symbol at given address
	// r_bin_query (bin, "s@0x8048080"); // return symbol at given address
	// r_bin_query (bin, "z/str/"); // return list subset of strings matching
	// r_bin_query (bin, "i\"printf\""); // imports
}
#endif

#endif
