/* radare - LGPL - Copyright 2009-2024 - pancake, nibble, dso */

#define R_LOG_ORIGIN "bin.java"

#include <r_bin.h>
#include "../../shlr/java/class.h"
#include "../../shlr/java/code.h"

static bool add_sdb_bin_obj(const char *key, RBinJavaObj *bin_obj) {
	char value[SDB_NUM_BUFSZ] = {0};
	char *addr = sdb_itoa ((ut64) (size_t) bin_obj, 16, value, sizeof (value));
	if (key && bin_obj && bin_obj->kv) {
		R_LOG_DEBUG ("Adding %s:%s to the bin_objs db", key, addr);
		sdb_set (bin_obj->kv, key, addr, 0);
		return true;
	}
	return false;
}

static void add_bin_obj_to_sdb(RBinJavaObj *bj) {
	R_RETURN_IF_FAIL (bj);
	char *jvcname = r_bin_java_build_obj_key (bj);
	add_sdb_bin_obj (jvcname, bj);
	bj->AllJavaBinObjs = bj->kv; // XXX that was a global.. so this must be inside bin->sdb namespace
	free (jvcname);
}

static Sdb *get_sdb(RBinFile *bf) {
	struct r_bin_java_obj_t *bin = R_UNWRAP3 (bf, bo, bin_obj);
	return bin? bin->kv: NULL;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	RBuffer *tbuf = r_buf_ref (buf);
	struct r_bin_java_obj_t *tbo = r_bin_java_new_buf (tbuf, loadaddr, bf->sdb);
	if (tbo) {
		bf->bo->bin_obj = tbo;
		add_bin_obj_to_sdb (tbo);
		if (bf && bf->file) {
			tbo->file = strdup (bf->file);
		}
		r_buf_free (tbuf);
		return true;
	}
	return false;
}

static void destroy(RBinFile *bf) {
	r_bin_java_free ((struct r_bin_java_obj_t *) bf->bo->bin_obj);
}

static RList *entries(RBinFile *bf) {
	return r_bin_java_get_entrypoints (bf->bo->bin_obj);
}

static RList *classes(RBinFile *bf) {
	return r_bin_java_get_classes ((struct r_bin_java_obj_t *) bf->bo->bin_obj);
}

static RList *symbols(RBinFile *bf) {
	return r_bin_java_get_symbols ((struct r_bin_java_obj_t *) bf->bo->bin_obj);
}

static RList *strings(RBinFile *bf) {
	return r_bin_java_get_strings ((struct r_bin_java_obj_t *) bf->bo->bin_obj);
}

static RBinInfo *info(RBinFile *bf) {
	RBinJavaObj *jo = bf->bo->bin_obj;
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->lang = jo ? jo->lang : "java";
	ret->file = strdup (bf->file);
	ret->type = strdup ("JAVA CLASS");
	ret->bclass = r_bin_java_get_version (bf->bo->bin_obj);
	ret->has_va = 0;
	// ret->has_lit = true;
	ret->rclass = strdup ("class");
	ret->os = strdup ("any");
	ret->subsystem = strdup ("any");
	ret->machine = strdup ("jvm");
	ret->arch = strdup ("java");
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 4 | 8; /* LineNums | Syms */
	return ret;
}

static bool check(RBinFile *bf, RBuffer *b) {
	if (r_buf_size (b) > 32) {
		ut8 buf[4];
		r_buf_read_at (b, 0, buf, sizeof (buf));
		if (!memcmp (buf, "\xca\xfe\xba\xbe", 4)) {
			int off = r_buf_read_be32_at (b, 4 * sizeof (int));
			int version = r_buf_read_be16_at (b, 6);
			if (off > 0 && version < 1024) {
				return true;
			}
		}
	}
	return false;
}

static int retdemangle(const char *str) {
	return R_BIN_LANG_JAVA;
}

static RBinAddr *binsym(RBinFile *bf, int sym) {
	return r_bin_java_get_entrypoint (bf->bo->bin_obj, sym);
}

static R_UNOWNED RList *lines(RBinFile *bf) {
	return NULL;
#if 0
	char *file = bf->file? strdup (bf->file): strdup ("");
	RList *list = r_list_newf (free);
	// XXX the owner of this list should be the plugin, so we are leaking here
	file = r_str_replace (file, ".class", ".java", 0);
	/*
	   int i;
	   RBinJavaObj *b = bf->bo->bin_obj;
	   for (i = 0; i < b->lines.count; i++) {
	        RBinDwarfRow *row = R_NEW0 (RBinDwarfRow);
	        r_bin_dwarf_line_new (row, b->lines.addr[i], file, b->lines.line[i]);
	        r_list_append (list, row);
	   }*/
	free (file);
	return list;
#endif
}

static RList *sections(RBinFile *bf) {
	return r_bin_java_get_sections (bf->bo->bin_obj);
}

static RList *imports(RBinFile *bf) {
	return r_bin_java_get_imports (bf->bo->bin_obj);
}

static RList *libs(RBinFile *bf) {
	return r_bin_java_get_lib_names (bf->bo->bin_obj);
}

RBinPlugin r_bin_plugin_java = {
	.meta = {
		.name = "java",
		.author = "pancake",
		.desc = "Java Cafebabe Class",
		.license = "LGPL-3.0-only",
	},
	.get_sdb = &get_sdb, // XXX we should remove this imho
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.binsym = binsym,
	.entries = &entries,
	.sections = sections,
	.symbols = symbols,
	.imports = &imports,
	.strings = &strings,
	.info = &info,
	.libs = libs,
	.lines = &lines,
	.classes = classes,
	.demangle_type = retdemangle,
	.minstrlen = 3,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_java,
	.version = R2_VERSION
};
#endif
