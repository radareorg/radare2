/* radare - LGPL - Copyright 2009-2022 - pancake, nibble, Adam Pridgen <dso@rice.edu || adam.pridgen@thecoverofnight.com> */

#define R_LOG_ORIGIN "bin.java"

#include <r_bin.h>
#include "../../shlr/java/class.h"
#include "../../shlr/java/code.h"

#define IFDBG_BIN_JAVA if (0)

// R2_590 XXX we need to refactor rbin to get rid of this
static R_TH_LOCAL Sdb *DB = NULL;

static void add_bin_obj_to_sdb(RBinJavaObj *bin);
static int add_sdb_bin_obj(const char *key, RBinJavaObj *bin_obj);

static int init(void *user) {
	R_LOG_DEBUG ("Calling plugin init = %d", DB? 1: 0);
	if (!DB) {
		R_LOG_DEBUG ("plugin DB beeing initted");
		DB = sdb_new ("bin.java", NULL, 0);
	} else {
		R_LOG_DEBUG ("plugin DB already initted");
	}
	return 0;
}

static int fini(void *user) {
	R_LOG_DEBUG ("Calling plugin fini = %d", DB? 1: 0);
	if (!DB) {
		IFDBG_BIN_JAVA eprintf ("plugin DB already uninited.\n");
	} else {
		IFDBG_BIN_JAVA eprintf ("plugin DB beeing uninited.\n");
		sdb_free (DB);
		DB = NULL;
	}
	return 0;
}

static int add_sdb_bin_obj(const char *key, RBinJavaObj *bin_obj) {
	int result = false;
	char *addr, value[SDB_NUM_BUFSZ] = {
		0
	};
	addr = sdb_itoa ((ut64) (size_t) bin_obj, 16, value, sizeof (value));
	if (key && bin_obj && DB) {
		IFDBG_BIN_JAVA eprintf("Adding %s:%s to the bin_objs db\n", key, addr);
		sdb_set (DB, key, addr, 0);
		result = true;
	}
	return result;
}

static void add_bin_obj_to_sdb(RBinJavaObj *bin) {
	if (!bin) {
		return;
	}
	char *jvcname = r_bin_java_build_obj_key (bin);
	add_sdb_bin_obj (jvcname, bin);
	bin->AllJavaBinObjs = DB;
	free (jvcname);
}

static Sdb *get_sdb(RBinFile *bf) {
	RBinObject *o = bf->bo;
	struct r_bin_java_obj_t *bin;
	if (!o) {
		return NULL;
	}
	bin = (struct r_bin_java_obj_t *) o->bin_obj;
	if (bin->kv) {
		return bin->kv;
	}
	return NULL;
}

static bool load_buffer(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
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
	sdb_free (DB);
	DB = NULL;
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
	ret->lang = (jo && jo->lang) ? jo->lang : "java";
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

static bool check_buffer(RBinFile *bf, RBuffer *b) {
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

static R_BORROW RList *lines(RBinFile *bf) {
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
	.name = "java",
	.desc = "java bin plugin",
	.license = "LGPL3",
	.init = init,
	.fini = fini,
	.get_sdb = &get_sdb,
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
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
