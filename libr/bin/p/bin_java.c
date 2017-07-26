/* radare - LGPL - Copyright 2009-2017 - pancake, nibble, Adam Pridgen <dso@rice.edu || adam.pridgen@thecoverofnight.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#include "../../shlr/java/class.h"
#include "../../shlr/java/code.h"

#define IFDBG_BIN_JAVA if (0)

static Sdb *DB = NULL;
static void add_bin_obj_to_sdb(RBinJavaObj *bin);
static int add_sdb_bin_obj(const char *key, RBinJavaObj *bin_obj);

static int init(void *user) {
	IFDBG_BIN_JAVA eprintf("Calling plugin init = %d.\n", DB? 1: 0);
	if (!DB) {
		IFDBG_BIN_JAVA eprintf("plugin DB beeing initted.\n");
		DB = sdb_new ("bin.java", NULL, 0);
	} else {
		IFDBG_BIN_JAVA eprintf("plugin DB already initted.\n");
	}
	return 0;
}

static int fini(void *user) {
	IFDBG_BIN_JAVA eprintf("Calling plugin fini = %d.\n", DB? 1: 0);
	if (!DB) {
		IFDBG_BIN_JAVA eprintf("plugin DB already uninited.\n");
	} else {
		IFDBG_BIN_JAVA eprintf("plugin DB beeing uninited.\n");
		sdb_free (DB);
		DB = NULL;
	}
	return 0;
}

static int add_sdb_bin_obj(const char *key, RBinJavaObj *bin_obj) {
	int result = false;
	char *addr, value[1024] = {
		0
	};
	addr = sdb_itoa ((ut64) (size_t) bin_obj, value, 16);
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
	RBinObject *o = bf->o;
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

static void *load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	struct r_bin_java_obj_t *bin_obj = NULL;
	RBuffer *tbuf = NULL;
	void *res = NULL;
	if (!buf || sz == 0 || sz == UT64_MAX) {
		return NULL;
	}
	tbuf = r_buf_new ();
	r_buf_set_bytes (tbuf, buf, sz);
	res = bin_obj = r_bin_java_new_buf (tbuf, loadaddr, sdb);
	add_bin_obj_to_sdb (bin_obj);
	if (arch && arch->file) {
		bin_obj->file = strdup (arch->file);
	}
	r_buf_free (tbuf);
	return res;
}

static bool load(RBinFile *arch) {
	int result = false;
	const ut8 *bytes = arch? r_buf_buffer (arch->buf): NULL;
	ut64 sz = arch? r_buf_size (arch->buf): 0;
	struct r_bin_java_obj_t *bin_obj = NULL;

	if (!arch || !arch->o) {
		return false;
	}

	bin_obj = load_bytes (arch, bytes, sz, arch->o->loadaddr, arch->sdb);

	if (bin_obj) {
		if (!arch->o->kv) {
			arch->o->kv = bin_obj->kv;
		}
		arch->o->bin_obj = bin_obj;
		bin_obj->AllJavaBinObjs = DB;
		// XXX - /\ this is a hack, but (one way but) necessary to get access to
		// the object addrs from anal. If only global variables are used,
		// they get "lost" somehow after they are initialized and go out of
		// scope.
		//
		// There are several points of indirection, but here is the gist:
		// 1) RAnal->(through RBinBind) RBin->RBinJavaObj->DB
		//
		// The purpose is to ensure that information about a give class file
		// can be grabbed at any time from RAnal.  This was tried with global
		// variables, but failed when attempting to access the DB
		// in the class.c scope.  Once DB  was moved here, it is initialized
		// once here and assigned to each of the other RBinJavaObjs.
		//
		// Now, the RAnal component of radare can get to each of the
		// RBinJavaObjs for analysing functions and dependencies using an Sdb.
		add_bin_obj_to_sdb (bin_obj);
		if (arch->file) {
			bin_obj->file = strdup (arch->file);
		}
		result = true;
	}
	return result;
}

static int destroy(RBinFile *arch) {
	r_bin_java_free ((struct r_bin_java_obj_t *) arch->o->bin_obj);
	sdb_free (DB);
	DB = NULL;
	return true;
}

static RList *entries(RBinFile *arch) {
	return r_bin_java_get_entrypoints (arch->o->bin_obj);
}

static ut64 baddr(RBinFile *arch) {
	return 0;
}

static RList *classes(RBinFile *arch) {
	return r_bin_java_get_classes ((struct r_bin_java_obj_t *) arch->o->bin_obj);
}

static RList *symbols(RBinFile *arch) {
	return r_bin_java_get_symbols ((struct r_bin_java_obj_t *) arch->o->bin_obj);
}

static RList *strings(RBinFile *arch) {
	return r_bin_java_get_strings ((struct r_bin_java_obj_t *) arch->o->bin_obj);
}

static RBinInfo *info(RBinFile *arch) {
	RBinJavaObj *jo = arch->o->bin_obj;
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->lang = (jo && jo->lang) ? jo->lang : "java";
	ret->file = strdup (arch->file);
	ret->type = strdup ("JAVA CLASS");
	ret->bclass = r_bin_java_get_version (arch->o->bin_obj);
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

static bool check_bytes(const ut8 *buf, ut64 length) {
	bool ret = false;
	int off, version = 0;
	if (buf && length > 32 && !memcmp (buf, "\xca\xfe\xba\xbe", 4)) {
		// XXX not sure about endianness here
		memcpy (&off, buf + 4 * sizeof (int), sizeof (int));
		version = buf[6] | (buf[7] << 8);
		if (version > 1024) {
			// XXX is this correct in all cases? opposite of prev?
			r_mem_swapendian ((ut8 *) &off, (ut8 *) &off, sizeof (int));
			ret = true;
		}
	}
	return ret;
}

static int retdemangle(const char *str) {
	return R_BIN_NM_JAVA;
}

static RBinAddr *binsym(RBinFile *arch, int sym) {
	return r_bin_java_get_entrypoint (arch->o->bin_obj, sym);
}

static RList *lines(RBinFile *arch) {
	return NULL;
#if 0
	char *file = arch->file? strdup (arch->file): strdup ("");
	RList *list = r_list_newf (free);
	// XXX the owner of this list should be the plugin, so we are leaking here
	file = r_str_replace (file, ".class", ".java", 0);
	/*
	   int i;
	   RBinJavaObj *b = arch->o->bin_obj;
	   for (i=0; i<b->lines.count; i++) {
	        RBinDwarfRow *row = R_NEW0(RBinDwarfRow);
	        r_bin_dwarf_line_new (row, b->lines.addr[i], file, b->lines.line[i]);
	        r_list_append (list, row);
	   }*/
	free (file);
	return list;
#endif
}

static RList *sections(RBinFile *arch) {
	return r_bin_java_get_sections (arch->o->bin_obj);
}

static RList *imports(RBinFile *arch) {
	return r_bin_java_get_imports (arch->o->bin_obj);
}

static RList *fields(RBinFile *arch) {
	return NULL;// r_bin_java_get_fields (arch->o->bin_obj);
}

static RList *libs(RBinFile *arch) {
	return r_bin_java_get_lib_names (arch->o->bin_obj);
}

RBinPlugin r_bin_plugin_java = {
	.name = "java",
	.desc = "java bin plugin",
	.license = "LGPL3",
	.init = init,
	.fini = fini,
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.binsym = binsym,
	.entries = &entries,
	.sections = sections,
	.symbols = symbols,
	.imports = &imports,
	.strings = &strings,
	.info = &info,
	.fields = fields,
	.libs = libs,
	.lines = &lines,
	.classes = classes,
	.demangle_type = retdemangle,
	.minstrlen = 3,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_java,
	.version = R2_VERSION
};
#endif
