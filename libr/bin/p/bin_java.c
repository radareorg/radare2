/* radare - LGPL - Copyright 2009-2014 - pancake, nibble, Adam Pridgen <dso@rice.edu || adam.pridgen@thecoverofnight.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#include "../../shlr/java/class.h"
#include "../../shlr/java/code.h"

#define IFDBG_BIN_JAVA  if(0)

static Sdb *DB = NULL;

static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);
static void add_bin_obj_to_sdb(RBinJavaObj *bin);
static int add_sdb_bin_obj(const char *key, RBinJavaObj *bin_obj);

static int init(void *user) {
	IFDBG_BIN_JAVA eprintf ("Calling plugin init = %d.\n", DB?1:0);
	if (!DB) {
		IFDBG_BIN_JAVA eprintf ("plugin DB beeing initted.\n");
		DB = sdb_new ("bin.java", NULL, 0);
	} else {
		IFDBG_BIN_JAVA eprintf ("plugin DB already initted.\n");
	}
	return 0;
}

static int add_sdb_bin_obj(const char *key, RBinJavaObj *bin_obj) {
	int result = R_FALSE;
	char *addr, value[1024] = {0};
	addr = sdb_itoa ((ut64)(size_t)bin_obj,  value, 16);
	if (key && bin_obj && DB) {
		IFDBG_BIN_JAVA eprintf ("Adding %s:%s to the bin_objs db\n", key, addr);
		sdb_set (DB, key, addr, 0);
		result = R_TRUE;
	}
	return result;
}

static void add_bin_obj_to_sdb(RBinJavaObj *bin) {
	char * jvcname = NULL;
	if (bin) {
		jvcname = r_bin_java_build_obj_key (bin);
		add_sdb_bin_obj (jvcname, bin);
		bin->AllJavaBinObjs = DB;
		free (jvcname);
	}
}

static Sdb* get_sdb (RBinObject *o) {
	if (!o) return NULL;
	struct r_bin_java_obj_t *bin = (struct r_bin_java_obj_t *) o->bin_obj;
	if (bin->kv) return bin->kv;
	return NULL;
}

static void * load_bytes(const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	void *res = NULL;
	RBuffer *tbuf = NULL;
	struct r_bin_java_obj_t* bin_obj = NULL;
	if (!buf || sz == 0 || sz == UT64_MAX) return NULL;
	tbuf = r_buf_new();
	r_buf_set_bytes (tbuf, buf, sz);
	res = bin_obj = r_bin_java_new_buf (tbuf, loadaddr, sdb);
	add_bin_obj_to_sdb (bin_obj);
	r_buf_free (tbuf);
	return res;
}

static int load(RBinFile *arch) {
	int result = R_FALSE;
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
 	struct r_bin_java_obj_t* bin_obj = NULL;

 	if (!arch || !arch->o) return R_FALSE;

	bin_obj = load_bytes (bytes, sz, arch->o->loadaddr, arch->sdb);

	if (bin_obj) {
		if (!arch->o->kv) arch->o->kv = bin_obj->kv;
		arch->o->bin_obj = bin_obj;
		bin_obj->AllJavaBinObjs = DB;
		// XXX - /\ this is a hack, but (one way but) necessary to get access to
		// the object addrs from anal. If only global variables are used,
		// they get "lost" somehow after they are initialized and go out of
		// scope.
		//
		// There are several points of indirection, but here is the gist:
		//	  1) RAnal->(through RBinBind) RBin->RBinJavaObj->DB
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
		if (arch->file)
			bin_obj->file = strdup (arch->file);
		result = R_TRUE;
	}
	return result;
}

static int destroy(RBinFile *arch) {
	r_bin_java_free ((struct r_bin_java_obj_t*)arch->o->bin_obj);
	sdb_free (DB);
	DB = NULL;
	return R_TRUE;
}

static RList* entries(RBinFile *arch) {
	return r_bin_java_get_entrypoints (arch->o->bin_obj);
}

static ut64 baddr(RBinFile *arch) {
	return 0;
}

static RList* classes(RBinFile *arch) {
	return r_bin_java_get_classes((struct r_bin_java_obj_t*)arch->o->bin_obj);
}

static RList* symbols(RBinFile *arch) {
	return r_bin_java_get_symbols ((struct r_bin_java_obj_t*)arch->o->bin_obj);
}

static RList* strings(RBinFile *arch) {
	return r_bin_java_get_strings((struct r_bin_java_obj_t*)arch->o->bin_obj);
}

static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = NULL;
	char *version;

	if (!(ret = R_NEW0 (RBinInfo)))
		return NULL;
	ret->lang = "java";
	strncpy (ret->file, arch->file, R_BIN_SIZEOF_STRINGS-1);
	strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS-1);
	strncpy (ret->type, "JAVA CLASS", R_BIN_SIZEOF_STRINGS-1);
	version = r_bin_java_get_version (arch->o->bin_obj);
	strncpy (ret->bclass, version, R_BIN_SIZEOF_STRINGS-1);
	free (version);
	ret->has_va = 0;
	strncpy (ret->rclass, "class", R_BIN_SIZEOF_STRINGS-1);
	strncpy (ret->os, "any", R_BIN_SIZEOF_STRINGS-1);
	strncpy (ret->subsystem, "any", R_BIN_SIZEOF_STRINGS-1);
	strncpy (ret->machine, "java", R_BIN_SIZEOF_STRINGS-1);
	strncpy (ret->arch, "java", R_BIN_SIZEOF_STRINGS-1);
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 4 | 8; /* LineNums | Syms */
	return ret;
}

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);

}

static int check_bytes(const ut8 *buf, ut64 length) {
	int off, ret = R_FALSE;
	int version = 0;

	if (buf && length>10)
	if (!memcmp (buf, "\xca\xfe\xba\xbe", 4)) {
		memcpy (&off, buf+4*sizeof(int), sizeof(int));
		version = buf[6] | (buf[7] <<8);
		if (version>1024) {
			r_mem_copyendian ((ut8*)&off,
				(ut8*)&off, sizeof(int),
				!LIL_ENDIAN);
			ret = R_TRUE;
		}
	}
	return ret;
}

static int retdemangle(const char *str) {
	return R_BIN_NM_JAVA;
}

static RBinAddr* binsym(RBinFile *arch, int sym) {
	return r_bin_java_get_entrypoint(arch->o->bin_obj, sym);
}

static RList* lines(RBinFile *arch) {
	char *file = arch->file ? strdup (arch->file) : strdup ("");
	RList *list = r_list_newf (free);
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
}

static RList* sections(RBinFile *arch) {
	return r_bin_java_get_sections (arch->o->bin_obj);
}

static RList* imports(RBinFile *arch) {
	return r_bin_java_get_imports (arch->o->bin_obj);
}

static RList* fields(RBinFile *arch) {
	return NULL;//r_bin_java_get_fields (arch->o->bin_obj);
}

static RList* libs(RBinFile *arch) {
	return r_bin_java_get_lib_names (arch->o->bin_obj);
}

RBinPlugin r_bin_plugin_java = {
	.name = "java",
	.desc = "java bin plugin",
	.license = "LGPL3",
	.init = init,
	.fini = NULL,
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check = &check,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.boffset = NULL,
	.binsym = binsym,
	.entries = &entries,
	.sections = sections,
	.symbols = symbols,
	.imports = &imports,
	.strings = &strings,
	.info = &info,
	.fields = fields,
	.libs = libs,
	.relocs = NULL,
	.dbginfo = NULL,
	.lines = &lines,
	.write = NULL,
	.classes = classes,
	.demangle_type = retdemangle,
	.minstrlen = 3,
	.user = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_java
};
#endif
