
/* radare - LGPL - Copyright 2009-2014 - pancake, nibble, Adam Pridgen <dso@rice.edu || adam.pridgen@thecoverofnight.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "../../shlr/java/class.h"

#define IFDBG  if(0)

static Sdb *BIN_OBJS_ADDRS = NULL;

static void add_bin_obj_to_sdb(RBinJavaObj *bin);
static int add_sdb_bin_obj(const char *key, RBinJavaObj *bin_obj);

static  int init(void *user) {
	IFDBG eprintf ("Calling plugin init = %d.\n", BIN_OBJS_ADDRS?1:0);
	if (!BIN_OBJS_ADDRS) {
		IFDBG eprintf ("plugin BIN_OBJS_ADDRS beeing initted.\n");
		BIN_OBJS_ADDRS = sdb_new (NULL, 0);
	} else {
		IFDBG eprintf ("plugin BIN_OBJS_ADDRS already initted.\n");
	}
	return 0;
}

static int add_sdb_bin_obj(const char *key, RBinJavaObj *bin_obj) {
	int result = R_FALSE;
	char value[1024] = {0};
	sdb_itoa ((ut64)(size_t)bin_obj,  value);
	if (key && bin_obj && BIN_OBJS_ADDRS) {
		IFDBG eprintf ("Adding %s:%s to the bin_objs db\n", key, value);
		sdb_set (BIN_OBJS_ADDRS, key, value, 0);
		result = R_TRUE;
	}
	return result;
}

static void add_bin_obj_to_sdb(RBinJavaObj *bin) {
	char * jvcname = NULL;
	if (bin) {
		jvcname = r_bin_java_build_obj_key (bin);
		add_sdb_bin_obj (jvcname, bin);
		free (jvcname);
	}
}

static int load(RBinArch *arch) {
	struct r_bin_java_obj_t* bin_obj = NULL;
	int result = R_FALSE;
	bin_obj = r_bin_java_new_buf (arch->buf, arch->o->loadaddr, arch->o->kv);
	if (bin_obj) {
		if (arch->o->kv == NULL) arch->o->kv = bin_obj->kv;
		arch->o->bin_obj = bin_obj;
		bin_obj->AllJavaBinObjs = BIN_OBJS_ADDRS;
		// XXX - /\ this is a hack, but (one way but) necessary to get access to
		// the object addrs from anal. If only global variables are used,
		// they get "lost" somehow after they are initialized and go out of
		// scope.
		//
		// There are several points of indirection, but here is the gist:
		//	  1) RAnal->(through RBinBind) RBin->RBinJavaObj->BIN_OBJS_ADDRS
		//
		// The purpose is to ensure that information about a give class file
		// can be grabbed at any time from RAnal.  This was tried with global
		// variables, but failed when attempting to access the BIN_OBJS_ADDRS
		// in the class.c scope.  Once BIN_OBJS_ADDRS  was moved here, it is initialized
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

static int destroy(RBinArch *arch) {
	r_bin_java_free ((struct r_bin_java_obj_t*)arch->o->bin_obj);
	sdb_free (BIN_OBJS_ADDRS);
	BIN_OBJS_ADDRS = NULL;
	return R_TRUE;
}

static RList* entries(RBinArch *arch) {
	return r_bin_java_get_entrypoints (arch->o->bin_obj);
}

static ut64 baddr(RBinArch *arch) {
	return 0;
}

static RList* classes(RBinArch *arch) {
	return r_bin_java_get_classes((struct r_bin_java_obj_t*)arch->o->bin_obj);
}

static RList* symbols(RBinArch *arch) {
	return r_bin_java_get_symbols ((struct r_bin_java_obj_t*)arch->o->bin_obj);
}

static RList* strings(RBinArch *arch) {
	return r_bin_java_get_strings((struct r_bin_java_obj_t*)arch->o->bin_obj);
}

static RBinInfo* info(RBinArch *arch) {
	RBinInfo *ret = NULL;
	char *version;

	if (!(ret = R_NEW (RBinInfo)))
		return NULL;
	memset (ret, '\0', sizeof (RBinInfo));
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
	strncpy (ret->machine, "Java VM", R_BIN_SIZEOF_STRINGS-1);
	strncpy (ret->arch, "java", R_BIN_SIZEOF_STRINGS-1);
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 4 | 8; /* LineNums | Syms */
	return ret;
}

static int check(RBinArch *arch) {
	int off, ret = R_FALSE;

	if (arch && arch->buf && arch->buf->buf && arch->buf->length>10)
	if (!memcmp (arch->buf->buf, "\xca\xfe\xba\xbe", 4)) {
		memcpy (&off, arch->buf->buf+4*sizeof(int), sizeof(int));
		r_mem_copyendian ((ut8*)&off, (ut8*)&off, sizeof(int), !LIL_ENDIAN);
		ret = R_TRUE;
	}
	return ret;
}

static int retdemangle(const char *str) {
	return R_BIN_NM_JAVA;
}

static RBinAddr* binsym(RBinArch *arch, int sym) {
	return r_bin_java_get_entrypoint(arch->o->bin_obj, sym);
}

static RList* lines(RBinArch *arch) {
	int i;
	char *file = strdup (arch->file);
	RList *list = r_list_new ();

	RBinJavaObj *b = arch->o->bin_obj;
	file = r_str_replace (file, ".class", ".java", 0);
	for (i=0; i<b->lines.count; i++) {
		RBinDwarfRow *row = R_NEW (RBinDwarfRow);
		r_bin_dwarf_line_new (row, b->lines.addr[i], file, b->lines.line[i]);
		r_list_append (list, row);
	}
	free (file);
	return list;
}

static RList* sections(RBinArch *arch) {
	return r_bin_java_get_sections (arch->o->bin_obj);
}

static RList* fields(RBinArch *arch) {
	return r_bin_java_get_fields (arch->o->bin_obj);
}

static RList* libs(RBinArch *arch) {
	return r_bin_java_get_lib_names (arch->o->bin_obj);
}

RBinPlugin r_bin_plugin_java = {
	.name = "java",
	.desc = "java bin plugin",
	.license = "LGPL3",
	.init = init,
	.fini = NULL,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.boffset = NULL,
	.binsym = binsym,
	.entries = &entries,
	.sections = sections,
	.symbols = symbols,
	.imports = NULL,
	.strings = &strings,
	.info = &info,
	.fields = NULL, //fields,
	.libs = libs,
	.relocs = NULL,
	.meta = NULL,
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
