/* radare - LGPL - Copyright 2009-2017 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "mach0/mach0.h"
#include "objc/mach0_classes.h"

extern RBinWrite r_bin_write_mach0;

static RBinInfo* info(RBinFile *arch);

static Sdb* get_sdb (RBinFile *bf) {
	RBinObject *o = bf->o;
	if (!o) {
		return NULL;
	}
	struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *) o->bin_obj;
	return bin? bin->kv: NULL;
}

static char *entitlements(RBinFile *arch, bool json) {
	struct MACH0_(obj_t) *bin;
	if (!arch || !arch->o || json) {
		return NULL;
	}
	bin = arch->o->bin_obj;
	if (!bin->signature) {
		return NULL;
	}
	return strdup ((char*) bin->signature);
}

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	struct MACH0_(obj_t) *res = NULL;
	RBuffer *tbuf = NULL;
	if (!buf || !sz || sz == UT64_MAX) {
		return NULL;
	}
	tbuf = r_buf_new ();
	r_buf_set_bytes (tbuf, buf, sz);
	res = MACH0_(new_buf) (tbuf, arch->rbin->verbose);
	if (res) {
		sdb_ns_set (sdb, "info", res->kv);
	}
	r_buf_free (tbuf);
	return res;
}

static bool load(RBinFile *arch) {
	void *res;
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;

	if (!arch || !arch->o) {
		return false;
	}
	res = load_bytes (arch, bytes, sz, arch->o->loadaddr, arch->sdb);
	if (!arch->o || !res) {
		MACH0_(mach0_free) (res);
		return false;
	}
	arch->o->bin_obj = res;
	struct MACH0_(obj_t) *mo = arch->o->bin_obj;
	arch->o->kv = mo->kv; // NOP
	sdb_ns_set (arch->sdb, "info", mo->kv);
	return true;
}

static int destroy(RBinFile *arch) {
	MACH0_(mach0_free) (arch->o->bin_obj);
	return true;
}

static ut64 baddr(RBinFile *arch) {
	struct MACH0_(obj_t) *bin;
	if (!arch || !arch->o || !arch->o->bin_obj) {
		return 0LL;
	}
	bin = arch->o->bin_obj;
	return MACH0_(get_baddr)(bin);
}

static RList* entries(RBinFile *arch) {
	RList *ret;
	RBinAddr *ptr = NULL;
	RBinObject *obj = arch ? arch->o : NULL;
	struct addr_t *entry = NULL;
	int wordsize = 0;

	if (!obj || !obj->bin_obj || !(ret = r_list_newf (free))) {
		return NULL;
	}
	wordsize = MACH0_(get_bits) (obj->bin_obj);
	if (!(entry = MACH0_(get_entrypoint) (obj->bin_obj))) {
		return ret;
	}
	if ((ptr = R_NEW0 (RBinAddr))) {
		ptr->paddr = entry->offset + obj->boffset;
		ptr->vaddr = entry->addr;
		ptr->haddr = entry->haddr;
		ptr->bits = wordsize;
		//realign due to thumb
		if (wordsize == 16) {
			if (ptr->vaddr & 1) {
				ptr->paddr--;
				ptr->vaddr--;
			}
		}
		r_list_append (ret, ptr);
	}
	free (entry);
	return ret;
}

static void handle_data_sections(RBinSection *sect) {
	if (strstr (sect->name, "_cstring")) {
		sect->is_data = true;
	} else if (strstr (sect->name, "_objc_methname")) {
		sect->is_data = true;
	} else if (strstr (sect->name, "_objc_classname")) {
		sect->is_data = true;
	} else if (strstr (sect->name, "_objc_methtype")) {
		sect->is_data = true;
	}
}

static RList* sections(RBinFile *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	struct section_t *sections = NULL;
	RBinObject *obj = arch ? arch->o : NULL;
	int i;

	if (!obj || !obj->bin_obj || !(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}
	if (!(sections = MACH0_(get_sections) (obj->bin_obj))) {
		return ret;
	}
	for (i = 0; !sections[i].last; i++) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			break;
		}
		strncpy (ptr->name, (char*)sections[i].name, R_BIN_SIZEOF_STRINGS);
		if (strstr (ptr->name, "la_symbol_ptr")) {
#ifndef R_BIN_MACH064
			const int sz = 4;
#else
			const int sz = 8;
#endif
			int len = sections[i].size / sz;
			ptr->format = r_str_newf ("Cd %d[%d]", sz, len);
		}
		ptr->name[R_BIN_SIZEOF_STRINGS] = 0;
		handle_data_sections (ptr);
		ptr->size = sections[i].size;
		ptr->vsize = sections[i].size;
		ptr->paddr = sections[i].offset + obj->boffset;
		ptr->vaddr = sections[i].addr;
		ptr->add = true;
		if (!ptr->vaddr) {
			ptr->vaddr = ptr->paddr;
		}
		ptr->srwx = sections[i].srwx | R_BIN_SCN_MAP;
		r_list_append (ret, ptr);
	}
	free (sections);
	return ret;
}

static void _handle_arm_thumb(struct MACH0_(obj_t) *bin, RBinSymbol **p) {
	RBinSymbol *ptr = *p;
	ptr->bits = 32;
	if (bin) {
		if (ptr->paddr & 1) {
			ptr->paddr--;
			ptr->vaddr--;
			ptr->bits = 16;
		}
	}

}

static RList* symbols(RBinFile *arch) {
	struct MACH0_(obj_t) *bin;
	int i;
	struct symbol_t *symbols = NULL;
	RBinSymbol *ptr = NULL;
	RBinObject *obj = arch ? arch->o : NULL;
	RList *ret = r_list_newf (free);
	const char *lang = "c";
	int wordsize = 0;
	if (!ret) {
		return NULL;
	}
	if (!obj || !obj->bin_obj) {
		free (ret);
		return NULL;
	}
	bool isStripped = false;
	wordsize = MACH0_(get_bits) (obj->bin_obj);
	if (!(symbols = MACH0_(get_symbols) (obj->bin_obj))) {
		return ret;
	}
	Sdb *symcache = sdb_new0 ();
	bin = (struct MACH0_(obj_t) *) obj->bin_obj;
	for (i = 0; !symbols[i].last; i++) {
		if (!symbols[i].name[0] || symbols[i].addr < 100) {
			continue;
		}
		if (!(ptr = R_NEW0 (RBinSymbol))) {
			break;
		}
		ptr->name = strdup ((char*)symbols[i].name);
		if (ptr->name[0] == '_' && strncmp (ptr->name, "imp.", 4)) {
			char *dn = r_bin_demangle (arch, ptr->name, ptr->name, ptr->vaddr);
			if (dn) {
				ptr->dname = dn;
				char *p = strchr (dn, '.');
				if (p) {
					if (IS_UPPER (ptr->name[0])) {
						ptr->classname = strdup (ptr->name);
						ptr->classname[p - ptr->name] = 0;
					} else if (IS_UPPER (p[1])) {
						ptr->classname = strdup (p + 1);
						p = strchr (ptr->classname, '.');
						if (p) {
							*p = 0;
						}
					}
				}
			}
		}
		ptr->forwarder = r_str_const ("NONE");
		ptr->bind = r_str_const ((symbols[i].type == R_BIN_MACH0_SYMBOL_TYPE_LOCAL)?
				"LOCAL": "GLOBAL");
		ptr->type = r_str_const ("FUNC");
		ptr->vaddr = symbols[i].addr;
		ptr->paddr = symbols[i].offset + obj->boffset;
		ptr->size = symbols[i].size;
		if (bin->hdr.cputype == CPU_TYPE_ARM && wordsize < 64) {
			_handle_arm_thumb (bin, &ptr);
		}
		ptr->ordinal = i;
		bin->dbg_info = strncmp (ptr->name, "radr://", 7)? 0: 1;
		sdb_set (symcache, sdb_fmt (0, "sym0x%llx", ptr->vaddr), "found", 0);
		if (!strncmp (ptr->name, "type.", 5)) {
			lang = "go";
		}
		r_list_append (ret, ptr);
	}
	//functions from LC_FUNCTION_STARTS
	if (bin->func_start) {
		ut64 value = 0, address = 0;
		const ut8* temp = bin->func_start;
		const ut8* temp_end = bin->func_start + bin->func_size;
		while (temp + 3 < temp_end && *temp) {
			temp = r_uleb128_decode (temp, NULL, &value);
			address += value;
			ptr = R_NEW0 (RBinSymbol);
			if (!ptr) {
				break;
			}
			ptr->vaddr = bin->baddr + address;
			ptr->paddr = address;
			ptr->size = 0;
			ptr->name = r_str_newf ("func.%08"PFMT64x, ptr->vaddr);
			ptr->type = r_str_const ("FUNC");
			ptr->forwarder = r_str_const ("NONE");
			ptr->bind = r_str_const ("LOCAL");
			ptr->ordinal = i++;
			if (bin->hdr.cputype == CPU_TYPE_ARM && wordsize < 64) {
				_handle_arm_thumb (bin, &ptr);
			}
			r_list_append (ret, ptr);
			// if any func is not found in symbols then we can consider it is stripped
			if (!isStripped) {
				if (!sdb_const_get (symcache, sdb_fmt (0, "sym0x%llx", ptr->vaddr), 0)) {
					isStripped = true;
				}
			}

		}
	}
	bin->lang = lang;
	if (isStripped) {
		bin->dbg_info |= R_BIN_DBG_STRIPPED;
	}
	free (symbols);
	sdb_free (symcache);
	return ret;
}

static RList* imports(RBinFile *arch) {
	const char *_objc_class = "_OBJC_CLASS_$";
	const int _objc_class_len = strlen (_objc_class);
	const char *_objc_metaclass = "_OBJC_METACLASS_$";
	const int _objc_metaclass_len = strlen (_objc_metaclass);
	struct MACH0_(obj_t) *bin = arch ? arch->o->bin_obj : NULL;
	struct import_t *imports = NULL;
	const char *name, *type;
	RBinImport *ptr = NULL;
	RList *ret = NULL;
	int i;
	RBinObject *obj = arch ? arch->o : NULL;

	if (!obj || !bin || !obj->bin_obj || !(ret = r_list_newf (free))) {
		return NULL;
	}
	if (!(imports = MACH0_(get_imports) (arch->o->bin_obj))) {
		return ret;
	}
	bin->has_canary = false;
	for (i = 0; !imports[i].last; i++) {
		if (!(ptr = R_NEW0 (RBinImport))) {
			break;
		}
		name = imports[i].name;
		type = "FUNC";

		if (!strncmp (name, _objc_class, _objc_class_len)) {
			name += _objc_class_len;
			type = "OBJC_CLASS";
		} else if (!strncmp (name, _objc_metaclass, _objc_metaclass_len)) {
			name += _objc_metaclass_len;
			type = "OBJC_METACLASS";
		}

		// Remove the extra underscore that every import seems to have in Mach-O.
		if (*name == '_') {
			name++;
		}
		ptr->name = strdup (name);
		ptr->bind = r_str_const ("NONE");
		ptr->type = r_str_const (type);
		ptr->ordinal = imports[i].ord;
		if (bin->imports_by_ord && ptr->ordinal < bin->imports_by_ord_size) {
			bin->imports_by_ord[ptr->ordinal] = ptr;
		}
		if (!strcmp (name, "__stack_chk_fail") ) {
			bin->has_canary = true;
		}
		r_list_append (ret, ptr);
	}
	free (imports);
	return ret;
}

static RList* relocs(RBinFile *arch) {
	RList *ret = NULL;
	RBinReloc *ptr = NULL;
	struct reloc_t *relocs = NULL;
	struct MACH0_(obj_t) *bin = NULL;
	int i;
	RBinObject *obj = arch ? arch->o : NULL;

	if (arch && arch->o) {
		bin = arch->o->bin_obj;
	}
	if (!obj || !obj->bin_obj || !(ret = r_list_newf (free))) {
		return NULL;
	}
	ret->free = free;
	if (!(relocs = MACH0_(get_relocs) (arch->o->bin_obj))) {
		return ret;
	}
	for (i = 0; !relocs[i].last; i++) {
		// TODO(eddyb) filter these out earlier.
		if (!relocs[i].addr) {
			continue;
		}
		if (!(ptr = R_NEW0 (RBinReloc))) {
			break;
		}
		ptr->type = relocs[i].type;
		ptr->additive = 0;
		if (bin->imports_by_ord && relocs[i].ord < bin->imports_by_ord_size) {
			ptr->import = bin->imports_by_ord[relocs[i].ord];
		} else {
			ptr->import = NULL;
		}
		ptr->addend = relocs[i].addend;
		ptr->vaddr = relocs[i].addr;
		ptr->paddr = relocs[i].offset;
		r_list_append (ret, ptr);
	}
	free (relocs);
	return ret;
}

static RList* libs(RBinFile *arch) {
	int i;
	char *ptr = NULL;
	struct lib_t *libs;
	RList *ret = NULL;
	RBinObject *obj = arch ? arch->o : NULL;

	if (!obj || !obj->bin_obj || !(ret = r_list_newf (free))) {
		return NULL;
	}
	if ((libs = MACH0_(get_libs) (obj->bin_obj))) {
		for (i = 0; !libs[i].last; i++) {
			ptr = strdup (libs[i].name);
			r_list_append (ret, ptr);
		}
		free (libs);
	}
	return ret;
}

static RBinInfo* info(RBinFile *arch) {
	struct MACH0_(obj_t) *bin = NULL;
	char *str;
	RBinInfo *ret;

	if (!arch || !arch->o)
		return NULL;

	ret = R_NEW0 (RBinInfo);
	if (!ret)
		return NULL;

	bin = arch->o->bin_obj;
	if (arch->file)
		ret->file = strdup (arch->file);
	if ((str = MACH0_(get_class) (arch->o->bin_obj))) {
		ret->bclass = str;
	}
	if (bin) {
		ret->has_canary = bin->has_canary;
		ret->dbg_info = bin->dbg_info;
		ret->lang = bin->lang;
	}
	ret->intrp = r_str_dup (NULL, MACH0_(get_intrp)(arch->o->bin_obj));
	ret->rclass = strdup ("mach0");
	ret->os = strdup (MACH0_(get_os)(arch->o->bin_obj));
	ret->subsystem = strdup ("darwin");
	ret->arch = MACH0_(get_cputype) (arch->o->bin_obj);
	ret->machine = MACH0_(get_cpusubtype) (arch->o->bin_obj);
	ret->has_lit = true;
	ret->type = MACH0_(get_filetype) (arch->o->bin_obj);
	ret->big_endian = MACH0_(is_big_endian) (arch->o->bin_obj);
	ret->bits = 32;
	if (arch && arch->o && arch->o->bin_obj) {
		ret->has_crypto = ((struct MACH0_(obj_t)*)
			arch->o->bin_obj)->has_crypto;
		ret->bits = MACH0_(get_bits) (arch->o->bin_obj);
	}
	ret->has_va = true;
	ret->has_pi = MACH0_(is_pie) (arch->o->bin_obj);
	ret->has_nx = MACH0_(has_nx) (arch->o->bin_obj);
	return ret;
}

#if !R_BIN_MACH064
static bool check_bytes(const ut8 *buf, ut64 length) {
	if (buf && length >= 4) {
		if (!memcmp (buf, "\xce\xfa\xed\xfe", 4) ||
			!memcmp (buf, "\xfe\xed\xfa\xce", 4))
			return true;
	}
	return false;
}

#if 0
typedef struct r_bin_create_t {
	int arch;
	ut8 *code;
	int clen;
	ut8 *data;
	int dlen;
} RBinCreate;
#endif

static RBuffer* create(RBin* bin, const ut8 *code, int clen, const ut8 *data, int dlen) {
	const bool use_pagezero = true;
	const bool use_main = true;
	const bool use_dylinker = true;
	const bool use_libsystem = true;
	const bool use_linkedit = true;
	ut32 filesize, codeva, datava;
	ut32 ncmds, cmdsize, magiclen;
	ut32 p_codefsz = 0, p_codeva = 0, p_codesz = 0, p_codepa = 0;
	ut32 p_datafsz = 0, p_datava = 0, p_datasz = 0, p_datapa = 0;
	ut32 p_cmdsize = 0, p_entry = 0, p_tmp = 0;
	ut32 baddr = 0x1000;

	bool is_arm = strstr (bin->cur->o->info->arch, "arm");
	RBuffer *buf = r_buf_new ();
#ifndef R_BIN_MACH064
	if (bin->cur->o->info->bits == 64) {
		eprintf ("TODO: Please use mach064 instead of mach0\n");
		free (buf);
		return NULL;
	}
#endif

#define B(x,y) r_buf_append_bytes(buf,(const ut8*)x,y)
#define D(x) r_buf_append_ut32(buf,x)
#define Z(x) r_buf_append_nbytes(buf,x)
#define W(x,y,z) r_buf_write_at(buf,x,(const ut8*)y,z)
#define WZ(x,y) p_tmp=buf->length;Z(x);W(p_tmp,y,strlen(y))

	/* MACH0 HEADER */
	B ("\xce\xfa\xed\xfe", 4); // header
// 64bit header	B ("\xce\xfa\xed\xfe", 4); // header
	if (is_arm) {
		D (12); // cpu type (arm)
		D (3); // subtype (all?)
	} else {
		/* x86-32 */
		D (7); // cpu type (x86)
// D(0x1000007); // x86-64
		D (3); // subtype (i386-all)
	}
	D (2); // filetype (executable)

	if (data && dlen > 0) {
		ncmds = 3;
		cmdsize = 0;
	} else {
		ncmds = 2;
		cmdsize = 0;
	}
	if (use_pagezero) {
		ncmds++;
	}
	if (use_dylinker) {
		ncmds++;
		if (use_linkedit) {
			ncmds += 3;
		}
		if (use_libsystem) {
			ncmds++;
		}
	}

	/* COMMANDS */
	D (ncmds); // ncmds
	p_cmdsize = buf->length;
	D (-1); // cmdsize
	D (0); // flags
	// D (0x01200085); // alternative flags found in some a.out..
	magiclen = buf->length;

	if (use_pagezero) {
		/* PAGEZERO */
		D (1);   // cmd.LC_SEGMENT
		D (56); // sizeof (cmd)
		WZ (16, "__PAGEZERO");
		D (0); // vmaddr
		D (0x00001000); // vmsize XXX
		D (0); // fileoff
		D (0); // filesize
		D (0); // maxprot
		D (0); // initprot
		D (0); // nsects
		D (0); // flags
	}

	/* TEXT SEGMENT */
	D (1);   // cmd.LC_SEGMENT
	D (124); // sizeof (cmd)
	WZ (16, "__TEXT");
	D (baddr); // vmaddr
	D (0x1000); // vmsize XXX
	D (0); // fileoff
	p_codefsz = buf->length;
	D (-1); // filesize
	D (7); // maxprot
	D (5); // initprot
	D (1); // nsects
	D (0); // flags
	WZ (16, "__text");
	WZ (16, "__TEXT");
	p_codeva = buf->length; // virtual address
	D (-1);
	p_codesz = buf->length; // size of code (end-start)
	D (-1);
	p_codepa = buf->length; // code - baddr
	D (-1); //_start-0x1000);
	D (0); // align // should be 2 for 64bit
	D (0); // reloff
	D (0); // nrelocs
	D (0); // flags
	D (0); // reserved
	D (0); // ??

	if (data && dlen > 0) {
		/* DATA SEGMENT */
		D (1);   // cmd.LC_SEGMENT
		D (124); // sizeof (cmd)
		p_tmp = buf->length;
		Z (16);
		W (p_tmp, "__TEXT", 6); // segment name
		D (0x2000); // vmaddr
		D (0x1000); // vmsize
		D (0); // fileoff
		p_datafsz = buf->length;
		D (-1); // filesize
		D (6); // maxprot
		D (6); // initprot
		D (1); // nsects
		D (0); // flags

		WZ (16, "__data");
		WZ (16, "__DATA");

		p_datava = buf->length;
		D (-1);
		p_datasz = buf->length;
		D (-1);
		p_datapa = buf->length;
		D (-1); //_start-0x1000);
		D (2); // align
		D (0); // reloff
		D (0); // nrelocs
		D (0); // flags
		D (0); // reserved
		D (0);
	}

	if (use_dylinker) {
		if (use_linkedit) {
			/* LINKEDIT */
			D (1);   // cmd.LC_SEGMENT
			D (56); // sizeof (cmd)
			WZ (16, "__LINKEDIT");
			D (0x3000); // vmaddr
			D (0x00001000); // vmsize XXX
			D (0x1000); // fileoff
			D (0); // filesize
			D (7); // maxprot
			D (1); // initprot
			D (0); // nsects
			D (0); // flags

			/* LC_SYMTAB */
			D (2); // cmd.LC_SYMTAB
			D (24); // sizeof (cmd)
			D (0x1000); // symtab offset
			D (0); // symtab size
			D (0x1000); // strtab offset
			D (0); // strtab size

			/* LC_DYSYMTAB */
			D (0xb); // cmd.LC_DYSYMTAB
			D (80); // sizeof (cmd)
			Z (18 * sizeof (ut32)); // empty
		}

		const char *dyld = "/usr/lib/dyld";
		const int dyld_len = strlen (dyld) + 1;
		D(0xe); /* LC_DYLINKER */
		D((4 * 3) + dyld_len);
		D(dyld_len - 2);
		WZ(dyld_len, dyld); // path

		if (use_libsystem) {
			/* add libSystem at least ... */
			const char *lib = "/usr/lib/libSystem.B.dylib";
			const int lib_len = strlen (lib) + 1;
			D (0xc); /* LC_LOAD_DYLIB */
			D (24 + lib_len); // cmdsize
			D (24); // offset where the lib string start
			D (0x2);
			D (0x1);
			D (0x1);
			WZ (lib_len, lib);
		}
	}

	if (use_main) {
		/* LC_MAIN */
		D (0x80000028);   // cmd.LC_MAIN
		D (24); // sizeof (cmd)
		D (baddr); // entryoff
		D (0); // stacksize
		D (0); // ???
		D (0); // ???
	} else {
		/* THREAD STATE */
		D (5); // LC_UNIXTHREAD
		D (80); // sizeof (cmd)
		if (is_arm) {
			/* arm */
			D (1); // i386-thread-state
			D (17); // thread-state-count
			p_entry = buf->length + (16 * sizeof (ut32));
			Z (17 * sizeof (ut32));
			// mach0-arm has one byte more
		} else {
			/* x86-32 */
			D (1); // i386-thread-state
			D (16); // thread-state-count
			p_entry = buf->length + (10 * sizeof (ut32));
			Z (16 * sizeof (ut32));
		}
	}

	/* padding to make mach_loader checks happy */
	/* binaries must be at least of 4KB :( not tiny anymore */
	WZ (4096 - buf->length, "");

	cmdsize = buf->length - magiclen;
	codeva = buf->length + baddr;
	datava = buf->length + clen + baddr;
	if (p_entry != 0) {
		W (p_entry, &codeva, 4); // set PC
	}

	/* fill header variables */
	W (p_cmdsize, &cmdsize, 4);
	filesize = magiclen + cmdsize + clen + dlen;
	// TEXT SEGMENT should span the whole file //
	W (p_codefsz, &filesize, 4);
	W (p_codefsz-8, &filesize, 4); // vmsize = filesize
	W (p_codeva, &codeva, 4);
	// clen = 4096;
	W (p_codesz, &clen, 4);
	p_tmp = codeva - baddr;
	W (p_codepa, &p_tmp, 4);

	B (code, clen);

	if (data && dlen > 0) {
		/* append data */
		W (p_datafsz, &filesize, 4);
		W (p_datava, &datava, 4);
		W (p_datasz, &dlen, 4);
		p_tmp = datava - baddr;
		W (p_datapa, &p_tmp, 4);
		B (data, dlen);
	}

	return buf;
}

static RBinAddr* binsym(RBinFile *arch, int sym) {
	ut64 addr;
	RBinAddr *ret = NULL;
	switch (sym) {
	case R_BIN_SYM_MAIN:
		addr = MACH0_(get_main) (arch->o->bin_obj);
		if (!addr || !(ret = R_NEW0 (RBinAddr)))
			return NULL;
		//if (arch->o->info && arch->o->info->bits == 16) {
		// align for thumb
		ret->vaddr = ((addr >>1)<<1);
		//}
		ret->paddr = ret->vaddr;
		break;
	}
	return ret;
}

static ut64 size(RBinFile *arch) {
	ut64 off = 0;
	ut64 len = 0;
	if (!arch->o->sections) {
		RListIter *iter;
		RBinSection *section;
		arch->o->sections = sections (arch);
		r_list_foreach (arch->o->sections, iter, section) {
			if (section->paddr > off) {
				off = section->paddr;
				len = section->size;
			}
		}
	}
	return off + len;
}

RBinPlugin r_bin_plugin_mach0 = {
	.name = "mach0",
	.desc = "mach0 bin plugin",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.signature = &entitlements,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.size = &size,
	.info = &info,
	.header = MACH0_(mach_headerfields),
	.fields = MACH0_(mach_fields),
	.libs = &libs,
	.relocs = &relocs,
	.create = &create,
	.classes = &MACH0_(parse_classes),
	.write = &r_bin_write_mach0,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_mach0,
	.version = R2_VERSION
};
#endif
#endif
