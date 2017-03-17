/* radare2 - LGPL - Copyright 2017 - pancake */

// http://webassembly.org/docs/binary-encoding/#module-structure

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

static bool check_bytes(const ut8 *buf, ut64 length) {
	return (buf && length >= 4 && !memcmp (buf, "\x00" "asm", 4));
}

static ut64 entrypoint = UT64_MAX;

static bool check(RBinFile *arch) {
	const ut8 *bytes = arch? r_buf_buffer (arch->buf): NULL;
	ut64 sz = arch? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static void *load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	return (void *) (size_t) check_bytes (buf, sz);
}

static bool load(RBinFile *arch) {
	return check (arch);
}

static int destroy(RBinFile *arch) {
	return true;
}

static ut64 baddr(RBinFile *arch) {
	return 0;
}

static RBinAddr *binsym(RBinFile *arch, int type) {
	return NULL; // TODO
}

static RList *sections(RBinFile *arch);

static RList *entries(RBinFile *arch) {
	RList *ret;
	RBinAddr *ptr = NULL;

	if (!(ret = r_list_new ())) {
		return NULL;
	}
	if (entrypoint == UT64_MAX) {
		r_list_free (sections (arch));
	}
	ret->free = free;
	if ((ptr = R_NEW0 (RBinAddr))) {
		ptr->paddr = entrypoint;
		ptr->vaddr = entrypoint;
		r_list_append (ret, ptr);
	}
	return ret;
}

static RList *sections(RBinFile *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	// ut64 textsize, datasize, symssize, spszsize, pcszsize;
	if (!arch->o->info) {
		return NULL;
	}

	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;

	int next, i = 0;
	ut8 *buf = arch->buf->buf; // skip magic + version
	for (i = 8; i < arch->buf->length;) {
		int id = buf[i];
#if 0
		1 Type Function signature declarations
		2 Import Import declarations
		3 Function Function declarations
		4 Table Indirect function table and other tables
		5 Memory Memory attributes
		6 Global Global declarations
		7 Export Exports
		8 Start Start function declaration
		9 Element Elements section
		10 Code Function bodies(code)
		11 Data Data segments
#endif
		ut64 res = 0;
		ut8 *p = buf + i + 1;
		const ut8 *afterBuf = r_uleb128 (p, 8, &res);
		int payloadLen = res;
		int payloadSize = (int) (size_t) (afterBuf - p);

		p += payloadSize;

		afterBuf = r_uleb128 (p, 8, &res);
		int nameLen = res;
		int nameSize = (int) (size_t) (afterBuf - p);

		eprintf (" 0x%x len = %d (%d) %d (%d): ", i, payloadLen, payloadSize, nameLen, nameSize);

		next = i + payloadSize + nameSize + payloadLen; // payloadLen - payloadSize - nameSize; //nameSize - nameLen + 1; //payloadLen + nameLen + 1;
		switch (id) {
		case 1: // "type"
			eprintf ("type: function signature declarations\n");
			break;
		case 2:
			eprintf ("import:\n");
			break;
		case 3:
			eprintf ("function:\n");
			break;
		case 4:
			eprintf ("table:\n");
			break;
		case 5:
			eprintf ("memory:\n");
			break;
		case 6:
			eprintf ("global:\n");
			break;
		case 7:
			eprintf ("export:\n");
			break;
		case 8:
			eprintf ("start:\n");
			break;
		case 9:
			eprintf ("element:\n");
			break;
		case 10: //
			eprintf ("code:\n");
			if (!(ptr = R_NEW0 (RBinSection))) {
				return ret;
			}
			strncpy (ptr->name, "code", R_BIN_SIZEOF_STRINGS);
			ptr->size = payloadLen;
			ptr->vsize = payloadLen;
			ptr->paddr = i + nameLen + payloadSize + nameSize + 1 + payloadSize;
			ptr->vaddr = ptr->paddr;
			if (entrypoint == UT64_MAX) {
				entrypoint = ptr->vaddr;
			}
			ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP; // r-x
			ptr->add = true;
			r_list_append (ret, ptr);
			break;
		case 11: //
			eprintf ("data:\n");
			break;
		default:
			eprintf ("unknown type id: %d\n", id);
			break;
		}
		if (next <= i) {
			eprintf ("Error: prevent infinite loop\n");
			break;
		}
		i = next;
	}
	// add text segment
#if 0
	textsize = r_mem_get_num (arch->buf->buf + 4, 4);
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	strncpy (ptr->name, "text", R_BIN_SIZEOF_STRINGS);
	ptr->size = textsize;
	ptr->vsize = textsize + (textsize % 4096);
	ptr->paddr = 8 * 4;
	ptr->vaddr = ptr->paddr;
	ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP; // r-x
	ptr->add = true;
	r_list_append (ret, ptr);
#endif
	return ret;
}

static RList *symbols(RBinFile *arch) {
	// TODO: parse symbol table
	return NULL;
}

static RList *imports(RBinFile *arch) {
	return NULL;
}

static RList *libs(RBinFile *arch) {
	return NULL;
}

static RBinInfo *info(RBinFile *arch) {
	RBinInfo *ret = NULL;

	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	ret->file = strdup (arch->file);
	ret->bclass = strdup ("module");
	ret->rclass = strdup ("wasm");
	ret->os = strdup ("Wasm");
	ret->arch = strdup ("wasm");
	ret->machine = strdup (ret->arch);
	ret->subsystem = strdup ("wasm");
	ret->type = strdup ("EXEC");
	ret->bits = 32;
	ret->has_va = true;
	ret->big_endian = false;
	ret->dbg_info = 0;
	ret->dbg_info = 0;
	return ret;
}

static ut64 size(RBinFile *arch) {
	ut64 text, data, syms, spsz;
	if (!arch->o->info) {
		arch->o->info = info (arch);
	}
	if (!arch->o->info) {
		return 0;
	}
	// TODO: reuse section list
	text = r_mem_get_num (arch->buf->buf + 4, 4);
	data = r_mem_get_num (arch->buf->buf + 8, 4);
	syms = r_mem_get_num (arch->buf->buf + 16, 4);
	spsz = r_mem_get_num (arch->buf->buf + 24, 4);
	return text + data + syms + spsz + (6 * 4);
}

/* inspired in http://www.phreedom.org/solar/code/tinype/tiny.97/tiny.asm */
static RBuffer *create(RBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen) {
	RBuffer *buf = r_buf_new ();
#define B(x, y) r_buf_append_bytes (buf, (const ut8 *) x, y)
#define D(x) r_buf_append_ut32 (buf, x)
	B ("\x00" "asm", 4);
	D (0xc); // TODO: last version is 0xd
	return buf;
}

RBinPlugin r_bin_plugin_wasm = {
	.name = "wasm",
	.desc = "WebAssembly bin plugin",
	.license = "MIT",
	.load = &load,
	.load_bytes = &load_bytes,
	.size = &size,
	.destroy = &destroy,
	.check = &check,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.info = &info,
	.libs = &libs,
	.create = &create,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_wasm,
	.version = R2_VERSION
};
#endif
