/* radare2 - MIT - Copyright 2021-2022 - pancake, keegan, Plan 9 Foundation */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "../format/p9/p9bin.h"

#undef P9_ALIGN
#define P9_ALIGN(address, align) (((address) + (align - 1)) & ~(align - 1))

extern struct r_bin_dbginfo_t r_bin_dbginfo_p9;

static bool check(RBinFile *bf, RBuffer *buf) {
	const char *arch;
	int bits, big_endian;
	return r_bin_p9_get_arch (buf, &arch, &bits, &big_endian);
}

static bool load(RBinFile *bf, RBuffer *b, ut64 loadaddr) {
	if (!check (bf, b)) {
		return false;
	}

	RBinPlan9Obj *o = R_NEW0 (RBinPlan9Obj);

	if (r_buf_fread_at (bf->buf, 0, (ut8 *)&o->header, "IIIIIIII", 1) != sizeof (o->header)) {
		return false;
	}

	o->header_size = sizeof (struct plan9_exec);

	// for extended headers (64-bit binaries)
	if (o->header.magic & HDR_MAGIC) {
		o->entry = r_buf_read_be64_at (bf->buf, o->header_size);
		if (o->entry == UT64_MAX) {
			return false;
		}
		o->header_size += 8;
	} else {
		o->entry = o->header.entry;
	}

	// kernels require different maps (see uses for details)
	o->is_kernel = o->entry & KERNEL_MASK;

	// each arch has a pc quantization used for line-number calculation
	switch (o->header.magic) {
	case MAGIC_AMD64:
	case MAGIC_INTEL_386:
		o->pcq = 1;
		break;
	case MAGIC_68020:
		o->pcq = 2;
		break;
	case MAGIC_ARM64:
	case MAGIC_PPC64:
	case MAGIC_SPARC:
	case MAGIC_SPARC64:
	case MAGIC_MIPS_3000BE:
	case MAGIC_MIPS_4000BE:
	case MAGIC_MIPS_4000LE:
	case MAGIC_MIPS_3000LE:
	case MAGIC_ARM:
	case MAGIC_PPC:
		o->pcq = 4;
		break;
	}

	bf->bo->bin_obj = o;
	return true;
}

static void destroy(RBinFile *bf) {
	free (bf->bo->bin_obj);
}

static ut64 baddr(RBinFile *bf) {
	RBinPlan9Obj *o = (RBinPlan9Obj *)bf->bo->bin_obj;

	switch (o->header.magic) {
	case MAGIC_ARM64:
		// if this is an arm64 kernel: check mask and return known
		// base address. see libmach for definitions.
		if (o->is_kernel) {
			return 0xffffffffc0080000ULL;
		}
		return 0x10000ULL;
	case MAGIC_AMD64:
		// if this is an amd64 kernel. see above
		if (o->is_kernel) {
			return 0xffffffff80110000ULL;
		}
		// fallthrough
	case MAGIC_PPC64:
		return 0x200000ULL;
	case MAGIC_68020:
	case MAGIC_INTEL_386:
	case MAGIC_SPARC:
	case MAGIC_SPARC64:
	case MAGIC_MIPS_3000BE:
	case MAGIC_MIPS_4000BE:
	case MAGIC_MIPS_4000LE:
	case MAGIC_MIPS_3000LE:
	case MAGIC_ARM:
	case MAGIC_PPC:
		return 0x1000ULL;
	}

	// unreachable because check only supports the above architectures
	return 0;
}

static RBinAddr *binsym(RBinFile *bf, int type) {
	return NULL;
}

static RList *entries(RBinFile *bf) {
	RList *ret;
	RBinAddr *ptr = NULL;
	RBinPlan9Obj *o = (RBinPlan9Obj *)bf->bo->bin_obj;

	if (!(ret = r_list_new ())) {
		return NULL;
	}

	ret->free = free;

	if ((ptr = R_NEW0 (RBinAddr))) {
		ptr->paddr = o->entry - baddr (bf);
		// for kernels the header is not mapped
		if (o->is_kernel) {
			ptr->paddr += o->header_size;
		}
		ptr->vaddr = o->entry;
		r_list_append (ret, ptr);
	}

	return ret;
}

static RList *sections(RBinFile *bf) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	RBinPlan9Obj *o = (RBinPlan9Obj *)bf->bo->bin_obj;

	if (!bf->bo->info) {
		return NULL;
	}

	if (!(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}

	ut32 align = 0x1000;
	// on some platforms the text segment has a separate alignment
	switch (o->header.magic) {
	case MAGIC_AMD64:
		align = 0x200000;
		break;
	case MAGIC_MIPS_3000BE:
		align = 0x4000;
		break;
	case MAGIC_ARM64:
		align = 0x10000;
		break;
	}

	// for kernels the header is not mapped
	ut64 phys = o->is_kernel? o->header_size: 0;
	ut64 vsize = 0;

	// add text segment
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("text");
	ptr->size = o->header.text;
	// for regular applications: header is included in the text segment
	if (!o->is_kernel) {
		ptr->size += o->header_size;
	}
	ptr->vsize = P9_ALIGN (o->header.text, align);
	ptr->paddr = phys;
	ptr->vaddr = baddr (bf);
	ptr->perm = R_PERM_RX; // r-x
	ptr->add = true;
	r_list_append (ret, ptr);
	phys += ptr->size;
	vsize += ptr->vsize;

	// switch back to 4k page size
	align = 0x1000;

	// add data segment
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("data");
	ptr->size = o->header.data;
	ptr->vsize = P9_ALIGN (o->header.data, align);
	ptr->paddr = phys;
	ptr->vaddr = baddr (bf) + vsize;
	ptr->perm = R_PERM_RW;
	ptr->add = true;
	r_list_append (ret, ptr);
	phys += ptr->size;
	vsize += ptr->vsize;

	// add bss segment
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("bss");
	ptr->size = 0;
	ptr->vsize = P9_ALIGN (o->header.bss, align);
	ptr->paddr = 0;
	ptr->vaddr = baddr (bf) + vsize;
	ptr->perm = R_PERM_RW;
	ptr->add = true;
	r_list_append (ret, ptr);
	phys += ptr->size;
	vsize += ptr->vsize;

	// add syms segment
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("syms");
	ptr->size = o->header.syms;
	ptr->vsize = P9_ALIGN (o->header.syms, align);
	ptr->paddr = phys;
	ptr->vaddr = baddr (bf) + vsize;
	ptr->perm = R_PERM_R; // r--
	ptr->add = true;
	r_list_append (ret, ptr);
	phys += ptr->size;
	vsize += ptr->vsize;

	// add pc/sp offsets segment
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("pcsp");
	ptr->size = o->header.spsz;
	ptr->vsize = P9_ALIGN (o->header.spsz, align);
	ptr->paddr = phys;
	ptr->vaddr = baddr (bf) + vsize;
	ptr->perm = R_PERM_R; // r--
	ptr->add = true;
	r_list_append (ret, ptr);
	phys += ptr->size;
	vsize += ptr->vsize;

	// add pc/line numbers segment
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("pcline");
	ptr->size = o->header.pcsz;
	ptr->vsize = P9_ALIGN (o->header.pcsz, align);
	ptr->paddr = phys;
	ptr->vaddr = baddr (bf) + vsize;
	ptr->perm = R_PERM_R; // r--
	ptr->add = true;
	r_list_append (ret, ptr);

	return ret;
}

typedef struct {
	ut64 value;
	char type;
	char *name;
} Sym;

static st64 sym_read(RBinFile *bf, Sym *sym, const ut64 offset) {
	st64 size = 0;
	const RBinPlan9Obj *o = (RBinPlan9Obj *)bf->bo->bin_obj;
	const ut64 syms = o->header_size + o->header.text + o->header.data;

	ut64 value;
	if (o->header.magic & HDR_MAGIC) {
		// for 64-bit binaries the value type is 8 bytes
		value = r_buf_read_be64_at (bf->buf, syms + offset);
		if (value == UT64_MAX) {
			return -1;
		}
		size += sizeof (ut64);
	} else {
		value = (ut64)r_buf_read_be32_at (bf->buf, syms + offset);
		if (value == UT32_MAX) {
			return -1;
		}
		size += sizeof (ut32);
	}

	const ut8 typ = r_buf_read8_at (bf->buf, syms + offset + size);
	if (typ == UT8_MAX) {
		return -1;
	}
	size += sizeof (typ);
	const char type = typ & 0x7f;

	char *name = r_buf_get_string (bf->buf, syms + offset + size);
	if (!name) {
		return -1;
	}
	size += strlen (name) + 1;

	sym->value = value;
	sym->type = type;
	sym->name = name;
	return size;
}

static void sym_fini(void *sym, R_UNUSED void *user) {
	Sym *s = (Sym *)sym;
	if (s && s->name) {
		R_FREE (s->name);
	}
}

static int apply_history(RBinFile *bf, ut64 pc, ut64 line, Sym *base, Sym **ret) {
	// start of current level
	Sym *start = base;
	// current entry
	Sym *h = base;
	// sum of size of files this level
	st64 delta = h->value;

	// see fline in libmach
	while (h && h->name && line > h->value) {
		if (strlen (h->name)) {
			if (start == base) {
				start = h++;
			} else {
				int k = apply_history (bf, pc, line, start, &h);
				if (k <= 0) {
					return k;
				}
			}
		} else {
			if (start == base) {
				// end of recursion level
				if (ret) {
					*ret = h;
				}
				return 1;
			}

			// end of included file
			delta += h->value - start->value;
			h++;
			start = base;
		}
	}

	if (!h) {
		return -1;
	}

	char *name = h->name? start->name: "<unknown>";
	if (start != base) {
		line = line - start->value + 1;
	} else {
		line = line - delta + 1;
	}

	RBinDbgItem item = {
		.addr = pc,
		.file = name,
		.line = line,
	};
	bf->addrline.al_add (&bf->addrline, item);
	return 0;
}

static RList *symbols(RBinFile *bf) {
	RList *ret = NULL;
	RVector *history = NULL; // <Sym>
	HtUP *histories = NULL; // <ut64, RVector<Sym> *>
	RPVector *names = NULL; // <char *>
	const RBinPlan9Obj *o = (RBinPlan9Obj *)bf->bo->bin_obj;
	ut64 i;
	Sym sym = {0};

	if (!(ret = r_list_newf (free))) {
		goto error;
	}

	if (!(histories = ht_up_new0 ())) {
		goto error;
	}

	if (!(names = r_pvector_new (NULL))) {
		goto error;
	}

	const ut64 syms = o->header_size + o->header.text + o->header.data;

	ut64 offset = 0;
	while (offset < o->header.syms) {
		const st64 size = sym_read (bf, &sym, offset);
		if (size == -1) {
			goto error;
		}
		offset += size;

		// source file name components
		if (sym.type == 'f') {
			if (sym.value * 4 > r_buf_size (bf->buf)) {
				R_LOG_ERROR ("Prevented huge memory allocation");
				break;
			}
			if (r_pvector_length (names) < sym.value) {
				if (!r_pvector_reserve (names, sym.value)) {
					goto error;
				}
				// reserve zeros so this is safe
				names->v.len = sym.value;
			}

			r_pvector_set (names, sym.value - 1, sym.name);
			continue;
		}

		// source file name
		if (sym.type == 'z') {
			// make a /-delim name
			RStrBuf *sb = r_strbuf_new (NULL);

			ut64 fin = (o->header.syms > offset)? o->header.syms - offset: 0;
			for (i = 0; i < fin; i += sizeof (ut16)) {
				ut16 index = r_buf_read_be16_at (bf->buf, syms + offset + i);
				if (index == UT16_MAX) {
					r_strbuf_free (sb);
					goto error;
				}

				// read indices until a zero index
				if (index == 0) {
					offset += i + sizeof (ut16);
					break;
				}

				const char *name = r_pvector_at (names, index - 1);
				r_strbuf_appendf (sb, "%s", name);
				// lead / is NOT assumed
				if (i != 0) {
					r_strbuf_append (sb, "/");
				}
			}

			char *name = r_strbuf_drain (sb);
			size_t name_size = strlen (name);
			// pop final /
			if (name_size) {
				name[name_size - 1] = '\0';
			}

			// a new history
			if (sym.value == 1 && history) {
				history = NULL;
			}

			if (!history) {
				history = r_vector_new (sizeof (Sym), sym_fini, NULL);
			}

			Sym history_sym = {sym.value, 'z', name};
			r_vector_push (history, &history_sym);
			continue;
		}

		// skip non symbol information
		switch (sym.type) {
		case 'T':
		case 't':
		case 'L':
		case 'l':
		case 'D':
		case 'd':
		case 'B':
		case 'b':
			break;
		// TODO: source file line offset
		case 'Z': {
			ut64 fin = (o->header.syms > offset)? o->header.syms - offset: 0;
			for (i = 0; i < fin; i += sizeof (ut16)) {
				ut16 index = r_buf_read_be16_at (bf->buf, syms + offset + i);
				if (index == UT16_MAX) {
					goto error;
				}

				// read indices until a zero index
				if (index == 0) {
					offset += i + sizeof (ut16);
					break;
				}
			}
		}
			// fallthrough
		default:
			sym_fini (&sym, NULL);
			continue;
		}

		RBinSymbol *bin_sym = R_NEW0 (RBinSymbol);
		if (!bin_sym) {
			goto error;
		}

		bin_sym->name = r_bin_name_new (sym.name);
		bin_sym->paddr = sym.value - baddr (bf);
		// for kernels the header is not mapped
		if (o->is_kernel) {
			bin_sym->paddr += o->header_size;
		}
		bin_sym->vaddr = sym.value;
		bin_sym->size = 0;
		bin_sym->ordinal = 0;
		r_list_append (ret, bin_sym);

		if (history) {
			ht_up_insert (histories, bin_sym->vaddr, history);
		}
	}

	history = NULL;

	const ut64 pcs = syms + o->header.syms + o->header.spsz;

	ut64 line = 0;
	// base address (for kernels the header is NOT mapped)
	ut64 pc = baddr (bf) + (o->is_kernel? 0: o->header_size) - o->pcq;

	offset = 0;
	while (offset < o->header.pcsz) {
		RVector *h = ht_up_find (histories, pc + o->pcq, NULL);
		if (h) {
			history = h;
		}

		ut64 prev = line;

		ut8 b;
		st64 r = r_buf_read_at (bf->buf, pcs + offset, &b, sizeof (b));
		if (r != sizeof (b)) {
			goto error;
		}
		offset += sizeof (ut8);

		// see pc2line in libmach
		if (b == 0) {
			ut32 d = r_buf_read_be32_at (bf->buf, pcs + offset);
			if (d == UT32_MAX) {
				goto error;
			}
			line += (st32)d;
			offset += sizeof (ut32);
		} else if (b < 65) {
			line += b;
		} else if (b < 129) {
			line -= b - 64;
		} else {
			pc += o->pcq * (b - 129);
		}

		pc += o->pcq;

		if (prev != line && r_vector_length (history) > 1) {
			apply_history (bf, pc, line, r_vector_at (history, 0), NULL);
		}
	}

	ht_up_free (histories);
	r_pvector_free (names);
	return ret;
error:
	sym_fini (&sym, NULL);
	r_list_free (ret);
	r_pvector_free (names);
	ht_up_free (histories);
	return NULL;
}

static RList *imports(RBinFile *bf) {
	// all executables are statically linked
	return NULL;
}

static RList *libs(RBinFile *bf) {
	// all executables are statically linked
	return NULL;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = NULL;
	const char *arch;
	int bits, big_endian;
	struct plan9_exec header;

	if (!r_bin_p9_get_arch (bf->buf, &arch, &bits, &big_endian)) {
		return NULL;
	}

	if (r_buf_fread_at (bf->buf, 0, (ut8 *)&header, "IIIIIIII", 1) != sizeof (header)) {
		return NULL;
	}

	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}

	ret->file = strdup (bf->file);
	ret->bclass = strdup ("program");
	ret->rclass = strdup ("p9");
	ret->os = strdup ("Plan9");
	ret->default_cc = strdup ("p9");
	ret->arch = strdup (arch);
	ret->machine = strdup (ret->arch);
	ret->subsystem = strdup ("plan9");
	ret->type = strdup ("EXEC (executable file)");
	ret->bits = bits;
	ret->has_va = true;
	ret->big_endian = big_endian;
	ret->dbg_info = 0;
	if (header.syms) {
		ret->dbg_info |= R_BIN_DBG_SYMS;
	}
	if (header.pcsz) {
		ret->dbg_info |= R_BIN_DBG_LINENUMS;
	}
	if (!ret->dbg_info) {
		ret->dbg_info |= R_BIN_DBG_STRIPPED;
	}
	return ret;
}

static ut64 size(RBinFile *bf) {
	if (!bf) {
		return 0;
	}
	if (!bf->bo->info) {
		bf->bo->info = info (bf);
	}
	if (!bf->bo->info) {
		return 0;
	}

	struct plan9_exec header;
	if (r_buf_fread_at (bf->buf, 0, (ut8 *)&header, "IIIIIIII", 1) != sizeof (header)) {
		return 0;
	}

	ut64 size = sizeof (header);

	// there may be an additional 64-bit entry after the header
	if (header.magic & HDR_MAGIC) {
		size += 8;
	}

	size += header.text;
	size += header.data;
	size += header.syms;
	size += header.spsz;
	size += header.pcsz;

	return size;
}

#if !R_BIN_P9

/* inspired in http://www.phreedom.org/solar/code/tinype/tiny.97/tiny.asm */
static RBuffer *create(RBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen, RBinArchOptions *opt) {
	RBuffer *buf = r_buf_new ();
#define B(x, y) r_buf_append_bytes (buf, (const ut8 *) (x), y)
#define D(x) r_buf_append_ut32 (buf, x)
	D (MAGIC_INTEL_386); // i386 only atm
	D (codelen);
	D (datalen);
	D (4096); // bss
	D (0); // syms
	D (8 * 4); // entry
	D (4096); // spsz
	D (4096); // pcsz
	B (code, codelen);
	if (datalen > 0) {
		B (data, datalen);
	}
	return buf;
}

RBinPlugin r_bin_plugin_p9 = {
	.meta = {
		.name = "p9",
		.desc = "Plan 9 bin plugin",
		.author = "keegan",
		.license = "MIT",
	},
	.load = &load,
	.size = &size,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.info = &info,
	.libs = &libs,
	// .dbginfo = &r_bin_dbginfo_p9,
	.create = &create,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_p9,
	.version = R2_VERSION
};
#endif
#endif
