/* radare2 - LGPL - Copyright 2009-2022 - nibble, pancake, keegan */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "../format/p9/p9bin.h"

#undef P9_ALIGN
#define P9_ALIGN(address, align) (((address) + (align - 1)) & ~(align - 1))

static bool check_buffer(RBinFile *bf, RBuffer *buf) {
	RSysArch arch;
	int bits, big_endian;
	return r_bin_p9_get_arch (buf, &arch, &bits, &big_endian);
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *b, ut64 loadaddr, Sdb *sdb) {
	if (!check_buffer (bf, b)) {
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

	if (bin_obj) {
		*bin_obj = o;
	}

	return true;
}

static void destroy(RBinFile *bf) {
	free (bf->o->bin_obj);
}

static ut64 baddr(RBinFile *bf) {
	RBinPlan9Obj *o = (RBinPlan9Obj *)bf->o->bin_obj;

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

	// unreachable because check_buffer only supports the above architectures
	return 0;
}

static RBinAddr *binsym(RBinFile *bf, int type) {
	return NULL;
}

static RList *entries(RBinFile *bf) {
	RList *ret;
	RBinAddr *ptr = NULL;
	RBinPlan9Obj *o = (RBinPlan9Obj *)bf->o->bin_obj;

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
	RBinPlan9Obj *o = (RBinPlan9Obj *)bf->o->bin_obj;

	if (!bf->o->info) {
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
	ptr->vsize = P9_ALIGN (o->header.text, align);
	ptr->paddr = phys;
	ptr->vaddr = baddr (bf);
	ptr->perm = R_PERM_RX; // r-x
	ptr->add = true;
	r_list_append (ret, ptr);
	phys += ptr->size;
	vsize += ptr->vsize;

	// for regular applications: header is included in the text segment
	if (!o->is_kernel) {
		phys += o->header_size;
	}

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

	// add spsz segment
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("spsz");
	ptr->size = o->header.spsz;
	ptr->vsize = P9_ALIGN (o->header.spsz, align);
	ptr->paddr = phys;
	ptr->vaddr = baddr (bf) + vsize;
	ptr->perm = R_PERM_R; // r--
	ptr->add = true;
	r_list_append (ret, ptr);
	phys += ptr->size;
	vsize += ptr->vsize;

	// add pcsz segment
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("pcsz");
	ptr->size = o->header.pcsz;
	ptr->vsize = P9_ALIGN (o->header.pcsz, align);
	ptr->paddr = phys;
	ptr->vaddr = baddr (bf) + vsize;
	ptr->perm = R_PERM_R; // r--
	ptr->add = true;
	r_list_append (ret, ptr);

	return ret;
}

static RList *symbols(RBinFile *bf) {
	RList *ret = NULL;
	RBinPlan9Obj *o = (RBinPlan9Obj *)bf->o->bin_obj;

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}

	ut64 syms = o->header_size + o->header.text + o->header.data;

	ut64 offset = 0;
	while (offset < o->header.syms) {
		ut64 value;
		if (o->header.magic & HDR_MAGIC) {
			// for 64-bit binaries the value type is 8 bytes
			value = r_buf_read_be64_at (bf->buf, syms + offset);
			if (value == UT64_MAX) {
				goto error;
			}
			offset += sizeof (ut64);
		} else {
			value = (ut64)r_buf_read_be32_at (bf->buf, syms + offset);
			if (value == UT32_MAX) {
				goto error;
			}
			offset += sizeof (ut32);
		}

		const ut8 typ = r_buf_read8_at (bf->buf, syms + offset);
		if (typ == UT8_MAX) {
			goto error;
		}
		offset += sizeof (typ);
		const char type = typ & 0x7f;

		char *name = r_buf_get_string (bf->buf, syms + offset);
		if (!name) {
			goto error;
		}
		offset += strlen (name) + 1;

		// source file names or source file line offsets contain additional details
		if (type == 'Z' || type == 'z') {
			// look for two adjacent zeros to terminate the sequence
			ut64 j, fin = (o->header.syms > offset)? o->header.syms - offset: 0;
			for (j = 0; j < fin; j++) {
				ut16 data = r_buf_read_be16_at (bf->buf, syms + offset + j);
				if (data == UT16_MAX) {
					goto error;
				}

				if (data == 0) {
					offset += j + sizeof (ut16);
					break;
				}
			}
		}

		// skip non symbol information
		switch (type) {
		case 'T':
		case 't':
		case 'L':
		case 'l':
		case 'D':
		case 'd':
		case 'B':
		case 'b':
			break;
		default:
			continue;
		}

		RBinSymbol *ptr = R_NEW0 (RBinSymbol);
		if (!ptr) {
			free (name);
			goto error;
		}

		ptr->name = name;
		ptr->paddr = value - baddr (bf);
		// for kernels the header is not mapped
		if (o->is_kernel) {
			ptr->paddr += o->header_size;
		}
		ptr->vaddr = value;
		ptr->size = 0;
		ptr->ordinal = 0;
		r_list_append (ret, ptr);
	}

	return ret;
error:
	r_list_free (ret);
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
	RSysArch arch;
	int bits, big_endian;

	if (!r_bin_p9_get_arch (bf->buf, &arch, &bits, &big_endian)) {
		return NULL;
	}

	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}

	ret->file = strdup (bf->file);
	ret->bclass = strdup ("program");
	ret->rclass = strdup ("p9");
	ret->os = strdup ("Plan9");
	ret->arch = strdup (r_sys_arch_str (arch));
	ret->machine = strdup (ret->arch);
	ret->subsystem = strdup ("plan9");
	ret->type = strdup ("EXEC (executable file)");
	ret->bits = bits;
	ret->has_va = true;
	ret->big_endian = big_endian;
	ret->dbg_info = 0;
	return ret;
}

static ut64 size(RBinFile *bf) {
	if (!bf) {
		return 0;
	}
	if (!bf->o->info) {
		bf->o->info = info (bf);
	}
	if (!bf->o->info) {
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
	.name = "p9",
	.desc = "Plan9 bin plugin",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.size = &size,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
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

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_p9,
	.version = R2_VERSION
};
#endif
#endif
