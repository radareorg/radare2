/* radare2 - MIT - Copyright 2023-2024 - keegan */

#define R_LOG_ORIGIN "bin.dis"

#include <r_bin.h>

#include "../../arch/p/dis/dis.h"
#include "../../arch/p/dis/dis.c"

static bool check(RBinFile *bf, RBuffer *buf) {
	ut64 pos = r_buf_tell (buf);
	r_buf_seek (buf, 0, R_BUF_SET);
	st32 magic;
	if (!dis_read_operand (buf, &magic)) {
		return false;
	}
	r_buf_seek (buf, pos, R_BUF_SET);
	// ensure size is bigger than the smallest possible header (since op is
	// variable-length encoded)
	return (magic == XMAGIC || magic == SMAGIC) && r_buf_size (buf) > 12;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	ut32 i;

	if (!check (bf, buf)) {
		return false;
	}

	RBinDisObj *o = R_NEW0 (RBinDisObj);

	o->pcs = ht_uu_new0 ();

	if (!dis_read_operand (buf, &o->header.magic)) {
		goto invalid;
	}
	// skip signature, if needed
	if (o->header.magic == SMAGIC) {
		st32 signature_size;
		if (!dis_read_operand (buf, &signature_size)) {
			goto invalid;
		}
		if (signature_size < 0) {
			goto invalid;
		}
		r_buf_seek (buf, signature_size, R_BUF_CUR);
	}

	if (!dis_read_operand (buf, &o->header.runtime_flags)) {
		goto invalid;
	}

	if (!dis_read_operand (buf, &o->header.stack_extent)) {
		goto invalid;
	}
	if (o->header.stack_extent < 0) {
		goto invalid;
	}

	if (!dis_read_operand (buf, &o->header.code_size)) {
		goto invalid;
	}
	if (o->header.code_size < 1) {
		goto invalid;
	}

	if (!dis_read_operand (buf, &o->header.data_size)) {
		goto invalid;
	}
	if (o->header.data_size < 0) {
		goto invalid;
	}

	if (!dis_read_operand (buf, &o->header.type_size)) {
		goto invalid;
	}
	if (o->header.type_size < 0) {
		goto invalid;
	}

	if (!dis_read_operand (buf, &o->header.link_size)) {
		goto invalid;
	}
	if (o->header.link_size < 0) {
		goto invalid;
	}

	if (!dis_read_operand (buf, &o->header.entry_pc)) {
		goto invalid;
	}
	if (o->header.entry_pc < 0) {
		goto invalid;
	}

	if (!dis_read_operand (buf, &o->header.entry_type)) {
		goto invalid;
	}
	if (o->header.entry_type < 0) {
		goto invalid;
	}

	o->header_size = r_buf_tell (buf);

	// in order to determine the size of the code section, we must parse
	// all instructions. if we encounter an invalid instruction we must fail
	// because instruction sizes are variable.
	ut64 addr = r_buf_tell (buf);
	const st32 code_size = o->header.code_size;
	for (i = 0; i < code_size; i++) {
		struct dis_instr instr = {0};
		ht_uu_insert (o->pcs, i, r_buf_tell (buf));
		if (!dis_read_instr (buf, &instr)) {
			R_LOG_ERROR ("Bad Dis instruction (pc is 0x%x)", i);
			goto invalid;
		}
	}
	o->code_size = r_buf_tell (buf) - addr;

	// parse type section
	addr = r_buf_tell (buf);
	const st32 type_size = o->header.type_size;
	for (i = 0; i < type_size; i++) {
		struct dis_type typ = {0};
		if (!dis_read_type (buf, &typ)) {
			goto invalid;
		}
	}
	o->type_size = r_buf_tell (buf) - addr;

	addr = r_buf_tell (buf);
	// module name (ignored)
	for (i = 0; ; i++) {
		ut8 b;
		if (r_buf_read (buf, &b, sizeof (b)) != sizeof (b)) {
			goto invalid;
		}
		if (b == 0) {
			break;
		}
	}
	o->module_name_size = r_buf_tell (buf) - addr;

	// parse link section
	addr = r_buf_tell (buf);
	const st32 link_size = o->header.link_size;
	for (i = 0; i < link_size; i++) {
		struct dis_link link = {0};
		if (!dis_read_link (buf, &link)) {
			goto invalid;
		}
	}
	o->link_size = r_buf_tell (buf) - addr;
	bf->bo->bin_obj = o;

	return true;
invalid:
	ht_uu_free (o->pcs);
	free (o);
	return false;
}

static void destroy(RBinFile *bf) {
	RBinDisObj *o = (RBinDisObj *)bf->bo->bin_obj;
	ht_uu_free (o->pcs);
	free (o);
}

static RList *entries(RBinFile *bf) {
	bool found;
	RBinDisObj *o = (RBinDisObj *)bf->bo->bin_obj;

	ut64 entry_address = ht_uu_find (o->pcs, o->header.entry_pc, &found);
	if (!found) {
		return NULL;
	}

	RList *ret = r_list_new ();
	ret->free = free;

	RBinAddr *ptr = R_NEW0 (RBinAddr);
	ptr->paddr = entry_address;
	ptr->vaddr = entry_address;
	r_list_append (ret, ptr);

	return ret;
}

static RList *sections(RBinFile *bf) {
	RBinDisObj *o = (RBinDisObj *)bf->bo->bin_obj;

	if (!bf->bo->info) {
		return NULL;
	}

	RList *ret = r_list_newf ((RListFree)free);

	ut64 addr = o->header_size;

	// add code section
	RBinSection *ptr = R_NEW0 (RBinSection);
	ptr->name = strdup ("code");
	ptr->size = ptr->vsize = o->code_size;
	ptr->paddr = ptr->vaddr = addr;
	ptr->perm = R_PERM_RX; // r-x
	ptr->add = true;
	r_list_append (ret, ptr);
	addr += ptr->size;

	// add types section
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("types");
	ptr->size = ptr->vsize = o->type_size;
	ptr->paddr = ptr->vaddr = addr;
	ptr->perm = R_PERM_R; // r--
	ptr->add = true;
	r_list_append (ret, ptr);
	addr += ptr->size;

	// add data section
	ptr = R_NEW0 (RBinSection);
	ptr->name = strdup ("data");
	ptr->size = ptr->vsize = o->header.data_size;
	ptr->paddr = ptr->vaddr = addr;
	ptr->perm = R_PERM_RW; // rw-
	ptr->add = true;
	r_list_append (ret, ptr);
	addr += ptr->size;

	// skip module name
	addr += o->module_name_size;

	// add link section
	ptr = R_NEW0 (RBinSection);
	ptr->name = strdup ("link");
	ptr->size = ptr->vsize = o->link_size;
	ptr->paddr = ptr->vaddr = addr;
	ptr->perm = R_PERM_R; // r--
	ptr->add = true;
	r_list_append (ret, ptr);
	addr += ptr->size;

	return ret;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = strdup (bf->file);
	ret->bclass = strdup ("program");
	ret->rclass = strdup ("dis");
	ret->os = strdup ("inferno");
	ret->arch = strdup ("dis");
	ret->machine = strdup ("Dis VM");
	ret->subsystem = strdup ("dis");
	ret->type = strdup ("DIS BYTECODE");
	ret->bits = 32;
	ret->big_endian = true;
	ret->dbg_info = 0;
	return ret;
}

RBinPlugin r_bin_plugin_dis = {
	.meta = {
		.name = "dis",
		.author = "keegan",
		.desc = "Inferno Dis Virtual Machine",
		.license = "MIT",
	},
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.entries = &entries,
	.sections = &sections,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_dis,
	.version = R2_VERSION
};
#endif
