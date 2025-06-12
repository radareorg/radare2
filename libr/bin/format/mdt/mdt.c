/* radare2 - LGPL - Copyright 2025 - Rot127 <unisono@quyllur.org> (ported from rizin2) */

#include "mdt.h"
#include "../elf/elf.h"
#include <r_bin.h>
#include <r_util.h>

static inline bool is_layout_bin(size_t p_flags) {
	return (p_flags & QCOM_MDT_TYPE_MASK) == QCOM_MDT_TYPE_LAYOUT;
}

R_IPI RBinMdtPart *r_bin_mdt_part_new(const char *name, size_t p_flags) {
	RBinMdtPart *part = R_NEW0 (RBinMdtPart);
	part->name = strdup (name);
	part->relocatable = p_flags & QCOM_MDT_RELOCATABLE;
	part->is_layout = is_layout_bin (p_flags);
	return part;
}

R_IPI void r_bin_mdt_part_free(RBinMdtPart *part) {
	if (!part) {
		return;
	}
	r_buf_free (part->vfile_buf);
	free (part->vfile_name);
	switch (part->format) {
	default:
		break;
	case R_BIN_MDT_PART_ELF:
		Elf_(free) (part->obj.elf);
		break;
	case R_BIN_MDT_PART_MBN:
		// mbn_destroy_obj (part->obj.mbn);
		free (part->obj.mbn); // For now, just free it
		break;
	}
	if (part->map) {
		free (part->map->file);
		free (part->map);
	}
	r_list_free (part->relocs);
	r_list_free (part->symbols);
	r_list_free (part->sections);
	r_list_free (part->sub_maps);
	free (part->patches_vfile_name);
	free (part->relocs_vfile_name);
	free (part->name);
	free (part);
}

R_IPI RBinMdtObj *r_bin_mdt_obj_new(void) {
	RBinMdtObj *obj = R_NEW0 (RBinMdtObj);
	obj->parts = r_list_newf ((RListFree)r_bin_mdt_part_free);
	return obj;
}

R_IPI void r_bin_mdt_obj_free(RBinMdtObj *obj) {
	if (!obj) {
		return;
	}
	Elf_(free) (obj->header);
	r_list_free (obj->parts);
	free (obj->name);
	free (obj);
}

static inline bool is_elf32(RBuffer *b) {
	ut8 magic[4];
	r_buf_read_at (b, 0, magic, 4);
	return magic[0] == ELFMAG0 && magic[1] == ELFMAG1 &&
	       magic[2] == ELFMAG2 && magic[3] == ELFMAG3;
}

R_IPI bool r_bin_mdt_check_buffer(RBuffer *b) {
	R_RETURN_VAL_IF_FAIL (b, false);
	if (!is_elf32 (b) || r_buf_size (b) <= 0x34) {
		return false;
	}

	// Simple check: read first segment flags to check for MDT layout marker
	ut32 flags = 0;
	if (r_buf_read_at (b, 0x34 + 0x18, (ut8*)&flags, 4) == 4) {
		return is_layout_bin (flags);
	}
	return false;
}

R_IPI bool r_bin_mdt_check_filename(const char *filename) {
	R_RETURN_VAL_IF_FAIL (filename, false);
	return r_str_endswith (filename, ".mdt");
}