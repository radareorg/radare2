/*
 * Copyright (c) FFRI Security, Inc., 2023 / Author: FFRI Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define R_LOG_ORIGIN "xtac"

#include <r_bin.h>
#include "../format/xtac/xtac.h"

#define GET_META_DATA(v) (((v)&0xF0000000) >> 28)
#define GET_OFFSET(v)    ((v)&0x0FFFFFFF)

static inline bool has_forward_edge_addr(ut8 meta) {
	return (meta & 0x1) == 0x1;
}

static inline bool has_backward_edge_addr(ut8 meta) {
	return (meta & 0x2) == 0x2;
}

static RList *sections(RBinFile *bf) {
	RBinXtacObj *bin = bf->bo->bin_obj;

	RList *ret = r_list_newf ((RListFree)r_bin_section_free);

	RBinSection *ptr_sect_header = NULL, *ptr_sect_blck = NULL, *ptr_sect_trans_code = NULL;

	if (!(ptr_sect_header = R_NEW0 (RBinSection))) {
		r_list_free (ret);
		return NULL;
	}
	ptr_sect_header->name = strdup ("header");
	ptr_sect_header->vsize = bin->header->ptr_to_head_blck_stub;
	ptr_sect_header->paddr = ptr_sect_header->vaddr = 0;
	ptr_sect_header->perm = R_PERM_R;
	r_list_append (ret, ptr_sect_header);

	ut32 blck_stub_code_size = bin->header->size_of_blck_stub_code + 8; // NOTE: always 8 bytes data is padded.
	ut32 ptr_addr = bin->header->ptr_to_head_blck_stub + sizeof (RBinBlckStubHeader) - 4;
	int i;
	for (i = 0; i < bin->blck_stubs->length; i++) {
		RBinBlckStubHeader *blck_stub_header = (RBinBlckStubHeader *)r_list_get_n (bin->blck_stubs, i);

		if (!(ptr_sect_blck = R_NEW0 (RBinSection))) {
			r_list_free (ret);
			return NULL;
		}

		ptr_sect_blck->name = r_str_newf ("blck_code_%d", i);
		ptr_sect_blck->vsize = blck_stub_code_size;
		ptr_sect_blck->paddr = ptr_addr;
		ptr_sect_blck->vaddr = ptr_addr;
		ptr_sect_blck->perm = R_PERM_RX;
		ptr_addr += blck_stub_code_size;
		r_list_append (ret, ptr_sect_blck);

		if (!(ptr_sect_trans_code = R_NEW0 (RBinSection))) {
			r_list_free (ret);
			return NULL;
		}

		const ut32 size_of_trans_code = blck_stub_header->offset_to_next_entry - blck_stub_code_size;

		ptr_sect_trans_code->name = r_str_newf ("trans_code_%d", i);
		ptr_sect_trans_code->vsize = size_of_trans_code;
		ptr_sect_trans_code->paddr = ptr_addr;
		ptr_sect_trans_code->vaddr = ptr_addr;
		ptr_sect_trans_code->perm = R_PERM_RX;
		ptr_addr += size_of_trans_code;
		r_list_append (ret, ptr_sect_trans_code);

		ptr_addr += sizeof (RBinBlckStubHeader) - 4;
	}

	return ret;
}

static RList *fields(RBinFile *bf) {
	RList *ret = r_list_new ();
	if (!ret) {
		return NULL;
	}

#define ROWL(nam, siz, val, fmt) \
	r_list_append (ret, r_bin_field_new (addr, addr, val, siz, nam, NULL, fmt, false));
	RBinXtacObj *bin = bf->bo->bin_obj;

	ut64 addr = 0;
	ROWL ("magic", 4, bin->header->magic, "x");
	addr += 4;
	ROWL ("version", 4, bin->header->version, "x");
	addr += 4;
	ROWL ("is_updated", 4, bin->header->is_updated, "x");
	addr += 4;
	ROWL ("ptr_to_addr_pairs", 4, bin->header->ptr_to_addr_pairs, "x");
	addr += 4;
	ROWL ("num_of_addr_pairs", 4, bin->header->num_of_addr_pairs, "x");
	addr += 4;

	r_list_append (ret, r_bin_field_new (bin->header->ptr_to_mod_name, bin->header->ptr_to_mod_name, 0, 0, "mod_name", strdup (bin->mod_name_u8), "s", false));
	ROWL ("ptr_to_mod_name", 4, bin->header->ptr_to_mod_name, "x");
	addr += 4;
	ROWL ("size_of_mod_name", 4, bin->header->size_of_mod_name, "x");
	addr += 4;

	r_list_append (ret, r_bin_field_new (bin->header->ptr_to_nt_pname, bin->header->ptr_to_nt_pname, 0, 0, "nt_pname", strdup (bin->nt_path_name_u8), "s", false));
	ROWL ("ptr_to_nt_pname", 4, bin->header->ptr_to_nt_pname, "x");
	addr += 4;
	ROWL ("size_of_nt_pname", 4, bin->header->size_of_nt_pname, "x");
	addr += 4;

	ROWL ("ptr_to_head_blck_stub", 4, bin->header->ptr_to_head_blck_stub, "x");
	addr += 4;
	ROWL ("ptr_to_tail_blck_stub", 4, bin->header->ptr_to_tail_blck_stub, "x");
	addr += 4;
	ROWL ("size_of_blck_stub_code", 4, bin->header->size_of_blck_stub_code, "x");
	addr += 4;
	ROWL ("ptr_to_xtac_linked_list_head", 4, bin->header->ptr_to_xtac_linked_list_head, "x");
	addr += 4;
	ROWL ("ptr_to_xtac_linked_list_tail", 4, bin->header->ptr_to_xtac_linked_list_tail, "x");
	addr += 4;

	addr = bin->header->ptr_to_addr_pairs;
	int i;
	ut64 last = r_buf_size (bf->buf);
	for (i = 0; addr < last && i < bin->header->num_of_addr_pairs; i++) {
		char *x86_rva_key_name = r_str_newf ("address_pairs[%d].x86_rva", i);
		char *arm64_rva_key_name = r_str_newf ("address_pairs[%d].arm64_rva", i);

		ROWL (x86_rva_key_name, 4, bin->address_pairs[i].x86_rva, "x");
		addr += 4;
		ROWL (arm64_rva_key_name, 4, bin->address_pairs[i].arm64_rva, "x");
		addr += 4;

		R_FREE (x86_rva_key_name);
		R_FREE (arm64_rva_key_name);
	}

	for (i = 0; i < bin->blck_stubs->length; i++) {
		char *blck_key_name = r_str_newf ("blck_stub[%d]", i);
		RBinBlckStubHeader *blck_stub = (RBinBlckStubHeader *)r_list_get_n (bin->blck_stubs, i);

		addr = blck_stub->ptr_to_entry;
		if (addr < last) {
			continue;
		}

		char *key_blck_magic = r_str_newf ("%s.magic", blck_key_name);
		ROWL (key_blck_magic, 4, blck_stub->magic, "x");
		addr += 4;
		R_FREE (key_blck_magic);

		char *key_blck_offset_to_next_entry = r_str_newf ("%s.offset_to_next_entry", blck_key_name);
		ROWL (key_blck_offset_to_next_entry, 4, blck_stub->offset_to_next_entry, "x");
		addr += 4;
		R_FREE (key_blck_offset_to_next_entry);

		char *key_blck_ptr_to_next_entry = r_str_newf ("%s.ptr_to_next_entry", blck_key_name);
		ROWL (key_blck_ptr_to_next_entry, 4, blck_stub->ptr_to_next_entry, "x");
		addr += 4;
		R_FREE (key_blck_ptr_to_next_entry);

		char *key_blck_padding = r_str_newf ("%s.padding", blck_key_name);
		ROWL (key_blck_padding, 4, blck_stub->padding, "x");
		addr += 4;
		R_FREE (key_blck_padding);

		R_FREE (blck_key_name);
	}

	for (i = 0; i < bin->xtac_linked_list->length; i++) {
		char *entry_key_name = r_str_newf ("xtac_linked_list[%d]", i);
		RBinXtacLinkedListEntry *entry = (RBinXtacLinkedListEntry *)r_list_get_n (bin->xtac_linked_list, i);
		addr = entry->ptr_to_entry;
		if (addr < last) {
			continue;
		}

		char *key_meta_and_offset = r_str_newf ("%s.meta_and_offset", entry_key_name);
		ROWL (key_meta_and_offset, 4, entry->meta_and_offset, "x");
		addr += 4;
		R_FREE (key_meta_and_offset);

		const ut8 meta = GET_META_DATA (entry->meta_and_offset);
		if (has_forward_edge_addr (meta)) {
			char *key_forward_edge_addr = r_str_newf ("%s.forward_edge_addr", entry_key_name);
			ROWL (key_forward_edge_addr, 4, entry->forward_edge_addr, "x");
			addr += 4;
			R_FREE (key_forward_edge_addr);
		}

		if (has_backward_edge_addr (meta)) {
			char *key_backward_edge_addr = r_str_newf ("%s.backward_edge_addr", entry_key_name);
			ROWL (key_backward_edge_addr, 4, entry->backward_edge_addr, "x");
			addr += 4;
			R_FREE (key_backward_edge_addr);
		}

		R_FREE (entry_key_name);
	}

	return ret;

#undef ROWL
}

static void header(RBinFile *bf) {
	RBinXtacObj *bin = bf->bo->bin_obj;
	struct r_bin_t *rbin = bf->rbin;
	rbin->cb_printf ("XTAC file header:\n");
	rbin->cb_printf ("  magic : 0x%x\n", bin->header->magic);
	rbin->cb_printf ("  version : 0x%x\n", bin->header->version);
	rbin->cb_printf ("  is_updated : 0x%x\n", bin->header->is_updated);
	rbin->cb_printf ("  ptr_to_addr_pairs : 0x%x\n", bin->header->ptr_to_addr_pairs);
	rbin->cb_printf ("  num_of_addr_pairs : 0x%x\n", bin->header->num_of_addr_pairs);

	rbin->cb_printf ("  ptr_to_mod_name : 0x%x\n", bin->header->ptr_to_mod_name);
	rbin->cb_printf ("  size_of_mod_name : 0x%x\n", bin->header->size_of_mod_name);
	rbin->cb_printf ("  module name : %s\n", bin->mod_name_u8);

	rbin->cb_printf ("  ptr_to_nt_pname : 0x%x\n", bin->header->ptr_to_nt_pname);
	rbin->cb_printf ("  size_of_nt_pname : 0x%x\n", bin->header->size_of_nt_pname);
	rbin->cb_printf ("  module name : %s\n", bin->nt_path_name_u8);

	rbin->cb_printf ("  ptr_to_head_blck_stub : 0x%x\n", bin->header->ptr_to_head_blck_stub);
	rbin->cb_printf ("  ptr_to_tail_blck_stub : 0x%x\n", bin->header->ptr_to_tail_blck_stub);
	rbin->cb_printf ("  size_of_blck_stub_code : 0x%x\n", bin->header->size_of_blck_stub_code);
	rbin->cb_printf ("  ptr_to_xtac_linked_list_head : 0x%x\n", bin->header->ptr_to_xtac_linked_list_head);
	rbin->cb_printf ("  ptr_to_xtac_linked_list_tail : 0x%x\n", bin->header->ptr_to_xtac_linked_list_tail);

	rbin->cb_printf ("address pairs (x86, arm64):\n");
	const ut32 n_addr_pairs = bin->header->num_of_addr_pairs;
	ut32 i;
	for (i = 0; i < n_addr_pairs; i++) {
		rbin->cb_printf ("  0x%x, 0x%x\n", bin->address_pairs[i].x86_rva, bin->address_pairs[i].arm64_rva);
	}

	rbin->cb_printf ("blck stubs:\n");
	RBinBlckStubHeader *blck_stub = NULL;
	RListIter *iter = NULL;
	r_list_foreach (bin->blck_stubs, iter, blck_stub) {
		rbin->cb_printf ("  blck stub entry\n");
		rbin->cb_printf ("    ptr_to_entry : 0x%x\n", blck_stub->ptr_to_entry);
		rbin->cb_printf ("    magic : 0x%x\n", blck_stub->magic);
		rbin->cb_printf ("    offset_to_next_entry : 0x%x\n", blck_stub->offset_to_next_entry);
		rbin->cb_printf ("    ptr_to_next_entry : 0x%x\n", blck_stub->ptr_to_next_entry);
		rbin->cb_printf ("    padding : 0x%x\n", blck_stub->padding);
	}

	rbin->cb_printf ("xtac linked list:\n");
	RBinXtacLinkedListEntry *entry = NULL;
	r_list_foreach (bin->xtac_linked_list, iter, entry) {
		rbin->cb_printf ("  xtac linked list entry\n");
		rbin->cb_printf ("    ptr_to_entry : 0x%x\n", entry->ptr_to_entry);
		rbin->cb_printf ("    meta_data : 0x%x\n", GET_META_DATA (entry->meta_and_offset));
		rbin->cb_printf ("    offset_to_next_entry : 0x%x\n", GET_OFFSET (entry->meta_and_offset) * 4);
		rbin->cb_printf ("    forward_edge_addr : 0x%x\n", entry->forward_edge_addr);
		rbin->cb_printf ("    backward_edge_addr : 0x%x\n", entry->backward_edge_addr);
	}
}

static bool r_bin_xtac_read_header(RBinXtacObj *bin) {
	if (!(bin->header = R_NEW0 (RBinXtacHeader))) {
		return false;
	}
	if (r_buf_read_at (bin->b, 0, (ut8 *)bin->header, sizeof (RBinXtacHeader)) < 0) {
		R_LOG_WARN ("Read (xtac header)");
		R_FREE (bin->header);
		return false;
	}
	return true;
}

static bool r_bin_xtac_read_address_pairs(RBinXtacObj *bin) {
	const ut32 n_addr_pairs = bin->header->num_of_addr_pairs;
	const ut32 addr_pair_size = n_addr_pairs * sizeof (X86ArmAddrPair);
	const ut32 p_addr_pair = bin->header->ptr_to_addr_pairs;
	if (n_addr_pairs > 0xfffff) {
		return false;
	}
	if (!(bin->address_pairs = R_NEWS0 (X86ArmAddrPair, n_addr_pairs))) {
		return false;
	}
	if (r_buf_read_at (bin->b, p_addr_pair, (ut8 *)bin->address_pairs, addr_pair_size) < 0) {
		R_LOG_WARN ("Read (xtac address pairs)");
		R_FREE (bin->address_pairs);
		return false;
	}
	return true;
}

static bool r_bin_xtac_read_module_name(RBinXtacObj *bin) {
	const ut32 len_of_mod_name = bin->header->size_of_mod_name / sizeof (ut16) + 1;
	const ut32 p_mod_name = bin->header->ptr_to_mod_name;
	if (len_of_mod_name > 0xfff) {
		return false;
	}
	if (!(bin->mod_name_u16 = R_NEWS0 (ut16, len_of_mod_name))) {
		return false;
	}
	if (r_buf_read_at (bin->b, p_mod_name, (ut8 *)bin->mod_name_u16, bin->header->size_of_mod_name) < 0) {
		R_LOG_WARN ("Read (xtac module name)");
		R_FREE (bin->mod_name_u16);
		return false;
	}
	if (!(bin->mod_name_u8 = r_str_utf16_decode ((ut8 *)bin->mod_name_u16, bin->header->size_of_mod_name))) {
		R_FREE (bin->mod_name_u16);
		return false;
	}
	return true;
}

static bool r_bin_xtac_read_nt_native_pathname(RBinXtacObj *bin) {
	const ut32 len_of_nt_pname = (bin->header->size_of_nt_pname / sizeof (ut16)) + 1;
	const ut32 p_nt_name = bin->header->ptr_to_nt_pname;
	if (len_of_nt_pname > 0xfff) {
		return false;
	}
	if (!(bin->nt_path_name_u16 = R_NEWS0 (ut16, len_of_nt_pname))) {
		return false;
	}
	const ut32 size_read = r_buf_read_at (bin->b, p_nt_name, (ut8 *)bin->nt_path_name_u16, bin->header->size_of_nt_pname);
	if (size_read != bin->header->size_of_nt_pname) {
		R_LOG_WARN ("Read (xtac nt path)");
		R_FREE (bin->nt_path_name_u16);
		return false;
	}

	char *nt_path_name_u8_raw;
	if (!(nt_path_name_u8_raw = r_str_utf16_decode ((ut8 *)bin->nt_path_name_u16, bin->header->size_of_nt_pname))) {
		R_FREE (bin->nt_path_name_u16);
		return false;
	}

	if (!(bin->nt_path_name_u8 = r_str_escape_utf8_for_json (nt_path_name_u8_raw, -1))) {
		R_FREE (bin->nt_path_name_u16);
		R_FREE (nt_path_name_u8_raw);
		return false;
	}

	R_FREE (nt_path_name_u8_raw);

	return true;
}

static bool r_bin_xtac_read_blck_stubs(RBinXtacObj *bin) {
	if (!(bin->blck_stubs = r_list_newf (free))) {
		return false;
	}
	const ut32 max_depth = 20;
	ut32 i = 0;
	ut32 p_blck_stub = bin->header->ptr_to_head_blck_stub;
	do {
		RBinBlckStubHeader *blck_stub = NULL;
		if (!(blck_stub = R_NEW0 (RBinBlckStubHeader))) {
			return false;
		}
		if (r_buf_read_at (bin->b, p_blck_stub, (ut8 *)blck_stub, sizeof (RBinBlckStubHeader) - sizeof (ut32)) < 0) {
			R_LOG_WARN ("Read (xtac BLCK stub)");
			R_FREE (blck_stub);
			return false;
		}
		blck_stub->ptr_to_entry = p_blck_stub;
		r_list_append (bin->blck_stubs, blck_stub);
		if (p_blck_stub == blck_stub->ptr_to_next_entry) {
			R_LOG_WARN ("An infinite loop is detected. Some header members of BOCK Stub might be broken");
			break;
		}
		p_blck_stub = blck_stub->ptr_to_next_entry;
		i++;
		if (i >= max_depth) {
			R_LOG_WARN ("Too many BLCK Stubs. Some header members of BLCK Stub might be broken");
			break;
		}
	} while (p_blck_stub);
	return true;
}

static bool r_bin_xtac_read_xtac_linked_list(RBinXtacObj *bin) {
	if (!(bin->xtac_linked_list = r_list_newf (free))) {
		return false;
	}
	RBinXtacLinkedListEntry *entry = NULL;
	ut32 p_xtac_linked_list_entry = bin->header->ptr_to_xtac_linked_list_head;
	if (p_xtac_linked_list_entry > bin->size) {
		return false;
	}
	do {
		ut32 p_buffer = p_xtac_linked_list_entry;

		if (!(entry = R_NEW0 (RBinXtacLinkedListEntry))) {
			return false;
		}
		entry->ptr_to_entry = p_buffer;

		if (r_buf_read_at (bin->b, p_buffer, (ut8 *)entry, sizeof (ut32)) < 0) {
			R_LOG_WARN ("Read (xtac linked list metadata)");
			R_FREE (entry);
			return false;
		}

		const ut32 meta = GET_META_DATA (entry->meta_and_offset);
		if (has_forward_edge_addr (meta)) {
			p_buffer += sizeof (ut32);
			if (r_buf_read_at (bin->b, p_buffer, (ut8 *)&entry->forward_edge_addr, sizeof (ut32)) < 0) {
				R_LOG_WARN ("Read (xtac linked list forward edge address)");
				R_FREE (entry);
				return false;
			}
		}
		if (has_backward_edge_addr (meta)) {
			p_buffer += sizeof (ut32);
			if (r_buf_read_at (bin->b, p_buffer, (ut8 *)&entry->backward_edge_addr, sizeof (ut32)) < 0) {
				R_LOG_WARN ("Read (xtac linked list backward edge address)");
				R_FREE (entry);
				return false;
			}
		}

		r_list_append (bin->xtac_linked_list, entry);
		int a = entry->meta_and_offset;
		if (a < 1 || a > 0xfff) {
			break;
		}
		p_xtac_linked_list_entry += (a * 4);
	} while (p_xtac_linked_list_entry < bin->header->ptr_to_addr_pairs);

	if (GET_OFFSET (entry->meta_and_offset) != 0x0FFFFFFF) {
		R_LOG_WARN ("xtac linked list is not properly terminated");
		R_LOG_WARN ("Some entry of xtac linked list might be broken");
	}

	return true;
}

static bool r_bin_xtac_init(RBinXtacObj *bin) {
	// NOTE: not tested on big-endian processor
	if (!r_bin_xtac_read_header (bin)) {
		return false;
	}

	if (!r_bin_xtac_read_address_pairs (bin)) {
		return false;
	}

	if (!r_bin_xtac_read_module_name (bin)) {
		return false;
	}

	if (!r_bin_xtac_read_nt_native_pathname (bin)) {
		return false;
	}

	if (!r_bin_xtac_read_blck_stubs (bin)) {
		return false;
	}

	if (!r_bin_xtac_read_xtac_linked_list (bin)) {
		return false;
	}

	return true;
}

static void r_bin_xtac_free(RBinXtacObj *bin) {
	if (!bin) {
		return;
	}
	R_FREE (bin->header);
	R_FREE (bin->address_pairs);
	R_FREE (bin->mod_name_u16);
	R_FREE (bin->mod_name_u8);
	R_FREE (bin->nt_path_name_u16);
	R_FREE (bin->nt_path_name_u8);

	r_buf_free (bin->b);
	bin->b = NULL;

	r_list_free (bin->blck_stubs);
	r_list_free (bin->xtac_linked_list);
	bin->blck_stubs = NULL;
	bin->xtac_linked_list = NULL;

	R_FREE (bin);
	return;
}

static RBinXtacObj *r_bin_xtac_new_buf(RBuffer *buf, bool verbose) {
	RBinXtacObj *bin = R_NEW0 (RBinXtacObj);
	if (R_LIKELY (bin)) {
		bin->b = r_buf_ref (buf);
		bin->size = r_buf_size (buf);
		bin->verbose = verbose;
		if (!r_bin_xtac_init (bin)) {
			r_bin_xtac_free (bin);
			bin = NULL;
		}
	}
	return bin;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	R_RETURN_VAL_IF_FAIL (bf && buf, false);
	RBinXtacObj *res = r_bin_xtac_new_buf (buf, bf->rbin->options.verbose);
	if (res) {
		bf->bo->bin_obj = res;
		return true;
	}
	return false;
}

static void destroy(RBinFile *bf) {
	r_bin_xtac_free ((RBinXtacObj *)bf->bo->bin_obj);
}

static ut64 baddr(RBinFile *bf) {
	return bf->bo->baddr;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->lang = NULL;
	ret->arch = strdup ("arm");
	ret->cpu = strdup ("v8");
	ret->bits = 64;
	ret->big_endian = 0;
	ret->file = bf->file? strdup (bf->file): NULL;
	ret->type = strdup ("XTAC");
	ret->has_pi = 0;
	ret->has_canary = 0;
	ret->has_retguard = -1;
	ret->big_endian = 0;
	ret->has_va = 0;
	ret->has_nx = 0;
	ret->dbg_info = 0;
	ret->dbg_info = 0;
	ret->dbg_info = 0;
	return ret;
}

static bool check(RBinFile *file, RBuffer *b) {
	ut64 length = r_buf_size (b);
	if (length <= sizeof (RBinXtacHeader)) {
		return false;
	}

	ut8 buf[sizeof (XTAC_MAGIC) - 1];
	r_buf_read_at (b, 0, buf, sizeof (buf));
	return memcmp (buf, XTAC_MAGIC, sizeof (buf)) == 0;
}

static RList *symbols(RBinFile *bf) {
	RBinXtacObj *bin = bf->bo->bin_obj;

	ut64 x86_baddr = baddr (bf), arm_baddr = 0x0;

	RList *ret = r_list_newf (free);

	RBinSymbol *ptr = NULL;
	const ut32 num_pairs = bin->header->num_of_addr_pairs;
	int i;
	for (i = 0; i < num_pairs; i++) {
		if (!(ptr = R_NEW0 (RBinSymbol))) {
			break;
		}
		const ut32 x86_vaddr = bin->address_pairs[i].x86_rva + x86_baddr;
		const ut32 arm_vaddr = bin->address_pairs[i].arm64_rva + arm_baddr;
		if (arm_vaddr == UT32_MAX || x86_vaddr == UT32_MAX) {
			continue;
		}
		ptr->name = r_bin_name_new_from (r_str_newf ("x86.%08x", x86_vaddr));
		ptr->bind = "NONE";
		ptr->type = R_BIN_TYPE_FUNC_STR;
		ptr->size = 0;
		ptr->paddr = arm_vaddr;
		ptr->vaddr = ptr->paddr;
		ptr->ordinal = i;
		r_list_append (ret, ptr);
	}

	return ret;
}

RBinPlugin r_bin_plugin_xtac = {
	.meta = {
		.name = "xtac",
		.author = "FFRI Security",
		.desc = "Compiled XTA Cache File from Windows/ARM JIT",
		.license = "Apache-2.0",
	},
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.minstrlen = 6,
	.info = &info,
	.fields = &fields,
	.header = &header,
	.symbols = &symbols,
	.sections = &sections,
};
