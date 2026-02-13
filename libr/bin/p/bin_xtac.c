/*
 * Copyright (c) FFRI Security, Inc., 2023-2026 / Author: FFRI Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
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

#define GET_META_DATA(v) (((v) & 0xF0000000) >> 28)
#define GET_OFFSET(v) ((v) & 0x0FFFFFFF)

static inline bool has_forward_edge_addr(ut8 meta) {
	return (meta & 0x1) == 0x1;
}

static inline bool has_backward_edge_addr(ut8 meta) {
	return (meta & 0x2) == 0x2;
}

static bool validate_header(RBinXtacObj *bin) {
	if (!bin || !bin->header) {
		return false;
	}
	ut64 buf_size = r_buf_size (bin->b);
	RBinXtacHeader *hdr = bin->header;
	if (hdr->num_of_addr_pairs > 0xfffff ||
		hdr->size_of_mod_name > 0xfff * sizeof (ut16) ||
		hdr->size_of_nt_pname > 0xfff * sizeof (ut16)) {
		return false;
	}
	if (UT64_ADD_OVFCHK (hdr->ptr_to_addr_pairs, (ut64)hdr->num_of_addr_pairs * sizeof (X86ArmAddrPair))) {
		return false;
	}
	if (UT64_ADD_OVFCHK (hdr->ptr_to_mod_name, hdr->size_of_mod_name)) {
		return false;
	}
	if (UT64_ADD_OVFCHK (hdr->ptr_to_nt_pname, hdr->size_of_nt_pname)) {
		return false;
	}
	if ((ut64)hdr->ptr_to_addr_pairs + (ut64)hdr->num_of_addr_pairs * sizeof (X86ArmAddrPair) > buf_size ||
		(ut64)hdr->ptr_to_mod_name + hdr->size_of_mod_name > buf_size ||
		(ut64)hdr->ptr_to_nt_pname + hdr->size_of_nt_pname > buf_size) {
		return false;
	}
	if (hdr->ptr_to_head_blck_stub > buf_size ||
		hdr->ptr_to_tail_blck_stub > buf_size ||
		hdr->ptr_to_xtac_linked_list_head > buf_size ||
		hdr->ptr_to_xtac_linked_list_tail > buf_size) {
		return false;
	}
	return true;
}

static RList *sections(RBinFile *bf) {
	RBinXtacObj *bin = bf->bo->bin_obj;
	if (!bin || !bin->header) {
		return NULL;
	}
	RBinXtacHeader *hdr = bin->header;

	RList *ret = r_list_newf ((RListFree)r_bin_section_free);

	RBinSection *s = R_NEW0 (RBinSection);
	s->name = strdup ("header");
	s->vsize = hdr->ptr_to_head_blck_stub;
	s->paddr = s->vaddr = 0;
	s->perm = R_PERM_R;
	r_list_append (ret, s);

	if (!bin->blck_stubs) {
		return ret; // No sections if no stubs
	}

	ut32 blck_stub_code_size = hdr->size_of_blck_stub_code + 8; // NOTE: always 8 bytes data is padded.
	ut32 ptr_addr = hdr->ptr_to_head_blck_stub + sizeof (RBinBlckStubHeader) - 4;
	int i;
	for (i = 0; i < bin->blck_stubs->length; i++) {
		RBinBlckStubHeader *blck_stub_header = (RBinBlckStubHeader *)r_list_get_n (bin->blck_stubs, i);

		s = R_NEW0 (RBinSection);
		s->name = r_str_newf ("blck_code_%d", i);
		s->vsize = blck_stub_code_size;
		s->paddr = ptr_addr;
		s->vaddr = ptr_addr;
		s->perm = R_PERM_RX;
		if (r_add_overflow (ptr_addr, blck_stub_code_size, &ptr_addr)) {
			free (s->name);
			free (s);
			continue;
		}
		r_list_append (ret, s);

		if (blck_stub_header->offset_to_next_entry < blck_stub_code_size) {
			continue; // Invalid offset, skip this section
		}
		const ut32 size_of_trans_code = blck_stub_header->offset_to_next_entry - blck_stub_code_size;

		s = R_NEW0 (RBinSection);
		s->name = r_str_newf ("trans_code_%d", i);
		s->vsize = size_of_trans_code;
		s->paddr = ptr_addr;
		s->vaddr = ptr_addr;
		s->perm = R_PERM_RX;
		if (r_add_overflow (ptr_addr, size_of_trans_code, &ptr_addr)) {
			free (s->name);
			free (s);
			continue;
		}
		r_list_append (ret, s);

		if (r_add_overflow (ptr_addr, (ut32)(sizeof (RBinBlckStubHeader) - 4), &ptr_addr)) {
			break;
		}
	}

	return ret;
}

static RList *fields(RBinFile *bf) {
	RList *ret = r_list_new ();
	if (!ret) {
		return NULL;
	}

#define ROWL(nam, siz, val, fmt) \
	do { \
		r_list_append (ret, r_bin_field_new (addr, addr, val, siz, nam, NULL, fmt, false)); \
		addr += (siz); \
	} while (0)
	RBinXtacObj *bin = bf->bo->bin_obj;
	RBinXtacHeader *hdr = bin->header;

	ut64 addr = 0;
	ROWL ("magic", 4, hdr->magic, "x");
	ROWL ("version", 4, hdr->version, "x");
	ROWL ("is_updated", 4, hdr->is_updated, "x");
	ROWL ("ptr_to_addr_pairs", 4, hdr->ptr_to_addr_pairs, "x");
	ROWL ("num_of_addr_pairs", 4, hdr->num_of_addr_pairs, "x");

	r_list_append (ret, r_bin_field_new (hdr->ptr_to_mod_name, hdr->ptr_to_mod_name, 0, 0, "mod_name", strdup (bin->mod_name_u8), "s", false));
	ROWL ("ptr_to_mod_name", 4, hdr->ptr_to_mod_name, "x");
	ROWL ("size_of_mod_name", 4, hdr->size_of_mod_name, "x");

	r_list_append (ret, r_bin_field_new (hdr->ptr_to_nt_pname, hdr->ptr_to_nt_pname, 0, 0, "nt_pname", strdup (bin->nt_path_name_u8), "s", false));
	ROWL ("ptr_to_nt_pname", 4, hdr->ptr_to_nt_pname, "x");
	ROWL ("size_of_nt_pname", 4, hdr->size_of_nt_pname, "x");

	ROWL ("ptr_to_head_blck_stub", 4, hdr->ptr_to_head_blck_stub, "x");
	ROWL ("ptr_to_tail_blck_stub", 4, hdr->ptr_to_tail_blck_stub, "x");
	ROWL ("size_of_blck_stub_code", 4, hdr->size_of_blck_stub_code, "x");
	ROWL ("ptr_to_xtac_linked_list_head", 4, hdr->ptr_to_xtac_linked_list_head, "x");
	ROWL ("ptr_to_xtac_linked_list_tail", 4, hdr->ptr_to_xtac_linked_list_tail, "x");

	addr = hdr->ptr_to_addr_pairs;
	int i;
	ut64 last = r_buf_size (bf->buf);
	for (i = 0; addr < last && i < hdr->num_of_addr_pairs; i++) {
		char *x86_rva_key_name = r_str_newf ("address_pairs[%d].x86_rva", i);
		char *arm64_rva_key_name = r_str_newf ("address_pairs[%d].arm64_rva", i);

		ROWL (x86_rva_key_name, 4, bin->address_pairs[i].x86_rva, "x");
		ROWL (arm64_rva_key_name, 4, bin->address_pairs[i].arm64_rva, "x");

		free (x86_rva_key_name);
		free (arm64_rva_key_name);
	}

	if (!bin->blck_stubs) {
		return ret; // No blck stubs to process
	}

	char *tmpstr;
	for (i = 0; i < bin->blck_stubs->length; i++) {
		char *bkn = r_str_newf ("blck_stub[%d]", i);
		RBinBlckStubHeader *blck_stub = (RBinBlckStubHeader *)r_list_get_n (bin->blck_stubs, i);

		addr = blck_stub->ptr_to_entry;
		if (addr <= last) {
			tmpstr = r_str_newf ("%s.magic", bkn);
			ROWL (tmpstr, 4, blck_stub->magic, "x");
			free (tmpstr);

			tmpstr = r_str_newf ("%s.offset_to_next_entry", bkn);
			ROWL (tmpstr, 4, blck_stub->offset_to_next_entry, "x");
			free (tmpstr);

			tmpstr = r_str_newf ("%s.ptr_to_next_entry", bkn);
			ROWL (tmpstr, 4, blck_stub->ptr_to_next_entry, "x");
			free (tmpstr);

			tmpstr = r_str_newf ("%s.padding", bkn);
			ROWL (tmpstr, 4, blck_stub->padding, "x");
			free (tmpstr);
		}
		free (bkn);
	}

	if (!bin->xtac_linked_list) {
		return ret; // No xtac linked list to process
	}

	for (i = 0; i < bin->xtac_linked_list->length; i++) {
		char *ekn = r_str_newf ("xtac_linked_list[%d]", i);
		RBinXtacLinkedListEntry *entry = (RBinXtacLinkedListEntry *)r_list_get_n (bin->xtac_linked_list, i);

		addr = entry->ptr_to_entry;
		if (addr <= last) {
			tmpstr = r_str_newf ("%s.meta_and_offset", ekn);
			ROWL (tmpstr, 4, entry->meta_and_offset, "x");
			free (tmpstr);

			const ut8 meta = GET_META_DATA (entry->meta_and_offset);
			if (has_forward_edge_addr (meta)) {
				tmpstr = r_str_newf ("%s.forward_edge_addr", ekn);
				ROWL (tmpstr, 4, entry->forward_edge_addr, "x");
				free (tmpstr);
			}
			if (has_backward_edge_addr (meta)) {
				tmpstr = r_str_newf ("%s.backward_edge_addr", ekn);
				ROWL (tmpstr, 4, entry->backward_edge_addr, "x");
				free (tmpstr);
			}
		}
		free (ekn);
	}

	return ret;

#undef ROWL
}

static void header(RBinFile *bf) {
	RBinXtacObj *bin = bf->bo->bin_obj;
	RBinXtacHeader *hdr = bin->header;
	struct r_bin_t *rbin = bf->rbin;
	rbin->cb_printf ("XTAC file header:\n");
	rbin->cb_printf ("  magic : 0x%x\n", hdr->magic);
	rbin->cb_printf ("  version : 0x%x\n", hdr->version);
	rbin->cb_printf ("  is_updated : 0x%x\n", hdr->is_updated);
	rbin->cb_printf ("  ptr_to_addr_pairs : 0x%x\n", hdr->ptr_to_addr_pairs);
	rbin->cb_printf ("  num_of_addr_pairs : 0x%x\n", hdr->num_of_addr_pairs);

	rbin->cb_printf ("  ptr_to_mod_name : 0x%x\n", hdr->ptr_to_mod_name);
	rbin->cb_printf ("  size_of_mod_name : 0x%x\n", hdr->size_of_mod_name);
	rbin->cb_printf ("  module name : %s\n", bin->mod_name_u8);

	rbin->cb_printf ("  ptr_to_nt_pname : 0x%x\n", hdr->ptr_to_nt_pname);
	rbin->cb_printf ("  size_of_nt_pname : 0x%x\n", hdr->size_of_nt_pname);
	rbin->cb_printf ("  module name : %s\n", bin->nt_path_name_u8);

	rbin->cb_printf ("  ptr_to_head_blck_stub : 0x%x\n", hdr->ptr_to_head_blck_stub);
	rbin->cb_printf ("  ptr_to_tail_blck_stub : 0x%x\n", hdr->ptr_to_tail_blck_stub);
	rbin->cb_printf ("  size_of_blck_stub_code : 0x%x\n", hdr->size_of_blck_stub_code);
	rbin->cb_printf ("  ptr_to_xtac_linked_list_head : 0x%x\n", hdr->ptr_to_xtac_linked_list_head);
	rbin->cb_printf ("  ptr_to_xtac_linked_list_tail : 0x%x\n", hdr->ptr_to_xtac_linked_list_tail);

	rbin->cb_printf ("address pairs (x86, arm64):\n");
	const ut32 n_addr_pairs = hdr->num_of_addr_pairs;
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
	ut8 buf[sizeof (RBinXtacHeader)];
	if (r_buf_read_at (bin->b, 0, buf, sizeof (RBinXtacHeader)) != sizeof (RBinXtacHeader)) {
		R_LOG_WARN ("Read (xtac header)");
		return false;
	}
	RBinXtacHeader *hdr = R_NEW0 (RBinXtacHeader);
	hdr->magic = r_read_le32 (buf);
	hdr->version = r_read_le32 (buf + 4);
	hdr->is_updated = r_read_le32 (buf + 8);
	hdr->ptr_to_addr_pairs = r_read_le32 (buf + 12);
	hdr->num_of_addr_pairs = r_read_le32 (buf + 16);
	hdr->ptr_to_mod_name = r_read_le32 (buf + 20);
	hdr->size_of_mod_name = r_read_le32 (buf + 24);
	hdr->ptr_to_nt_pname = r_read_le32 (buf + 28);
	hdr->size_of_nt_pname = r_read_le32 (buf + 32);
	hdr->ptr_to_head_blck_stub = r_read_le32 (buf + 36);
	hdr->ptr_to_tail_blck_stub = r_read_le32 (buf + 40);
	hdr->size_of_blck_stub_code = r_read_le32 (buf + 44);
	hdr->ptr_to_xtac_linked_list_head = r_read_le32 (buf + 48);
	hdr->ptr_to_xtac_linked_list_tail = r_read_le32 (buf + 52);
	bin->header = hdr;
	return true;
}

static bool read_address_pairs(RBinXtacObj *bin) {
	RBinXtacHeader *hdr = bin->header;
	const ut32 n_addr_pairs = hdr->num_of_addr_pairs;
	const ut32 addr_pair_size = n_addr_pairs * sizeof (X86ArmAddrPair);

	if (n_addr_pairs == 0) {
		return true;
	}
	if (! (bin->address_pairs = R_NEWS0 (X86ArmAddrPair, n_addr_pairs))) {
		return false;
	}

	ut8 *buf = malloc (addr_pair_size);
	if (R_LIKELY (buf)) {
		if (r_buf_read_at (bin->b, hdr->ptr_to_addr_pairs, buf, addr_pair_size) != addr_pair_size) {
			R_LOG_WARN ("Read (xtac address pairs)");
			free (buf);
			R_FREE (bin->address_pairs);
			return false;
		}
		ut32 i;
		for (i = 0; i < n_addr_pairs; i++) {
			ut32 offset = i * sizeof (X86ArmAddrPair);
			bin->address_pairs[i].x86_rva = r_read_le32 (buf + offset);
			bin->address_pairs[i].arm64_rva = r_read_le32 (buf + offset + 4);
		}
		free (buf);
		return true;
	}
	R_LOG_WARN ("Memory allocation for address pairs");
	R_FREE (bin->address_pairs);
	return false;
}

static bool read_module_name(RBinXtacObj *bin) {
	RBinXtacHeader *hdr = bin->header;
	const ut32 len_of_mod_name = hdr->size_of_mod_name / sizeof (ut16) + 1;

	if (hdr->size_of_mod_name == 0) {
		return true;
	}
	if (! (bin->mod_name_u16 = R_NEWS0 (ut16, len_of_mod_name))) {
		return false;
	}
	if (r_buf_read_at (bin->b, hdr->ptr_to_mod_name, (ut8 *)bin->mod_name_u16, hdr->size_of_mod_name) != hdr->size_of_mod_name) {
		R_LOG_WARN ("Read (xtac module name)");
		R_FREE (bin->mod_name_u16);
		return false;
	}
	if (! (bin->mod_name_u8 = r_str_utf16_decode ((ut8 *)bin->mod_name_u16, hdr->size_of_mod_name))) {
		R_FREE (bin->mod_name_u16);
		return false;
	}
	return true;
}

static bool read_nt_native_pathname(RBinXtacObj *bin) {
	RBinXtacHeader *hdr = bin->header;
	const ut32 len_of_nt_pname = (hdr->size_of_nt_pname / sizeof (ut16)) + 1;

	if (hdr->size_of_nt_pname == 0) {
		return true;
	}
	if (! (bin->nt_path_name_u16 = R_NEWS0 (ut16, len_of_nt_pname))) {
		return false;
	}
	if (r_buf_read_at (bin->b, hdr->ptr_to_nt_pname, (ut8 *)bin->nt_path_name_u16, hdr->size_of_nt_pname) != hdr->size_of_nt_pname) {
		R_LOG_WARN ("Read (xtac nt path)");
		R_FREE (bin->nt_path_name_u16);
		return false;
	}

	char *nt_path_name_u8_raw = r_str_utf16_decode ((ut8 *)bin->nt_path_name_u16, hdr->size_of_nt_pname);
	if (!nt_path_name_u8_raw) {
		R_FREE (bin->nt_path_name_u16);
		return false;
	}

	bin->nt_path_name_u8 = r_str_escape_json (nt_path_name_u8_raw, -1);
	R_FREE (nt_path_name_u8_raw);
	if (!bin->nt_path_name_u8) {
		R_FREE (bin->nt_path_name_u16);
		return false;
	}

	return true;
}

static bool read_blck_stubs(RBinXtacObj *bin) {
	RBinXtacHeader *hdr = bin->header;
	if (! (bin->blck_stubs = r_list_newf (free))) {
		return false;
	}
	const ut32 max_depth = 20;
	ut32 i = 0;
	ut32 p_blck_stub = hdr->ptr_to_head_blck_stub;
	do {
		if (p_blck_stub == 0) {
			break; // End of list
		}
		ut8 buf[sizeof (RBinBlckStubHeader) - sizeof (ut32)];
		if (r_buf_read_at (bin->b, p_blck_stub, buf, sizeof (buf)) != sizeof (buf)) {
			R_LOG_WARN ("Read (xtac BLCK stub)");
			return false;
		}

		RBinBlckStubHeader *blck_stub = R_NEW0 (RBinBlckStubHeader);
		blck_stub->magic = r_read_le32 (buf);
		blck_stub->offset_to_next_entry = r_read_le32 (buf + 4);
		blck_stub->ptr_to_next_entry = r_read_le32 (buf + 8);
		blck_stub->padding = r_read_le32 (buf + 12);
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

static bool read_xtac_linked_list(RBinXtacObj *bin) {
	RBinXtacHeader *hdr = bin->header;
	if (! (bin->xtac_linked_list = r_list_newf (free))) {
		return false;
	}
	ut32 p_xtac_linked_list_entry = hdr->ptr_to_xtac_linked_list_head;
	ut64 buf_size = r_buf_size (bin->b);

	if (p_xtac_linked_list_entry > buf_size) {
		return false;
	}

	RBinXtacLinkedListEntry *entry = NULL;
	do {
		if (p_xtac_linked_list_entry == 0) {
			break;
		}
		ut8 buf[12]; // maximum size: meta + forward + backward = 12 bytes
		ut32 p_buffer = p_xtac_linked_list_entry + sizeof (ut32);

		if (r_buf_read_at (bin->b, p_xtac_linked_list_entry, buf, sizeof (ut32)) != sizeof (ut32)) {
			R_LOG_WARN ("Read (xtac linked list metadata)");
			return false;
		}
		entry = R_NEW0 (RBinXtacLinkedListEntry);
		entry->ptr_to_entry = p_xtac_linked_list_entry;
		entry->meta_and_offset = r_read_le32 (buf);
		const ut32 meta = GET_META_DATA (entry->meta_and_offset);
		if (has_forward_edge_addr (meta)) {
			if (r_buf_read_at (bin->b, p_buffer, buf, sizeof (ut32)) != sizeof (ut32)) {
				R_LOG_WARN ("Read (xtac linked list forward edge address)");
				free (entry);
				return false;
			}
			entry->forward_edge_addr = r_read_le32 (buf);
			p_buffer += sizeof (ut32);
		}
		if (has_backward_edge_addr (meta)) {
			if (r_buf_read_at (bin->b, p_buffer, buf, sizeof (ut32)) != sizeof (ut32)) {
				R_LOG_WARN ("Read (xtac linked list backward edge address)");
				free (entry);
				return false;
			}
			entry->backward_edge_addr = r_read_le32 (buf);
			p_buffer += sizeof (ut32);
		}
		r_list_append (bin->xtac_linked_list, entry);
		int a = entry->meta_and_offset;
		if (a < 1 || a > 0xfff) {
			break;
		}

		p_xtac_linked_list_entry += (a * 4);
	} while (p_xtac_linked_list_entry < buf_size && p_xtac_linked_list_entry < hdr->ptr_to_addr_pairs);

	if (entry && GET_OFFSET (entry->meta_and_offset) != 0x0FFFFFFF) {
		R_LOG_WARN ("xtac linked list is not properly terminated");
		R_LOG_WARN ("Some entry of xtac linked list might be broken");
	}

	return true;
}

static bool r_bin_xtac_init(RBinXtacObj *bin) {
	if (!r_bin_xtac_read_header (bin)) {
		return false;
	}
	if (!validate_header (bin)) {
		R_LOG_WARN ("Invalid header pointers detected");
		// XXX imho this shouldnt be fatal. so we can try not returning and fuzz
		return false;
	}
	if (!read_address_pairs (bin)) {
		return false;
	}
	if (!read_module_name (bin)) {
		return false;
	}
	if (!read_nt_native_pathname (bin)) {
		return false;
	}
	if (!read_blck_stubs (bin)) {
		return false;
	}
	if (!read_xtac_linked_list (bin)) {
		return false;
	}
	return true;
}

static void r_bin_xtac_free(RBinXtacObj *bin) {
	if (!bin) {
		return;
	}
	free (bin->header);
	free (bin->address_pairs);
	free (bin->mod_name_u16);
	free (bin->mod_name_u8);
	free (bin->nt_path_name_u16);
	free (bin->nt_path_name_u8);
	r_unref (bin->b);
	bin->b = NULL;
	r_list_free (bin->blck_stubs);
	r_list_free (bin->xtac_linked_list);
	bin->blck_stubs = NULL;
	bin->xtac_linked_list = NULL;
	free (bin);
}

static RBinXtacObj *r_bin_xtac_new_buf(RBuffer *buf, bool verbose) {
	RBinXtacObj *bin = R_NEW0 (RBinXtacObj);
	bin->b = r_ref (buf);
	bin->size = r_buf_size (buf);
	bin->verbose = verbose;
	if (!r_bin_xtac_init (bin)) {
		r_bin_xtac_free (bin);
		bin = NULL;
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

	ut32 magic = r_read_le32 (buf);
	return memcmp (&magic, XTAC_MAGIC, sizeof (XTAC_MAGIC) - 1) == 0;
}

static RList *symbols(RBinFile *bf) {
	RBinXtacObj *bin = bf->bo->bin_obj;
	RBinXtacHeader *hdr = bin->header;
	ut64 x86_baddr = baddr (bf), arm_baddr = 0x0;
	RList *ret = r_list_newf (free);
	const ut32 num_pairs = hdr->num_of_addr_pairs;
	int i;
	for (i = 0; i < num_pairs; i++) {
		const ut32 x86_vaddr = bin->address_pairs[i].x86_rva + x86_baddr;
		const ut32 arm_vaddr = bin->address_pairs[i].arm64_rva + arm_baddr;
		if (arm_vaddr == UT32_MAX || x86_vaddr == UT32_MAX) {
			continue;
		}
		RBinSymbol *s = R_NEW0 (RBinSymbol);
		s->name = r_bin_name_new_from (r_str_newf ("x86.%08x", x86_vaddr));
		s->bind = "NONE";
		s->type = R_BIN_TYPE_FUNC_STR;
		s->size = 0;
		s->paddr = arm_vaddr;
		s->vaddr = arm_vaddr;
		s->ordinal = i;
		r_list_append (ret, s);
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
