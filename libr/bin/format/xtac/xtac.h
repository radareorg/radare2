/*
 * Copyright (c) FFRI Security, Inc., 2023 / Author: FFRI Security, Inc.
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

#ifndef _INCLUDE_XTAC_H_
#define _INCLUDE_XTAC_H_

#include <r_types.h>

#define XTAC_MAGIC "XTAC"

typedef struct x86_arm_addr_pair_t {
	ut32 x86_rva;
	ut32 arm64_rva;
} X86ArmAddrPair;

// NOTE: Here "pointer" means RVA from the image base of the cache file
typedef struct r_bin_xtac_header_t {
	ut32 magic; // signature (always "XTAC")
	ut32 version; // version of XTAC
	ut32 is_updated; // cache file is updated (1) or not (0)
	ut32 ptr_to_addr_pairs; // pointer to x86 to arm address pairs
	ut32 num_of_addr_pairs; // number of address pairs
	ut32 ptr_to_mod_name; // pointer to module name
	ut32 size_of_mod_name; // size of module name (in bytes)
	ut32 ptr_to_nt_pname; // pointer to NT path name
	ut32 size_of_nt_pname; // size of NT path name (in bytes)
	ut32 ptr_to_head_blck_stub; // pointer to head BLCK stub
	ut32 ptr_to_tail_blck_stub; // pointer to tail BLCK stub
	ut32 size_of_blck_stub_code; // size of BLCK stub code (not including BLCK stub header)
	ut32 ptr_to_xtac_linked_list_head; // pointer to the head of linked list for updating
					   // xtac.exe uses this for accessing the location to be corrected
	ut32 ptr_to_xtac_linked_list_tail; // pointer to the tail of linked list for updating
} RBinXtacHeader;

typedef struct r_bin_blck_stub_header_t {
	ut32 magic; // signature (always "BLCK")
	ut32 offset_to_next_entry; // offset to the next entry from the current BLCK stub code
	ut32 ptr_to_next_entry; // pointer to the next BLCK stub
	ut32 padding; // padding (always 0)

	ut32 ptr_to_entry; // pointer to this entry
} RBinBlckStubHeader;

typedef struct r_bin_xtac_linked_list_entry_t {
	ut32 meta_and_offset; // metadata (upper 8bits) and quarter of offset to next entry (lower 24bits)
	ut32 forward_edge_addr; // x86 RVA of forward edge address
	ut32 backward_edge_addr; // x86 RVA of backward edge address

	ut32 ptr_to_entry; // pointer to this entry
} RBinXtacLinkedListEntry;

typedef struct r_bin_xtac_obj_t {
	RBinXtacHeader *header;
	X86ArmAddrPair *address_pairs;
	ut16 *mod_name_u16;
	char *mod_name_u8;
	ut16 *nt_path_name_u16;
	char *nt_path_name_u8;

	RBuffer *b;
	RList *blck_stubs; // RList of r_bin_bock_stub_header_t
	RList *xtac_linked_list; // RList of r_bin_xtac_linked_list_entry_t
	Sdb *kv;
	bool verbose;
	int size;
} RBinXtacObj;

#endif
