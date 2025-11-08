/* radare2 - LGPL - Copyright 2025 - Analysis plugin for Solana BPF */

#include <r_anal.h>

#define SBPF_MAX_STRING_SIZE 0x100
#define SBPF_COMMENT_SIZE 512

#define SBPF_INS_HOR64			0xf7
#define SBPF_INS_MOV_IMM 		0xb4
#define SBPF_INS_MOV64_IMM 		0xb7
#define SBPF_INS_LDDW 			0x18

typedef struct {
	ut64 addr;
	ut64 xref_addr;
	bool is_pointer; // true if this is a pointer to a string structure
	ut32 size; // for string pointers, this holds the size from the structure
} SbpfStringRef;

static int sbpf_string_ref_cmp(const void *a, const void *b) {
	const SbpfStringRef *sa = (const SbpfStringRef *)a;
	const SbpfStringRef *sb = (const SbpfStringRef *)b;
	if (sa->addr < sb->addr) {
		return -1;
	}
	if (sa->addr > sb->addr) {
		return 1;
	}
	return 0;
}

// TODO, this can be simplified too, we have primitives in r_iutil for that
static bool is_printable_string(const char *buf, ut32 size) {
	if (size < 1) {
		return false;
	}
	ut32 actual_size = size;
	if (buf[size - 1] == 0) {
		actual_size = size - 1;
	}
	if (actual_size == 0) {
		return false;
	}
	return r_str_is_printable_limited ((const char *)buf, actual_size);
}

// Check if a pointer points to a string structure (string ptr at +0, size at +8)
static bool sbpf_check_string_pointer(RAnal *anal, ut64 ptr_addr, ut64 data_start, ut64 data_end, ut64 *out_str_addr, ut32 *out_str_size) {
	R_RETURN_VAL_IF_FAIL (anal && anal->iob.io, false);

	// First check if the address itself could be a direct string
	ut8 struct_buf[16];
	if (!anal->iob.read_at (anal->iob.io, ptr_addr, struct_buf, 16)) {
		return false;
	}

	// Check if the first 4 bytes look like printable ASCII
	int ascii_count = 0;
	int i;
	for (i = 0; i < 4; i++) {
		if (struct_buf[i] >= 0x20 && struct_buf[i] <= 0x7e) {
			ascii_count++;
		}
	}

	// If the first 4 bytes are all printable ASCII, this is definitely a direct string
	if (ascii_count == 4) {
		R_LOG_DEBUG ("Rejecting string pointer at 0x%"PFMT64x": first 4 bytes are ASCII", ptr_addr);
		return false;
	}

	// Get string pointer from offset 0
	ut64 str_ptr = r_read_le64 (struct_buf);
	// Get size from offset 8
	ut64 size = r_read_le64 (struct_buf + 8);

	R_LOG_DEBUG ("  Checking potential string pointer: str_ptr=0x%"PFMT64x", size=0x%"PFMT64x, str_ptr, size);

	// Validate size is reasonable (but not too small, and not a typical pointer value)
	if (size == 0 || size > 0x100) {
		R_LOG_DEBUG ("  Rejected: size out of range (0 or > 0x100)");
		return false;
	}

	// Check if string pointer is in data segment
	if (str_ptr < data_start || str_ptr >= data_end) {
		R_LOG_DEBUG ("  Rejected: str_ptr 0x%"PFMT64x" not in data segment [0x%"PFMT64x" - 0x%"PFMT64x")",
			str_ptr, data_start, data_end);
		return false;
	}

	// Try to read the actual string to verify it's printable
	char sample[0x100];
	ut32 sample_size = (size < 0x100) ? size : 0x100;
	if (!anal->iob.read_at (anal->iob.io, str_ptr, (ut8 *)sample, sample_size)) {
		R_LOG_DEBUG ("  Rejected: failed to read string at 0x%"PFMT64x, str_ptr);
		return false;
	}
	if (!is_printable_string (sample, sample_size)) {
		R_LOG_DEBUG ("  Rejected: string at 0x%"PFMT64x" is not printable", str_ptr);
		return false;
	}
	if (out_str_addr) {
		*out_str_addr = str_ptr;
	}
	if (out_str_size) {
		*out_str_size = (ut32)size;
	}
	R_LOG_DEBUG ("Found string pointer at 0x%"PFMT64x": size=%u, str_ptr=0x%"PFMT64x,
			ptr_addr, (ut32)size, str_ptr);

	return true;
}

static RList *sbpf_find_string_xrefs(RAnal *anal, ut64 from, ut64 to, ut64 data_start, ut64 data_end) {
	R_RETURN_VAL_IF_FAIL (anal && anal->iob.io, NULL);

	RList *refs = r_list_new ();
	if (!refs) {
		return NULL;
	}

	R_LOG_DEBUG ("Looking for references to data segment 0x%"PFMT64x" - 0x%"PFMT64x, data_start, data_end);

	// LDDW instructions are 16 bytes but can appear at any 8-byte alignment
	ut64 addr;
	ut8 buf[24]; // Read extra to handle unaligned reads

	for (addr = from; addr < to - 15; addr++) {
		if (!anal->iob.read_at (anal->iob.io, addr, buf, 16)) {
			continue;
		}

		ut64 imm_val = 0;
		bool found_pattern = false;

		// Check for MOV + HOR64 pattern (v2+ sBPF: opcodes 0xb4 or 0xb7 followed by 0xf7)
		if ((buf[0] == SBPF_INS_MOV_IMM || buf[0] == SBPF_INS_MOV64_IMM) && buf[8] == SBPF_INS_HOR64) {
			// Check that both instructions use the same destination register
			ut8 dst_reg_mov = buf[1] & 0x0F;
			ut8 dst_reg_hor = buf[9] & 0x0F;
			if (dst_reg_mov == dst_reg_hor) {
				// Extract the 64-bit immediate value from both instructions
				ut32 imm_low = r_read_le32 (buf + 4);
				ut32 imm_high = r_read_le32 (buf + 12);
				imm_val = ((ut64)imm_high << 32) | imm_low;
				found_pattern = true;
				R_LOG_DEBUG ("Found MOV+HOR64 at 0x%"PFMT64x" -> 0x%"PFMT64x, addr, imm_val);
			}
		}
		// Check if this is a LDDW instruction (0x18 in first byte)
		else if ((buf[0] & 0xff) == SBPF_INS_LDDW) {
			// Second instruction should have opcode 0x00
			if (buf[8] != 0x00) {
				continue;
			}

			// Extract the 64-bit immediate value
			ut32 imm_low = r_read_le32 (buf + 4);
			ut32 imm_high = r_read_le32 (buf + 12);
			imm_val = ((ut64)imm_high << 32) | imm_low;
			found_pattern = true;
		}

		// Process any found 64-bit immediate value (from either MOV+HOR64 or LDDW)
		if (found_pattern) {
			// Check if the immediate points to the data segment
			if (imm_val >= data_start && imm_val < data_end) {
				R_LOG_DEBUG ("  Immediate value 0x%"PFMT64x" is in data segment [0x%"PFMT64x" - 0x%"PFMT64x")",
					imm_val, data_start, data_end);

				// First check if this is a string pointer structure
				ut64 actual_str_addr;
				ut32 actual_str_size;
				bool is_string_pointer = sbpf_check_string_pointer (anal, imm_val, data_start, data_end,
						&actual_str_addr, &actual_str_size);

				R_LOG_DEBUG ("  sbpf_check_string_pointer returned: %s", is_string_pointer ? "true" : "false");
				if (is_string_pointer) {
					R_LOG_DEBUG ("    -> points to string at 0x%"PFMT64x" size %u", actual_str_addr, actual_str_size);
				}

				// Check if we already have this reference (avoid duplicates)
				bool duplicate = false;
				RListIter *iter;
				SbpfStringRef *existing;
				r_list_foreach (refs, iter, existing) {
					// Check if we already have this exact reference
					// (same address loaded by same instruction)
					if (existing->addr == imm_val && existing->xref_addr == addr) {
						duplicate = true;
						break;
					}
				}

				if (!duplicate) {
					R_LOG_DEBUG ("  Not a duplicate, adding reference");
					if (is_string_pointer) {
						// Add BOTH the pointer structure AND the string it points to
						// First, add the pointer structure reference
						SbpfStringRef *ptr_ref = R_NEW0 (SbpfStringRef);
						ptr_ref->addr = imm_val;  // The pointer structure address
						ptr_ref->xref_addr = addr;
						ptr_ref->is_pointer = true;
						ptr_ref->size = actual_str_size;
						r_list_append (refs, ptr_ref);
						R_LOG_DEBUG ("Added pointer structure at 0x%"PFMT64x" (from LDDW at 0x%"PFMT64x")",
								imm_val, addr);

						// Also add the actual string address as a reference
						// This ensures we have all string addresses for size calculation
						SbpfStringRef *str_ref = R_NEW0 (SbpfStringRef);
						str_ref->addr = actual_str_addr;
						str_ref->xref_addr = UT64_MAX;  // No direct xref for substring
						str_ref->is_pointer = false;
						str_ref->size = actual_str_size;  // We know the size from the pointer
						r_list_append (refs, str_ref);
						R_LOG_DEBUG ("String pointed to at 0x%"PFMT64x" (size %u)", actual_str_addr, actual_str_size);
					} else {
						// Regular direct string reference
						SbpfStringRef *ref = R_NEW0 (SbpfStringRef);
						ref->addr = imm_val;
						ref->xref_addr = addr;
						ref->is_pointer = false;
						ref->size = 0; // Will be calculated later
						r_list_append (refs, ref);
						R_LOG_DEBUG ("Found direct string ref at 0x%"PFMT64x" (from instruction at 0x%"PFMT64x")",
								imm_val, addr);
					}
				}
			}

			// Skip ahead 8 bytes since we found a valid LDDW (they're 8-byte aligned)
			addr += 7; // Will be incremented by 1 in loop
		}
	}

	r_list_sort (refs, sbpf_string_ref_cmp);
	return refs;
}

static bool sbpf_find_segment_bounds(RAnal *anal, int segment_index, ut64 *start, ut64 *end) {
	R_RETURN_VAL_IF_FAIL (anal && anal->iob.io && start && end, false);

	// Get base address - try to get it from core config
	ut64 baddr = 0;
	if (anal->coreb.core && anal->coreb.cfgGetI) {
		// Get bin.baddr from config which includes user-specified -B value
		baddr = anal->coreb.cfgGetI (anal->coreb.core, "bin.baddr");
		R_LOG_DEBUG ("Got baddr from config: 0x%"PFMT64x, baddr);
	}

	// Get sections from the binary, but filter for segments
	if (anal->binb.get_sections) {
		RList *sections = anal->binb.get_sections (anal->binb.bin);
		if (sections) {
			RListIter *iter;
			RBinSection *section;
			int idx = 0;
			r_list_foreach (sections, iter, section) {
				// Only process segments (program headers)
				if (section && section->is_segment) {
					if (idx == segment_index) {
						*start = section->vaddr + baddr;
						*end = section->vaddr + section->vsize + baddr;
						return true;
					}
					idx++;
				}
			}
		}
	}

	return false;
}

static void sbpf_create_string(RAnal *anal, ut64 addr, ut32 size, ut64 xref_addr, bool is_pointer) {
	R_LOG_DEBUG ("sbpf_create_string called: addr=0x%"PFMT64x" size=%u xref=0x%"PFMT64x, addr, size, xref_addr);

	R_RETURN_IF_FAIL (anal && anal->iob.io && size > 0 && size <= SBPF_MAX_STRING_SIZE);

	char buf[SBPF_MAX_STRING_SIZE + 1];

	// Read the string data
	if (!anal->iob.read_at (anal->iob.io, addr, (ut8*)buf, size)) {
		R_LOG_WARN ("Failed to read string data at 0x%"PFMT64x, addr);
		return;
	}

	// Rust strings are NOT null-terminated - they use exact size
	// Force null termination for our buffer
	buf[size] = 0;

	// For Rust strings, we use the exact size from the structure
	ut32 str_size = size;

	// Validate printable using the exact size
	if (!is_printable_string (buf, size)) {
		return;
	}

	// First, delete any existing metadata at this address
	r_meta_del (anal, R_META_TYPE_STRING, addr, UT64_MAX);

	// Create a properly null-terminated string for metadata
	// Rust strings are NOT null-terminated, so we must be careful
	// We need to create a string that's EXACTLY the size specified
	char *truncated_str = calloc(1, str_size + 1);
	if (!truncated_str) {
		return;
	}
	memcpy (truncated_str, buf, str_size);
	truncated_str[str_size] = '\0';  // Ensure null termination

	// Add string metadata to radare2's metadata database
	// Pass the exact size so r2 knows where the string ends
	if (!r_meta_set (anal, R_META_TYPE_STRING, addr, str_size, truncated_str)) {
		R_LOG_DEBUG ("Failed to set string metadata at 0x%"PFMT64x, addr);
	} else {
		R_LOG_DEBUG ("Set string metadata at 0x%"PFMT64x" size %u: %s", addr, str_size, truncated_str);
	}

	// Create xref from the instruction to the string
	if (xref_addr != UT64_MAX) {
		r_anal_xrefs_set (anal, xref_addr, addr, R_ANAL_REF_TYPE_STRN | R_ANAL_REF_TYPE_READ);
		char *s = r_str_ndup ((char *)buf, str_size);
		r_str_filter (s, -1);
		char *comment_str = r_str_newf ("\"%s\"", s);
		r_meta_set_string (anal, R_META_TYPE_COMMENT, xref_addr, comment_str);
		R_LOG_DEBUG ("Added comment at 0x%"PFMT64x": %s", xref_addr, comment_str);
		free (s);
		free (comment_str);
	}

	// Free the allocated string
	free (truncated_str);

	// Create a flag for the string
	R_LOG_INFO ("Attempting to create flag for string at 0x%"PFMT64x, addr);

	if (!anal->flb.f) {
		R_LOG_ERROR ("anal->flb.f is NULL - cannot create flags");
	} else if (!anal->flb.set) {
		R_LOG_ERROR ("anal->flb.set is NULL - cannot create flags");
	} else {
		// Build a proper flag name from the truncated string
		char safe_str[64] = {0};

		// Copy only the actual string size
		ut32 copy_len = str_size < 63 ? str_size : 63;
		r_str_ncpy (safe_str, (char *)buf, copy_len + 1);

		// Filter for safe flag name
		r_str_filter (safe_str, -1);

		// Create the flag name with appropriate prefix
		const char *prefix = is_pointer ? "ptr" : "str";
		char *flagname = r_str_newf ("%s.%s", prefix, safe_str);

		R_LOG_INFO ("Calling anal->flb.set with flag name: %s", flagname);

		// Unset any existing flag at this address first
		if (anal->flb.get_at && anal->flb.unset) {
			RFlagItem *existing = anal->flb.get_at (anal->flb.f, addr, false);
			if (existing) {
				R_LOG_DEBUG ("Unsetting existing flag %s at 0x%"PFMT64x, existing->name, addr);
				anal->flb.unset (anal->flb.f, existing);
			}
		}

		// Create the flag
		RFlagItem *item = NULL;
		if (anal->flb.set && anal->flb.f) {
			item = anal->flb.set (anal->flb.f, flagname, addr, str_size);
			if (item) {
				R_LOG_INFO ("Successfully created flag %s at 0x%"PFMT64x" size %u", flagname, addr, str_size);
			} else {
				r_strf_var (fallback, 64, "str_%08" PFMT64x, addr);
				R_LOG_INFO ("First flag failed, trying fallback: %s", fallback);
				item = anal->flb.set (anal->flb.f, fallback, addr, str_size);
				if (item) {
					R_LOG_INFO ("Created fallback flag %s at 0x%"PFMT64x" size %u", fallback, addr, str_size);
				} else {
					R_LOG_ERROR ("Failed to create any flag at 0x%"PFMT64x, addr);
				}
			}
		}
		free (flagname);
	}
}

static bool sbpf_analyze_strings(RAnal *anal) {
	R_RETURN_VAL_IF_FAIL (anal, false);

	ut64 code_start, code_end;
	if (!sbpf_find_segment_bounds (anal, 0, &code_start, &code_end)) {
		R_LOG_WARN ("Could not determine CODE segment bounds for string analysis");
		return false;
	}
	R_LOG_INFO ("CODE segment bounds: 0x%"PFMT64x" - 0x%"PFMT64x, code_start, code_end);

	ut64 data_start, data_end;
	if (!sbpf_find_segment_bounds (anal, 1, &data_start, &data_end)) {
		if (!sbpf_find_segment_bounds (anal, 2, &data_start, &data_end)) {
			R_LOG_WARN ("Could not find data segment for string analysis");
			return false;
		}
	}
	R_LOG_INFO ("DATA segment bounds: 0x%"PFMT64x" - 0x%"PFMT64x, data_start, data_end);

	RList *refs = sbpf_find_string_xrefs (anal, code_start, code_end, data_start, data_end);
	if (!refs) {
		return false;
	}

	R_LOG_INFO ("Found %d potential string references", r_list_length (refs));

	RListIter *iter, *next_iter;
	SbpfStringRef *ref, *next_ref;
	int strings_created = 0;

	SetU *created_addrs = set_u_new ();

	r_list_foreach (refs, iter, ref) {
		if (ref->addr < data_start || ref->addr >= data_end) {
			R_LOG_DEBUG ("Skipping reference to 0x%"PFMT64x" - outside data segment", ref->addr);
			continue;
		}

		// Check if we've already created a string at this address
		bool already_created = set_u_contains (created_addrs, ref->addr);

		// Skip substring entries (they have no direct xref)
		if (ref->xref_addr == UT64_MAX) {
			R_LOG_DEBUG ("Skipping substring entry at 0x%"PFMT64x, ref->addr);
			continue;
		}

		// Always create the xref
		if (anal->flb.set) {
			r_anal_xrefs_set (anal, ref->xref_addr, ref->addr, R_ANAL_REF_TYPE_DATA | R_ANAL_REF_TYPE_READ);
		}

		if (already_created) {
			R_LOG_DEBUG ("String/pointer at 0x%"PFMT64x" already created, adding xref from 0x%"PFMT64x,
					ref->addr, ref->xref_addr);
			continue;
		}

		// Handle pointer structures separately
		if (ref->is_pointer) {
			// This is a pointer structure, create a pointer flag
			ut8 struct_buf[16];
			if (!anal->iob.read_at (anal->iob.io, ref->addr, struct_buf, 16)) {
				continue;
			}
			ut64 str_ptr = r_read_le64 (struct_buf);
			ut64 size = r_read_le64 (struct_buf + 8);

			if (size > SBPF_MAX_STRING_SIZE) {
				size = SBPF_MAX_STRING_SIZE;
			}

			char *flagname = NULL;
			char *comment_str = NULL;
			char *str_buf = malloc (size + 1);

			if (!str_buf) {
				R_LOG_ERROR ("Failed to allocate memory for string buffer");
				continue;
			}

			if (anal->iob.read_at (anal->iob.io, str_ptr, (ut8 *)str_buf, size)) {
				str_buf[size] = 0;  // Null terminate at the size boundary
				// Find actual string length (up to first null terminator)
				ut32 actual_len = r_str_nlen (str_buf, size);
				str_buf[actual_len] = 0;  // Ensure termination at actual length
				r_str_filter (str_buf, -1);
				flagname = r_str_newf ("ptr.%"PFMT64x"_%s", ref->addr, str_buf);
				comment_str = strdup (str_buf);
			} else {
				flagname = r_str_newf ("ptr.%"PFMT64x, ref->addr);
				comment_str = strdup ("");
			}
			free (str_buf);

			if (anal->flb.set && anal->flb.f) {
				// Unset any existing flag at this address first
				if (anal->flb.get_at) {
					RFlagItem *existing = anal->flb.get_at (anal->flb.f, ref->addr, false);
					if (existing && anal->flb.unset) {
						R_LOG_DEBUG ("Unsetting existing flag %s at 0x%"PFMT64x, existing->name, ref->addr);
						anal->flb.unset (anal->flb.f, existing);
					}
				}

				RFlagItem *item = anal->flb.set (anal->flb.f, flagname, ref->addr, 16);
				if (item) {
					R_LOG_INFO ("Created pointer flag %s at 0x%"PFMT64x, flagname, ref->addr);
				} else {
					R_LOG_ERROR ("Failed to create pointer flag %s at 0x%"PFMT64x, flagname, ref->addr);
				}
			}

			// Add comment at the instruction address showing the string value
			if (ref->xref_addr != UT64_MAX && comment_str && *comment_str) {
				char *comment = r_str_newf ("ptr -> \"%s\"", comment_str);
				if (strlen (comment) > 64) {
					strcpy (comment + 50, "...\"");
				}
				r_meta_set_string (anal, R_META_TYPE_COMMENT, ref->xref_addr, comment);
				R_LOG_DEBUG ("Added pointer comment at 0x%"PFMT64x": %s", ref->xref_addr, comment);
				free (comment);
			}
			free (flagname);
			free (comment_str);
			set_u_add (created_addrs, ref->addr);
			strings_created++;
			continue;
		}

		// For regular strings, calculate size
		ut32 string_size = SBPF_MAX_STRING_SIZE;

		if (ref->size > 0) {
			// Use pre-calculated size if available (from pointer structure)
			string_size = ref->size;
		} else {
			// For direct strings, calculate size based on next reference address
			// This includes ALL entries: direct strings, pointer structures, and substrings
			next_iter = iter->n;
			while (next_iter) {
				next_ref = (SbpfStringRef *)next_iter->data;
				// Use any reference that comes after this one as a boundary
				// Don't skip substring entries - they are valid boundaries!
				if (next_ref->addr > ref->addr && next_ref->addr < data_end) {
					string_size = next_ref->addr - ref->addr;
					break;
				}
				next_iter = next_iter->n;
			}

			// If we didn't find a next reference, use data_end
			if (!next_iter) {
				string_size = data_end - ref->addr;
			}

			if (string_size > SBPF_MAX_STRING_SIZE) {
				string_size = SBPF_MAX_STRING_SIZE;
			}

			R_LOG_DEBUG ("Creating string at 0x%"PFMT64x" with size %u (xref from 0x%"PFMT64x")",
					ref->addr, string_size, ref->xref_addr);
		}

		// Only create strings for non-pointer entries
		// Pointer structures are already handled above
		sbpf_create_string (anal, ref->addr, string_size, ref->xref_addr, false);
		// XXX this is wrong for 32bit systems
		set_u_add (created_addrs, ref->addr);
		strings_created++;
	}

	set_u_free (created_addrs);

	R_LOG_INFO ("Created %d strings", strings_created);

	r_list_free (refs);

	return true;
}

static bool already_processed(RList *processed, ut64 addr) {
	SbpfStringRef *processed_ref;
	RListIter *iter2;
	r_list_foreach (processed, iter2, processed_ref) {
		if (processed_ref->addr == addr) {
			return true;
			break;
		}
	}
	return false;
}

static void sbpf_print_string_xrefs(RAnal *anal) {
	R_RETURN_IF_FAIL (anal);

	ut64 code_start, code_end;
	if (!sbpf_find_segment_bounds (anal, 0, &code_start, &code_end)) {
		return;
	}

	ut64 data_start, data_end;
	if (!sbpf_find_segment_bounds (anal, 1, &data_start, &data_end)) {
		return;
	}

	RList *refs = sbpf_find_string_xrefs (anal, code_start, code_end, data_start, data_end);
	if (!refs) {
		return;
	}

	r_list_sort (refs, sbpf_string_ref_cmp);

	RList *processed = r_list_new ();

	RTable *table = r_table_new ("sbpf_strings");
	if (!table) {
		r_list_free (processed);
		r_list_free (refs);
		return;
	}

	RTableColumnType *n = r_table_type ("number");
	RTableColumnType *s = r_table_type ("string");

	r_table_add_column (table, n, "nth", 0);
	r_table_add_column (table, n, "xref", 0);
	r_table_add_column (table, n, "vaddr", 0);
	r_table_add_column (table, n, "len", 0);
	r_table_add_column (table, n, "size", 0);
	r_table_add_column (table, s, "section", 0);
	r_table_add_column (table, s, "type", 0);
	r_table_add_column (table, s, "string", 0);

	RListIter *iter, *next_iter, *iter2;
	SbpfStringRef *ref, *next_ref, *ref2;
	int nth = 0;

	r_list_foreach (refs, iter, ref) {
		if (ref->addr < data_start || ref->addr >= data_end) {
			continue;
		}

		if (already_processed (processed, ref->addr)) {
			continue;
		}

		r_list_append (processed, ref);

		// Skip substring entries that have no direct xref
		if (ref->xref_addr == UT64_MAX) {
			continue;
		}

		ut32 string_size = SBPF_MAX_STRING_SIZE;

		if (ref->is_pointer) {
			// This is a pointer structure
			// Read the pointer structure to get the actual string
			ut8 struct_buf[16];
			if (!anal->iob.read_at (anal->iob.io, ref->addr, struct_buf, 16)) {
				continue;
			}
			ut64 str_ptr = r_read_le64 (struct_buf);
			ut64 size = r_read_le64 (struct_buf + 8);

			// Read the actual string
			char str_buf[SBPF_MAX_STRING_SIZE + 1] = {0};
			if (size >= sizeof (str_buf)) {
				size = sizeof (str_buf) - 1;
			}

			if (anal->iob.read_at (anal->iob.io, str_ptr, (ut8 *)str_buf, size)) {
				str_buf[size] = 0; // null terminated
				r_str_filter (str_buf, -1);
				if (str_buf[sizeof (str_buf) - 5]) {
					strcpy (str_buf + sizeof (str_buf) - 5, "...");
				}
				// Add pointer structure to table
				r_table_add_rowf (table, "xxxxxsss",
						(ut64)nth++, ref->xref_addr, ref->addr, (ut64)size, (ut64)(size + 1),
						".rodata", "pointer", str_buf);
				// Add a comment showing the actual string
				char *pcomment = r_str_newf ("ptr -> \"%s\"", str_buf);
				r_meta_set_string (anal, R_META_TYPE_COMMENT, ref->xref_addr, pcomment);
				free (pcomment);
			}
			continue;
		}
		// Calculate size based on next reference (any type)
		r_list_foreach (refs, next_iter, next_ref) {
			// Use ANY reference that comes after this one as a boundary
			// Including substring entries - they are valid boundaries!
			if (next_ref->addr > ref->addr && next_ref->addr < data_end) {
				string_size = next_ref->addr - ref->addr;
				break;
			}
		}

		// If no next reference found, use end of data segment
		if (string_size == SBPF_MAX_STRING_SIZE) {
			string_size = data_end - ref->addr;
		}

		if (string_size > SBPF_MAX_STRING_SIZE) {
			string_size = SBPF_MAX_STRING_SIZE;
		}

		char buf[SBPF_MAX_STRING_SIZE + 1] = {0};

		if (anal->iob.read_at (anal->iob.io, ref->addr, (ut8 *)buf, string_size)) {
			buf[sizeof (buf) - 1] = 0;

			ut32 actual_len = 0;
			bool found_null = false;
			ut32 i;
			for (i = 0; i < string_size; i++) {
				if (buf[i] == 0) {
					actual_len = i;
					found_null = true;
					break;
				}
			}

			if (found_null) {
				if (!is_printable_string (buf, actual_len)) {
					continue;
				}
			} else {
				if (!is_printable_string (buf, string_size)) {
					continue;
				}
				actual_len = string_size;
			}

			if (actual_len < 2) {
				continue;
			}
			// Ensure the buffer is null-terminated at the actual string length
			buf[actual_len] = '\0';
			r_str_filter (buf, actual_len);
			if (actual_len > 60) {
				buf[57] = '.';
				buf[58] = '.';
				buf[59] = '\0';
			}
			r_list_foreach (refs, iter2, ref2) {
				if (ref2->addr == ref->addr) {
					const char *type = ref2->is_pointer ? "pointer" : "ascii";
					r_table_add_rowf (table, "xxxxxsss",
							(ut64)nth++, ref2->xref_addr, ref2->addr, (ut64)actual_len, (ut64)(actual_len + 1),
							".rodata", type, buf);
				}
			}
		}
	}

	// Print the table
	char *table_str = r_table_tostring (table);
	if (table_str) {
		eprintf ("%s\n", table_str);
		free (table_str);
	}

	r_table_free (table);
	r_list_free (processed);
	r_list_free (refs);
}

static bool sbpfcmd(RAnal *anal, const char *cmd) {
	R_RETURN_VAL_IF_FAIL (anal && cmd, false);

	if (r_str_startswith (cmd, "sbpf.analyze")) {
		const char *result = sbpf_analyze_strings (anal)? "completed": "failed";
		R_LOG_INFO ("sBPF string analysis %s", result);
		return true;
	}

	if (r_str_startswith (cmd, "sbpf.strings")) {
		sbpf_print_string_xrefs (anal);
		return true;
	}

	if (r_str_startswith (cmd, "sbpf")) {
		eprintf ("sBPF analysis plugin commands:\n");
		eprintf ("  a:sbpf.analyze  - Analyze sBPF strings and create flags\n");
		eprintf ("  a:sbpf.strings  - Display sBPF strings\n");
		return true;
	}

	return false;
}

RAnalPlugin r_anal_plugin_sbpf = {
	.meta = {
		.name = "sbpf",
		.desc = "Solana BPF analysis plugin with enhanced string detection",
		.license = "LGPL3",
		.author = "ulexec",
	},
	.cmd = sbpfcmd,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_sbpf,
	.version = R2_VERSION
};
#endif
