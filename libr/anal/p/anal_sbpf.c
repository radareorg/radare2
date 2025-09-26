/* radare2 - LGPL - Copyright 2025 - Analysis plugin for Solana BPF */

#include <r_anal.h>
#include <r_lib.h>
#include <r_bin.h>
#include <r_util.h>
#include <r_cons.h>
#include <r_flag.h>
#include <r_util/r_new_rbtree.h>

#define SBPF_PROGRAM_ADDR 	0x100000000ULL
#define SBPF_MAX_STRING_SIZE 0x100
#define SBPF_COMMENT_SIZE 512

typedef struct {
	ut64 addr;
	ut64 xref_addr;
	bool is_pointer; // true if this is a pointer to a string structure
	ut32 size; // for string pointers, this holds the size from the structure
} SbpfStringRef;

static bool sbpf_analyze_strings(RAnal *anal);

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

static bool is_printable_string(const ut8 *buf, ut32 size) {
	if (size < 1) {
		return false;
	}

	ut32 i;
	ut32 printable_count = 0;

	for (i = 0; i < size; i++) {
		// Allow null terminator at the end
		if (i == size - 1 && buf[i] == 0) {
			return printable_count > 0;
		}

		// Check if character is printable ASCII or common whitespace
		if ((buf[i] >= 0x20 && buf[i] <= 0x7e) ||
		    buf[i] == '\t' || buf[i] == '\n' || buf[i] == '\r') {
			printable_count++;
		} else if (buf[i] != 0) {
			return false;
		}
	}

	return printable_count > 0;
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

	// Validate size is reasonable (but not too small, and not a typical pointer value)
	if (size == 0 || size > 0x100) {
		return false;
	}

	// Check if string pointer is in data segment
	if (str_ptr < data_start || str_ptr >= data_end) {
		return false;
	}

	// Try to read the actual string to verify it's printable
	ut8 sample[0x100];
	ut32 sample_size = (size < 0x100) ? size : 0x100;
	if (!anal->iob.read_at (anal->iob.io, str_ptr, sample, sample_size)) {
		return false;
	}
	// Check if it's a printable string
	if (!is_printable_string (sample, sample_size)) {
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

		// Check if this is a LDDW instruction (0x18 in first byte)
		if ((buf[0] & 0xff) == 0x18) {
			// Second instruction should have opcode 0x00
			if (buf[8] != 0x00) {
				continue;
			}

			// Extract the 64-bit immediate value
			ut32 imm_low = r_read_le32 (buf + 4);
			ut32 imm_high = r_read_le32 (buf + 12);
			ut64 imm_val = ((ut64)imm_high << 32) | imm_low;

			// Check if the immediate points to the data segment
			if (imm_val >= data_start && imm_val < data_end) {
				// First check if this is a string pointer structure
				ut64 actual_str_addr;
				ut32 actual_str_size;
				bool is_string_pointer = sbpf_check_string_pointer (anal, imm_val, data_start, data_end,
				                                                    &actual_str_addr, &actual_str_size);

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
					if (is_string_pointer) {
						// Add BOTH the pointer structure AND the string it points to
						// First, add the pointer structure reference
						SbpfStringRef *ptr_ref = R_NEW0 (SbpfStringRef);
						ptr_ref->addr = imm_val;  // The pointer structure address
						ptr_ref->xref_addr = addr;
						ptr_ref->is_pointer = true;
						ptr_ref->size = actual_str_size;
						r_list_append (refs, ptr_ref);
						R_LOG_DEBUG ("Found pointer structure at 0x%"PFMT64x" (from LDDW at 0x%"PFMT64x")",
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
						R_LOG_DEBUG ("Found direct string ref at 0x%"PFMT64x" (from LDDW at 0x%"PFMT64x")",
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
						*start = section->vaddr;
						*end = section->vaddr + section->vsize;
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

	ut8 *buf = malloc (size + 1);
	if (!buf) {
		R_LOG_ERROR ("Failed to allocate memory for string");
		return;
	}

	// Read the string data
	if (!anal->iob.read_at (anal->iob.io, addr, buf, size)) {
		R_LOG_WARN ("Failed to read string data at 0x%"PFMT64x, addr);
		free (buf);
		return;
	}

	buf[size] = 0;

	ut32 actual_size = 0;
	ut32 i;
	for (i = 0; i < size; i++) {
		if (buf[i] == 0) {
			actual_size = i;
			break;
		}
	}

	// If no null terminator found in the range, check if it's printable up to size
	if (actual_size == 0) {
		if (is_printable_string (buf, size)) {
			actual_size = size;
			buf[size] = 0;
		} else {
			free (buf);
			return;
		}
	} else {
		if (!is_printable_string (buf, actual_size)) {
			free (buf);
			return;
		}
	}

	// Use the actual string size
	ut32 str_size = actual_size;

	// First, delete any existing metadata at this address
	r_meta_del (anal, R_META_TYPE_STRING, addr, UT64_MAX);

	// Create a properly null-terminated string for metadata
	char truncated_str[256];
	ut32 copy_len = str_size < 255 ? str_size : 255;
	r_str_ncpy (truncated_str, (char *)buf, copy_len + 1);

	// Add string metadata to radare2's metadata database
	if (!r_meta_set (anal, R_META_TYPE_STRING, addr, str_size, truncated_str)) {
		R_LOG_DEBUG ("Failed to set string metadata at 0x%"PFMT64x, addr);
	} else {
		R_LOG_DEBUG ("Set string metadata at 0x%"PFMT64x" size %u: %s", addr, str_size, truncated_str);
	}

	// Create xref from the instruction to the string
	if (xref_addr != UT64_MAX) {
		r_anal_xrefs_set (anal, xref_addr, addr, R_ANAL_REF_TYPE_STRN | R_ANAL_REF_TYPE_READ);

		// Add a comment at the xref address showing the string content
		char comment[SBPF_COMMENT_SIZE];
		char safe_str[256];
		ut32 comment_len = str_size < 250 ? str_size : 250;
		r_str_ncpy (safe_str, (char *)buf, comment_len + 1);

		// Replace non-printable chars with dots for the comment
		ut32 i;
		for (i = 0; i < comment_len; i++) {
			if (safe_str[i] < 0x20 || safe_str[i] > 0x7e) {
				if (safe_str[i] != '\t' && safe_str[i] != '\n') {
					safe_str[i] = '.';
				}
			}
		}

		// Create comment with string content (r2 adds "; " prefix automatically)
		if (str_size > 0x100) {
			snprintf (comment, sizeof (comment), "\"%s...\" (truncated, %u bytes total)", safe_str, str_size);
		} else {
			snprintf (comment, sizeof (comment), "\"%s\"", safe_str);
		}

		// Set comment at the instruction address
		r_meta_set_string (anal, R_META_TYPE_COMMENT, xref_addr, comment);
		R_LOG_DEBUG ("Added comment at 0x%"PFMT64x": %s", xref_addr, comment);
	}

	// Create a flag for the string
	R_LOG_INFO ("Attempting to create flag for string at 0x%"PFMT64x, addr);

	if (!anal->flb.f) {
		R_LOG_ERROR ("anal->flb.f is NULL - cannot create flags");
	} else if (!anal->flb.set) {
		R_LOG_ERROR ("anal->flb.set is NULL - cannot create flags");
	} else {
		// Build a proper flag name from the truncated string
		char flagname[R_FLAG_NAME_SIZE];
		char safe_str[64];

		// Copy only the actual string size
		ut32 copy_len = str_size < 63 ? str_size : 63;
		r_str_ncpy (safe_str, (char *)buf, copy_len + 1);

		// Filter for safe flag name
		r_str_filter (safe_str, -1);

		// Create the flag name with appropriate prefix
		const char *prefix = is_pointer ? "ptr" : "str";
		snprintf (flagname, sizeof (flagname), "%s.%s", prefix, safe_str);

		R_LOG_INFO ("Calling anal->flb.set with flag name: %s", flagname);

		// Unset any existing flag at this address first
		if (anal->flb.get_at && anal->flb.unset) {
			RFlagItem *existing = anal->flb.get_at (anal->flb.f, addr, false);
			if (existing && anal->flb.unset) {
				R_LOG_DEBUG ("Unsetting existing flag %s at 0x%"PFMT64x, existing->name, addr);
				anal->flb.unset (anal->flb.f, existing);
			}
		}

		// Create the flag
		RFlagItem *item = anal->flb.set(anal->flb.f, flagname, addr, str_size);
		if (item) {
			R_LOG_INFO ("Successfully created flag %s at 0x%"PFMT64x" size %u", flagname, addr, str_size);
		} else {
			snprintf (flagname, sizeof (flagname), "str_%08"PFMT64x, addr);
			R_LOG_INFO ("First flag failed, trying fallback: %s", flagname);
			item = anal->flb.set(anal->flb.f, flagname, addr, str_size);
			if (item) {
				R_LOG_INFO ("Created fallback flag %s at 0x%"PFMT64x" size %u", flagname, addr, str_size);
			} else {
				R_LOG_ERROR ("Failed to create any flag at 0x%"PFMT64x, addr);
			}
		}
	}

	free (buf);
}

static bool sbpf_analyze_strings(RAnal *anal) {
	R_RETURN_VAL_IF_FAIL (anal, false);

	ut64 code_start, code_end;
	if (!sbpf_find_segment_bounds (anal, 0, &code_start, &code_end)) {
		R_LOG_WARN ("Could not determine CODE segment bounds for string analysis");
		return false;
	}

	ut64 data_start, data_end;
	if (!sbpf_find_segment_bounds (anal, 1, &data_start, &data_end)) {
		if (!sbpf_find_segment_bounds (anal, 2, &data_start, &data_end)) {
			R_LOG_WARN ("Could not find data segment for string analysis");
			return false;
		}
	}

	RList *refs = sbpf_find_string_xrefs (anal, code_start, code_end, data_start, data_end);
	if (!refs) {
		return false;
	}

	R_LOG_INFO ("Found %d potential string references", r_list_length (refs));

	RListIter *iter, *next_iter;
	SbpfStringRef *ref, *next_ref;
	int strings_created = 0;

	// Track which string addresses we've already created to avoid duplicates
	RList *created_addrs = r_list_newf (NULL);
	if (!created_addrs) {
		r_list_free (refs);
		return false;
	}

	r_list_foreach (refs, iter, ref) {
		if (ref->addr < data_start || ref->addr >= data_end) {
			R_LOG_DEBUG ("Skipping reference to 0x%"PFMT64x" - outside data segment", ref->addr);
			continue;
		}

		// Check if we've already created a string at this address
		bool already_created = false;
		RListIter *addr_iter;
		void *addr_ptr;
		r_list_foreach (created_addrs, addr_iter, addr_ptr) {
			if ((ut64)(size_t)addr_ptr == ref->addr) {
				already_created = true;
				break;
			}
		}

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

			// Read the actual string for the flag name and comment
			ut8 *str_buf = malloc (size + 1);
			if (!str_buf) {
				continue;
			}

			char flagname[R_FLAG_NAME_SIZE];
			char comment_str[256] = {0};

			if (anal->iob.read_at (anal->iob.io, str_ptr, str_buf, size)) {
				str_buf[size] = 0;

				// Create safe string for flag name
				char safe_str[64];
				ut32 copy_len = size < 63 ? size : 63;
				r_str_ncpy (safe_str, (char *)str_buf, copy_len + 1);

				// Filter for safe flag name
				r_str_filter (safe_str, -1);

				// Create flag with format: ptr.<pointer_addr>_<string>
				snprintf (flagname, sizeof (flagname), "ptr.%"PFMT64x"_%s", ref->addr, safe_str);

				// Save string for comment (unfiltered for readability)
				ut32 comment_len = size < 250 ? size : 250;
				r_str_ncpy (comment_str, (char *)str_buf, comment_len + 1);

				// Replace non-printable chars with dots for the comment
				ut32 i;
				for (i = 0; i < comment_len; i++) {
					if (comment_str[i] < 0x20 || comment_str[i] > 0x7e) {
						if (comment_str[i] != '\t' && comment_str[i] != '\n') {
							comment_str[i] = '.';
						}
					}
				}
			} else {
				snprintf (flagname, sizeof (flagname), "ptr.%"PFMT64x, ref->addr);
			}

			if (anal->flb.set && anal->flb.f) {
				// Unset any existing flag at this address first
				if (anal->flb.get_at) {
					RFlagItem *existing = anal->flb.get_at (anal->flb.f, ref->addr, false);
					if (existing && anal->flb.unset) {
						R_LOG_DEBUG ("Unsetting existing flag %s at 0x%"PFMT64x, existing->name, ref->addr);
						anal->flb.unset (anal->flb.f, existing);
					}
				}

				RFlagItem *item = anal->flb.set(anal->flb.f, flagname, ref->addr, 16);
				if (item) {
					R_LOG_INFO ("Created pointer flag %s at 0x%"PFMT64x, flagname, ref->addr);
				} else {
					R_LOG_ERROR ("Failed to create pointer flag %s at 0x%"PFMT64x, flagname, ref->addr);
				}
			}

			// Add comment at the instruction address showing the string value
			if (ref->xref_addr != UT64_MAX && strlen(comment_str) > 0) {
				char comment[SBPF_COMMENT_SIZE];
				if (size > 250) {
					snprintf (comment, sizeof (comment), "ptr -> \"%s...\" (truncated, %u bytes total)", comment_str, (ut32)size);
				} else {
					snprintf (comment, sizeof (comment), "ptr -> \"%s\"", comment_str);
				}
				r_meta_set_string (anal, R_META_TYPE_COMMENT, ref->xref_addr, comment);
				R_LOG_DEBUG ("Added pointer comment at 0x%"PFMT64x": %s", ref->xref_addr, comment);
			}

			free (str_buf);
			r_list_append (created_addrs, (void*)(size_t)ref->addr);
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
		r_list_append (created_addrs, (void*)(size_t)ref->addr);
		strings_created++;
	}

	r_list_free (created_addrs);

	R_LOG_INFO ("Created %d strings", strings_created);

	r_list_free (refs);

	return true;
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
	if (!processed) {
		r_list_free (refs);
		return;
	}

	// Create table for output
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

		bool already_processed = false;
		SbpfStringRef *processed_ref;
		r_list_foreach (processed, iter2, processed_ref) {
			if (processed_ref->addr == ref->addr) {
				already_processed = true;
				break;
			}
		}

		if (already_processed) {
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

			if (size > SBPF_MAX_STRING_SIZE) {
				size = SBPF_MAX_STRING_SIZE;
			}

			// Read the actual string
			ut8 *str_buf = malloc (size + 1);
			if (!str_buf) {
				continue;
			}

			if (anal->iob.read_at (anal->iob.io, str_ptr, str_buf, size)) {
				str_buf[size] = 0;

				// Make safe for display
				char display_buf[256];
				ut32 display_len = (size < 250) ? size : 250;
				r_str_ncpy (display_buf, (char *)str_buf, display_len + 1);

				ut32 i;
				for (i = 0; i < display_len; i++) {
					if (display_buf[i] < 0x20 || display_buf[i] > 0x7e) {
						display_buf[i] = '.';
					}
				}
				if (size > 0x100) {
					strcat (display_buf, "...");
				}

				// Add pointer structure to table
				r_table_add_rowf (table, "xxxxxsss",
					(ut64)nth++, ref->xref_addr, ref->addr, (ut64)size, (ut64)(size + 1),
					".rodata", "pointer", display_buf);
			}
			free (str_buf);
			continue;
		} else {
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
		}

		ut8 *buf = malloc (string_size + 1);
		if (!buf) {
			continue;
		}

		if (anal->iob.read_at (anal->iob.io, ref->addr, buf, string_size)) {
			buf[string_size] = 0;

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

			if (!found_null) {
				if (is_printable_string (buf, string_size)) {
					actual_len = string_size;
				} else {
					free (buf);
					continue;
				}
			} else {
				if (!is_printable_string (buf, actual_len)) {
					free (buf);
					continue;
				}
			}

			if (actual_len < 4) {
				free (buf);
				continue;
			}

			char display_buf[80];
			if (actual_len > 60) {
				r_str_ncpy (display_buf, (char *)buf, 57);
				strcat (display_buf, "...");
			} else {
				r_str_ncpy (display_buf, (char *)buf, actual_len + 1);
			}

			for (i = 0; display_buf[i]; i++) {
				if (display_buf[i] < 0x20 || display_buf[i] > 0x7e) {
					display_buf[i] = '.';
				}
			}

			r_list_foreach (refs, iter2, ref2) {
				if (ref2->addr == ref->addr) {
					const char *type = ref2->is_pointer ? "pointer" : "ascii";
					r_table_add_rowf (table, "xxxxxsss",
						(ut64)nth++, ref2->xref_addr, ref2->addr, (ut64)actual_len, (ut64)(actual_len + 1),
						".rodata", type, display_buf);
				}
			}
		}
		free (buf);
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
		if (sbpf_analyze_strings (anal)) {
			eprintf ("sBPF string analysis completed\n");
		} else {
			eprintf ("sBPF string analysis failed\n");
		}
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