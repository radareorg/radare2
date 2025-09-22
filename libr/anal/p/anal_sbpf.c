/* radare2 - LGPL - Copyright 2025 - Analysis plugin for Solana BPF */

#include <r_anal.h>
#include <r_lib.h>
#include <r_bin.h>
#include <r_util.h>
#include <r_util/r_new_rbtree.h>

#define SBPF_PROGRAM_ADDR 	0x100000000ULL
#define SBPF_MAX_STRING_SIZE 0x100

typedef struct {
	ut64 addr;
	ut64 xref_addr;
} SbpfStringRef;

// Global flag to track if analysis has been done
static bool sbpf_strings_analyzed = false;

static void sbpf_try_auto_analyze(RAnal *anal);
static bool sbpf_analyze_strings(RAnal *anal);

static int sbpf_string_ref_cmp(const void *a, const void *b) {
	const SbpfStringRef *sa = (const SbpfStringRef *)a;
	const SbpfStringRef *sb = (const SbpfStringRef *)b;
	if (sa->addr < sb->addr) return -1;
	if (sa->addr > sb->addr) return 1;
	return 0;
}

static RList *sbpf_find_string_xrefs(RAnal *anal, ut64 from, ut64 to, ut64 data_start, ut64 data_end) {
	RList *refs = r_list_new();
	if (!refs) {
		return NULL;
	}

	if (!anal || !anal->iob.io) {
		return NULL;
	}

	R_LOG_DEBUG("Aggressive scan for LDDW instructions from 0x%"PFMT64x" to 0x%"PFMT64x, from, to);
	R_LOG_DEBUG("Looking for references to data segment 0x%"PFMT64x" - 0x%"PFMT64x, data_start, data_end);

	// LDDW instructions are 16 bytes but can appear at any 8-byte alignment
	ut64 addr;
	ut8 buf[24]; // Read extra to handle unaligned reads
	int lddw_count = 0;
	int data_refs = 0;

	for (addr = from; addr < to - 15; addr++) {
		if (!anal->iob.read_at (anal->iob.io, addr, buf, 16)) {
			continue;
		}

		// Check if this is a LDDW instruction (0x18 in first byte)
		if ((buf[0] & 0xff) == 0x18) {
			// Verify it's actually a valid LDDW by checking the second instruction
			// LDDW is a 16-byte instruction: first 8 bytes + second 8 bytes
			// Second instruction should have opcode 0x00
			if (buf[8] != 0x00) {
				continue;
			}

			lddw_count++;

			// Extract the 64-bit immediate value
			ut32 imm_low = r_read_le32 (buf + 4);
			ut32 imm_high = r_read_le32 (buf + 12);
			ut64 imm_val = ((ut64)imm_high << 32) | imm_low;

			// Check if the immediate points to the data segment
			if (imm_val >= data_start && imm_val < data_end) {
				// Check if we already have this reference (avoid duplicates)
				bool duplicate = false;
				RListIter *iter;
				SbpfStringRef *existing;
				r_list_foreach (refs, iter, existing) {
					if (existing->addr == imm_val && existing->xref_addr == addr) {
						duplicate = true;
						break;
					}
				}

				if (!duplicate) {
					data_refs++;
					SbpfStringRef *ref = R_NEW0 (SbpfStringRef);
					if (ref) {
						ref->addr = imm_val;
						ref->xref_addr = addr;
						r_list_append (refs, ref);
						R_LOG_DEBUG("Found LDDW at 0x%"PFMT64x" -> data at 0x%"PFMT64x, addr, imm_val);
					}
				}
			}

			// Skip ahead 8 bytes since we found a valid LDDW (they're 8-byte aligned)
			addr += 7; // Will be incremented by 1 in loop
		}
	}

	R_LOG_INFO("Found %d total LDDW instructions, %d reference the data segment", lddw_count, data_refs);

	r_list_sort (refs, sbpf_string_ref_cmp);

	return refs;
}

static bool sbpf_find_segment_bounds(RAnal *anal, int segment_index, ut64 *start, ut64 *end) {
	if (!anal || !anal->iob.io || !start || !end) {
		return false;
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

static void sbpf_create_string(RAnal *anal, ut64 addr, ut32 size, ut64 xref_addr) {
	R_LOG_DEBUG("sbpf_create_string called: addr=0x%"PFMT64x" size=%u xref=0x%"PFMT64x, addr, size, xref_addr);

	if (!anal || !anal->iob.io || size == 0 || size > SBPF_MAX_STRING_SIZE) {
		R_LOG_WARN("String creation skipped: anal=%p, size=%u, max=%u", anal, size, SBPF_MAX_STRING_SIZE);
		return;
	}

	ut8 *buf = malloc (size + 1);
	if (!buf) {
		R_LOG_ERROR("Failed to allocate memory for string");
		return;
	}

	// Read the string data
	if (!anal->iob.read_at (anal->iob.io, addr, buf, size)) {
		R_LOG_WARN("Failed to read string data at 0x%"PFMT64x, addr);
		free (buf);
		return;
	}

	buf[size] = 0;

	R_LOG_DEBUG("Read string data: %.30s%s", buf, size > 30 ? "..." : "");

	ut32 actual_size = 0;
	for (ut32 i = 0; i < size; i++) {
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

	if (actual_size < 4) {
		free (buf);
		return;
	}
	// Use the actual string size
	ut32 str_size = actual_size;

	// First, delete any existing metadata at this address
	r_meta_del (anal, R_META_TYPE_STRING, addr, UT64_MAX);

	// Create a properly null-terminated string for metadata
	char truncated_str[256];
	ut32 copy_len = str_size < 255 ? str_size : 255;
	memcpy(truncated_str, buf, copy_len);
	truncated_str[copy_len] = 0;

	// Add string metadata to radare2's metadata database
	if (!r_meta_set (anal, R_META_TYPE_STRING, addr, str_size, truncated_str)) {
		R_LOG_DEBUG ("Failed to set string metadata at 0x%"PFMT64x, addr);
	} else {
		R_LOG_DEBUG ("Set string metadata at 0x%"PFMT64x" size %u: %s", addr, str_size, truncated_str);
	}

	// Create xref from the instruction to the string
	if (xref_addr != UT64_MAX) {
		r_anal_xrefs_set (anal, xref_addr, addr, R_ANAL_REF_TYPE_STRN | R_ANAL_REF_TYPE_READ);
	}

	// Create a flag for the string
	R_LOG_INFO("Attempting to create flag for string at 0x%"PFMT64x, addr);

	if (!anal->flb.f) {
		R_LOG_ERROR("anal->flb.f is NULL - cannot create flags");
	} else if (!anal->flb.set) {
		R_LOG_ERROR("anal->flb.set is NULL - cannot create flags");
	} else {
		// Build a proper flag name from the truncated string
		char flagname[256];
		char safe_str[64];

		// Copy only the actual string size
		ut32 copy_len = str_size < 63 ? str_size : 63;
		memcpy(safe_str, buf, copy_len);
		safe_str[copy_len] = 0;

		// Filter for safe flag name
		r_str_filter(safe_str, -1);

		// Create the flag name
		snprintf(flagname, sizeof(flagname), "str.%s", safe_str);

		R_LOG_INFO("Calling anal->flb.set with flag name: %s", flagname);

		// Create the flag
		RFlagItem *item = anal->flb.set(anal->flb.f, flagname, addr, str_size);
		if (item) {
			R_LOG_INFO("Successfully created flag %s at 0x%"PFMT64x" size %u", flagname, addr, str_size);
		} else {
			snprintf(flagname, sizeof(flagname), "str_%08"PFMT64x, addr);
			R_LOG_INFO("First flag failed, trying fallback: %s", flagname);
			item = anal->flb.set(anal->flb.f, flagname, addr, str_size);
			if (item) {
				R_LOG_INFO("Created fallback flag %s at 0x%"PFMT64x" size %u", flagname, addr, str_size);
			} else {
				R_LOG_ERROR("Failed to create any flag at 0x%"PFMT64x, addr);
			}
		}
	}

	free (buf);
}

static bool sbpf_analyze_strings(RAnal *anal) {
	if (!anal) {
		return false;
	}

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

	R_LOG_INFO ("Scanning CODE segment 0x%"PFMT64x" - 0x%"PFMT64x" for LDDW instructions",
		code_start, code_end);
	R_LOG_INFO ("Data segment 0x%"PFMT64x" - 0x%"PFMT64x,
		data_start, data_end);

	RList *refs = sbpf_find_string_xrefs (anal, code_start, code_end, data_start, data_end);
	if (!refs) {
		return false;
	}

	R_LOG_INFO ("Found %d potential string references", r_list_length (refs));

	RListIter *iter, *next_iter;
	SbpfStringRef *ref, *next_ref;
	int strings_created = 0;

	r_list_foreach (refs, iter, ref) {
		if (ref->addr < data_start || ref->addr >= data_end) {
			R_LOG_DEBUG ("Skipping reference to 0x%"PFMT64x" - outside data segment", ref->addr);
			continue;
		}

		ut32 string_size = SBPF_MAX_STRING_SIZE;

		next_iter = iter->n;
		if (next_iter) {
			next_ref = (SbpfStringRef *)next_iter->data;
			if (next_ref->addr > ref->addr && next_ref->addr < data_end) {
				string_size = next_ref->addr - ref->addr;
			}
		} else {
			string_size = data_end - ref->addr;
		}

		if (string_size > SBPF_MAX_STRING_SIZE) {
			string_size = SBPF_MAX_STRING_SIZE;
		}

		R_LOG_DEBUG ("Creating string at 0x%"PFMT64x" with size %u (xref from 0x%"PFMT64x")",
			ref->addr, string_size, ref->xref_addr);
		sbpf_create_string (anal, ref->addr, string_size, ref->xref_addr);
		strings_created++;
	}

	R_LOG_INFO ("Created %d strings", strings_created);

	r_list_free (refs);

	return true;
}

static void sbpf_print_string_xrefs(RAnal *anal) {
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

	RList *processed = r_list_new();
	if (!processed) {
		r_list_free (refs);
		return;
	}

	eprintf ("nth xref          vaddr         len size section  type  string\n");
	eprintf ("―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――\n");

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

		ut32 string_size = SBPF_MAX_STRING_SIZE;

		r_list_foreach (refs, next_iter, next_ref) {
			if (next_ref->addr > ref->addr && next_ref->addr < data_end) {
				string_size = next_ref->addr - ref->addr;
				break;
			}
		}

		if (string_size > SBPF_MAX_STRING_SIZE) {
			string_size = SBPF_MAX_STRING_SIZE;
		}

		ut8 *buf = malloc(string_size + 1);
		if (!buf) {
			continue;
		}

		if (anal->iob.read_at (anal->iob.io, ref->addr, buf, string_size)) {
			buf[string_size] = 0;

			ut32 actual_len = 0;
			bool found_null = false;
			for (ut32 i = 0; i < string_size; i++) {
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
					free(buf);
					continue;
				}
			} else {
				if (!is_printable_string (buf, actual_len)) {
					free(buf);
					continue;
				}
			}

			if (actual_len < 4) {
				free(buf);
				continue;
			}

			char display_buf[80];
			if (actual_len > 60) {
				memcpy(display_buf, buf, 57);
				strcpy(display_buf + 57, "...");
			} else {
				memcpy(display_buf, buf, actual_len);
				display_buf[actual_len] = 0;
			}

			for (int i = 0; display_buf[i]; i++) {
				if (display_buf[i] < 0x20 || display_buf[i] > 0x7e) {
					display_buf[i] = '.';
				}
			}

			r_list_foreach (refs, iter2, ref2) {
				if (ref2->addr == ref->addr) {
					eprintf ("%-3d 0x%010"PFMT64x" 0x%010"PFMT64x" %-3u %-4u .rodata  ascii %s\n",
						nth++, ref2->xref_addr, ref2->addr, actual_len, actual_len + 1, display_buf);
				}
			}
		}
		free(buf);
	}

	r_list_free (processed);
	r_list_free (refs);
}

static bool sbpfcmd(RAnal *anal, const char *cmd) {
	if (!anal || !cmd) {
		return false;
	}

	sbpf_try_auto_analyze (anal);

	if (r_str_startswith (cmd, "sbpf.strings")) {
		sbpf_print_string_xrefs (anal);
		return true;
	}

	if (r_str_startswith (cmd, "sbpf")) {
		eprintf ("sBPF analysis plugin commands:\n");
		eprintf ("  a:sbpf.strings - Show string cross-references\n");
		return true;
	}

	return false;
}

static bool sbpf_init(RAnal *anal) {
	if (!anal) {
		return false;
	}
	sbpf_strings_analyzed = false;
	R_LOG_DEBUG("sBPF analysis plugin initialized");

	sbpf_try_auto_analyze(anal);

	return true;
}

static void sbpf_try_auto_analyze(RAnal *anal) {
	if (sbpf_strings_analyzed) {
		return;
	}

	// Check if we have proper conditions for analysis
	if (!anal || !anal->flb.f || !anal->flb.set) {
		R_LOG_DEBUG("sBPF auto-analysis skipped - flag bindings not ready");
		return;
	}

	// Check if we have an iob interface (indicates file is loaded)
	if (!anal->iob.io) {
		R_LOG_DEBUG("sBPF auto-analysis skipped - no IO available");
		return;
	}

	// Check if we have segments loaded
	ut64 code_start, code_end;
	if (!sbpf_find_segment_bounds (anal, 0, &code_start, &code_end)) {
		R_LOG_DEBUG("sBPF auto-analysis skipped - no CODE segment found");
		return;
	}

	// Check if we have data segment
	ut64 data_start, data_end;
	if (!sbpf_find_segment_bounds (anal, 1, &data_start, &data_end)) {
		R_LOG_DEBUG("sBPF auto-analysis skipped - no DATA segment found");
		return;
	}

	R_LOG_INFO("Running automatic sBPF string analysis...");
	if (sbpf_analyze_strings (anal)) {
		R_LOG_INFO("sBPF string analysis completed successfully");
		sbpf_strings_analyzed = true;
	} else {
		R_LOG_WARN("sBPF string analysis failed");
	}
}

static bool sbpf_fini(RAnal *anal) {
	if (!anal) {
		return false;
	}
	R_LOG_DEBUG ("Finalizing sBPF analysis plugin");
	return true;
}

static int sbpf_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	if (!sbpf_strings_analyzed) {
		sbpf_try_auto_analyze (anal);
	}

	return -1;
}

RAnalPlugin r_anal_plugin_sbpf = {
	.meta = {
		.name = "sbpf",
		.desc = "Solana BPF analysis plugin with enhanced string detection",
		.license = "LGPL3",
		.author = "ulexec",
	},
	.init = sbpf_init,
	.fini = sbpf_fini,
	.op = sbpf_op,
	.cmd = sbpfcmd,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_sbpf,
	.version = R2_VERSION
};
#endif