/* Original code from Yara dotnet.c, forked in 2017-2025 by pancake for radare2 */

/*
Copyright(c) 2015. The YARA Authors. All Rights Reserved.

Licensed under the Apache License, Version 2.0(the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>
#include <r_types.h>
#include <r_util.h>
#include <r_list.h>

#include "dotnet.h"

typedef struct _PE {
	const uint8_t *data;
	size_t data_size;
	void *object;
} PE;

static char *pe_get_dotnet_string(PE *pe, const uint8_t *string_offset, ut32 string_index) {
	// Start of string must be within boundary
	if (! (string_offset + string_index >= pe->data &&
		string_offset + string_index < pe->data + pe->data_size)) {
		return NULL;
	}
	// Calculate how much until end of boundary, don't scan past that.
	size_t remaining = (pe->data + pe->data_size) - (string_offset + string_index);
	// Search for a NULL terminator from start of string, up to remaining.
	char *start = (char *) (string_offset + string_index);
	char *eos = (char *)r_mem_mem ((void *)start, remaining, (void *)"\0", 1);
	return eos? start: NULL;
}

static uint32_t max_rows(int count, ...) {
	va_list ap;
	int i;
	uint32_t biggest;
	uint32_t x;

	if (count == 0) {
		return 0;
	}

	va_start (ap, count);
	biggest = va_arg (ap, uint32_t);

	for (i = 1; i < count; i++) {
		x = va_arg (ap, uint32_t);
		if (x > biggest) {
			biggest = x;
		}
	}

	va_end (ap);
	return biggest;
}

static STREAMS dotnet_parse_stream_headers(PE *pe, ut64 offset, ut64 metadata_root, ut32 num_streams) {
	char stream_name[DOTNET_STREAM_NAME_SIZE + 1];
	STREAMS headers = { 0 };
	unsigned int i;

	PSTREAM_HEADER stream_header = (PSTREAM_HEADER) (pe->data + offset);

	for (i = 0; i < num_streams; i++) {
		if (!struct_fits_in_pe (pe, stream_header, STREAM_HEADER)) {
			break;
		}

		char *start = (char *)stream_header->Name;

		if (!fits_in_pe (pe, start, DOTNET_STREAM_NAME_SIZE)) {
			break;
		}

		char *eos = (char *)r_mem_mem ((void *)start, DOTNET_STREAM_NAME_SIZE, (void *)"\0", 1);

		if (eos == NULL) {
			break;
		}

		strncpy (stream_name, stream_header->Name, DOTNET_STREAM_NAME_SIZE);
		stream_name[DOTNET_STREAM_NAME_SIZE] = '\0';

		// Store necessary bits to parse these later
		if (r_str_startswith (stream_name, "#GUID")) {
			headers.guid = stream_header;
		} else if (r_str_startswith (stream_name, "#~") && !headers.tilde) {
			headers.tilde = stream_header;
		} else if (r_str_startswith (stream_name, "#Strings") && !headers.string) {
			headers.string = stream_header;
		} else if (r_str_startswith (stream_name, "#Blob")) {
			headers.blob = stream_header;
		} else if (r_str_startswith (stream_name, "#US") && !headers.us) {
			headers.us = stream_header;
		}

		// Stream name is padded to a multiple of 4.
		stream_header = (PSTREAM_HEADER) ((uint8_t *)stream_header +
			sizeof (STREAM_HEADER) +
			strlen (stream_name) +
			4 - (strlen (stream_name) % 4));
	}

	return headers;
}

static void dotnet_parse_tilde_assemblyref(
	PE *pe,
	PTILDE_HEADER tilde_header,
	ut64 metadata_root,
	ROWS rows,
	INDEX_SIZES index_sizes,
	PSTREAMS streams,
	RList *libraries) {

	int bit_check, matched_bits = 0;
	uint32_t num_rows = 0;
	uint8_t *row_ptr = NULL;
	int i;
	char *name;

	// Validate we have the required streams
	if (!streams->tilde || !streams->string) {
		return;
	}

	// Number of rows is the number of bits set to 1 in Valid
	for (i = 0; i < 64; i++) {
		matched_bits += ((tilde_header->Valid >> i) & 0x01);
	}

	uint32_t *row_offset = (uint32_t *) (tilde_header + 1);
	uint8_t *table_offset = (uint8_t *)row_offset;
	table_offset += sizeof (uint32_t) * matched_bits;

	const uint8_t *string_offset = pe->data + metadata_root + streams->string->Offset;

	matched_bits = 0;

	// Parse AssemblyRef table
	for (bit_check = 0; bit_check < 64; bit_check++) {
		if (! ((tilde_header->Valid >> bit_check) & 0x01)) {
			continue;
		}

		if (!fits_in_pe (pe, table_offset, 1)) {
			return;
		}

		num_rows = *(row_offset + matched_bits);

		if (bit_check == BIT_ASSEMBLYREF) {
			// AssemblyRef structure: MajorVersion (2) MinorVersion (2) BuildNumber (2) RevisionNumber (2)
			// Flags (4) PublicKeyOrToken (blob) Name (string) Culture (string)
			row_ptr = table_offset;
			for (i = 0; i < num_rows; i++) {
				uint32_t row_size = 2 + 2 + 2 + 2 + 4 + (index_sizes.blob * 2) + (index_sizes.string * 2);
				if (!fits_in_pe (pe, row_ptr, row_size)) {
					break;
				}
				ut16 major = *(ut16 *)row_ptr;
				ut16 minor = *(ut16 *) (row_ptr + 2);
				ut16 build = *(ut16 *) (row_ptr + 4);
				ut16 revision = *(ut16 *) (row_ptr + 6);

				// Get assembly name from string stream
				// Skip flags (4) and PublicKeyOrToken (blob) to get to Name
				uint8_t *name_ptr = row_ptr + 4 + 4;
				if (index_sizes.blob == 4) {
					name_ptr += 4;
				} else {
					name_ptr += 2;
				}
				if (index_sizes.blob == 4) {
					name_ptr += 4;
				} else {
					name_ptr += 2;
				}

				if (index_sizes.string == 4) {
					name = pe_get_dotnet_string (pe, string_offset, *(ut32 *)name_ptr);
				} else {
					name = pe_get_dotnet_string (pe, string_offset, *(ut16 *)name_ptr);
				}

				if (name && name[0] != '\0') {
					DotNetLibrary *lib = R_NEW0 (DotNetLibrary);
					lib->name = strdup (name);
					lib->major_version = major;
					lib->minor_version = minor;
					lib->build_number = build;
					lib->revision_number = revision;
					lib->version = r_str_newf ("%d.%d.%d.%d", major, minor, build, revision);
					r_list_append (libraries, lib);
				}

				row_ptr += row_size;
			}
			return;
		} else {
			if (bit_check) {
				table_offset += (2 + index_sizes.string + (index_sizes.guid * 3)) * num_rows;
			} else {
				// Skip other tables
				return;
			}
		}
		matched_bits++;
	}
}

// Structure to hold TypeDef metadata for method and field matching
typedef struct {
	char *class_name;
	char *namespace;
	uint32_t method_list_start;
	uint32_t method_list_end;
	uint32_t field_list_start;
	uint32_t field_list_end;
} DotNetTypeDefInfo;

// Free function for DotNetField
static void dotnet_field_free(void *f) {
	if (f) {
		DotNetField *field = f;
		free (field->name);
		free (field);
	}
}

// Helper to find class name for a method index
static DotNetTypeDefInfo *dotnet_find_typedef_for_method_index(RList *typedefs, uint32_t method_idx) {
	RListIter *iter;
	DotNetTypeDefInfo *td;
	r_list_foreach (typedefs, iter, td) {
		// method_idx is 1-based in the MethodDef table
		// method_list_start/end are the ranges from TypeDef.MethodList field
		// Check if method_idx falls in this typedef's method range
		if (method_idx >= td->method_list_start && method_idx < td->method_list_end) {
			return td;
		}
	}
	return NULL;
}

// Parse Field table to collect field information for types
static void dotnet_parse_tilde_field(
	PE *pe,
	PTILDE_HEADER tilde_header,
	ut64 metadata_root,
	ROWS rows,
	INDEX_SIZES index_sizes,
	PSTREAMS streams,
	RList *typedef_info,
	RList *symbols) {

	int bit_check;
	uint32_t num_rows = 0;
	const uint8_t *string_offset = NULL;
	uint8_t *row_ptr = NULL;
	int i;
	char *name;

	// Validate we have the required streams
	if (!streams->tilde || !streams->string) {
		return;
	}
	int matched_bits = 0;

	// Number of rows is the number of bits set to 1 in Valid
	for (i = 0; i < 64; i++) {
		matched_bits += ((tilde_header->Valid >> i) & 0x01);
	}

	uint32_t *row_offset = (uint32_t *) (tilde_header + 1);
	uint8_t *table_offset = (uint8_t *)row_offset;
	table_offset += sizeof (uint32_t) * matched_bits;

	matched_bits = 0;

	string_offset = pe->data + metadata_root + streams->string->Offset;

	// Iterate through tables, looking for Field
	for (bit_check = 0; bit_check < 64; bit_check++) {
		if (! ((tilde_header->Valid >> bit_check) & 0x01)) {
			continue;
		}

		if (!fits_in_pe (pe, table_offset, 1)) {
			return;
		}

		num_rows = *(row_offset + matched_bits);

		if (bit_check == BIT_FIELD) {
			// Parse Field table
			// Structure: Flags (2) Name (string) Signature (blob)
			row_ptr = table_offset;
			uint32_t field_idx = 1; // Field indices are 1-based
			for (i = 0; i < num_rows; i++) {
				uint32_t row_size = 2 + index_sizes.string + index_sizes.blob;
				if (!fits_in_pe (pe, row_ptr, row_size)) {
					break;
				}
				ut16 flags = *(ut16 *)row_ptr;
				// Get field name from string stream
				if (index_sizes.string == 4) {
					name = pe_get_dotnet_string (pe, string_offset, *(ut32 *) (row_ptr + 2));
				} else {
					name = pe_get_dotnet_string (pe, string_offset, *(ut16 *) (row_ptr + 2));
				}

				if (name && name[0] != '\0') {
					// Find which typedef this field belongs to
					RListIter *iter;
					DotNetTypeDefInfo *td;
					r_list_foreach (typedef_info, iter, td) {
						if (field_idx >= td->field_list_start && field_idx < td->field_list_end) {
							// Find the corresponding DotNetSymbol
							char *full_name;
							if (td->namespace && td->namespace[0] != '\0') {
								full_name = r_str_newf ("%s.%s", td->namespace, td->class_name);
							} else {
								full_name = strdup (td->class_name);
							}
							RListIter *sym_iter;
							DotNetSymbol *sym;
							r_list_foreach (symbols, sym_iter, sym) {
								if (sym->type && !strcmp (sym->type, "typedef")) {
									char *sym_full_name;
									const char *ns = sym->namespace;
									if (R_STR_ISNOTEMPTY (ns)) {
										sym_full_name = r_str_newf ("%s.%s", ns, sym->name);
									} else {
										sym_full_name = strdup (sym->name);
									}
									if (!strcmp (sym_full_name, full_name)) {
										DotNetField *field = R_NEW0 (DotNetField);
										field->name = strdup (name);
										field->flags = flags;
										if (!sym->fields) {
											sym->fields = r_list_newf (dotnet_field_free);
										}
										r_list_append (sym->fields, field);
										free (sym_full_name);
										break;
									}
									free (sym_full_name);
								}
							}
							free (full_name);
							break;
						}
					}
				}

				row_ptr += row_size;
				field_idx++;
			}
			return;
		} else if (bit_check < BIT_FIELD) {
			// Skip tables before Field
			switch (bit_check) {
			case BIT_MODULE:
				table_offset += (2 + index_sizes.string + (index_sizes.guid * 3)) * num_rows;
				break;
			case BIT_TYPEREF:
				{
					// ResolutionScope is a coded index (module | moduleref | assemblyref)
					uint32_t resolution_scope_row_count = max_rows (3, rows.module, rows.moduleref, rows.assemblyref);
					uint8_t resolution_scope_size = (resolution_scope_row_count > (0xFFFF >> 0x02))? 4: 2;
					table_offset += (resolution_scope_size + (index_sizes.string * 2)) * num_rows;
				}
				break;
			case BIT_TYPEDEF:
				{
					uint32_t row_count = max_rows (3, rows.typedef_, rows.typeref, rows.typespec);
					uint8_t extends_index_size = (row_count > (0xFFFF >> 0x02))? 4: 2;
					uint8_t field_index_size = (rows.field > 0xFFFF)? 4: 2;
					uint8_t methoddef_index_size = (rows.methoddef > 0xFFFF)? 4: 2;
					table_offset += (4 + (index_sizes.string * 2) + extends_index_size + field_index_size + methoddef_index_size) * num_rows;
				}
				break;
			case BIT_FIELDPTR:
				table_offset += index_sizes.field * num_rows;
				break;
			default:
				break;
			}
		} else {
			// We've passed Field table
			return;
		}

		matched_bits++;
	}
}

static void dotnet_parse_tilde_typedef(
	PE *pe,
	PTILDE_HEADER tilde_header,
	ut64 metadata_root,
	ROWS rows,
	INDEX_SIZES index_sizes,
	PSTREAMS streams,
	RList *symbols) {

	uint8_t *table_offset = NULL;
	uint32_t *row_offset = NULL;
	int bit_check, matched_bits = 0;
	uint32_t num_rows = 0;
	const uint8_t *string_offset = NULL;
	uint8_t *row_ptr = NULL;
	int i;
	char *name, *namespace;

	// Validate we have the required streams
	if (!streams->tilde || !streams->string) {
		return;
	}

	// Number of rows is the number of bits set to 1 in Valid
	for (i = 0; i < 64; i++) {
		matched_bits += ((tilde_header->Valid >> i) & 0x01);
	}

	row_offset = (uint32_t *) (tilde_header + 1);
	table_offset = (uint8_t *)row_offset;
	table_offset += sizeof (uint32_t) * matched_bits;

	string_offset = pe->data + metadata_root + streams->string->Offset;

	matched_bits = 0;

	// Parse TypeDef table
	for (bit_check = 0; bit_check < 64; bit_check++) {
		if (! ((tilde_header->Valid >> bit_check) & 0x01)) {
			continue;
		}

		if (!fits_in_pe (pe, table_offset, 1)) {
			return;
		}

		num_rows = *(row_offset + matched_bits);

		if (bit_check == BIT_TYPEDEF) {
			// TypeDef structure: Flags (4) Name (string) Namespace (string) Extends (coded_idx) FieldList (field) MethodList (methoddef)
			uint32_t row_count = max_rows (3, rows.typedef_, rows.typeref, rows.typespec);
			uint8_t extends_index_size = (row_count > (0xFFFF >> 0x02))? 4: 2;
			uint8_t field_index_size = (rows.field > 0xFFFF)? 4: 2;
			uint8_t methoddef_index_size = (rows.methoddef > 0xFFFF)? 4: 2;
			row_ptr = table_offset;
			for (i = 0; i < num_rows; i++) {
				uint32_t row_size = 4 + (index_sizes.string * 2) + extends_index_size +
					field_index_size + methoddef_index_size;

				if (!fits_in_pe (pe, row_ptr, row_size)) {
					break;
				}

				uint32_t flags = *(ut32 *)row_ptr;

				// Get type name from string stream
				if (index_sizes.string == 4) {
					name = pe_get_dotnet_string (pe, string_offset, *(ut32 *) (row_ptr + 4));
					namespace = pe_get_dotnet_string (pe, string_offset, *(ut32 *) (row_ptr + 8));
				} else {
					name = pe_get_dotnet_string (pe, string_offset, *(ut16 *) (row_ptr + 4));
					namespace = pe_get_dotnet_string (pe, string_offset, *(ut16 *) (row_ptr + 6));
				}

				if (name && name[0] != '\0') {
					DotNetSymbol *sym = R_NEW0 (DotNetSymbol);
					sym->name = strdup (name);
					sym->namespace = (namespace && namespace[0] != '\0')? strdup (namespace): strdup ("");
					sym->type = strdup ("typedef");
					sym->flags = flags;
					sym->vaddr = 0; // TypeDefs don't have direct RVAs
					sym->size = 0;
					sym->fields = r_list_newf (dotnet_field_free);
					r_list_append (symbols, sym);
				}

				row_ptr += row_size;
			}
			return;
		} else if (bit_check < BIT_TYPEDEF) {
			// Skip tables that come before TypeDef
			num_rows = *(row_offset + matched_bits);
			switch (bit_check) {
			case BIT_MODULE:
				table_offset += (2 + index_sizes.string + (index_sizes.guid * 3)) * num_rows;
				break;
			case BIT_TYPEREF:
				{
					// TypeRef: ResolutionScope (coded index) + Name (string) + Namespace (string)
					// ResolutionScope is a ResolutionScope coded index (module | moduleref | assemblyref)
					uint32_t resolution_scope_row_count = max_rows (3, rows.module, rows.moduleref, rows.assemblyref);
					uint8_t resolution_scope_size = (resolution_scope_row_count > (0xFFFF >> 0x02))? 4: 2;
					table_offset += (resolution_scope_size + (index_sizes.string * 2)) * num_rows;
				}
				break;
			default:
				// Other tables before typedef (FieldPtr, Field, MethodDefPtr) - skip for now
				// This is incomplete but matches the original logic
				break;
			}
		} else if (bit_check > BIT_TYPEDEF) {
			// We've passed TypeDef table, stop looking
			return;
		}

		matched_bits++;
	}
}

static void dotnet_parse_tilde_methoddef(
	PE *pe,
	PTILDE_HEADER tilde_header,
	ut64 metadata_root,
	ROWS rows,
	INDEX_SIZES index_sizes,
	PSTREAMS streams,
	RList *symbols,
	RList *typedef_info) {

	uint8_t *table_offset = NULL;
	uint32_t *row_offset = NULL;
	int bit_check, matched_bits = 0;
	uint32_t num_rows = 0;
	const uint8_t *string_offset = NULL;
	uint8_t *row_ptr = NULL;
	int i;
	char *name;
	ut32 rva;
	uint32_t row_count;

	// Validate we have the required streams
	if (!streams->tilde || !streams->string) {
		return;
	}

	// Number of rows is the number of bits set to 1 in Valid
	for (i = 0; i < 64; i++) {
		matched_bits += ((tilde_header->Valid >> i) & 0x01);
	}

	row_offset = (uint32_t *) (tilde_header + 1);
	table_offset = (uint8_t *)row_offset;
	table_offset += sizeof (uint32_t) * matched_bits;

	string_offset = pe->data + metadata_root + streams->string->Offset;

	matched_bits = 0;

	// Iterate through tables in order, looking for MethodDef
	for (bit_check = 0; bit_check < 64; bit_check++) {
		if (! ((tilde_header->Valid >> bit_check) & 0x01)) {
			continue;
		}

		if (!fits_in_pe (pe, table_offset, 1)) {
			return;
		}

		num_rows = *(row_offset + matched_bits);
		if (bit_check == BIT_METHODDEF) {
			// Parse MethodDef table
			// Structure: RVA (4) ImplFlags (2) Flags (2) Name (string) Signature (blob) ParamList (param)
			row_count = max_rows (3, rows.methoddef, rows.memberref, rows.typedef_);
			uint8_t param_index_size = (row_count > (0xFFFF >> 0x01))? 4: 2;

			row_ptr = table_offset;
			for (i = 0; i < num_rows; i++) {
				uint32_t row_size = 4 + 2 + 2 + index_sizes.string + index_sizes.blob + param_index_size;
				if (!fits_in_pe (pe, row_ptr, row_size)) {
					break;
				}
				rva = *(ut32 *)row_ptr;
				ut16 impl_flags = *(ut16 *)(row_ptr + 4);

				// Get method name from string stream
				// Offset: RVA (4) + ImplFlags (2) + Flags (2) = 8
				if (index_sizes.string == 4) {
					name = pe_get_dotnet_string (pe, string_offset, *(ut32 *) (row_ptr + 8));
				} else {
					name = pe_get_dotnet_string (pe, string_offset, *(ut16 *) (row_ptr + 8));
				}
				if (R_STR_ISNOTEMPTY (name)) {
					DotNetSymbol *sym = R_NEW0 (DotNetSymbol);
					// Methods are 1-based, the method index is relative to MethodDef table start
					// So method 1 is the first row (i = 0), method 2 is the second row (i = 1), etc.
					uint32_t method_idx = i + 1;
					DotNetTypeDefInfo *parent_typedef = dotnet_find_typedef_for_method_index (typedef_info, method_idx);
					if (parent_typedef) {
						// Create fully qualified name: namespace.classname.methodname
						const char *ns = parent_typedef->namespace;
						if (R_STR_ISNOTEMPTY (ns)) {
							sym->name = r_str_newf ("%s.%s.%s", ns, parent_typedef->class_name, name);
						} else {
							sym->name = r_str_newf ("%s.%s", parent_typedef->class_name, name);
						}
					} else {
						sym->name = strdup (name);
					}
					sym->vaddr = rva; // RVA from the method table
					sym->size = 0;
					sym->type = strdup ("methoddef");
					sym->token = 0x06000000 | method_idx;
					// Set is_native based on ImplFlags
					// IL = 0x0000, Native = 0x0001, OPTIL = 0x0002, Runtime = 0x0003
					sym->is_native = (impl_flags & 0x0003) == 0x0001;
					r_list_append (symbols, sym);
				}

				row_ptr += row_size;
			}
			// Successfully parsed MethodDef, continue to process other tables
			table_offset += (4 + 2 + 2 + index_sizes.string + index_sizes.blob + param_index_size) * num_rows;
			matched_bits++;
			continue;
		} else if (bit_check == BIT_MEMBERREF) {
			// Parse MemberRef table
			// Structure: Class (coded_idx) Name (string) Signature (blob)
			row_count = max_rows (4, rows.methoddef, rows.memberref, rows.typeref, rows.typespec);
			uint8_t class_index_size = (row_count > (0xFFFF >> 0x03))? 4: 2;

			row_ptr = table_offset;
			for (i = 0; i < num_rows; i++) {
				uint32_t row_size = class_index_size + index_sizes.string + index_sizes.blob;

				if (!fits_in_pe (pe, row_ptr, row_size)) {
					break;
				}

				// Name
				if (index_sizes.string == 4) {
					name = pe_get_dotnet_string (pe, string_offset, *(ut32 *) (row_ptr + class_index_size));
				} else {
					name = pe_get_dotnet_string (pe, string_offset, *(ut16 *) (row_ptr + class_index_size));
				}

				if (name && name[0] != '\0') {
					DotNetSymbol *sym = R_NEW0 (DotNetSymbol);
					sym->name = strdup (name);
					sym->vaddr = 0; // MemberRef don't have RVA
					sym->size = 0;
					sym->type = strdup ("memberref");
					sym->token = 0x0A000000 | (i + 1);
					r_list_append (symbols, sym);
				}

				row_ptr += row_size;
			}
			// Successfully parsed MemberRef
			table_offset += (class_index_size + index_sizes.string + index_sizes.blob) * num_rows;
			matched_bits++;
			continue;
		} else if (bit_check == BIT_TYPEDEF) {
			// Parse TypeDef table
			// TypeDef structure: Flags (4) Name (string) Namespace (string) Extends (coded_idx) FieldList (field) MethodList (methoddef)
			row_count = max_rows (3, rows.typedef_, rows.typeref, rows.typespec);
			uint8_t extends_index_size = (row_count > (0xFFFF >> 0x02))? 4: 2;

			row_ptr = table_offset;
			for (i = 0; i < num_rows; i++) {
				uint32_t row_size = 4 + (index_sizes.string * 2) + extends_index_size +
					index_sizes.field + index_sizes.methoddef;

				if (!fits_in_pe (pe, row_ptr, row_size)) {
					break;
				}

				uint32_t flags = *(ut32 *)row_ptr;

				// Get type name from string stream
				// Offset: Flags (4)
				char *type_name, *namespace;
				if (index_sizes.string == 4) {
					type_name = pe_get_dotnet_string (pe, string_offset, *(ut32 *) (row_ptr + 4));
					namespace = pe_get_dotnet_string (pe, string_offset, *(ut32 *) (row_ptr + 8));
				} else {
					type_name = pe_get_dotnet_string (pe, string_offset, *(ut16 *) (row_ptr + 4));
					namespace = pe_get_dotnet_string (pe, string_offset, *(ut16 *) (row_ptr + 6));
				}

				if (type_name && type_name[0] != '\0') {
					DotNetSymbol *sym = R_NEW0 (DotNetSymbol);
					sym->name = strdup (type_name);
					sym->namespace = (namespace && namespace[0] != '\0')? strdup (namespace): strdup ("");
					sym->vaddr = 0; // TypeDefs don't have direct RVAs
					sym->type = strdup ("typedef");
					sym->flags = flags;

					// Extract MethodList index - stored in size field for now
					// MethodList is at offset: Flags (4) + Name (string) + Namespace (string) + Extends (coded_idx) + FieldList (field)
					uint8_t *method_list_ptr = row_ptr + 4 + (index_sizes.string * 2) + extends_index_size + index_sizes.field;
					if (index_sizes.methoddef == 4) {
						sym->size = *(ut32 *)method_list_ptr;
					} else {
						sym->size = *(ut16 *)method_list_ptr;
					}
					r_list_append (symbols, sym);
				}

				row_ptr += row_size;
			}
			// Successfully parsed TypeDef, continue to process other tables
			table_offset += (4 + (index_sizes.string * 2) +
						((max_rows (3, rows.typedef_, rows.typeref, rows.typespec) > (0xFFFF >> 0x02))? 4: 2) +
						index_sizes.field + index_sizes.methoddef) *
				num_rows;
			matched_bits++;
			continue;
		} else {
			// Calculate table size to skip this table
			uint32_t table_size = 0;
			switch (bit_check) {
			case BIT_MODULE:
				table_size = (2 + index_sizes.string + (index_sizes.guid * 3)) * num_rows;
				break;
			case BIT_TYPEREF:
				// ResolutionScope is a coded index (module | moduleref | assemblyref)
				row_count = max_rows (3, rows.module, rows.moduleref, rows.assemblyref);
				table_size = ((row_count > (0xFFFF >> 0x02)? 4: 2) + (index_sizes.string * 2)) * num_rows;
				break;
#if 0
			case BIT_TYPEDEF:
				row_count = max_rows (3, rows.typedef_, rows.typeref, rows.typespec);
				table_size = (4 + (index_sizes.string * 2) + (row_count > (0xFFFF >> 0x02)? 4: 2) +
						index_sizes.field + index_sizes.methoddef) *
					num_rows;
				break;
#endif
			case BIT_FIELDPTR:
				table_size = (index_sizes.field) * num_rows;
				break;
			case BIT_FIELD:
				table_size = (2 + index_sizes.string + index_sizes.blob) * num_rows;
				break;
			case BIT_METHODDEFPTR:
				table_size = (index_sizes.methoddef) * num_rows;
				break;
			case BIT_PARAM:
				table_size = (2 + 2 + index_sizes.string) * num_rows;
				break;
			case BIT_INTERFACEIMPL:
				row_count = max_rows (3, rows.typedef_, rows.typeref, rows.typespec);
				table_size = (index_sizes.typedef_ + (row_count > (0xFFFF >> 0x02)? 4: 2)) * num_rows;
				break;
#if 0
			case BIT_MEMBERREF:
				row_count = max_rows (4, rows.methoddef, rows.memberref, rows.typeref, rows.typespec);
				table_size = ((row_count > (0xFFFF >> 0x03)? 4: 2) + index_sizes.string + index_sizes.blob) * num_rows;
				break;
#endif
			case BIT_CONSTANT:
				row_count = max_rows (3, rows.field, rows.param, rows.property);
				table_size = (2 + (row_count > (0xFFFF >> 0x02)? 4: 2) + index_sizes.blob) * num_rows;
				break;
			case BIT_CUSTOMATTRIBUTE:
				row_count = max_rows (3, rows.methoddef, rows.field, rows.param);
				table_size = ((row_count > (0xFFFF >> 0x05)? 4: 2) + index_sizes.memberref + index_sizes.blob) * num_rows;
				break;
			case BIT_FIELDMARSHAL:
				row_count = max_rows (2, rows.field, rows.param);
				table_size = ((row_count > (0xFFFF >> 0x01)? 4: 2) + index_sizes.blob) * num_rows;
				break;
			case BIT_DECLSECURITY:
				row_count = max_rows (3, rows.typedef_, rows.methoddef, rows.assembly);
				table_size = (2 + (row_count > (0xFFFF >> 0x02)? 4: 2) + index_sizes.blob) * num_rows;
				break;
			case BIT_CLASSLAYOUT:
				table_size = (2 + 4 + index_sizes.typedef_) * num_rows;
				break;
			case BIT_FIELDLAYOUT:
				table_size = (4 + index_sizes.field) * num_rows;
				break;
			case BIT_STANDALONESIG:
				table_size = (index_sizes.blob) * num_rows;
				break;
			case BIT_EVENTMAP:
				table_size = (index_sizes.typedef_ + index_sizes.event) * num_rows;
				break;
			case BIT_EVENTPTR:
				table_size = (index_sizes.event) * num_rows;
				break;
			case BIT_EVENT:
				table_size = (2 + index_sizes.string + index_sizes.typedef_) * num_rows;
				break;
			case BIT_PROPERTYMAP:
				table_size = (index_sizes.typedef_ + index_sizes.property) * num_rows;
				break;
			case BIT_PROPERTYPTR:
				table_size = (index_sizes.property) * num_rows;
				break;
			case BIT_PROPERTY:
				table_size = (2 + index_sizes.string + index_sizes.blob) * num_rows;
				break;
			case BIT_METHODSEMANTICS:
				row_count = max_rows (2, rows.event, rows.property);
				table_size = (2 + index_sizes.methoddef + (row_count > (0xFFFF >> 0x01)? 4: 2)) * num_rows;
				break;
			case BIT_METHODIMPL:
				row_count = max_rows (2, rows.methoddef, rows.memberref);
				table_size = (index_sizes.typedef_ + index_sizes.methoddef + (row_count > (0xFFFF >> 0x01)? 4: 2)) * num_rows;
				break;
			case BIT_MODULEREF:
				table_size = (index_sizes.string) * num_rows;
				break;
			case BIT_TYPESPEC:
				table_size = (index_sizes.blob) * num_rows;
				break;
			case BIT_IMPLMAP:
				row_count = max_rows (3, rows.field, rows.methoddef, rows.typedef_);
				table_size = (2 + (row_count > (0xFFFF >> 0x01)? 4: 2) + index_sizes.string + index_sizes.moduleref) * num_rows;
				break;
			case BIT_FIELDRVA:
				table_size = (4 + index_sizes.field) * num_rows;
				break;
			case BIT_ENCLOG:
				table_size = (4) * num_rows;
				break;
			case BIT_ENCMAP:
				table_size = (4) * num_rows;
				break;
			case BIT_ASSEMBLY:
				table_size = (2 + 2 + 2 + 2 + 4 + index_sizes.blob + (index_sizes.string * 2)) * num_rows;
				break;
			case BIT_ASSEMBLYPROCESSOR:
				table_size = (4) * num_rows;
				break;
			case BIT_ASSEMBLYOS:
				table_size = (4 + 4 + 4) * num_rows;
				break;
			case BIT_ASSEMBLYREF:
				table_size = (2 + 2 + 2 + 2 + 4 + (index_sizes.blob * 2) + (index_sizes.string * 2)) * num_rows;
				break;
			case BIT_ASSEMBLYREFPROCESSOR:
				table_size = (4 + index_sizes.assemblyrefprocessor) * num_rows;
				break;
			case BIT_ASSEMBLYREFOS:
				table_size = (4 + 4 + 4 + index_sizes.assemblyref) * num_rows;
				break;
			case BIT_FILE:
				table_size = (4 + index_sizes.string + index_sizes.blob) * num_rows;
				break;
			case BIT_EXPORTEDTYPE:
				row_count = max_rows (3, rows.file, rows.assemblyref, rows.exportedtype);
				table_size = (4 + 4 + (index_sizes.string * 2) + (row_count > (0xFFFF >> 0x02)? 4: 2)) * num_rows;
				break;
			case BIT_MANIFESTRESOURCE:
				row_count = max_rows (2, rows.file, rows.assemblyref);
				table_size = (4 + 4 + index_sizes.string + (row_count > (0xFFFF >> 0x02)? 4: 2)) * num_rows;
				break;
			case BIT_NESTEDCLASS:
				table_size = (index_sizes.typedef_ * 2) * num_rows;
				break;
			case BIT_GENERICPARAM:
				row_count = max_rows (2, rows.typedef_, rows.methoddef);
				table_size = (2 + 2 + (row_count > (0xFFFF >> 0x01)? 4: 2) + index_sizes.string) * num_rows;
				break;
			case BIT_METHODSPEC:
				row_count = max_rows (2, rows.methoddef, rows.memberref);
				table_size = ((row_count > (0xFFFF >> 0x01)? 4: 2) + index_sizes.blob) * num_rows;
				break;
			case BIT_GENERICPARAMCONSTRAINT:
				row_count = max_rows (3, rows.typedef_, rows.typeref, rows.typespec);
				table_size = (index_sizes.genericparam + (row_count > (0xFFFF >> 0x02)? 4: 2)) * num_rows;
				break;
			default:
				return;
			}
			table_offset += table_size;
		}
		matched_bits++;
	}
}

// Helper function to collect typedef metadata for method association
static RList *dotnet_collect_typedefs(PE *pe, ut64 metadata_root, PSTREAMS streams, ROWS rows, INDEX_SIZES index_sizes) {
	PTILDE_HEADER tilde_header = (PTILDE_HEADER) (pe->data + metadata_root + streams->tilde->Offset);
	uint32_t *row_offset = (uint32_t *) (tilde_header + 1);
	const uint8_t *string_offset = pe->data + metadata_root + streams->string->Offset;
	uint8_t *table_offset = (uint8_t *)row_offset;
	int j, bit_check, matched_bits = 0;
	uint32_t num_rows;
	RList *typedef_info = r_list_newf ((RListFree)free);

	// Calculate offset to TypeDef table
	// First count how many tables are present so we can skip the row-counts array
	for (j = 0; j < 64; j++) {
		matched_bits += ((tilde_header->Valid >> j) & 0x01);
	}
	// Advance past the row-count array (one uint32_t per present table)
	table_offset += sizeof (uint32_t) * matched_bits;
	matched_bits = 0;
	for (bit_check = 0; bit_check < 64; bit_check++) {
		if (! ((tilde_header->Valid >> bit_check) & 0x01)) {
			continue;
		}

		if (bit_check == BIT_TYPEDEF) {
			// Found TypeDef table, parse it
			uint32_t row_count = max_rows (3, rows.typedef_, rows.typeref, rows.typespec);
			uint8_t extends_index_size = (row_count > (0xFFFF >> 0x02))? 4: 2;
			uint8_t field_index_size = (rows.field > 0xFFFF)? 4: 2;
			uint8_t methoddef_index_size = (rows.methoddef > 0xFFFF)? 4: 2;
			num_rows = *(row_offset + matched_bits);

			uint8_t *row_ptr = table_offset;

			int i;
			for (i = 0; i < num_rows; i++) {
				uint32_t row_size = 4 + (index_sizes.string * 2) + extends_index_size + field_index_size + methoddef_index_size;

				if (!fits_in_pe (pe, row_ptr, row_size)) {
					break;
				}

				uint32_t name_idx = 0, ns_idx = 0;
				char *type_name, *namespace;
				if (index_sizes.string == 4) {
					name_idx = *(ut32 *) (row_ptr + 4);
					ns_idx = *(ut32 *) (row_ptr + 8);
				} else {
					name_idx = *(ut16 *) (row_ptr + 4);
					ns_idx = *(ut16 *) (row_ptr + 6);
				}
				type_name = pe_get_dotnet_string (pe, string_offset, name_idx);
				namespace = pe_get_dotnet_string (pe, string_offset, ns_idx);

				// Extract FieldList and MethodList indices
				// Layout: Flags (4) + Name (string) + Namespace (string) + Extends (coded_idx) + FieldList (field) + MethodList (methoddef)
				uint8_t *field_list_ptr = row_ptr + 4 + (index_sizes.string * 2) + extends_index_size;
				uint8_t *method_list_ptr = field_list_ptr + index_sizes.field;

				uint32_t field_list_idx, method_list_idx;
				if (index_sizes.field == 4) {
					field_list_idx = *(ut32 *)field_list_ptr;
				} else {
					field_list_idx = *(ut16 *)field_list_ptr;
				}
				if (index_sizes.methoddef == 4) {
					method_list_idx = *(ut32 *)method_list_ptr;
				} else {
					method_list_idx = *(ut16 *)method_list_ptr;
				}

				// Find next typedef's lists to know the range for this class
				uint32_t next_field_list_idx = rows.field + 1; // Default to end
				uint32_t next_method_list_idx = rows.methoddef + 1; // Default to end
				uint8_t *next_row_ptr = row_ptr + row_size;
				if (i + 1 < num_rows && fits_in_pe (pe, next_row_ptr, row_size)) {
					uint8_t *next_field_list_ptr = next_row_ptr + 4 + (index_sizes.string * 2) + extends_index_size;
					uint8_t *next_method_list_ptr = next_field_list_ptr + index_sizes.field;
					if (index_sizes.field == 4) {
						next_field_list_idx = *(ut32 *)next_field_list_ptr;
					} else {
						next_field_list_idx = *(ut16 *)next_field_list_ptr;
					}
					if (index_sizes.methoddef == 4) {
						next_method_list_idx = *(ut32 *)next_method_list_ptr;
					} else {
						next_method_list_idx = *(ut16 *)next_method_list_ptr;
					}
				}

				DotNetTypeDefInfo *td = R_NEW0 (DotNetTypeDefInfo);
				td->class_name = (type_name && type_name[0] != '\0')? strdup (type_name): strdup ("<unnamed>");
				td->namespace = (namespace && namespace[0] != '\0')? strdup (namespace): strdup ("");
				td->field_list_start = field_list_idx;
				td->field_list_end = next_field_list_idx;
				td->method_list_start = method_list_idx;
				td->method_list_end = next_method_list_idx;
				r_list_append (typedef_info, td);
				// Next Row
				row_ptr += row_size;
			}
			break;
		} else if (bit_check < BIT_TYPEDEF) {
			// Skip tables before TypeDef
			num_rows = *(row_offset + matched_bits);
			// Calculate row size for this table and skip it
			switch (bit_check) {
			case BIT_MODULE:
				table_offset += (2 + index_sizes.string + (index_sizes.guid * 3)) * num_rows;
				break;
			case BIT_TYPEREF:
				{
					// TypeRef: ResolutionScope (coded index) + Name (string) + Namespace (string)
					// ResolutionScope is a ResolutionScope coded index (module | moduleref | assemblyref)
					uint32_t resolution_scope_row_count = max_rows (3, rows.module, rows.moduleref, rows.assemblyref);
					uint8_t resolution_scope_size = (resolution_scope_row_count > (0xFFFF >> 0x02))? 4: 2;
					table_offset += (resolution_scope_size + (index_sizes.string * 2)) * num_rows;
				}
				break;
#if 0
			case BIT_FIELDPTR:
				table_offset += index_sizes.field * num_rows;
				break;
#endif
#if 0
			case BIT_FIELD:
				table_offset += (2 + index_sizes.string + index_sizes.blob) * num_rows;
				break;
#endif
#if 0
			case BIT_METHODDEFPTR:
				table_offset += index_sizes.methoddef * num_rows;
				break;
#endif
			default:
				// Other tables shouldn't appear before TypeDef in standard order
				break;
			}
		}

		matched_bits++;
	}

	return typedef_info;
}

static void dotnet_parse_tilde(PE *pe, ut64 metadata_root, PSTREAMS streams, RList *symbols) {
	PTILDE_HEADER tilde_header;
	uint32_t *row_offset = NULL;
	int bit_check;
	int matched_bits = 0;
	ROWS rows;
	INDEX_SIZES index_sizes;

	if (!streams->tilde || !streams->string) {
		return;
	}

	// Default all rows to 0
	memset (&rows, '\0', sizeof (ROWS));

	// Default index sizes are 2. Will be bumped to 4 if necessary.
	memset (&index_sizes, 2, sizeof (index_sizes));

	tilde_header = (PTILDE_HEADER) (pe->data +
		metadata_root +
		streams->tilde->Offset);

	if (!struct_fits_in_pe (pe, tilde_header, TILDE_HEADER)) {
		return;
	}

	// Set index sizes for various heaps.
	if (tilde_header->HeapSizes & 0x01) {
		index_sizes.string = 4;
	}
	if (tilde_header->HeapSizes & 0x02) {
		index_sizes.guid = 4;
	}
	if (tilde_header->HeapSizes & 0x04) {
		index_sizes.blob = 4;
	}

	row_offset = (uint32_t *) (tilde_header + 1);

	// Walk all the bits first to collect row counts
	for (bit_check = 0; bit_check < 64; bit_check++) {
		if (! ((tilde_header->Valid >> bit_check) & 0x01)) {
			continue;
		}

#define ROW_CHECK(name) \
	if (fits_in_pe (pe, row_offset, (matched_bits + 1) * sizeof (uint32_t))) \
		rows.name = *(row_offset + matched_bits);

#define ROW_CHECK_WITH_INDEX(name) \
	ROW_CHECK (name); \
	if (rows.name > 0xFFFF) \
		index_sizes.name = 4;

		switch (bit_check) {
		case BIT_MODULE:
			ROW_CHECK (module);
			break;
		case BIT_MODULEREF:
			ROW_CHECK_WITH_INDEX (moduleref);
			break;
		case BIT_ASSEMBLYREF:
			ROW_CHECK_WITH_INDEX (assemblyref);
			break;
		case BIT_TYPEREF:
			ROW_CHECK (typeref);
			break;
		case BIT_METHODDEF:
			ROW_CHECK_WITH_INDEX (methoddef);
			break;
		case BIT_MEMBERREF:
			ROW_CHECK_WITH_INDEX (memberref);
			break;
		case BIT_TYPEDEF:
			ROW_CHECK_WITH_INDEX (typedef_);
			break;
		case BIT_TYPESPEC:
			ROW_CHECK (typespec);
			break;
		case BIT_FIELD:
			ROW_CHECK_WITH_INDEX (field);
			break;
		case BIT_PARAM:
			ROW_CHECK_WITH_INDEX (param);
			break;
		case BIT_PROPERTY:
			ROW_CHECK_WITH_INDEX (property);
			break;
		case BIT_INTERFACEIMPL:
			ROW_CHECK (interfaceimpl);
			break;
		case BIT_EVENT:
			ROW_CHECK_WITH_INDEX (event);
			break;
		case BIT_STANDALONESIG:
			ROW_CHECK (standalonesig);
			break;
		case BIT_ASSEMBLY:
			ROW_CHECK (assembly);
			break;
		case BIT_FILE:
			ROW_CHECK (file);
			break;
		case BIT_EXPORTEDTYPE:
			ROW_CHECK (exportedtype);
			break;
		case BIT_MANIFESTRESOURCE:
			ROW_CHECK (manifestresource);
			break;
		case BIT_GENERICPARAM:
			ROW_CHECK_WITH_INDEX (genericparam);
			break;
		case BIT_GENERICPARAMCONSTRAINT:
			ROW_CHECK (genericparamconstraint);
			break;
		case BIT_METHODSPEC:
			ROW_CHECK (methodspec);
			break;
		default:
			break;
		}

		matched_bits++;
	}

	// Now parse the tables with the row information we collected
	// Collect typedef metadata for method and field association
	RList *typedef_info = dotnet_collect_typedefs (pe, metadata_root, streams, rows, index_sizes);

	// Parse typedef first to establish class definitions
	dotnet_parse_tilde_typedef (pe, tilde_header, metadata_root, rows, index_sizes, streams, symbols);
	// Parse fields to associate them with classes
	dotnet_parse_tilde_field (pe, tilde_header, metadata_root, rows, index_sizes, streams, typedef_info, symbols);
	// Then parse methoddef to assign methods to classes with full qualified names
	dotnet_parse_tilde_methoddef (pe, tilde_header, metadata_root, rows, index_sizes, streams, symbols, typedef_info);

	// Clean up typedef info
	r_list_free (typedef_info);
}

static RList *dotnet_parse_com(PE *pe, ut64 baddr) {
	PNET_METADATA metadata;
	ut64 metadata_root;
	STREAMS headers;
	ut16 num_streams;
	RList *symbols = NULL;
	st64 offset = -1;
	int i, j, metadata_offset = -1;

	symbols = r_list_newf ((RListFree)free);
	if (!symbols) {
		return NULL;
	}

	// Try to find the CLI header by looking for the magic number
	// The NET_METADATA_MAGIC (0x424a5342) appears right after the CLI header structure
	// The CLI header structure is: Size (4) + MajorVersion (2) + MinorVersion (2) +
	// MetaDataDir (8) + ... so metadata usually starts 8-20 bytes after cli header start
	if (pe->data_size > 0x100) {
		for (i = 0x40; i < (int)pe->data_size - (int)sizeof (NET_METADATA); i++) {
			PNET_METADATA test_metadata = (PNET_METADATA) (pe->data + i);
			if (test_metadata->Magic == NET_METADATA_MAGIC) {
				metadata_offset = i; // Save the metadata offset
				// Found metadata magic at offset i
				// The metadata in .NET files is typically preceded by the CLI header
				// The CLI header can be quite far before the metadata (hundreds of bytes)
				// Search back to find the CLI header with a wider range
				// Search range: go back up to 0x400 bytes or to start of file
				int search_start = (i > 0x400)? (i - 0x400): 0;
				for (j = i - 1; j >= search_start; j--) {
#if 0
					if (j < 0) {
						continue;
					}
#endif
					PCLI_HEADER cli = (PCLI_HEADER) (pe->data + j);
					if (cli->Size == 0x48 || cli->Size == 0x44) {
						// Verify the version looks reasonable
						if (cli->MajorRuntimeVersion >= 1 && cli->MajorRuntimeVersion <= 5) {
							offset = j;
							break;
						}
					}
				}
				if (offset >= 0) {
					break;
				}
			}
		}
	}

	if (offset < 0) {
		return symbols;
	}

	if (!struct_fits_in_pe (pe, pe->data + offset, CLI_HEADER)) {
		return symbols;
	}

	// The CLI header contains an RVA to the metadata, not a direct offset
	// Use the offset where we found the metadata magic
	metadata_root = metadata_offset;

	if (!struct_fits_in_pe (pe, pe->data + metadata_root, NET_METADATA)) {
		return symbols;
	}

	metadata = (PNET_METADATA) (pe->data + metadata_root);

	if (metadata->Magic != NET_METADATA_MAGIC) {
		return symbols;
	}

	// Version length must be between 1 and 255, and be a multiple of 4.
	if (metadata->Length == 0 ||
		metadata->Length > 255 ||
		metadata->Length % 4 != 0 ||
		!fits_in_pe (pe, pe->data + metadata_root, metadata->Length)) {
		return symbols;
	}

	// The metadata structure has some variable length records after the version.
	offset = metadata_root + sizeof (NET_METADATA) + metadata->Length + 2;

	// 2 bytes for Streams.
	if (!fits_in_pe (pe, pe->data + offset, 2)) {
		return symbols;
	}

	num_streams = (ut16) *(pe->data + offset);
	offset += 2;

	headers = dotnet_parse_stream_headers (pe, offset, metadata_root, num_streams);

	// Parse the #~ stream which contains the metadata tables
	if (headers.tilde && headers.string && headers.blob) {
		eprintf ("[dotnet] Parsing tilde stream\n");
		dotnet_parse_tilde (pe, metadata_root, &headers, symbols);
		eprintf ("[dotnet] After parse_tilde: %d symbols\n", r_list_length (symbols));
	} else {
		eprintf ("[dotnet] Missing required streams: tilde=%p, string=%p, blob=%p\n",
			headers.tilde, headers.string, headers.blob);
	}

	return symbols;
}

// entrypoint - returns a list of DotNetSymbol pointers
RList *dotnet_parse(const ut8 *buf, int size, ut64 baddr) {
	PE pe = { buf, (ut32)size, NULL };
	return dotnet_parse_com (&pe, baddr);
}

RList *dotnet_parse_libs(const ut8 *buf, int size) {
	PNET_METADATA metadata;
	ut64 metadata_root;
	STREAMS headers;
	ut16 num_streams;
	RList *libraries = NULL;
	st64 offset = -1;
	int i, j, metadata_offset = -1;
	PE pe_struct = { buf, (ut32)size, NULL };
	PE *pe = &pe_struct;

	libraries = r_list_newf ((RListFree)free);
	if (!libraries) {
		return NULL;
	}

	// Try to find the CLI header by looking for the magic number
	if (pe->data_size > 0x100) {
		for (i = 0x40; i < (int)pe->data_size - (int)sizeof (NET_METADATA); i++) {
			PNET_METADATA test_metadata = (PNET_METADATA) (pe->data + i);
			if (test_metadata->Magic == NET_METADATA_MAGIC) {
				metadata_offset = i;
				int search_start = (i > 0x400)? (i - 0x400): 0;
				for (j = i - 1; j >= search_start; j--) {
#if 0
					if (j < 0) {
						continue;
					}
#endif
					PCLI_HEADER cli = (PCLI_HEADER) (pe->data + j);
					if (cli->Size == 0x48 || cli->Size == 0x44) {
						if (cli->MajorRuntimeVersion >= 1 && cli->MajorRuntimeVersion <= 5) {
							offset = j;
							break;
						}
					}
				}
				if (offset >= 0) {
					break;
				}
			}
		}
	}

	if (offset < 0) {
		return libraries;
	}

	if (! (fits_in_pe (pe, pe->data + offset, sizeof (CLI_HEADER)))) {
		return libraries;
	}

	metadata_root = metadata_offset;

	if (! (fits_in_pe (pe, pe->data + metadata_root, sizeof (NET_METADATA)))) {
		return libraries;
	}

	metadata = (PNET_METADATA) (pe->data + metadata_root);

	if (metadata->Magic != NET_METADATA_MAGIC) {
		return libraries;
	}

	if (metadata->Length == 0 ||
		metadata->Length > 255 ||
		metadata->Length % 4 != 0 ||
		! (fits_in_pe (pe, pe->data + metadata_root, metadata->Length))) {
		return libraries;
	}

	offset = metadata_root + sizeof (NET_METADATA) + metadata->Length + 2;

	if (! (fits_in_pe (pe, pe->data + offset, 2))) {
		return libraries;
	}

	num_streams = (ut16) *(pe->data + offset);
	offset += 2;

	headers = dotnet_parse_stream_headers (pe, offset, metadata_root, num_streams);

	// Parse the #~ stream which contains the metadata tables for libraries
	if (headers.tilde && headers.string) {
		PTILDE_HEADER tilde_header;
		uint32_t *row_offset = NULL;
		int bit_check;
		int matched_bits = 0;
		ROWS rows;
		INDEX_SIZES index_sizes;

		memset (&rows, '\0', sizeof (ROWS));
		memset (&index_sizes, 2, sizeof (index_sizes));

		tilde_header = (PTILDE_HEADER) (pe->data + metadata_root + headers.tilde->Offset);

		if (fits_in_pe (pe, (uint8_t *)tilde_header, sizeof (TILDE_HEADER))) {
			if (tilde_header->HeapSizes & 0x01) {
				index_sizes.string = 4;
			}
			if (tilde_header->HeapSizes & 0x02) {
				index_sizes.guid = 4;
			}
			if (tilde_header->HeapSizes & 0x04) {
				index_sizes.blob = 4;
			}

			row_offset = (uint32_t *) (tilde_header + 1);

			// Walk all the bits first to collect row counts
			for (bit_check = 0; bit_check < 64; bit_check++) {
				if (! ((tilde_header->Valid >> bit_check) & 0x01)) {
					continue;
				}

				if (fits_in_pe (pe, (uint8_t *)row_offset, (matched_bits + 1) * sizeof (uint32_t))) {
					rows.assemblyref = *(row_offset + matched_bits);
				}

				matched_bits++;
			}

			// Parse AssemblyRef table
			dotnet_parse_tilde_assemblyref (pe, tilde_header, metadata_root, rows, index_sizes, &headers, libraries);
		}
	}

	return libraries;
}

RList *dotnet_parse_imports(const ut8 *buf, int size) {
	// TODO: Parse ImplMap table for P/Invoke declarations
	// This would extract native library imports from .NET assemblies
	RList *imports = r_list_newf ((RListFree)free);
	return imports;
}

// Extract .NET runtime version and assembly version from MSIL headers
DotNetVersionInfo *dotnet_parse_version_info(const ut8 *buf, int size) {
	st64 offset = -1;
	int i, j, metadata_offset = -1;
	PE pe_struct = { buf, (ut32)size, NULL };
	PE *pe = &pe_struct;

	// Try to find the CLI header by looking for the metadata magic number
	if (pe->data_size > 0x100) {
		for (i = 0x40; i < (int)pe->data_size - (int)sizeof (NET_METADATA); i++) {
			PNET_METADATA test_metadata = (PNET_METADATA) (pe->data + i);
			if (test_metadata->Magic == NET_METADATA_MAGIC) {
				metadata_offset = i;
				// Search backwards for CLI header
				int search_start = (i > 0x400)? (i - 0x400): 0;
				for (j = i - 1; j >= search_start; j--) {
#if 0
					if (j < 0) {
						continue;
					}
#endif
					PCLI_HEADER cli = (PCLI_HEADER) (pe->data + j);
					if (cli->Size == 0x48 || cli->Size == 0x44) {
						if (cli->MajorRuntimeVersion >= 1 && cli->MajorRuntimeVersion <= 5) {
							offset = j;
							break;
						}
					}
				}
				if (offset >= 0) {
					break;
				}
			}
		}
	}

	if (offset < 0) {
		return NULL;
	}

	// Allocate version info structure
	DotNetVersionInfo *version_info = R_NEW0 (DotNetVersionInfo);
	// Get CLI header version
	if (!struct_fits_in_pe (pe, pe->data + offset, CLI_HEADER)) {
		free (version_info);
		return NULL;
	}

	PCLI_HEADER cli = (PCLI_HEADER) (pe->data + offset);
	version_info->cli_major = cli->MajorRuntimeVersion;
	version_info->cli_minor = cli->MinorRuntimeVersion;

	// Try to parse Assembly table, but don't fail if we can't
	// The CLR version alone is valuable
	PNET_METADATA metadata;
	ut64 metadata_root = metadata_offset;

	if (struct_fits_in_pe (pe, pe->data + metadata_root, NET_METADATA)) {
		metadata = (PNET_METADATA) (pe->data + metadata_root);

		if (metadata->Magic == NET_METADATA_MAGIC &&
			metadata->Length > 0 &&
			metadata->Length <= 255 &&
			metadata->Length % 4 == 0 &&
			fits_in_pe (pe, pe->data + metadata_root, metadata->Length)) {

			st64 offset_2 = metadata_root + sizeof (NET_METADATA) + metadata->Length + 2;
			if (fits_in_pe (pe, pe->data + offset_2, 2)) {
				ut16 num_streams = (ut16) *(pe->data + offset_2);
				offset_2 += 2;
				STREAMS headers = dotnet_parse_stream_headers (pe, offset_2, metadata_root, num_streams);

				// Try to parse Assembly table
				if (headers.tilde && headers.string) {
					PTILDE_HEADER tilde_header;
					uint32_t *row_offset = NULL;
					INDEX_SIZES index_sizes;
					memset (&index_sizes, 2, sizeof (index_sizes));

					tilde_header = (PTILDE_HEADER) (pe->data + metadata_root + headers.tilde->Offset);

					if (fits_in_pe (pe, (uint8_t *)tilde_header, sizeof (TILDE_HEADER))) {
						if (tilde_header->HeapSizes & 0x01) {
							index_sizes.string = 4;
						}
						if (tilde_header->HeapSizes & 0x02) {
							index_sizes.guid = 4;
						}
						if (tilde_header->HeapSizes & 0x04) {
							index_sizes.blob = 4;
						}

						row_offset = (uint32_t *) (tilde_header + 1);
						uint8_t *table_offset = (uint8_t *)row_offset;

						// Count tables and advance to Assembly table
						// (This is a simplified version - in production we'd calculate exact sizes)

						// Check if Assembly table exists
						if ((tilde_header->Valid >> BIT_ASSEMBLY) & 0x01) {
							// Get row count for Assembly table
							int matched_bits = 0;
							for (i = 0; i < BIT_ASSEMBLY; i++) {
								if ((tilde_header->Valid >> i) & 0x01) {
									matched_bits++;
								}
							}
							uint32_t num_rows = *(row_offset + matched_bits);
							if (num_rows > 0) {
								// Find Assembly table offset - count matched bits to know where to start
								matched_bits = 0;
								for (i = 0; i < 64; i++) {
									matched_bits += ((tilde_header->Valid >> i) & 0x01);
								}
								table_offset = (uint8_t *)row_offset;
								table_offset += sizeof (uint32_t) * matched_bits;

								matched_bits = 0;
								int bit_check;
								for (bit_check = 0; bit_check < BIT_ASSEMBLY && bit_check < 64; bit_check++) {
									if ((tilde_header->Valid >> bit_check) & 0x01) {
										uint32_t rows = *(row_offset + matched_bits);
										uint32_t table_size = 0;
										switch (bit_check) {
										case BIT_MODULE:
											table_size = (2 + index_sizes.string + (index_sizes.guid * 3)) * rows;
											break;
										default:
											break;
										}
										if (table_size > 0) {
											table_offset += table_size;
										}
										matched_bits++;
									}
								}

								// Now read Assembly table first row
								if (fits_in_pe (pe, table_offset, 4 + 2 + 2 + 2 + 2)) {
									version_info->asm_major = r_read_le16 (table_offset + 4);
									version_info->asm_minor = r_read_le16 (table_offset + 6);
									version_info->asm_build = r_read_le16 (table_offset + 8);
									version_info->asm_revision = r_read_le16 (table_offset + 10);
								}
							}
						}
					}
				}
			}
		}
	}
	return version_info;
}
