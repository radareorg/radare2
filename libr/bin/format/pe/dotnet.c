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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

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

static ut64 dotnet_max_stream_headers(PE *pe, ut64 offset) {
	if (offset >= pe->data_size) {
		return 0;
	}
	ut64 remaining_size = pe->data_size - offset;
	return remaining_size / (sizeof (STREAM_HEADER) + 4);
}

static ut32 dotnet_max_rows_at(PE *pe, const ut8 *row_ptr, ut32 row_size) {
	const ut8 *data = (const ut8 *)pe->data;
	const ut8 *end = data + pe->data_size;
	if (!row_size || row_ptr < data || row_ptr > end) {
		return 0;
	}
	ut64 remaining_size = end - row_ptr;
	return (ut32)(remaining_size / row_size);
}

static ut64 dotnet_tilde_valid(PTILDE_HEADER tilde_header) {
	return r_read_le64 ((const ut8 *)&tilde_header->Valid);
}

static ut32 dotnet_row_count_at(const ut32 *row_offset, int matched_bits) {
	return r_read_le32 ((const ut8 *)(row_offset + matched_bits));
}

static bool dotnet_metadata_magic_at(const ut8 *metadata) {
	return r_read_le32 (metadata) == NET_METADATA_MAGIC;
}

static ut32 dotnet_metadata_length(PNET_METADATA metadata) {
	return r_read_le32 ((const ut8 *)&metadata->Length);
}

static ut32 dotnet_stream_offset(PSTREAM_HEADER stream) {
	return r_read_le32 ((const ut8 *)&stream->Offset);
}

static ut32 dotnet_stream_size(PSTREAM_HEADER stream) {
	return r_read_le32 ((const ut8 *)&stream->Size);
}

static const ut8 *dotnet_stream_data(PE *pe, ut64 metadata_root, PSTREAM_HEADER stream) {
	if (!pe || !stream || metadata_root >= pe->data_size) {
		return NULL;
	}
	ut32 offset = dotnet_stream_offset (stream);
	if (offset >= pe->data_size - metadata_root) {
		return NULL;
	}
	return pe->data + metadata_root + offset;
}

static bool dotnet_parse_tilde_rows(PE *pe, PTILDE_HEADER tilde_header, R_OUT ROWS *rows, R_OUT INDEX_SIZES *index_sizes) {
	int bit_check, matched_bits = 0;

	if (!pe || !rows || !index_sizes || !struct_fits_in_pe (pe, tilde_header, TILDE_HEADER)) {
		return false;
	}

	memset (rows, 0, sizeof (ROWS));
	memset (index_sizes, 2, sizeof (INDEX_SIZES));

	if (tilde_header->HeapSizes & 0x01) {
		index_sizes->string = 4;
	}
	if (tilde_header->HeapSizes & 0x02) {
		index_sizes->guid = 4;
	}
	if (tilde_header->HeapSizes & 0x04) {
		index_sizes->blob = 4;
	}

	ut32 *row_offset = (ut32 *)(tilde_header + 1);
	for (bit_check = 0; bit_check < 64; bit_check++) {
		ut32 *row = NULL;
		ut8 *index_size = NULL;

		if (!((dotnet_tilde_valid (tilde_header) >> bit_check) & 0x01)) {
			continue;
		}
		if (!fits_in_pe (pe, row_offset, (matched_bits + 1) * sizeof (ut32))) {
			return false;
		}
		ut32 row_count = dotnet_row_count_at (row_offset, matched_bits);
		switch (bit_check) {
		case BIT_MODULE:
			row = &rows->module;
			break;
		case BIT_MODULEREF:
			row = &rows->moduleref;
			index_size = &index_sizes->moduleref;
			break;
		case BIT_ASSEMBLYREF:
			row = &rows->assemblyref;
			index_size = &index_sizes->assemblyref;
			break;
		case BIT_TYPEREF:
			row = &rows->typeref;
			break;
		case BIT_METHODDEF:
			row = &rows->methoddef;
			index_size = &index_sizes->methoddef;
			break;
		case BIT_MEMBERREF:
			row = &rows->memberref;
			index_size = &index_sizes->memberref;
			break;
		case BIT_TYPEDEF:
			row = &rows->typedef_;
			index_size = &index_sizes->typedef_;
			break;
		case BIT_TYPESPEC:
			row = &rows->typespec;
			break;
		case BIT_FIELD:
			row = &rows->field;
			index_size = &index_sizes->field;
			break;
		case BIT_PARAM:
			row = &rows->param;
			index_size = &index_sizes->param;
			break;
		case BIT_PROPERTY:
			row = &rows->property;
			index_size = &index_sizes->property;
			break;
		case BIT_INTERFACEIMPL:
			row = &rows->interfaceimpl;
			break;
		case BIT_EVENT:
			row = &rows->event;
			index_size = &index_sizes->event;
			break;
		case BIT_STANDALONESIG:
			row = &rows->standalonesig;
			break;
		case BIT_ASSEMBLY:
			row = &rows->assembly;
			break;
		case BIT_FILE:
			row = &rows->file;
			break;
		case BIT_EXPORTEDTYPE:
			row = &rows->exportedtype;
			break;
		case BIT_MANIFESTRESOURCE:
			row = &rows->manifestresource;
			break;
		case BIT_GENERICPARAM:
			row = &rows->genericparam;
			index_size = &index_sizes->genericparam;
			break;
		case BIT_GENERICPARAMCONSTRAINT:
			row = &rows->genericparamconstraint;
			break;
		case BIT_METHODSPEC:
			row = &rows->methodspec;
			break;
		case BIT_ASSEMBLYREFPROCESSOR:
			row = &rows->assemblyrefprocessor;
			index_size = &index_sizes->assemblyrefprocessor;
			break;
		default:
			break;
		}

		if (row) {
			*row = row_count;
			if (index_size && row_count > 0xFFFF) {
				*index_size = 4;
			}
		}
		matched_bits++;
	}
	return true;
}

static bool dotnet_tilde_table_size(R_IN const ROWS *rows, R_IN const INDEX_SIZES *index_sizes, int bit_check, ut32 num_rows, R_OUT ut32 *table_size) {
	ut32 row_count = 0;
	ut64 table_size64 = 0;

	if (!rows || !index_sizes || !table_size) {
		return false;
	}

	switch (bit_check) {
	case BIT_MODULE:
		table_size64 = (ut64)(2 + index_sizes->string + (index_sizes->guid * 3)) * num_rows;
		break;
	case BIT_TYPEREF:
		row_count = max_rows (3, rows->module, rows->moduleref, rows->assemblyref);
		table_size64 = (ut64)((row_count > (0xFFFF >> 0x02)? 4: 2) + (index_sizes->string * 2)) * num_rows;
		break;
	case BIT_TYPEDEF:
		row_count = max_rows (3, rows->typedef_, rows->typeref, rows->typespec);
		table_size64 = (ut64)(4 + (index_sizes->string * 2) + (row_count > (0xFFFF >> 0x02)? 4: 2) +
			index_sizes->field + index_sizes->methoddef) * num_rows;
		break;
	case BIT_FIELDPTR:
		table_size64 = (ut64)(index_sizes->field) * num_rows;
		break;
	case BIT_FIELD:
		table_size64 = (ut64)(2 + index_sizes->string + index_sizes->blob) * num_rows;
		break;
	case BIT_METHODDEFPTR:
		table_size64 = (ut64)(index_sizes->methoddef) * num_rows;
		break;
	case BIT_METHODDEF:
		table_size64 = (ut64)(4 + 2 + 2 + index_sizes->string + index_sizes->blob + index_sizes->param) * num_rows;
		break;
	case BIT_PARAMPTR:
		table_size64 = (ut64)(index_sizes->param) * num_rows;
		break;
	case BIT_PARAM:
		table_size64 = (ut64)(2 + 2 + index_sizes->string) * num_rows;
		break;
	case BIT_INTERFACEIMPL:
		row_count = max_rows (3, rows->typedef_, rows->typeref, rows->typespec);
		table_size64 = (ut64)(index_sizes->typedef_ + (row_count > (0xFFFF >> 0x02)? 4: 2)) * num_rows;
		break;
	case BIT_MEMBERREF:
		row_count = max_rows (4, rows->methoddef, rows->memberref, rows->typeref, rows->typespec);
		table_size64 = (ut64)((row_count > (0xFFFF >> 0x03)? 4: 2) + index_sizes->string + index_sizes->blob) * num_rows;
		break;
	case BIT_CONSTANT:
		row_count = max_rows (3, rows->field, rows->param, rows->property);
		table_size64 = (ut64)(2 + (row_count > (0xFFFF >> 0x02)? 4: 2) + index_sizes->blob) * num_rows;
		break;
	case BIT_CUSTOMATTRIBUTE:
		row_count = max_rows (3, rows->methoddef, rows->field, rows->param);
		table_size64 = (ut64)((row_count > (0xFFFF >> 0x05)? 4: 2) + index_sizes->memberref + index_sizes->blob) * num_rows;
		break;
	case BIT_FIELDMARSHAL:
		row_count = max_rows (2, rows->field, rows->param);
		table_size64 = (ut64)((row_count > (0xFFFF >> 0x01)? 4: 2) + index_sizes->blob) * num_rows;
		break;
	case BIT_DECLSECURITY:
		row_count = max_rows (3, rows->typedef_, rows->methoddef, rows->assembly);
		table_size64 = (ut64)(2 + (row_count > (0xFFFF >> 0x02)? 4: 2) + index_sizes->blob) * num_rows;
		break;
	case BIT_CLASSLAYOUT:
		table_size64 = (ut64)(2 + 4 + index_sizes->typedef_) * num_rows;
		break;
	case BIT_FIELDLAYOUT:
		table_size64 = (ut64)(4 + index_sizes->field) * num_rows;
		break;
	case BIT_STANDALONESIG:
		table_size64 = (ut64)(index_sizes->blob) * num_rows;
		break;
	case BIT_EVENTMAP:
		table_size64 = (ut64)(index_sizes->typedef_ + index_sizes->event) * num_rows;
		break;
	case BIT_EVENTPTR:
		table_size64 = (ut64)(index_sizes->event) * num_rows;
		break;
	case BIT_EVENT:
		table_size64 = (ut64)(2 + index_sizes->string + index_sizes->typedef_) * num_rows;
		break;
	case BIT_PROPERTYMAP:
		table_size64 = (ut64)(index_sizes->typedef_ + index_sizes->property) * num_rows;
		break;
	case BIT_PROPERTYPTR:
		table_size64 = (ut64)(index_sizes->property) * num_rows;
		break;
	case BIT_PROPERTY:
		table_size64 = (ut64)(2 + index_sizes->string + index_sizes->blob) * num_rows;
		break;
	case BIT_METHODSEMANTICS:
		row_count = max_rows (2, rows->event, rows->property);
		table_size64 = (ut64)(2 + index_sizes->methoddef + (row_count > (0xFFFF >> 0x01)? 4: 2)) * num_rows;
		break;
	case BIT_METHODIMPL:
		row_count = max_rows (2, rows->methoddef, rows->memberref);
		table_size64 = (ut64)(index_sizes->typedef_ + index_sizes->methoddef + (row_count > (0xFFFF >> 0x01)? 4: 2)) * num_rows;
		break;
	case BIT_MODULEREF:
		table_size64 = (ut64)(index_sizes->string) * num_rows;
		break;
	case BIT_TYPESPEC:
		table_size64 = (ut64)(index_sizes->blob) * num_rows;
		break;
	case BIT_IMPLMAP:
		row_count = max_rows (3, rows->field, rows->methoddef, rows->typedef_);
		table_size64 = (ut64)(2 + (row_count > (0xFFFF >> 0x01)? 4: 2) + index_sizes->string + index_sizes->moduleref) * num_rows;
		break;
	case BIT_FIELDRVA:
		table_size64 = (ut64)(4 + index_sizes->field) * num_rows;
		break;
	case BIT_ENCLOG:
		table_size64 = (ut64)(4) * num_rows;
		break;
	case BIT_ENCMAP:
		table_size64 = (ut64)(4) * num_rows;
		break;
	case BIT_ASSEMBLY:
		table_size64 = (ut64)(4 + 2 + 2 + 2 + 2 + 4 + index_sizes->blob + (index_sizes->string * 2)) * num_rows;
		break;
	case BIT_ASSEMBLYPROCESSOR:
		table_size64 = (ut64)(4) * num_rows;
		break;
	case BIT_ASSEMBLYOS:
		table_size64 = (ut64)(4 + 4 + 4) * num_rows;
		break;
	case BIT_ASSEMBLYREF:
		table_size64 = (ut64)(2 + 2 + 2 + 2 + 4 + (index_sizes->blob * 2) + (index_sizes->string * 2)) * num_rows;
		break;
	case BIT_ASSEMBLYREFPROCESSOR:
		table_size64 = (ut64)(4 + index_sizes->assemblyrefprocessor) * num_rows;
		break;
	case BIT_ASSEMBLYREFOS:
		table_size64 = (ut64)(4 + 4 + 4 + index_sizes->assemblyref) * num_rows;
		break;
	case BIT_FILE:
		table_size64 = (ut64)(4 + index_sizes->string + index_sizes->blob) * num_rows;
		break;
	case BIT_EXPORTEDTYPE:
		row_count = max_rows (3, rows->file, rows->assemblyref, rows->exportedtype);
		table_size64 = (ut64)(4 + 4 + (index_sizes->string * 2) + (row_count > (0xFFFF >> 0x02)? 4: 2)) * num_rows;
		break;
	case BIT_MANIFESTRESOURCE:
		row_count = max_rows (3, rows->file, rows->assemblyref, rows->exportedtype);
		table_size64 = (ut64)(4 + 4 + index_sizes->string + (row_count > (0xFFFF >> 0x02)? 4: 2)) * num_rows;
		break;
	case BIT_NESTEDCLASS:
		table_size64 = (ut64)(index_sizes->typedef_ * 2) * num_rows;
		break;
	case BIT_GENERICPARAM:
		row_count = max_rows (2, rows->typedef_, rows->methoddef);
		table_size64 = (ut64)(2 + 2 + (row_count > (0xFFFF >> 0x01)? 4: 2) + index_sizes->string) * num_rows;
		break;
	case BIT_METHODSPEC:
		row_count = max_rows (2, rows->methoddef, rows->memberref);
		table_size64 = (ut64)((row_count > (0xFFFF >> 0x01)? 4: 2) + index_sizes->blob) * num_rows;
		break;
	case BIT_GENERICPARAMCONSTRAINT:
		row_count = max_rows (3, rows->typedef_, rows->typeref, rows->typespec);
		table_size64 = (ut64)(index_sizes->genericparam + (row_count > (0xFFFF >> 0x02)? 4: 2)) * num_rows;
		break;
	default:
		return false;
	}

	if (table_size64 > UT32_MAX) {
		return false;
	}
	*table_size = (ut32)table_size64;
	return true;
}

static const ut8 *dotnet_tilde_table_offset(PE *pe, PTILDE_HEADER tilde_header, R_IN const ROWS *rows, R_IN const INDEX_SIZES *index_sizes, int target_bit, R_OUT ut32 *target_rows) {
	int bit_check, matched_bits = 0, valid_tables = 0;

	if (!pe || !rows || !index_sizes || !target_rows || !struct_fits_in_pe (pe, tilde_header, TILDE_HEADER)) {
		return NULL;
	}

	ut32 *row_offset = (ut32 *)(tilde_header + 1);
	for (bit_check = 0; bit_check < 64; bit_check++) {
		valid_tables += ((dotnet_tilde_valid (tilde_header) >> bit_check) & 0x01);
	}
	ut64 table_offset = (const ut8 *)row_offset - pe->data;
	table_offset += (ut64)sizeof (ut32) * valid_tables;

	for (bit_check = 0; bit_check < 64; bit_check++) {
		ut32 num_rows;
		ut32 table_size;

		if (!((dotnet_tilde_valid (tilde_header) >> bit_check) & 0x01)) {
			continue;
		}
		if (!fits_in_pe (pe, row_offset, (matched_bits + 1) * sizeof (ut32))) {
			return NULL;
		}

		num_rows = dotnet_row_count_at (row_offset, matched_bits);
		if (bit_check == target_bit) {
			ut32 row_size;
			if (table_offset > pe->data_size ||
				!dotnet_tilde_table_size (rows, index_sizes, bit_check, 1, &row_size)) {
				return NULL;
			}
			*target_rows = R_MIN (num_rows, dotnet_max_rows_at (pe,
				pe->data + table_offset, row_size));
			return pe->data + table_offset;
		}
		if (!dotnet_tilde_table_size (rows, index_sizes, bit_check, num_rows, &table_size)) {
			return NULL;
		}
		if (table_offset > pe->data_size || table_size > pe->data_size - table_offset) {
			return NULL;
		}

		table_offset += table_size;
		matched_bits++;
	}
	return NULL;
}

static STREAMS dotnet_parse_stream_headers(PE *pe, ut64 offset, ut64 metadata_root, ut32 num_streams) {
	char stream_name[DOTNET_STREAM_NAME_SIZE + 1];
	STREAMS headers = { 0 };
	unsigned int i;

	if (offset >= pe->data_size || num_streams > dotnet_max_stream_headers (pe, offset)) {
		return headers;
	}
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

		if (!eos) {
			break;
		}

		size_t name_len = eos - start;
		r_str_ncpy (stream_name, start, R_MIN (name_len + 1, DOTNET_STREAM_NAME_SIZE + 1));

		// Store necessary bits to parse these later
		if (!strcmp (stream_name, "#GUID")) {
			headers.guid = stream_header;
		} else if ((!strcmp (stream_name, "#~") || !strcmp (stream_name, "#-")) && !headers.tilde) {
			headers.tilde = stream_header;
		} else if (!strcmp (stream_name, "#Strings") && !headers.string) {
			headers.string = stream_header;
		} else if (!strcmp (stream_name, "#Blob")) {
			headers.blob = stream_header;
		} else if (!strcmp (stream_name, "#US") && !headers.us) {
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
		matched_bits += ((dotnet_tilde_valid (tilde_header) >> i) & 0x01);
	}

	uint32_t *row_offset = (uint32_t *) (tilde_header + 1);
	uint8_t *table_offset = (uint8_t *)row_offset;
	table_offset += sizeof (uint32_t) * matched_bits;

	const uint8_t *string_offset = dotnet_stream_data (pe, metadata_root, streams->string);
	if (!string_offset) {
		return;
	}

	matched_bits = 0;

	// Parse AssemblyRef table
	for (bit_check = 0; bit_check < 64; bit_check++) {
		if (! ((dotnet_tilde_valid (tilde_header) >> bit_check) & 0x01)) {
			continue;
		}

		if (!fits_in_pe (pe, table_offset, 1)) {
			return;
		}

		if (!fits_in_pe (pe, (uint8_t *)row_offset, (matched_bits + 1) * sizeof (uint32_t))) {
			return;
		}
		num_rows = dotnet_row_count_at (row_offset, matched_bits);

		if (bit_check == BIT_ASSEMBLYREF) {
			// AssemblyRef structure: MajorVersion (2) MinorVersion (2) BuildNumber (2) RevisionNumber (2)
			// Flags (4) PublicKeyOrToken (blob) Name (string) Culture (string)
			row_ptr = table_offset;
			ut32 row_size = 2 + 2 + 2 + 2 + 4 + (index_sizes.blob * 2) + (index_sizes.string * 2);
			ut32 max_rows = dotnet_max_rows_at (pe, row_ptr, row_size);
			if (num_rows > max_rows) {
				return;
			}
			for (i = 0; i < num_rows; i++) {
				if (!fits_in_pe (pe, row_ptr, row_size)) {
					break;
				}
				ut16 major = r_read_le16 (row_ptr);
				ut16 minor = r_read_le16 (row_ptr + 2);
				ut16 build = r_read_le16 (row_ptr + 4);
				ut16 revision = r_read_le16 (row_ptr + 6);

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
					name = pe_get_dotnet_string (pe, string_offset, r_read_le32 (name_ptr));
				} else {
					name = pe_get_dotnet_string (pe, string_offset, r_read_le16 (name_ptr));
				}

				if (R_STR_ISNOTEMPTY (name)) {
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
			switch (bit_check) {
			case BIT_MODULE:
				table_offset += (2 + index_sizes.string + (index_sizes.guid * 3)) * num_rows;
				break;
			default:
				// Cannot compute table size for unknown table, bail out
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
		free (field->type_name);
		free (field);
	}
}

static void dotnet_symbol_free(void *s) {
	if (s) {
		DotNetSymbol *sym = s;
		free (sym->name);
		free (sym->namespace);
		free (sym->classname);
		free (sym->short_name);
		free (sym->signature);
		free (sym->return_type);
		free (sym->type);
		r_list_free (sym->methods);
		r_list_free (sym->fields);
		free (sym);
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

static ut32 dotnet_typedef_or_ref_token(ut32 coded) {
	static const ut8 tables[] = { 0x02, 0x01, 0x1b };
	ut32 tag = coded & 3;
	ut32 rid = coded >> 2;
	return tag < R_ARRAY_SIZE (tables) && rid? ((ut32)tables[tag] << 24) | rid: 0;
}

static DotNetSymbol *dotnet_symbol_by_token(RList *symbols, ut32 token) {
	RListIter *iter;
	DotNetSymbol *sym;
	r_list_foreach (symbols, iter, sym) {
		if (sym->token == token) {
			return sym;
		}
	}
	return NULL;
}

static char *dotnet_symbol_fullname(const DotNetSymbol *sym) {
	if (!sym || !sym->name) {
		return NULL;
	}
	return R_STR_ISNOTEMPTY (sym->namespace)
		? r_str_newf ("%s.%s", sym->namespace, sym->name)
		: strdup (sym->name);
}

static void dotnet_parse_tilde_typeref(PE *pe, PTILDE_HEADER tilde_header,
		ut64 metadata_root, ROWS rows, INDEX_SIZES index_sizes,
		PSTREAMS streams, RList *symbols) {
	if (!streams->tilde || !streams->string) {
		return;
	}
	ut32 num_rows = 0;
	const ut8 *table = dotnet_tilde_table_offset (pe, tilde_header, &rows,
		&index_sizes, BIT_TYPEREF, &num_rows);
	const ut8 *strings = dotnet_stream_data (pe, metadata_root, streams->string);
	if (!table || !strings) {
		return;
	}
	ut32 scope_rows = max_rows (4, rows.module, rows.moduleref, rows.assemblyref, rows.typeref);
	ut8 scope_size = scope_rows > (0xffff >> 2)? 4: 2;
	ut32 row_size = scope_size + index_sizes.string * 2;
	ut32 i;
	for (i = 0; i < num_rows; i++, table += row_size) {
		if (!fits_in_pe (pe, table, row_size)) {
			break;
		}
		ut32 name_index = index_sizes.string == 4
			? r_read_le32 (table + scope_size)
			: r_read_le16 (table + scope_size);
		ut32 namespace_index = index_sizes.string == 4
			? r_read_le32 (table + scope_size + index_sizes.string)
			: r_read_le16 (table + scope_size + index_sizes.string);
		char *name = pe_get_dotnet_string (pe, strings, name_index);
		if (!R_STR_ISNOTEMPTY (name)) {
			continue;
		}
		DotNetSymbol *sym = R_NEW0 (DotNetSymbol);
		sym->name = strdup (name);
		sym->short_name = strdup (name);
		char *namespace = pe_get_dotnet_string (pe, strings, namespace_index);
		sym->namespace = strdup (r_str_get (namespace));
		sym->type = strdup ("typeref");
		sym->token = 0x01000000 | (i + 1);
		r_list_append (symbols, sym);
	}
}

static char *dotnet_parse_field_sig(PE *pe, PSTREAM_HEADER blob_hdr,
	ut64 metadata_root, ut32 blob_index, RList *symbols);

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
		matched_bits += ((dotnet_tilde_valid (tilde_header) >> i) & 0x01);
	}

	uint32_t *row_offset = (uint32_t *) (tilde_header + 1);
	uint8_t *table_offset = (uint8_t *)row_offset;
	table_offset += sizeof (uint32_t) * matched_bits;

	matched_bits = 0;

	string_offset = dotnet_stream_data (pe, metadata_root, streams->string);
	if (!string_offset) {
		return;
	}
	// Iterate through tables, looking for Field
	for (bit_check = 0; bit_check < 64; bit_check++) {
		if (! ((dotnet_tilde_valid (tilde_header) >> bit_check) & 0x01)) {
			continue;
		}

		if (!fits_in_pe (pe, table_offset, 1)) {
			return;
		}

		num_rows = dotnet_row_count_at (row_offset, matched_bits);

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
				ut16 flags = r_read_le16 (row_ptr);
				ut32 signature_index = index_sizes.blob == 4
					? r_read_le32 (row_ptr + 2 + index_sizes.string)
					: r_read_le16 (row_ptr + 2 + index_sizes.string);
				char *field_type = dotnet_parse_field_sig (pe, streams->blob,
					metadata_root, signature_index, symbols);
				// Get field name from string stream
				if (index_sizes.string == 4) {
					name = pe_get_dotnet_string (pe, string_offset, r_read_le32 (row_ptr + 2));
				} else {
					name = pe_get_dotnet_string (pe, string_offset, r_read_le16 (row_ptr + 2));
				}

				if (R_STR_ISNOTEMPTY (name)) {
					// Find which typedef this field belongs to
					RListIter *iter;
					DotNetTypeDefInfo *td;
					r_list_foreach (typedef_info, iter, td) {
						if (field_idx >= td->field_list_start && field_idx < td->field_list_end) {
							// Find the corresponding DotNetSymbol
							char *full_name;
							if (R_STR_ISNOTEMPTY (td->namespace)) {
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
										field->type_name = strdup (r_str_get_fail (field_type, "unknown"));
										field->flags = flags;
										field->token = 0x04000000 | field_idx;
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
				if (R_STR_ISNOTEMPTY (name)) {
					DotNetTypeDefInfo *owner = NULL;
					RListIter *iter;
					DotNetTypeDefInfo *td;
					r_list_foreach (typedef_info, iter, td) {
						if (field_idx >= td->field_list_start && field_idx < td->field_list_end) {
							owner = td;
							break;
						}
					}
					DotNetSymbol *field_symbol = R_NEW0 (DotNetSymbol);
					field_symbol->short_name = strdup (name);
					field_symbol->return_type = strdup (r_str_get_fail (field_type, "unknown"));
					field_symbol->flags = flags;
					field_symbol->token = 0x04000000 | field_idx;
					field_symbol->type = strdup ("field");
					if (owner) {
						field_symbol->classname = R_STR_ISNOTEMPTY (owner->namespace)
							? r_str_newf ("%s.%s", owner->namespace, owner->class_name)
							: strdup (owner->class_name);
						field_symbol->name = r_str_newf ("%s.%s", field_symbol->classname, name);
					} else {
						field_symbol->name = strdup (name);
					}
					field_symbol->signature = r_str_newf ("%s:%s", field_symbol->name,
						r_str_get_fail (field_type, "unknown"));
					r_list_append (symbols, field_symbol);
				}
				free (field_type);

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
					uint32_t resolution_scope_row_count = max_rows (4, rows.module, rows.moduleref, rows.assemblyref, rows.typeref);
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
		matched_bits += ((dotnet_tilde_valid (tilde_header) >> i) & 0x01);
	}

	row_offset = (uint32_t *) (tilde_header + 1);
	table_offset = (uint8_t *)row_offset;
	table_offset += sizeof (uint32_t) * matched_bits;

	string_offset = dotnet_stream_data (pe, metadata_root, streams->string);
	if (!string_offset) {
		return;
	}

	matched_bits = 0;

	// Parse TypeDef table
	for (bit_check = 0; bit_check < 64; bit_check++) {
		if (! ((dotnet_tilde_valid (tilde_header) >> bit_check) & 0x01)) {
			continue;
		}

		if (!fits_in_pe (pe, table_offset, 1)) {
			return;
		}

		num_rows = dotnet_row_count_at (row_offset, matched_bits);

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

				uint32_t flags = r_read_le32 (row_ptr);

				// Get type name from string stream
				if (index_sizes.string == 4) {
					name = pe_get_dotnet_string (pe, string_offset, r_read_le32 (row_ptr + 4));
					namespace = pe_get_dotnet_string (pe, string_offset, r_read_le32 (row_ptr + 8));
				} else {
					name = pe_get_dotnet_string (pe, string_offset, r_read_le16 (row_ptr + 4));
					namespace = pe_get_dotnet_string (pe, string_offset, r_read_le16 (row_ptr + 6));
				}

				if (R_STR_ISNOTEMPTY (name)) {
					DotNetSymbol *sym = R_NEW0 (DotNetSymbol);
					sym->name = strdup (name);
					sym->short_name = strdup (name);
					sym->namespace = strdup (r_str_get (namespace));
					sym->type = strdup ("typedef");
					sym->flags = flags;
					sym->token = 0x02000000 | (i + 1);
					const ut8 *extends_ptr = row_ptr + 4 + index_sizes.string * 2;
					ut32 extends = extends_index_size == 4
						? r_read_le32 (extends_ptr): r_read_le16 (extends_ptr);
					sym->extends_token = dotnet_typedef_or_ref_token (extends);
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
			num_rows = dotnet_row_count_at (row_offset, matched_bits);
			switch (bit_check) {
			case BIT_MODULE:
				table_offset += (2 + index_sizes.string + (index_sizes.guid * 3)) * num_rows;
				break;
			case BIT_TYPEREF:
				{
					// TypeRef: ResolutionScope (coded index) + Name (string) + Namespace (string)
					// ResolutionScope is a ResolutionScope coded index (module | moduleref | assemblyref)
					uint32_t resolution_scope_row_count = max_rows (4, rows.module, rows.moduleref, rows.assemblyref, rows.typeref);
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

// ECMA-335 II.23.2 compressed-uint. Returns the value and advances *p past it.
// Returns 0 on malformed input (and leaves *p untouched).
static ut32 dotnet_read_compressed_uint(const ut8 **p, const ut8 *end) {
	if (*p >= end) {
		return 0;
	}
	ut8 b0 = **p;
	if ((b0 & 0x80) == 0) {
		(*p)++;
		return b0 & 0x7f;
	}
	if ((b0 & 0xc0) == 0x80) {
		if (*p + 1 >= end) {
			return 0;
		}
		ut32 v = ((ut32)(b0 & 0x3f) << 8) | (*p)[1];
		*p += 2;
		return v;
	}
	if ((b0 & 0xe0) == 0xc0) {
		if (*p + 3 >= end) {
			return 0;
		}
		ut32 v = ((ut32)(b0 & 0x1f) << 24) | ((ut32)(*p)[1] << 16)
				| ((ut32)(*p)[2] << 8) | (*p)[3];
		*p += 4;
		return v;
	}
	return 0;
}

typedef struct {
	bool has_this;
	char *return_type;
	RList *parameters;
} DotNetMethodSig;

static void dotnet_method_sig_fini(DotNetMethodSig *sig) {
	if (sig) {
		free (sig->return_type);
		r_list_free (sig->parameters);
	}
}

static char *dotnet_type_alias(ut8 element) {
	switch (element) {
	case ELEMENT_TYPE_VOID: return strdup ("void");
	case ELEMENT_TYPE_BOOLEAN: return strdup ("bool");
	case ELEMENT_TYPE_CHAR: return strdup ("char");
	case ELEMENT_TYPE_I1: return strdup ("sbyte");
	case ELEMENT_TYPE_U1: return strdup ("byte");
	case ELEMENT_TYPE_I2: return strdup ("short");
	case ELEMENT_TYPE_U2: return strdup ("ushort");
	case ELEMENT_TYPE_I4: return strdup ("int");
	case ELEMENT_TYPE_U4: return strdup ("uint");
	case ELEMENT_TYPE_I8: return strdup ("long");
	case ELEMENT_TYPE_U8: return strdup ("ulong");
	case ELEMENT_TYPE_R4: return strdup ("float");
	case ELEMENT_TYPE_R8: return strdup ("double");
	case ELEMENT_TYPE_STRING: return strdup ("string");
	case ELEMENT_TYPE_TYPEDBYREF: return strdup ("TypedReference");
	case ELEMENT_TYPE_I: return strdup ("nint");
	case ELEMENT_TYPE_U: return strdup ("nuint");
	case ELEMENT_TYPE_OBJECT: return strdup ("object");
	default: return NULL;
	}
}

static char *dotnet_parse_sig_type(const ut8 **p, const ut8 *end, RList *symbols, int depth) {
	if (*p >= end || depth > 32) {
		return NULL;
	}
	ut8 element = *(*p)++;
	char *alias = dotnet_type_alias (element);
	if (alias) {
		return alias;
	}
	switch (element) {
	case ELEMENT_TYPE_CMOD_REQD:
	case ELEMENT_TYPE_CMOD_OPT:
		{
			const ut8 *before = *p;
			dotnet_read_compressed_uint (p, end);
			return *p == before? NULL: dotnet_parse_sig_type (p, end, symbols, depth + 1);
		}
	case ELEMENT_TYPE_PINNED:
	case ELEMENT_TYPE_SENTINEL:
		return dotnet_parse_sig_type (p, end, symbols, depth + 1);
	case ELEMENT_TYPE_CLASS:
	case ELEMENT_TYPE_VALUETYPE:
		{
			const ut8 *before = *p;
			ut32 coded = dotnet_read_compressed_uint (p, end);
			if (*p == before) {
				return NULL;
			}
			DotNetSymbol *sym = dotnet_symbol_by_token (symbols, dotnet_typedef_or_ref_token (coded));
			return sym? dotnet_symbol_fullname (sym): r_str_newf ("type_token.0x%08x", dotnet_typedef_or_ref_token (coded));
		}
	case ELEMENT_TYPE_PTR:
	case ELEMENT_TYPE_BYREF:
	case ELEMENT_TYPE_SZARRAY:
		{
			char *inner = dotnet_parse_sig_type (p, end, symbols, depth + 1);
			if (!inner) {
				return NULL;
			}
			const char *suffix = element == ELEMENT_TYPE_PTR? "*"
				: element == ELEMENT_TYPE_BYREF? "&": "[]";
			char *out = r_str_newf ("%s%s", inner, suffix);
			free (inner);
			return out;
		}
	case ELEMENT_TYPE_VAR:
	case ELEMENT_TYPE_MVAR:
		{
			const ut8 *before = *p;
			ut32 index = dotnet_read_compressed_uint (p, end);
			return *p == before? NULL: r_str_newf (element == ELEMENT_TYPE_VAR? "T%u": "M%u", index);
		}
	case ELEMENT_TYPE_ARRAY:
		{
			char *inner = dotnet_parse_sig_type (p, end, symbols, depth + 1);
			if (!inner) {
				return NULL;
			}
			const ut8 *before = *p;
			ut32 rank = dotnet_read_compressed_uint (p, end);
			if (*p == before) {
				free (inner);
				return NULL;
			}
			ut32 sizes = dotnet_read_compressed_uint (p, end);
			ut32 i;
			for (i = 0; i < sizes && *p < end; i++) {
				dotnet_read_compressed_uint (p, end);
			}
			ut32 lows = dotnet_read_compressed_uint (p, end);
			for (i = 0; i < lows && *p < end; i++) {
				dotnet_read_compressed_uint (p, end);
			}
			RStrBuf *sb = r_strbuf_new (inner);
			r_strbuf_append (sb, "[");
			for (i = 1; i < rank; i++) {
				r_strbuf_append (sb, ",");
			}
			r_strbuf_append (sb, "]");
			free (inner);
			return r_strbuf_drain (sb);
		}
	case ELEMENT_TYPE_GENERICINST:
		{
			char *base = dotnet_parse_sig_type (p, end, symbols, depth + 1);
			if (!base) {
				return NULL;
			}
			const ut8 *before = *p;
			ut32 count = dotnet_read_compressed_uint (p, end);
			if (*p == before || count > 1024) {
				free (base);
				return NULL;
			}
			RStrBuf *sb = r_strbuf_new (base);
			r_strbuf_append (sb, "<");
			ut32 i;
			for (i = 0; i < count; i++) {
				char *arg = dotnet_parse_sig_type (p, end, symbols, depth + 1);
				if (!arg) {
					r_strbuf_free (sb);
					free (base);
					return NULL;
				}
				r_strbuf_appendf (sb, "%s%s", i? ",": "", arg);
				free (arg);
			}
			r_strbuf_append (sb, ">");
			free (base);
			return r_strbuf_drain (sb);
		}
	case ELEMENT_TYPE_FNPTR:
		return strdup ("delegate");
	default:
		return r_str_newf ("element_type.0x%02x", element);
	}
}

static bool dotnet_parse_method_sig(PE *pe, PSTREAM_HEADER blob_hdr,
		ut64 metadata_root, ut32 blob_index, RList *symbols, DotNetMethodSig *sig) {
	memset (sig, 0, sizeof (*sig));
	sig->parameters = r_list_newf (free);
	if (!sig->parameters || !blob_hdr || !blob_index) {
		return false;
	}
	const ut8 *heap = dotnet_stream_data (pe, metadata_root, blob_hdr);
	ut32 heap_size = dotnet_stream_size (blob_hdr);
	if (!heap || blob_index >= heap_size || heap_size > (ut64)(pe->data + pe->data_size - heap)) {
		return false;
	}
	const ut8 *p = heap + blob_index;
	const ut8 *heap_end = heap + heap_size;
	const ut8 *before = p;
	ut32 size = dotnet_read_compressed_uint (&p, heap_end);
	if (p == before || size > (ut64)(heap_end - p)) {
		return false;
	}
	const ut8 *end = p + size;
	if (p >= end) {
		return false;
	}
	ut8 header = *p++;
	ut8 calling_convention = header & 0x0f;
	if (calling_convention == 0x06 || calling_convention == 0x07
			|| calling_convention == 0x08 || calling_convention == 0x0a) {
		return false;
	}
	sig->has_this = (header & 0x20) != 0;
	if (header & 0x10) {
		before = p;
		dotnet_read_compressed_uint (&p, end);
		if (p == before) {
			return false;
		}
	}
	before = p;
	ut32 count = dotnet_read_compressed_uint (&p, end);
	if (p == before || count > 0xffff) {
		return false;
	}
	sig->return_type = dotnet_parse_sig_type (&p, end, symbols, 0);
	if (!sig->return_type) {
		return false;
	}
	ut32 i;
	for (i = 0; i < count; i++) {
		if (p < end && *p == ELEMENT_TYPE_SENTINEL) {
			p++;
		}
		char *type = dotnet_parse_sig_type (&p, end, symbols, 0);
		if (!type) {
			return false;
		}
		r_list_append (sig->parameters, type);
	}
	return true;
}

static char *dotnet_parse_field_sig(PE *pe, PSTREAM_HEADER blob_hdr,
		ut64 metadata_root, ut32 blob_index, RList *symbols) {
	if (!blob_hdr || !blob_index) {
		return NULL;
	}
	const ut8 *heap = dotnet_stream_data (pe, metadata_root, blob_hdr);
	ut32 heap_size = dotnet_stream_size (blob_hdr);
	if (!heap || blob_index >= heap_size || heap_size > (ut64)(pe->data + pe->data_size - heap)) {
		return NULL;
	}
	const ut8 *p = heap + blob_index;
	const ut8 *heap_end = heap + heap_size;
	const ut8 *before = p;
	ut32 size = dotnet_read_compressed_uint (&p, heap_end);
	if (p == before || size > (ut64)(heap_end - p) || !size) {
		return NULL;
	}
	const ut8 *end = p + size;
	if (p >= end || *p++ != 0x06) {
		return NULL;
	}
	return dotnet_parse_sig_type (&p, end, symbols, 0);
}

static char *dotnet_parse_type_spec_sig(PE *pe, PSTREAM_HEADER blob_hdr,
		ut64 metadata_root, ut32 blob_index, RList *symbols) {
	if (!blob_hdr || !blob_index) {
		return NULL;
	}
	const ut8 *heap = dotnet_stream_data (pe, metadata_root, blob_hdr);
	ut32 heap_size = dotnet_stream_size (blob_hdr);
	if (!heap || blob_index >= heap_size || heap_size > (ut64)(pe->data + pe->data_size - heap)) {
		return NULL;
	}
	const ut8 *p = heap + blob_index;
	const ut8 *heap_end = heap + heap_size;
	const ut8 *before = p;
	ut32 size = dotnet_read_compressed_uint (&p, heap_end);
	if (p == before || size > (ut64)(heap_end - p) || !size) {
		return NULL;
	}
	return dotnet_parse_sig_type (&p, p + size, symbols, 0);
}

static void dotnet_parse_tilde_typespec(PE *pe, PTILDE_HEADER tilde_header,
		ut64 metadata_root, ROWS rows, INDEX_SIZES index_sizes,
		PSTREAMS streams, RList *symbols) {
	if (!streams->tilde || !streams->blob) {
		return;
	}
	ut32 num_rows = 0;
	const ut8 *table = dotnet_tilde_table_offset (pe, tilde_header, &rows,
		&index_sizes, BIT_TYPESPEC, &num_rows);
	ut32 i;
	for (i = 0; table && i < num_rows; i++, table += index_sizes.blob) {
		if (!fits_in_pe (pe, table, index_sizes.blob)) {
			break;
		}
		ut32 blob_index = index_sizes.blob == 4? r_read_le32 (table): r_read_le16 (table);
		char *name = dotnet_parse_type_spec_sig (pe, streams->blob,
			metadata_root, blob_index, symbols);
		if (!name) {
			continue;
		}
		DotNetSymbol *sym = R_NEW0 (DotNetSymbol);
		if (!sym) {
			free (name);
			break;
		}
		sym->name = name;
		sym->short_name = strdup (name);
		sym->type = strdup ("typespec");
		sym->token = 0x1b000000 | (i + 1);
		r_list_append (symbols, sym);
	}
}

static char *dotnet_param_name(PE *pe, const ut8 *table, ut32 rows,
		ut32 row_size, ut8 string_size, const ut8 *strings,
		ut32 first, ut32 last, ut32 sequence) {
	if (!table || !first || first > rows || last <= first) {
		return NULL;
	}
	last = R_MIN (last, rows + 1);
	ut32 rid;
	for (rid = first; rid < last; rid++) {
		const ut8 *row = table + (ut64)(rid - 1) * row_size;
		if (!fits_in_pe (pe, row, row_size) || r_read_le16 (row + 2) != sequence) {
			continue;
		}
		ut32 name_index = string_size == 4? r_read_le32 (row + 4): r_read_le16 (row + 4);
		char *name = pe_get_dotnet_string (pe, strings, name_index);
		return R_STR_ISNOTEMPTY (name)? strdup (name): NULL;
	}
	return NULL;
}

static char *dotnet_build_method_signature(const char *fullname,
		const DotNetMethodSig *sig, PE *pe, const ut8 *param_table,
		ut32 param_rows, ut32 param_row_size, ut8 string_size,
		const ut8 *strings, ut32 param_first, ut32 param_last) {
	if (!fullname || !sig || !sig->return_type) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new (fullname);
	r_strbuf_append (sb, "(");
	if (sig->has_this) {
		r_strbuf_append (sb, "this;");
	}
	RListIter *iter;
	char *type;
	ut32 i = 0;
	r_list_foreach (sig->parameters, iter, type) {
		char *name = dotnet_param_name (pe, param_table, param_rows,
			param_row_size, string_size, strings, param_first, param_last, i + 1);
		r_strbuf_appendf (sb, "%s%s", i? ",": "", type);
		if (name) {
			r_strbuf_appendf (sb, ":%s", name);
		}
		free (name);
		i++;
	}
	r_strbuf_appendf (sb, "):%s", sig->return_type);
	return r_strbuf_drain (sb);
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
		matched_bits += ((dotnet_tilde_valid (tilde_header) >> i) & 0x01);
	}

	row_offset = (uint32_t *) (tilde_header + 1);
	table_offset = (uint8_t *)row_offset;
	table_offset += sizeof (uint32_t) * matched_bits;

	string_offset = dotnet_stream_data (pe, metadata_root, streams->string);
	if (!string_offset) {
		return;
	}
	ut32 param_rows = 0;
	const ut8 *param_table = dotnet_tilde_table_offset (pe, tilde_header, &rows,
		&index_sizes, BIT_PARAM, &param_rows);
	ut32 param_row_size = 4 + index_sizes.string;

	matched_bits = 0;

	// Iterate through tables in order, looking for MethodDef
	for (bit_check = 0; bit_check < 64; bit_check++) {
		if (! ((dotnet_tilde_valid (tilde_header) >> bit_check) & 0x01)) {
			continue;
		}

		if (!fits_in_pe (pe, table_offset, 1)) {
			return;
		}

		num_rows = dotnet_row_count_at (row_offset, matched_bits);
		if (bit_check == BIT_METHODDEF) {
			// Parse MethodDef table
			// Structure: RVA (4) ImplFlags (2) Flags (2) Name (string) Signature (blob) ParamList (param)
			uint8_t param_index_size = rows.param > 0xffff? 4: 2;

			row_ptr = table_offset;
			for (i = 0; i < num_rows; i++) {
				uint32_t row_size = 4 + 2 + 2 + index_sizes.string + index_sizes.blob + param_index_size;
				if (!fits_in_pe (pe, row_ptr, row_size)) {
					break;
				}
				rva = r_read_le32 (row_ptr);
				ut16 impl_flags = r_read_le16 (row_ptr + 4);
				ut16 method_flags = r_read_le16 (row_ptr + 6);

				// Get method name from string stream
				// Offset: RVA (4) + ImplFlags (2) + Flags (2) = 8
				if (index_sizes.string == 4) {
					name = pe_get_dotnet_string (pe, string_offset, r_read_le32 (row_ptr + 8));
				} else {
					name = pe_get_dotnet_string (pe, string_offset, r_read_le16 (row_ptr + 8));
				}
				// Signature blob index: Offset 8 + string-index-size
				ut32 sig_blob_off = 8 + index_sizes.string;
				ut32 sig_idx = (index_sizes.blob == 4)
					? r_read_le32 (row_ptr + sig_blob_off)
					: r_read_le16 (row_ptr + sig_blob_off);
				ut32 param_list_off = sig_blob_off + index_sizes.blob;
				ut32 param_first = param_index_size == 4
					? r_read_le32 (row_ptr + param_list_off)
					: r_read_le16 (row_ptr + param_list_off);
				ut32 param_last = param_rows + 1;
				if (i + 1 < num_rows && fits_in_pe (pe, row_ptr + row_size, row_size)) {
					const ut8 *next = row_ptr + row_size + param_list_off;
					param_last = param_index_size == 4? r_read_le32 (next): r_read_le16 (next);
				}
				if (R_STR_ISNOTEMPTY (name)) {
					DotNetSymbol *sym = R_NEW0 (DotNetSymbol);
					// Methods are 1-based, the method index is relative to MethodDef table start
					// So method 1 is the first row (i = 0), method 2 is the second row (i = 1), etc.
					uint32_t method_idx = i + 1;
					DotNetMethodSig method_sig = { 0 };
					bool have_sig = dotnet_parse_method_sig (pe, streams->blob,
						metadata_root, sig_idx, symbols, &method_sig);
					bool has_this = have_sig && method_sig.has_this;
					ut32 args = have_sig? r_list_length (method_sig.parameters) + (has_this? 1: 0): 0;
					sym->param_count = (args > 0xffff)? 0xffff: (ut16)args;
					sym->ret_count = have_sig && method_sig.return_type
						&& !strcmp (method_sig.return_type, "void")? 0: 1;
					sym->is_instance = has_this;
					sym->flags = method_flags;
					sym->short_name = strdup (name);
					DotNetTypeDefInfo *parent_typedef = dotnet_find_typedef_for_method_index (typedef_info, method_idx);
					if (parent_typedef) {
						// Create fully qualified name: namespace.classname.methodname
						const char *ns = parent_typedef->namespace;
						if (R_STR_ISNOTEMPTY (ns)) {
							sym->classname = r_str_newf ("%s.%s", ns, parent_typedef->class_name);
						} else {
							sym->classname = strdup (parent_typedef->class_name);
						}
						sym->name = r_str_newf ("%s.%s", sym->classname, name);
					} else {
						sym->name = strdup (name);
					}
					if (have_sig) {
						sym->return_type = strdup (method_sig.return_type);
						sym->signature = dotnet_build_method_signature (sym->name,
							&method_sig, pe, param_table, param_rows, param_row_size,
							index_sizes.string, string_offset, param_first, param_last);
					}
					sym->vaddr = rva; // RVA from the method table
					sym->size = 0;
					sym->type = strdup ("methoddef");
					sym->token = 0x06000000 | method_idx;
					// Set is_native based on ImplFlags
					// IL = 0x0000, Native = 0x0001, OPTIL = 0x0002, Runtime = 0x0003
					sym->is_native = (impl_flags & 0x0003) == 0x0001;
					r_list_append (symbols, sym);
					dotnet_method_sig_fini (&method_sig);
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
			row_count = max_rows (5, rows.typedef_, rows.typeref, rows.moduleref,
				rows.methoddef, rows.typespec);
			uint8_t class_index_size = (row_count > (0xFFFF >> 0x03))? 4: 2;

			row_ptr = table_offset;
			for (i = 0; i < num_rows; i++) {
				uint32_t row_size = class_index_size + index_sizes.string + index_sizes.blob;

				if (!fits_in_pe (pe, row_ptr, row_size)) {
					break;
				}

				ut32 parent_coded = class_index_size == 4
					? r_read_le32 (row_ptr): r_read_le16 (row_ptr);
				ut32 parent_rid = parent_coded >> 3;
				ut32 parent_tag = parent_coded & 7;
				ut32 parent_token = 0;
				switch (parent_tag) {
				case 0: parent_token = 0x02000000 | parent_rid; break;
				case 1: parent_token = 0x01000000 | parent_rid; break;
				case 3: parent_token = 0x06000000 | parent_rid; break;
				case 4: parent_token = 0x1b000000 | parent_rid; break;
				default: break;
				}
				ut32 signature_offset = class_index_size + index_sizes.string;
				ut32 signature_index = index_sizes.blob == 4
					? r_read_le32 (row_ptr + signature_offset)
					: r_read_le16 (row_ptr + signature_offset);

				// Name
				if (index_sizes.string == 4) {
					name = pe_get_dotnet_string (pe, string_offset, r_read_le32 (row_ptr + class_index_size));
				} else {
					name = pe_get_dotnet_string (pe, string_offset, r_read_le16 (row_ptr + class_index_size));
				}

				if (R_STR_ISNOTEMPTY (name)) {
					DotNetSymbol *sym = R_NEW0 (DotNetSymbol);
					sym->short_name = strdup (name);
					DotNetSymbol *parent = dotnet_symbol_by_token (symbols, parent_token);
					sym->classname = dotnet_symbol_fullname (parent);
					sym->name = sym->classname
						? r_str_newf ("%s.%s", sym->classname, name): strdup (name);
					sym->vaddr = 0; // MemberRef don't have RVA
					sym->size = 0;
					sym->type = strdup ("memberref");
					sym->token = 0x0A000000 | (i + 1);
					DotNetMethodSig method_sig = { 0 };
					if (dotnet_parse_method_sig (pe, streams->blob, metadata_root,
							signature_index, symbols, &method_sig)) {
						sym->is_instance = method_sig.has_this;
						ut32 args = r_list_length (method_sig.parameters) + (method_sig.has_this? 1: 0);
						sym->param_count = args > 0xffff? 0xffff: (ut16)args;
						sym->return_type = strdup (method_sig.return_type);
						sym->ret_count = strcmp (method_sig.return_type, "void")? 1: 0;
						sym->signature = dotnet_build_method_signature (sym->name,
							&method_sig, pe, NULL, 0, 0, index_sizes.string,
							string_offset, 0, 0);
					} else {
						sym->return_type = dotnet_parse_field_sig (pe, streams->blob,
							metadata_root, signature_index, symbols);
						if (sym->return_type) {
							sym->signature = r_str_newf ("%s:%s", sym->name, sym->return_type);
						}
					}
					dotnet_method_sig_fini (&method_sig);
					r_list_append (symbols, sym);
				}

				row_ptr += row_size;
			}
			// Successfully parsed MemberRef
			table_offset += (class_index_size + index_sizes.string + index_sizes.blob) * num_rows;
			matched_bits++;
			continue;
		} else if (bit_check == BIT_TYPEDEF) {
			row_count = max_rows (3, rows.typedef_, rows.typeref, rows.typespec);
			uint8_t extends_index_size = (row_count > (0xFFFF >> 0x02))? 4: 2;
			table_offset += (4 + (index_sizes.string * 2) +
						extends_index_size +
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
				row_count = max_rows (4, rows.module, rows.moduleref, rows.assemblyref, rows.typeref);
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
				row_count = max_rows (5, rows.typedef_, rows.typeref, rows.moduleref,
					rows.methoddef, rows.typespec);
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
				table_size = (4 + 2 + 2 + 2 + 2 + 4 + index_sizes.blob + (index_sizes.string * 2)) * num_rows;
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
				row_count = max_rows (3, rows.file, rows.assemblyref, rows.exportedtype);
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

static char *dotnet_parse_method_instantiation(PE *pe, PSTREAM_HEADER blob_hdr,
		ut64 metadata_root, ut32 blob_index, RList *symbols) {
	if (!blob_hdr || !blob_index) {
		return NULL;
	}
	const ut8 *heap = dotnet_stream_data (pe, metadata_root, blob_hdr);
	ut32 heap_size = dotnet_stream_size (blob_hdr);
	if (!heap || blob_index >= heap_size || heap_size > (ut64)(pe->data + pe->data_size - heap)) {
		return NULL;
	}
	const ut8 *p = heap + blob_index;
	const ut8 *heap_end = heap + heap_size;
	const ut8 *before = p;
	ut32 size = dotnet_read_compressed_uint (&p, heap_end);
	if (p == before || !size || size > (ut64)(heap_end - p)) {
		return NULL;
	}
	const ut8 *end = p + size;
	if (p >= end || *p++ != 0x0a) { // GENERICINST method signature
		return NULL;
	}
	before = p;
	ut32 count = dotnet_read_compressed_uint (&p, end);
	if (p == before || count > 1024) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new ("<");
	ut32 i;
	for (i = 0; i < count; i++) {
		char *type = dotnet_parse_sig_type (&p, end, symbols, 0);
		if (!type) {
			r_strbuf_free (sb);
			return NULL;
		}
		r_strbuf_appendf (sb, "%s%s", i? ",": "", type);
		free (type);
	}
	r_strbuf_append (sb, ">");
	return r_strbuf_drain (sb);
}

static char *dotnet_add_generic_arguments(const char *name, const char *arguments) {
	if (!name) {
		return NULL;
	}
	if (!arguments) {
		return strdup (name);
	}
	const char *paren = strchr (name, '(');
	return paren
		? r_str_newf ("%.*s%s%s", (int)(paren - name), name, arguments, paren)
		: r_str_newf ("%s%s", name, arguments);
}

static void dotnet_parse_tilde_standalonesig(PE *pe, PTILDE_HEADER tilde_header,
		ut64 metadata_root, ROWS rows, INDEX_SIZES index_sizes,
		PSTREAMS streams, RList *symbols) {
	if (!streams->tilde || !streams->blob) {
		return;
	}
	ut32 num_rows = 0;
	const ut8 *table = dotnet_tilde_table_offset (pe, tilde_header, &rows,
		&index_sizes, BIT_STANDALONESIG, &num_rows);
	ut32 i;
	for (i = 0; table && i < num_rows; i++, table += index_sizes.blob) {
		if (!fits_in_pe (pe, table, index_sizes.blob)) {
			break;
		}
		ut32 blob_index = index_sizes.blob == 4? r_read_le32 (table): r_read_le16 (table);
		DotNetMethodSig method_sig = { 0 };
		if (!dotnet_parse_method_sig (pe, streams->blob, metadata_root,
				blob_index, symbols, &method_sig)) {
			dotnet_method_sig_fini (&method_sig);
			continue;
		}
		DotNetSymbol *sym = R_NEW0 (DotNetSymbol);
		if (!sym) {
			dotnet_method_sig_fini (&method_sig);
			break;
		}
		sym->name = r_str_newf ("calli.%u", i + 1);
		sym->short_name = strdup ("calli");
		sym->signature = dotnet_build_method_signature ("calli", &method_sig,
			pe, NULL, 0, 0, index_sizes.string, NULL, 0, 0);
		sym->return_type = strdup (method_sig.return_type);
		sym->is_instance = method_sig.has_this;
		ut32 args = r_list_length (method_sig.parameters) + (method_sig.has_this? 1: 0);
		sym->param_count = args > 0xffff? 0xffff: (ut16)args;
		sym->ret_count = strcmp (method_sig.return_type, "void")? 1: 0;
		sym->type = strdup ("standalonesig");
		sym->token = 0x11000000 | (i + 1);
		r_list_append (symbols, sym);
		dotnet_method_sig_fini (&method_sig);
	}
}

static void dotnet_parse_tilde_methodspec(PE *pe, PTILDE_HEADER tilde_header,
		ut64 metadata_root, ROWS rows, INDEX_SIZES index_sizes,
		PSTREAMS streams, RList *symbols) {
	if (!streams->tilde || !streams->blob) {
		return;
	}
	ut32 num_rows = 0;
	const ut8 *table = dotnet_tilde_table_offset (pe, tilde_header, &rows,
		&index_sizes, BIT_METHODSPEC, &num_rows);
	ut32 method_rows = R_MAX (rows.methoddef, rows.memberref);
	ut8 method_size = method_rows > (0xffff >> 1)? 4: 2;
	ut32 row_size = method_size + index_sizes.blob;
	ut32 i;
	for (i = 0; table && i < num_rows; i++, table += row_size) {
		if (!fits_in_pe (pe, table, row_size)) {
			break;
		}
		ut32 coded = method_size == 4? r_read_le32 (table): r_read_le16 (table);
		ut32 method_token = ((coded & 1)? 0x0a000000: 0x06000000) | (coded >> 1);
		ut32 blob_index = index_sizes.blob == 4
			? r_read_le32 (table + method_size): r_read_le16 (table + method_size);
		DotNetSymbol *base = dotnet_symbol_by_token (symbols, method_token);
		char *arguments = dotnet_parse_method_instantiation (pe, streams->blob,
			metadata_root, blob_index, symbols);
		DotNetSymbol *sym = R_NEW0 (DotNetSymbol);
		if (!sym) {
			free (arguments);
			break;
		}
		sym->name = dotnet_add_generic_arguments (base? base->name: "methodspec", arguments);
		sym->short_name = dotnet_add_generic_arguments (base? base->short_name: "methodspec", arguments);
		sym->signature = dotnet_add_generic_arguments (base? base->signature: NULL, arguments);
		sym->classname = base && base->classname? strdup (base->classname): NULL;
		sym->return_type = base && base->return_type? strdup (base->return_type): NULL;
		sym->flags = base? base->flags: 0;
		sym->is_instance = base && base->is_instance;
		sym->param_count = base? base->param_count: 0;
		sym->ret_count = base? base->ret_count: 0;
		sym->type = strdup ("methodspec");
		sym->token = 0x2b000000 | (i + 1);
		r_list_append (symbols, sym);
		free (arguments);
	}
}

// Helper function to collect typedef metadata for method association
static void dotnet_typedef_free(void *p) {
	if (p) {
		DotNetTypeDefInfo *td = (DotNetTypeDefInfo *)p;
		free (td->class_name);
		free (td->namespace);
		free (td);
	}
}

static RList *dotnet_collect_typedefs(PE *pe, ut64 metadata_root, PSTREAMS streams, ROWS rows, INDEX_SIZES index_sizes) {
	if (!streams->tilde || !streams->string) {
		return r_list_newf ((RListFree)dotnet_typedef_free);
	}
	const ut8 *tilde_data = dotnet_stream_data (pe, metadata_root, streams->tilde);
	if (!tilde_data) {
		return r_list_newf ((RListFree)dotnet_typedef_free);
	}
	PTILDE_HEADER tilde_header = (PTILDE_HEADER)tilde_data;
	if (!struct_fits_in_pe (pe, tilde_header, TILDE_HEADER)) {
		return r_list_newf ((RListFree)dotnet_typedef_free);
	}
	uint32_t *row_offset = (uint32_t *) (tilde_header + 1);
	const uint8_t *string_offset = dotnet_stream_data (pe, metadata_root, streams->string);
	if (!string_offset) {
		return r_list_newf ((RListFree)dotnet_typedef_free);
	}
	uint8_t *table_offset = (uint8_t *)row_offset;
	int j, bit_check, matched_bits = 0;
	uint32_t num_rows;
	RList *typedef_info = r_list_newf ((RListFree)dotnet_typedef_free);

	// Calculate offset to TypeDef table
	// First count how many tables are present so we can skip the row-counts array
	for (j = 0; j < 64; j++) {
		matched_bits += ((dotnet_tilde_valid (tilde_header) >> j) & 0x01);
	}
	// Advance past the row-count array (one uint32_t per present table)
	table_offset += sizeof (uint32_t) * matched_bits;
	matched_bits = 0;
	for (bit_check = 0; bit_check < 64; bit_check++) {
		if (! ((dotnet_tilde_valid (tilde_header) >> bit_check) & 0x01)) {
			continue;
		}

		if (bit_check == BIT_TYPEDEF) {
			// Found TypeDef table, parse it
			uint32_t row_count = max_rows (3, rows.typedef_, rows.typeref, rows.typespec);
			uint8_t extends_index_size = (row_count > (0xFFFF >> 0x02))? 4: 2;
			uint8_t field_index_size = (rows.field > 0xFFFF)? 4: 2;
			uint8_t methoddef_index_size = (rows.methoddef > 0xFFFF)? 4: 2;
			if (!fits_in_pe (pe, row_offset, (matched_bits + 1) * sizeof (uint32_t))) {
				return typedef_info;
			}
			num_rows = dotnet_row_count_at (row_offset, matched_bits);

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
					name_idx = r_read_le32 (row_ptr + 4);
					ns_idx = r_read_le32 (row_ptr + 8);
				} else {
					name_idx = r_read_le16 (row_ptr + 4);
					ns_idx = r_read_le16 (row_ptr + 6);
				}
				type_name = pe_get_dotnet_string (pe, string_offset, name_idx);
				namespace = pe_get_dotnet_string (pe, string_offset, ns_idx);

				// Extract FieldList and MethodList indices
				// Layout: Flags (4) + Name (string) + Namespace (string) + Extends (coded_idx) + FieldList (field) + MethodList (methoddef)
				uint8_t *field_list_ptr = row_ptr + 4 + (index_sizes.string * 2) + extends_index_size;
				uint8_t *method_list_ptr = field_list_ptr + index_sizes.field;

				uint32_t field_list_idx, method_list_idx;
				if (index_sizes.field == 4) {
					field_list_idx = r_read_le32 (field_list_ptr);
				} else {
					field_list_idx = r_read_le16 (field_list_ptr);
				}
				if (index_sizes.methoddef == 4) {
					method_list_idx = r_read_le32 (method_list_ptr);
				} else {
					method_list_idx = r_read_le16 (method_list_ptr);
				}

				// Find next typedef's lists to know the range for this class
				uint32_t next_field_list_idx = rows.field + 1; // Default to end
				uint32_t next_method_list_idx = rows.methoddef + 1; // Default to end
				uint8_t *next_row_ptr = row_ptr + row_size;
				if (i + 1 < num_rows && fits_in_pe (pe, next_row_ptr, row_size)) {
					uint8_t *next_field_list_ptr = next_row_ptr + 4 + (index_sizes.string * 2) + extends_index_size;
					uint8_t *next_method_list_ptr = next_field_list_ptr + index_sizes.field;
					if (index_sizes.field == 4) {
						next_field_list_idx = r_read_le32 (next_field_list_ptr);
					} else {
						next_field_list_idx = r_read_le16 (next_field_list_ptr);
					}
					if (index_sizes.methoddef == 4) {
						next_method_list_idx = r_read_le32 (next_method_list_ptr);
					} else {
						next_method_list_idx = r_read_le16 (next_method_list_ptr);
					}
				}

				DotNetTypeDefInfo *td = R_NEW0 (DotNetTypeDefInfo);
				td->class_name = strdup (r_str_get_fail (type_name, "<unnamed>"));
				td->namespace = strdup (r_str_get (namespace));
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
			if (!fits_in_pe (pe, row_offset, (matched_bits + 1) * sizeof (uint32_t))) {
				return typedef_info;
			}
			num_rows = dotnet_row_count_at (row_offset, matched_bits);
			// Calculate row size for this table and skip it
			switch (bit_check) {
			case BIT_MODULE:
				table_offset += (2 + index_sizes.string + (index_sizes.guid * 3)) * num_rows;
				break;
			case BIT_TYPEREF:
				{
					// TypeRef: ResolutionScope (coded index) + Name (string) + Namespace (string)
					// ResolutionScope is a ResolutionScope coded index (module | moduleref | assemblyref)
					uint32_t resolution_scope_row_count = max_rows (4, rows.module, rows.moduleref, rows.assemblyref, rows.typeref);
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

	const ut8 *tilde_data = dotnet_stream_data (pe, metadata_root, streams->tilde);
	if (!tilde_data) {
		return;
	}
	tilde_header = (PTILDE_HEADER)tilde_data;

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
		if (! ((dotnet_tilde_valid (tilde_header) >> bit_check) & 0x01)) {
			continue;
		}

#define ROW_CHECK(name) \
	if (fits_in_pe (pe, row_offset, (matched_bits + 1) * sizeof (uint32_t))) \
		rows.name = dotnet_row_count_at (row_offset, matched_bits);

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
	// TypeRef names are required to decode field and method signatures.
	dotnet_parse_tilde_typeref (pe, tilde_header, metadata_root, rows, index_sizes, streams, symbols);
	// TypeSpec rows resolve generic, pointer and array types used by member refs.
	dotnet_parse_tilde_typespec (pe, tilde_header, metadata_root, rows, index_sizes, streams, symbols);
	// Parse fields to associate them with classes
	dotnet_parse_tilde_field (pe, tilde_header, metadata_root, rows, index_sizes, streams, typedef_info, symbols);
	// Then parse methoddef to assign methods to classes with full qualified names
	dotnet_parse_tilde_methoddef (pe, tilde_header, metadata_root, rows, index_sizes, streams, symbols, typedef_info);
	// Resolve calli and generic-call tokens after MethodDef and MemberRef exist.
	dotnet_parse_tilde_standalonesig (pe, tilde_header, metadata_root, rows, index_sizes, streams, symbols);
	dotnet_parse_tilde_methodspec (pe, tilde_header, metadata_root, rows, index_sizes, streams, symbols);

	// Clean up typedef info
	r_list_free (typedef_info);
}

static RList *dotnet_parse_com(PE *pe, ut64 baddr) {
	PNET_METADATA metadata;
	ut64 metadata_root;
	STREAMS headers;
	ut16 num_streams;
	RList *symbols = NULL;
	int i;
	st64 metadata_offset = -1;

	symbols = r_list_newf ((RListFree)dotnet_symbol_free);
	if (!symbols) {
		return NULL;
	}

	// Find the .NET metadata by searching for the magic number (BSJB = 0x424a5342)
	// The metadata can be anywhere in the file, so scan the entire file
	if (pe->data_size > 0x100) {
		for (i = 0x40; i < (int)pe->data_size - (int)sizeof (NET_METADATA); i++) {
			if (dotnet_metadata_magic_at (pe->data + i)) {
				metadata_offset = i;
				break;
			}
		}
	}

	if (metadata_offset < 0) {
		return symbols;
	}

	metadata_root = metadata_offset;

	if (!struct_fits_in_pe (pe, pe->data + metadata_root, NET_METADATA)) {
		return symbols;
	}

	metadata = (PNET_METADATA) (pe->data + metadata_root);

	if (!dotnet_metadata_magic_at ((const ut8 *)metadata)) {
		return symbols;
	}

	ut32 metadata_length = dotnet_metadata_length (metadata);
	// Version length must be between 1 and 255, and be a multiple of 4.
	if (metadata_length == 0 ||
		metadata_length > 255 ||
		metadata_length % 4 != 0 ||
		!fits_in_pe (pe, pe->data + metadata_root, metadata_length)) {
		return symbols;
	}

	// The metadata structure has some variable length records after the version.
	st64 stream_offset = metadata_root + sizeof (NET_METADATA) + metadata_length + 2;

	// 2 bytes for Streams.
	if (!fits_in_pe (pe, pe->data + stream_offset, 2)) {
		return symbols;
	}

	num_streams = r_read_le16 (pe->data + stream_offset);
	stream_offset += 2;
	if (num_streams > dotnet_max_stream_headers (pe, stream_offset)) {
		return symbols;
	}

	headers = dotnet_parse_stream_headers (pe, stream_offset, metadata_root, num_streams);

	// Parse the #~ stream which contains the metadata tables
	if (headers.tilde && headers.string && headers.blob) {
		dotnet_parse_tilde (pe, metadata_root, &headers, symbols);
	}

	return symbols;
}

// entrypoint - returns a list of DotNetSymbol pointers
RList *dotnet_parse(const ut8 *buf, int size, ut64 baddr) {
	if (!buf || size < 1) {
		return NULL;
	}
	PE pe = { buf, (ut32)size, NULL };
	return dotnet_parse_com (&pe, baddr);
}

static void dotnet_manifest_resource_free(void *ptr) {
	DotNetManifestResource *resource = ptr;
	free (resource->name);
	free (resource);
}

static const ut8 *dotnet_bounded_stream_data(PE *pe, PSTREAM_HEADER stream, R_OUT ut32 *size) {
	if (!pe || !stream || !size) {
		return NULL;
	}
	ut32 offset = dotnet_stream_offset (stream);
	ut32 stream_size = dotnet_stream_size (stream);
	if (offset > pe->data_size || stream_size > pe->data_size - offset) {
		return NULL;
	}
	*size = stream_size;
	return pe->data + offset;
}

static char *dotnet_manifest_resource_name(const ut8 *strings, ut32 strings_size, ut32 index) {
	if (!strings || !index || index >= strings_size) {
		return NULL;
	}
	const char *name = (const char *)strings + index;
	size_t remaining = strings_size - index;
	return memchr (name, 0, remaining)? strdup (name): NULL;
}

RList *dotnet_parse_manifest_resources(RBuffer *buf, ut64 metadata_paddr, ut64 metadata_size) {
	if (!buf || metadata_size < sizeof (NET_METADATA) || metadata_size > SIZE_MAX) {
		return NULL;
	}
	ut64 file_size = r_buf_size (buf);
	if (metadata_paddr > file_size || metadata_size > file_size - metadata_paddr) {
		return NULL;
	}
	ut8 *data = malloc ((size_t)metadata_size);
	if (!data) {
		return NULL;
	}
	RList *resources = r_list_newf (dotnet_manifest_resource_free);
	if (!resources) {
		free (data);
		return NULL;
	}
	if ((ut64)r_buf_read_at (buf, metadata_paddr, data, metadata_size) != metadata_size) {
		goto done;
	}
	PE metadata_pe = { data, (size_t)metadata_size, NULL };
	PE *pe = &metadata_pe;
	PNET_METADATA metadata = (PNET_METADATA)data;
	if (!dotnet_metadata_magic_at (data)) {
		goto done;
	}
	ut32 version_size = dotnet_metadata_length (metadata);
	if ((version_size & 3) || version_size > metadata_size - sizeof (NET_METADATA) ||
		metadata_size - sizeof (NET_METADATA) - version_size < 4) {
		goto done;
	}
	ut64 stream_offset = sizeof (NET_METADATA) + version_size;
	ut16 num_streams = r_read_le16 (data + stream_offset + 2);
	stream_offset += 4;
	STREAMS streams = dotnet_parse_stream_headers (pe, stream_offset, 0, num_streams);
	if (!streams.tilde || !streams.string) {
		goto done;
	}
	ut32 tables_size = 0;
	const ut8 *tables_data = dotnet_bounded_stream_data (pe, streams.tilde, &tables_size);
	ut32 strings_size = 0;
	const ut8 *strings_data = dotnet_bounded_stream_data (pe, streams.string, &strings_size);
	if (!tables_data || !strings_data || tables_size < sizeof (TILDE_HEADER)) {
		goto done;
	}
	PE tables_pe = { tables_data, tables_size, NULL };
	PTILDE_HEADER tilde_header = (PTILDE_HEADER)tables_data;
	ROWS rows;
	INDEX_SIZES index_sizes;
	if (!dotnet_parse_tilde_rows (&tables_pe, tilde_header, &rows, &index_sizes)) {
		goto done;
	}
	ut32 num_rows;
	const ut8 *row = dotnet_tilde_table_offset (&tables_pe, tilde_header, &rows,
		&index_sizes, BIT_MANIFESTRESOURCE, &num_rows);
	if (!row) {
		goto done;
	}
	ut32 implementation_rows = max_rows (3, rows.file, rows.assemblyref, rows.exportedtype);
	ut8 implementation_size = implementation_rows > (0xFFFF >> 2)? 4: 2;
	ut32 row_size = 8 + index_sizes.string + implementation_size;
	ut32 i;
	for (i = 0; i < num_rows; i++, row += row_size) {
		ut32 flags = r_read_le32 (row + 4);
		ut32 visibility = flags & 7;
		if (visibility != 1 && visibility != 2) {
			continue;
		}
		ut32 name_index = index_sizes.string == 4
			? r_read_le32 (row + 8): r_read_le16 (row + 8);
		const ut8 *implementation_ptr = row + 8 + index_sizes.string;
		ut32 implementation = implementation_size == 4
			? r_read_le32 (implementation_ptr): r_read_le16 (implementation_ptr);
		char *name = dotnet_manifest_resource_name (strings_data, strings_size, name_index);
		if (!name) {
			continue;
		}
		DotNetManifestResource *resource = R_NEW0 (DotNetManifestResource);
		resource->name = name;
		resource->offset = r_read_le32 (row);
		resource->flags = flags;
		resource->implementation = implementation;
		if (!r_list_append (resources, resource)) {
			dotnet_manifest_resource_free (resource);
			r_list_free (resources);
			resources = NULL;
			break;
		}
	}
done:
	free (data);
	return resources;
}

RList *dotnet_parse_libs(const ut8 *buf, int size) {
	PNET_METADATA metadata;
	ut64 metadata_root;
	STREAMS headers;
	ut16 num_streams;
	RList *libraries = NULL;
	int i;
	st64 metadata_offset = -1;
	if (!buf || size < 1) {
		return NULL;
	}
	PE pe_struct = { buf, (ut32)size, NULL };
	PE *pe = &pe_struct;

	libraries = r_list_newf ((RListFree)free);
	if (!libraries) {
		return NULL;
	}

	// Find the .NET metadata by searching for the magic number
	if (pe->data_size > 0x100) {
		for (i = 0x40; i < (int)pe->data_size - (int)sizeof (NET_METADATA); i++) {
			if (dotnet_metadata_magic_at (pe->data + i)) {
				metadata_offset = i;
				break;
			}
		}
	}

	if (metadata_offset < 0) {
		return libraries;
	}

	metadata_root = metadata_offset;

	if (! (fits_in_pe (pe, pe->data + metadata_root, sizeof (NET_METADATA)))) {
		return libraries;
	}

	metadata = (PNET_METADATA) (pe->data + metadata_root);

	if (!dotnet_metadata_magic_at ((const ut8 *)metadata)) {
		return libraries;
	}

	ut32 metadata_length = dotnet_metadata_length (metadata);
	if (metadata_length == 0 ||
		metadata_length > 255 ||
		metadata_length % 4 != 0 ||
		! (fits_in_pe (pe, pe->data + metadata_root, metadata_length))) {
		return libraries;
	}

	st64 stream_offset = metadata_root + sizeof (NET_METADATA) + metadata_length + 2;

	if (! (fits_in_pe (pe, pe->data + stream_offset, 2))) {
		return libraries;
	}

	num_streams = r_read_le16 (pe->data + stream_offset);
	stream_offset += 2;
	if (num_streams > dotnet_max_stream_headers (pe, stream_offset)) {
		return libraries;
	}

	headers = dotnet_parse_stream_headers (pe, stream_offset, metadata_root, num_streams);

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

		const ut8 *tilde_data = dotnet_stream_data (pe, metadata_root, headers.tilde);
		if (!tilde_data) {
			return libraries;
		}
		tilde_header = (PTILDE_HEADER)tilde_data;

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
				if (! ((dotnet_tilde_valid (tilde_header) >> bit_check) & 0x01)) {
					continue;
				}

				if (fits_in_pe (pe, (uint8_t *)row_offset, (matched_bits + 1) * sizeof (uint32_t))) {
					rows.assemblyref = dotnet_row_count_at (row_offset, matched_bits);
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
	if (!buf || size < 1) {
		return NULL;
	}
	// TODO: Parse ImplMap table for P/Invoke declarations
	// This would extract native library imports from .NET assemblies
	RList *imports = r_list_newf ((RListFree)free);
	return imports;
}

// Extract .NET runtime version and assembly version from MSIL headers
DotNetVersionInfo *dotnet_parse_version_info(const ut8 *buf, int size) {
	st64 cli_offset = -1;
	int i;
	st64 metadata_offset = -1;
	if (!buf || size < 1) {
		return NULL;
	}
	PE pe_struct = { buf, (ut32)size, NULL };
	PE *pe = &pe_struct;

	// First, find the CLI header by scanning for its signature near the start of the file
	// CLI headers are typically within the first 0x1000 bytes of the .text section
	if (pe->data_size > 0x100) {
		int search_limit = (pe->data_size > 0x2000)? 0x2000: (int)pe->data_size;
		for (i = 0x100; i < search_limit - (int)sizeof (CLI_HEADER); i++) {
			ut32 cli_size = r_read_le32 (pe->data + i);
			ut16 cli_major = r_read_le16 (pe->data + i + 4);
			ut16 cli_minor = r_read_le16 (pe->data + i + 6);
			if ((cli_size == 0x48 || cli_size == 0x44) &&
				cli_major >= 1 && cli_major <= 5 &&
				cli_minor <= 10) {
				cli_offset = i;
				break;
			}
		}
	}

	// Find the metadata magic
	if (pe->data_size > 0x100) {
		for (i = 0x40; i < (int)pe->data_size - (int)sizeof (NET_METADATA); i++) {
			if (dotnet_metadata_magic_at (pe->data + i)) {
				metadata_offset = i;
				break;
			}
		}
	}

	if (cli_offset < 0 && metadata_offset < 0) {
		return NULL;
	}

	// Allocate version info structure
	DotNetVersionInfo *version_info = R_NEW0 (DotNetVersionInfo);
	// Get CLI header version if we found it
	if (cli_offset >= 0 && struct_fits_in_pe (pe, pe->data + cli_offset, CLI_HEADER)) {
		version_info->cli_major = r_read_le16 (pe->data + cli_offset + 4);
		version_info->cli_minor = r_read_le16 (pe->data + cli_offset + 6);
	}

	if (metadata_offset < 0) {
		return version_info;
	}

	// Try to parse Assembly table, but don't fail if we can't
	// The CLR version alone is valuable
	PNET_METADATA metadata;
	ut64 metadata_root = metadata_offset;

	if (struct_fits_in_pe (pe, pe->data + metadata_root, NET_METADATA)) {
		metadata = (PNET_METADATA) (pe->data + metadata_root);

		ut32 metadata_length = dotnet_metadata_length (metadata);
		if (dotnet_metadata_magic_at ((const ut8 *)metadata) &&
			metadata_length > 0 &&
			metadata_length <= 255 &&
			metadata_length % 4 == 0 &&
			fits_in_pe (pe, pe->data + metadata_root, metadata_length)) {

			st64 offset_2 = metadata_root + sizeof (NET_METADATA) + metadata_length + 2;
			if (fits_in_pe (pe, pe->data + offset_2, 2)) {
				ut16 num_streams = r_read_le16 (pe->data + offset_2);
				offset_2 += 2;
				if (num_streams > dotnet_max_stream_headers (pe, offset_2)) {
					return version_info;
				}
				STREAMS headers = dotnet_parse_stream_headers (pe, offset_2, metadata_root, num_streams);

				// Try to parse Assembly table
				if (headers.tilde && headers.string) {
					PTILDE_HEADER tilde_header;
					const ut8 *assembly_row;
					ROWS rows;
					INDEX_SIZES index_sizes;
					ut32 num_rows = 0;

					const ut8 *tilde_data = dotnet_stream_data (pe, metadata_root, headers.tilde);
					if (!tilde_data) {
						return version_info;
					}
					tilde_header = (PTILDE_HEADER)tilde_data;

					if (dotnet_parse_tilde_rows (pe, tilde_header, &rows, &index_sizes) &&
						((dotnet_tilde_valid (tilde_header) >> BIT_ASSEMBLY) & 0x01)) {
						assembly_row = dotnet_tilde_table_offset (pe, tilde_header, &rows, &index_sizes, BIT_ASSEMBLY, &num_rows);
						if (assembly_row && num_rows > 0 && fits_in_pe (pe, assembly_row, 12)) {
							version_info->asm_major = r_read_le16 (assembly_row + 4);
							version_info->asm_minor = r_read_le16 (assembly_row + 6);
							version_info->asm_build = r_read_le16 (assembly_row + 8);
							version_info->asm_revision = r_read_le16 (assembly_row + 10);
						}
					}
				}
			}
		}
	}
	return version_info;
}
