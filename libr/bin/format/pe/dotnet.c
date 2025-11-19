/*
Forked by pancake in 2017-2025

Copyright (c) 2015. The YARA Authors. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
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

typedef struct R_IMAGE_DATA_DIRECTORY {
	ut32 VirtualAddress;
	ut32 Size;
} R_IMAGE_DATA_DIRECTORY, *R_PIMAGE_DATA_DIRECTORY;

#include "pe_specs.h"
#include "dotnet.h"

static void set_string(const char *k, const char *f, const char *v, ...) {
	// TODO
	eprintf ("-> %s = %s\n", k, v);
}

static void set_integer(int a, void *b, const char *name, ...) {
	// TODO
	eprintf ("-> %s = %d\n", name, a);
}

static void set_sized_string(char *a, int len, void *p, const char *fmt, ...) {
	// TODO
	eprintf ("-> %s = %d (%s)\n", fmt, len, (char *)a);
}

static ut64 pe_rva_to_offset(void *pe, ut64 addr) {
	// TODO
	return addr;
}

typedef struct _PE {
	const uint8_t* data;
	size_t data_size;
	//  YR_OBJECT* object;
	void* object;
} PE;

R_PIMAGE_DATA_DIRECTORY pe_get_directory_entry( PE* pe, int entry) {
#if 0
	R_PIMAGE_DATA_DIRECTORY result = IS_64BITS_PE(pe)
		? &pe->header64->OptionalHeader.DataDirectory[entry]
		: &pe->header->OptionalHeader.DataDirectory[entry];
#else
	R_PIMAGE_DATA_DIRECTORY result = {0};
#endif
	return result;
}

char* pe_get_dotnet_string( PE* pe, const uint8_t* string_offset, ut32 string_index) {
	// Start of string must be within boundary
	if (!(string_offset + string_index >= pe->data &&
			string_offset + string_index < pe->data + pe->data_size)) {
		return NULL;
	}
	// Calculate how much until end of boundary, don't scan past that.
	size_t remaining = (pe->data + pe->data_size) - (string_offset + string_index);

	// Search for a NULL terminator from start of string, up to remaining.
	char *start = (char*) (string_offset + string_index);
	char *eos = (char*) r_mem_mem((void*) start, remaining, (void*)"\0", 1);

	return eos? start: NULL;
}

uint32_t max_rows(int count, ...) {
	va_list ap;
	int i;
	uint32_t biggest;
	uint32_t x;

	if (count == 0)
		return 0;

	va_start(ap, count);
	biggest = va_arg(ap, uint32_t);

	for (i = 1; i < count; i++) {
		x = va_arg(ap, uint32_t);
		if (x > biggest) biggest = x;
	}

	va_end(ap);
	return biggest;
}

void dotnet_parse_guid( PE* pe, ut64 metadata_root, PSTREAM_HEADER guid_header) {
	// GUIDs are 16 bytes each, converted to hex format plus separators and NULL.
	char guid[37];
	int i = 0;

	const uint8_t* guid_offset = pe->data + metadata_root + guid_header->Offset;
	ut32 guid_size = guid_header->Size;

	// Parse GUIDs if we have them.
	// GUIDs are 16 bytes each.
	while (guid_size >= 16 && fits_in_pe (pe, guid_offset, 16)) {
		snprintf (guid, sizeof (guid), "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
				*(uint32_t*) guid_offset,
				*(uint16_t*) (guid_offset + 4),
				*(uint16_t*) (guid_offset + 6),
				*(guid_offset + 8),
				*(guid_offset + 9),
				*(guid_offset + 10),
				*(guid_offset + 11),
				*(guid_offset + 12),
				*(guid_offset + 13),
				*(guid_offset + 14),
				*(guid_offset + 15));
		guid[(16 * 2) + 4] = '\0';
		set_string (guid, pe->object, "guids[%i]", i);
		i++;
		guid_size -= 16;
	}
	set_integer(i, pe->object, "number_of_guids");
}

// Given an offset into a #US or #Blob stream, parse the entry at that position.
// The offset is relative to the start of the PE file.
BLOB_PARSE_RESULT dotnet_parse_blob_entry( PE* pe, const uint8_t* offset) {
	BLOB_PARSE_RESULT result = {0};

	// Blob size is encoded in the first 1, 2 or 4 bytes of the blob.
	//
	// If the high bit is not set the length is encoded in one byte.
	//
	// If the high 2 bits are 10 (base 2) then the length is encoded in
	// the rest of the bits and the next byte.
	//
	// If the high 3 bits are 110 (base 2) then the length is encoded
	// in the rest of the bits and the next 3 bytes.
	//
	// See ECMA-335 II.24.2.4 for details.

	// Make sure we have at least one byte.

	if (!fits_in_pe (pe, offset, 1)) {
		result.size = 0;
		return result;
	}

	if ((*offset & 0x80) == 0x00) {
		result.length = (ut32) *offset;
		result.size = 1;
	} else if ((*offset & 0xC0) == 0x80) {
		// Make sure we have one more byte.
		if (!fits_in_pe (pe, offset, 2)) {
			result.size = 0;
			return result;
		}

		// Shift remaining 6 bits left by 8 and OR in the remaining byte.
		result.length = ((*offset & 0x3F) << 8) | *(offset + 1);
		result.size = 2;
	} else if (offset + 4 < pe->data + pe->data_size && (*offset & 0xE0) == 0xC0) {
		// Make sure we have 3 more bytes.
		if (!fits_in_pe (pe, offset, 4)) {
			result.size = 0;
			return result;
		}

		result.length = ((*offset & 0x1F) << 24) |
			(*(offset + 1) << 16) |
			(*(offset + 2) << 8) |
			*(offset + 3);
		result.size = 4;
	} else {
		// Return a 0 size as an error.
		result.size = 0;
	}
	return result;
}

void dotnet_parse_us( PE* pe, ut64 metadata_root, PSTREAM_HEADER us_header) {
	BLOB_PARSE_RESULT blob_result;
	int i = 0;

	const uint8_t* offset = pe->data + metadata_root + us_header->Offset;
	const uint8_t* end_of_header = offset + us_header->Size;

	// Make sure end of header is not past end of PE, and the first entry MUST be
	// a single NULL byte.
	if (!fits_in_pe (pe, offset, us_header->Size) || *offset != 0x00) {
		return;
	}

	offset++;

	while (offset < end_of_header) {
		blob_result = dotnet_parse_blob_entry (pe, offset);

		if (blob_result.size == 0 || !fits_in_pe (pe, offset, blob_result.length)) {
			set_integer(i, pe->object, "number_of_user_strings");
			return;
		}

		offset += blob_result.size;
		// Avoid empty strings, which usually happen as padding at the end of the
		// stream.

		if (blob_result.length > 0) {
			set_sized_string(
					(char*) offset,
					blob_result.length,
					pe->object,
					"user_strings[%i]",
					i);

			offset += blob_result.length;
			i++;
		}
	}

	set_integer(i, pe->object, "number_of_user_strings");
}

STREAMS dotnet_parse_stream_headers(PE* pe, ut64 offset, ut64 metadata_root, ut32 num_streams) {
	PSTREAM_HEADER stream_header;
	STREAMS headers;

	char *start;
	char *eos;
	char stream_name[DOTNET_STREAM_NAME_SIZE + 1];
	unsigned int i;

	memset (&headers, '\0', sizeof (STREAMS));

	stream_header = (PSTREAM_HEADER) (pe->data + offset);

	for (i = 0; i < num_streams; i++) {
		if (!struct_fits_in_pe (pe, stream_header, STREAM_HEADER)) {
			break;
		}

		start = (char*) stream_header->Name;

		if (!fits_in_pe (pe, start, DOTNET_STREAM_NAME_SIZE)) {
			break;
		}

		eos = (char*) r_mem_mem((void*) start, DOTNET_STREAM_NAME_SIZE, (void*)"\0", 1);

		if (eos == NULL)
			break;

		strncpy (stream_name, stream_header->Name, DOTNET_STREAM_NAME_SIZE);
		stream_name[DOTNET_STREAM_NAME_SIZE] = '\0';

		set_string (stream_name,
				pe->object, "streams[%i].name", i);
		// Offset is relative to metadata_root.
		set_integer (metadata_root + stream_header->Offset,
				pe->object, "streams[%i].offset", i);
		set_integer (stream_header->Size,
				pe->object, "streams[%i].size", i);

		// Store necessary bits to parse these later. Not all tables will be
		// parsed, but are referenced from others. For example, the #Strings
		// stream is referenced from various tables in the #~ heap.
		if (strncmp (stream_name, "#GUID", 5)) {
			headers.guid = stream_header;
		// Believe it or not, I have seen at least one binary which has a #- stream
		// instead of a #~ (215e1b54ae1aac153e55596e6f1a4350). This isn't in the
		// documentation anywhere but the structure is the same. I'm chosing not
		// to parse it for now.
		} else if (strncmp (stream_name, "#~", 2) == 0 && headers.tilde == NULL) {
			headers.tilde = stream_header;
		} else if (strncmp (stream_name, "#Strings", 8) == 0 && headers.string == NULL) {
			headers.string = stream_header;
		} else if (strncmp (stream_name, "#Blob", 5) == 0) {
			headers.blob = stream_header;
		} else if (strncmp (stream_name, "#US", 3) == 0 && headers.us == NULL) {
			headers.us = stream_header;
		}

		// Stream name is padded to a multiple of 4.
		stream_header = (PSTREAM_HEADER) ((uint8_t*) stream_header +
				sizeof (STREAM_HEADER) +
				strlen(stream_name) +
				4 - (strlen(stream_name) % 4));
	}

	set_integer (i, pe->object, "number_of_streams");

	return headers;
}


// This is the second pass through the data for #~. The first pass collects
// information on the number of rows for tables which have coded indexes.
// This pass uses that information and the index_sizes to parse the tables
// of interest.
//
// Because the indexes can vary in size depending upon the number of rows in
// other tables it is impossible to use static sized structures. To deal with
// this hardcode the sizes of each table based upon the documentation (for the
// static sized portions) and use the variable sizes accordingly.

void dotnet_parse_tilde_2(
    PE* pe,
    PTILDE_HEADER tilde_header,
    ut64 resource_base,
    ut64 metadata_root,
    ROWS rows,
    INDEX_SIZES index_sizes,
    PSTREAMS streams)
{
	PMODULE_TABLE module_table;
	PASSEMBLY_TABLE assembly_table;
	PASSEMBLYREF_TABLE assemblyref_table;
	PMANIFESTRESOURCE_TABLE manifestresource_table;
	PMODULEREF_TABLE moduleref_table;
	PCUSTOMATTRIBUTE_TABLE customattribute_table;
	PCONSTANT_TABLE constant_table;
	ut32 resource_size, implementation;

	char *name;
	char typelib[MAX_TYPELIB_SIZE + 1];
	unsigned int i;
	int bit_check;
	int matched_bits = 0;

	ut64 resource_offset;
	uint32_t row_size, row_count, counter;

	const uint8_t* string_offset;
	const uint8_t* blob_offset;

	uint32_t num_rows = 0;
	uint32_t valid_rows = 0;
	uint32_t* row_offset = NULL;
	uint8_t* table_offset = NULL;
	uint8_t* row_ptr = NULL;

	// These are pointers and row sizes for tables of interest to us for special
	// parsing. For example, we are interested in pulling out any CustomAttributes
	// that are GUIDs so we need to be able to walk these tables. To find GUID
	// CustomAttributes you need to walk the CustomAttribute table and look for
	// any row with a Parent that indexes into the Assembly table and Type indexes
	// into the MemberRef table. Then you follow the index into the MemberRef
	// table and check the Class to make sure it indexes into TypeRef table. If it
	// does you follow that index and make sure the Name is "GuidAttribute". If
	// all that is valid then you can take the Value from the CustomAttribute
	// table to find out the index into the Blob stream and parse that.
	//
	// Luckily we can abuse the fact that the order of the tables is guaranteed
	// consistent (though some may not exist, but if they do exist they must exist
	// in a certain order). The order is defined by their position in the Valid
	// member of the tilde_header structure. By the time we are parsing the
	// CustomAttribute table we have already recorded the location of the TypeRef
	// and MemberRef tables, so we can follow the chain back up from
	// CustomAttribute through MemberRef to TypeRef.

	uint8_t* typeref_ptr = NULL;
	uint8_t* memberref_ptr = NULL;
	uint32_t typeref_row_size = 0;
	uint32_t memberref_row_size = 0;
	uint8_t* typeref_row = NULL;
	uint8_t* memberref_row = NULL;

	ut32 type_index;
	ut32 class_index;
	BLOB_PARSE_RESULT blob_result;
	ut32 blob_index;
	ut32 blob_length;

	// These are used to determine the size of coded indexes, which are the
	// dynamically sized columns for some tables. The coded indexes are
	// documented in ECMA-335 Section II.24.2.6.
	uint8_t index_size, index_size2;

	// Number of rows is the number of bits set to 1 in Valid.
	// Should use this technique:
	// https://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetKernighan
	for (i = 0; i < 64; i++) {
		valid_rows += ((tilde_header->Valid >> i) & 0x01);
	}

	row_offset = (uint32_t*) (tilde_header + 1);
	table_offset = (uint8_t*) row_offset;
	table_offset += sizeof (uint32_t) * valid_rows;

#define DOTNET_STRING_INDEX(Name) \
	index_sizes.string == 2 ? Name.Name_Short : Name.Name_Long

	string_offset = pe->data + metadata_root + streams->string->Offset;

	// Now walk again this time parsing out what we care about.
	for (bit_check = 0; bit_check < 64; bit_check++) {
		// If the Valid bit is not set for this table, skip it...
		if (!((tilde_header->Valid >> bit_check) & 0x01)) {
			continue;
		}

		// Make sure table_offset doesn't go crazy by inserting a large value
		// for num_rows. For example edc05e49dd3810be67942b983455fd43 sets a
		// large value for number of rows for the BIT_MODULE section.
		if (!fits_in_pe (pe, table_offset, 1)) {
			return;
		}

		num_rows = *(row_offset + matched_bits);

		// Those tables which exist, but that we don't care about must be
		// skipped.
		//
		// Sadly, given the dynamic sizes of some columns we can not have well
		// defined structures for all tables and use them accordingly. To deal
		// with this manually move the table_offset pointer by the appropriate
		// number of bytes as described in the documentation for each table.
		//
		// The table structures are documented in ECMA-335 Section II.22.

		switch (bit_check) {
		case BIT_MODULE:
			module_table = (PMODULE_TABLE) table_offset;
			name = pe_get_dotnet_string(pe,
					string_offset,
					DOTNET_STRING_INDEX(module_table->Name));
			if (name) {
				set_string (name, pe->object, "module_name");
			}
			table_offset += (2 + index_sizes.string + (index_sizes.guid * 3)) * num_rows;
			break;
		case BIT_TYPEREF:
			row_count = max_rows (4,
					rows.module,
					rows.moduleref,
					rows.assemblyref,
					rows.typeref);

			index_size = (row_count > (0xFFFF >> 0x02))? 4: 2;
			row_size = (index_size + (index_sizes.string * 2));
			typeref_row_size = row_size;
			typeref_ptr = table_offset;
			table_offset += row_size * num_rows;
			break;
		case BIT_TYPEDEF:
			row_count = max_rows (3, rows.typedef_, rows.typeref, rows.typespec);
			index_size = (row_count > (0xFFFF >> 0x02))? 4: 2;
			table_offset += (4 + (index_sizes.string * 2) + index_size +
					index_sizes.field + index_sizes.methoddef) * num_rows;
			break;
		case BIT_FIELDPTR:
			// This one is not documented in ECMA-335.
			table_offset += (index_sizes.field) * num_rows;
			break;
		case BIT_FIELD:
			table_offset += (2 + (index_sizes.string) + index_sizes.blob) * num_rows;
			break;
		case BIT_METHODDEFPTR:
			// This one is not documented in ECMA-335.
			table_offset += (index_sizes.methoddef) * num_rows;
			break;
		case BIT_METHODDEF:
			table_offset += (
					4 + 2 + 2 +
					index_sizes.string +
					index_sizes.blob +
					index_sizes.param) * num_rows;
			break;
		case BIT_PARAM:
			table_offset += (2 + 2 + index_sizes.string) * num_rows;
			break;
		case BIT_INTERFACEIMPL:
			row_count = max_rows (3,
					rows.typedef_,
					rows.typeref,
					rows.typespec);
			index_size = (row_count > (0xFFFF >> 0x02))? 4: 2;
			table_offset += (index_sizes.typedef_ + index_size) * num_rows;
			break;
		case BIT_MEMBERREF:
			row_count = max_rows (4,
					rows.methoddef,
					rows.moduleref,
					rows.typeref,
					rows.typespec);

			index_size = (row_count > (0xFFFF >> 0x03))? 4: 2;
			row_size = (index_size + index_sizes.string + index_sizes.blob);
			memberref_row_size = row_size;
			memberref_ptr = table_offset;
			table_offset += row_size * num_rows;
			break;
		case BIT_CONSTANT:
			row_count = max_rows(3, rows.param, rows.field, rows.property);
			index_size = (row_count > (0xFFFF >> 0x02))? 4: 2;
			// Using 'i' is insufficent since we may skip certain constants and
			// it would give an inaccurate count in that case.
			counter = 0;
			row_size = (1 + 1 + index_size + index_sizes.blob);
			row_ptr = table_offset;

			for (i = 0; i < num_rows; i++) {
				if (!fits_in_pe (pe, row_ptr, row_size)) {
					break;
				}

				constant_table = (PCONSTANT_TABLE) row_ptr;

				// Only look for constants of type string.
				if (constant_table->Type != ELEMENT_TYPE_STRING) {
					row_ptr += row_size;
					continue;
				}

				// Get the blob offset and pull it out of the blob table.
				blob_offset = ((uint8_t*) constant_table) + 2 + index_size;

				if (index_sizes.blob == 4) {
					blob_index = *(ut32*) blob_offset;
				} else {
					// Cast the value (index into blob table) to a 32bit value.
					blob_index = (ut32) (*(ut16*) blob_offset);
				}

				// Everything checks out. Make sure the index into the blob field
				// is valid (non-null and within range).
				blob_offset = pe->data + metadata_root + streams->blob->Offset + blob_index;

				blob_result = dotnet_parse_blob_entry (pe, blob_offset);

				if (blob_result.size == 0) {
					row_ptr += row_size;
					continue;
				}

				blob_length = blob_result.length;
				blob_offset += blob_result.size;

				// Quick sanity check to make sure the blob entry is within bounds.
				if (blob_offset + blob_length >= pe->data + pe->data_size) {
					row_ptr += row_size;
					continue;
				}
				set_sized_string (
						(char*) blob_offset,
						blob_result.length,
						pe->object,
						"constants[%i]",
						counter);
				counter++;
				row_ptr += row_size;
			}
			set_integer (counter, pe->object, "number_of_constants");
			table_offset += row_size * num_rows;
			break;
		case BIT_CUSTOMATTRIBUTE:
			// index_size is size of the parent column.
			row_count = max_rows(21,
					rows.methoddef,
					rows.field,
					rows.typeref,
					rows.typedef_,
					rows.param,
					rows.interfaceimpl,
					rows.memberref,
					rows.module,
					rows.property,
					rows.event,
					rows.standalonesig,
					rows.moduleref,
					rows.typespec,
					rows.assembly,
					rows.assemblyref,
					rows.file,
					rows.exportedtype,
					rows.manifestresource,
					rows.genericparam,
					rows.genericparamconstraint,
					rows.methodspec);

			index_size = (row_count > (0xFFFF >> 0x05)) ? 4: 2;

			// index_size2 is size of the type column.
			row_count = max_rows (2, rows.methoddef, rows.memberref);

			index_size2 = (row_count > (0xFFFF >> 0x03))? 4: 2;

			row_size = (index_size + index_size2 + index_sizes.blob);

			if (typeref_ptr && memberref_ptr) {
				row_ptr = table_offset;

				for (i = 0; i < num_rows; i++) {
					if (!fits_in_pe (pe, row_ptr, row_size)) {
						break;
					}

					// Check the Parent field.
					customattribute_table = (PCUSTOMATTRIBUTE_TABLE) row_ptr;

					if (index_size == 4) {
						// Low 5 bits tell us what this is an index into. Remaining bits
						// tell us the index value.
						// Parent must be an index into the Assembly (0x0E) table.
						if ((*(ut32*) customattribute_table & 0x1F) != 0x0E) {
							row_ptr += row_size;
							continue;
						}
					} else {
						// Low 5 bits tell us what this is an index into. Remaining bits
						// tell us the index value.
						// Parent must be an index into the Assembly (0x0E) table.
						if ((*(ut16*) customattribute_table & 0x1F) != 0x0E) {
							row_ptr += row_size;
							continue;
						}
					}

					// Check the Type field.
					customattribute_table = (PCUSTOMATTRIBUTE_TABLE) \
								(row_ptr + index_size);

					if (index_size2 == 4) {
						// Low 3 bits tell us what this is an index into. Remaining bits
						// tell us the index value. Only values 2 and 3 are defined.
						// Type must be an index into the MemberRef table.
						if ((*(ut32*) customattribute_table & 0x07) != 0x03) {
							row_ptr += row_size;
							continue;
						}

						type_index = *(ut32*) customattribute_table >> 3;
					} else {
						// Low 3 bits tell us what this is an index into. Remaining bits
						// tell us the index value. Only values 2 and 3 are defined.
						// Type must be an index into the MemberRef table.
						if ((*(ut16*) customattribute_table & 0x07) != 0x03) {
							row_ptr += row_size;
							continue;
						}

						// Cast the index to a 32bit value.
						type_index = (ut32) ((*(ut16*) customattribute_table >> 3));
					}

					if (type_index > 0) {
						type_index--;
					}

					// Now follow the Type index into the MemberRef table.
					memberref_row = memberref_ptr + (memberref_row_size * type_index);

					if (index_sizes.memberref == 4) {
						// Low 3 bits tell us what this is an index into. Remaining bits
						// tell us the index value. Class must be an index into the
						// TypeRef table.
						if ((*(ut32*) memberref_row & 0x07) != 0x01) {
							row_ptr += row_size;
							continue;
						}

						class_index = *(ut32*) memberref_row >> 3;
					} else {
						// Low 3 bits tell us what this is an index into. Remaining bits
						// tell us the index value. Class must be an index into the
						// TypeRef table.
						if ((*(ut16*) memberref_row & 0x07) != 0x01)
						{
							row_ptr += row_size;
							continue;
						}

						// Cast the index to a 32bit value.
						class_index = (ut32) (*(ut16*) memberref_row >> 3);
					}

					if (class_index > 0) {
						class_index--;
					}

					// Now follow the Class index into the TypeRef table.
					typeref_row = typeref_ptr + (typeref_row_size * class_index);

					// Skip over the ResolutionScope and check the Name field,
					// which is an index into the Strings heap.
					row_count = max_rows(4,
							rows.module,
							rows.moduleref,
							rows.assemblyref,
							rows.typeref);

					if (row_count > (0xFFFF >> 0x02)) {
						typeref_row += 4;
					} else {
						typeref_row += 2;
					}

					if (index_sizes.string == 4) {
						name = pe_get_dotnet_string(
								pe, string_offset, *(ut32*) typeref_row);
					} else {
						name = pe_get_dotnet_string(
								pe, string_offset, *(ut16*) typeref_row);
					}

					if (name && strncmp (name, "GuidAttribute", 13) != 0) {
						row_ptr += row_size;
						continue;
					}

					// Get the Value field.
					customattribute_table = (PCUSTOMATTRIBUTE_TABLE) \
								(row_ptr + index_size + index_size2);

					if (index_sizes.blob == 4) {
						blob_index = *(ut32*) customattribute_table;
					} else {
						// Cast the value (index into blob table) to a 32bit value.
						blob_index = (ut32) (*(ut16*) customattribute_table);
					}

					// Everything checks out. Make sure the index into the blob field
					// is valid (non-null and within range).
					blob_offset = pe->data + metadata_root + streams->blob->Offset + blob_index;

					// If index into blob is 0 or past the end of the blob stream, skip
					// it. We don't know the size of the blob entry yet because that is
					// encoded in the start.
					if (blob_index == 0x00 || blob_offset >= pe->data + pe->data_size) {
						row_ptr += row_size;
						continue;
					}

					blob_result = dotnet_parse_blob_entry(pe, blob_offset);

					if (blob_result.size == 0) {
						row_ptr += row_size;
						continue;
					}

					blob_length = blob_result.length;
					blob_offset += blob_result.size;

					// Quick sanity check to make sure the blob entry is within bounds.
					if (blob_offset + blob_length >= pe->data + pe->data_size) {
						row_ptr += row_size;
						continue;
					}

					// Custom attributes MUST have a 16 bit prolog of 0x0001
					if (*(ut16*) blob_offset != 0x0001) {
						row_ptr += row_size;
						continue;
					}

					// The next byte is the length of the string.
					blob_offset += 2;

					if (blob_offset + *blob_offset >= pe->data + pe->data_size) {
						row_ptr += row_size;
						continue;
					}

					blob_offset += 1;

					if (*blob_offset == 0xFF || *blob_offset == 0x00) {
						typelib[0] = '\0';
					} else {
						strncpy (typelib, (char*) blob_offset, MAX_TYPELIB_SIZE);
						typelib[MAX_TYPELIB_SIZE] = '\0';
					}
					set_string (typelib, pe->object, "typelib");
					row_ptr += row_size;
				}
			}
			table_offset += row_size * num_rows;
			break;
		case BIT_FIELDMARSHAL:
			row_count = max_rows(2, rows.field, rows.param);
			index_size = (row_count > (0xFFFF >> 0x01))? 4: 2;
			table_offset += (index_size + index_sizes.blob) * num_rows;
			break;

		case BIT_DECLSECURITY:
			row_count = max_rows (3, rows.typedef_, rows.methoddef, rows.assembly);
			index_size = (row_count > (0xFFFF >> 0x02))? 4: 2;
			table_offset += (2 + index_size + index_sizes.blob) * num_rows;
			break;
		case BIT_CLASSLAYOUT:
			table_offset += (2 + 4 + index_sizes.typedef_) * num_rows;
			break;
		case BIT_FIELDLAYOUT:
			table_offset += (4 + index_sizes.field) * num_rows;
			break;
		case BIT_STANDALONESIG:
			table_offset += (index_sizes.blob) * num_rows;
			break;
		case BIT_EVENTMAP:
			table_offset += (index_sizes.typedef_ + index_sizes.event) * num_rows;
			break;
		case BIT_EVENTPTR:
			// This one is not documented in ECMA-335.
			table_offset += (index_sizes.event) * num_rows;
			break;
		case BIT_EVENT:
			row_count = max_rows (3, rows.typedef_, rows.typeref, rows.typespec);
			index_size = (row_count > (0xFFFF >> 0x02))? 4: 2;
			table_offset += (2 + index_sizes.string + index_size) * num_rows;
			break;
		case BIT_PROPERTYMAP:
			table_offset += (index_sizes.typedef_ + index_sizes.property) * num_rows;
			break;
		case BIT_PROPERTYPTR:
			// This one is not documented in ECMA-335.
			table_offset += (index_sizes.property) * num_rows;
			break;
		case BIT_PROPERTY:
			table_offset += (2 + index_sizes.string + index_sizes.blob) * num_rows;
			break;
		case BIT_METHODSEMANTICS:
			row_count = max_rows (2, rows.event, rows.property);
			index_size = (row_count > (0xFFFF >> 0x01))? 4: 2;
			table_offset += (2 + index_sizes.methoddef + index_size) * num_rows;
			break;
		case BIT_METHODIMPL:
			row_count = max_rows (2, rows.methoddef, rows.memberref);
			index_size = (row_count > (0xFFFF >> 0x01))? 4: 2;
			table_offset += (index_sizes.typedef_ + (index_size * 2)) * num_rows;
			break;
		case BIT_MODULEREF:
			row_ptr = table_offset;

			// Can't use 'i' here because we only set the string if it is not
			// NULL. Instead use 'counter'.
			counter = 0;

			for (i = 0; i < num_rows; i++) {
				moduleref_table = (PMODULEREF_TABLE) row_ptr;
				name = pe_get_dotnet_string (pe, string_offset,
						DOTNET_STRING_INDEX(moduleref_table->Name));
				if (name) {
					set_string (name, pe->object, "modulerefs[%i]", counter);
					counter++;
				}
				row_ptr += index_sizes.string;
			}
			set_integer (counter, pe->object, "number_of_modulerefs");
			table_offset += (index_sizes.string) * num_rows;
			break;
		case BIT_TYPESPEC:
			table_offset += (index_sizes.blob) * num_rows;
			break;
		case BIT_IMPLMAP:
			row_count = max_rows(2, rows.field, rows.methoddef);
			index_size = (row_count > (0xFFFF >> 0x01))? 4: 2;
			table_offset += (2 + index_size + index_sizes.string +
					index_sizes.moduleref) * num_rows;
			break;
		case BIT_FIELDRVA:
			table_offset += (4 + index_sizes.field) * num_rows;
			break;
		case BIT_ENCLOG:
			table_offset += (4 + 4) * num_rows;
			break;
		case BIT_ENCMAP:
			table_offset += (4) * num_rows;
			break;
		case BIT_ASSEMBLY:
			row_size = (4 + 2 + 2 + 2 + 2 + 4 + index_sizes.blob +
					(index_sizes.string * 2));
			if (!fits_in_pe (pe, table_offset, row_size)) {
				break;
			}
			row_ptr = table_offset;
			assembly_table = (PASSEMBLY_TABLE) table_offset;
			set_integer (assembly_table->MajorVersion,
					pe->object, "assembly.version.major");
			set_integer (assembly_table->MinorVersion,
					pe->object, "assembly.version.minor");
			set_integer (assembly_table->BuildNumber,
					pe->object, "assembly.version.build_number");
			set_integer (assembly_table->RevisionNumber,
					pe->object, "assembly.version.revision_number");

			// Can't use assembly_table here because the PublicKey comes before
			// Name and is a variable length field.

			if (index_sizes.string == 4) {
				name = pe_get_dotnet_string (
						pe,
						string_offset,
						*(ut32*) (
							row_ptr + 4 + 2 + 2 + 2 + 2 + 4 +
							index_sizes.blob));
			} else {
				name = pe_get_dotnet_string(
						pe,
						string_offset,
						*(ut16*) (
							row_ptr + 4 + 2 + 2 + 2 + 2 + 4 +
							index_sizes.blob));
			}

			if (name) {
				set_string (name, pe->object, "assembly.name");
			}
			// Culture comes after Name.
			if (index_sizes.string == 4) {
				name = pe_get_dotnet_string (
						pe,
						string_offset,
						*(ut32*) (
							row_ptr + 4 + 2 + 2 + 2 + 2 + 4 +
							index_sizes.blob +
							index_sizes.string));
			} else {
				name = pe_get_dotnet_string (
						pe,
						string_offset,
						*(ut16*) (
							row_ptr + 4 + 2 + 2 + 2 + 2 + 4 +
							index_sizes.blob +
							index_sizes.string));
			}

			// Sometimes it will be a zero length string. This is technically
			// against the specification but happens from time to time.
			if (R_STR_ISNOTEMPTY (name)) {
				set_string (name, pe->object, "assembly.culture");
			}
			table_offset += row_size * num_rows;
			break;
		case BIT_ASSEMBLYPROCESSOR:
			table_offset += (4) * num_rows;
			break;
		case BIT_ASSEMBLYOS:
			table_offset += (4 + 4 + 4) * num_rows;
			break;
		case BIT_ASSEMBLYREF:
			row_size = (2 + 2 + 2 + 2 + 4 + (index_sizes.blob * 2) + (index_sizes.string * 2));
			row_ptr = table_offset;

			for (i = 0; i < num_rows; i++) {
				if (!fits_in_pe (pe, table_offset, row_size)) {
					break;
				}
				assemblyref_table = (PASSEMBLYREF_TABLE) row_ptr;

				set_integer(assemblyref_table->MajorVersion,
						pe->object, "assembly_refs[%i].version.major", i);
				set_integer(assemblyref_table->MinorVersion,
						pe->object, "assembly_refs[%i].version.minor", i);
				set_integer(assemblyref_table->BuildNumber,
						pe->object, "assembly_refs[%i].version.build_number", i);
				set_integer(assemblyref_table->RevisionNumber,
						pe->object, "assembly_refs[%i].version.revision_number", i);

				blob_offset = pe->data + metadata_root + streams->blob->Offset;

				if (index_sizes.blob == 4) {
					blob_offset += assemblyref_table->PublicKeyOrToken.PublicKeyOrToken_Long;
				} else {
					blob_offset += assemblyref_table->PublicKeyOrToken.PublicKeyOrToken_Short;
				}

				blob_result = dotnet_parse_blob_entry(pe, blob_offset);

				if (blob_result.size == 0 || !fits_in_pe (pe, blob_offset, blob_result.length)) {
					row_ptr += row_size;
					continue;
				}

				// Avoid empty strings.
				if (blob_result.length > 0) {
					blob_offset += blob_result.size;
					set_sized_string((char*) blob_offset,
							blob_result.length, pe->object,
							"assembly_refs[%i].public_key_or_token", i);
				}

				// Can't use assemblyref_table here because the PublicKey comes before
				// Name and is a variable length field.

				if (index_sizes.string == 4) {
					name = pe_get_dotnet_string (pe,
							string_offset,
							*(ut32*) (row_ptr + 2 + 2 + 2 + 2 + 4 + index_sizes.blob));
				} else {
					name = pe_get_dotnet_string(pe,
							string_offset,
							*(ut16*) (row_ptr + 2 + 2 + 2 + 2 + 4 + index_sizes.blob));
				}
				if (name) {
					set_string (name, pe->object, "assembly_refs[%i].name", i);
				}
				row_ptr += row_size;
			}
			set_integer (i, pe->object, "number_of_assembly_refs");
			table_offset += row_size * num_rows;
			break;
		case BIT_ASSEMBLYREFPROCESSOR:
			table_offset += (4 + index_sizes.assemblyrefprocessor) * num_rows;
			break;
		case BIT_ASSEMBLYREFOS:
			table_offset += (4 + 4 + 4 + index_sizes.assemblyref) * num_rows;
			break;
		case BIT_FILE:
			table_offset += (4 + index_sizes.string + index_sizes.blob) * num_rows;
			break;
		case BIT_EXPORTEDTYPE:
			row_count = max_rows(3, rows.file, rows.assemblyref, rows.exportedtype);
			index_size = (row_count > (0xFFFF >> 0x02))? 4: 2;
			table_offset += (4 + 4 + (index_sizes.string * 2) + index_size) * num_rows;
			break;
		case BIT_MANIFESTRESOURCE:
			// This is an Implementation coded index with no 3rd bit specified.
			row_count = max_rows(2, rows.file, rows.assemblyref);
			index_size = (row_count > (0xFFFF >> 0x02))? 4: 2;
			row_size = (4 + 4 + index_sizes.string + index_size);

			// Using 'i' is insufficent since we may skip certain resources and
			// it would give an inaccurate count in that case.
			counter = 0;
			row_ptr = table_offset;
			// First ut32 is the offset.
			for (i = 0; i < num_rows; i++) {
				if (!fits_in_pe (pe, row_ptr, row_size)) {
					break;
				}

				manifestresource_table = (PMANIFESTRESOURCE_TABLE) row_ptr;
				resource_offset = manifestresource_table->Offset;

				// Only set offset if it is in this file (implementation != 0).
				// Can't use manifestresource_table here because the Name and
				// Implementation fields are variable size.
				if (index_size == 4) {
					implementation = *(ut32*) (row_ptr + 4 + 4 + index_sizes.string);
				} else {
					implementation = *(ut16*) (row_ptr + 4 + 4 + index_sizes.string);
				}
				if (implementation != 0) {
					row_ptr += row_size;
					continue;
				}

				if (!fits_in_pe (pe, pe->data + resource_base + resource_offset, sizeof (ut32))) {
					row_ptr += row_size;
					continue;
				}

				resource_size = *(ut32*)(pe->data + resource_base + resource_offset);

				if (!fits_in_pe(
							pe, pe->data + resource_base +
							resource_offset,
							resource_size))
				{
					row_ptr += row_size;
					continue;
				}

				// Add 4 to skip the size.
				set_integer (resource_base + resource_offset + 4,
						pe->object, "resources[%i].offset", counter);

				set_integer (resource_size,
						pe->object, "resources[%i].length", counter);

				name = pe_get_dotnet_string (pe, string_offset,
						DOTNET_STRING_INDEX(manifestresource_table->Name));
				if (name) {
					set_string (name, pe->object, "resources[%i].name", counter);
				}
				row_ptr += row_size;
				counter++;
			}

			set_integer(counter, pe->object, "number_of_resources");

			table_offset += row_size * num_rows;
			break;
		case BIT_NESTEDCLASS:
			table_offset += (index_sizes.typedef_ * 2) * num_rows;
			break;
		case BIT_GENERICPARAM:
			row_count = max_rows(2, rows.typedef_, rows.methoddef);
			index_size = (row_count > (0xFFFF >> 0x01))? 4: 2;
			table_offset += (2 + 2 + index_size + index_sizes.string) * num_rows;
			break;
		case BIT_METHODSPEC:
			row_count = max_rows(2, rows.methoddef, rows.memberref);
			index_size = (row_count > (0xFFFF >> 0x01))? 4: 2;
			table_offset += (index_size + index_sizes.blob) * num_rows;
			break;
		case BIT_GENERICPARAMCONSTRAINT:
			row_count = max_rows(3, rows.typedef_, rows.typeref, rows.typespec);
			index_size = (row_count > (0xFFFF >> 0x02))? 4: 2;
			table_offset += (index_sizes.genericparam + index_size) * num_rows;
			break;
		default:
			//printf("Unknown bit: %i\n", bit_check);
			return;
		}

		matched_bits++;
	}
}


// Parsing the #~ stream is done in two parts. The first part (this function)
// parses enough of the Stream to provide context for the second pass. In
// particular it is collecting the number of rows for each of the tables. The
// second part parses the actual tables of interest.

static void dotnet_parse_tilde(PE* pe, ut64 metadata_root, PCLI_HEADER cli_header, PSTREAMS streams) {
	PTILDE_HEADER tilde_header;
	ut64 resource_base;
	uint32_t* row_offset = NULL;

	int bit_check;

	// This is used as an offset into the rows and tables. For every bit set in
	// Valid this will be incremented. This is because the bit position doesn't
	// matter, just the number of bits that are set, when determining how many
	// rows and what the table structure is.
	int matched_bits = 0;

	// We need to know the number of rows for some tables, because they are
	// indexed into. The index will be either 2 or 4 bytes, depending upon the
	// number of rows being indexed into.
	ROWS rows;
	INDEX_SIZES index_sizes;

	// Default all rows to 0. They will be set to actual values later on, if
	// they exist in the file.
	memset (&rows, '\0', sizeof (ROWS));

	// Default index sizes are 2. Will be bumped to 4 if necessary.
	memset (&index_sizes, 2, sizeof (index_sizes));

	tilde_header = (PTILDE_HEADER) (
			pe->data +
			metadata_root +
			streams->tilde->Offset);

	if (!struct_fits_in_pe(pe, tilde_header, TILDE_HEADER))
		return;

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

	// Immediately after the tilde header is an array of 32bit values which
	// indicate how many rows are in each table. The tables are immediately
	// after the rows array.
	//
	// Save the row offset.
	row_offset = (uint32_t*) (tilde_header + 1);

	// Walk all the bits first because we need to know the number of rows for
	// some tables in order to parse others. In particular this applies to
	// coded indexes, which are documented in ECMA-335 II.24.2.6.
	for (bit_check = 0; bit_check < 64; bit_check++) {
		if (!((tilde_header->Valid >> bit_check) & 0x01)) {
			continue;
		}

#define ROW_CHECK(name) \
		if (fits_in_pe(pe, row_offset, (matched_bits + 1) * sizeof (uint32_t))) \
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
		case BIT_ASSEMBLYREFPROCESSOR:
			ROW_CHECK_WITH_INDEX (assemblyrefprocessor);
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

	// This is used when parsing the MANIFEST RESOURCE table.
	resource_base = pe_rva_to_offset(pe, cli_header->Resources.VirtualAddress);

	dotnet_parse_tilde_2(
			pe,
			tilde_header,
			resource_base,
			metadata_root,
			rows,
			index_sizes,
			streams);
}

#if 0
        pe->data = block_data;
        pe->data_size = block->size;
        pe->object = module_object;
        pe->header = pe_header;

        module_object->data = pe;

        dotnet_parse_com(pe, block->base);
#endif

void dotnet_parse_com(PE* pe, ut64 baddr) {
	R_PIMAGE_DATA_DIRECTORY directory;
	PCLI_HEADER cli_header;
	PNET_METADATA metadata;
	ut64 metadata_root;
	char* end;
	STREAMS headers;
	ut16 num_streams;

	directory = pe_get_directory_entry (pe, PE_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
	st64 offset = pe_rva_to_offset (pe, directory->VirtualAddress);

	if (offset < 0 || !struct_fits_in_pe (pe, pe->data + offset, CLI_HEADER)) {
		return;
	}

	cli_header = (PCLI_HEADER) (pe->data + offset);

	offset = metadata_root = pe_rva_to_offset (pe, cli_header->MetaData.VirtualAddress);

	if (!struct_fits_in_pe (pe, pe->data + offset, NET_METADATA)) {
		return;
	}

	metadata = (PNET_METADATA) (pe->data + offset);

	if (metadata->Magic != NET_METADATA_MAGIC) {
		return;
	}

	// Version length must be between 1 and 255, and be a multiple of 4.
	// Also make sure it fits in pe.
	if (metadata->Length == 0 ||
			metadata->Length > 255 ||
			metadata->Length % 4 != 0 ||
			!fits_in_pe (pe, pe->data + offset, metadata->Length))
	{
		return;
	}

	// The length includes the NULL terminator and is rounded up to a multiple of
	// 4. We need to exclude the terminator and the padding, so search for the
	// first NULL byte.
	end = (char*) r_mem_mem ((void*) metadata->Version, metadata->Length, (void*)"\0", 1);
	if (end) {
		set_sized_string (metadata->Version,
			(end - metadata->Version),
			pe->object, "version");
	}

	// The metadata structure has some variable length records after the version.
	// We must manually parse things from here on out.
	//
	// Flags are 2 bytes (always 0).
	offset += sizeof (NET_METADATA) + metadata->Length + 2;

	// 2 bytes for Streams.
	if (!fits_in_pe (pe, pe->data + offset, 2)) {
		return;
	}

	num_streams = (ut16) *(pe->data + offset);
	offset += 2;

	headers = dotnet_parse_stream_headers(pe, offset, metadata_root, num_streams);

	if (headers.guid) {
		dotnet_parse_guid(pe, metadata_root, headers.guid);
	}

	// Parse the #~ stream, which includes various tables of interest.
	// These tables reference the blob and string streams, so we need to ensure
	// those are not NULL also.
	if (headers.tilde && headers.string && headers.blob) {
		dotnet_parse_tilde (pe, metadata_root, cli_header, &headers);
	}

	if (headers.us) {
		dotnet_parse_us (pe, metadata_root, headers.us);
	}
}

// entrypoint
void dotnet_parse(const ut8 *buf, int size, ut64 baddr) {
	PE pe = { buf, (ut32)size, NULL};
	dotnet_parse_com (&pe, baddr);
}
