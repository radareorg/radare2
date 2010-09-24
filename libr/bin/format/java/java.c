// XXX this is dupped in r_asm and r_bin :O

/*
 * Copyright (C) 2007, 2008, 2009, 2010
 *       pancake <youterm.com>, nibble <develsec.org>
 *
 * radare is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * radare is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with radare; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdarg.h>
#include <unistd.h>
#include "java.h"
#include <r_types.h>
#include <r_util.h>


static struct constant_t {
	char *name;
	int tag;
	int len;
} constants[] = {
	{ "Class", 7, 2 }, // 2 name_idx
	{ "FieldRef", 9, 4 }, // 2 class idx, 2 name/type_idx
	{ "MethodRef", 10, 4 }, // 2 class idx, 2 name/type_idx
	{ "InterfaceMethodRef", 11, 4 }, // 2 class idx, 2 name/type_idx
	{ "String", 8, 2 }, // 2 string_idx
	{ "Integer", 3, 4 }, // 4 bytes
	{ "Float", 4, 4 }, // 4 bytes
	{ "Long", 5, 8 }, // 4 high 4 low
	{ "Double", 6, 8 }, // 4 high 4 low
	{ "NameAndType", 12, 4 }, // 4 high 4 low
	{ "Utf8", 1, 2 }, // 2 bytes = length, N bytes string
	{ NULL, 0, 0 }
};

static struct r_bin_java_cp_item_t cp_null_item; // NOTE: must be initialized for safe use

static unsigned short read_short(struct r_bin_java_obj_t *bin) {
	unsigned short sh=0;

	r_buf_read_at(bin->b, R_BUF_CUR, (ut8*)&sh, 2);
	return R_BIN_JAVA_SWAPUSHORT(sh);
}

static struct r_bin_java_cp_item_t* get_cp(struct r_bin_java_obj_t *bin, unsigned short i) {
	if (i<0||i>bin->cf.cp_count)
		return &cp_null_item;
	return &bin->cp_items[i];
}

static int attributes_walk(struct r_bin_java_obj_t *bin, struct r_bin_java_attr_t *attr, int sz2, int fields) {
	char buf[0xffff+1];
	int sz3, sz4;
	int j=0,k;
	char *name;

	for(j=0;j<sz2;j++) {
		if (r_buf_read_at(bin->b, R_BUF_CUR, (ut8*)buf, 6) != 6) {
			eprintf ("Cannot read 6 bytes in class file\n");
			return R_FALSE;
		}
		attr->name_idx = R_BIN_JAVA_USHORT(buf,0);
		attr->name = strdup((get_cp(bin, attr->name_idx-1))->value);
		name = (get_cp(bin, attr->name_idx-1))->value;//cp_items[R_BIN_JAVA_USHORT(buf,0)-1].value;
		IFDBG printf("   %2d: Name Index: %d (%s)\n", j, attr->name_idx, name);
		// TODO add comment with constant pool index
		sz3 = R_BIN_JAVA_UINT(buf, 2);
		if (fields) {
			attr->type = R_BIN_JAVA_TYPE_FIELD;
			IFDBG printf("FIELD\n");
		} else if (sz3 > 0){
			attr->length = sz3;
			IFDBG printf("     Length: %d\n", sz3); //R_BIN_JAVA_UINT(buf, 2));
			if (!name) {
				IFDBG printf("**ERROR ** Cannot identify attribute name into constant pool\n");
				continue;
			}
			if (!strcmp(name, "Code")) {
				attr->type = R_BIN_JAVA_TYPE_CODE;
				r_buf_read_at(bin->b, R_BUF_CUR, (ut8*)buf, 8);

				attr->info.code.max_stack = R_BIN_JAVA_USHORT(buf, 0);
				IFDBG printf("      Max Stack: %d\n", attr->info.code.max_stack);
				attr->info.code.max_locals = R_BIN_JAVA_USHORT(buf, 2);
				IFDBG printf("      Max Locals: %d\n", attr->info.code.max_locals);
				attr->info.code.code_length = R_BIN_JAVA_UINT(buf, 4);
				IFDBG printf("      Code Length: %d\n", attr->info.code.code_length);
				attr->info.code.code_offset = (ut64)bin->b->cur;
				IFDBG printf("      Code At Offset: 0x%08"PFMT64x"\n", (ut64)attr->info.code.code_offset);

				r_buf_read_at(bin->b, R_BUF_CUR, (ut8*)buf, R_BIN_JAVA_UINT(buf, 4)); // READ CODE
				sz4 = read_short(bin);
				attr->info.code.exception_table_length = sz4;
				IFDBG printf("      Exception table length: %d\n", attr->info.code.exception_table_length);
				for(k=0;k<sz4;k++) {
					r_buf_read_at(bin->b, R_BUF_CUR, (ut8*)buf, 8);
					attr->info.code.start_pc = R_BIN_JAVA_USHORT(buf,0);
					IFDBG printf("       start_pc:   0x%04x\n", attr->info.code.start_pc);
					attr->info.code.end_pc = R_BIN_JAVA_USHORT(buf,2);
					IFDBG printf("       end_pc:     0x%04x\n", attr->info.code.end_pc);
					attr->info.code.handler_pc = R_BIN_JAVA_USHORT(buf,4);
					IFDBG printf("       handler_pc: 0x%04x\n", attr->info.code.handler_pc);
					attr->info.code.catch_type = R_BIN_JAVA_USHORT(buf,6);
					IFDBG printf("       catch_type: %d\n", attr->info.code.catch_type);
				}
				sz4 = (unsigned int)read_short(bin);
				IFDBG printf("      code Attributes_count: %d\n", sz4);

				if (sz4>0)
					attr->attributes = malloc(sz4 * sizeof(struct r_bin_java_attr_t));
					attributes_walk(bin, attr->attributes, sz4, fields);
			} else
			if (!strcmp(name, "LineNumberTable")) {
				attr->type = R_BIN_JAVA_TYPE_LINENUM;
				sz4 = (unsigned int)read_short(bin);
				attr->info.linenum.table_length = sz4;
				IFDBG printf("     Table Length: %d\n", attr->info.linenum.table_length);
				for(k=0;k<sz4;k++) {
					r_buf_read_at(bin->b, R_BUF_CUR, (ut8*)buf, 4);
					attr->info.linenum.start_pc = R_BIN_JAVA_USHORT(buf, 0);
					IFDBG printf("     %2d: start_pc:    0x%04x\n", k, attr->info.linenum.start_pc);
					attr->info.linenum.line_number = R_BIN_JAVA_USHORT(buf, 2);
					IFDBG printf("         line_number: %d\n", attr->info.linenum.line_number);
				}
			} else
			if (!strcmp(name, "ConstantValue")) {
				attr->type = R_BIN_JAVA_TYPE_CONST;
				r_buf_read_at(bin->b, R_BUF_CUR, (ut8*)buf, 2);
	#if 0
				printf("     Name Index: %d\n", R_BIN_JAVA_USHORT(buf, 0)); // %s\n", R_BIN_JAVA_USHORT(buf, 0), cp_items[R_BIN_JAVA_USHORT(buf,0)-1].value);
				printf("     AttributeLength: %d\n", R_BIN_JAVA_UINT(buf, 2));
	#endif
				attr->info.const_value_idx = R_BIN_JAVA_USHORT(buf, 0);
				IFDBG printf("     ConstValueIndex: %d\n", attr->info.const_value_idx);
			} else {
				IFDBG fprintf(stderr, "** ERROR ** Unknown section '%s'\n", name);
				return R_FALSE;
			}
		}
	}
	return R_TRUE;
}

static int javasm_init(struct r_bin_java_obj_t *bin)
{
	unsigned short sz, sz2;
	char buf[0x9999];
	int i,j;

	/* Initialize structs */
	bin->cp_items = NULL;
	bin->fields = NULL;
	bin->methods = NULL;

	/* Initialize cp_null_item */
	cp_null_item.tag = -1;
	strcpy(cp_null_item.name, "(null)");
	cp_null_item.value = strdup("(null)");

	/* start parsing */
	r_buf_read_at(bin->b, R_BUF_CUR, (ut8*)&bin->cf, 10); //sizeof(struct r_bin_java_classfile_t), 1, bin->fd);
	if (memcmp(bin->cf.cafebabe, "\xCA\xFE\xBA\xBE", 4)) {
		fprintf(stderr, "Invalid header\n");
		return R_FALSE;
	}

	bin->cf.cp_count = R_BIN_JAVA_SWAPUSHORT(bin->cf.cp_count);
	if (bin->cf.major[0]==bin->cf.major[1] && bin->cf.major[0]==0) {
		fprintf(stderr, "This is a MachO\n");
		return R_FALSE;
	}
	bin->cf.cp_count--;

	IFDBG printf("ConstantPoolCount %d\n", bin->cf.cp_count);
	bin->cp_items = malloc(sizeof(struct r_bin_java_cp_item_t)*(bin->cf.cp_count+1));
	for(i=0;i<bin->cf.cp_count;i++) {
		struct constant_t *c;

		r_buf_read_at(bin->b, R_BUF_CUR, (ut8*)buf, 1);

		c = NULL;
		for(j=0;constants[j].name;j++) {
			if (constants[j].tag == buf[0])  {
				c = &constants[j];
				break;
			}
		}
		if (c == NULL) {
			fprintf(stderr, "Invalid tag '%d' at offset 0x%08"PFMT64x"\n",
				buf[0], (ut64)bin->b->cur);
			return R_FALSE;
		}
		IFDBG printf(" %3d %s: ", i+1, c->name);

		/* store constant pool item */
		strcpy(bin->cp_items[i].name, c->name);
		bin->cp_items[i].ord = i+1;
		bin->cp_items[i].tag = c->tag;
		bin->cp_items[i].value = NULL; // no string by default
		bin->cp_items[i].off = bin->b->cur-1;

		/* read bytes */
		switch(c->tag) {
		case 1: // Utf8 string
			r_buf_read_at(bin->b, R_BUF_CUR, (ut8*)buf, 2);
			sz = R_BIN_JAVA_USHORT (buf, 0);
			bin->cp_items[i].length = sz;
			bin->cp_items[i].off += 3;
			if (sz > 0)
				r_buf_read_at(bin->b, R_BUF_CUR, (ut8*)buf, sz);
			buf[sz] = '\0';
			break;
		default:
			r_buf_read_at(bin->b, R_BUF_CUR, (ut8*)buf, c->len);
		}

		memcpy(bin->cp_items[i].bytes, buf, 5);

		/* parse value */
		switch (c->tag) {
		case 1:
			IFDBG printf("%s\n", buf);
			bin->cp_items[i].value = strdup(buf);
			break;
		case 5:
		case 6:
			i += 2;
			break;
		case 7:
			IFDBG printf("%d\n", R_BIN_JAVA_USHORT(buf,0));
			break;
		case 8:
			IFDBG printf("string ptr %d\n", R_BIN_JAVA_USHORT(buf, 0));
			break;
		case 9:
		case 11:
		case 10: // METHOD REF
			IFDBG printf("class = %d, ", R_BIN_JAVA_USHORT(buf,0));
			IFDBG printf("name_type = %d\n", R_BIN_JAVA_USHORT(buf,2));
			break;
		case 12:
			IFDBG printf("name = %d, ", R_BIN_JAVA_USHORT(buf,0));
			IFDBG printf("descriptor = %d\n", R_BIN_JAVA_USHORT(buf,2));
			break;
		default:
			printf("%d\n", R_BIN_JAVA_UINT(buf, 40));
		}
	}

	r_buf_read_at(bin->b, R_BUF_CUR, (ut8*)&bin->cf2, sizeof(struct r_bin_java_classfile2_t));
	IFDBG printf("Access flags: 0x%04x\n", bin->cf2.access_flags);
	bin->cf2.this_class = R_BIN_JAVA_SWAPUSHORT(bin->cf2.this_class);
	IFDBG printf("This class: %d\n", bin->cf2.this_class);
	//printf("This class: %d (%s)\n", R_BIN_JAVA_SWAPUSHORT(bin->cf2.this_class), bin->cp_items[R_BIN_JAVA_SWAPUSHORT(bin->cf2.this_class)-1].value); // XXX this is a double pointer !!1
	//printf("Super class: %d (%s)\n", R_BIN_JAVA_SWAPUSHORT(bin->cf2.super_class), bin->cp_items[R_BIN_JAVA_SWAPUSHORT(bin->cf2.super_class)-1].value);
	sz = read_short(bin);

	/* TODO: intefaces*/
	IFDBG printf("Interfaces count: %d\n", sz);
	if (sz>0) {
		r_buf_read_at(bin->b, R_BUF_CUR, (ut8*)buf, sz*2);
		sz = read_short(bin);
		for(i=0;i<sz;i++) {
			fprintf(stderr, "Interfaces: TODO\n");
		}
	}

	sz = read_short(bin);
	bin->fields_count = sz;
	IFDBG printf("Fields count: %d\n", sz);
	if (sz>0) {
		bin->fields = malloc(sz * sizeof(struct r_bin_java_fm_t));
		for (i=0;i<sz;i++) {
			r_buf_read_at(bin->b, R_BUF_CUR, (ut8*)buf, 8);
			bin->fields[i].flags = R_BIN_JAVA_USHORT(buf, 0);
			IFDBG printf("%2d: Access Flags: %d\n", i, bin->fields[i].flags);
			bin->fields[i].name_idx = R_BIN_JAVA_USHORT(buf, 2);
			bin->fields[i].name = strdup((get_cp(bin, R_BIN_JAVA_USHORT(buf,2)-1))->value);
			IFDBG printf("    Name Index: %d (%s)\n", bin->fields[i].name_idx, bin->fields[i].name);
			bin->fields[i].descriptor_idx = R_BIN_JAVA_USHORT(buf, 4);
			bin->fields[i].descriptor = NULL;
			IFDBG printf("    Descriptor Index: %d\n", bin->fields[i].descriptor_idx); //, bin->cp_items[R_BIN_JAVA_USHORT(buf, 4)-1].value);
			sz2 = R_BIN_JAVA_USHORT(buf, 6);
			bin->fields[i].attr_count = sz2;
			IFDBG printf("    field Attributes Count: %d\n", sz2);
			if (sz2 > 0) {
				bin->fields[i].attributes = malloc(sz2 * sizeof(struct r_bin_java_attr_t));
				for(j=0;j<sz2;j++)
					attributes_walk(bin, &bin->fields[i].attributes[j], sz2, 1);
			}
		}
	}

	sz = read_short(bin);
	bin->methods_count = sz;
	IFDBG printf("Methods count: %d\n", sz);
	if (sz>0) {
		bin->methods = malloc(sz * sizeof(struct r_bin_java_fm_t));
		for (i=0;i<sz;i++) {
			r_buf_read_at(bin->b, R_BUF_CUR, (ut8*)buf, 8);

			bin->methods[i].flags = R_BIN_JAVA_USHORT(buf, 0);
			IFDBG printf("%2d: Access Flags: %d\n", i, bin->methods[i].flags);
			bin->methods[i].name_idx = R_BIN_JAVA_USHORT(buf, 2);
			bin->methods[i].name = strdup((get_cp(bin, R_BIN_JAVA_USHORT(buf, 2)-1))->value);
			IFDBG printf("    Name Index: %d (%s)\n", bin->methods[i].name_idx, bin->methods[i].name);
			bin->methods[i].descriptor_idx = R_BIN_JAVA_USHORT(buf, 4);
			bin->methods[i].descriptor = strdup((get_cp(bin, R_BIN_JAVA_USHORT(buf, 4)-1))->value);
			IFDBG printf("    Descriptor Index: %d (%s)\n", bin->methods[i].descriptor_idx, bin->methods[i].descriptor);

			sz2 = R_BIN_JAVA_USHORT(buf, 6);
			bin->methods[i].attr_count = sz2;
			IFDBG printf("    method Attributes Count: %d\n", sz2);
			if (sz2 > 0) {
				bin->methods[i].attributes = malloc(sz2 * sizeof(struct r_bin_java_attr_t));
				for(j=0;j<sz2;j++)
					attributes_walk(bin, &bin->methods[i].attributes[j], sz2, 0);
			}
		}
	}
	
	return R_TRUE;
}

char* r_bin_java_get_version(struct r_bin_java_obj_t* bin)
{
	return r_str_dup_printf("0x%02x%02x 0x%02x%02x",
			bin->cf.major[1],bin->cf.major[0],
			bin->cf.minor[1],bin->cf.minor[0]);
}

ut64 r_bin_java_get_entrypoint(struct r_bin_java_obj_t* bin) {
	int i, j;
	for (i=0; i < bin->methods_count; i++)
		if (!strcmp(bin->methods[i].name, "<init>"))
			for (j=0; j < bin->methods[i].attr_count; j++)
				if (bin->methods[i].attributes[j].type == R_BIN_JAVA_TYPE_CODE)
					return (ut64)bin->methods[i].attributes->info.code.code_offset;
	return 0;
}

struct r_bin_java_sym_t* r_bin_java_get_symbols(struct r_bin_java_obj_t* bin) {
	struct r_bin_java_sym_t *symbols;
	int i, j, ctr = 0;

	if ((symbols = malloc((bin->methods_count + 1) * sizeof(struct r_bin_java_sym_t))) == NULL)
		return NULL;
	for (i=0; i < bin->methods_count; i++) {
		memcpy(symbols[ctr].name, bin->methods[i].name, R_BIN_JAVA_MAXSTR);
		symbols[ctr].name[R_BIN_JAVA_MAXSTR-1] = '\0';
		for (j=0; j < bin->methods[i].attr_count; j++)
			if (bin->methods[i].attributes[j].type == R_BIN_JAVA_TYPE_CODE) {
				symbols[ctr].offset = (ut64)bin->methods[i].attributes->info.code.code_offset;
				symbols[ctr].size = bin->methods[i].attributes->info.code.code_length;
				symbols[ctr].last = 0;
				ctr++;
			}
	}
	symbols[ctr].last = 1;
	return symbols;
}

struct r_bin_java_str_t* r_bin_java_get_strings(struct r_bin_java_obj_t* bin) {
	struct r_bin_java_str_t *strings = NULL;
	int i, ctr = 0;

	for(i=0;i<bin->cf.cp_count;i++) 
		if (bin->cp_items[i].tag == 1) {
			if ((strings = realloc(strings, (ctr + 1) * sizeof(struct r_bin_java_str_t))) == NULL)
				return NULL;
			strings[ctr].offset = (ut64)bin->cp_items[i].off;
			strings[ctr].ordinal = (ut64)bin->cp_items[i].ord;
			strings[ctr].size = (ut64)bin->cp_items[i].length;
			memcpy(strings[ctr].str, bin->cp_items[i].value, R_BIN_JAVA_MAXSTR);
			strings[ctr].last = 0;
			ctr++;
		}
	if (ctr) {
		if ((strings = realloc(strings, (ctr + 1) * sizeof(struct r_bin_java_str_t))) == NULL)
			return NULL;
		strings[ctr].last = 1;
	}
	return strings;
}

void* r_bin_java_free(struct r_bin_java_obj_t* bin) {
	if (!bin)
		return NULL;
	if (bin->cp_items)
		free(bin->cp_items);
	if (bin->fields)
		free(bin->fields);
	if (bin->methods)
		free(bin->methods);
	if (bin->b)
		r_buf_free(bin->b);
	free(bin);
	return NULL;
}

struct r_bin_java_obj_t* r_bin_java_new(const char* file) {
	struct r_bin_java_obj_t *bin;
	ut8 *buf;

	if (!(bin = malloc(sizeof(struct r_bin_java_obj_t))))
		return NULL;
	memset (bin, 0, sizeof (struct r_bin_java_obj_t));
	bin->file = file;
	if (!(buf = (ut8*)r_file_slurp(file, &bin->size))) 
		return r_bin_java_free(bin);
	bin->b = r_buf_new();
	if (!r_buf_set_bytes(bin->b, buf, bin->size))
		return r_bin_java_free(bin);
	free (buf);
	if (!javasm_init(bin))
		return r_bin_java_free(bin);
	return bin;
}

struct r_bin_java_obj_t* r_bin_java_new_buf(struct r_buf_t *buf) {
	struct r_bin_java_obj_t *bin;

	if (!(bin = malloc(sizeof(struct r_bin_java_obj_t))))
		return NULL;
	memset (bin, 0, sizeof (struct r_bin_java_obj_t));
	bin->b = buf;
	bin->size = buf->length;
	if (!javasm_init(bin))
		return r_bin_java_free(bin);
	return bin;
}
