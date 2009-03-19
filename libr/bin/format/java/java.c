/*
 * Copyright (C) 2007, 2008
 *       pancake <youterm.com>
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

static unsigned short read_short(int fd)
{
	unsigned short sh=0;

	read(fd, &sh, 2);//sizeof(unsigned short), 1, fd);
	return R_BIN_JAVA_SWAPUSHORT(sh);
}

static struct r_bin_java_cp_item_t* get_cp(struct r_bin_java_t *bin, unsigned short i)
{
	if (i<0||i>bin->cf.cp_count)
		return &cp_null_item;
	return &bin->cp_items[i];
}

static int attributes_walk(struct r_bin_java_t *bin, struct r_bin_java_attr_t *attr, int fd, int sz2, int fields)
{
	char buf[99999];
	int sz3, sz4;
	int j=0,k;
	char *name;

	for(j=0;j<sz2;j++) {
		read(fd, buf, 6);
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
				read(fd, buf, 8);

				attr->info.code.max_stack = R_BIN_JAVA_USHORT(buf, 0);
				IFDBG printf("      Max Stack: %d\n", attr->info.code.max_stack);
				attr->info.code.max_locals = R_BIN_JAVA_USHORT(buf, 2);
				IFDBG printf("      Max Locals: %d\n", attr->info.code.max_locals);
				attr->info.code.code_length = R_BIN_JAVA_UINT(buf, 4);
				IFDBG printf("      Code Length: %d\n", attr->info.code.code_length);
				attr->info.code.code_offset = (u64)lseek(fd, 0, SEEK_CUR);
				IFDBG printf("      Code At Offset: 0x%08llx\n", (u64)attr->info.code.code_offset);

				read(fd, buf, R_BIN_JAVA_UINT(buf, 4)); // READ CODE
				sz4 = read_short(fd);
				attr->info.code.exception_table_length = sz4;
				IFDBG printf("      Exception table length: %d\n", attr->info.code.exception_table_length);
				for(k=0;k<sz4;k++) {
					read(fd, buf, 8);
					attr->info.code.start_pc = R_BIN_JAVA_USHORT(buf,0);
					IFDBG printf("       start_pc:   0x%04x\n", attr->info.code.start_pc);
					attr->info.code.end_pc = R_BIN_JAVA_USHORT(buf,2);
					IFDBG printf("       end_pc:     0x%04x\n", attr->info.code.end_pc);
					attr->info.code.handler_pc = R_BIN_JAVA_USHORT(buf,4);
					IFDBG printf("       handler_pc: 0x%04x\n", attr->info.code.handler_pc);
					attr->info.code.catch_type = R_BIN_JAVA_USHORT(buf,6);
					IFDBG printf("       catch_type: %d\n", attr->info.code.catch_type);
				}
				sz4 = (unsigned int)read_short(fd);
				IFDBG printf("      code Attributes_count: %d\n", sz4);

				if (sz4>0)
					attr->attributes = malloc(sz4 * sizeof(struct r_bin_java_attr_t));
					attributes_walk(bin, attr->attributes, fd, sz4, fields);
			} else
			if (!strcmp(name, "LineNumberTable")) {
				attr->type = R_BIN_JAVA_TYPE_LINENUM;
				sz4 = (unsigned int)read_short(fd);
				attr->info.linenum.table_length = sz4;
				IFDBG printf("     Table Length: %d\n", attr->info.linenum.table_length);
				for(k=0;k<sz4;k++) {
					read(fd, buf, 4);
					attr->info.linenum.start_pc = R_BIN_JAVA_USHORT(buf, 0);
					IFDBG printf("     %2d: start_pc:    0x%04x\n", k, attr->info.linenum.start_pc);
					attr->info.linenum.line_number = R_BIN_JAVA_USHORT(buf, 2);
					IFDBG printf("         line_number: %d\n", attr->info.linenum.line_number);
				}
			} else
			if (!strcmp(name, "ConstantValue")) {
				attr->type = R_BIN_JAVA_TYPE_CONST;
				read(fd, buf, 2);
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

static int javasm_init(struct r_bin_java_t *bin)
{
	unsigned short sz, sz2;
	char buf[0x9999];
	int i,j;

	/* Initialize cp_null_item */
	cp_null_item.tag = -1;
	strcpy(cp_null_item.name, "(null)");
	cp_null_item.value = strdup("(null)");

	/* start parsing */
	read(bin->fd, &bin->cf, 10); //sizeof(struct r_bin_java_classfile_t), 1, bin->fd);
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

		read(bin->fd, buf, 1);

		c = NULL;
		for(j=0;constants[j].name;j++) {
			if (constants[j].tag == buf[0])  {
				c = &constants[j];
				break;
			}
		}
		if (c == NULL) {
			fprintf(stderr, "Invalid tag '%d'\n", buf[0]);
			return R_FALSE;
		}
		IFDBG printf(" %3d %s: ", i+1, c->name);

		/* store constant pool item */
		strcpy(bin->cp_items[i].name, c->name);
		bin->cp_items[i].ord = i+1;
		bin->cp_items[i].tag = c->tag;
		bin->cp_items[i].value = NULL; // no string by default
		bin->cp_items[i].off = lseek(bin->fd, 0, SEEK_CUR)-1;

		/* read bytes */
		switch(c->tag) {
			case 1: // utf 8 string
				read(bin->fd, buf, 2);
				sz = R_BIN_JAVA_USHORT(buf,0); //(buf[0]<<8)|buf[1];
				bin->cp_items[i].length = sz;
				bin->cp_items[i].off += 3;
				read(bin->fd, buf, sz);
				buf[sz] = '\0';
				break;
			default:
				read(bin->fd, buf, c->len);
		}

		memcpy(bin->cp_items[i].bytes, buf, 5);

		/* parse value */
		switch(c->tag) {
			case 1:
				IFDBG printf("%s\n", buf);
				bin->cp_items[i].value = strdup(buf);
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

	read(bin->fd, &bin->cf2, sizeof(struct r_bin_java_classfile2_t));
	IFDBG printf("Access flags: 0x%04x\n", bin->cf2.access_flags);
	bin->cf2.this_class = R_BIN_JAVA_SWAPUSHORT(bin->cf2.this_class);
	IFDBG printf("This class: %d\n", bin->cf2.this_class);
	//printf("This class: %d (%s)\n", R_BIN_JAVA_SWAPUSHORT(bin->cf2.this_class), bin->cp_items[R_BIN_JAVA_SWAPUSHORT(bin->cf2.this_class)-1].value); // XXX this is a double pointer !!1
	//printf("Super class: %d (%s)\n", R_BIN_JAVA_SWAPUSHORT(bin->cf2.super_class), bin->cp_items[R_BIN_JAVA_SWAPUSHORT(bin->cf2.super_class)-1].value);
	sz = read_short(bin->fd);

	/* TODO: intefaces*/
	IFDBG printf("Interfaces count: %d\n", sz);
	if (sz>0) {
		read(bin->fd, buf, sz*2);
		sz = read_short(bin->fd);
		for(i=0;i<sz;i++) {
			fprintf(stderr, "Interfaces: TODO\n");
		}
	}

	sz = read_short(bin->fd);
	bin->fields_count = sz;
	IFDBG printf("Fields count: %d\n", sz);
	if (sz>0) {
		bin->fields = malloc(sz * sizeof(struct r_bin_java_fm_t));
		for (i=0;i<sz;i++) {
			read(bin->fd, buf, 8);
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
					attributes_walk(bin, &bin->fields[i].attributes[j], bin->fd, sz2, 1);
			}
		}
	}

	sz = read_short(bin->fd);
	bin->methods_count = sz;
	IFDBG printf("Methods count: %d\n", sz);
	if (sz>0) {
		bin->methods = malloc(sz * sizeof(struct r_bin_java_fm_t));
		for (i=0;i<sz;i++) {
			read(bin->fd, buf, 8);

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
					attributes_walk(bin, &bin->methods[i].attributes[j], bin->fd, sz2, 0);
			}
		}
	}
	
	return R_TRUE;
}

int r_bin_java_open(struct r_bin_java_t *bin, const char *file)
{
	if ((bin->fd = open(file, 0)) == -1) {
		fprintf(stderr, "Cannot open file\n");
		return -1;
	}

	if (javasm_init(bin))
		return bin->fd;
	else return -1;
}

int r_bin_java_close(struct r_bin_java_t *bin)
{
	return close(bin->fd);
}

int r_bin_java_get_version(struct r_bin_java_t *bin, char *version)
{
	snprintf(version, R_BIN_JAVA_MAXSTR, "0x%02x%02x 0x%02x%02x",
			bin->cf.major[1],bin->cf.major[0],
			bin->cf.minor[1],bin->cf.minor[0]);
	return R_TRUE;
}

u64 r_bin_java_get_entrypoint(struct r_bin_java_t *bin)
{
	int i, j;
	
	for (i=0; i < bin->methods_count; i++)
		if (!strcmp(bin->methods[i].name, "<init>"))
			for (j=0; j < bin->methods[i].attr_count; j++)
				if (bin->methods[i].attributes[j].type == R_BIN_JAVA_TYPE_CODE)
					return (u64)bin->methods[i].attributes->info.code.code_offset;

	return 0;
}

int r_bin_java_get_symbols(struct r_bin_java_t *bin, struct r_bin_java_sym_t *sym)
{
	int i, j, ctr = 0;

	for (i=0; i < bin->methods_count; i++) {
			memcpy(sym[ctr].name, bin->methods[i].name, R_BIN_JAVA_MAXSTR);
			sym[ctr].name[R_BIN_JAVA_MAXSTR-1] = '\0';
			for (j=0; j < bin->methods[i].attr_count; j++)
				if (bin->methods[i].attributes[j].type == R_BIN_JAVA_TYPE_CODE) {
					sym[ctr].offset = (u64)bin->methods[i].attributes->info.code.code_offset;
					sym[ctr].size = bin->methods[i].attributes->info.code.code_length;
					ctr++;
				}
	}

	return ctr;
}

int r_bin_java_get_symbols_count(struct r_bin_java_t *bin)
{
	int i, j, ctr = 0;

	for (i=0; i < bin->methods_count; i++)
		for (j=0; j < bin->methods[i].attr_count; j++)
				if (bin->methods[i].attributes[j].type == R_BIN_JAVA_TYPE_CODE)
					ctr++;

	return ctr;
}

int r_bin_java_get_strings(struct r_bin_java_t *bin, struct r_bin_java_str_t *str)
{
	int i, ctr = 0;

	for(i=0;i<bin->cf.cp_count;i++) 
		if (bin->cp_items[i].tag == 1) {
			str[ctr].offset = (u64)bin->cp_items[i].off;
			str[ctr].ordinal = (u64)bin->cp_items[i].ord;
			str[ctr].size = (u64)bin->cp_items[i].length;
			memcpy(str[ctr].str, bin->cp_items[i].value, R_BIN_JAVA_MAXSTR);
			ctr++;
		}

	return ctr;
}

int r_bin_java_get_strings_count(struct r_bin_java_t *bin)
{
	int i, ctr = 0;

	for(i=0;i<bin->cf.cp_count;i++) 
		if (bin->cp_items[i].tag == 1)
			ctr++;

	return ctr;
}
