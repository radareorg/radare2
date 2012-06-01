// XXX: dupped in rasm, rbin.. rasm must use rbin callback to do it
/*
 * Copyright (C) 2007-2011
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

// TODO: add radare related commands to stdout with -r (R printf..)

#include <r_types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//#include <getopt.h>
#include <stdarg.h>
#include "javasm.h"
#if __UNIX__
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#define V if(verbose)

static struct cp_item *cp_items = NULL;
static struct cp_item cp_null_item; // NOTE: must be initialized for safe use

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

static struct classfile cf;

static ut16 r_ntohs (ut16 foo) {
/* XXX BIGENDIAN NOT DEFINED HERE !!!1 */
#if BIGENDIAN
	/* do nothing */
#else
	ut8 *p = (ut8 *)&foo;
	foo = p[1] | p[0]<<8;
#endif
	return foo;
}

static struct cp_item * get_cp(int i) {
	if (i<0||i>cf.cp_count)
		return &cp_null_item;
	return &cp_items[i];
}

static int java_resolve(int idx, char *str) {
	if (str == NULL)
		return 0;

	str[0]='\0';
	if (idx<0||idx>cf.cp_count)
		return 1;
	if (cp_items) {
		if ((!strcmp (cp_items[idx].name, "MethodRef"))
		|| (!strcmp (cp_items[idx].name, "FieldRef"))) {
			int class = USHORT (get_cp(idx)->bytes,0);
			//int namet = USHORT(get_cp(idx)->bytes,2);
			char *class_str = get_cp(USHORT(get_cp(class)->bytes,0)-1)->value;
			char *namet_str = get_cp(USHORT(get_cp(class)->bytes,2)-1)->value;
			//char *namet_str = get_cp(namet)->value;
			sprintf (str, "%s %s", class_str, namet_str);
		} else
		if (!strcmp (cp_items[idx].name, "String")) {
			sprintf(str, "\"%s\"", get_cp(USHORT(get_cp(idx)->bytes,0)-1)->value);
		} else
		if (!strcmp(cp_items[idx].name, "Utf8")) {
			sprintf (str, "\"%s\"", get_cp(idx)->value);
		} else sprintf (str, "0x%04x", USHORT(get_cp(idx)->bytes,0));
	} else strcpy (str, "(null)");
	return 0;
}

int java_print_opcode(int idx, const ut8 *bytes, char *output) {
	char arg[1024];

	switch(java_ops[idx].byte) {
	case 0x12:
	case 0x13:
	case 0x14:
		java_resolve(bytes[1]-1, arg);
		sprintf(output, "%s %s", java_ops[idx].name, arg);
		return java_ops[idx].size;
	case 0xb2: // getstatic
	case 0xb6: // invokevirtual
	case 0xb7: // invokespecial
	case 0xb8: // invokestatic
	case 0xb9: // invokeinterface
		java_resolve((int)USHORT(bytes,1)-1, arg);
		sprintf(output, "%s %s", java_ops[idx].name, arg);
		return java_ops[idx].size;
	}

	/* process arguments */
	switch(java_ops[idx].size) {
	case 1: sprintf(output, "%s", java_ops[idx].name);
		break;
	case 2: sprintf(output, "%s %d", java_ops[idx].name, bytes[1]);
		break;
	case 3: sprintf(output, "%s 0x%x 0x%x", java_ops[idx].name, bytes[0], bytes[1]);
		break;
	case 5: sprintf(output, "%s %d", java_ops[idx].name, bytes[1]);
		break;
	}

	return java_ops[idx].size;
}

int java_disasm(const ut8 *bytes, char *output) {
	int i;
	for(i = 0;java_ops[i].name != NULL;i++)
		if (bytes[0] == java_ops[i].byte)
			return java_print_opcode (i, bytes, output);
	return -1;
}

static void check_eof(FILE *fd) {
	if (feof(fd)) {
		fprintf(stderr, "Unexpected eof\n");
		exit(0);
	}
}

int java_assemble(unsigned char *bytes, const char *string) {
	int i;
	char name[128];
	int a,b,c,d;

	sscanf (string, "%s %d %d %d %d", name, &a, &b, &c, &d);
	for(i = 0;java_ops[i].name != NULL;i++)
		if (!strcmp(name, java_ops[i].name)) {
			bytes[0] = java_ops[i].byte;
			switch(java_ops[i].size) {
			case 2: bytes[1] = a; break;
			case 3: bytes[1] = a; bytes[2] = b; break;
			case 5: bytes[1] = a;
				bytes[2] = b;
				bytes[3] = c;
				bytes[4] = d;
				break;
			}
			return java_ops[i].size;
		}
	return 0;
}

#define resolve(dst,from,field,value) {\
	int i;\
	for(i=0;from[i].field;i++) {\
		if (from[i].field == value) \
			dst = &from[i];\
			break;\
	}\
}

unsigned short read_short(FILE *fd) {
	unsigned short sh = 0;
	fread (&sh, 2, 1, fd);
	return r_ntohs (sh);
}

static int attributes_walk(FILE *fd, int sz2, int fields, int verbose) {
	char *name, buf[99999];
	int sz, k, j=0;

	for (j=0;j<sz2;j++) {
		fread(buf, 6, 1, fd);
		name = (get_cp (USHORT(buf,0)-1))->value;
		V printf("   %2d: Name Index: %d (%s)\n", j, USHORT(buf,0), name);
		// TODO add comment with constant pool index
		if (fields) {
			V printf("FIELD\n");
		} else {
			V printf ("     Length: %d\n", UINT (buf, 2));
			if (!name) {
				printf ("**ERROR ** Cannot identify attribute name into constant pool\n");
				continue;
			}
			if (!strcmp (name, "Code")) {
				fread(buf, 8, 1, fd);

				V printf("      Max Stack: %d\n", USHORT(buf, 0));
				V printf("      Max Locals: %d\n", USHORT(buf, 2));
				V printf("      Code Length: %d\n", UINT(buf, 4));
				V printf("      Code At Offset: 0x%08"PFMT64x"\n", (ut64)ftell(fd));

				fread(buf, UINT(buf, 4), 1, fd); // READ CODE
				sz = read_short(fd);
				V printf("      Exception table length: %d\n", sz);
				for (k=0;k<sz;k++) {
					fread(buf, 8, 1, fd);
					V printf("       start_pc:   0x%04x\n", USHORT(buf,0));
					V printf("       end_pc:     0x%04x\n", USHORT(buf,2));
					V printf("       handler_pc: 0x%04x\n", USHORT(buf,4));
					V printf("       catch_type: %d\n", USHORT(buf,6));
				}
				sz = (int)read_short(fd);
				V printf("      code Attributes_count: %d\n", sz);

				if (sz>0)
					attributes_walk(fd, sz, fields, verbose);
			} else
			if (!strcmp(name, "LineNumberTable")) {
				sz = (int)read_short(fd);
				V printf("     Table Length: %d\n", sz);
				for(k=0;k<sz;k++) {
					fread(buf, 4, 1, fd);
					V printf("     %2d: start_pc:    0x%04x\n", k, USHORT(buf, 0));
					V printf("         line_number: %d\n", USHORT(buf, 2));
				}
			} else
			if (!strcmp(name, "StackMapTable")) {
				fread (buf, 2, 1, fd);
				V printf("     StackMapTable: %d\n", USHORT(buf, 0));
			} else
			if (!strcmp (name, "LocalVariableTable")) {
				int i;
				ut32 lvtl = (ut32)read_short (fd);
				for (i=0; i<lvtl; i++) {
					int start_pc = start_pc = read_short (fd);
					int length = length = read_short (fd);
					int name_idx = name_idx = read_short (fd);
					int desc_idx = desc_idx = read_short (fd);
					int index = index = read_short (fd);
				}
			} else
			if (!strcmp(name, "ConstantValue")) {
				fread(buf, 2, 1, fd);
	#if 0
				printf("     Name Index: %d\n", USHORT(buf, 0)); // %s\n", USHORT(buf, 0), cp_items[USHORT(buf,0)-1].value);
				printf("     AttributeLength: %d\n", UINT(buf, 2));
	#endif
				V printf("     ConstValueIndex: %d\n", USHORT(buf, 0));
			} else {
				fprintf (stderr, "** ERROR ** Unknown section '%s'\n", name);
				return 1;
			}
		}
	}
	return 0;
}

void javasm_init() {
	cp_null_item.tag = -1;
	strcpy (cp_null_item.name, "(null)");
	cp_null_item.value = strdup ("(null)");
}

int java_classdump(const char *file, int verbose) {
	struct classfile2 cf2;
	unsigned short sz, sz2;
	int this_class;
	char buf[0x9999];
	int i,j;
	FILE *fd = fopen(file, "rb");

	if (fd == NULL)
		return -1;

	javasm_init();

	/* start parsing */
	fread (&cf, 10, 1, fd); //sizeof(struct classfile), 1, fd);
	if (memcmp (cf.cafebabe, "\xCA\xFE\xBA\xBE", 4)) {
		fprintf(stderr, "java_classdump: Invalid header\n");
		return -1;
	}

	/* show class version information */
	V printf("Version: 0x%02x%02x 0x%02x%02x\n", cf.major[1],cf.major[0], cf.minor[1],cf.minor[0]);

	cf.cp_count = r_ntohs(cf.cp_count);
	if (cf.major[0]==cf.major[1] && cf.major[0]==0) {
		fprintf(stderr, "Oops. this is a Mach-O\n");
		return 0;
	}
	
	cf.cp_count--;
	V printf ("ConstantPoolCount %d\n", cf.cp_count);
	cp_items = malloc (sizeof (struct cp_item)*(cf.cp_count+1));
	for (i=0;i<cf.cp_count;i++) {
		struct constant_t *c;
		fread (buf, 1, 1, fd);
		c = NULL;
		for (j=0; constants[j].name; j++) {
			if (constants[j].tag == buf[0])  {
				c = &constants[j];
				break;
			}
		}
		if (c == NULL) {
			eprintf ("Invalid tag '%d'\n", buf[0]);
			return 0;
		}
		V printf(" %3d %s: ", i+1, c->name);

		/* store constant pool item */
		strcpy( cp_items[i].name, c->name);
		cp_items[i].tag = c->tag;
		cp_items[i].value = NULL; // no string by default
		cp_items[i].off = ftell(fd)-1;

		/* read bytes */
		switch (c->tag) {
		case 1: // utf 8 string
			fread (buf, 2, 1, fd);
			sz = USHORT (buf,0);
			//cp_items[i].len = sz;
			fread(buf, sz, 1, fd);
			buf[sz] = '\0';
			break;
		default:
			fread(buf, c->len, 1, fd);
		}

		memcpy (cp_items[i].bytes, buf, 5);

		/* parse value */
		switch(c->tag) {
		case 1:
			V printf ("%s\n", buf);
			cp_items[i].value = strdup(buf);
			break;
		case 7:
			V printf ("%d\n", USHORT(buf,0));
			break;
		case 8:
			V printf ("string ptr %d\n", USHORT(buf, 0));
			break;
		case 9:
		case 11:
		case 10: // METHOD REF
			V printf("class = %d, ", USHORT(buf,0));
			V printf("name_type = %d\n", USHORT(buf,2));
			break;
		case 12:
			V printf("name = %d, ", USHORT(buf,0));
			V printf("descriptor = %d\n", USHORT(buf,2));
			break;
		default:
			V printf("%d\n", UINT(buf, 40));
		}
	}

	fread (&cf2, sizeof (struct classfile2), 1, fd);
	check_eof(fd);
	V printf("Access flags: 0x%04x\n", cf2.access_flags);
	this_class = r_ntohs(cf2.this_class);
	V printf ("This class: %d\n", this_class);
	check_eof (fd);
	//printf("This class: %d (%s)\n", ntohs(cf2.this_class), cp_items[ntohs(cf2.this_class)-1].value); // XXX this is a double pointer !!1
	//printf("Super class: %d (%s)\n", ntohs(cf2.super_class), cp_items[ntohs(cf2.super_class)-1].value);
	sz = read_short (fd);
	V printf ("Interfaces count: %d\n", sz);
	if (sz>0) {
		fread (buf, sz*2, 1, fd);
		sz = read_short (fd);
		for (i=0; i<sz; i++) {
			eprintf ("interfaces: TODO\n");
		}
	}

	sz = read_short(fd);
	V printf("Fields count: %d\n", sz);
	if (sz>0) {
		for (i=0;i<sz;i++) {
			fread(buf, 8, 1, fd);

			V printf("%2d: Access Flags: %d\n", i, USHORT(buf, 0));
			V printf("    Name Index: %d (%s)\n", USHORT(buf, 2), get_cp(USHORT(buf,2)-1)->value);
			V printf("    Descriptor Index: %d\n", USHORT(buf, 4)); //, cp_items[USHORT(buf, 4)-1].value);

			sz2 = USHORT(buf, 6);
			V printf("    field Attributes Count: %d\n", sz2);
			attributes_walk(fd, sz2, 1, verbose);
		}
	}

	sz = read_short(fd);
	V printf("Methods count: %d\n", sz);
	if (sz>0) {
		for (i=0;i<sz;i++) {
			fread(buf, 8, 1, fd);
			check_eof(fd);
			
			V printf("%2d: Access Flags: %d\n", i, USHORT(buf, 0));
			V printf("    Name Index: %d (%s)\n", USHORT(buf, 2), get_cp(USHORT(buf, 2)-1)->value);
			V printf("    Descriptor Index: %d (%s)\n", USHORT(buf, 4), get_cp(USHORT(buf, 4)-1)->value);

			sz2 = USHORT(buf, 6);
			V printf("    method Attributes Count: %d\n", sz2);
			attributes_walk(fd, sz2, 0, verbose);
		}
	}

	fclose(fd);

	return 0;
}
