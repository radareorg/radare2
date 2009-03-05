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

// TODO: add radare related commands to stdout with -r (R printf..)

#if __UNIX__
#include <arpa/inet.h>
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdarg.h>

#include "javasm.h"

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

static struct java_op {
	char *name;
	unsigned char byte;
	int size;
} java_ops[] = {
	{ "aconst_null"     , 0x01 , 1 } , 
	{ "aload"           , 0x19 , 2 } , 
	{ "aload_0"         , 0x2a , 1 } , 
	{ "aload_1"         , 0x2b , 1 } , 
	{ "aload_2"         , 0x2c , 1 } , 
	{ "aload_3"         , 0x2d , 1 } , 
	{ "areturn"         , 0xb0 , 1 } , 
	{ "arraylength"     , 0xbe , 1 } , 
	{ "astore"          , 0x3a , 2 } , 
	{ "astore_0"        , 0x4b , 1 } , 
	{ "astore_1"        , 0x4c , 1 } , 
	{ "astore_2"        , 0x4d , 1 } , 
	{ "astore_3"        , 0x4e , 1 } , 
	{ "athrow"          , 0xbf , 1 } , 
	{ "baload"          , 0x33 , 1 } , 
	{ "bastore"         , 0x54 , 1 } , 
	{ "bipush"          , 0x10 , 2 } , 
	{ "caload"          , 0x34 , 1 } , 
	{ "castore"         , 0x55 , 1 } , 
	{ "checkcast"       , 0xc0 , 3 } , 
	{ "d2f"             , 0x90 , 1 } , 
	{ "d2i"             , 0x8e , 1 } , 
	{ "d2l"             , 0x8f , 1 } , 
	{ "dadd"            , 0x63 , 1 } , 
	{ "daload"          , 0x31 , 1 } , 
	{ "dastore"         , 0x52 , 1 } , 
	{ "dcmpg"           , 0x98 , 1 } , 
	{ "dcmpl"           , 0x97 , 1 } , 
	{ "dconst_0"        , 0x0e , 1 } , 
	{ "dconst_1"        , 0x0f , 1 } , 
	{ "ddiv"            , 0x6f , 1 } , 
	{ "dload"           , 0x18 , 2 } , 
	{ "dload_0"         , 0x26 , 1 } , 
	{ "dload_1"         , 0x27 , 1 } , 
	{ "dload_2"         , 0x28 , 1 } , 
	{ "dload_3"         , 0x29 , 1 } , 
	{ "dmul"            , 0x6b , 1 } , 
	{ "dneg"            , 0x77 , 1 } , 
	{ "drem"            , 0x73 , 1 } , 
	{ "dreturn"         , 0xaf , 1 } , 
	{ "dstore"          , 0x39 , 2 } , 
	{ "dstore_0"        , 0x47 , 1 } , 
	{ "dstore_1"        , 0x48 , 1 } , 
	{ "dstore_2"        , 0x49 , 1 } , 
	{ "dstore_3"        , 0x4a , 1 } , 
	{ "dsub"            , 0x67 , 1 } , 
	{ "dup"             , 0x59 , 1 } , 
	{ "dup_x1"          , 0x5a , 1 } , 
	{ "dup_x2"          , 0x5b , 1 } , 
	{ "dup2"            , 0x5c , 1 } , 
	{ "dup2_x1"         , 0x5d , 1 } , 
	{ "dup2_x2"         , 0x5e , 1 } , 
	{ "f2d"             , 0x8d , 1 } , 
	{ "f2i"             , 0x8b , 1 } , 
	{ "f2l"             , 0x8c , 1 } , 
	{ "fadd"            , 0x62 , 1 } , 
	{ "faload"          , 0x30 , 1 } , 
	{ "fastore"         , 0x51 , 1 } , 
	{ "fcmpg"           , 0x96 , 1 } , 
	{ "fcmpl"           , 0x95 , 1 } , 
	{ "fconst_0"        , 0x0b , 1 } , 
	{ "fconst_1"        , 0x0c , 1 } , 
	{ "fconst_2"        , 0x0d , 1 } , 
	{ "fdiv"            , 0x6e , 1 } , 
	{ "fload"           , 0x17 , 2 } , 
	{ "fload_0"         , 0x22 , 1 } , 
	{ "fload_1"         , 0x23 , 1 } , 
	{ "fload_2"         , 0x24 , 1 } , 
	{ "fload_3"         , 0x25 , 1 } , 
	{ "fmul"            , 0x6a , 1 } , 
	{ "fneg"            , 0x76 , 1 } , 
	{ "frem"            , 0x72 , 1 } , 
	{ "freturn"         , 0xae , 1 } , 
	{ "fstore"          , 0x38 , 2 } , 
	{ "fstore_0"        , 0x43 , 1 } , 
	{ "fstore_1"        , 0x44 , 1 } , 
	{ "fstore_2"        , 0x45 , 1 } , 
	{ "fstore_3"        , 0x46 , 1 } , 
	{ "fsub"            , 0x66 , 1 } , 
	{ "getfield"        , 0xb4 , 3 } , 
	{ "getstatic"       , 0xb2 , 3 } , 
	{ "goto"            , 0xa7 , 3 } , 
	{ "goto_w"          , 0xc8 , 5 } , 
	{ "i2b"             , 0x91 , 1 } , 
	{ "i2c"             , 0x92 , 1 } , 
	{ "i2d"             , 0x87 , 1 } , 
	{ "i2f"             , 0x86 , 1 } , 
	{ "i2l"             , 0x85 , 1 } , 
	{ "i2s"             , 0x93 , 1 } , 
	{ "iadd"            , 0x60 , 1 } , 
	{ "iaload"          , 0x2e , 1 } , 
	{ "iand"            , 0x7e , 1 } , 
	{ "iastore"         , 0x4f , 1 } , 
	{ "iconst_m1"       , 0x02 , 1 } , 
	{ "iconst_0"        , 0x03 , 1 } , 
	{ "iconst_1"        , 0x04 , 1 } , 
	{ "iconst_2"        , 0x05 , 1 } , 
	{ "iconst_3"        , 0x06 , 1 } , 
	{ "iconst_4"        , 0x07 , 1 } , 
	{ "iconst_5"        , 0x08 , 1 } , 
	{ "idiv"            , 0x6c , 1 } , 
	{ "if_acmpeq"       , 0xa5 , 3 } , 
	{ "if_acmpne"       , 0xa6 , 3 } , 
	{ "if_icmpeq"       , 0x9f , 3 } , 
	{ "if_icmpne"       , 0xa0 , 3 } , 
	{ "if_icmplt"       , 0xa1 , 3 } , 
	{ "if_icmpge"       , 0xa2 , 3 } , 
	{ "if_icmpgt"       , 0xa3 , 3 } , 
	{ "if_icmple"       , 0xa4 , 3 } , 
	{ "ifeq"            , 0x99 , 3 } , 
	{ "ifne"            , 0x9a , 3 } , 
	{ "iflt"            , 0x9b , 3 } , 
	{ "ifge"            , 0x9c , 3 } , 
	{ "ifgt"            , 0x9d , 3 } , 
	{ "ifle"            , 0x9e , 3 } , 
	{ "ifnonnull"       , 0xc7 , 3 } , 
	{ "ifnull"          , 0xc6 , 3 } , 
	{ "iinc"            , 0x84 , 3 } , 
	{ "iload"           , 0x15 , 2 } , 
	{ "iload_0"         , 0x1a , 1 } , 
	{ "iload_1"         , 0x1b , 1 } , 
	{ "iload_2"         , 0x1c , 1 } , 
	{ "iload_3"         , 0x1d , 1 } , 
	{ "imul"            , 0x68 , 1 } , 
	{ "ineg"            , 0x74 , 1 } , 
	{ "instanceof"      , 0xc1 , 3 } , 
	{ "invokevirtual"   , 0xb6 , 3 } , 
	{ "invokespecial"   , 0xb7 , 3 } , 
	{ "invokestatic"    , 0xb8 , 3 } , 
	{ "invokeinterface" , 0xb9 , 5 } , 
	{ "ior"             , 0x80 , 1 } , 
	{ "irem"            , 0x70 , 1 } , 
	{ "ireturn"         , 0xac , 1 } , 
	{ "ishl"            , 0x78 , 1 } , 
	{ "ishr"            , 0x7a , 1 } , 
	{ "istore"          , 0x36 , 2 } , 
	{ "istore_0"        , 0x3b , 1 } , 
	{ "istore_1"        , 0x3c , 1 } , 
	{ "istore_2"        , 0x3d , 1 } , 
	{ "istore_3"        , 0x3e , 1 } , 
	{ "isub"            , 0x64 , 1 } , 
	{ "iushr"           , 0x7c , 1 } ,
	{ "ixor"            , 0x82 , 1 } ,
	{ "lxor"            , 0x83 , 1 } ,
	{ "jsr"             , 0xa8 , 3 } , 
	{ "jsr_w"           , 0xc9 , 5 } , 
	{ "l2d"             , 0x8a , 1 } , 
	{ "l2f"             , 0x89 , 1 } , 
	{ "l2i"             , 0x88 , 1 } , 
	{ "ladd"            , 0x61 , 1 } , 
	{ "laload"          , 0x2f , 1 } , 
	{ "land"            , 0x7f , 1 } , 
	{ "lastore"         , 0x50 , 1 } , 
	{ "lcmp"            , 0x94 , 1 } , 
	{ "lconst_0"        , 0x09 , 1 } , 
	{ "lconst_1"        , 0x0a , 1 } , 
	{ "ldc"             , 0x12 , 2 } , 
	{ "ldc_w"           , 0x13 , 3 } , 
	{ "ldc2_w"          , 0x14 , 3 } , 
	{ "ldiv"            , 0x6d , 1 } , 
	{ "lload"           , 0x16 , 2 } , 
	{ "lload_0"         , 0x1e , 1 } , 
	{ "lload_1"         , 0x1f , 1 } , 
	{ "lload_2"         , 0x20 , 1 } , 
	{ "lload_3"         , 0x21 , 1 } , 
	{ "lmul"            , 0x69 , 1 } , 
	{ "lneg"            , 0x75 , 1 } , 
	{ "lookupswitch"    , 0xab , 3 } , // XXX broken opcode
	{ "lor"             , 0x81 , 1 } , 
	{ "lrem"            , 0x71 , 1 } , 
	{ "lreturn"         , 0xad , 1 } , 
	{ "lshl"            , 0x79 , 1 } , 
	{ "lshr"            , 0x7b , 1 } , 
	{ "lstore"          , 0x37 , 2 } , 
	{ "lstore_0"        , 0x3f , 1 } , 
	{ "lstore_1"        , 0x40 , 1 } , 
	{ "lstore_2"        , 0x41 , 1 } , 
	{ "lstore_3"        , 0x42 , 1 } , 
	{ "lsub"            , 0x65 , 1 } , 
	{ "lushr"           , 0x7d , 1 } , 
	{ "lxor"            , 0x83 , 1 } , 
	{ "monitorenter"    , 0xc2 , 1 } , 
	{ "monitorexit"     , 0xc3 , 1 } , 
	{ "multinewarray"   , 0xc5 , 3 } , // XXX broken opcode ?
	{ "new"             , 0xbb , 3 } , 
	{ "newarray"        , 0xbc , 2 } , 
	{ "nop"             , 0x00 , 1 } , 
	{ "pop"             , 0x57 , 1 } , 
	{ "pop2"            , 0x58 , 1 } , 
	{ "putfield"        , 0xb5 , 3 } , 
	{ "putstatic"       , 0xb3 , 3 } , 
	{ "ret"             , 0xa9 , 2 } , 
	{ "return"          , 0xb1 , 1 } , 
	{ "saload"          , 0x35 , 1 } , 
	{ "sastore"         , 0x36 , 1 } , 
	{ "sipush"          , 0x11 , 3 } , 
	{ "swap"            , 0x5f , 1 } , 
	{ "tableswitch"     , 0xaa , 3 } , // broken opcode
	{ "wide"            , 0xc4 , 1 } , // broken opcode - variable length
	{ "breakpoint"      , 0xca , 1 } , 
	{ "impdep1"         , 0xfe , 1 } , 
	{ "impdep2"         , 0xff , 1 } , 
	{ "unused"          , 0xba , 1 } , 
	{ NULL, 0x0, 0 }
};

static struct classfile cf;

static struct cp_item * get_cp(int i)
{
	if (i<0||i>cf.cp_count)
		return &cp_null_item;
	return &cp_items[i];
}

static int java_resolve(int idx, char *str)
{
	if (str == NULL)
		return 0;

	str[0]='\0';
	if (idx<0||idx>cf.cp_count)
		return 1;
	if((!strcmp(cp_items[idx].name, "MethodRef"))
	|| (!strcmp(cp_items[idx].name, "FieldRef"))) {
		int class = USHORT(get_cp(idx)->bytes,0);
		//int namet = USHORT(get_cp(idx)->bytes,2);
		char *class_str = get_cp(USHORT(get_cp(class)->bytes,0)-1)->value;
		char *namet_str = get_cp(USHORT(get_cp(class)->bytes,2)-1)->value;
		//char *namet_str = get_cp(namet)->value;
		sprintf(str, "%s %s", class_str, namet_str);
	} else
	if (!strcmp(cp_items[idx].name, "String")) {
		sprintf(str, "\"%s\"", get_cp(USHORT(get_cp(idx)->bytes,0)-1)->value);
	} else
	if (!strcmp(cp_items[idx].name, "Utf8")) {
		sprintf(str, "\"%s\"", get_cp(idx)->value);
	} else
		sprintf(str, "0x%04x", USHORT(get_cp(idx)->bytes,0));
	return 0;
}

int java_print_opcode(int idx, const u8 *bytes, char *output)
{
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
	case 2: sprintf(output, "%s %d", java_ops[idx].name, bytes[0]);
		break;
	case 3: sprintf(output, "%s 0x%x 0x%x", java_ops[idx].name, bytes[0], bytes[1]);
		break;
	case 5: sprintf(output, "%s %d", java_ops[idx].name, bytes[0]);
		break;
	}

	return java_ops[idx].size;
}

int java_disasm(const u8 *bytes, char *output)
{
	int i;
	for(i = 0;java_ops[i].name != NULL;i++)
		if (bytes[0] == java_ops[i].byte)
			return java_print_opcode(i, bytes, output);
	return -1;
}
static void check_eof(FILE *fd)
{
	if (feof(fd)) {
		fprintf(stderr, "Unexpected eof\n");
		exit(0);
	}
}

int java_assemble(unsigned char *bytes, char *string)
{
	int i;
	char name[128];
	int a,b,c,d;

	sscanf(string, "%s %d %d %d %d", name, &a, &b, &c, &d);
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

#define resolve(dst,from,field,value)\
{\
	int i;\
	for(i=0;from[i].field;i++) {\
		if (from[i].field == value) \
			dst = &from[i];\
			break;\
	}\
}

unsigned short read_short(FILE *fd)
{
	unsigned short sh=0;

	fread(&sh, 2,1,fd);//sizeof(unsigned short), 1, fd);
	return ntohs(sh);
}

static int attributes_walk(FILE *fd, int sz2, int fields)
{
	char buf[99999];
	int sz3, sz4;
	int j=0,k;
	char *name;

	for(j=0;j<sz2;j++) {
		fread(buf, 6, 1, fd);
		name = (get_cp(USHORT(buf,0)-1))->value;//cp_items[USHORT(buf,0)-1].value;
		printf("   %2d: Name Index: %d (%s)\n", j, USHORT(buf,0), name);
		// TODO add comment with constant pool index
		sz3 = UINT(buf, 2);
		if (fields) {
			printf("FIELD\n");
		} else {
			printf("     Length: %d\n", sz3); //UINT(buf, 2));
			if (!name) {
				printf("**ERROR ** Cannot identify attribute name into constant pool\n");
				continue;
			}
			if (!strcmp(name, "Code")) {
				fread(buf, 8, 1, fd);

				printf("      Max Stack: %d\n", USHORT(buf, 0));
				printf("      Max Locals: %d\n", USHORT(buf, 2));
				printf("      Code Length: %d\n", UINT(buf, 4));
				printf("      Code At Offset: 0x%08llx\n", (u64)ftell(fd));

				fread(buf, UINT(buf, 4), 1, fd); // READ CODE
				sz4 = read_short(fd);
				printf("      Exception table length: %d\n", sz4);
				for(k=0;k<sz4;k++) {
					fread(buf, 8, 1, fd);

					printf("       start_pc:   0x%04x\n", USHORT(buf,0));
					printf("       end_pc:     0x%04x\n", USHORT(buf,2));
					printf("       handler_pc: 0x%04x\n", USHORT(buf,4));
					printf("       catch_type: %d\n", USHORT(buf,6));

				}
				sz4 = (int)read_short(fd);
				printf("      code Attributes_count: %d\n", sz4);

				if (sz4>0)
					attributes_walk(fd, sz4, fields);
			} else
			if (!strcmp(name, "LineNumberTable")) {
				sz4 = (int)read_short(fd);
				printf("     Table Length: %d\n", sz4);
				for(k=0;k<sz4;k++) {
					fread(buf, 4, 1, fd);
					printf("     %2d: start_pc:    0x%04x\n", k, USHORT(buf, 0));
					printf("         line_number: %d\n", USHORT(buf, 2));
				}
			} else
			if (!strcmp(name, "ConstantValue")) {
				fread(buf, 2, 1, fd);
	#if 0
				printf("     Name Index: %d\n", USHORT(buf, 0)); // %s\n", USHORT(buf, 0), cp_items[USHORT(buf,0)-1].value);
				printf("     AttributeLength: %d\n", UINT(buf, 2));
	#endif
				printf("     ConstValueIndex: %d\n", USHORT(buf, 0));
			} else {
				fprintf(stderr, "** ERROR ** Unknown section '%s'\n", name);
				return 1;
			}
		}
	}
	return 0;
}

int javasm_init()
{
	/* INIT JAVA DISASSEMBLER */
	cp_null_item.tag = -1;
	strcpy(cp_null_item.name, "(null)");
	cp_null_item.value = strdup("(null)");
	return 0;
}

int java_classdump(const char *file)
{
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
	fread(&cf, 10, 1, fd); //sizeof(struct classfile), 1, fd);
	if (memcmp(cf.cafebabe, "\xCA\xFE\xBA\xBE", 4)) {
		fprintf(stderr, "Invalid header\n");
		return -1;
	}

	/* show class version information */
	printf("Version: 0x%02x%02x 0x%02x%02x\n", cf.major[1],cf.major[0], cf.minor[1],cf.minor[0]);

	cf.cp_count = ntohs(cf.cp_count);
	if (cf.major[0]==cf.major[1] && cf.major[0]==0) {
		fprintf(stderr, "Oops. this is a Mach-O\n");
		return 0;
	}
	
	cf.cp_count--;
	printf("ConstantPoolCount %d\n", cf.cp_count);
	cp_items = malloc(sizeof(struct cp_item)*(cf.cp_count+1));
	for(i=0;i<cf.cp_count;i++) {
		struct constant_t *c;

		fread(buf, 1, 1, fd);

		c = NULL;
		for(j=0;constants[j].name;j++) {
			if (constants[j].tag == buf[0])  {
				c = &constants[j];
				break;
			}
		}
		if (c == NULL) {
			fprintf(stderr, "Invalid tag '%d'\n", buf[0]);
			return 0;
		}
		printf(" %3d %s: ", i+1, c->name);

		/* store constant pool item */
		strcpy( cp_items[i].name, c->name);
		cp_items[i].tag = c->tag;
		cp_items[i].value = NULL; // no string by default
		cp_items[i].off = ftell(fd)-1;

		/* read bytes */
		switch(c->tag) {
		case 1: // utf 8 string
			fread(buf, 2, 1, fd);
			sz = USHORT(buf,0); //(buf[0]<<8)|buf[1];
			//cp_items[i].len = sz;
			fread(buf, sz, 1, fd);
			buf[sz] = '\0';
			break;
		default:
			fread(buf, c->len, 1, fd);
		}

		memcpy(cp_items[i].bytes, buf, 5);

		/* parse value */
		switch(c->tag) {
		case 1:
			printf("%s\n", buf);
			cp_items[i].value = strdup(buf);
			break;
		case 7:
			printf("%d\n", USHORT(buf,0));
			break;
		case 8:
			printf("string ptr %d\n", USHORT(buf, 0));
			break;
		case 9:
		case 11:
		case 10: // METHOD REF
			printf("class = %d, ", USHORT(buf,0));
			printf("name_type = %d\n", USHORT(buf,2));
			break;
		case 12:
			printf("name = %d, ", USHORT(buf,0));
			printf("descriptor = %d\n", USHORT(buf,2));
			break;
		default:
			printf("%d\n", UINT(buf, 40));
		}
	}

	fread(&cf2, sizeof(struct classfile2), 1, fd);
	check_eof(fd);
	printf("Access flags: 0x%04x\n", cf2.access_flags);
	this_class = ntohs(cf2.this_class);
	printf("This class: %d\n", cf2.this_class);
	check_eof(fd);
	//printf("This class: %d (%s)\n", ntohs(cf2.this_class), cp_items[ntohs(cf2.this_class)-1].value); // XXX this is a double pointer !!1
	//printf("Super class: %d (%s)\n", ntohs(cf2.super_class), cp_items[ntohs(cf2.super_class)-1].value);
	sz = read_short(fd);
	printf("Interfaces count: %d\n", sz);
	if (sz>0) {
		fread(buf, sz*2, 1, fd);
		sz = read_short(fd);
		for(i=0;i<sz;i++) {
			fprintf(stderr, "interfaces: TODO\n");
		}
	}

	sz = read_short(fd);
	printf("Fields count: %d\n", sz);
	if (sz>0) {
		for (i=0;i<sz;i++) {
			fread(buf, 8, 1, fd);

			printf("%2d: Access Flags: %d\n", i, USHORT(buf, 0));
			printf("    Name Index: %d (%s)\n", USHORT(buf, 2), get_cp(USHORT(buf,2)-1)->value);
			printf("    Descriptor Index: %d\n", USHORT(buf, 4)); //, cp_items[USHORT(buf, 4)-1].value);

			sz2 = USHORT(buf, 6);
			printf("    field Attributes Count: %d\n", sz2);
			attributes_walk(fd, sz2, 1);
		}
	}

	sz = read_short(fd);
	printf("Methods count: %d\n", sz);
	if (sz>0) {
		for (i=0;i<sz;i++) {
			fread(buf, 8, 1, fd);
			check_eof(fd);
			
			printf("%2d: Access Flags: %d\n", i, USHORT(buf, 0));
			printf("    Name Index: %d (%s)\n", USHORT(buf, 2), get_cp(USHORT(buf, 2)-1)->value);
			printf("    Descriptor Index: %d (%s)\n", USHORT(buf, 4), get_cp(USHORT(buf, 4)-1)->value);

			sz2 = USHORT(buf, 6);
			printf("    method Attributes Count: %d\n", sz2);
			attributes_walk(fd, sz2, 0);
		}
	}

	fclose(fd);

	return 0;
}
