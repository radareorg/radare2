/* radare - LGPL - Copyright 2007-2013 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <r_list.h>
#include "code.h"
#include "class.h"

#define V if(verbose)



static RList *cp_items = NULL;


static RBinJavaClass cf;

R_API void r_java_setcp(void *cp, int n) {
	// eprintf ("SET CP (%p) %d\n", cp, n);
	cp_items = (RList *) cp;
	if(cp == NULL)
		cp_items = r_list_new();

	cf.cp_count = n;
}

static RBinJavaCPTypeObj* get_cp(int i) {
	RBinJavaCPTypeObj *item = NULL;
	if (i<0||i>cf.cp_count)
		return r_bin_java_get_java_null_cp();
	item = (RBinJavaCPTypeObj *) r_list_get_n(cp_items, i);
	return item;
}

static int java_resolve(int idx, char *str) {
	// TODO XXX FIXME add a size parameter to the str when it is passed in
	RBinJavaCPTypeObj *item = NULL, 
					*class_cp_item = NULL, 
					*namet_cp_item = NULL;
	char *class_str = NULL, 
		 *namet_str = NULL, 
		 *string_str = NULL, 
		 *empty = "",
		 *cp_name = NULL;
	int class_idx, namet_idx;
	if (str == NULL)
		return 0;
	sprintf (str, "(%d)", idx);
	if (cf.cp_count<1) {
		/* load constant pool here */
	}
	if (idx<0||idx>cf.cp_count)
		return 1;

	// default case.
	if (cp_items == NULL){
		strcpy (str, "(null)");
		return 0;	
	}
	

	item = (RBinJavaCPTypeObj *) r_list_get_n(cp_items, idx);
	if (!item){
		sprintf (str, "(?): 0x%04x", item->tag);
		return 0;			
	}
	cp_name = ((RBinJavaCPTypeMetas *) item->metas->type_info)->name;
	if ( !cp_name) {  
		sprintf (str, "0x%02x", item->tag);
		return 0;
	}
	
	// Damn this is a long logic statement :-(
	if ( strcmp (cp_name, "Class") == 0 ){
		class_idx = item->info.cp_class.name_idx;
		class_str = r_bin_java_get_utf8_from_cp_item_list(cp_items, class_idx);	
		if (class_str == NULL)
			class_str = empty;

		sprintf (str, "%s", class_str);
		
		if (class_str != empty)
			free(class_str);
	
	}else if ( strcmp (cp_name, "MethodRef") == 0 ||
		 strcmp (cp_name, "FieldRef") == 0 || 
		 strcmp (cp_name, "InterfaceMethodRef") == 0) {
		
		int class_idx = -1;
		int namet_idx =	-1;		
		if (strcmp (cp_name, "MethodRef") == 0){
			class_idx = item->info.cp_method.class_idx;
			namet_idx = item->info.cp_method.name_and_type_idx;
		}else if(strcmp (cp_name, "FieldRef") == 0){
			class_idx = item->info.cp_field.class_idx;
			namet_idx = item->info.cp_field.name_and_type_idx;				
		}else if(strcmp (cp_name, "InterfaceMethodRef") == 0){
			class_idx = item->info.cp_interface.class_idx;
			namet_idx = item->info.cp_interface.name_and_type_idx;				
		}

		class_str = r_bin_java_get_name_from_cp_item_list(cp_items, class_idx);	
		namet_str = r_bin_java_get_item_name_from_cp_item_list(cp_items, item);
		if (class_str == NULL)
			class_str = empty;
		if (namet_str == NULL)
			namet_str = empty;
		
		sprintf (str, "%s %s", class_str, namet_str);
		
		if (class_str != empty)
			free(class_str);
		if (namet_str != empty)
			free(namet_str);
	} else if (strcmp (cp_name, "String") == 0) {
		string_str = r_bin_java_get_utf8_from_cp_item_list(cp_items, item->info.cp_string.string_idx); 
		if (string_str){
			sprintf (str, "\"%s\"", string_str);
			free(string_str);	
		}else
			sprintf (str, "\"%s\"", empty);

		
	} else if (strcmp (cp_name, "Utf8") == 0) {
		sprintf (str, "\"%s\"", item->info.cp_utf8.bytes);
	} else if (strcmp (cp_name, "Long") == 0) {
		sprintf (str, "0x%llx", rbin_java_raw_to_long (item->info.cp_long.bytes.raw,0));
	} else if (strcmp (cp_name, "Double") == 0) {
		sprintf (str, "%f", rbin_java_raw_to_double (item->info.cp_double.bytes.raw,0));
	} else if (strcmp (cp_name, "Integer") == 0) {
		sprintf (str, "0x%08x", R_BIN_JAVA_UINT (item->info.cp_integer.bytes.raw,0));
	} else if (strcmp (cp_name, "Float") == 0) {
		sprintf (str, "%f", R_BIN_JAVA_FLOAT (item->info.cp_float.bytes.raw,0));
	} else if (strcmp (cp_name, "NameAndType") == 0) {
		sprintf (str, "Name: 0x%04x Type: 0x%04x", item->info.cp_name_and_type.name_idx, item->info.cp_name_and_type.descriptor_idx);
	}  else{ 
		strcpy (str, "(null)");
	}
	return 0;
}

int java_print_opcode(ut64 addr, int idx, const ut8 *bytes, char *output, int outlen) {
	char arg[1024];

	switch (java_ops[idx].byte) {
	case 0x12:
	case 0x13:
	case 0x14:
		java_resolve (bytes[1]-1, arg);
		snprintf (output, outlen, "%s %s", java_ops[idx].name, arg);
		return java_ops[idx].size;
	case 0x99: // ifeq
	case 0x9a: // ifne
	case 0x9b: // iflt
	case 0x9c: // ifge
	case 0x9d: // ifgt
	case 0x9e: // ifle
	case 0x9f: // if_icmpeq
	case 0xa0: // if_icmpne
	case 0xa1: // if_icmplt
	case 0xa2: // if_icmpge
	case 0xa3: // if_icmpgt
	case 0xa4: // if_icmple
	case 0xa5: // if_acmpne
	case 0xa6: // if_acmpne
	case 0xa7: // goto
	case 0xa8: // jsr
		snprintf (output, outlen, "%s 0x%08"PFMT64x, java_ops[idx].name,
			addr+(int)(short)USHORT (bytes, 1));
		return java_ops[idx].size;
	case 0xb2: // getstatic
	case 0xb6: // invokevirtual
	case 0xb7: // invokespecial
	case 0xb8: // invokestatic
	case 0xb9: // invokeinterface
	case 0xba: // invokedynamic
		java_resolve ((int)USHORT (bytes, 1)-1, arg);
		snprintf (output, outlen, "%s %s", java_ops[idx].name, arg);
		return java_ops[idx].size;
	}

	/* process arguments */
	switch (java_ops[idx].size) {
	case 1: snprintf (output, outlen, "%s", java_ops[idx].name);
		break;
	case 2: snprintf (output, outlen, "%s %d", java_ops[idx].name, bytes[1]);
		break;
	case 3: snprintf (output, outlen, "%s 0x%x 0x%x", java_ops[idx].name, bytes[0], bytes[1]);
		break;
	case 5: snprintf (output, outlen, "%s %d", java_ops[idx].name, bytes[1]);
		break;
	}
	return java_ops[idx].size;
}

R_API int r_java_disasm(ut64 addr, const ut8 *bytes, char *output, int outlen) {
	int i;
	// TODO: replace loop for direct array index
	for (i = 0; java_ops[i].name != NULL; i++)
		if (bytes[0] == java_ops[i].byte)
			return java_print_opcode (addr, i, bytes, output, outlen);
	return -1;
}

R_API int r_java_assemble(ut8 *bytes, const char *string) {
	char name[128];
	int a,b,c,d;
	int i;

	sscanf (string, "%s %d %d %d %d", name, &a, &b, &c, &d);
	for (i = 0; java_ops[i].name != NULL; i++)
		if (!strcmp (name, java_ops[i].name)) {
			bytes[0] = java_ops[i].byte;
			switch (java_ops[i].size) {
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

#if 0
unsigned short read_short(FILE *fd) {
	unsigned short sh = 0;
	fread (&sh, 2, 1, fd);
	return r_num_ntohs (sh);
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

static void check_eof(FILE *fd) {
	if (feof (fd)) {
		fprintf(stderr, "Unexpected eof\n");
		// XXX cannot exit on a library!!
		exit(0);
	}
}

int java_classdump(const char *file, int verbose) {
	RBinJavaClass2 cf2;
	unsigned short sz, sz2;
	int this_class;
	char buf[0x9999];
	int i,j;
	FILE *fd = fopen(file, "rb");

	if (fd == NULL)
		return -1;

	/* start parsing */
	fread (&cf, 10, 1, fd); //sizeof(struct classfile), 1, fd);
	if (memcmp (cf.cafebabe, "\xCA\xFE\xBA\xBE", 4)) {
		eprintf ("java_classdump: Invalid header\n");
		return -1;
	}
	javasm_init ();

	/* show class version information */
	V printf ("Version: 0x%02x%02x 0x%02x%02x\n",
		cf.major[1],cf.major[0], cf.minor[1],cf.minor[0]);

	cf.cp_count = r_num_ntohs(cf.cp_count);
	if (cf.major[0]==cf.major[1] && cf.major[0]==0) {
		eprintf ("Oops. this is a Mach-O\n");
		return 0;
	}
	
	cf.cp_count--;
	V printf ("ConstantPoolCount %d\n", cf.cp_count);
	cp_items = malloc (sizeof (struct cp_item)*(cf.cp_count+1));
	for (i=0;i<cf.cp_count;i++) {
		struct constant_t *c;
		fread (buf, 1, 1, fd);
		c = NULL;
		for (j=0; r_bin_java_constants[j].name; j++) {
			if (r_bin_java_constants[j].tag == buf[0])  {
				c = &r_bin_java_constants[j];
				break;
			}
		}
		if (c == NULL) {
			eprintf ("Invalid tag '%d'\n", buf[0]);
			return 0;
		}
		V eprintf (" %3d %s: ", i+1, c->name);

		/* store constant pool item */
		strcpy (cp_items[i].name, c->name);
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

	fread (&cf2, sizeof (RBinJavaClass2), 1, fd);
	check_eof(fd);
	V printf("Access flags: 0x%04x\n", cf2.access_flags);
	this_class = r_num_ntohs (cf2.this_class);
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
#endif
