/* radare - LGPL - Copyright 2007-2013 - pancake */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include "class.h"
#include <r_types.h>
#include <r_util.h>

#undef IFDBG
#define IFDBG if(0)

// pool count = 0x52

static RBinJavaConstant r_bin_java_constants[] = {
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

// NOTE: must be initialized for safe use
static struct r_bin_java_cp_item_t cp_null_item = {0};

static ut16 read_short(RBinJavaObj *bin) {
	ut16 sh = 0;
	r_buf_read_at (bin->b, R_BUF_CUR, (ut8*)&sh, 2);
	return R_BIN_JAVA_SWAPUSHORT (sh);
}

static void addrow (RBinJavaObj *bin, int addr, int line) {
	int n = bin->lines.count++;
	// XXX. possible memleak
	bin->lines.addr = realloc (bin->lines.addr, sizeof(int)*n+1);
	bin->lines.addr[n] = addr;
	bin->lines.line = realloc (bin->lines.line, sizeof(int)*n+1);
	bin->lines.line[n] = line;
}

static struct r_bin_java_cp_item_t* get_CP(RBinJavaObj *bin, int i) {
	return (i<0||i>bin->cf.cp_count)? &cp_null_item: &bin->cp_items[i];
}

static int attributes_walk(RBinJavaObj *bin, struct r_bin_java_attr_t *attr, int sz2, int fields) {
	ut32 symaddr = 0;
	char buf[0xffff+1]; // that's kinda ugly :)
	int sz3, sz4;
	int j=0,k;
	char *name;

	for (j=0; j<sz2; j++) {
		if (r_buf_read_at (bin->b, R_BUF_CUR, (ut8*)buf, 6) != 6) {
			eprintf ("Cannot read 6 bytes in class file\n");
			return R_FALSE;
		}
		attr->name_idx = R_BIN_JAVA_USHORT (buf,0);
		name = get_CP (bin, attr->name_idx-1)->value;
		if (!name) {
			eprintf ("Attribute name is null\n");
			return R_FALSE;
		}
		// XXX: if name is null.. wat?
		attr->name = strdup (name? name: "");
		name = (get_CP (bin, attr->name_idx-1))->value;//cp_items[R_BIN_JAVA_USHORT(buf,0)-1].value;
		IFDBG printf("   %2d: Name Index: %d (%s)\n", j, attr->name_idx, name);
		// TODO add comment with constant pool index
		sz3 = R_BIN_JAVA_UINT (buf, 2);
		if (sz3<0) {
			// XXX: this is a hack. this parser must be fixed
			sz3 = -sz3;
		}
		if (fields) {
			attr->type = R_BIN_JAVA_TYPE_FIELD;
		} else if (sz3 > 0) {
			attr->length = sz3;
			IFDBG printf ("     Length: %d\n", sz3); //R_BIN_JAVA_UINT(buf, 2));
			if (!name) {
				IFDBG printf ("**ERROR ** Cannot identify attribute name into constant pool\n");
				continue;
			}
			if (!strcmp (name, "Code")) {
				attr->type = R_BIN_JAVA_TYPE_CODE;
				r_buf_read_at (bin->b, R_BUF_CUR, (ut8*)buf, 8);

				attr->info.code.max_stack = R_BIN_JAVA_USHORT(buf, 0);
				IFDBG printf("      Max Stack: %d\n", attr->info.code.max_stack);
				attr->info.code.max_locals = R_BIN_JAVA_USHORT(buf, 2);
				IFDBG printf("      Max Locals: %d\n", attr->info.code.max_locals);
				attr->info.code.code_length = R_BIN_JAVA_UINT(buf, 4);
				IFDBG printf("      Code Length: %d\n", attr->info.code.code_length);
				attr->info.code.code_offset = (ut64)bin->b->cur;
				IFDBG printf("      Code At Offset: 0x%08"PFMT64x"\n", (ut64)attr->info.code.code_offset);

				r_buf_read_at (bin->b, R_BUF_CUR, (ut8*)buf, R_BIN_JAVA_UINT (buf, 4)); // READ CODE
				sz4 = read_short (bin);
				attr->info.code.exception_table_length = sz4;
				IFDBG printf("      Exception table length: %d\n",
					attr->info.code.exception_table_length);
				for (k=0; k<sz4; k++) {
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

				if (sz4>0) {
					attr->attributes = malloc(1+sz4 * sizeof(struct r_bin_java_attr_t));
					attributes_walk(bin, attr->attributes, sz4, fields);
				}
			} else
			if (!strcmp (name, "LocalVariableTypeTable")) {
				eprintf ("TODO: LOCAL VARIABLE TYPE TABLE\n");
				sz4 = (unsigned int)read_short (bin);
			} else
			if (!strcmp (name, "LineNumberTable")) {
				attr->type = R_BIN_JAVA_TYPE_LINENUM;
				sz4 = (unsigned int)read_short (bin);
				attr->info.linenum.table_length = sz4;
				IFDBG printf("     Table Length: %d\n", attr->info.linenum.table_length);
//eprintf ("line.%d.sym=%s\n", bin->midx, bin->methods[bin->midx].name);
				symaddr = bin->methods[bin->midx].attributes->info.code.code_offset;
				for (k=0; k<sz4; k++) {
					r_buf_read_at (bin->b, R_BUF_CUR, (ut8*)buf, 4);
					attr->info.linenum.start_pc = R_BIN_JAVA_USHORT (buf, 0);
					//eprintf ("     %2d: start_pc:    0x%04x\n", k, attr->info.linenum.start_pc);
					attr->info.linenum.line_number = R_BIN_JAVA_USHORT (buf, 2);
					//eprintf ("         line_number: %d\n", attr->info.linenum.line_number);
					addrow (bin, symaddr + attr->info.linenum.start_pc, attr->info.linenum.line_number);
#if 0
					eprintf ("line.%d.%d.%d=%d\n", bin->midx, k,
							attr->info.linenum.line_number,
							attr->info.linenum.start_pc);
#endif
				}
			} else
			if (!strcmp (name, "StackMapTable")) {
				r_buf_read_at (bin->b, R_BUF_CUR, (ut8*)buf, 2); // XXX: this is probably wrong
				//printf("     StackMapTable: %d\n", USHORT(buf, 0));
			} else
			if (!strcmp (name, "LocalVariableTable")) {
				int i;
				ut32 lvtl = (ut32)read_short (bin);
//eprintf ("local.%d.sym=%s\n", bin->midx, bin->methods[bin->midx].name);
				for (i=0; i<lvtl; i++) {
					int start_pc = start_pc = read_short (bin);
					int length = length = read_short (bin);
					int name_idx = name_idx = read_short (bin);
					int desc_idx = desc_idx = read_short (bin);
					int index = index = read_short (bin);

#if 0
					const char *name = get_CP (bin, name_idx-1)->value;
					const char *desc = get_CP (bin, desc_idx-1)->value;
eprintf ("local.%d.%d.type=%s\n", bin->midx, i, desc);
eprintf ("local.%d.%d.name=%s\n", bin->midx, i, name);
#endif
				}
			} else
			if (!strcmp (name, "ConstantValue")) {
				attr->type = R_BIN_JAVA_TYPE_CONST;
				r_buf_read_at (bin->b, R_BUF_CUR, (ut8*)buf, 2);
	#if 0
				printf("     Name Index: %d\n", R_BIN_JAVA_USHORT(buf, 0)); // %s\n", R_BIN_JAVA_USHORT(buf, 0), cp_items[R_BIN_JAVA_USHORT(buf,0)-1].value);
				printf("     AttributeLength: %d\n", R_BIN_JAVA_UINT(buf, 2));
	#endif
				attr->info.const_value_idx = R_BIN_JAVA_USHORT(buf, 0);
				IFDBG printf ("     ConstValueIndex: %d\n", attr->info.const_value_idx);
			} else {
				//if (*name) eprintf ("** ERROR ** Unknown section '%s'\n", name);
				IFDBG eprintf ("** ERROR ** Unknown section name\n");
			}
		}
	}
	return R_TRUE;
}

static int javasm_init(RBinJavaObj *bin) {
	RBinJavaConstant *c;
	int i, j, bufsz;
	ut16 sz, sz2;
	char *buf;

	/* Initialize structs */
	bin->fields = NULL;
	bin->methods = NULL;
	bin->cp_items = NULL;
	bin->lines.count = 0;

	/* Initialize cp_null_item */
	cp_null_item.tag = -1;
	strncpy (cp_null_item.name, "(null)", sizeof (cp_null_item.name)-1);
	cp_null_item.value = strdup ("(null)"); // strdup memleak wtf

	/* start parsing */
	r_buf_read_at (bin->b, R_BUF_CUR, (ut8*)&bin->cf, 10);
	if (memcmp (bin->cf.cafebabe, "\xCA\xFE\xBA\xBE", 4)) {
		eprintf ("javasm_init: Invalid header (%02x %02x %02x %02x)\n",
				bin->cf.cafebabe[0], bin->cf.cafebabe[1],
				bin->cf.cafebabe[2], bin->cf.cafebabe[3]);
		return R_FALSE;
	}

	bin->cf.cp_count = R_BIN_JAVA_SWAPUSHORT (bin->cf.cp_count);
	if (bin->cf.major[0]==bin->cf.major[1] && bin->cf.major[0]==0) {
		eprintf ("Java CLASS with MACH0 header?\n");
		return R_FALSE;
	}
	bin->cf.cp_count--;

	IFDBG printf ("ConstantPoolCount %d\n", bin->cf.cp_count);
	bin->cp_items = malloc (sizeof (RBinJavaCpItem)*(bin->cf.cp_count+1));
//eprintf ("CP = %d = %p\n", bin->cf.cp_count, bin->cp_items);
	bufsz = 4024;
	buf = malloc (bufsz);
	for (i=0; i<bin->cf.cp_count; i++) {
		r_buf_read_at (bin->b, R_BUF_CUR, (ut8*)buf, 1);
		c = NULL;
		for (j=0; r_bin_java_constants[j].name; j++) {
			if (r_bin_java_constants[j].tag == buf[0])  {
				c = &r_bin_java_constants[j];
				break;
			}
		}
		if (c == NULL) {
			eprintf ("Invalid tag '%d' at offset 0x%08"PFMT64x"\n",
				*buf, (ut64)bin->b->cur);
			return R_FALSE;
		}
		IFDBG printf (" %3d %s: ", i+1, c->name);

		/* store constant pool item */
		strncpy (bin->cp_items[i].name, c->name,
			sizeof (bin->cp_items[i].name)-1);
		bin->cp_items[i].ord = i+1;
		bin->cp_items[i].tag = c->tag;
		bin->cp_items[i].value = NULL; // no string by default
		bin->cp_items[i].off = bin->b->cur-1;

		/* read bytes */
		switch (c->tag) {
		case 1: // Utf8 string
			r_buf_read_at (bin->b, R_BUF_CUR, (ut8*)buf, 2);
			sz = R_BIN_JAVA_USHORT (buf, 0);
			bin->cp_items[i].length = sz;
			bin->cp_items[i].off += 3;
			if (sz>=bufsz) {
				free (buf);
				buf = malloc (sz);
				if (!buf) {
					eprintf ("ETOOBIGSTR\n");
					break;
				}
			}
			r_buf_read_at (bin->b, R_BUF_CUR, (ut8*)buf, sz);
			buf[sz] = '\0';
//eprintf ("\n %d ((%s))\n", i+1, buf);
			break;
		default:
//eprintf ("\n %d ((%s))\n", i+1, c->name);
			r_buf_read_at (bin->b, R_BUF_CUR, (ut8*)buf, c->len);
		}

		memcpy (bin->cp_items[i].bytes, buf, 5);

		/* parse value */
		switch (c->tag) {
		case 1:
			// eprintf ("%s\n", buf);
			bin->cp_items[i].value = strdup (buf);
			break;
		case 3:
			IFDBG eprintf ("integer = %d\n", R_BIN_JAVA_UINT (buf, 0));
			break;
		case 5:
		case 6:
			IFDBG eprintf ("longlong %d\n", R_BIN_JAVA_UINT (buf, 0));
			IFDBG eprintf ("longlong %d\n", R_BIN_JAVA_UINT (buf, 4));
			// 64bit values
			i++; // skip one cp item
			break;
		case 7:
			IFDBG eprintf ("class ref %d\n", R_BIN_JAVA_USHORT (buf, 0));
			break;
		case 8:
			IFDBG printf("string ptr %d\n", R_BIN_JAVA_USHORT (buf, 0));
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
			printf ("UNKNOWN TAG %d\n", R_BIN_JAVA_UINT (buf, 40));
		}
	}
	free (buf);
	buf = NULL;

	r_buf_read_at (bin->b, R_BUF_CUR, (ut8*)&bin->cf2,
		sizeof(struct r_bin_java_classfile2_t));
	IFDBG printf ("Access flags: 0x%04x\n", bin->cf2.access_flags);
	bin->cf2.this_class = R_BIN_JAVA_SWAPUSHORT (bin->cf2.this_class);
	IFDBG printf ("This class: %d\n", bin->cf2.this_class);
	//printf("This class: %d (%s)\n", R_BIN_JAVA_SWAPUSHORT(bin->cf2.this_class), bin->cp_items[R_BIN_JAVA_SWAPUSHORT(bin->cf2.this_class)-1].value); // XXX this is a double pointer !!1
	//printf("Super class: %d (%s)\n", R_BIN_JAVA_SWAPUSHORT(bin->cf2.super_class), bin->cp_items[R_BIN_JAVA_SWAPUSHORT(bin->cf2.super_class)-1].value);
	sz = read_short (bin);

	/* TODO: intefaces*/
	IFDBG printf("Interfaces count: %d\n", sz);
	if (sz>0) {
		bufsz = sz*2;
		buf = malloc (bufsz+8);
		r_buf_read_at (bin->b, R_BUF_CUR, (ut8*)buf, bufsz);
		sz = read_short (bin);
		for (i=0;i<sz;i++)
			eprintf ("Interfaces: TODO (%d)\n", sz);
	} else buf = malloc (128);

	sz = read_short (bin);
	bin->fields_count = sz;
	IFDBG printf ("Fields count: %d\n", sz);
	if (sz>0) {
		bin->fields = malloc (1+sz * sizeof(struct r_bin_java_fm_t));
		for (i=0; i<sz; i++) {
			r_buf_read_at (bin->b, R_BUF_CUR, (ut8*)buf, 8);
			bin->fields[i].flags = R_BIN_JAVA_USHORT (buf, 0);
			IFDBG printf("%2d: Access Flags: %d\n", i, bin->fields[i].flags);
			bin->fields[i].name_idx = R_BIN_JAVA_USHORT(buf, 2);
			bin->fields[i].name = r_str_dup (NULL, (get_CP (bin, R_BIN_JAVA_USHORT(buf,2)-1))->value);
			IFDBG printf("    Name Index: %d (%s)\n", bin->fields[i].name_idx, bin->fields[i].name);
			bin->fields[i].descriptor_idx = R_BIN_JAVA_USHORT(buf, 4);
			bin->fields[i].descriptor = NULL;
			IFDBG printf("    Descriptor Index: %d\n", bin->fields[i].descriptor_idx); //, bin->cp_items[R_BIN_JAVA_USHORT(buf, 4)-1].value);
			sz2 = R_BIN_JAVA_USHORT(buf, 6);
			bin->fields[i].attr_count = sz2;
			IFDBG printf("    field Attributes Count: %d\n", sz2);
			if (sz2 > 0) {
				bin->fields[i].attributes = malloc(1+sz2 * sizeof(struct r_bin_java_attr_t));
				for (j=0;j<sz2;j++)
					if (!attributes_walk(bin, &bin->fields[i].attributes[j], sz2, 1))
						return R_TRUE; // false?
			}
		}
	}

	sz = read_short (bin);
	bin->methods_count = sz;
	IFDBG eprintf ("Methods count: %d\n", sz);
	if (sz>0) {
		int methods_sz = sz * sizeof(struct r_bin_java_fm_t);
		bin->methods = malloc (methods_sz);
		memset (bin->methods, 0, methods_sz);
		for (i=0; i<sz; i++) {
			r_buf_read_at (bin->b, R_BUF_CUR, (ut8*)buf, 8);

			bin->methods[i].flags = R_BIN_JAVA_USHORT (buf, 0);
			IFDBG printf("%2d: Access Flags: %d\n", i, bin->methods[i].flags);
			bin->methods[i].name_idx = R_BIN_JAVA_USHORT (buf, 2);
#if 0
			bin->methods[i].name = r_str_dup (NULL, (get_CP(bin, R_BIN_JAVA_USHORT(buf, 2)-1))->value);
#else
			{
				struct r_bin_java_cp_item_t *a, *b;
				a = get_CP (bin, R_BIN_JAVA_USHORT (buf, 2)-1);
				b = get_CP (bin, R_BIN_JAVA_USHORT (buf, 2));
				if (a == &cp_null_item || b == &cp_null_item || a->value == NULL || b->value == NULL) {
					bin->methods[i].name = NULL;
					bin->methods[i].name = malloc (32);
					sprintf (bin->methods[i].name, "sym.method_%d", i);
				} else {
					int newlen = strlen (a->value) + strlen (b->value);
					bin->methods[i].name = malloc (newlen+2);
					// XXX: can null ptr here
					snprintf (bin->methods[i].name, newlen, "%s%s", a->value, b->value);
				}
			}
#endif
			bin->midx = i;
			IFDBG printf("    Name Index: %d (%s)\n", bin->methods[i].name_idx, bin->methods[i].name);
			bin->methods[i].descriptor_idx = R_BIN_JAVA_USHORT (buf, 4);
			bin->methods[i].descriptor = r_str_dup (NULL, (get_CP(bin, R_BIN_JAVA_USHORT(buf, 4)-1))->value);
			IFDBG printf("    Descriptor Index: %d (%s)\n", bin->methods[i].descriptor_idx, bin->methods[i].descriptor);

			sz2 = R_BIN_JAVA_USHORT(buf, 6);
			bin->methods[i].attr_count = sz2;
			IFDBG printf("    method Attributes Count: %d\n", sz2);
			if (sz2 > 0) {
				bin->methods[i].attributes = malloc (1+sz2 * sizeof (struct r_bin_java_attr_t));
				for (j=0; j<sz2; j++) {
					if (!attributes_walk (bin, &bin->methods[i].attributes[j], sz2, 0))
						break; // can be false :?
				}
			} else bin->methods[i].attributes = NULL;
		}
	}
	free (buf);
	return R_TRUE;
}

R_API char* r_bin_java_get_version(RBinJavaObj* bin) {
	return r_str_dup_printf ("0x%02x%02x 0x%02x%02x",
			bin->cf.major[1],bin->cf.major[0],
			bin->cf.minor[1],bin->cf.minor[0]);
}

R_API ut64 r_bin_java_get_main(RBinJavaObj* bin) {
	int i, j;
	for (i=0; i < bin->methods_count; i++) {
		if (!strcmp (bin->methods[i].name, "main([Ljava/lang/String;)") || // WTF.. 
				!strcmp (bin->methods[i].name, "main([Ljava/lang/String;)V"))
			for (j=0; j < bin->methods[i].attr_count; j++)
				if (bin->methods[i].attributes[j].type == R_BIN_JAVA_TYPE_CODE)
					return (ut64)bin->methods[i].attributes->info.code.code_offset;
	}
	return 0;
}

R_API ut64 r_bin_java_get_entrypoint(RBinJavaObj* bin) {
	int i, j;
	for (i=0; i < bin->methods_count; i++) {
		if (!strcmp (bin->methods[i].name, "<init>()V"))
			for (j=0; j < bin->methods[i].attr_count; j++)
				if (bin->methods[i].attributes[j].type == R_BIN_JAVA_TYPE_CODE)
					return (ut64)bin->methods[i].attributes->info.code.code_offset;
	}
	return 0;
}

struct r_bin_java_sym_t* r_bin_java_get_symbols(RBinJavaObj* bin) {
	struct r_bin_java_sym_t *symbols;
	int ns, i, j, ctr = 0;
	int symbols_sz = (bin->methods_count + 1) *  sizeof (struct r_bin_java_sym_t);

	if (!(symbols = malloc (symbols_sz)))
		return NULL;
	bin->fsym = 0;
	bin->fsymsz = 0;
	for (i=0; i < bin->methods_count; i++) {
		symbols[i].last = 0;
		if (bin->methods[i].name) {
			strncpy (symbols[ctr].name, bin->methods[i].name, R_BIN_JAVA_MAXSTR);
			symbols[ctr].name[R_BIN_JAVA_MAXSTR-1] = '\0';
#if 0
		} else {
eprintf ("-----------\n");
			sprintf (symbols[ctr].name, "method_%d", i);
			symbols[ctr].offset = (ut64)123; //bin->methods[i].attributes->info.code.code_offset;
			symbols[ctr].size = 456; //bin->methods[i].attributes->info.code.code_length;
			ctr++;
			continue;
#endif
			if (bin->methods[i].attributes) {
				symbols[ctr].offset = (ut64)bin->methods[i].attributes->info.code.code_offset;
				symbols[ctr].size = bin->methods[i].attributes->info.code.code_length;
			} else {
				symbols[ctr].offset = symbols[ctr].size = 0;
				eprintf ("[r2-java-class] Cannot load method attributes for %d (%s)\n", i,
					bin->methods[i].name);
			}
		}
		for (j=0; j < bin->methods[i].attr_count; j++) {
			if (bin->methods[i].attributes[j].type == R_BIN_JAVA_TYPE_CODE) {
				symbols[ctr].offset = (ut64)bin->methods[i].attributes->info.code.code_offset;
				symbols[ctr].size = bin->methods[i].attributes->info.code.code_length;
				if (bin->fsym == 0 || symbols[ctr].offset<bin->fsym)
					bin->fsym = symbols[ctr].offset;
				ns = symbols[ctr].offset + symbols[ctr].size;
				if (ns>bin->fsymsz)
					bin->fsymsz = ns;
				break;
			}
		}
		ctr++;
	}
	bin->fsymsz -= bin->fsym;
	symbols[ctr].last = 1;
	return symbols;
}

struct r_bin_java_str_t* r_bin_java_get_strings(RBinJavaObj* bin) {
	struct r_bin_java_str_t *strings = NULL;
	int i, ctr = 0;

	for (i=0; i<bin->cf.cp_count; i++) {
		if (bin->cp_items[i].tag == 1) {
			if ((strings = realloc(strings, (ctr + 1) * \
				sizeof (RBinJavaString))) == NULL)
				return NULL;
			strings[ctr].offset = (ut64)bin->cp_items[i].off;
			strings[ctr].ordinal = (ut64)bin->cp_items[i].ord;
			strings[ctr].size = (ut64)bin->cp_items[i].length;
			strncpy (strings[ctr].str, bin->cp_items[i].value, R_BIN_JAVA_MAXSTR);
			strings[ctr].last = 0;
			ctr++;
		}
	}
	if (ctr) {
		if (!(strings = realloc (strings, (ctr + 1) * 
				sizeof (RBinJavaString))))
			return NULL;
		strings[ctr].last = 1;
	}
	return strings;
}

R_API void* r_bin_java_free(RBinJavaObj* bin) {
	if (!bin) return NULL;
	if (bin->cp_items) free (bin->cp_items);
	bin->cp_items = NULL;
	if (bin->fields) free (bin->fields);
	bin->fields = NULL;
	if (bin->methods) free (bin->methods);
	bin->methods = NULL;
	if (bin->b) r_buf_free (bin->b);
	bin->b = NULL;
	free (bin);
	return NULL;
}

R_API RBinJavaObj* r_bin_java_new(const char* file) {
	ut8 *buf;
	RBinJavaObj *bin = R_NEW0 (RBinJavaObj);
	bin->file = file;
	if (!(buf = (ut8*)r_file_slurp (file, &bin->size))) 
		return r_bin_java_free (bin);
	bin->b = r_buf_new ();
	if (!r_buf_set_bytes (bin->b, buf, bin->size))
		return r_bin_java_free (bin);
	free (buf);
	if (!javasm_init (bin))
		return r_bin_java_free (bin);
	return bin;
}

R_API RBinJavaObj* r_bin_java_new_buf(RBuffer *buf) {
	RBinJavaObj *bin = R_NEW0 (RBinJavaObj);
	if (!bin) return NULL;
	bin->b = buf;
	bin->size = buf->length;
	buf->cur = 0; // rewind
	if (!javasm_init (bin))
		return r_bin_java_free (bin);
	return bin;
}
