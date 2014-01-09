/* radare - LGPL - Copyright 2007-2014 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_list.h>
#include <r_anal.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "code.h"
#include "class.h"

#define V if (verbose)

#define IFDBG if(0)

static ut8 IN_SWITCH_OP = 0;
typedef struct current_table_switch_t {
	ut64 addr;
	int def_jmp;
	int min_val;
	int max_val;
	int cur_val;
} CurrentTableSwitch;

static CurrentTableSwitch SWITCH_OP;
static RBinJavaObj *BIN_OBJ = NULL;

R_API void r_java_set_obj(RBinJavaObj *obj) {
	// eprintf ("SET CP (%p) %d\n", cp, n);
	BIN_OBJ = obj;
}

static char * java_resolve_with_space(int idx) {
	return java_resolve(idx, 1); 
}

static char * java_resolve_without_space(int idx) {
	return java_resolve(idx, 0); 
}

static char * java_resolve(int idx, ut8 space_bn_name_type) {
	// TODO XXX FIXME add a size parameter to the str when it is passed in
	RBinJavaCPTypeObj *item = NULL, *item2 = NULL;
	char *class_str = NULL, 
		 *name_str = NULL, 
		 *desc_str = NULL,
		 *string_str = NULL, 
		 *empty = "",
		 *cp_name = NULL,
		 *cp_name2 = NULL,
		 *str = NULL;

   	int memory_alloc = 0;

	if (BIN_OBJ && BIN_OBJ->cp_count < 1 ) {
		//javasm_init(BIN_OBJ);
		return NULL;
	}
	
	item = (RBinJavaCPTypeObj *) r_bin_java_get_item_from_bin_cp_list (BIN_OBJ, idx);
	
	if (item) {
		cp_name = ((RBinJavaCPTypeMetas *) item->metas->type_info)->name;
		IFDBG eprintf("java_resolve Resolved: (%d) %s\n", idx, cp_name);
	} else {
		str = malloc (512);
		if (str)
			snprintf (str,512,  "(%d) INVALID CP_OBJ", idx);		
		
		return str;
	}

	cp_name = ((RBinJavaCPTypeMetas *) item->metas->type_info)->name;

	if ( strcmp (cp_name, "Class") == 0 ) {
		item2 = (RBinJavaCPTypeObj *) r_bin_java_get_item_from_bin_cp_list (BIN_OBJ, idx);
		
		//str = r_bin_java_get_name_from_bin_cp_list (BIN_OBJ, idx-1);
		class_str = empty;
		class_str = r_bin_java_get_item_name_from_bin_cp_list (BIN_OBJ, item);	
		
		if (!class_str)
			class_str = empty;

		name_str = r_bin_java_get_item_name_from_bin_cp_list (BIN_OBJ, item2);	
		if (!name_str)
			name_str = empty;

		desc_str = r_bin_java_get_item_desc_from_bin_cp_list (BIN_OBJ, item2);			
		if (!desc_str)
			desc_str = empty;

		memory_alloc = strlen (class_str) + strlen (name_str) + strlen (desc_str) + 3;
		
		if (memory_alloc)
			str = malloc (memory_alloc);
		
		if (str && !space_bn_name_type)
			snprintf (str, memory_alloc, "%s%s", name_str, desc_str);
		else if (str && space_bn_name_type)
			snprintf (str, memory_alloc, "%s %s", name_str, desc_str);

		
		if (class_str != empty)
			free (class_str);
		
		if (name_str != empty)
			free (name_str);
		if (desc_str != empty)
			free (desc_str);

	}else if ( strcmp (cp_name, "MethodRef") == 0 ||
		 strcmp (cp_name, "FieldRef") == 0 || 
		 strcmp (cp_name, "InterfaceMethodRef") == 0) {
				
		/*
		 *  The MethodRef, FieldRef, and InterfaceMethodRef structures
		 */

		class_str = r_bin_java_get_name_from_bin_cp_list (BIN_OBJ, item->info.cp_method.class_idx);	
		if (!class_str)
			class_str = empty;

		name_str = r_bin_java_get_item_name_from_bin_cp_list (BIN_OBJ, item);	
		if (!name_str)
			name_str = empty;

		desc_str = r_bin_java_get_item_desc_from_bin_cp_list (BIN_OBJ, item);			
		if (!desc_str)
			desc_str = empty;

		memory_alloc = strlen (class_str) + strlen (name_str) + strlen (desc_str) + 3;
		
		if (memory_alloc)
			str = malloc (memory_alloc);
		
		if (str && !space_bn_name_type)
			snprintf (str, memory_alloc, "%s/%s%s", class_str, name_str, desc_str);
		else if (str && space_bn_name_type)
			snprintf (str, memory_alloc, "%s/%s %s", class_str, name_str, desc_str);


		if (class_str != empty)
			free (class_str);
		if (name_str != empty)
			free (name_str);
		if (desc_str != empty)
			free (desc_str);

	} else if (strcmp (cp_name, "String") == 0) {
		string_str = r_bin_java_get_utf8_from_bin_cp_list (BIN_OBJ, item->info.cp_string.string_idx); 
		str = NULL;

		IFDBG eprintf("java_resolve String got: (%d) %s\n", item->info.cp_string.string_idx, string_str);
		if (!string_str)
			string_str = empty;

		memory_alloc = strlen (string_str) + 3;
		
		if (memory_alloc)
			str = malloc (memory_alloc);

		
		if (str) {
			snprintf (str, memory_alloc, "\"%s\"", string_str);
		}
		IFDBG eprintf("java_resolve String return: %s\n", str);
		if (string_str != empty)
			free (string_str);

		
	} else if (strcmp (cp_name, "Utf8") == 0) {
		str = malloc (item->info.cp_utf8.length+3);
		if (str) {
			snprintf (str, item->info.cp_utf8.length+3, "\"%s\"", item->info.cp_utf8.bytes);	
		}
	} else if (strcmp (cp_name, "Long") == 0) {
		str = malloc (34);
		if (str) {
			snprintf (str, 34, "0x%llx", rbin_java_raw_to_long (item->info.cp_long.bytes.raw,0));
		}
	} else if (strcmp (cp_name, "Double") == 0) {
		str = malloc (1000);
		if (str) {
			snprintf (str, 1000, "%f", rbin_java_raw_to_double (item->info.cp_double.bytes.raw,0));
		}
	} else if (strcmp (cp_name, "Integer") == 0) {
		str = malloc (34);
		if (str) {
			snprintf (str, 34, "0x%08x", R_BIN_JAVA_UINT (item->info.cp_integer.bytes.raw,0));
		}
	} else if (strcmp (cp_name, "Float") == 0) {
		str = malloc (34);
		if (str) {
			snprintf (str, 34, "%f", R_BIN_JAVA_FLOAT (item->info.cp_float.bytes.raw,0));
		}
	} else if (strcmp (cp_name, "NameAndType") == 0) {
		str = malloc (64);
		if (str) {
			
			name_str = r_bin_java_get_item_name_from_bin_cp_list (BIN_OBJ, item);	
			if (!name_str)
				name_str = empty;

			desc_str = r_bin_java_get_item_desc_from_bin_cp_list (BIN_OBJ, item);			
			if (!desc_str)
				desc_str = empty;

			memory_alloc = strlen (name_str) + strlen (desc_str) + 3;
			
			if (memory_alloc)
				str = malloc (memory_alloc);
			
			if (str && !space_bn_name_type)
				snprintf (str, memory_alloc, "%s%s", name_str, desc_str);
			else if (str && space_bn_name_type)
				snprintf (str, memory_alloc, "%s %s", name_str, desc_str);
			
			if (name_str != empty)
				free (name_str);
			if (desc_str != empty)
				free (desc_str);
		}
	}  else { 
		str = malloc (16);
		if (str) {
			snprintf (str, 16, "(null)");
		}
	}
	return str;
}

int java_print_opcode(ut64 addr, int idx, const ut8 *bytes, char *output, int outlen) {
	char *arg = NULL; //(char *) malloc (1024);
	
	ut32 val_one = 0,
		val_two = 0;

	ut8 op_byte = java_ops[idx].byte;

	if (IN_SWITCH_OP) {
		ut32 jmp = (ut32)(UINT (bytes, 0)) + SWITCH_OP.addr;
		ut32 ccase = SWITCH_OP.cur_val + SWITCH_OP.min_val; 
		snprintf(output, outlen, "case %d: goto 0x%04x", ccase, jmp);
		if ( ccase+1 > SWITCH_OP.max_val) IN_SWITCH_OP = 0;
		SWITCH_OP.cur_val++;
		return 4;
	}

	
	switch (op_byte) {

		case 0x10: // "bipush"
			snprintf (output, outlen, "%s %d", java_ops[idx].name, (char) bytes[1]);
			return java_ops[idx].size;			
		case 0x11:
			snprintf (output, outlen, "%s %d", java_ops[idx].name, (int)USHORT (bytes, 1));
			return java_ops[idx].size;		
		
	    case 0x15: // "iload" 
		case 0x16: // "lload"
		case 0x17: // "fload"
		case 0x18: // "dload" 
		case 0x19: // "aload"
		case 0x37: // "lstore"
		case 0x38: // "fstore"
		case 0x39: // "dstore"
		case 0x3a: // "astore"
		case 0xbc: // "newarray" 
	    case 0xa9: // ret <var-num>
			snprintf (output, outlen, "%s %d", java_ops[idx].name, bytes[1]);
			return java_ops[idx].size;

		case 0x12: // ldc
			arg = java_resolve_without_space ((ut16)bytes[1]);				
			if (arg) {
				snprintf (output, outlen, "%s %s", java_ops[idx].name, arg);
				free (arg);
			}else {
				snprintf (output, outlen, "%s %s", java_ops[idx].name, "\0");
			}
			return java_ops[idx].size;		
		case 0x13:
		case 0x14:
			arg = java_resolve_without_space ((int)USHORT (bytes, 1));				
			if (arg) {
				snprintf (output, outlen, "%s %s", java_ops[idx].name, arg);
				free (arg);
			}else {
				snprintf (output, outlen, "%s %s", java_ops[idx].name, "\0");
			}
			return java_ops[idx].size;

		case 0x84: // iinc
			val_one = (ut32)bytes[1];
			val_two = (ut32) bytes[2];
			snprintf (output, outlen, "%s %d %d", java_ops[idx].name, val_one, val_two);
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
			snprintf (output, outlen, "%s 0x%04"PFMT64x, java_ops[idx].name,
				addr+(int)(short)USHORT (bytes, 1));
			return java_ops[idx].size;
		// XXX - Figure out what constitutes the [<high>] value
		case 0xab: // tableswitch
		case 0xaa: // tableswitch
			{
				// XXX - This is a hack, need a better approach to getting the 
				// disassembly
				ut8 sz = (4 - (addr+1) % 4) + (addr+1)  % 4;
				memset(&SWITCH_OP, 0, sizeof (SWITCH_OP));
				IN_SWITCH_OP = 1;
				SWITCH_OP.addr = addr;
				SWITCH_OP.def_jmp = (ut32)(UINT (bytes, sz));
				SWITCH_OP.min_val = (ut32)(UINT (bytes, sz + 4));
				SWITCH_OP.max_val = (ut32)(UINT (bytes, sz + 8));
				sz += 12;
				snprintf (output, outlen, "%s default: 0x%04"PFMT64x, java_ops[idx].name,
					SWITCH_OP.def_jmp+addr);
				return sz; 
			}
		case 0xb6: // invokevirtual
		case 0xb7: // invokespecial
		case 0xb8: // invokestatic
		case 0xb9: // invokeinterface
		case 0xba: // invokedynamic
			arg = java_resolve_without_space ((int)USHORT (bytes, 1));					
			if (arg) {
				snprintf (output, outlen, "%s %s", java_ops[idx].name, arg);
				free (arg);
			}else {
				snprintf (output, outlen, "%s %s", java_ops[idx].name, "WTF?!?" );
			}
			return java_ops[idx].size;
		case 0xb2: // getstatic
		case 0xb3: // putstatic
		case 0xb4: // getfield
		case 0xb5: // putfield
		case 0xbb: // new
		case 0xbd: // anewarray
		case 0xc0: // checkcast
		case 0xc1: // instance of
			arg = java_resolve_with_space ((int)USHORT (bytes, 1));					
			if (arg) {
				snprintf (output, outlen, "%s %s", java_ops[idx].name, arg);
				free (arg);
			}else {
				snprintf (output, outlen, "%s %s", java_ops[idx].name, "WTF?!?" );
			}
			return java_ops[idx].size;
		}

	/* process arguments */
	switch (java_ops[idx].size) {
	case 1: snprintf (output, outlen, "%s", java_ops[idx].name);
		break;
	case 2: snprintf (output, outlen, "%s %d", java_ops[idx].name, bytes[1]);
		break;
	case 3: snprintf (output, outlen, "%s 0x%04x 0x%04x", java_ops[idx].name, bytes[0], bytes[1]);
		break;
	case 5: snprintf (output, outlen, "%s %d", java_ops[idx].name, bytes[1]);
		break;
	}

	return java_ops[idx].size;
}

R_API int r_java_disasm(ut64 addr, const ut8 *bytes, char *output, int outlen) {
	//r_cons_printf ("r_java_disasm (allowed %d): 0x%02x, 0x%0x.\n", outlen, bytes[0], addr);
	return java_print_opcode (addr, bytes[0], bytes, output, outlen);
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
