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

#define DO_THE_DBG 0
#define IFDBG if(DO_THE_DBG)

#ifndef R_API
#define R_API
#endif

static void init_switch_op ();
static int enter_switch_op (ut64 addr, const ut8 * bytes);
static int update_switch_op (ut64 addr, const ut8 * bytes);
static int update_bytes_consumed (int sz);
static int handle_switch_op (ut64 addr, const ut8 * bytes, char *output, int outlen );

static ut8 IN_SWITCH_OP = 0;
typedef struct current_table_switch_t {
	ut64 addr;
	int def_jmp;
	int min_val;
	int max_val;
	int cur_val;
} CurrentTableSwitch;

static CurrentTableSwitch SWITCH_OP;
static volatile ut64 BYTES_CONSUMED = 0;
//static RBinJavaObj *BIN_OBJ = NULL;

static void init_switch_op () {
	memset (&SWITCH_OP, 0, sizeof(SWITCH_OP));
}

static int enter_switch_op (ut64 addr, const ut8 * bytes ) {
	ut8 sz = (BYTES_CONSUMED+1) % 4 ? 1 + 4 - (BYTES_CONSUMED+1) % 4: 1; // + (BYTES_CONSUMED+1)  % 4;
	ut8 sz2 = (4 - (addr+1) % 4) + (addr+1)  % 4;
	IFDBG eprintf ("Addr approach: 0x%04x and BYTES_CONSUMED approach: 0x%04"PFMT64x", BYTES_CONSUMED%%4 = 0x%04x\n", sz2, BYTES_CONSUMED, sz);
	init_switch_op ();
	IN_SWITCH_OP = 1;
	SWITCH_OP.addr = addr;
	SWITCH_OP.def_jmp = (int)(UINT (bytes, sz));
	SWITCH_OP.min_val = (int)(UINT (bytes, sz + 4));
	SWITCH_OP.max_val = (int)(UINT (bytes, sz + 8));
	sz += 12;
	return sz;
}

static int update_bytes_consumed (int sz) {
	BYTES_CONSUMED += sz;
	return sz;
}

static int update_switch_op (ut64 addr, const ut8 * bytes) {
	int sz = 4;
	int ccase = SWITCH_OP.cur_val + SWITCH_OP.min_val;
	SWITCH_OP.cur_val++;
	if ( ccase+1 > SWITCH_OP.max_val) IN_SWITCH_OP = 0;
	IFDBG eprintf ("Addr approach: 0x%04"PFMT64x" and BYTES_CONSUMED approach: 0x%04"PFMT64x"\n", addr, BYTES_CONSUMED);
	return update_bytes_consumed(sz);
}

static int handle_switch_op (ut64 addr, const ut8 * bytes, char *output, int outlen ) {
	int sz = 4;
	ut32 jmp = (int)(UINT (bytes, 0)) + SWITCH_OP.addr;
	int ccase = SWITCH_OP.cur_val + SWITCH_OP.min_val;
	snprintf(output, outlen, "case %d: goto 0x%04x", ccase, jmp);

	update_switch_op (addr, bytes);
	return update_bytes_consumed(sz);
}

R_API int java_print_opcode(RBinJavaObj *obj, ut64 addr, int idx, const ut8 *bytes, char *output, int outlen) {
	char *arg = NULL; //(char *) malloc (1024);
	int sz = 0;
	ut32 val_one = 0,
		val_two = 0;

	ut8 op_byte = JAVA_OPS[idx].byte;

	if (IN_SWITCH_OP) {
		return handle_switch_op (addr, bytes, output, outlen );
	}

	IFDBG {
		eprintf ("Handling the following opcode %s expects: %d bytes, BYTES_CONSUMED: 0x%04"PFMT64x"\n",
			JAVA_OPS[idx].name, JAVA_OPS[idx].size, BYTES_CONSUMED);
	}
	switch (op_byte) {

		case 0x10: // "bipush"
			snprintf (output, outlen, "%s %d", JAVA_OPS[idx].name, (char) bytes[1]);
			output[outlen-1] = 0;
			return update_bytes_consumed (JAVA_OPS[idx].size);
		case 0x11:
			snprintf (output, outlen, "%s %d", JAVA_OPS[idx].name, (int)USHORT (bytes, 1));
			output[outlen-1] = 0;
			return update_bytes_consumed (JAVA_OPS[idx].size);

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
			snprintf (output, outlen, "%s %d", JAVA_OPS[idx].name, bytes[1]);
			output[outlen-1] = 0;
			return update_bytes_consumed (JAVA_OPS[idx].size);

		case 0x12: // ldc
			arg = r_bin_java_resolve_without_space (obj, (ut16)bytes[1]);
			if (arg) {
				snprintf (output, outlen, "%s %s", JAVA_OPS[idx].name, arg);
				free (arg);
			}else {
				snprintf (output, outlen, "%s #%d", JAVA_OPS[idx].name, USHORT (bytes, 1));
			}
			output[outlen-1] = 0;
			return update_bytes_consumed (JAVA_OPS[idx].size);
		case 0x13:
		case 0x14:
			arg = r_bin_java_resolve_without_space (obj, (int)USHORT (bytes, 1));
			if (arg) {
				snprintf (output, outlen, "%s %s", JAVA_OPS[idx].name, arg);
				free (arg);
			}else {
				snprintf (output, outlen, "%s #%d", JAVA_OPS[idx].name, USHORT (bytes, 1));
			}
			output[outlen-1] = 0;
			return update_bytes_consumed (JAVA_OPS[idx].size);

		case 0x84: // iinc
			val_one = (ut32)bytes[1];
			val_two = (ut32) bytes[2];
			snprintf (output, outlen, "%s %d %d", JAVA_OPS[idx].name, val_one, val_two);
			output[outlen-1] = 0;
			return update_bytes_consumed (JAVA_OPS[idx].size);


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
			snprintf (output, outlen, "%s 0x%04"PFMT64x, JAVA_OPS[idx].name,
				(addr+(short)USHORT (bytes, 1)));
			output[outlen-1] = 0;
			return update_bytes_consumed (JAVA_OPS[idx].size);
		// XXX - Figure out what constitutes the [<high>] value
		case 0xab: // tableswitch
		case 0xaa: // tableswitch
			sz = enter_switch_op (addr, bytes);
			snprintf (output, outlen, "%s default: 0x%04"PFMT64x, JAVA_OPS[idx].name,
				SWITCH_OP.def_jmp+SWITCH_OP.addr);
			return update_bytes_consumed (sz);
		case 0xb6: // invokevirtual
		case 0xb7: // invokespecial
		case 0xb8: // invokestatic
		case 0xb9: // invokeinterface
		case 0xba: // invokedynamic
			arg = r_bin_java_resolve_without_space (obj, (int)USHORT (bytes, 1));
			if (arg) {
				snprintf (output, outlen, "%s %s", JAVA_OPS[idx].name, arg);
				free (arg);
			}else {
				snprintf (output, outlen, "%s #%d", JAVA_OPS[idx].name, USHORT (bytes, 1) );
			}
			output[outlen-1] = 0;
			return update_bytes_consumed (JAVA_OPS[idx].size);
		case 0xb2: // getstatic
		case 0xb3: // putstatic
		case 0xb4: // getfield
		case 0xb5: // putfield
		case 0xbb: // new
		case 0xbd: // anewarray
		case 0xc0: // checkcast
		case 0xc1: // instance of
			arg = r_bin_java_resolve_with_space (obj, (int)USHORT (bytes, 1));
			if (arg) {
				snprintf (output, outlen, "%s %s", JAVA_OPS[idx].name, arg);
				free (arg);
			} else {
				snprintf (output, outlen, "%s #%d", JAVA_OPS[idx].name, USHORT (bytes, 1) );
			}
			output[outlen-1] = 0;
			return update_bytes_consumed (JAVA_OPS[idx].size);
		}

	/* process arguments */
	switch (JAVA_OPS[idx].size) {
	case 1: snprintf (output, outlen, "%s", JAVA_OPS[idx].name);
		break;
	case 2: snprintf (output, outlen, "%s %d", JAVA_OPS[idx].name, bytes[1]);
		break;
	case 3: snprintf (output, outlen, "%s 0x%04x 0x%04x", JAVA_OPS[idx].name, bytes[0], bytes[1]);
		break;
	case 5: snprintf (output, outlen, "%s %d", JAVA_OPS[idx].name, bytes[1]);
		break;
	}

	return update_bytes_consumed (JAVA_OPS[idx].size);
}

R_API void r_java_new_method () {
	IFDBG eprintf ("Reseting the bytes consumed, they were: 0x%04"PFMT64x".\n", BYTES_CONSUMED);
	IN_SWITCH_OP = 0;
	init_switch_op ();
	BYTES_CONSUMED = 0;
}

R_API void U(r_java_set_obj)(RBinJavaObj *obj) {
	// eprintf ("SET CP (%p) %d\n", cp, n);
	//BIN_OBJ = obj;
}

R_API int r_java_disasm(RBinJavaObj *obj, ut64 addr, const ut8 *bytes, char *output, int outlen) {
	//r_cons_printf ("r_java_disasm (allowed %d): 0x%02x, 0x%0x.\n", outlen, bytes[0], addr);
	return java_print_opcode (obj, addr, bytes[0], bytes, output, outlen);
}

R_API int r_java_assemble(ut8 *bytes, const char *string) {
	char name[128];
	int a,b,c,d;
	int i;

	sscanf (string, "%s %d %d %d %d", name, &a, &b, &c, &d);
	for (i = 0; JAVA_OPS[i].name != NULL; i++)
		if (!strcmp (name, JAVA_OPS[i].name)) {
			bytes[0] = JAVA_OPS[i].byte;
			switch (JAVA_OPS[i].size) {
			case 2: bytes[1] = a; break;
			case 3: bytes[1] = a; bytes[2] = b; break;
			case 5: bytes[1] = a;
				bytes[2] = b;
				bytes[3] = c;
				bytes[4] = d;
				break;
			}
			return JAVA_OPS[i].size;
		}
	return 0;
}
