/* radare - LGPL - Copyright 2007-2026 - pancake */

#include <r_anal.h>
#include "ops.h"
#include "code.h"
#include "class.h"

#define V if (verbose)

#ifndef R_API
#define R_API
#endif

typedef struct current_table_switch_t {
	ut64 addr;
	int def_jmp;
	int min_val;
	int max_val;
	int sz;
} CurrentTableSwitch;

static CurrentTableSwitch enter_switch_op(ut64 addr, const ut8* bytes, int len) {
	CurrentTableSwitch sw = {0};
	if (len < 16) {
		return sw;
	}
	int sz = 4;
	sw.addr = addr;
	sw.def_jmp = (UINT (bytes, sz));
	sw.min_val = (UINT (bytes, sz + 4));
	sw.max_val = (UINT (bytes, sz + 8));
	sw.sz = sz + 12;
	return sw;
}

static bool isRelative(ut32 type) {
	return (type & R_ANAL_JAVA_CODEOP_CJMP) || (type & R_ANAL_JAVA_CODEOP_JMP);
}

R_API int java_print_opcode(RBinJavaObj *obj, ut64 addr, int idx, const ut8 *bytes, int len, char *output, int outlen) {
	if (idx < 0 || idx >= JAVA_OPS_COUNT) {
		return -1;
	}
	char *arg = NULL;
	ut32 val_one = 0;
	ut32 val_two = 0;
	ut8 op_byte = JAVA_OPS[idx].byte;
	switch (op_byte) {
	case 0x10: // "bipush"
		if (len > 1) {
			snprintf (output, outlen, "%s %d", JAVA_OPS[idx].name, (char) bytes[1]);
			output[outlen - 1] = 0;
			return JAVA_OPS[idx].size;
		}
		return -1;
	case 0x11:
		if (len > 2) {
			snprintf (output, outlen, "%s %d", JAVA_OPS[idx].name, (int)USHORT (bytes, 1));
			output[outlen - 1] = 0;
			return JAVA_OPS[idx].size;
		}
		return -1;
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
		if (len > 1) {
			snprintf (output, outlen, "%s %d", JAVA_OPS[idx].name, bytes[1]);
			output[outlen-1] = 0;
			return JAVA_OPS[idx].size;
		}
		return 0;
	case 0x12: // ldc
		if (len > 1) {
			arg = r_bin_java_resolve_without_space (obj, (ut16)bytes[1]);
			if (arg) {
				snprintf (output, outlen, "%s %s", JAVA_OPS[idx].name, arg);
				free (arg);
			} else {
				const int num = (len > 2)? USHORT (bytes, 1): bytes[1];
				snprintf (output, outlen, "%s #%d", JAVA_OPS[idx].name, num);
			}
			output[outlen - 1] = 0;
			return JAVA_OPS[idx].size;
		}
		return -1;
	case 0x13:
	case 0x14:
		if (len > 2) {
			arg = r_bin_java_resolve_without_space (obj, (int)USHORT (bytes, 1));
			if (arg) {
				snprintf (output, outlen, "%s %s", JAVA_OPS[idx].name, arg);
				free (arg);
			} else {
				snprintf (output, outlen, "%s #%d", JAVA_OPS[idx].name, USHORT (bytes, 1));
			}
			output[outlen-1] = 0;
			return JAVA_OPS[idx].size;
		}
		return -1;
	case 0x84: // iinc
		if (len > 2) {
			val_one = (ut32)bytes[1];
			val_two = (ut32) bytes[2];
			snprintf (output, outlen, "%s %d %d", JAVA_OPS[idx].name, val_one, val_two);
			output[outlen-1] = 0;
			return JAVA_OPS[idx].size;
		}
		return -1;
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
		if (len > 2) {
			const short delta = USHORT (bytes, 1);
			snprintf (output, outlen, "%s 0x%04"PFMT64x, JAVA_OPS[idx].name, addr + delta);
			output[outlen - 1] = 0;
			return JAVA_OPS[idx].size;
		}
		return -1;
	case 0xab: // tableswitch
	case 0xaa: // tableswitch
		{
			CurrentTableSwitch sw = enter_switch_op (addr, bytes, len);
			snprintf (output, outlen, "%s default: 0x%04"PFMT64x,
					JAVA_OPS[idx].name,
					(ut64)(sw.def_jmp + sw.addr));
			return sw.sz;
		}
	case 0xb6: // invokevirtual
	case 0xb7: // invokespecial
	case 0xb8: // invokestatic
	case 0xb9: // invokeinterface
	case 0xba: // invokedynamic
		if (len > 2) {
			arg = r_bin_java_resolve_without_space (obj, (int)USHORT (bytes, 1));
			if (arg) {
				snprintf (output, outlen, "%s %s", JAVA_OPS[idx].name, arg);
				free (arg);
			} else {
				snprintf (output, outlen, "%s #%d", JAVA_OPS[idx].name, USHORT (bytes, 1) );
			}
			output[outlen - 1] = 0;
			return JAVA_OPS[idx].size;
		}
		return -1;
	case 0xbb: // new
	case 0xbd: // anewarray
	case 0xc0: // checkcast
	case 0xc1: // instance of
		if (len > 2) {
			arg = r_bin_java_resolve_without_space (obj, (int)USHORT (bytes, 1));
			if (arg) {
				snprintf (output, outlen, "%s %s", JAVA_OPS[idx].name, arg);
				free (arg);
			} else {
				snprintf (output, outlen, "%s #%d", JAVA_OPS[idx].name, USHORT (bytes, 1) );
			}
			output[outlen-1] = 0;
			return JAVA_OPS[idx].size;
		}
		return -1;
	case 0xb2: // getstatic
	case 0xb3: // putstatic
	case 0xb4: // getfield
	case 0xb5: // putfield
		if (len > 2) {
			arg = r_bin_java_resolve_with_space (obj, (int)USHORT (bytes, 1));
			if (arg) {
				snprintf (output, outlen, "%s %s", JAVA_OPS[idx].name, arg);
				free (arg);
			} else {
				snprintf (output, outlen, "%s #%d", JAVA_OPS[idx].name, USHORT (bytes, 1) );
			}
			output[outlen - 1] = 0;
			return JAVA_OPS[idx].size;
		}
		return -1;
	}

	/* process arguments */
	if (JAVA_OPS[idx].size > len) {
		snprintf (output, outlen, "truncated");
		return -1;
	}
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
	return JAVA_OPS[idx].size;
}

R_API void r_java_new_method(void) {
	// no-op: switch state is now local to each disasm call
}

R_API void U(r_java_set_obj)(RBinJavaObj *obj) {
}

R_API int r_java_disasm(RBinJavaObj *obj, ut64 addr, const ut8 *bytes, int len, char *output, int outlen) {
	R_RETURN_VAL_IF_FAIL (bytes && output && outlen > 0, -1);
	if (len > 0) {
		return java_print_opcode (obj, addr, bytes[0], bytes, len, output, outlen);
	}
	return -1;
}

static int parseJavaArgs(char *str, ut64 *args, int args_sz) {
	int i, nargs = -1;
	char *q, *p = strchr (str, ' ');
	if (p) {
		*p++ = 0;
		nargs ++;
		for (i = 0; i < args_sz; i++) {
			nargs ++;
			q = strchr (p, ' ');
			if (q) {
				*q++ = 0;
			}
			args[i] = r_num_math (NULL, p);
			if (q) {
				p = q;
			} else {
				break;
			}
		}
	}
	return nargs;
}

R_API int r_java_assemble(ut64 addr, ut8 *bytes, const char *string) {
	char *name = strdup (string);

	ut64 args[4] = {0};
	int i, nargs = parseJavaArgs (name, args, 4);
	int a = args[0];
	int b = args[1];
	int c = args[2];
	int d = args[3];
	for (i = 0; JAVA_OPS[i].name != NULL; i++) {
		if (!strcmp (name, JAVA_OPS[i].name)) {
			bytes[0] = JAVA_OPS[i].byte;
			switch (JAVA_OPS[i].size) {
			case 2: bytes[1] = a;
				break;
			case 3:
				if (nargs == 2) {
					bytes[1] = a;
					bytes[2] = b;
				} else {
					if (isRelative (JAVA_OPS[i].op_type)) {
						// relative jmp
						a -= addr;
					}
					bytes[1] = (a >> 8) & 0xff;
					bytes[2] = a & 0xff;
				}
				break;
			case 5: bytes[1] = a;
				bytes[2] = b;
				bytes[3] = c;
				bytes[4] = d;
				break;
			}
			free (name);
			return JAVA_OPS[i].size;
		}
	}
	free (name);
	return 0;
}
