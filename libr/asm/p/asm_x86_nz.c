/* * Copyright (C) 2008-2011 - pancake <nopcode.org> */

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

static ut8 getreg(const char *str) {
	if (!memcmp ("eax", str, 3)) return 0;
	if (!memcmp ("ecx", str, 3)) return 1;
	if (!memcmp ("edx", str, 3)) return 2;
	if (!memcmp ("ebx", str, 3)) return 3;
	if (!memcmp ("esp", str, 3)) return 4;
	if (!memcmp ("ebp", str, 3)) return 5;
	if (!memcmp ("esi", str, 3)) return 6;
	if (!memcmp ("edi", str, 3)) return 7;
	return 0xff;
}

static int isnum(const char *str) {
	return (*str >= '0' && *str <= '9');
}

static int assemble(RAsm *a, RAsmOp *ao, const char *str) {
	ut64 offset = a->pc;
	ut8 *data = ao->buf;
	char *arg, op[128];
	int l = 0;

	strncpy (op, str, sizeof (op)-1);
	if (!memcmp (op, "rep ", 4)) {
		data[l++] = 0xf3;
		memmove (op, op+4, strlen (op+4)+1);
	}
 	arg = strchr (op, ' ');
	if (arg) {
		*arg = '\0';
		arg++;
	}
	if (!strcmp (op, "hang") || !strcmp (str, "jmp $$")) {
		data[l++] = 0xeb;
		data[l++] = 0xfe;
		return 2;
	} else
	if (arg) {
		if (!strcmp (op, "int")) {
			int a = (int)r_num_get (NULL, arg);
			data[l++]='\xcd';
			data[l++]=(ut8)a;
			return 2;
		} else
		if (!strcmp (op, "call")) {
			ut64 dst = r_num_math (NULL, arg);
			ut32 addr = dst;
			ut8 *ptr = (ut8 *)&addr;

			if (dst == 0) {
				data[l++] = '\xff';
				data[l] = getreg (arg) | 0xd0;
				if (data[l] == 0xff) {
					eprintf ("Invalid argument for 'call'\n");
					return 0;
				}
				l++;
				return l;
			}
			addr = addr - offset - 5;

			data[l++] = '\xe8';
			data[l++] = ptr[0];
			data[l++] = ptr[1];
			data[l++] = ptr[2];
			data[l++] = ptr[3];
			return l;
		} else if (!strcmp (op, "push")) {
			ut64 dst = r_num_math (NULL, arg);
			ut32 addr = dst;
			ut8 *ptr = (ut8 *)&addr;

			if (dst == 0 && arg[0]!='0') {
				if (!strcmp(arg, "eax")) data[0]='\x50'; else
				if (!strcmp(arg, "ebx")) data[0]='\x53'; else
				if (!strcmp(arg, "ecx")) data[0]='\x51'; else
				if (!strcmp(arg, "edx")) data[0]='\x52'; else
				if (!strcmp(arg, "esi")) data[0]='\x56'; else
				if (!strcmp(arg, "edi")) data[0]='\x57'; else
				if (!strcmp(arg, "ebp")) data[0]='\x55'; else
				if (!strcmp(arg, "esp")) data[0]='\x54';
				else return 0; // invalid register name to push
				return 1;
			}

			data[l++] = '\x68';
			data[l++] = ptr[0];
			data[l++] = ptr[1];
			data[l++] = ptr[2];
			data[l++] = ptr[3];
			return 5;
		} else if (!strcmp (op, "pop")) {
			ut64 dst = r_num_math (NULL, arg);
			if (dst == 0) {
				data[l++] = getreg (arg) | 0x50;
				return l;
			}
			eprintf ("Invalid pop syntax\n");
			return 0;
		} else if (!strcmp (op, "xor")) {
			char *arg2 = strchr (arg, ',');
			if (arg2 == NULL) {
				eprintf ("Invalid syntax\n");
				return 0;
			}
			*arg2 = 0;
			arg2++;
			data[l++] = 0x31;
			if (isnum (arg2)) {
				data[l++] = getreg (arg) | 0xf0;
				data[l++] = atoi (arg2);
				return l;
			}
			data[l++] = getreg (arg2);
			// XXX: xor eax, eax is wrong f.ex
			return l;
		} else if (!strcmp (op, "mov")) {
			ut64 dst;
			ut32 addr;
			ut8 *ptr = (ut8 *)&addr;
			char *arg2 = strchr (arg, ',');
			if (arg2 == NULL) {
				eprintf ("Invalid syntax\n");
				return 0;
			}
			arg2[0]='\0';
			dst = r_num_math (NULL, arg2+1);
			addr = dst;

			data[l] = getreg (arg) | 0xb0;
			if (data[l++] == 0xff) {
				data[l++]='\xb8';
				eprintf ("oops. wrong arg?\n");
			}

			if (dst==0 && arg2[1]!='0') {
				int src = data[0];
				data[l++]=0x89;
				if (strstr (arg2+l, "eax")) {
					switch(src) {
					case 0xb8: data[l++]=0xc0; break;
					case 0xbb: data[l++]=0xd8; break;
					case 0xb9: data[l++]=0xc8; break;
					case 0xba: data[l++]=0xd0; break;
					case 0xbc: data[l++]=0xe0; break;
					case 0xbd: data[l++]=0xe8; break;
					case 0xbe: data[l++]=0xf0; break;
					case 0xbf: data[l++]=0xf8; break;
					default:
						eprintf ("OOPS: unknown register\n");
						return 0;
					}
					return l;
				} else {
					data[l] = getreg (arg2) | 0x58;
					if (data[l] == 0xff) {
						return 0;
					}
					return l+1;
				}
			} else {
				data[1] = ptr[0];
				data[2] = ptr[1];
				data[3] = ptr[2];
				data[4] = ptr[3];
			}
			return l;
		} else if (!strcmp (op, "jmp")) {
			//ut64 dst = r_num_math (NULL, arg); // XXX: r_num_math  breaks ebp+33 to be 33 instead of 0
			ut64 dst = r_num_get (NULL, arg) - offset;
			ut32 addr = dst;
			ut8 *ptr = (ut8 *)&addr;

			if (dst+offset == 0) {
				data[l++] = '\xff';
				data[l] = getreg (arg) | 0xe0;
				if (data[l] != 0xff)
					return 2;
				l++;
				if (arg[0] == '[' && arg[strlen (arg)] == ']') {
					data[l] = getreg (arg+1) | 0x20;
					if (data[l] != 0xff)
						return l;
					l++;
				}
#if 0
				if (!strcmp(arg, "esp")) { data[1]='\x24'; data[2]='\x24'; } else
				if (!strcmp(arg, "ebp")) { data[1]='\x24'; data[2]='\x24'; } else
				if (strstr(arg, "[eax")) { data[1]='\x60'; data[2]=(char)r_num_math (NULL, arg+4); } else
				if (strstr(arg, "[ebx")) { data[1]='\x63'; data[2]=(char)r_num_math (NULL, arg+4); } else
				if (strstr(arg, "[ecx")) { data[1]='\x61'; data[2]=(char)r_num_math (NULL, arg+4); } else
				if (strstr(arg, "[edx")) { data[1]='\x62'; data[2]=(char)r_num_math (NULL, arg+4); } else
				if (strstr(arg, "[esi")) { data[1]='\x66'; data[2]=(char)r_num_math (NULL, arg+4); } else
				if (strstr(arg, "[edi")) { data[1]='\x67'; data[2]=(char)r_num_math (NULL, arg+4); } else
				if (strstr(arg, "[esi")) { data[1]='\x67'; data[2]=(char)r_num_math (NULL, arg+4); } else
				if (strstr(arg, "[ebp")) { data[1]='\x65'; data[2]=(char)r_num_math (NULL, arg+4); } 
				else {
					if (!strcmp(arg, "[esp")) { data[1]='\x64'; data[2]='\x24'; data[3]=(char)r_num_math (NULL, arg+4); }
						else return 0;
					return 4;
				}
#endif
			}

			dst-=offset;
	// 7C90EAF5   .- E9 42158783   JMP     0018003C
	// RELATIVE LONG JUMP (nice coz is 4 bytes, not 5) 

			if (dst>-0x80 && dst<0x7f) {
				/* relative address */
				addr-=2;
				addr-=offset;
				data[l++]='\xeb';
				data[l++]=(char)dst;
				return l;
			} else {
				/* absolute address */
				addr-=5;
				data[l++]= 0xe9;
				data[l++] = ptr[0];
				data[l++] = ptr[1];
				data[l++] = ptr[2];
				data[l++] = ptr[3];
				return l;
			}
		} else
		if (!strcmp (op, "jnz")) {
			ut64 dst = r_num_math (NULL, arg) - offset;

			if (dst>-0x80 && dst<0x7f) {
				dst-=2;
				data[l++]='\x75';
				data[l++]=(char)dst;
				return l;
			} else {
				data[l++]=0x0f;
				data[l++]=0x85;
				dst -= 6;
				memcpy (data+l, &dst, 4);
				return l+4;
			}
		} else
		if (!strcmp (op, "jz")) {
			ut64 dst = r_num_math (NULL, arg) - offset;

			if (dst>-0x80 && dst<0x7f) {
				dst-=2;
				data[l++]='\x74';
				data[l++]=(char)dst;
				return l;
			} else {
				data[l++]=0x0f;
				data[l++]=0x84;
				dst-=6;
				memcpy (data+l,&dst,4);
				return l+4;
			}
		}
	} else {
		if (!strcmp (op, "ret")) {
			data[l++]='\xc3';
			return l;
		} else
		if (!strcmp (op, "ret0")) {
			memcpy (data+l, "\x31\xc0\xc3", 3);
			return l+3;
		} else
		if (!strcmp(op, "int3")) {
			data[l++]='\xcc';
			return l;
		} else
		if (!strcmp (op, "pusha")) {
			data[l++]='\x60';
			return l;
		} else
		if (!strcmp (op, "popa")) {
			data[l++] = 0x61;
			return l;
		} else
		if (!strcmp (op, "nop")) {
			data[l++]='\x90';
			return l;
		}
	}
	eprintf ("Unknown opcode\n");
	return 0;
}

RAsmPlugin r_asm_plugin_x86_nz = {
	.name = "x86.nz",
	.desc = "x86 assembler with non-zeros",
	.arch = "x86",
	.bits = (int[]){ 32, 64, 0 },
	.init = NULL,
	.fini = NULL,
	.disassemble = NULL,
	.modify = NULL,
	.assemble = &assemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86_nz
};
#endif
