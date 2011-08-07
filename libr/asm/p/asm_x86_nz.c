/* * Copyright (C) 2008-2011 - pancake <nopcode.org> */

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

static ut8 getreg(const char *str) {
	int i;
	const char *regs[] = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", NULL };
	const char *regs64[] = { "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", NULL };
	if (!str)
		return 0xff;
	for (i=0; regs[i]; i++)
		if (!memcmp (regs[i], str, strlen (regs[i])))
			return i;
	for (i=0; regs64[i]; i++)
		if (!memcmp (regs64[i], str, strlen (regs64[i])))
			return i;
	return 0xff;
}

static int getnum(const char *s) {
	if (*s=='0' && s[1]=='x') {
		int n;
		sscanf (s+2, "%x", &n);
		return n;
	}
	return atoi (s);
}

static int isnum(const char *str) {
	return str && (*str == '-' || (*str >= '0' && *str <= '9'));
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
	if (!strcmp (str, "call $$")) {
		memcpy (data, "\xE8\xFF\xFF\xFF\xFF\xC1", 6);
		return 6;
	}
	if (!strcmp (op, "hang") || !strcmp (str, "jmp $$")) {
		data[l++] = 0xeb;
		data[l++] = 0xfe;
		return l;
	}
 	arg = strchr (op, ' ');
	if (arg) {
		*arg = '\0';
		arg++;
	}
	if (arg) {
		char *arg2 = strchr (arg, ',');
		if (arg2) {
			*arg2 = 0;
			for (arg2++; *arg2==' '; arg2++);
		}
		if (!strcmp (op, "add")) {
			int pfx;
			if (*arg=='[') {
				arg++;
				pfx = 0;
			} else pfx = 0xc0;
			if (arg2 == NULL) {
				eprintf ("Invalid syntax\n");
				return 0;
			}
			if (a->bits == 64)
				data[l++] = 0x48;
			if (isnum (arg2)) {
				int num = getnum (arg2);
				if (num>127 || num<-127) {
					ut8 *ptr = (ut8 *)&num;
					data[l++] = 0x81;
					data[l++] = pfx | getreg (arg);
					data[l++] = ptr[0];
					data[l++] = ptr[1];
					data[l++] = ptr[2];
					data[l++] = ptr[3];
				} else {
					data[l++] = 0x83;
					data[l++] = pfx | getreg (arg);
					data[l++] = num;
				}
			} else {
				data[l++] = 0x01;
				data[l++] = pfx | getreg (arg2)<<3 | getreg (arg);
			}
			return l;
		} else
		if (!strcmp (op, "sub")) {
			int pfx;
			if (*arg=='[') {
				arg++;
				pfx = 0;
			} else pfx = 0xc0;
			if (arg2 == NULL) {
				eprintf ("Invalid syntax\n");
				return 0;
			}
			if (a->bits == 64)
				data[l++] = 0x48;
			if (isnum (arg2)) {
				int num = getnum (arg2);
				if (num>127 || num<-127) {
					ut8 *ptr = (ut8*) &num;
					data[l++] = 0x81;
					data[l++] = 0xe8 | getreg (arg);
					data[l++] = ptr[0];
					data[l++] = ptr[1];
					data[l++] = ptr[2];
					data[l++] = ptr[3];
				} else {
					data[l++] = 0x83;
					data[l++] = 0xe8 | getreg (arg);
					data[l++] = getnum (arg2);
				}
			} else {
				data[l++] = 0x29;
				data[l++] = pfx | getreg (arg2)<<3 | getreg (arg);
			}
			return l;
		} else
		if (!strcmp (op, "test")) {
			int arg0 = getreg (arg);
			if (a->bits==64)
				data[l++] = 0x48;
			data[l++] = 0x85;
			data[l++] = 0xc0 | (arg0<<3) | getreg (arg2);
			return l;
		} else
		if (!strcmp (op, "int")) {
			int a = (int)r_num_get (NULL, arg);
			data[l++] = 0xcd;
			data[l++] = (ut8)a;
			return l;
		} else
		if (!strcmp (op, "call")) {
			ut64 dst = r_num_math (NULL, arg);
			ut32 addr = dst;
			ut8 *ptr = (ut8 *)&addr;

			if (dst == 0) {
				data[l++] = '\xff';
				data[l] = getreg (arg) | 0xd0;
				if (data[l] == 0xff) {
					eprintf ("Invalid argument for 'call' (%s)\n", arg);
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
		} else if (!strcmp (op, "inc")) {
			data[l++] = 0x40 | getreg (arg);
			return l;
		} else if (!strcmp (op, "dec")) {
			data[l++] = 0x48 | getreg (arg);
			return l;
		} else if (!strcmp (op, "push")) {
			char *delta;
			ut64 dst;
			ut32 addr = dst;
			ut8 *ptr = (ut8 *)&addr;

			if (*arg=='[') {
				arg++;
				delta = strchr (arg, '+');
				if (delta) {
					*delta++ = 0;
					data[l++] = 0xff;
					data[l++] = 0x70 | getreg (arg);
					data[l++] = getnum (delta);
				} else {
					int r = getreg (arg);
					data[l++] = 0xff;
					if (r==4) { //ESP
						data[l++] = 0x34;
						data[l++] = 0x24;
					} else if (r== 5) { // EBP
						data[l++] = 0x75;
						data[l++] = 0;
					} else data[l++] = 0x30 | r;
				}
				return l;
			}
			dst = r_num_math (NULL, arg);
			if (!isnum (arg)) {
				ut8 ch = getreg (arg) | 0x50;
				if (ch == 0xff) {
					eprintf ("Invalid register name (%s)\n", arg);
					return 0;
				}
				data[l++] = ch;
				return l;
			}
			data[l++] = '\x68';
			data[l++] = ptr[0];
			data[l++] = ptr[1];
			data[l++] = ptr[2];
			data[l++] = ptr[3];
			return 5;
		} else if (!strcmp (op, "pop")) {
			char *delta;
			ut64 dst;
			if (*arg=='[') {
				arg++;
				delta = strchr (arg, '+');
				if (delta) {
					*delta++ = 0;
					data[l++] = 0x8f;
					data[l++] = 0x40 | getreg (arg);
					data[l++] = delta? getnum (delta): 0;
				} else {
					int r = getreg (arg);
					data[l++] = 0x8f;
					if (r==4) { //ESP
						data[l++] = 0x04;
						data[l++] = 0x24;
					} else if (r==5) { // EBP
						data[l++] = 0x45;
						data[l++] = 0;
					} else data[l++] = r;
				}
				return l;
			}
			dst = r_num_math (NULL, arg);
			if (dst == 0) {
				data[l++] = getreg (arg) | 0x58;
				return l;
			}
			eprintf ("Invalid pop syntax\n");
			return 0;
		} else if (!strcmp (op, "xor")) {
			int pfx, arg0;
			if (*arg=='[') {
				arg++;
				pfx = 0;
			} else pfx = 0xc0;
			arg0 = getreg (arg);
			if (a->bits==64) {
				data[l++] = 0x48;
				data[l++] = 0x31; // NOTE: 0x33 is also a valid encoding for xor.. polimorfi?
				data[l++] = arg0 | (getreg(arg2)<<3) | pfx;
			} else {
				data[l++] = 0x31;
				if (isnum (arg2)) {
					data[l++] = arg0 | 0xf0;
					data[l++] = getnum (arg2);
				} else {
					data[l++] = arg0 | (getreg (arg2)<<3) | pfx;
				}
			}
			return l;
		} else if (!strcmp (op, "mov")) {
			char *delta = NULL;
			int pfx, arg0;
			ut64 dst;
			ut32 addr;
			ut8 *ptr = (ut8 *)&addr;
			dst = r_num_math (NULL, arg2);
			addr = dst;
			if (!arg || !arg2) {
				eprintf ("No args for mov?\n");
				return 0;
			}

			if (*arg=='[') {
				arg++;
				delta = strchr (arg, '+');
				if (delta) {
					*delta++ = 0;
				}
				pfx = 0;
			} else pfx = 0xc0;

			if (*arg2=='[') {
				arg2++;
				if (a->bits == 64)  {
					data[l++] = 0x67;
					data[l++] = 0x8b;
					data[l++] = getreg (arg)<<3 | getreg (arg2);
				} else {
					data[l++] = 0x8b;
					data[l++] = getreg (arg)<<3 | getreg (arg2);
				}
				return l;
				pfx = 0;
			} //else pfx = 0xc0;
			arg0 = getreg (arg); // hack to make is64 work
			if (isnum (arg)) {
				int num = getnum (arg);
				ut8 *ptr = (ut8 *)&num;
				data[l++] = 0x89;
				data[l++] = (getreg (arg2)<<3) |5;
				data[l++] = ptr[0];
				data[l++] = ptr[1];
				data[l++] = ptr[2];
				data[l++] = ptr[3];
				return l;
			}
			if (a->bits==64) {
				if (isnum (arg2)) {
					data[l++] = 0x48;
					data[l++] = 0xc7;
					data[l++] = arg0 | pfx;
					data[l++] = ptr[0];
					data[l++] = ptr[1];
					data[l++] = ptr[2];
					data[l++] = ptr[3];
					return l;
				}
				data[l++] = 0x48;
				data[l++] = 0x89;
				data[l++] = arg0 | (getreg (arg2)<<3) | pfx;
				return l;
			}

			if (isnum (arg2)) {
				data[l++] = 0xb8;
				data[l++] = ptr[0];
				data[l++] = ptr[1];
				data[l++] = ptr[2];
				data[l++] = ptr[3];
				return l;
			} else {
				data[l++] = 0x89;
				if (delta) {
					if (isnum (delta)){
						data[l++] = 0x58 | getreg (arg);
						data[l++] = getnum (delta);
					} else {
						data[l++] = getreg (arg2)<<3 | 0x4;
						data[l++] = (getreg (delta)<<3 ) | getreg (arg);
					}
				} else {
					data[l++] = getreg (arg2)<<3 | getreg (arg) | pfx;
				}
			}
			return l;
		} else if (!strcmp (op, "jmp")) {
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

			dst -= offset;
	// 7C90EAF5   .- E9 42158783   JMP     0018003C
	// RELATIVE LONG JUMP (nice coz is 4 bytes, not 5) 

			if (dst>-0x80 && dst<0x7f) {
				/* relative address */
				addr -= 2;
				addr -= offset;
				data[l++] = '\xeb';
				data[l++] = (char)dst;
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
			int num = getnum (arg);
			if (num>-127 && num<127) {
				num-=2;
				data[l++]='\x75';
				data[l++]=(char)num;
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
		if (!strcmp (op, "leave")) {
			data[l++]='\xc9';
		} else
		if (!strcmp (op, "syscall")) {
			data[l++]='\x0f';
			data[l++]='\x05';
		} else
		if (!strcmp (op, "ret")) {
			data[l++]='\xc3';
		} else
		if (!strcmp (op, "ret0")) {
			memcpy (data+l, "\x31\xc0\xc3", 3);
			l += 3;
		} else
		if (!strcmp(op, "int3")) {
			data[l++]='\xcc';
		} else
		if (!strcmp (op, "pusha")) {
			data[l++]='\x60';
		} else
		if (!strcmp (op, "popa")) {
			data[l++] = 0x61;
		} else
		if (!strcmp (op, "nop")) {
			data[l++]='\x90';
		}
		return l;
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
