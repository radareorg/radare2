/* Copyright (C) 2008-2014 - pancake */

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

static int getnum(RAsm *a, const char *s);
static int isnum(RAsm *a, const char *str);
static ut8 getreg(const char *s);
#if 0
TODO
	mov [esp+4], N
	mov [esp+4], reg
BLA:
	Add support for AND, OR, ..
        0x100000ec5    1    4883e4f0         and rsp, 0xfffffffffffffff0
#endif

static int getnum(RAsm *a, const char *s) {
	if (!s) return 0;
	if (*s=='$') s++;
	return r_num_math (a->num, s);
}

static ut8 getshop(const char *s) {
	int i;
	const char *ops = \
		"sar\xf8" \
		"shl\xf0" \
		"shr\xe8" \
		"shl\xe0" \
		"rcr\xd8" \
		"rcl\xd0" \
		"ror\xc8" \
		"rol\xc0";
	if (strlen (s)<3)
		return 0;
	for (i=0; i<strlen (ops); i+=4)
		if (!memcmp (s, ops+i, 3))
			return (ut8)ops[i+3];
	return 0;
}

static int jop (RAsm *a, ut8 *data, ut8 x, ut8 b, const char *arg) {
	ut32 dst32;
	int l = 0;
	ut64 addr = a->pc;
	int num = getnum (a, arg);
	if (!isnum (a, arg))
		return 0;
	dst32 = num - addr;
#if 0
	d = num - addr; // obey sign
	if (d>-127 && d<127) {
		d-=2;
		data[l++] = a;
		data[l++] = (char)d;
		return 2;
	}
#endif
	data[l++] = 0x0f;
	data[l++] = b;
	dst32 -= 6;
	memcpy (data+l, &dst32, 4);
	return 6;
}

static int bits8 (const char *p) {
	const char *b8r[] = { "al", "cl", "dl", "bl", NULL };
	int i;
	if (strlen (p) == 2)
		for (i=0; b8r[i]; i++)
			if (!strcmp (b8r[i], p))
				return i;
	return -1;
}

static ut8 getreg(const char *str) {
	int i;
	const char *regs[] = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", NULL };
//	const char *regs16[] = { "al", "ah", "cl", "ch", "dl", "dh", "bl", "bh", NULL };
	const char *regs16[] = { "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh", NULL };
	const char *regs64[] = { "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", NULL };
	if (!str)
		return 0xff;
	for (i=0; regs[i]; i++)
		if (!strncmp (regs[i], str, strlen (regs[i])))
			return i;
	for (i=0; regs64[i]; i++)
		if (!strncmp (regs64[i], str, strlen (regs64[i])))
			return i;
	for (i=0; regs16[i]; i++)
		if (!strncmp (regs16[i], str, strlen (regs16[i])))
			return i;
	return 0xff;
}

static int isnum(RAsm *a, const char *str) {
	if (r_num_get (a->num, str) != 0)
		return 1;
	return str && (*str == '-' || (*str >= '0' && *str <= '9'));
}

static int assemble(RAsm *a, RAsmOp *ao, const char *str) {
	ut64 offset = a->pc;
	ut8 t, *data = ao->buf;
	char *arg, op[128];
	int l = 0;

	strncpy (op, str, sizeof (op)-1);
	op[sizeof (op)-1] = '\0';
	arg = strstr (op, "dword ptr");
	if (arg) {
		const int dword_len = strlen ("dword ptr");
		memmove (arg, arg+dword_len, strlen (arg+dword_len)+1);
	}
	arg = strstr (op, "dword ");
	if (arg) {
		const int dword_len = strlen ("dword ");
		memmove (arg, arg+dword_len, strlen (arg+dword_len)+1);
	} else arg = strchr (op, ' ');

	if (!memcmp (op, "ret ", 4) || !memcmp (op, "retn ", 5)) {
		int n = getnum (a, op+4);
		data[l++] = 0xc2;
		data[l++] = n & 0xff;
		data[l++] = (n>>8) & 0xff;
		return l;
	}
	if (!memcmp (op, "retf ", 5)) {
		int n = getnum (a, op+4);
		data[l++] = 0xca;
		data[l++] = n & 0xff;
		data[l++] = (n>>8) & 0xff;
		return l;
	}

	if (!memcmp (op, "rep ", 4)) {
		data[l++] = 0xf3;
		memmove (op, op+4, strlen (op+4)+1);
	}

	if (!strcmp (op, "movsb")) { data[l++] = 0xa4; return l; }
	if (!strcmp (op, "movsw")) { data[0] = 0x66; data[1] = 0xa5; return 2; }
	if (!strcmp (op, "movsd")) { data[0] = 0xa5; return 1; }
	if (!strcmp (op, "outsd")) { data[0] = 0x6f; return 1; }
	if (!strcmp (op, "outsb")) { data[0] = 0x6e; return 1; }
	if (!strcmp (op, "insb")) { data[0] = 0x6c; return 1; }
	if (!strcmp (op, "hlt")) { data[0] = 0xf4; return 1; }
	if (!strcmp (op, "cpuid")) { data[0] = 0xf; data[1] = 0xa2; return 2; }

	if (!strcmp (str, "call $$")) {
		memcpy (data, "\xE8\xFF\xFF\xFF\xFF\xC1", 6);
		return 6;
	}
	if (!strcmp (op, "hang") || !strcmp (str, "jmp $$")) {
		data[l++] = 0xeb;
		data[l++] = 0xfe;
		return l;
	}
	if (!strcmp (op, "rdtsc")) {
		data[l++] = 0x0f;
		data[l++] = 0x31;
		return l;
	}
	if (!strncmp (op, "set", 3)) {
#if 0
SETAE/SETNB - Set if Above or Equal / Set if Not Below (386+)
SETB/SETNAE - Set if Below / Set if Not Above or Equal (386+)
SETBE/SETNA - Set if Below or Equal / Set if Not Above (386+)
SETE/SETZ - Set if Equal / Set if Zero (386+)
SETNE/SETNZ - Set if Not Equal / Set if Not Zero (386+)
SETL/SETNGE - Set if Less / Set if Not Greater or Equal (386+)
SETGE/SETNL - Set if Greater or Equal / Set if Not Less (386+)
SETLE/SETNG - Set if Less or Equal / Set if Not greater or Equal (386+)
SETG/SETNLE - Set if Greater / Set if Not Less or Equal (386+)
SETS - Set if Signed (386+)
SETNS - Set if Not Signed (386+)
SETC - Set if Carry (386+)
SETNC - Set if Not Carry (386+)
SETO - Set if Overflow (386+)
SETNO - Set if Not Overflow (386+)
SETP/SETPE - Set if Parity / Set if Parity Even (386+)
SETNP/SETPO - Set if No Parity / Set if Parity Odd (386+)
#endif
		const char *keys[] = {"o ","no ","b ","ae ","e ","ne ","be ", "a ",
			"s ", "ns ","p ", "np ", "l ", "ge ", "le ", "g ", NULL};
		char *tmp;
		int i, arg0;
		arg = strchr (op, ' ');
		if (!arg) {
			eprintf ("Missing parameter for '%s'\n", op);
			return -1;
		} else arg++;
		tmp = strchr (arg, ' ');
		if (!tmp) tmp = strchr (arg, '[');
		if (tmp) {
			if (*tmp != '[')
				arg = tmp+1;
			else arg = tmp;
		} 

		data[l++] = 0x0f;
		for (i=0;keys[i];i++) {
			if (!strncmp (op+3,keys[i], strlen(keys[i]))) {
				data[l++] = 0x90|i;
				break;
			}
		}
		if (l==1) {
			eprintf ("Invalid instruction\n");
			return -1;
		}
		if (*arg=='[') {
			// skip/implicit byte [...]
			arg0 = getreg (arg+1);
			if (arg0==4 || arg0==5) {
				eprintf ("Invalid arg for '%s'\n", op);
				return -1;
			}
			data[l++] = arg0;
		} else {
			arg0 = getreg (arg);
			data[l++] = 0xc0 | arg0;
		}
		//TODO: verify if (l!=3)
		return 3;
	}
 	arg = strchr (op, ' ');
	if (arg) {
		*arg = '\0';
		for (arg++; *arg==' '; arg++);
	}
	if (arg) {
		char *arg2 = strchr (arg, ',');
		if (arg2) {
			*arg2 = 0;
			//arg2 = skipspaces (arg2+1);
			for (arg2++; *arg2==' '; arg2++);
		}
		if (!strcmp (op, "xchg")) {
			if (arg2) {
				if (*arg == '[' || *arg2=='[') {
					eprintf ("xchg with memory access not yet implemented\n");
				} else {
					int reg1 = getreg (arg);
					int reg2 = getreg (arg2);
					if (reg1 == reg2) {
						data[l++] = 0x90;
					} else {
						data[l++] = 0x87;
						data[l++] = 0xc0 | reg1 | reg2<<3;
					}
					return l;
				}
			} else {
				eprintf ("xchg expects 2 arguments\n");
				return 0;
			}
		} else
		if (!strcmp (op, "add")) {
			int pfx;
			if (*arg=='[') {
				char *delta = strchr (arg+1, '+');
				arg++;
				pfx = 0;
				if (delta) {
					int n = getnum (a, arg2);
					int d = getnum (a, delta+1);
					int r = getreg (arg);
					if (d<127 && d>-127) {
						data[l++] = 0x83;
						data[l++] = 0x40 | getreg (arg); // XXX: hardcoded
						data[l++] = getnum (a, delta+1);
						data[l++] = getnum (a, arg2);
					} else {
						ut8 *ptr = (ut8 *)&d;
						data[l++] = 0x83;
						data[l++] = 0x80|r;

						data[l++] = ptr[0];
						data[l++] = ptr[1];
						data[l++] = ptr[2];
						data[l++] = ptr[3];
						// XXX: for big numbere here
						data[l++] = n;
					}
					return l;
				}
			} else pfx = 0xc0;
			if (arg2 == NULL) {
				eprintf ("Invalid syntax\n");
				return 0;
			}
			if (a->bits == 64)
				if (*arg=='r')
					data[l++] = 0x48;
			if (isnum (a, arg2)) {
				int num = getnum (a, arg2);
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
			int parg0 = 0;
			int pfx;
			if (*arg=='[') {
				char *delta = strchr (arg+1, '+');
				if (!delta) delta = strchr (arg+1,'-');
				arg++;
				parg0 = 1;
				pfx = 0;
				if (delta) {
					int n = getnum (a, arg2);
					int d = getnum (a, delta+1);
					int r = getreg (arg);
					if (d<127 && d>-127) {
						data[l++] = 0x83;
						data[l++] = 0x6d; // XXX hardcoded
						data[l++] = d;
						data[l++] = n;
					} else {
						ut8 *ptr = (ut8 *)&d;
						data[l++] = 0x81;
						data[l++] = 0xa8|r;

						data[l++] = ptr[0];
						data[l++] = ptr[1];
						data[l++] = ptr[2];
						data[l++] = ptr[3];

						ptr = (ut8*)&n;
						data[l++] = ptr[0];
						data[l++] = ptr[1];
						data[l++] = ptr[2];
						data[l++] = ptr[3];
					}
					return l;
				}
			} else pfx = 0xc0;
			if (arg2 == NULL) {
				eprintf ("Invalid syntax\n");
				return 0;
			}
			if (a->bits == 64)
				if (*arg=='r')
					data[l++] = 0x48;
			if (isnum (a, arg2)) {
				int num = getnum (a, arg2);
				if (num>127 || num<-127) {
					ut8 *ptr = (ut8*) &num;
					if (parg0) {
						data[l++] = 0x81;
						//data[l++] = 0xe8 | getreg (arg);
						data[l++] = 0x28 | getreg (arg);
						data[l++] = ptr[0];
						data[l++] = ptr[1];
						data[l++] = ptr[2];
						data[l++] = ptr[3];
					} else {
						int r = getreg (arg);
						if (r==0) { // eax
							data[l++] = 0x2d;
							data[l++] = ptr[0];
							data[l++] = ptr[1];
							data[l++] = ptr[2];
							data[l++] = ptr[3];
						} else {
							data[l++] = 0x81;
							data[l++] = 0xe8 | getreg (arg);
							data[l++] = ptr[0];
							data[l++] = ptr[1];
							data[l++] = ptr[2];
							data[l++] = ptr[3];
						}
					}
				} else {
					data[l++] = 0x83;
					if (parg0) {
						data[l++] = 0x28 | getreg (arg);
					} else {
						data[l++] = 0xe8 | getreg (arg);
					}
					data[l++] = getnum (a, arg2);
				}
			} else {
				data[l++] = 0x29;
				data[l++] = pfx | getreg (arg2)<<3 | getreg (arg);
			}
			return l;
		} else
		if (!strcmp (op, "cmp")) {
			int arg0 = getreg (arg);
			int arg1 = getreg (arg2);
			if (arg2 == NULL) {
				eprintf ("Invalid syntax\n");
				return 0;
			}
			if (a->bits==64)
				if (*arg=='r')
					data[l++] = 0x48;
			if (*arg2=='[') {
				char *p = strchr (arg2+1, '+');
				if (!p) {
					p = strchr (arg2+1, '-');
				}
				if (p) {
					*p = 0;
					ut32 n = getnum (a, p+1);
					ut8 *ptr = (ut8*)&n;
					arg1 = getreg (arg2+1);
					data[l++] = 0x3b;
					if (arg1 == 4) { // esp
						data[l++] = 0x80 | arg1 | (arg0<<3);
						data[l++] = 0x24;
					} else {
						data[l++] = 0xb8 | arg1;
					}
					data[l++] = ptr[0];
					data[l++] = ptr[1];
					data[l++] = ptr[2];
					data[l++] = ptr[3];
					return l;
				} else {
					eprintf ("unknown cmp\n");
					return 0;
				}

				return 0;
			}
			if (isnum (a, arg2)) { // reg, num
				int n = atoi (arg2);
				if (n>127 || n<-127) {
					ut8 *ptr = (ut8 *)&n;
					data[l++] = 0x81;
					data[l++] = 0xf8 | arg0;
					//data[l++] = 0x50 | arg0;
					data[l++] = ptr[0];
					data[l++] = ptr[1];
					data[l++] = ptr[2];
					data[l++] = ptr[3];
				} else {
					data[l++] = 0x83;
					data[l++] = 0xc0 | arg0 | (arg1<<3);
					data[l++] = atoi (arg2);
				}
				return l;
			} else // reg, reg
			if (arg0 != 0xff && arg1 != 0xff) {
				data[l++] = 0x39;
				data[l++] = 0xc0 | arg0 | (arg1<<3);
				return l;
			}
		} else
		if (!strcmp (op, "test")) {
			int arg0 = getreg (arg);
			if (a->bits==64)
				if (*arg=='r')
					data[l++] = 0x48;
			data[l++] = 0x85;
			//data[l++] = 0xc0 | arg0<<3 | getreg (arg2);
			data[l++] = 0xc0 | getreg (arg2)<<3 | arg0; //getreg (arg2);
			return l;
		} else
		if (!strcmp (op, "int")) {
			int b = (int)getnum (a, arg);
			data[l++] = 0xcd;
			data[l++] = (ut8)b;
			return l;
		} else
		if (!strcmp (op, "call")) {
			if (arg[0] == '[' && arg[strlen (arg)-1] == ']') {
				if (getreg (arg+4) != 0xff) {
					eprintf ("Cannot use reg here\n");
					return -1;
				}
				if (!memcmp (arg+1, "rip", 3)) {
					ut64 dst = r_num_math (a->num, arg+4);
					ut32 addr = dst;
					ut8 *ptr = (ut8 *)&addr;
					data[l++] = 0xff;
					data[l++] = 0x1d;
					data[l++] = ptr[0];
					data[l++] = ptr[1];
					data[l++] = ptr[2];
					data[l++] = ptr[3];
					return l;
				} else {
					ut64 dst = r_num_math (a->num, arg+1);
					ut32 addr = dst;
					ut8 *ptr = (ut8 *)&addr;
					if (dst != 0) {
						data[l++] = 0xff;
						data[l++] = 0x15;
						data[l++] = ptr[0];
						data[l++] = ptr[1];
						data[l++] = ptr[2];
						data[l++] = ptr[3];
						return l;
					}
					return -1;
				}
			} else {
				int reg = getreg (arg);
				if (reg != 0xff) {
					data[l++] = '\xff';
					data[l] = getreg (arg) | 0xd0;
					if (data[l] == 0xff)
						return 0;
					l++;
					return l;
				} else {
					ut64 dst = r_num_math (a->num, arg);
					ut32 addr = dst;
					ut8 *ptr = (ut8 *)&addr;

					if (dst == 0 && *arg != '0') {
					}
					addr = addr - offset - 5;

					data[l++] = 0xe8;
					data[l++] = ptr[0];
					data[l++] = ptr[1];
					data[l++] = ptr[2];
					data[l++] = ptr[3];
					return l;
				}
			}
		} else if (!strcmp (op, "inc")) {
			if (arg[0]=='r') {
				data[l++] = 0x48;
				data[l++] = 0xff;
				data[l++] = 0xc0 | getreg (arg);
			} else data[l++] = 0x40 | getreg (arg);
			return l;
		} else if (!strcmp (op, "dec")) {
			if (arg[0]=='r') {
				data[l++] = 0x48;
				data[l++] = 0xff;
				data[l++] = 0xc8 | getreg (arg);
			} else data[l++] = 0x48 | getreg (arg);
			return l;
		} else if (!strcmp (op, "push")) {
			char *delta;
			ut64 dst;
			ut32 addr;
			ut8 *ptr;

			if (*arg=='[') {
				while (*arg=='[') arg++;
				delta = strchr (arg, '+');
				if (!delta) delta = strchr (arg,'-');
				if (delta) {
					int r = getreg (arg);
					int d = getnum (a, delta+1);
					if (*delta=='-') d = -d;
					*delta++ = 0;
					data[l++] = 0xff;
					if (d<127 && d>-127) {
						data[l++] = 0x70 | r;
						if (r==4)
							data[l++]=0x24; // wtf
						data[l++] = d;
					} else {
						data[l++] = 0xb0 | r;
						addr = d;
						ptr = (ut8 *)&addr;
						data[l++] = ptr[0];
						data[l++] = ptr[1];
						data[l++] = ptr[2];
						data[l++] = ptr[3];
					}
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
			if (!arg) {
				eprintf ("Missing argument for push\n");
				return 0;
			}
			dst = r_num_math (NULL, arg);
			addr = dst;
			ptr = (ut8 *)&addr;
			if (arg[0] && arg[1]=='s' && !arg[2]) {
				data[l++] = 0x0f;
				switch (arg[0]) {
				case 'c': data[0] = 0x0e; return 1;
				case 'd': data[0] = 0x1e; return 1;
				case 's': data[0] = 0x16; return 1;
				case 'f': data[l++] = 0xa0; break;
				case 'g': data[l++] = 0xa8; break;
				}
				return l;
			}
			if (!isnum (a, arg)) {
				ut8 ch = getreg (arg) | 0x50;
				if (ch == 0xff) {
					eprintf ("Invalid register name (%s)\n", arg);
					return 0;
				}
				data[l++] = ch;
				return l;
			}
			{
				int n = addr;
				if (n>-127 && n<=127) {
					data[l++] = 0x6a;
					data[l++] = addr;
					return 2;
				}
			}
			data[l++] = 0x68;
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
					data[l++] = getnum (a, delta);
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
			if (arg[0] && arg[1]=='s' && !arg[2]) {
				data[l++] = 0x0f;
				switch (arg[0]) {
				case 's': data[0] = 0x17; return 1;
				case 'f': data[l++] = 0xa1; break;
				case 'g': data[l++] = 0xa9; break;
				case 'd': data[0] = 0x1f; return 1;
				}
				return l;
			}
			dst = r_num_math (NULL, arg);
			if (dst == 0) {
				ut8 r = getreg (arg);
				if (r==(ut8)-1) return 0;
				data[l++] = r | 0x58;
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
				if (*arg=='r')
					data[l++] = 0x48;
				data[l++] = 0x31; // NOTE: 0x33 is also a valid encoding for xor.. polimorfi?
				data[l++] = arg0 | (getreg(arg2)<<3) | pfx;
			} else {
				data[l++] = 0x31;
				if (isnum (a, arg2)) {
					data[l++] = arg0 | 0xf0;
					data[l++] = getnum (a, arg2);
				} else {
					data[l++] = arg0 | (getreg (arg2)<<3) | pfx;
				}
			}
			return l;
		} else if (!strcmp (op, "lea")) {
			if (!arg || !arg2) {
				eprintf ("No args for lea?\n");
				return 0;
			}
			if (a->bits==64)
				if (*arg=='r')
					data[l++] = 0x48;
			data[l++] = 0x8d;
			if (*arg2=='[') {
				int r = getreg (arg);
				int r2 = getreg (arg2+1);
				arg2++;
				if (isnum (a, arg2)) {
					ut64 n = getnum (a, arg2);
					ut32 n32 = (ut32)n;
					ut8 *ptr;
					data[l++] = 0x05 | getreg (arg)<<3;
					ptr = (ut8*)&n32;
					data[l++] = ptr[0];
					data[l++] = ptr[1];
					data[l++] = ptr[2];
					data[l++] = ptr[3];
				} else {
					char *p = strchr (arg2, '+');
					if (!p) p = strchr (arg2, '-');
					if (p) {
						if (isnum (a, p+1)) {
							int n = getnum (a, p+1);
							*p++ = 0;
							ut8 *ptr = (ut8*)&n;
							if (n>127 || n<-127 || r2==4) {
								if (!strcmp (arg2, "rip")) {
									// the rip exception
									data[l++] = 0x5 + (getreg(arg)<<3);
								} else {
									data[l++] = 0x80 | getreg (arg)<<3 | getreg (arg2);
								}
								if (r2==4)
									data[l++] = 0x24; // THE ESP EXCEPTION
								data[l++] = ptr[0];
								data[l++] = ptr[1];
								data[l++] = ptr[2];
								data[l++] = ptr[3];
								// TODO
							} else {
								data[l++] = 0x40 | getreg (arg)<<3 | getreg (arg2);
								data[l++] = n;
							}
						} else {
							int r3 = getreg (p+1);
							// lea reg, [reg+reg]
							data[l++] = (r<<3) | 4;
							if (r2>r3) {
								data[l++] = (r3) | (r2<<3);
							} else {
								data[l++] = (r3<<3) | (r2);
							}
						}
					} else {
						if (r2==4) { //ESP
							data[l++] = r<<3 | r2;
							data[l++] = 0x24;
						} else if (r2== 5) { // EBP
							data[l++] = 0x5d;
							data[l++] = 0;
						} else data[l++] = r<<3 | r2;
					}
				}
			} else eprintf ("Invalid args for lea?\n");
			return l;
		} else if ((t=getshop (op))) { // sar, shl, shr, rcr, rcl, ror, rol
			if (arg[1]=='l') { // 8bits
				data[l++] = 0xc0;
				data[l++] = t | getreg (arg);
				data[l++] = getnum (a, arg2);
			} else
			if (*arg=='r') { // 64bits
				data[l++] = 0x48;
				data[l++] = 0xc1;
				data[l++] = t | getreg (arg);
				data[l++] = getnum (a, arg2);
			} else { // 32bits
				data[l++] = 0xc1;
				data[l++] = t | getreg (arg);
				data[l++] = getnum (a, arg2);
			}
			return l;
		} else if (!strcmp (op, "cmovz")) {
			ut8 a, b;
			if ((a = getreg (arg))==0xff) return 0;
			if ((b = getreg (arg2))==0xff) return 0;
			data[l++] = 0x0f;
			data[l++] = 0x44;
			data[l++] = 0xc0 + (b|(a<<3));
			return 3;
		} else if (!strcmp (op, "mov")) {
			ut64 dst;
			ut8 *ptr;
			ut32 addr;
			int pfx, arg0;
			char *delta = NULL;
			int argk = (*arg == '[');
			addr = dst = r_num_math (NULL, arg2);
			ptr = (ut8 *)&addr;
			if (dst> UT32_MAX) {
				if (a->bits==64) {
					if (*arg=='r')
						data[l++] = 0x48;
					data[1] = 0xb8| getreg (arg);
					data[2] = ptr[0];
					data[3] = ptr[1];
					data[4] = ptr[2];
					data[5] = ptr[3];
					data[6] = ptr[4];
					data[7] = ptr[5];
					data[8] = ptr[6];
					data[9] = ptr[7];
					return 10;
				} else {
					eprintf ("Error: cannot encode 64bit value in 32bit mode\n");
					return -1;
				} 
			}

			if (!arg || !arg2) {
				eprintf ("No args for mov?\n");
				return 0;
			}
			{
				int b0 = bits8 (arg);
				int b1 = bits8 (arg2);
				if (b0!=-1 && b1!=-1) {
					data[0] = 0x8a;
					data[1] = 0xc0 | (b0 <<3)| b1;
					return 2;
				}
			}

			if (argk) {
				arg++;
				delta = strchr (arg, '+');
				//if (!delta) delta = strchr (arg, '-'); // XXX: TODO: handle negative off
				if (delta) {
					*delta++ = 0;
				} else {
					delta = strchr (arg, '-');
					if (delta) {
						ut32 n = -getnum (a, delta+1);
						ut8 *N = (ut8*)&n;
						*delta++ = 0;
						data[l++] = 0xc7;
						data[l++] = 0x80 | getreg (arg);
						data[l++] = N[0];
						data[l++] = N[1];
						data[l++] = N[2];
						data[l++] = N[3];
						n = getnum (a, arg2);
						data[l++] = N[0];
						data[l++] = N[1];
						data[l++] = N[2];
						data[l++] = N[3];
						return l;
					}
				}
				pfx = 0;
			} else pfx = 0xc0;

			if (*arg2=='[') {
				int N;
				arg2++;
				if (a->bits==64)
					if (*arg=='r')
						data[l++] = 0x48;
				delta = strchr (arg2, '+');
				if (delta) {
					N=1;
					*delta++ = 0;
				} else {
					delta = strchr (arg2, '-');
					if (delta) {
						N=-1;
						*delta++ = 0;
					}
				}
				data[l++] = 0x8b;
				if (delta) {
					int r = getreg (arg2);
					if (r==4) { //ESP
						data[l++] = getreg (arg)<<3 | r | 0x40;
						data[l++] = 0x24;
					} else if (r==5) { // EBP
						data[l++] = getreg (arg)<<3 | r | 0x40;
						data[l++] = 0;
					} else data[l++] = getreg (arg) | r | 0x40;
					data[l++] = atoi (delta) * N;
				} else {
					int r = getreg (arg2);
					if (r==4) { //ESP
						data[l++] = getreg (arg)<<3 | r;
						data[l++] = 0x24;
					} else if (r== 5) { // EBP
						data[l++] = getreg (arg)<<3 | r | 0x40;
						data[l++] = 0;
					} else {
						if (r == 0xff) {
							ut32 n;
							ut8 *N = (ut8*)&n;
							data[l++] = getreg (arg)<<3|5;
							n = getnum (a, arg2);
							data[l++] = N[0];
							data[l++] = N[1];
							data[l++] = N[2];
							data[l++] = N[3];
						} else data[l++] = getreg (arg)<<3 | r;
					}
				}
				return l;
			} //else pfx = 0xc0;

			arg0 = getreg (arg); // hack to make is64 work
			if (isnum (a, arg) && argk) {
				int num = getnum (a, arg);
				int r0 = getreg (arg2);
				if (r0 == 0xff) {
					return 0;
				} else {
					// mov [num], reg
					ut8 *ptr = (ut8 *)&num;
					data[l++] = 0x89;
					data[l++] = (r0<<3) | 5;
					data[l++] = ptr[0];
					data[l++] = ptr[1];
					data[l++] = ptr[2];
					data[l++] = ptr[3];
					return l;
				}
			}
			// mov rax, 33
			if (a->bits==64 && *arg == 'r' && !argk) {
				data[l++] = 0x48;
				if (isnum (a, arg2)) {
					data[l++] = 0xc7;
					data[l++] = arg0 | pfx;
					data[l++] = ptr[0];
					data[l++] = ptr[1];
					data[l++] = ptr[2];
					data[l++] = ptr[3];
					return l;
				}
				data[l++] = 0x89;
				data[l++] = arg0 | (getreg (arg2)<<3) | pfx;
				return l;
			}

			if (isnum (a, arg2)) {
				if (delta) {
					int n = getnum (a, delta);
					if (*arg != 'r' && a->bits==64)
						data[l++] = 0x67;
					data[l++] = 0xc7;
					if (1||n>127 || n<-127) { // XXX
						int reg = getreg (arg);
						ut8 *ptr = (ut8 *)&n;
						data[l++] = 0x80 | reg;
						if (reg == 4) // reg=ESP
							data[l++] = ptr[0] | 0x20;
						data[l++] = ptr[0];
						data[l++] = ptr[1];
						data[l++] = ptr[2];
						data[l++] = ptr[3];
					} else {
						data[l++] = 0x40 | getreg (arg);
						data[l++] = getnum (a, delta); //getreg (arg2);
					}
				} else {
					if (argk) {
						int r = getreg (arg);
						data[l++] = 0xc7;
						if (r==4) { //ESP
							data[l++] = 0x04;
							data[l++] = 0x24;
						} else if (r==5) { // EBP
							data[l++] = 0x75;
							data[l++] = 0;
						} else  data[l++] = r;
#define is16reg(x) (x[1]=='l'||x[1]=='h')
					} else {
						if (is16reg (arg)) {
							int op = 0xc0;
							if (arg[1]=='h') op |= 4;
							data[l++] = 0xc6;
							data[l++] = op | (getreg (arg)>>1);
							data[l++] = atoi (arg2);
							return l;
						} else {
							data[l++] = 0xb8 | getreg (arg);
						}
					}
				}
				data[l++] = ptr[0];
				data[l++] = ptr[1];
				data[l++] = ptr[2];
				data[l++] = ptr[3];
				return l;
			} else {
				int r0 = getreg (arg);
				int r1 = getreg (arg2);
				if (r0 == 0xff) {
					return 0;
				}
				if (r1 == 0xff) {
					return 0;
				}
				if (a->bits==64)
					if (*arg=='r')
						data[l++] = 0x48;
				data[l++] = 0x89;
				if (delta) {
					if (isnum (a, delta)){
						data[l++] = 0x40 | r0 | r1<<3;
						data[l++] = getnum (a, delta);
					} else {
						data[l++] = r1<<3 | 0x4;
						data[l++] = (getreg (delta)<<3 ) | r0;
					}
				} else {
					data[l++] = r1<<3 | r0 | pfx;
				}
			}
			return l;
		} else if (!strcmp (op, "jmp")) {
			if (arg[0] == '[' && arg[strlen (arg)-1] == ']') {
				ut8 reg = getreg (arg+1);
				if (reg != 0xff) {
					char *plus = strchr (arg+1, '+');
					if (!plus) plus = strchr (arg+1, '-');
					if (plus) { // "jmp [reg+off]"
						int delta = getnum(a, plus+1);
						ut8 *ptr = (ut8 *)&delta;
						data[l++] = 0xff;
						data[l++] = 0xa0 | reg;
						data[l++] = ptr[0];
						data[l++] = ptr[1];
						data[l++] = ptr[2];
						data[l++] = ptr[3];
					} else { // "jmp [reg]"
						data[l++] = 0xff;
						data[l++] = 0x20 | reg;
					}
					return l;
				} else
				if (!memcmp (arg+1, "rip", 3)) {
					ut64 dst = getnum (a, arg+4);
					ut32 addr = dst;
					ut8 *ptr = (ut8 *)&addr;
					data[l++] = 0xff;
					data[l++] = 0x25;
					data[l++] = ptr[0];
					data[l++] = ptr[1];
					data[l++] = ptr[2];
					data[l++] = ptr[3];
					return l;
				} else {
					ut64 dst = getnum (a, arg+1);
					ut32 addr = dst;
					ut8 *ptr = (ut8 *)&addr;
					if (dst != 0) {
						data[l++] = 0xff;
						data[l++] = 0x25;
						data[l++] = ptr[0];
						data[l++] = ptr[1];
						data[l++] = ptr[2];
						data[l++] = ptr[3];
						return l;
					}
					return -1;
				}
			} else {
				st64 dst = getnum (a, arg); // - offset;
				ut32 addr = dst;
				ut8 *ptr = (ut8 *)&addr;

				if (dst == 0 && *arg != '0') {
					data[l++] = '\xff';
					data[l] = getreg (arg) | 0xe0;
					if (data[l] != 0xff)
						return 2;
					if (arg[0] == '[' && arg[strlen (arg)-1] == ']') {
						data[l] = getreg (arg+1) | 0x20;
						if (data[l] != 0xff)
							return l+1;
						l++;
					}
					return -1;
				}

				dst -= offset;
				if (dst>-0x80 && dst<0x7f) {
					/* relative byte address */
					data[l++] = 0xeb;
					data[l++] = (char)(dst-2);
					return l;
				} else {
					/* relative address */
					addr -= offset;
					addr -= 5;
					data[l++] = 0xe9;
					data[l++] = ptr[0];
					data[l++] = ptr[1];
					data[l++] = ptr[2];
					data[l++] = ptr[3];
					return l;
				}
			}
		} else
// SPAGUETTI
		if (!strcmp (op, "jle")) {
			return jop (a, data, 0x7e, 0x8e, arg);
		} else
		if (!strcmp (op, "jl")) {
			return jop (a, data, 0x7c, 0x8c, arg);
		} else
		if (!strcmp (op, "jg")) {
			return jop (a, data, 0x7f, 0x8f, arg);
		} else
		if (!strcmp (op, "jge")) {
			return jop (a, data, 0x7d, 0x8d, arg);
		} else
		if (!strcmp (op, "ja")) {
			return jop (a, data, 0x77, 0x87, arg);
		} else
		if (!strcmp (op, "jb")) {
			return jop (a, data, 0x72, 0x82, arg);
		} else
		if (!strcmp (op, "jnz") || !strcmp (op, "jne")) {
			return jop (a, data, 0x75, 0x85, arg);
		} else
		if (!strcmp (op, "jz") || !strcmp (op, "je")) {
			return jop (a, data, 0x74, 0x84, arg);
		}
	} else {
		if (!strcmp (op, "leave")) {
			data[l++] = 0xc9;
		} else
		if (!strcmp (op, "syscall")) {
			data[l++] = 0x0f;
			data[l++] = 0x05;
		} else
		if (!strcmp (op, "retf")) {
			data[l++] = 0xcb;
		} else
		if (!strcmp (op, "ret")) {
			data[l++] = 0xc3;
		} else
		if (!strcmp (op, "ret0")) {
			memcpy (data+l, "\x31\xc0\xc3", 3);
			l += 3;
		} else
		if (!strcmp(op, "int3")) {
			data[l++] = 0xcc;
		} else
		if (!strcmp(op, "iret") || !strcmp(op, "iretd")) {
			data[l++] = 0xcf;
		} else
		if (!strcmp (op, "pusha") || !strcmp (op, "pushad")) {
			data[l++] = 0x60;
		} else
		if (!strcmp (op, "popa") || !strcmp (op, "popad")) {
			data[l++] = 0x61;
		} else
		if (!strcmp (op, "nop")) {
			data[l++] = 0x90;
		}
		return l;
	}
	eprintf ("Unknown opcode (%s)\n", op);
	return 0;
}

RAsmPlugin r_asm_plugin_x86_nz = {
	.name = "x86.nz",
	.desc = "x86 handmade assembler",
	.license = "LGPL3",
	.arch = "x86",
	.bits = 32|64,
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
