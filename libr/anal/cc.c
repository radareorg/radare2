/* radare - LGPL - Copyright 2011-2012 - pancake */

// moved from core/cmd.c // the loop that does the funny trick ..
#if 0
NOTES
=====
- RAnalCC must be defined in every function.. maybe in xrefs? or per-opcode cache?
  - hashtable with offset-opcode must be faster to index than to recalc every time
- Interrupts (SWI) will use always a predefined type.. this must be rethinked
#endif

#include <r_anal.h>

R_API RAnalCC* r_anal_cc_new () {
	RAnalCC *cc = R_NEW (RAnalCC);
	r_anal_cc_init (cc);
	return cc;
}

R_API void r_anal_cc_init (RAnalCC *cc) {
	memset (cc, 0, sizeof (RAnalCC));
}

R_API int r_anal_cc_str2type (const char *str) {
	if (!strcmp (str, "none")) return R_ANAL_CC_TYPE_NONE;
	if (!strcmp (str, "cdecl")) return R_ANAL_CC_TYPE_CDECL;
	if (!strcmp (str, "stdcall")) return R_ANAL_CC_TYPE_STDCALL;
	if (!strcmp (str, "fastcall")) return R_ANAL_CC_TYPE_FASTCALL;
	if (!strcmp (str, "pascal")) return R_ANAL_CC_TYPE_PASCAL;
	if (!strcmp (str, "winapi")) return R_ANAL_CC_TYPE_WINAPI;
	if (!strcmp (str, "msfastcall")) return R_ANAL_CC_TYPE_MSFASTCALL;
	if (!strcmp (str, "bofastcall")) return R_ANAL_CC_TYPE_BOFASTCALL;
	if (!strcmp (str, "wafastcall")) return R_ANAL_CC_TYPE_WAFASTCALL;
	if (!strcmp (str, "clarion")) return R_ANAL_CC_TYPE_CLARION;
	if (!strcmp (str, "safecall")) return R_ANAL_CC_TYPE_SAFECALL;
	if (!strcmp (str, "sysv")) return R_ANAL_CC_TYPE_SYSV;
	if (!strcmp (str, "thiscall")) return R_ANAL_CC_TYPE_THISCALL;
	return -1;
}

R_API const char *r_anal_cc_type2str(int type) {
	switch (type) {
	case R_ANAL_CC_TYPE_NONE: return "none";
	case R_ANAL_CC_TYPE_CDECL: return "cdecl";
	case R_ANAL_CC_TYPE_STDCALL: return "stdcall";
	case R_ANAL_CC_TYPE_FASTCALL: return "fastcall";
	case R_ANAL_CC_TYPE_PASCAL: return "pascal";
	case R_ANAL_CC_TYPE_WINAPI: return "winapi";
	case R_ANAL_CC_TYPE_MSFASTCALL: return "msfastcall";
	case R_ANAL_CC_TYPE_BOFASTCALL: return "bofastcall";
	case R_ANAL_CC_TYPE_WAFASTCALL: return "wafastcall";
	case R_ANAL_CC_TYPE_CLARION: return "clarion";
	case R_ANAL_CC_TYPE_SAFECALL: return "safecall";
	case R_ANAL_CC_TYPE_SYSV: return "sysv";
	case R_ANAL_CC_TYPE_THISCALL: return "thiscall";
	}
	return NULL;
}

R_API RAnalCC* r_anal_cc_new_from_string (const char *str, int type) {
	// str = 0x804899 (123, 930, 0x804800)
	return NULL;
}

R_API void r_anal_cc_free (RAnalCC* cc) {
	free (cc);
}

R_API void r_anal_cc_reset (RAnalCC *cc) {
	cc->nargs = 0;
	cc->jump = 0;
}

// XXX: RVM must be inside RAnal ???? imho no. rsyscall must provide ret reg info
//XXX: may overflow. this is vulnerable. needs fix
R_API char *r_anal_cc_to_string (RAnal *anal, RAnalCC* cc) {
	RSyscallItem *si;
	RAnalFunction *fcn;
	char str[1024], buf[64];
	int i, eax = 0; // eax = arg0
	int str_len = 0;
	int buf_len = 0;

	str[0] = 0;
	switch (cc->type) {
	case R_ANAL_CC_TYPE_FASTCALL: // INT
		{
		RRegItem *item;
		const char *a0 = r_reg_get_name (anal->reg, R_REG_NAME_A0); // A0 or RET ??
		item = r_reg_get (anal->reg, a0, R_REG_TYPE_GPR);
		if (!item) {
			//eprintf ("cannot get reg a0\n");
			return R_FALSE;
		}
		eax = (int)r_reg_get_value (anal->reg, item);
		si = r_syscall_get (anal->syscall, eax, (int)cc->jump);
		if (si) {
			//DEBUG r_cons_printf (" ; sc[0x%x][%d]=%s(", (int)analop.value, eax, si->name);
			snprintf (str, sizeof (str), "%s (", si->name);
			for (i=0; i<si->args; i++) {
				const char *reg = r_syscall_reg (anal->syscall, i+1, si->args);
				if (!reg) break; // no registers?
				item = r_reg_get (anal->reg, reg, R_REG_TYPE_GPR);
				if (item) {
					snprintf (buf, sizeof (buf), "0x%"PFMT64x, r_reg_get_value (anal->reg, item));
					strcat (str, buf); // XXX: do not use strcat
				} //else eprintf ("Unknown reg '%s'\n", reg);
				if (i<si->args-1)
					strcat (str, ","); // XXX: do not use strcat
			}
			strcat (str, ")");
		} else {
			int n = (int)cc->jump;
			//if (n == 3) return NULL; // XXX: hack for x86
			snprintf (str, sizeof (str), "syscall[0x%x][%d]=?", n, eax);
		}
		}
		break;
	case R_ANAL_CC_TYPE_CDECL:
		eprintf ("TODO\n");
		break;
	case R_ANAL_CC_TYPE_STDCALL: // CALL
		fcn = r_anal_get_fcn_in (anal, cc->jump,
				R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM|R_ANAL_FCN_TYPE_IMP);
		if (fcn && fcn->name)
			snprintf (str, sizeof (str), "%s(", fcn->name);
		else if (cc->jump != -1LL)
			snprintf (str, sizeof (str), "0x%08"PFMT64x"(", cc->jump);
		else strncpy (str, "unk(", sizeof (str)-1);
		str_len = strlen (str);
		if (fcn) cc->nargs = (fcn->nargs>cc->nargs?fcn->nargs:cc->nargs);
		if (cc->nargs>8) {
			//eprintf ("too many arguments for stdcall. chop to 8\n");
			cc->nargs = 8;
		}
		// TODO: optimize string concat
		for (i=0; i<cc->nargs; i++) {
			if (cc->args[cc->nargs-i] != -1LL)
				 snprintf (buf, sizeof (buf),
					"0x%"PFMT64x, cc->args[cc->nargs-i]);
			else strncpy (buf, "unk", sizeof (buf)-1);
			buf_len = strlen (buf);
			if ((buf_len+str_len+5)>=sizeof (str)) {
				strcat (str, "...");
				break;
			}
			strcat (str, buf);
			str_len += buf_len;
			if (i<cc->nargs-1) strcat (str, ", ");
		}
		strcat (str, ")");
		break;
	}
	return strdup (str);
}

R_API boolt r_anal_cc_update (RAnal *anal, RAnalCC *cc, RAnalOp *op) {
	RRegItem *it;
	cc->off = op->addr;
	switch (op->type) {
	case R_ANAL_OP_TYPE_CALL:
	case R_ANAL_OP_TYPE_UCALL:
		cc->type = R_ANAL_CC_TYPE_STDCALL;
		// TODO: check if next instruction after call is restoring stack
		cc->jump = op->jump;
		return R_FALSE;
	case R_ANAL_OP_TYPE_SWI: // syscall
		cc->type = R_ANAL_CC_TYPE_FASTCALL;
		cc->off = op->jump;
		cc->jump = op->val; // syscall number
		return R_FALSE;
	case R_ANAL_OP_TYPE_XOR:
		if (op->src[0] && op->src[0]->reg && op->dst && op->dst->reg && op->dst->reg->name) {
			char *n1 = op->dst->reg->name;
			char *n2 = op->src[0]->reg->name;
			// XXX: must handle XOR operation properly
			// if n1 == n2 then set to 0
			if (!strcmp (n1, n2)) {
				it = r_reg_get (anal->reg, n1, R_REG_TYPE_GPR);
				r_reg_set_value (anal->reg, it, 0);
			}
		}
		return R_TRUE;
	case R_ANAL_OP_TYPE_MOV:
		if (op->dst && op->dst->reg) {
			it = r_reg_get (anal->reg, op->dst->reg->name, R_REG_TYPE_GPR);
			if (it && op->src[0])
				r_reg_set_value (anal->reg, it, op->src[0]->imm);
		}
		return R_TRUE;
	case R_ANAL_OP_TYPE_PUSH:
	case R_ANAL_OP_TYPE_UPUSH: // add argument
		cc->nargs ++;
		if (cc->nargs>0 && cc->nargs < R_ANAL_CC_ARGS)
			cc->args[cc->nargs] = op->val;
		return R_TRUE;
	}
	// must update internal stuff to recognize parm
	return R_TRUE;
}

// Mixed up with XRefs
R_API int r_anal_cc_register (RAnal *anal, RAnalCC *cc) {
	// register this calling convention to the destination call address
	return R_FALSE;
}

R_API int r_anal_cc_unregister (RAnal *anal, RAnalCC *cc) {
	// register this calling convention to the destination call address
	return R_FALSE;
}

#if 0
////
| - left-to-right, right-to-left
| - stack aligned by caller or callee?
| - list of regs used for args
| - register args, stack args (int, ptr, fpu)
\\\\
typedef struct {
	int type;
	int idx;
	const char *name;
} RAnalCCArg;

typedef struct {
	int order = (rtl/ltr)
	int caller = caller or callee realign the stack
	RAnalCCAarg args[16];
} RAnalCCType;

#define R_ANAL_CC_TYPE_RTL 0 // right to left if lower bit is unset
#define R_ANAL_CC_TYPE_LTR 1 // left to right if lower bit is set
#define R_ANAL_CC_TYPE_CAS 2 // caller aligns stack?
// return stuff
  - type of value , register
    fpu
#define R_ANAL_CC_TYPE_ { INT, PTR, FLT, ANY } .. what for 64bit regs (composed regs, r0+r1<<32)
  - type of value (int, ptr, flt)
  - name of reg ("eax", ..)
  - index of arg (0, 1, 2)
  -

RTL = push 3; push 2; push 1; call foo == foo(1,2,3)
LTR = push 1; push 2; push 3; call foo == foo(1,2,3)

stdcall ___________ rtl
syscall ___________ rtl
fastcall __________
pascal ____________
ms fastcall _______ rtl
borland fastcall __ ltr
watcom fastcall ___ ltr
topspeed/clarion __
intelabi __________
arm _______________
mips ______________
sparc _____________


Calling conventions:
====================
x86: cdecl, fastcall, stdcall
  cdecl: push args in the stack (right-to-left order)
       - return value in eax

  push eax
  push 123
  push byte[ebp+30]
  call eax
  add esp, 12

  syscall: (args right to left)
    - eax, ecx, edx : not preserved, used as args
    - size of parameter list in dwords is passed in AL ??? (OS/2) ???

  optlink:
    - first 3 parameters: eax, edx, ecx
    - up to 4 floating point args: ST(0)-ST(3)

pascal:
  like cdecl, but inverse order, the callee is responsible to clean the code
  push eax
  push 123
  push byte[ebp+30]
  call eax
    -- in eax: ... add esp, 12, ret

fastcall: (borland)

stdcall:
  like cdecl, but the callee is responsible to realign the stack
  - the one used by microsoft and watcom
  - return value in EAX

fastcall:
  - not standarized.. see following

microsoft fastcall:
  - first two args in ECX, EDX, the rest in stack right-to-left

borland fastcall:
  - left-to-right
  - args: eax, edx, ecx, the rest in the stack (also left-to-right)

watcom fastcall:
  - eax, edx, ebx, ecx: left-to-right
  - in stack are right-to-left

topspeed/clarion:
  - eax, ebx, ecx, edx,
  - fpu: st0, st1, st2, st3, st4, st6
  - struct params are in the stack
  - return value:
    - integer: eax
    - pointer: edx
    - floatin: st0

Intel ABI
  - eax, edx, ecx: to not be preserved

x86-64:
  rcx, rdx, r8, r9: integer/pointer arguments
  additional args are pushed into stack
  xmm6, 8-15: floating point args (must preserve xmm6,xmm7)
  return value in rax

  * System V AMD64 ABI convention (osx, linux, ...)
  - rdi, rsi, rdx, rcx, r8, r9: integer arguments
  - for syscalls, s/rcx/r10/
  - xmm0-xmm7 : floating point arguments
  - return value in RAX
  * Windows x64 calling conventions works in this way:
  - everything is pushed into the stack
  - return value in RAX

arm:
  r13 : stack pointer
  r0-r3 : arguments
  r4-r11 : local vars
  r0 : return value

mips:
  first 4 arguments as registers $a0-$a3
  next args in stack.
  return value in $v0 and $v1

sparc:

#endif
