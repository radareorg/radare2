/* radare - LGPL - Copyright 2011 -- pancake@nopcode.org */

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
	RAnalFcn *fcn;
	char str[1024], buf[32];
	int i, eax = 0; // eax = arg0

	str[0] = 0;
	switch (cc->type) {
	case R_ANAL_CC_TYPE_FASTCALL: // INT
		//int eax = (int)r_vm_reg_get (core->vm, core->vm->cpu.ret); //"eax");
		si = r_syscall_get (anal->syscall, eax, (int)cc->jump);
		if (si) {
			//DEBUG r_cons_printf (" ; sc[0x%x][%d]=%s(", (int)analop.value, eax, si->name);
			snprintf (str, sizeof (str), "%s (", si->name);
			for (i=0; i<si->args; i++) {
				const char *reg = r_syscall_reg (anal->syscall, i+1, si->args);
				sprintf (buf, "(%s)", reg);
				//TODO sprintf (buf, "0x%"PFMT64x, 0LL); //r_vm_reg_get (core->vm, reg));
				strcat (str, buf);
				if (i<si->args-1)
					strcat (str, ",");
			}
			strcat (str, ")");
		} else snprintf (str, sizeof (str), "syscall[0x%x][%d]=?", (int)cc->jump, eax);
		break;
	case R_ANAL_CC_TYPE_STDCALL: // CALL
		//	if (analop.jump != UT64_MAX) {
		fcn = r_anal_fcn_find (anal, cc->off, R_ANAL_FCN_TYPE_FCN);
		if (fcn && fcn->name) snprintf (str, sizeof (str), "%s(", fcn->name);
		else snprintf (str, sizeof (str), "0x%08"PFMT64x"(", cc->jump);
		if (fcn) cc->nargs = (fcn->nargs>cc->nargs?cc->nargs:fcn->nargs);
		for (i=0; i<cc->nargs; i++) {
			snprintf (buf, sizeof (buf),
				(cc->args[cc->nargs-i]>1024)?"%"PFMT64d:"0x%"PFMT64x,
				cc->args[cc->nargs-i]);
			strcat (str, buf);
			if (i<cc->nargs-1) strcat (str, ", ");
		}
		strcat (str, ")");
		break;
	}
	return strdup (str);
}

R_API boolt r_anal_cc_update (RAnal *anal, RAnalCC *cc, RAnalOp *op) {
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
		cc->jump = op->value; // syscall number
		return R_FALSE;
	//case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_PUSH:
	case R_ANAL_OP_TYPE_UPUSH: // add argument
		cc->nargs ++;
		if (cc->nargs>0 && cc->nargs < R_ANAL_CC_ARGS)
			cc->args[cc->nargs] = op->ref;
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
