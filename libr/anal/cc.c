/* radare - LGPL - Copyright 2011 -- pancake@nopcode.org */

// moved from core/cmd.c // the loop that does the funny trick ..

#include <r_anal.h>

R_API RAnalCC* r_anal_cc_new () {
	RAnalCC *cc = R_NEW (RAnalCC);
	//
	return cc;
}

R_API RAnalCC* r_anal_cc_new_from_string (const char *str, int type) {
	// str = 0x804899 (123, 930, 0x804800)
	return NULL;
}

R_API char *r_anal_cc_to_string (RAnalCC* cc) {
	char str[1024];
	str[0] = 0;
	return strdup (str);
}

R_API void r_anal_cc_free (RAnalCC* cc) {
	free (cc);
}

R_API void r_anal_reset (RAnalCC *cc) {
}

R_API boolt r_anal_cc_update (RAnal *anal, RAnalCC *cc, RAnalOp *op) {
	switch (op->type) {
	case R_ANAL_OP_TYPE_CALL:
	case R_ANAL_OP_TYPE_UCALL:
		cc->off = 0;
		// TODO: check if next instruction after call is restoring stack
		return R_FALSE;
	//case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_PUSH:
	case R_ANAL_OP_TYPE_UPUSH:
		// add argument
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
  - the one ised by microsoft and watcom
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
