/* radare - LGPL - Copyright 2009 */
/*   pancake<nopcode.org> */
/*   nibble<.ds@gmail.com> */

#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#include "x86/dislen.h"

/* code analysis functions */

/* arch_aop for x86 */
// CMP ARG1
// 837d0801        cmp dword [ebp+0x8], 0x1
// SET VAR_41c
// 8985e4fbffff    mov [ebp-41C],eax 
// GET VAR_41c
// 8b85e4fbffff    mov eax,[ebp-41C]
// 8b450c          mov eax,[ebp+C] 
// 8d85e8fbffff    lea eax,[ebp-418]
// c68405e7fbffff. mov byte ptr [ebp+eax-419],0x0

// NOTE: buf should be at least 16 bytes!
// XXX addr should be off_t for 64 love
static int aop(RAnal *anal, RAnalAop *aop, ut64 addr, const ut8 *data, int len) {
	ut8 *buf = (ut8*)data;
	if (data == NULL)
		return 0;
	memset (aop, '\0', sizeof (RAnalAop));
	aop->type = R_ANAL_OP_TYPE_UNK;
	aop->addr = addr;

	switch (buf[0]) {
	case 0x8a:
	case 0x8b:
	case 0x03: //  034518          add eax, [ebp+0x18]
		switch (buf[1]) {
		case 0x45:
		case 0x46:
		case 0x55:
		case 0x5d:
		case 0x7d:
			/* mov -0xc(%ebp, %eax */
			aop->ref = (st64)((char)buf[2]);
			aop->stackop = R_ANAL_STACK_LOCAL_GET;
			break;
		case 0x95:
			if (buf[2]==0xe0) { // ebp
				aop->ref = (st64)((int)(buf[3]+(buf[4]<<8)+(buf[5]<<16)+(buf[6]<<24)));
				aop->stackop = R_ANAL_STACK_LOCAL_GET;
			}
			//aop->ref = -(buf[2]+(buf[3]<<8)+(buf[4]<<16)+(buf[5]<<24));
			break;
		case 0xbd:
			aop->ref = (st64)((int)(buf[2]+(buf[3]<<8)+(buf[4]<<16)+(buf[5]<<24)));
			//aop->ref = -(buf[2]+(buf[3]<<8)+(buf[4]<<16)+(buf[5]<<24));
			aop->stackop = R_ANAL_STACK_LOCAL_GET;
			break;
		}
		break;
	case 0x88:
	case 0x89: // move
		switch(buf[1]) {
		case 0x45:
		case 0x4d: //  894de0          mov [ebp-0x20], ecx 
		case 0x55:
			aop->stackop = R_ANAL_STACK_LOCAL_SET;
			aop->ref = (st64)((char)buf[2]);
			break;
		case 0x85:
			aop->stackop = R_ANAL_STACK_LOCAL_SET;
			aop->ref = (st64)((int)(buf[2]+(buf[3]<<8)+(buf[4]<<16)+(buf[5]<<24)));
			break;
		case 0x75:
			aop->stackop = R_ANAL_STACK_LOCAL_GET;
			aop->ref = (st64)((char)buf[2]); //+(buf[3]<<8)+(buf[4]<<16)+(buf[5]<<24));
			break;
		}
		aop->type   = R_ANAL_OP_TYPE_MOV;
		aop->length = 2;
		break;
	case 0xf4: // hlt
		aop->type   = R_ANAL_OP_TYPE_RET;
		aop->length = 1;
		break;
	case 0xc3: // ret
	case 0xc2: // ret + 2 bytes
	case 0xcb: // lret
	case 0xcf: // iret
		aop->type   = R_ANAL_OP_TYPE_RET;
	//	aop->length = 1;
		aop->eob = 1;
		break;
	//case 0xea: // far jmp
	// TODO moar
	case 0x3b: //cmp
		aop->ref = (st64)((char)buf[2]);
		aop->stackop = R_ANAL_STACK_LOCAL_GET;
	case 0x39:
	case 0x3c:
	case 0x3d:
	case 0x85:
		aop->type   = R_ANAL_OP_TYPE_CMP;
		aop->length = 2;
		break;
	case 0x90:
		aop->type   = R_ANAL_OP_TYPE_NOP;
		aop->length = 1;
		break;
	case 0x0f: // 3 byte nop
		//0fbe55ff        movsx edx, byte [ebp-0x1]
		if (buf[1]==0xbe) {
			aop->ref = (st64)((char)buf[3]);
			aop->stackop = R_ANAL_STACK_LOCAL_GET;
		} else
		if (buf[1]==0x31) {
			// RDTSC // colorize or sthg?
			aop->eob = 0;
		} else
		if (buf[1]>=0x18 && buf[1]<=0x1f) {
			aop->type = R_ANAL_OP_TYPE_NOP;
			aop->length = 3;
		} else
		if (buf[1]>=0x80 && buf[1]<=0x8f) {
			aop->type   = R_ANAL_OP_TYPE_CJMP;
			aop->jump   = addr+6+buf[2]+(buf[3]<<8)+(buf[4]<<16)+(buf[5]<<24);//((unsigned long)((buf+2))+6);
			aop->fail   = addr+6;
			aop->length = 6;
			//aop->eob    = 1;
		} 
		else
		if (buf[1]>=0x40 && buf[1]<=0x4f) { /* Conditional MOV */
			aop->type = R_ANAL_OP_TYPE_MOV;
			aop->eob = 0;
			aop->length = 4;
			return 4;
		}
		break;
	case 0xcc: // int3
		aop->eob = 1;
	case 0xf1: // int1
		aop->length = 1;
		aop->type   = R_ANAL_OP_TYPE_SWI;
		break;
	case 0xb8: // mov eax, <inmedate>
	case 0xb9: // mov ecx, <inmedate>
	case 0xba: // mov edx, <inmedate>
	case 0xbb: // mov ebx, <inmedate>
	case 0xbc: // mov esp, <inmedate>
	case 0xbd: // mov esp, <inmedate>
	case 0xbf:
		aop->type = R_ANAL_OP_TYPE_MOV; //  bfdc054000      mov edi, 0x4005dc
		aop->ref = (st64)((int)buf[1]+(buf[2]<<8)+(buf[3]<<16)+(buf[4]<<24));//((unsigned long)((buf+2))+6);
		break;
	case 0xcd:
		aop->length = 2;
		aop->type   = R_ANAL_OP_TYPE_SWI;
		break;
	case 0xe8: // call
		aop->type   = R_ANAL_OP_TYPE_CALL;
		aop->length = 5;
		//aop->jump   = addr+*ptr+5; //(unsigned long)((buf+1)+5);
		aop->jump = addr+5+buf[1]+(buf[2]<<8)+(buf[3]<<16)+(buf[4]<<24);//((unsigned long)((buf+2))+6);
		aop->fail = addr+5;
//printf("addr: %08llx\n call %08llx \n ret %08llx\n", addr, aop->jump, aop->fail);
	//	aop->eob    = 1;
		break;
	case 0xe9: // jmp
		aop->type = R_ANAL_OP_TYPE_JMP;
		aop->length = 5;
		//aop->jump   = (unsigned long)((buf+1)+5);
		aop->jump = addr+5+buf[1]+(buf[2]<<8)+(buf[3]<<16)+(buf[4]<<24);//((unsigned long)((buf+2))+6);
		aop->fail = 0L;
		aop->eob = 1;
		break;
	case 0xeb: // short jmp 
		aop->type = R_ANAL_OP_TYPE_JMP;
		aop->length = 2;
		aop->jump = addr+((unsigned long)((char)buf[1])+2);
		aop->fail = 0L;
		aop->eob = 1;
		break;
	case 0xf2: // repnz
	case 0xf3: // repz
		aop->type   = R_ANAL_OP_TYPE_REP;
		//aop->length = dislen((unsigned char *)&buf); //instLength(buf, 16, 0);
		aop->jump   = 0L;
		aop->fail   = 0L;
		break;
	case 0xff:
		if (buf[1]== 0x75) {
			aop->type = R_ANAL_OP_TYPE_PUSH;
			aop->stackop = R_ANAL_STACK_ARG_GET;
			aop->ref = 0LL;
			aop->ref = (st64)((char)(buf[2]));
		} else
		if (buf[1]== 0x45) {
			aop->type = R_ANAL_OP_TYPE_ADD;
			aop->stackop = R_ANAL_STACK_LOCAL_SET;
			aop->ref = (st64)((char)buf[2]);
		} else
		if (buf[1]>=0x50 && buf[1]<=0x6f) {
			aop->type = R_ANAL_OP_TYPE_UJMP;
			aop->eob    = 1;
		} else
		if (buf[1]>=0xd0 && buf[1]<=0xd7) {
			aop->type = R_ANAL_OP_TYPE_CALL;
			aop->length = 2;
			aop->eob    = 1;
			//aop->jump   = vm_arch_x86_regs[VM_X86_EAX+buf[1]-0xd0];
			aop->fail   = addr+2;
		} else
		if (buf[1]>=0xe0 && buf[1]<=0xe7) {
			aop->type = R_ANAL_OP_TYPE_UJMP;
			aop->length = 2;
			//aop->jump   = vm_arch_x86_regs[VM_X86_EAX+buf[1]-0xd0];
			aop->eob    = 1;
		}
		break;
	case 0x50:
	case 0x51:
	case 0x52:
	case 0x53:
	case 0x54:
	case 0x55:
	case 0x56:
	case 0x57:
	case 0x58:
	case 0x59:
		aop->type = R_ANAL_OP_TYPE_UPUSH;
		aop->ref = 0; // TODO value of register here! get_offset
		break;
	case 0x5a:
	case 0x5b:
	case 0x5c:
	case 0x5d:
	case 0x5e:
	case 0x5f:
		aop->type = R_ANAL_OP_TYPE_POP;
		aop->length = 1;
		break;
	case 0x68:
		aop->type = R_ANAL_OP_TYPE_PUSH;
		aop->ref = (st64)((int)buf[1]+(buf[2]<<8)+(buf[3]<<16)+(buf[4]<<24));
		break;
	case 0x81:
		if (buf[1] == 0xec) {
			/* sub $0x????????, $esp*/
  			// 81ece00d0000    sub esp, 0xde0 ; 
			aop->value = buf[2]+(buf[3]<<8)+(buf[4]<<16)+(buf[5]<<24);
			aop->stackop = R_ANAL_STACK_INCSTACK;
			break;
		}
		aop->type = R_ANAL_OP_TYPE_ADD;
		break;
	case 0x83:
		switch(buf[1]) {
		case 0xe4: // and
			aop->value = (ut64)(unsigned char)buf[2];
			aop->type = R_ANAL_OP_TYPE_AND;
			break;
		case 0xc4:
			/* inc $0x????????, $esp*/
			aop->value = -(ut64)(unsigned char)buf[2];
			aop->stackop = R_ANAL_STACK_INCSTACK;
			break;
		case 0xec:
			/* sub $0x????????, $esp*/
			aop->value = (ut64)(unsigned char)buf[2];
			aop->stackop = R_ANAL_STACK_INCSTACK;
			break;
		case 0xbd: /* 837dfc02        cmp dword [ebp-0x4], 0x2 */
			switch(buf[2]) {
			case 0xe0: // ebp
				if ((char)buf[2]>0) {
					aop->stackop = R_ANAL_STACK_ARG_GET;
					aop->value = buf[3]+(buf[4]<<8)+(buf[5]<<16)+(buf[6]<<24);
				} else {
					aop->stackop = R_ANAL_STACK_LOCAL_GET;
					aop->value = buf[3]+(buf[4]<<8)+(buf[5]<<16)+(buf[6]<<24);
				}
				aop->type = R_ANAL_OP_TYPE_CMP;
				break;
			}
			break;
		case 0x7d: /* 837dfc02        cmp dword [ebp-0x4], 0x2 */
			if ((char)buf[2]>0) {
				aop->stackop = R_ANAL_STACK_ARG_GET;
				aop->value = (ut64)(char)buf[2];
			} else {
				aop->stackop = R_ANAL_STACK_LOCAL_GET;
				aop->value = (ut64)-(char)buf[2];
			}
			aop->type = R_ANAL_OP_TYPE_CMP;
			break;
		}
		break;
	case 0x8d:
		/* LEA */
		if (buf[1] == 0x85) {
			aop->ref = (st64)((int)(buf[2]+(buf[3]<<8)+(buf[4]<<16)+(buf[5]<<24)));
			aop->stackop = R_ANAL_STACK_LOCAL_GET;
		}
		aop->type =R_ANAL_OP_TYPE_MOV;
		break;
	case 0xc7:
		/* mov dword [ebp-0xc], 0x0  ||  c7 45 f4 00000000 */
		switch (buf[1]) {
		case 0x85:
			aop->ref = (st64)(((int)(buf[2]+(buf[3]<<8)+(buf[4]<<16)+(buf[5]<<24))));
			break;
 			//c785 e4fbffff 00. mov dword [ebp+0xfffffbe4], 0x0
		case 0x45:
			aop->stackop = R_ANAL_STACK_LOCAL_SET;
			aop->ref = (st64)((char)buf[2]);
			break;
		case 0x04:
			// c7042496850408    dword [esp] = 0x8048596 ; LOL
			aop->ref = (st64)(((int)(buf[3]+(buf[4]<<8)+(buf[5]<<16)+(buf[6]<<24))));
			break;
		}
		aop->type = R_ANAL_OP_TYPE_STORE;
		break;
	case 0x82:
		aop->type = R_ANAL_OP_TYPE_ADD;
		break;
	case 0x29:
		aop->type = R_ANAL_OP_TYPE_SUB;
		break;
	case 0x31:
		aop->type = R_ANAL_OP_TYPE_XOR;
		break;
	case 0x32:
		aop->type = R_ANAL_OP_TYPE_AND;
		break;

	case 0xa1: // mov eax, [addr]
		aop->type = R_ANAL_OP_TYPE_MOV;
		//vm_arch_x86_regs[VM_X86_EAX] = addr+buf[1]+(buf[2]<<8)+(buf[3]<<16)+(buf[4]<<24);
		//radare_read_at((ut64)vm_arch_x86_regs[VM_X86_EAX], (unsigned char *)&(vm_arch_x86_regs[VM_X86_EAX]), 4);
		break;
#if 0
	case0xF
		/* conditional jump */
		if (buf[1]>=0x80&&buf[1]<=0x8F) {
			aop->type   = R_ANAL_OP_TYPE_CJMP;
			aop->length = 6;
			aop->jump   = (unsigned long)((buf+2)+6);
			aop->fail   = addr+6;
			aop->eob    = 1;
			return 5;
		}
		break;
#endif
	case 0x70:
	case 0x71:
	case 0x72:
	case 0x73:
	case 0x74:
	case 0x75:
	case 0x76:
	case 0x77:
	case 0x78:
	case 0x79:
	case 0x7a:
	case 0x7b:
	case 0x7c:
	case 0x7d:
	case 0x7e:
	case 0x7f: {
		int bo = (int)((char) buf[1]);
		/* conditional jump */
		//if (buf[1]>=0x80&&buf[1]<=0x8F) {
			aop->type = R_ANAL_OP_TYPE_CJMP;
			aop->length = 2;
		//	aop->jump   = (unsigned long)((buf+2)+6);
			aop->jump = addr+bo+2; //(unsigned long)((buf+1)+5);
			aop->fail = addr+2;
			aop->eob = 1;
			//return 2;
		}
		break;
	//default:
		//aop->type = R_ANAL_OP_TYPE_UNK;
	}

	//if (aop->length == 0)
	aop->length = dislen ((unsigned char *)buf, 64); //instLength(buf, 16, 0);
		//aop->length = instLength(buf, 16, 0);
	if (!(aop->jump>>33))
		aop->jump &= 0xFFFFFFFF; // XXX may break on 64 bits here
	return aop->length;
}

struct r_anal_handle_t r_anal_plugin_x86 = {
	.name = "x86",
	.desc = "X86 analysis plugin",
	.init = NULL,
	.fini = NULL,
	.aop = &aop
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_x86
};
#endif
