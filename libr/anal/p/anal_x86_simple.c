/* radare - LGPL - Copyright 2009-2010 */
/*   pancake<nopcode.org> */
/*   nibble<.ds@gmail.com> */

#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#include "x86/dislen/dislen.h"

/* code analysis functions */

/* arch_op for x86 */
// CMP ARG1
// 837d0801        cmp dword [ebp+0x8], 0x1
// 803db501060800  cmp byte [0x80601b5], 0x0
// SET VAR_41c
// 8985e4fbffff    mov [ebp-41C],eax 
// GET VAR_41c
// 8b85e4fbffff    mov eax,[ebp-41C]
// 8b450c          mov eax,[ebp+C] 
// 8d85e8fbffff    lea eax,[ebp-418]
// c68405e7fbffff. mov byte ptr [ebp+eax-419],0x0



//3d00400000  cmp eax, 0x4000
//81fa00c00000  cmp edx, 0xc000
//83fa01  cmp edx, 0x1

static const char *testregs[] = {
	"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };

// NOTE: buf should be at least 16 bytes!
// XXX addr should be off_t for 64 love
static int myop(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	if (buf == NULL)
		return 0;
	memset (op, 0, sizeof (RAnalOp));
	op->type = R_ANAL_OP_TYPE_UNK;
	op->addr = addr;
	op->jump = op->fail = -1;
	op->ptr = op->val = -1;

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
			op->ptr = (st64)((char)buf[2]);
			op->stackop = R_ANAL_STACK_GET;
			break;
		case 0x95:
			if (buf[2]==0xe0) { // ebp
				op->ptr = (st64)((int)(buf[3]+(buf[4]<<8)+(buf[5]<<16)+(buf[6]<<24)));
				op->stackop = R_ANAL_STACK_GET;
			}
			//op->ptr = -(buf[2]+(buf[3]<<8)+(buf[4]<<16)+(buf[5]<<24));
			break;
		case 0xbd:
			op->ptr = (st64)((int)(buf[2]+(buf[3]<<8)+(buf[4]<<16)+(buf[5]<<24)));
			//op->ptr = -(buf[2]+(buf[3]<<8)+(buf[4]<<16)+(buf[5]<<24));
			op->stackop = R_ANAL_STACK_GET;
			break;
		}
		break;
	case 0x88:
	case 0x89: // move
		switch (buf[1]) {
		case 0x45:
		case 0x4d: //  894de0          mov [ebp-0x20], ecx 
		case 0x55:
			op->stackop = R_ANAL_STACK_SET;
			op->ptr = (st64)((char)buf[2]);
			break;
		case 0x85:
			op->stackop = R_ANAL_STACK_SET;
			op->ptr = (st64)((int)(buf[2]+(buf[3]<<8)+(buf[4]<<16)+(buf[5]<<24)));
			break;
		case 0x75:
			op->stackop = R_ANAL_STACK_GET;
			op->ptr = (st64)((char)buf[2]); //+(buf[3]<<8)+(buf[4]<<16)+(buf[5]<<24));
			break;
		}
		// XXX: maybe store or mov depending on opcode
		// 89c3  mov ebx, eax
		// 897c2408  mov [esp+0x8], edi
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case 0xf4: // hlt
		op->type   = R_ANAL_OP_TYPE_RET;
		op->length = 1;
		break;
	case 0xc3: // ret
	case 0xc2: // ret + 2 bytes
	case 0xcb: // lret
	case 0xcf: // iret
		op->type   = R_ANAL_OP_TYPE_RET;
		op->eob = 1;
		break;
	//case 0xea: // far jmp
	// TODO moar
	case 0x3b: //cmp
		op->ptr = (st64)((char)buf[2]);
		op->stackop = R_ANAL_STACK_GET;
	case 0x39:
	case 0x3c:
	case 0x3d:
		// 3d 00 40 00 00  cmp eax, 0x4000
		op->src[0] = r_anal_value_new ();
		op->src[0]->reg = r_reg_get (anal->reg, testregs[(buf[0]&7)%8], R_REG_TYPE_GPR);
		op->src[1] = r_anal_value_new ();
		op->src[1]->base = buf[1]+(buf[2]<<8)+(buf[3]<<16)+(buf[4]<<24);
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case 0x80:
		op->type = R_ANAL_OP_TYPE_CMP;
		switch (buf[1]) {
		case 0x3d: // 80 3d b5010608 00  cmp byte [0x80601b5], 0x0
			op->src[0] = r_anal_value_new ();
			op->src[0]->memref = 1;
			op->src[0]->base = buf[2]+(buf[3]<<8)+(buf[4]<<16)+(buf[5]<<24);
			op->src[1] = r_anal_value_new ();
			op->src[1]->base = buf[6];
			break;
		}
		break;
	case 0x85:
		op->type = R_ANAL_OP_TYPE_CMP;
		if (buf[1]>=0xc0) {
			int src = buf[1]&7;
			int dst = (buf[1]&0x38)>>3;
			op->src[0] = r_anal_value_new ();
			op->src[0]->reg = r_reg_get (anal->reg, testregs[src%8], R_REG_TYPE_GPR);
			op->src[1] = r_anal_value_new ();
			op->src[1]->reg = r_reg_get (anal->reg, testregs[dst%8], R_REG_TYPE_GPR);
			op->src[2] = NULL;
//eprintf ("REGZ (%s)\n", anal->reg);
//eprintf ("REG IZ: (%s)\n", testregs[src%8]);
//eprintf ("REG IZ: %p (%s)\n", op->src[0], op->src[0]->reg->name);
			if (op->src[0]->reg == op->src[1]->reg) {
//eprintf ("fruity\n");
				r_anal_value_free (op->src[1]);
				op->src[1] = NULL;
			}
			//eprintf ("0x%"PFMT64x": (%02x) %d %d\n", addr, buf[1], src, dst);
		} else if (buf[1]<0xc0) { // test [eax+delta], eax
			/* not yet supported */
		}
		// c0-c7 : eax, ecx, edx, ebx, esp, ebp, esi, edi
		// 83f821  cmp eax, 0x21
		// 85c0    test eax, eax
		// 85c9  test ecx, ecx
		break;
	case 0x90:
		op->type   = R_ANAL_OP_TYPE_NOP;
		op->length = 1;
		break;
	case 0x0f: // 3 byte nop
		//0fbe55ff        movsx edx, byte [ebp-0x1]
		if (buf[1]==0xbe) {
			op->ptr = (st64)((char)buf[3]);
			op->stackop = R_ANAL_STACK_GET;
		} else
		if (buf[1]==0x31) {
			// RDTSC // colorize or sthg?
			op->eob = 0;
		} else
		if (buf[1]>=0x18 && buf[1]<=0x1f) {
			op->type = R_ANAL_OP_TYPE_NOP;
			op->length = 3;
		} else
		if (buf[1]>=0x80 && buf[1]<=0x8f) {
			op->type   = R_ANAL_OP_TYPE_CJMP;
			op->jump   = addr+6+buf[2]+(buf[3]<<8)+(buf[4]<<16)+(buf[5]<<24);//((unsigned long)((buf+2))+6);
			op->fail   = addr+6;
			op->length = 6;
			//op->eob    = 1;
		} else
		if (buf[1]>=0x40 && buf[1]<=0x4f) { /* Conditional MOV */
			op->type = R_ANAL_OP_TYPE_MOV;
			op->eob = 0;
			op->length = 4;
			return 4;
		}
		break;
	case 0xcc: // int3
//		op->eob = 1;
		op->val = 3;
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case 0xf1: // int1
		op->length = 1;
		op->val = 1;
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case 0xb8: // mov eax, <inmedate>
	case 0xb9: // mov ecx, <inmedate>
	case 0xba: // mov edx, <inmedate>
	case 0xbb: // mov ebx, <inmedate>
	case 0xbc: // mov esp, <inmedate>
	case 0xbd: // mov esp, <inmedate>
	case 0xbf:
		op->type = R_ANAL_OP_TYPE_MOV; //  bfdc054000      mov edi, 0x4005dc
		op->ptr = (st64)((int)buf[1]+(buf[2]<<8)+(buf[3]<<16)+(buf[4]<<24));//((unsigned long)((buf+2))+6);
		break;
	case 0xcd:
		op->length = 2;
		op->type = R_ANAL_OP_TYPE_SWI;
		op->val = buf[1];
		break;
	case 0xe8: // call
		op->type   = R_ANAL_OP_TYPE_CALL;
		op->length = 5;
		//op->jump   = addr+*ptr+5; //(unsigned long)((buf+1)+5);
		op->jump = addr+5+buf[1]+(buf[2]<<8)+(buf[3]<<16)+(buf[4]<<24);//((unsigned long)((buf+2))+6);
		op->fail = addr+5;
//printf("addr: %08"PFMT64x"\n call %08"PFMT64x" \n ret %08"PFMT64x"\n", addr, op->jump, op->fail);
	//	op->eob    = 1;
		break;
	case 0xe9: // jmp
		op->type = R_ANAL_OP_TYPE_JMP;
		op->length = 5;
		//op->jump   = (unsigned long)((buf+1)+5);
		op->jump = addr+5+buf[1]+(buf[2]<<8)+(buf[3]<<16)+(buf[4]<<24);//((unsigned long)((buf+2))+6);
		op->fail = 0L;
		op->eob = 1;
		break;
	case 0xeb: // short jmp 
		op->type = R_ANAL_OP_TYPE_JMP;
		op->length = 2;
		op->jump = addr+((unsigned long)((char)buf[1])+2);
		op->fail = 0L;
		op->eob = 1;
		break;
	case 0xf2: // repnz
	case 0xf3: // repz
		op->type   = R_ANAL_OP_TYPE_REP;
		//op->length = dislen((unsigned char *)&buf); //instLength(buf, 16, 0);
		op->jump   = 0L;
		op->fail   = 0L;
		break;
	case 0xff:
		if (buf[1]== 0x75) {
			op->type = R_ANAL_OP_TYPE_PUSH;
			op->stackop = R_ANAL_STACK_GET;
			op->ptr = 0LL;
			op->ptr = (st64)((char)(buf[2]));
			op->stackptr = 4;
		} else
		if (buf[1]== 0x45) {
			op->type = R_ANAL_OP_TYPE_ADD;
			op->stackop = R_ANAL_STACK_SET;
			op->ptr = (st64)((char)buf[2]);
		} else
		if (buf[1]>=0x50 && buf[1]<=0x6f) {
			op->type = R_ANAL_OP_TYPE_UJMP;
			op->eob    = 1;
		} else
		if (buf[1]>=0xd0 && buf[1]<=0xd7) {
			op->type = R_ANAL_OP_TYPE_CALL;
			op->length = 2;
			op->eob    = 1;
			//op->jump   = vm_arch_x86_regs[VM_X86_EAX+buf[1]-0xd0];
			op->fail   = addr+2;
		} else
		if (buf[1]>=0xe0 && buf[1]<=0xe7) {
			op->type = R_ANAL_OP_TYPE_UJMP;
			op->length = 2;
			//op->jump   = vm_arch_x86_regs[VM_X86_EAX+buf[1]-0xd0];
			op->eob    = 1;
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
		op->type = R_ANAL_OP_TYPE_UPUSH;
		op->ptr = 0; // TODO value of register here! get_offset
		op->stackptr = 4;
		break;
	case 0x6a: // push $7
		op->type = R_ANAL_OP_TYPE_PUSH;
		op->ptr = buf[1];
		op->stackptr = 4;
		break;
		break;
	case 0x5a:
	case 0x5b:
	case 0x5c:
	case 0x5d:
	case 0x5e:
	case 0x5f:
		op->type = R_ANAL_OP_TYPE_POP;
		op->length = 1;
		op->stackptr = -4;
		break;
	case 0x2e: // 2e64796e jns 0xb770a4ab !!
		if (buf[1]>=0x64 && buf[1]<=0x67) {
			int ret = myop (anal, op, addr, buf+1, len-1);
			op->jump++;
			op->length++;
			return ret;
		}
		break;
	case 0x64:
	case 0x65:
	case 0x66:
	case 0x67:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addr+3+buf[2]; //+(buf[2]<<8)+(buf[3]<<16); // XXX
		op->length = 3;
		op->fail = addr+op->length;
		//op->eob    = 1;
		break;
	case 0x68:
		op->type = R_ANAL_OP_TYPE_PUSH;
		op->ptr = (st64)((int)buf[1]+(buf[2]<<8)+(buf[3]<<16)+(buf[4]<<24));
		op->stackptr = 4;
		break;
	case 0x81:
		op->type = R_ANAL_OP_TYPE_ADD;
		if (buf[1] == 0xec) {
			/* sub $0x????????, $esp*/
  			// 81ece00d0000    sub esp, 0xde0 ; 
			op->val = buf[2]+(buf[3]<<8)+(buf[4]<<16)+(buf[5]<<24);
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = op->val;
			break;
		} else
		if (buf[1] == 0xfa) {
			op->type = R_ANAL_OP_TYPE_CMP;
			// 81fa00c00000  cmp edx, 0xc000
			// XXX TODO
		}
		break;
	case 0x83:
		switch (buf[1]) {
		case 0xe4: // and
			op->val = (ut64)(unsigned char)buf[2];
			op->type = R_ANAL_OP_TYPE_AND;
			break;
		case 0xc4:
			/* inc $0x????????, $esp*/
			op->val = -(ut64)(unsigned char)buf[2];
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = op->val;
			break;
		case 0xf8:
		case 0xf9:
		case 0xfa:
			{
			int src = buf[1]&7;
			op->src[0] = r_anal_value_new ();
			op->src[0]->reg = r_reg_get (anal->reg, testregs[src%8], R_REG_TYPE_GPR);
			op->src[1] = r_anal_value_new ();
			op->src[1]->base = buf[2];
			// 83f821  cmp eax, 0x21
			op->type = R_ANAL_OP_TYPE_CMP;
			op->length = 3;
			}
			break;
		case 0xec:
			/* sub $0x????????, $esp*/
			op->val = (ut64)(unsigned char)buf[2];
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = op->val;
			break;
		case 0xbd: /* 837dfc02        cmp dword [ebp-0x4], 0x2 */
			switch (buf[2]) {
			case 0xe0: // ebp
				if ((char)buf[2]>0) {
					op->stackop = R_ANAL_STACK_GET;
					op->val = buf[3]+(buf[4]<<8)+(buf[5]<<16)+(buf[6]<<24);
				} else {
					op->stackop = R_ANAL_STACK_GET;
					op->val = buf[3]+(buf[4]<<8)+(buf[5]<<16)+(buf[6]<<24);
				}
				op->type = R_ANAL_OP_TYPE_CMP;
				break;
			}
			break;
		case 0x7d: /* 837dfc02        cmp dword [ebp-0x4], 0x2 */
			if ((char)buf[2]>0) {
				op->stackop = R_ANAL_STACK_GET;
				op->val = (ut64)(char)buf[2];
			} else {
				op->stackop = R_ANAL_STACK_GET;
				op->val = (ut64)-(char)buf[2];
			}
			op->type = R_ANAL_OP_TYPE_CMP;
			break;
		}
		break;
	case 0x8d:
		/* LEA */
		if (buf[1] == 0x85) {
			op->ptr = (st64)((int)(buf[2]+(buf[3]<<8)+(buf[4]<<16)+(buf[5]<<24)));
			op->stackop = R_ANAL_STACK_GET;
		}
		op->type =R_ANAL_OP_TYPE_MOV;
		break;
	case 0xc6:
	case 0xc7:
		/* mov dword [ebp-0xc], 0x0  ||  c7 45 f4 00000000 */
		switch (buf[1]) {
		case 0x85:
			op->ptr = (st64)(((int)(buf[2]+(buf[3]<<8)+(buf[4]<<16)+(buf[5]<<24))));
			break;
 			//c785 e4fbffff 00. mov dword [ebp+0xfffffbe4], 0x0
		case 0x45:
			op->stackop = R_ANAL_STACK_SET;
			op->ptr = (st64)((char)buf[2]);
			break;
		case 0x05:
			// c7050c0106080000. mov dword [0x806010c], 0x0
			//  c605b401060800  mov byte [0x80601b4], 0x0
			// TODO: 
			break;
		case 0x04:
			// c7042496850408    dword [esp] = 0x8048596 ; LOL
                        op->refptr = 4;
			op->ptr = (st64)(((int)(buf[3]+(buf[4]<<8)+(buf[5]<<16)+(buf[6]<<24))));
			break;
		}
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case 0x82:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case 0x29:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case 0x31:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case 0x32:
		op->type = R_ANAL_OP_TYPE_AND;
		break;

	case 0xa1: // mov eax, [addr]
		op->type = R_ANAL_OP_TYPE_MOV;
		//vm_arch_x86_regs[VM_X86_EAX] = addr+buf[1]+(buf[2]<<8)+(buf[3]<<16)+(buf[4]<<24);
		//radare_read_at((ut64)vm_arch_x86_regs[VM_X86_EAX], (unsigned char *)&(vm_arch_x86_regs[VM_X86_EAX]), 4);
		break;
#if 0
	case0xF
		/* conditional jump */
		if (buf[1]>=0x80&&buf[1]<=0x8F) {
			op->type   = R_ANAL_OP_TYPE_CJMP;
			op->length = 6;
			op->jump   = (unsigned long)((buf+2)+6);
			op->fail   = addr+6;
			op->eob    = 1;
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
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->length = 2;
		//	op->jump   = (unsigned long)((buf+2)+6);
			op->jump = addr+bo+2; //(unsigned long)((buf+1)+5);
			op->fail = addr+2;
			op->eob = 1;
			//return 2;
		}
		break;
	//default:
		//op->type = R_ANAL_OP_TYPE_UNK;
	}

	//if (op->length == 0)
	op->length = dislen ((unsigned char *)buf, 64); //instLength(buf, 16, 0);
		//op->length = instLength(buf, 16, 0);
	if (!(op->jump>>33))
		op->jump &= 0xFFFFFFFF; // XXX may break on 64 bits here
	return op->length;
}

struct r_anal_plugin_t r_anal_plugin_x86_simple = {
	.name = "x86.simple",
	.desc = "X86 analysis plugin",
	.license = "LGPL3",
	.arch = R_SYS_ARCH_X86,
	.bits = 32,
	.init = NULL,
	.fini = NULL,
	.op = &myop,
	.set_reg_profile = NULL,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_x86_simple
};
#endif
