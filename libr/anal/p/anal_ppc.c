/* radare - LGPL - Copyright 2009-2010   pancake<nopcode.org> */

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

// NOTE: buf should be at least 16 bytes!
// XXX addr should be off_t for 64 love
static int aop(struct r_anal_t *anal, struct r_anal_aop_t *aop, ut64 addr, const ut8 *bytes, int len) {
//int arch_ppc_aop(ut64 addr, const u8 *bytes, struct aop_t *aop)
// TODO swap endian here??
	int opcode = (bytes[0] & 0xf8) >> 3; // bytes 0-5
	short baddr  = ((bytes[2]<<8) | (bytes[3]&0xfc));// 16-29
	int aa     = bytes[3]&0x2;
	int lk     = bytes[3]&0x1;
	//if (baddr>0x7fff)
	//      baddr = -baddr;

	memset (aop, '\0', sizeof (struct r_anal_aop_t));
	aop->type = R_ANAL_OP_TYPE_NOP;
	aop->length = 4;

	//printf("OPCODE IS %08x : %02x (opcode=%d) baddr = %d\n", addr, bytes[0], opcode, baddr);

	switch(opcode) {
	case 11: // cmpi
		aop->type = R_ANAL_OP_TYPE_CMP;
		break;
	case 9: // pure branch
		if (bytes[0] == 0x4e) {
			// bctr
		} else {
			aop->jump = (aa)?(baddr):(addr+baddr);
			if (lk) aop->fail = addr+4;
		}
		aop->eob = 1;
		break;
	case 6: // bc // conditional jump
		aop->type = R_ANAL_OP_TYPE_JMP;
		aop->jump = (aa)?(baddr):(addr+baddr+4);
		aop->eob = 1;
		break;
	case 7: // sc/svc
		aop->type = R_ANAL_OP_TYPE_SWI;
		break;
#if 0
	case 15: // bl
		// OK
		aop->type = R_ANAL_OP_TYPE_CJMP;
		aop->jump = (aa)?(baddr):(addr+baddr);
		aop->fail = addr+4;
		aop->eob = 1;
		break;
#endif
	case 8: // bne i tal
		// OK
		aop->type = R_ANAL_OP_TYPE_CJMP;
		aop->jump = (aa)?(baddr):(addr+baddr+4);
		aop->fail = addr+4;
		aop->eob = 1;
		break;
	case 19: // bclr/bcr/bcctr/bcc
		aop->type = R_ANAL_OP_TYPE_RET; // jump to LR
		if (lk) {
			aop->jump = 0xFFFFFFFF; // LR ?!?
			aop->fail = addr+4;
		}
		aop->eob = 1;
		break;
	}
	return 4;
}

static struct r_anal_handle_t r_anal_plugin_ppc = {
	.name = "ppc",
	.desc = "PowerPC analysis plugin",
	.init = NULL,
	.fini = NULL,
	.aop = &aop
};

struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_ppc
};

#if 0
NOTES:
======
     10000
     AA = absolute address
     LK = link bit
     BD = bits 16-19 
       address
     if (AA) {
       address = (int32) BD << 2
     } else {
       address += (int32) BD << 2
     }
    AA LK
    30 31
     0  0  bc
     1  0  bca
     0  1  bcl
     1  1  bcla
    
     10011
     BCCTR
     LK = 31
    
     bclr or bcr (Branch Conditional Link Register) Instruction
     10011
    
     6-29 -> LL (addr) ?
     B  10010 -> branch
     30 31
     0  0   b
     1  0   ba
     0  1   bl
     1  1   bla
     SC SYSCALL 5 first bytes 10001
     SVC SUPERVISORCALL
     30 31
     0  0  svc
     0  1  svcl
     1  0  svca
     1  1  svcla
#endif
