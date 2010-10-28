#include <stdio.h>
#include <stdlib.h>
#include <r_util.h>
#include <r_types.h>
#include "x86/x86im/x86im.h"

static int anal_op (char *buf, int bits) {
	x86im_instr_object io;
	ut8 data[1024];
	int ret;
	
	r_hex_str2bin (buf, data);

	if ((ret = x86im_dec (&io, bits == 32 ? X86IM_IO_MODE_32BIT : X86IM_IO_MODE_64BIT,
			(unsigned char*)data)) == X86IM_STATUS_SUCCESS) {
		printf ("X86IM io struct\n"
			"---------------\n");
		printf ("mode: 0x%lx\n", io.mode);
		printf ("flags: 0x%lx\n", io.flags);
		printf ("id: 0x%lx\n", io.id);
		printf ("grp: 0x%lx\n", io.grp);
		printf ("mnm: 0x%lx\n", io.mnm);
		printf ("len: 0x%lx\n", io.len);
		printf ("def_opsz: 0x%x\n", io.def_opsz);
		printf ("def_adsz: 0x%x\n", io.def_adsz);
		printf ("opcode: 0x%x 0x%x 0x%x\n",
				io.opcode[0], io.opcode[1], io.opcode[2]);
		printf ("opcode_count: 0x%x\n", io.opcode_count);
		printf ("prefix: 0x%hx\n", io.prefix);
		printf ("prefix_values: 0x%x 0x%x 0x%x 0x%x\n",
				io.prefix_values[0], io.prefix_values[1],
				io.prefix_values[2], io.prefix_values[3]);
		printf ("prefix_count: 0x%x\n", io.prefix_count);
		printf ("prefix_order: 0x%lx\n", io.prefix_order);
		printf ("rexp: 0x%x\n", io.rexp);
		printf ("somimp: 0x%x\n", io.somimp);
		printf ("n3did: 0x%x\n", io.n3did);
		printf ("seg: 0x%x\n", io.seg);
		printf ("w_bit: 0x%x\n", io.w_bit);
		printf ("s_bit: 0x%x\n", io.s_bit);
		printf ("d_bit: 0x%x\n", io.d_bit);
		printf ("gg_fld: 0x%x\n", io.gg_fld);
		printf ("tttn_fld: 0x%x\n", io.tttn_fld);
		printf ("selector: 0x%hx\n", io.selector);
		printf ("imm_size: 0x%lx\n", io.imm_size);
		printf ("imm: 0x%"PFMT64x"\n", io.imm);
		printf ("disp_size: 0x%lx\n", io.disp_size);
		printf ("disp: 0x%"PFMT64x"\n", io.disp);
		printf ("mem_flags: 0x%x\n", io.mem_flags);
		printf ("mem_am: 0x%hx\n", io.mem_am);
		printf ("mem_size: 0x%hx\n", io.mem_size);
		printf ("mem_base: 0x%x\n", io.mem_base);
		printf ("mem_index: 0x%x\n", io.mem_index);
		printf ("mem_scale: 0x%x\n", io.mem_scale);
		printf ("modrm: 0x%x\n", io.modrm);
		printf ("sib: 0x%x\n", io.sib);
		printf ("rop: 0x%lx 0x%lx 0x%lx 0x%lx \n",
				io.rop[0], io.rop[1], io.rop[2], io.rop[3]);
		printf ("rop_count: 0x%x\n", io.rop_count);
	} else eprintf ("Error: Unknown opcode\n");
	return ret;
}

int main(int argc, char **argv) {
	int bits = 32;
	if (argc < 2) {
		eprintf ("Usage: %s opcode [bits]\n", argv[0]);
		return 1;
	} else if (argc == 3)
		bits = atoi (argv[2]);
	return anal_op (argv[1], bits);
}
