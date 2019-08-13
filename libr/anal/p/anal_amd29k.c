/* radare2 - LGPL - Copyright 2013-2019 - pancake */

#include <r_anal.h>
#include <r_lib.h>
#include "../../asm/arch/amd29k/amd29k.h"


static int set_reg_profile(RAnal *anal) {
	const char *p =
			"=PC	pc\n"
			"=SP	gp1\n"
			"=BP	gp2\n"
			"=SR	gp3\n" // status register ??
			"=SN	gp4\n" // also for ret
			"=A0	lr1\n" // also for ret
			"=A1	lr2\n"
			"=A2	lr3\n"
			"=A3	lr4\n"
			"=A4	lr5\n"
			"=A5	lr6\n"
			"=A6	lr7\n"
			"gpr	gp0     .32 0 0\n"
			"gpr	gp1     .32 8 0\n"
			"gpr	gp2     .32 16 0\n"
			"gpr	gp3     .32 24 0\n"
			"gpr	gp4     .32 32 0\n"
			"gpr	gp5     .32 40 0\n"
			"gpr	gp6     .32 48 0\n"
			"gpr	gp7     .32 56 0\n"
			"gpr	gp8     .32 64 0\n"
			"gpr	gp9     .32 72 0\n"
			"gpr	gp10    .32 80 0\n"
			"gpr	gp11    .32 88 0\n"
			"gpr	gp12    .32 96 0\n"
			"gpr	gp13    .32 104 0\n"
			"gpr	gp14    .32 112 0\n"
			"gpr	gp15    .32 120 0\n"
			"gpr	gp16    .32 128 0\n"
			"gpr	gp17    .32 136 0\n"
			"gpr	gp18    .32 144 0\n"
			"gpr	gp19    .32 152 0\n"
			"gpr	gp20    .32 160 0\n"
			"gpr	gp21    .32 168 0\n"
			"gpr	gp22    .32 176 0\n"
			"gpr	gp23    .32 184 0\n"
			"gpr	gp24    .32 192 0\n"
			"gpr	gp25    .32 200 0\n"
			"gpr	gp26    .32 208 0\n"
			"gpr	gp27    .32 216 0\n"
			"gpr	gp28    .32 224 0\n"
			"gpr	gp29    .32 232 0\n"
			"gpr	gp30    .32 240 0\n"
			"gpr	gp31    .32 248 0\n"
			"gpr	gp32    .32 256 0\n"
			"gpr	gp33    .32 264 0\n"
			"gpr	gp34    .32 272 0\n"
			"gpr	gp35    .32 280 0\n"
			"gpr	gp36    .32 288 0\n"
			"gpr	gp37    .32 296 0\n"
			"gpr	gp38    .32 304 0\n"
			"gpr	gp39    .32 312 0\n"
			"gpr	gp40    .32 320 0\n"
			"gpr	gp41    .32 328 0\n"
			"gpr	gp42    .32 336 0\n"
			"gpr	gp43    .32 344 0\n"
			"gpr	gp44    .32 352 0\n"
			"gpr	gp45    .32 360 0\n"
			"gpr	gp46    .32 368 0\n"
			"gpr	gp47    .32 376 0\n"
			"gpr	gp48    .32 384 0\n"
			"gpr	gp49    .32 392 0\n"
			"gpr	gp50    .32 400 0\n"
			"gpr	gp51    .32 408 0\n"
			"gpr	gp52    .32 416 0\n"
			"gpr	gp53    .32 424 0\n"
			"gpr	gp54    .32 432 0\n"
			"gpr	gp55    .32 440 0\n"
			"gpr	gp56    .32 448 0\n"
			"gpr	gp57    .32 456 0\n"
			"gpr	gp58    .32 464 0\n"
			"gpr	gp59    .32 472 0\n"
			"gpr	gp60    .32 480 0\n"
			"gpr	gp61    .32 488 0\n"
			"gpr	gp62    .32 496 0\n"
			"gpr	gp63    .32 504 0\n"
			"gpr	gp64    .32 512 0\n"
			"gpr	gp65    .32 520 0\n"
			"gpr	gp66    .32 528 0\n"
			"gpr	gp67    .32 536 0\n"
			"gpr	gp68    .32 544 0\n"
			"gpr	gp69    .32 552 0\n"
			"gpr	gp70    .32 560 0\n"
			"gpr	gp71    .32 568 0\n"
			"gpr	gp72    .32 576 0\n"
			"gpr	gp73    .32 584 0\n"
			"gpr	gp74    .32 592 0\n"
			"gpr	gp75    .32 600 0\n"
			"gpr	gp76    .32 608 0\n"
			"gpr	gp77    .32 616 0\n"
			"gpr	gp78    .32 624 0\n"
			"gpr	gp79    .32 632 0\n"
			"gpr	gp80    .32 640 0\n"
			"gpr	gp81    .32 648 0\n"
			"gpr	gp82    .32 656 0\n"
			"gpr	gp83    .32 664 0\n"
			"gpr	gp84    .32 672 0\n"
			"gpr	gp85    .32 680 0\n"
			"gpr	gp86    .32 688 0\n"
			"gpr	gp87    .32 696 0\n"
			"gpr	gp88    .32 704 0\n"
			"gpr	gp89    .32 712 0\n"
			"gpr	gp90    .32 720 0\n"
			"gpr	gp91    .32 728 0\n"
			"gpr	gp92    .32 736 0\n"
			"gpr	gp93    .32 744 0\n"
			"gpr	gp94    .32 752 0\n"
			"gpr	gp95    .32 760 0\n"
			"gpr	gp96    .32 768 0\n"
			"gpr	gp97    .32 776 0\n"
			"gpr	gp98    .32 784 0\n"
			"gpr	gp99    .32 792 0\n"
			"gpr	gp100   .32 800 0\n"
			"gpr	gp101   .32 808 0\n"
			"gpr	gp102   .32 816 0\n"
			"gpr	gp103   .32 824 0\n"
			"gpr	gp104   .32 832 0\n"
			"gpr	gp105   .32 840 0\n"
			"gpr	gp106   .32 848 0\n"
			"gpr	gp107   .32 856 0\n"
			"gpr	gp108   .32 864 0\n"
			"gpr	gp109   .32 872 0\n"
			"gpr	gp110   .32 880 0\n"
			"gpr	gp111   .32 888 0\n"
			"gpr	gp112   .32 896 0\n"
			"gpr	gp113   .32 904 0\n"
			"gpr	gp114   .32 912 0\n"
			"gpr	gp115   .32 920 0\n"
			"gpr	gp116   .32 928 0\n"
			"gpr	gp117   .32 936 0\n"
			"gpr	gp118   .32 944 0\n"
			"gpr	gp119   .32 952 0\n"
			"gpr	gp120   .32 960 0\n"
			"gpr	gp121   .32 968 0\n"
			"gpr	gp122   .32 976 0\n"
			"gpr	gp123   .32 984 0\n"
			"gpr	gp124   .32 992 0\n"
			"gpr	gp125   .32 1000 0\n"
			"gpr	gp126   .32 1008 0\n"
			"gpr	gp127   .32 1016 0\n"
			"gpr	lr1     .32 1024 0\n"
			"gpr	lr2     .32 1032 0\n"
			"gpr	lr3     .32 1040 0\n"
			"gpr	lr4     .32 1048 0\n"
			"gpr	lr5     .32 1056 0\n"
			"gpr	lr6     .32 1064 0\n"
			"gpr	lr7     .32 1072 0\n"
			"gpr	lr8     .32 1080 0\n"
			"gpr	lr9     .32 1088 0\n"
			"gpr	lr10    .32 1096 0\n"
			"gpr	lr11    .32 1104 0\n"
			"gpr	lr12    .32 1112 0\n"
			"gpr	lr13    .32 1120 0\n"
			"gpr	lr14    .32 1128 0\n"
			"gpr	lr15    .32 1136 0\n"
			"gpr	lr16    .32 1144 0\n"
			"gpr	lr17    .32 1152 0\n"
			"gpr	lr18    .32 1160 0\n"
			"gpr	lr19    .32 1168 0\n"
			"gpr	lr20    .32 1176 0\n"
			"gpr	lr21    .32 1184 0\n"
			"gpr	lr22    .32 1192 0\n"
			"gpr	lr23    .32 1200 0\n"
			"gpr	lr24    .32 1208 0\n"
			"gpr	lr25    .32 1216 0\n"
			"gpr	lr26    .32 1224 0\n"
			"gpr	lr27    .32 1232 0\n"
			"gpr	lr28    .32 1240 0\n"
			"gpr	lr29    .32 1248 0\n"
			"gpr	lr30    .32 1256 0\n"
			"gpr	lr31    .32 1264 0\n"
			"gpr	lr32    .32 1272 0\n"
			"gpr	lr33    .32 1280 0\n"
			"gpr	lr34    .32 1288 0\n"
			"gpr	lr35    .32 1296 0\n"
			"gpr	lr36    .32 1304 0\n"
			"gpr	lr37    .32 1312 0\n"
			"gpr	lr38    .32 1320 0\n"
			"gpr	lr39    .32 1328 0\n"
			"gpr	lr40    .32 1336 0\n"
			"gpr	lr41    .32 1344 0\n"
			"gpr	lr42    .32 1352 0\n"
			"gpr	lr43    .32 1360 0\n"
			"gpr	lr44    .32 1368 0\n"
			"gpr	lr45    .32 1376 0\n"
			"gpr	lr46    .32 1384 0\n"
			"gpr	lr47    .32 1392 0\n"
			"gpr	lr48    .32 1400 0\n"
			"gpr	lr49    .32 1408 0\n"
			"gpr	lr50    .32 1416 0\n"
			"gpr	lr51    .32 1424 0\n"
			"gpr	lr52    .32 1432 0\n"
			"gpr	lr53    .32 1440 0\n"
			"gpr	lr54    .32 1448 0\n"
			"gpr	lr55    .32 1456 0\n"
			"gpr	lr56    .32 1464 0\n"
			"gpr	lr57    .32 1472 0\n"
			"gpr	lr58    .32 1480 0\n"
			"gpr	lr59    .32 1488 0\n"
			"gpr	lr60    .32 1496 0\n"
			"gpr	lr61    .32 1504 0\n"
			"gpr	lr62    .32 1512 0\n"
			"gpr	lr63    .32 1520 0\n"
			"gpr	lr64    .32 1528 0\n"
			"gpr	lr65    .32 1536 0\n"
			"gpr	lr66    .32 1544 0\n"
			"gpr	lr67    .32 1552 0\n"
			"gpr	lr68    .32 1560 0\n"
			"gpr	lr69    .32 1568 0\n"
			"gpr	lr70    .32 1576 0\n"
			"gpr	lr71    .32 1584 0\n"
			"gpr	lr72    .32 1592 0\n"
			"gpr	lr73    .32 1600 0\n"
			"gpr	lr74    .32 1608 0\n"
			"gpr	lr75    .32 1616 0\n"
			"gpr	lr76    .32 1624 0\n"
			"gpr	lr77    .32 1632 0\n"
			"gpr	lr78    .32 1640 0\n"
			"gpr	lr79    .32 1648 0\n"
			"gpr	lr80    .32 1656 0\n"
			"gpr	lr81    .32 1664 0\n"
			"gpr	lr82    .32 1672 0\n"
			"gpr	lr83    .32 1680 0\n"
			"gpr	lr84    .32 1688 0\n"
			"gpr	lr85    .32 1696 0\n"
			"gpr	lr86    .32 1704 0\n"
			"gpr	lr87    .32 1712 0\n"
			"gpr	lr88    .32 1720 0\n"
			"gpr	lr89    .32 1728 0\n"
			"gpr	lr90    .32 1736 0\n"
			"gpr	lr91    .32 1744 0\n"
			"gpr	lr92    .32 1752 0\n"
			"gpr	lr93    .32 1760 0\n"
			"gpr	lr94    .32 1768 0\n"
			"gpr	lr95    .32 1776 0\n"
			"gpr	lr96    .32 1784 0\n"
			"gpr	lr97    .32 1792 0\n"
			"gpr	lr98    .32 1800 0\n"
			"gpr	lr99    .32 1808 0\n"
			"gpr	lr100   .32 1816 0\n"
			"gpr	lr101   .32 1824 0\n"
			"gpr	lr102   .32 1832 0\n"
			"gpr	lr103   .32 1840 0\n"
			"gpr	lr104   .32 1848 0\n"
			"gpr	lr105   .32 1856 0\n"
			"gpr	lr106   .32 1864 0\n"
			"gpr	lr107   .32 1872 0\n"
			"gpr	lr108   .32 1880 0\n"
			"gpr	lr109   .32 1888 0\n"
			"gpr	lr110   .32 1896 0\n"
			"gpr	lr111   .32 1904 0\n"
			"gpr	lr112   .32 1912 0\n"
			"gpr	lr113   .32 1920 0\n"
			"gpr	lr114   .32 1928 0\n"
			"gpr	lr115   .32 1936 0\n"
			"gpr	lr116   .32 1944 0\n"
			"gpr	lr117   .32 1952 0\n"
			"gpr	lr118   .32 1960 0\n"
			"gpr	lr119   .32 1968 0\n"
			"gpr	lr120   .32 1976 0\n"
			"gpr	lr121   .32 1984 0\n"
			"gpr	lr122   .32 1992 0\n"
			"gpr	lr123   .32 2000 0\n"
			"gpr	lr124   .32 2008 0\n"
			"gpr	lr125   .32 2016 0\n"
			"gpr	lr126   .32 2024 0\n"
			"gpr	lr127   .32 2032 0\n"
			"gpr	lr128   .32 2040 0\n";
	return r_reg_set_profile_string (anal->reg, p);
}

static int archinfo(RAnal *a, int q) {
	return 4;
}

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	op->delay = 0;
	op->type = R_ANAL_OP_TYPE_NULL;
	op->jump = op->fail = UT64_MAX;
	op->ptr = op->val = UT64_MAX;
	op->size = 4;
	op->eob = false;

	// delayed branch is bugged as hell. disabled for now.

	amd29k_instr_t instruction = {0};
	if (amd29k_instr_decode (buf, len, &instruction, a->cpu)) {
		op->type = instruction.op_type;
		switch (op->type) {
		case R_ANAL_OP_TYPE_JMP:
			op->jump = amd29k_instr_jump (addr, &instruction);
			//op->delay = 1;
			break;
		case R_ANAL_OP_TYPE_CJMP:
			op->jump = amd29k_instr_jump (addr, &instruction);
			op->fail = addr + 4;
			//op->delay = 1;
			break;
		case R_ANAL_OP_TYPE_ICALL:
			if (amd29k_instr_is_ret (&instruction)) {
				op->type = R_ANAL_OP_TYPE_RET;
				op->eob = true;
			}
			//op->delay = 1;
			break;
		case R_ANAL_OP_TYPE_RET:
			op->eob = true;
			//op->delay = 1;
			break;
		default:
			op->delay = 0;
			break;
		}
	}

	return op->size;
}

RAnalPlugin r_anal_plugin_amd29k = {
	.name = "amd29k",
	.desc = "AMD 29k analysis",
	.license = "BSD",
	.esil = false,
	.arch = "amd29k",
	.bits = 32,
	.archinfo = archinfo,
	.op = &analop,
	.set_reg_profile = &set_reg_profile,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_amd29k,
	.version = R2_VERSION
};
#endif
