/* c55plus - LGPL - Copyright 2013 - th0rpe */

#include "ins.h"

ut8 *ins_buff = (ut8 *)NULL; // = "\x77\x21\x20\x21\x00\x30\x21\x77\x20\x21";
ut32 ins_buff_len = 0;

static unsigned int has_failed = 0;

ut32 get_ins_len(ut8 opcode) {
	ut32 val = (opcode >> 4) & 0xF;
	ut32 len = 0;

	switch (val) {
	case 0:
	case 1:
		len = 2;
		break;
	case 2:
	case 3:
		len = 1;
		break;
	case 4:
	case 5:
	case 6:
	case 7:
		len = 3;
		break;
	case 8:
	case 9:
	case 10:
		len = 4;
		break;
	case 11:
	case 12:
	case 13:
		len = 5;
		break;
	case 14:
		len = 6;
		break;
	case 15:
		len = 7;
		break;
	}

	return len;
}

ut32 get_ins_part(ut32 pos, ut32 len) {
	ut32 ret = 0;
	has_failed = 0;
	if (C55PLUS_DEBUG)
        	printf("pos => 0x%x len => %d ins_buff_len => %d\n", pos, len, ins_buff_len);

	if ((st32)pos < 0 || pos >= ins_buff_len) {
		has_failed = 1;
		return ret;
	} 

	for (; len > 0; --len) {
		ret <<= 8;
		if (pos >= ins_buff_len) 
			has_failed = 1;
		else ret |= ins_buff[pos++];
	}

	return ret;
}

// pseudo instructions array (used for replacement tokens)
st8* ins_str[] = {
(st8 *)0x0,
(st8*)"OOOOOOppHHHhhhhhkkkkkkkk"
,
(st8*)"while (`HHHhhhhh` && (RPTC < `kkkkkkkk`)) repeat"
,
(st8*)"RPTCC `kkkkkkkk`, `HHHhhhhh`"
,
(st8 *)0x1,
(st8*)"OOOOOOOOHHHhhhhh"
,
(st8*)"if (`HHHhhhhh`) return"
,
(st8*)"RETCC `HHHhhhhh`"
,
(st8 *)0x2,
(st8*)"OOOOOOOpLLLLLLLLHHHhhhhh"
,
(st8*)"if (`HHHhhhhh`) goto `LLLLLLLL`"
,
(st8*)"BCC `LLLLLLLL`, `HHHhhhhh`"
,
(st8 *)0x3,
(st8*)"OOOOOOOpLLLLLLLLLLLLLLLL"
,
(st8*)"`q_SAT,n`goto `LLLLLLLLLLLLLLLL`"
,
(st8*)"`q_SAT,N`B `LLLLLLLLLLLLLLLL`"
,
(st8 *)0x4,
(st8*)"OOOOOOOpLLLLLLLLLLLLLLLL"
,
(st8*)"call `LLLLLLLLLLLLLLLL`"
,
(st8*)"CALL `LLLLLLLLLLLLLLLL`"
,
(st8 *)0x5,
(st8 *)0x0,
(st8*)"RPTL_P_64"
,
(st8*)"RPTL_P_64"
,
(st8 *)0x6,
(st8*)"OOOOOOppkkkkkkkkkkkkkkkk"
,
(st8*)"repeat(`kkkkkkkkkkkkkkkk`)"
,
(st8*)"RPT `kkkkkkkkkkkkkkkk`"
,
(st8 *)0x7,
(st8*)"OOOOOOppllllllllllllllll"
,
(st8*)"blockrepeat { `llllllllllllllll,i`"
,
(st8*)"RPTB `llllllllllllllll`"
,
(st8 *)0x8,
(st8*)"OOOOOOOOpAAaaaaapCCccccco-SSSSSS"
,
(st8*)"`AAaaaaa,WACx` = `AAaaaaa,WACx` & (`CCccccc,WACx` <<< `SSSSSS`)"
,
(st8*)"AND `CCccccc,WACx` << `SSSSSS`, `AAaaaaa,WACx`"
,
(st8 *)0x9,
(st8*)"OOOOOOOOpAAaaaaapCCccccco-SSSSSS"
,
(st8*)"`AAaaaaa,WACx` = `AAaaaaa,WACx` | (`CCccccc,WACx` <<< `SSSSSS`)"
,
(st8*)"OR `CCccccc,WACx` << `SSSSSS`, `AAaaaaa,WACx`"
,
(st8 *)0xA,
(st8*)"OOOOOOOOpAAaaaaapCCccccco-SSSSSS"
,
(st8*)"`AAaaaaa,WACx` = `AAaaaaa,WACx` ^ (`CCccccc,WACx` <<< `SSSSSS`)"
,
(st8*)"XOR `CCccccc,WACx` << `SSSSSS`, `AAaaaaa,WACx`"
,
(st8 *)0xB,
(st8*)"OOOOOOOOpAAaaaaapCCccccco-SSSSSS"
,
(st8*)"`AAaaaaa,WACx` = `q_SAT,(``AAaaaaa,WACx` + (`CCccccc,WACx` << `SSSSSS`)`q_SAT,)`"
,
(st8*)"ADD`q_SAT` `CCccccc,WACx` << `SSSSSS`, `AAaaaaa,WACx`"
,
(st8 *)0xC,
(st8*)"OOOOOOOOpAAaaaaapCCccccco-SSSSSS"
,
(st8*)"`AAaaaaa,WACx` = `q_SAT,(``AAaaaaa,WACx` - (`CCccccc,WACx` << `SSSSSS`)`q_SAT,)`"
,
(st8*)"SUB`q_SAT` `CCccccc,WACx` << `SSSSSS`, `AAaaaaa,WACx`"
,
(st8 *)0xD,
(st8*)"OOOOOOOOpAAaaaaapCCccccco-SSSSSS"
,
(st8*)"`AAaaaaa,WACx` = `q_SAT,(``CCccccc,WACx` << `SSSSSS``q_SAT,)`"
,
(st8*)"SFTS`q_SAT` `CCccccc,WACx`, `SSSSSS`, `AAaaaaa,WACx`"
,
(st8 *)0xE,
(st8*)"OOOOOOOOpAAaaaaapCCccccco-SSSSSS"
,
(st8*)"`AAaaaaa,WACx` = `q_SAT,(``CCccccc,WACx` <<C `SSSSSS``q_SAT,)`"
,
(st8*)"SFTSC`q_SAT` `CCccccc,WACx`, `SSSSSS`, `AAaaaaa,WACx`"
,
(st8 *)0xF,
(st8*)"OOOOOOOOpAAaaaaapCCccccco-SSSSSS"
,
(st8*)"`AAaaaaa,WACx` = `CCccccc,WACx` <<< `SSSSSS`"
,
(st8*)"SFTL `CCccccc,WACx`, `SSSSSS`, `AAaaaaa,WACx`"
,
(st8 *)0x10,
(st8*)"OOOOOOOOpAAaaaaap----------ccccc"
,
(st8*)"`AAaaaaa,RLHx` = exp(`ccccc,ACx`)"
,
(st8*)"EXP `ccccc,ACx`, `AAaaaaa,RLHx`"
,
(st8 *)0x11,
(st8*)"OOOOOOOOpAAaaaaap--bbbbb---ccccc"
,
(st8*)"`bbbbb,ACx` = mant(`ccccc,ACx`), `AAaaaaa,RLHx` = exp(`ccccc,ACx`)"
,
(st8*)"MANT `ccccc,ACx`, `bbbbb,ACx` :: NEXP `ccccc,ACx`, `AAaaaaa,RLHx`"
,
(st8 *)0x12,
(st8*)"OOOOOOOOpAAaaaaap-Tccccc---ddddd"
,
(st8*)"`AAaaaaa,RLHx` = count(`ccccc,ACx`, `ddddd,ACx`, `T`)"
,
(st8*)"BCNT `ccccc,ACx`, `ddddd,ACx`, `T`, `AAaaaaa,RLHx`"
,
(st8 *)0x13,
(st8*)"OOOOOOOOp--aaaaap--bbbbb---cccccrrrddddd"
,
(st8*)"max_diff`q_SAT,a`(`ccccc,ACx`, `ddddd,ACx`, `aaaaa,ACx`, `bbbbb,ACx`, pair(`rrr`))"
,
(st8*)"MAXDIFF`q_SAT` `ccccc,ACx`, `ddddd,ACx`, `aaaaa,ACx`, `bbbbb,ACx`, pair(`rrr`)"
,
(st8 *)0x14,
(st8*)"OOOOOOOOp--aaaaap--bbbbb---cccccrrrddddd"
,
(st8*)"max_diff_dbl`q_SAT,a`(`ccccc,ACx`, `ddddd,ACx`, `aaaaa,ACx`, `bbbbb,ACx`, `rrr`)"
,
(st8*)"DMAXDIFF`q_SAT` `ccccc,ACx`, `ddddd,ACx`, `aaaaa,ACx`, `bbbbb,ACx`, `rrr`"
,
(st8 *)0x15,
(st8*)"OOOOOOOOp--aaaaap--bbbbb---cccccrrrddddd"
,
(st8*)"min_diff`q_SAT,a`(`ccccc,ACx`, `ddddd,ACx`, `aaaaa,ACx`, `bbbbb,ACx`, pair(`rrr`))"
,
(st8*)"MINDIFF`q_SAT` `ccccc,ACx`, `ddddd,ACx`, `aaaaa,ACx`, `bbbbb,ACx`, pair(`rrr`)"
,
(st8 *)0x16,
(st8*)"OOOOOOOOp--aaaaap--bbbbb---cccccrrrddddd"
,
(st8*)"min_diff_dbl`q_SAT,a`(`ccccc,ACx`, `ddddd,ACx`, `aaaaa,ACx`, `bbbbb,ACx`, `rrr`)"
,
(st8*)"DMINDIFF`q_SAT` `ccccc,ACx`, `ddddd,ACx`, `aaaaa,ACx`, `bbbbb,ACx`, `rrr`"
,
(st8 *)0x17,
(st8*)"OOOOOOOOpCCcccccpDDdddddo-$-JJ-T"
,
(st8*)"`T` = `$`(`CCccccc,Rx` `JJ` `DDddddd,Rx`)"
,
(st8*)"CMP`$` `CCccccc,Rx` `JJ` `DDddddd,Rx`, `T`"
,
(st8 *)0x18,
(st8*)"OOOOOOOOpCCcccccpDDdddddo-$-JJTT"
,
(st8*)"`TT,2` = `TT,1` & `$`(`CCccccc,Rx` `JJ` `DDddddd,Rx`)"
,
(st8*)"CMPAND`$` `CCccccc,Rx` `JJ` `DDddddd,Rx`, `TT,1`, `TT,2`"
,
(st8 *)0x19,
(st8*)"OOOOOOOOpCCcccccpDDdddddo-$-JJTT"
,
(st8*)"`TT,2` = !`TT,1` & `$`(`CCccccc,Rx` `JJ` `DDddddd,Rx`)"
,
(st8*)"CMPAND`$` `CCccccc,Rx` `JJ` `DDddddd,Rx`, !`TT,1`, `TT,2`"
,
(st8 *)0x1A,
(st8*)"OOOOOOOOpCCcccccpDDdddddo-$-JJTT"
,
(st8*)"`TT,2` = `TT,1` | `$`(`CCccccc,Rx` `JJ` `DDddddd,Rx`)"
,
(st8*)"CMPOR`$` `CCccccc,Rx` `JJ` `DDddddd,Rx`, `TT,1`, `TT,2`"
,
(st8 *)0x1B,
(st8*)"OOOOOOOOpCCcccccpDDdddddo-$-JJTT"
,
(st8*)"`TT,2` = !`TT,1` | `$`(`CCccccc,Rx` `JJ` `DDddddd,Rx`)"
,
(st8*)"CMPOR`$` `CCccccc,Rx` `JJ` `DDddddd,Rx`, !`TT,1`, `TT,2`"
,
(st8 *)0x1C,
(st8*)"OOOOOOOO-AAaaaaapCCccccc------VV"
,
(st8*)"`AAaaaaa,Rx` = `VV,2` \\ `CCccccc,Rx` \\ `VV,1`"
,
(st8*)"ROL `VV,2`, `CCccccc,Rx`, `VV,1`, `AAaaaaa,Rx`"
,
(st8 *)0x1D,
(st8*)"OOOOOOOO-AAaaaaapCCccccc------VV"
,
(st8*)"`AAaaaaa,Rx` = `VV,1` // `CCccccc,Rx` // `VV,2`"
,
(st8*)"ROR `VV,1`, `CCccccc,Rx`, `VV,2`, `AAaaaaa,Rx`"
,
(st8 *)0x1E,
(st8*)"OOOOOOOOp-Aaaaaap-Cccccc"
,
(st8*)"mar(`q_CIRC,(``q_LINR,(``Aaaaaa,WDAx` + `Cccccc,WDAx``q_CIRC,)``q_LINR,)`)"
,
(st8*)"AADD`q_CIRC``q_LINR` `Cccccc,WDAx`, `Aaaaaa,WDAx`"
,
(st8 *)0x1F,
(st8*)"OOOOOOOOp-Aaaaaap-Cccccc"
,
(st8*)"mar(`q_CIRC,(``q_LINR,(``Aaaaaa,WDAx` = `Cccccc,WDAx``q_CIRC,)``q_LINR,)`)"
,
(st8*)"AMOV`q_CIRC``q_LINR` `Cccccc,WDAx`, `Aaaaaa,WDAx`"
,
(st8 *)0x20,
(st8*)"OOOOOOOOp-Aaaaaap-Cccccc"
,
(st8*)"mar(`q_CIRC,(``q_LINR,(``Aaaaaa,WDAx` - `Cccccc,WDAx``q_CIRC,)``q_LINR,)`)"
,
(st8*)"ASUB`q_CIRC``q_LINR` `Cccccc,WDAx`, `Aaaaaa,WDAx`"
,
(st8 *)0x21,
(st8*)"OOOOOOOOppAaaaaakkkkkkkkkkkkkkkk"
,
(st8*)"mar(`q_CIRC,(``q_LINR,(``Aaaaaa,WDAx` + `kkkkkkkkkkkkkkkk``q_CIRC,)``q_LINR,)`)"
,
(st8*)"AADD`q_CIRC``q_LINR` `kkkkkkkkkkkkkkkk`, `Aaaaaa,WDAx`"
,
(st8 *)0x22,
(st8 *)0x0,
(st8*)"MAR_K_MX"
,
(st8*)"MAR_K_MX"
,
(st8 *)0x23,
(st8*)"OOOOOOOOppAaaaaakkkkkkkkkkkkkkkk"
,
(st8*)"mar(`q_CIRC,(``q_LINR,(``Aaaaaa,WDAx` - `kkkkkkkkkkkkkkkk``q_CIRC,)``q_LINR,)`)"
,
(st8*)"ASUB`q_CIRC``q_LINR` `kkkkkkkkkkkkkkkk`, `Aaaaaa,WDAx`"
,
(st8 *)0x24,
(st8 *)0x0,
(st8*)"MAR_DA_AY"
,
(st8*)"MAR_DA_AY"
,
(st8 *)0x25,
(st8 *)0x0,
(st8*)"MAR_DA_MY"
,
(st8*)"MAR_DA_MY"
,
(st8 *)0x26,
(st8 *)0x0,
(st8*)"MAR_DA_SY"
,
(st8*)"MAR_DA_SY"
,
(st8 *)0x27,
(st8 *)0x0,
(st8*)"MAR_K_AY"
,
(st8*)"MAR_K_AY"
,
(st8 *)0x28,
(st8 *)0x0,
(st8*)"MAR_K_MY"
,
(st8*)"MAR_K_MY"
,
(st8 *)0x29,
(st8 *)0x0,
(st8*)"MAR_K_SY"
,
(st8*)"MAR_K_SY"
,
(st8 *)0x2A,
(st8 *)0x0,
(st8*)"LD_RPK_MDP"
,
(st8*)"LD_RPK_MDP"
,
(st8 *)0x2B,
(st8 *)0x0,
(st8*)"LD_RPK_MDP05"
,
(st8*)"LD_RPK_MDP05"
,
(st8 *)0x2C,
(st8 *)0x0,
(st8*)"LD_RPK_MDP67"
,
(st8*)"LD_RPK_MDP67"
,
(st8 *)0x2D,
(st8 *)0x0,
(st8*)"LD_RPK_PDP"
,
(st8*)"LD_RPK_PDP"
,
(st8 *)0x2E,
(st8 *)0x0,
(st8*)"LD_BK_03"
,
(st8*)"LD_BK_03"
,
(st8 *)0x2F,
(st8 *)0x0,
(st8*)"LD_BK_47"
,
(st8*)"LD_BK_47"
,
(st8 *)0x30,
(st8 *)0x0,
(st8*)"LD_BK_C"
,
(st8*)"LD_BK_C"
,
(st8 *)0x31,
(st8 *)0x0,
(st8*)"LD_BK_CSR"
,
(st8*)"LD_BK_CSR"
,
(st8 *)0x32,
(st8 *)0x0,
(st8*)"LD_BK_BR0"
,
(st8*)"LD_BK_BR0"
,
(st8 *)0x33,
(st8 *)0x0,
(st8*)"LD_BK_BR1"
,
(st8*)"LD_BK_BR1"
,
(st8 *)0x34,
(st8*)"OOOOOOOOpp-kkkkk"
,
(st8*)"sim_trig"
,
(st8*)"SIM_TRIG"
,
(st8 *)0x35,
(st8 *)0x0,
(st8*)"AND_RBK"
,
(st8*)"AND_RBK"
,
(st8 *)0x36,
(st8 *)0x0,
(st8*)"OR_RBK"
,
(st8*)"OR_RBK"
,
(st8 *)0x37,
(st8 *)0x0,
(st8*)"XOR_RBK"
,
(st8*)"XOR_RBK"
,
(st8 *)0x38,
(st8*)"OOOOOOOO-/%aaaaap--------CCcccccKKKKKKKK"
,
(st8*)"`aaaaa,ACx` = `%,(``/,(``CCccccc,MRx` * `KKKKKKKK``/,)``%,)`"
,
(st8*)"MPYK`/``q_SAT``%` `KKKKKKKK`, `CCccccc,MRx`, `aaaaa,ACx`"
,
(st8 *)0x39,
(st8*)"OOOOOOOO-/%aaaaap--ccccc-DDdddddKKKKKKKK"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``%,(``ccccc,ACx` + `/,(``DDddddd,MRx` * `KKKKKKKK``/,)``%,)``q_SAT,)`"
,
(st8*)"MACK`/``q_SAT``%` `KKKKKKKK`, `DDddddd,MRx`, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x3A,
(st8*)"OOOOOOpp"
,
(st8*)"nop"
,
(st8*)"NOP"
,
(st8 *)0x3B,
(st8*)"OOOOOOOopAAaaaaapCCccccc"
,
(st8*)"`AAaaaaa,RAx` = `q_SAT,(``CCccccc,RAx``q_SAT,)`"
,
(st8*)"MOV`q_SAT` `CCccccc,RAx`, `AAaaaaa,RAx`"
,
(st8 *)0x3C,
(st8*)"OOOOOOOopAAaaaaapCCccccc"
,
(st8*)"`AAaaaaa,Rx` = `q_SAT,(``AAaaaaa,Rx` + `CCccccc,Rx``q_SAT,)`"
,
(st8*)"ADD`q_SAT` `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(st8 *)0x3D,
(st8*)"OOOOOOOopAAaaaaapCCccccc"
,
(st8*)"`AAaaaaa,Rx` = `q_SAT,(``AAaaaaa,Rx` - `CCccccc,Rx``q_SAT,)`"
,
(st8*)"SUB`q_SAT` `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(st8 *)0x3E,
(st8*)"OOOOOOOopAAaaaaapCCccccc"
,
(st8*)"`AAaaaaa,Rx` = `AAaaaaa,Rx` & `CCccccc,Rx`"
,
(st8*)"AND `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(st8 *)0x3F,
(st8*)"OOOOOOOopAAaaaaapCCccccc"
,
(st8*)"`AAaaaaa,Rx` = `AAaaaaa,Rx` | `CCccccc,Rx`"
,
(st8*)"OR `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(st8 *)0x40,
(st8*)"OOOOOOOopAAaaaaapCCccccc"
,
(st8*)"`AAaaaaa,Rx` = `AAaaaaa,Rx` ^ `CCccccc,Rx`"
,
(st8*)"XOR `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(st8 *)0x41,
(st8*)"OOOOOOOopAAaaaaapCCccccc"
,
(st8*)"`AAaaaaa,Rx` = max(`CCccccc,Rx`, `AAaaaaa,Rx`)"
,
(st8*)"MAX `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(st8 *)0x42,
(st8*)"OOOOOOOopAAaaaaapCCccccc"
,
(st8*)"`AAaaaaa,Rx` = min(`CCccccc,Rx`, `AAaaaaa,Rx`)"
,
(st8*)"MIN `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(st8 *)0x43,
(st8*)"OOOOOOOopAAaaaaapCCccccc"
,
(st8*)"`AAaaaaa,Rx` = `q_SAT,(`|`CCccccc,Rx`|`q_SAT,)`"
,
(st8*)"ABS`q_SAT` `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(st8 *)0x44,
(st8*)"OOOOOOOopAAaaaaapCCccccc"
,
(st8*)"`AAaaaaa,Rx` = `q_SAT,(`-`CCccccc,Rx``q_SAT,)`"
,
(st8*)"NEG`q_SAT` `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(st8 *)0x45,
(st8*)"OOOOOOOopAAaaaaapCCccccc"
,
(st8*)"`AAaaaaa,Rx` = ~`CCccccc,Rx`"
,
(st8*)"NOT `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(st8 *)0x46,
(st8*)"OOOOOOOp-CCccccc-DDddddd"
,
(st8*)"push(`CCccccc,RLHx`, `DDddddd,RLHx`)"
,
(st8*)"PSH `CCccccc,RLHx`, `DDddddd,RLHx`"
,
(st8 *)0x47,
(st8*)"OOOOOOOp-AAaaaaa-BBbbbbb"
,
(st8*)"`AAaaaaa,RLHx`, `BBbbbbb,RLHx` = pop()"
,
(st8*)"POP `AAaaaaa,RLHx`, `BBbbbbb,RLHx`"
,
(st8 *)0x48,
(st8*)"OOOOOOOOpAAaaaaap-o-kkkk"
,
(st8*)"`AAaaaaa,Rx` = `kkkk`"
,
(st8*)"MOV `kkkk`, `AAaaaaa,Rx`"
,
(st8 *)0x49,
(st8*)"OOOOOOOOpAAaaaaap-o-kkkk"
,
(st8*)"`AAaaaaa,Rx` = `kkkk,-`"
,
(st8*)"MOV `kkkk,-`, `AAaaaaa,Rx`"
,
(st8 *)0x4A,
(st8*)"OOOOOOOOpAAaaaaap-o-kkkk"
,
(st8*)"`AAaaaaa,Rx` = `q_SAT,(``AAaaaaa,Rx` + `kkkk``q_SAT,)`"
,
(st8*)"ADD`q_SAT` `kkkk`, `AAaaaaa,Rx`"
,
(st8 *)0x4B,
(st8*)"OOOOOOOOpAAaaaaap-o-kkkk"
,
(st8*)"`AAaaaaa,Rx` = `q_SAT,(``AAaaaaa,Rx` - `kkkk``q_SAT,)`"
,
(st8*)"SUB`q_SAT` `kkkk`, `AAaaaaa,Rx`"
,
(st8 *)0x4C,
(st8 *)0x0,
(st8*)"MV_AC_R"
,
(st8*)"MV_AC_R"
,
(st8 *)0x4D,
(st8*)"OOOOOOOOpAAaaaaap-o-----"
,
(st8*)"`AAaaaaa,Rx` = `q_SAT,(``AAaaaaa,Rx` >> #1`q_SAT,)`"
,
(st8*)"SFTS `AAaaaaa,Rx`, #-1"
,
(st8 *)0x4E,
(st8*)"OOOOOOOOpAAaaaaap-o-----"
,
(st8*)"`AAaaaaa,Rx` = `q_SAT,(``AAaaaaa,Rx` << #1`q_SAT,)`"
,
(st8*)"SFTS`q_SAT` `AAaaaaa,Rx`, #1"
,
(st8 *)0x4F,
(st8 *)0x0,
(st8*)"MV_SP_R"
,
(st8*)"MV_SP_R"
,
(st8 *)0x50,
(st8 *)0x0,
(st8*)"MV_SSP_R"
,
(st8*)"MV_SSP_R"
,
(st8 *)0x51,
(st8 *)0x0,
(st8*)"MV_CDP_R"
,
(st8*)"MV_CDP_R"
,
(st8 *)0x52,
(st8 *)0x0,
(st8*)"MV_BRC0_R"
,
(st8*)"MV_BRC0_R"
,
(st8 *)0x53,
(st8 *)0x0,
(st8*)"MV_BRC1_R"
,
(st8*)"MV_BRC1_R"
,
(st8 *)0x54,
(st8 *)0x0,
(st8*)"MV_RPTC_R"
,
(st8*)"MV_RPTC_R"
,
(st8 *)0x55,
(st8*)"OOOOOOOOppq-kkkk"
,
(st8*)"bit(ST0, #`kkkk,ST0`) = #0"
,
(st8*)"BCLR `kkkk,ST0`, ST0_55"
,
(st8 *)0x56,
(st8*)"OOOOOOOOppq-kkkk"
,
(st8*)"bit(ST0, #`kkkk,ST0`) = #1"
,
(st8*)"BSET `kkkk,ST0`, ST0_55"
,
(st8 *)0x57,
(st8*)"OOOOOOOOppq-kkkk"
,
(st8*)"bit(ST1, #`kkkk,ST1`) = #0"
,
(st8*)"BCLR `kkkk,ST1`, ST1_55"
,
(st8 *)0x58,
(st8*)"OOOOOOOOppq-kkkk"
,
(st8*)"bit(ST1, #`kkkk,ST1`) = #1"
,
(st8*)"BSET `kkkk,ST1`, ST1_55"
,
(st8 *)0x59,
(st8*)"OOOOOOOOppq-kkkk"
,
(st8*)"bit(ST2, #`kkkk,ST2`) = #0"
,
(st8*)"BCLR `kkkk,ST2`, ST2_55"
,
(st8 *)0x5A,
(st8*)"OOOOOOOOppq-kkkk"
,
(st8*)"bit(ST2, #`kkkk,ST2`) = #1"
,
(st8*)"BSET `kkkk,ST2`, ST2_55"
,
(st8 *)0x5B,
(st8*)"OOOOOOOOppq-kkkk"
,
(st8*)"bit(ST3, #`kkkk,ST3`) = #0"
,
(st8*)"BCLR `kkkk,ST3`, ST3_55"
,
(st8 *)0x5C,
(st8*)"OOOOOOOOppq-kkkk"
,
(st8*)"bit(ST3, #`kkkk,ST3`) = #1"
,
(st8*)"BSET `kkkk,ST3`, ST3_55"
,
(st8 *)0x5D,
(st8 *)0x0,
(st8*)"eallow()"
,
(st8*)"EALLOW__"
,
(st8 *)0x5E,
(st8 *)0x0,
(st8*)"edis()"
,
(st8*)"EDIS__"
,
(st8 *)0x5F,
(st8*)"OOOOOOOOppqq----"
,
(st8*)"aborti()"
,
(st8*)"ABORTI__"
,
(st8 *)0x60,
(st8*)"OOOOOOOOppqq----"
,
(st8*)"estop_1()"
,
(st8*)"ESTOP_INC"
,
(st8 *)0x61,
(st8*)"OOOOOOOOpp------"
,
(st8*)"repeat(CSR) "
,
(st8*)"RPT CSR"
,
(st8 *)0x62,
(st8*)"OOOOOOOOpp-ccccc"
,
(st8*)"repeat(CSR), CSR += `ccccc,DAx`"
,
(st8*)"RPTADD CSR, `ccccc,DAx`"
,
(st8 *)0x63,
(st8*)"OOOOOOOOpp--kkkk"
,
(st8*)"repeat(CSR), CSR += `kkkk`"
,
(st8*)"RPTADD CSR, `kkkk`"
,
(st8 *)0x64,
(st8*)"OOOOOOOOpp--kkkk"
,
(st8*)"repeat(CSR), CSR -= `kkkk`"
,
(st8*)"RPTSUB CSR, `kkkk`"
,
(st8 *)0x65,
(st8*)"OOOOOOpp"
,
(st8*)"return"
,
(st8*)"RET"
,
(st8 *)0x66,
(st8*)"OOOOOOOOppqq----"
,
(st8*)"return_int"
,
(st8*)"RETI"
,
(st8 *)0x67,
(st8 *)0x0,
(st8*)"SWT_P_RPT"
,
(st8*)"SWT_P_RPT"
,
(st8 *)0x68,
(st8 *)0x0,
(st8*)"BR_P_S"
,
(st8*)"BR_P_S"
,
(st8 *)0x69,
(st8*)"OOOOOOpp--------llllllll"
,
(st8*)"localrepeat { `llllllll,i`"
,
(st8*)"RPTBLOCAL `llllllll`"
,
(st8 *)0x6A,
(st8 *)0x0,
(st8*)"RPT_P_BK"
,
(st8*)"RPT_P_BK"
,
(st8 *)0x6B,
(st8*)"OOOOOOOOKKKKKKKK"
,
(st8*)"SP = SP + `KKKKKKKK`"
,
(st8*)"AADD `KKKKKKKK`, SP"
,
(st8 *)0x6C,
(st8*)"OOOOOOOOpAAaaaaap-o-----"
,
(st8*)"`AAaaaaa,Rx` = `AAaaaaa,Rx` <<< #1"
,
(st8*)"SFTL `AAaaaaa,Rx`, #1"
,
(st8 *)0x6D,
(st8*)"OOOOOOOOpAAaaaaap-o-----"
,
(st8*)"`AAaaaaa,Rx` = `AAaaaaa,Rx` >>> #1"
,
(st8*)"SFTL `AAaaaaa,Rx`, #-1"
,
(st8 *)0x6E,
(st8*)"OOOOOOOpAAAaaaaa"
,
(st8*)"`AAAaaaaa,ALLx` = `AAAaaaaa,d(ALLx`pop()`AAAaaaaa,)ALLx`"
,
(st8*)"POP `AAAaaaaa,d(ALLx``AAAaaaaa,ALLx``AAAaaaaa,)ALLx`"
,
(st8 *)0x6F,
(st8 *)0x0,
(st8*)"DPOPR_SPR_DB"
,
(st8*)"DPOPR_SPR_DB"
,
(st8 *)0x70,
(st8*)"OOOOOOOOp-Aaaaaa"
,
(st8*)"`Aaaaaa,XRx` = popboth()"
,
(st8*)"POPBOTH `Aaaaaa,XRx`"
,
(st8 *)0x71,
(st8*)"OOOOOOOOp-Cccccc"
,
(st8*)"pshboth(`Cccccc,XRx`)"
,
(st8*)"PSHBOTH `Cccccc,XRx`"
,
(st8 *)0x72,
(st8*)"OOOOOOOpCCCccccc"
,
(st8*)"`CCCccccc,d(ALLx`push(`CCCccccc,ALLx`)`CCCccccc,)ALLx`"
,
(st8*)"PSH `CCCccccc,d(ALLx``CCCccccc,ALLx``CCCccccc,)ALLx`"
,
(st8 *)0x73,
(st8 *)0x0,
(st8*)"DPSHR_SPW_DB"
,
(st8*)"DPSHR_SPW_DB"
,
(st8 *)0x74,
(st8 *)0x0,
(st8*)"MV_R_ACH"
,
(st8*)"MV_R_ACH"
,
(st8 *)0x75,
(st8 *)0x0,
(st8*)"MV_R_SP"
,
(st8*)"MV_R_SP"
,
(st8 *)0x76,
(st8 *)0x0,
(st8*)"MV_R_SSP"
,
(st8*)"MV_R_SSP"
,
(st8 *)0x77,
(st8 *)0x0,
(st8*)"MV_R_CDP"
,
(st8*)"MV_R_CDP"
,
(st8 *)0x78,
(st8 *)0x0,
(st8*)"MV_R_CSR"
,
(st8*)"MV_R_CSR"
,
(st8 *)0x79,
(st8 *)0x0,
(st8*)"MV_R_BRC1"
,
(st8*)"MV_R_BRC1"
,
(st8 *)0x7A,
(st8 *)0x0,
(st8*)"MV_R_BRC0"
,
(st8*)"MV_R_BRC0"
,
(st8 *)0x7B,
(st8*)"OOOOOOOOp/%aaaaapCCccccc"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``%,(``aaaaa,ACx` + `/,(`|`CCccccc,MAx`|`/,)``%,)``q_SAT,)`"
,
(st8*)"ADD`/``q_SAT``%`V `CCccccc,MAx`, `aaaaa,ACx`"
,
(st8 *)0x7C,
(st8 *)0x0,
(st8*)"SQURA_R_RR"
,
(st8*)"SQURA_R_RR"
,
(st8 *)0x7D,
(st8 *)0x0,
(st8*)"SQURS_R_RR"
,
(st8*)"SQURS_R_RR"
,
(st8 *)0x7E,
(st8 *)0x0,
(st8*)"MPY_R_RR_AC"
,
(st8*)"MPY_R_RR_AC"
,
(st8 *)0x7F,
(st8 *)0x0,
(st8*)"SQUR_R_RR"
,
(st8*)"SQUR_R_RR"
,
(st8 *)0x80,
(st8*)"OOOOOOOOp-%aaaaap--ccccc"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(`rnd(`ccccc,ACx`)`q_SAT,)`"
,
(st8*)"ROUND`q_SAT` `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x81,
(st8*)"OOOOOOOOp-%aaaaap--ccccc"
,
(st8*)"`aaaaa,ACx` = saturate(`%,(``ccccc,ACx``%,)`)"
,
(st8*)"SAT`%` `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x82,
(st8*)"OOOOOOO$p/%aaaaapCCccccc#DDddddd"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``%,(``aaaaa,ACx` + `/,(``$,(``CCccccc,MRx``$,)` * `#,(``DDddddd,MAx``#,)``/,)``%,)``q_SAT,)`"
,
(st8*)"MAC`/``q_SAT``%` `$,(``CCccccc,MRx``$,)`, `#,(``DDddddd,MAx``#,)`, `aaaaa,ACx`"
,
(st8 *)0x83,
(st8*)"OOOOOOO$p/%aaaaapCCccccc#DDddddd"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``%,(``aaaaa,ACx` - `/,(``$,(``CCccccc,MRx``$,)` * `#,(``DDddddd,MAx``#,)``/,)``%,)``q_SAT,)`"
,
(st8*)"MAS`/``q_SAT``%` `#,(``DDddddd,MAx``#,)`, `$,(``CCccccc,MRx``$,)`, `aaaaa,ACx`"
,
(st8 *)0x84,
(st8*)"OOOOOOO$p/%aaaaapCCccccc#DDddddd"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``%,(``/,(``$,(``CCccccc,MRx``$,)` * `#,(``DDddddd,MAx``#,)``/,)``%,)``q_SAT,)`"
,
(st8*)"MPY`/``q_SAT``%` `#,(``DDddddd,MAx``#,)`, `$,(``CCccccc,MRx``$,)`, `aaaaa,ACx`"
,
(st8 *)0x85,
(st8*)"OOOOOOO-p/%aaaaapDDddddd---ccccc"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``%,(``ccccc,ACx` + `/,(``DDddddd,MRx` * `aaaaa,ACx``/,)``%,)``q_SAT,)`"
,
(st8*)"MAC`/``q_SAT``%` `aaaaa,ACx`, `DDddddd,MRx`, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x86,
(st8*)"OOOOOOOOpAAaaaaapCCcccccoNNnnnnn"
,
(st8*)"`AAaaaaa,WACx` = `q_SAT,(``AAaaaaa,WACx` + (`CCccccc,WACx` << `NNnnnnn,SRx`)`q_SAT,)`"
,
(st8*)"ADD`q_SAT` `CCccccc,WACx` << `NNnnnnn,SRx`, `AAaaaaa,WACx`"
,
(st8 *)0x87,
(st8*)"OOOOOOOOpAAaaaaapCCcccccoNNnnnnn"
,
(st8*)"`AAaaaaa,WACx` = `q_SAT,(``AAaaaaa,WACx` - (`CCccccc,WACx` << `NNnnnnn,SRx`)`q_SAT,)`"
,
(st8*)"SUB`q_SAT` `CCccccc,WACx` << `NNnnnnn,SRx`, `AAaaaaa,WACx`"
,
(st8 *)0x88,
(st8*)"OOOOOOOOp00aaaaap-Taaaaa--------"
,
(st8*)"`aaaaa,ACx` = sftc(`aaaaa,ACx`, `T`)"
,
(st8*)"SFTCC `aaaaa,ACx`, `T`"
,
(st8 *)0x89,
(st8*)"OOOOOOOOpAAaaaaapCCcccccoNNnnnnn"
,
(st8*)"`AAaaaaa,WACx` = `CCccccc,WACx` <<< `NNnnnnn,SRx`"
,
(st8*)"SFTL `CCccccc,WACx`, `NNnnnnn,SRx`, `AAaaaaa,WACx`"
,
(st8 *)0x8A,
(st8*)"OOOOOOOOpAAaaaaapCCcccccoNNnnnnn"
,
(st8*)"`AAaaaaa,WACx` = `q_SAT,(``CCccccc,WACx` << `NNnnnnn,SRx``q_SAT,)`"
,
(st8*)"SFTS`q_SAT` `CCccccc,WACx`, `NNnnnnn,SRx`, `AAaaaaa,WACx`"
,
(st8 *)0x8B,
(st8*)"OOOOOOOOpAAaaaaapCCcccccoNNnnnnn"
,
(st8*)"`AAaaaaa,WACx` = `q_SAT,(``CCccccc,WACx` <<C `NNnnnnn,SRx``q_SAT,)`"
,
(st8*)"SFTSC`q_SAT` `CCccccc,WACx`, `NNnnnnn,SRx`, `AAaaaaa,WACx`"
,
(st8 *)0x8C,
(st8*)"OOOOOOOOpp-kkkkk"
,
(st8*)"swap(`kkkkk,!`)"
,
(st8*)"SWAP `kkkkk,!`"
,
(st8 *)0x8D,
(st8 *)0x0,
(st8*)"COPR_16"
,
(st8*)"COPR_16"
,
(st8 *)0x8E,
(st8*)"OOOOOOOOppqq----"
,
(st8*)"nop_16"
,
(st8*)"NOP_16"
,
(st8 *)0x8F,
(st8 *)0x0,
(st8*)"BRC_P_SD"
,
(st8*)"BRC_P_SD"
,
(st8 *)0x90,
(st8*)"OOOOOOOpllllllllllllllllllllllllHHHhhhhh"
,
(st8*)"if (`HHHhhhhh`) goto `llllllllllllllllllllllll`"
,
(st8*)"BCC `llllllllllllllllllllllll`, `HHHhhhhh`"
,
(st8 *)0x91,
(st8*)"OOOOOOOpllllllllllllllllllllllllHHHhhhhh"
,
(st8*)"if (`HHHhhhhh`) call `llllllllllllllllllllllll`"
,
(st8*)"CALLCC `llllllllllllllllllllllll`, `HHHhhhhh`"
,
(st8 *)0x92,
(st8*)"OOOOOOFpllllllllllllllllllllllll"
,
(st8*)"`q_SAT,n`goto `llllllllllllllllllllllll``F`"
,
(st8*)"`q_SAT,N`B `llllllllllllllllllllllll``F`"
,
(st8 *)0x93,
(st8*)"OOOOOOFpllllllllllllllllllllllll"
,
(st8*)"call `llllllllllllllllllllllll``F`"
,
(st8*)"CALL `llllllllllllllllllllllll``F`"
,
(st8 *)0x94,
(st8*)"OOOOOOOpLLLLLLLLLLLLLLLLHHHhhhhh"
,
(st8*)"if (`HHHhhhhh`) goto `LLLLLLLLLLLLLLLL`"
,
(st8*)"BCC `LLLLLLLLLLLLLLLL`, `HHHhhhhh`"
,
(st8 *)0x95,
(st8*)"OOOOOOOpLLLLLLLLLLLLLLLLHHHhhhhh"
,
(st8*)"if (`HHHhhhhh`) call `LLLLLLLLLLLLLLLL`"
,
(st8*)"CALLCC `LLLLLLLLLLLLLLLL`, `HHHhhhhh`"
,
(st8 *)0x96,
(st8*)"OOOOOOK$JCCcccccJKKKKKKKLLLLLLLLLLLLLLLL"
,
(st8*)"compare (`$,(``CCccccc,RAx` `JJ` `KKKKKKKK``$,)`) goto `LLLLLLLLLLLLLLLL`"
,
(st8*)"BCC`$` `LLLLLLLLLLLLLLLL`, `CCccccc,RAx` `JJ` `KKKKKKKK`"
,
(st8 *)0x97,
(st8*)"OOOOOOOopssaaaaapsscccccKKKKKKKKKKKKKKKK"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` + (`KKKKKKKKKKKKKKKK` << `ssss`)`q_SAT,)`"
,
(st8*)"ADD`q_SAT` `KKKKKKKKKKKKKKKK` << `ssss`, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x98,
(st8*)"OOOOOOOopssaaaaapsscccccKKKKKKKKKKKKKKKK"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` - (`KKKKKKKKKKKKKKKK` << `ssss`)`q_SAT,)`"
,
(st8*)"SUB`q_SAT` `KKKKKKKKKKKKKKKK` << `ssss`, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x99,
(st8*)"OOOOOOOopssaaaaapssccccckkkkkkkkkkkkkkkk"
,
(st8*)"`aaaaa,ACx` = `ccccc,ACx` & (`kkkkkkkkkkkkkkkk` <<< `ssss`)"
,
(st8*)"AND `kkkkkkkkkkkkkkkk` << `ssss`, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x9A,
(st8*)"OOOOOOOopssaaaaapssccccckkkkkkkkkkkkkkkk"
,
(st8*)"`aaaaa,ACx` = `ccccc,ACx` | (`kkkkkkkkkkkkkkkk` <<< `ssss`)"
,
(st8*)"OR `kkkkkkkkkkkkkkkk` << `ssss`, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x9B,
(st8*)"OOOOOOOopssaaaaapssccccckkkkkkkkkkkkkkkk"
,
(st8*)"`aaaaa,ACx` = `ccccc,ACx` ^ (`kkkkkkkkkkkkkkkk` <<< `ssss`)"
,
(st8*)"XOR `kkkkkkkkkkkkkkkk` << `ssss`, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x9C,
(st8*)"OOOOOOOopssaaaaapss-----KKKKKKKKKKKKKKKK"
,
(st8*)"`aaaaa,ACx` = `KKKKKKKKKKKKKKKK` << `ssss`"
,
(st8*)"MOV `KKKKKKKKKKKKKKKK` << `ssss`, `aaaaa,ACx`"
,
(st8 *)0x9D,
(st8*)"OOOOOOOO-AAaaaaap11ccccckkkkkkkkkkkkkkkk"
,
(st8*)"`AAaaaaa,Rx` = field_extract(`ccccc,ACx`.L, `kkkkkkkkkkkkkkkk`)"
,
(st8*)"BFXTR `kkkkkkkkkkkkkkkk`, `ccccc,ACx`, `AAaaaaa,Rx`"
,
(st8 *)0x9E,
(st8*)"OOOOOOOO-AAaaaaap11ccccckkkkkkkkkkkkkkkk"
,
(st8*)"`AAaaaaa,Rx` = field_expand(`ccccc,ACx`.L, `kkkkkkkkkkkkkkkk`)"
,
(st8*)"BFXPA `kkkkkkkkkkkkkkkk`, `ccccc,ACx`, `AAaaaaa,Rx`"
,
(st8 *)0x9F,
(st8*)"OOOOOOOO-AAaaaaaKKKKKKKKKKKKKKKK"
,
(st8*)"`AAaaaaa,Rx` = `q_SAT,(``KKKKKKKKKKKKKKKK``q_SAT,)`"
,
(st8*)"MOV`q_SAT` `KKKKKKKKKKKKKKKK`, `AAaaaaa,Rx`"
,
(st8 *)0xA0,
(st8*)"OOOOOOOOpp-aaaaakkkkkkkkkkkkkkkk"
,
(st8*)"mar(`aaaaa,DAx` = `kkkkkkkkkkkkkkkk`)"
,
(st8*)"AMOV `kkkkkkkkkkkkkkkk`, `aaaaa,DAx`"
,
(st8 *)0xA1,
(st8 *)0x0,
(st8*)"LD_RPK_DP"
,
(st8*)"LD_RPK_DP"
,
(st8 *)0xA2,
(st8 *)0x0,
(st8*)"LD_RPK_SSP"
,
(st8*)"LD_RPK_SSP"
,
(st8 *)0xA3,
(st8 *)0x0,
(st8*)"LD_RPK_CDP"
,
(st8*)"LD_RPK_CDP"
,
(st8 *)0xA4,
(st8 *)0x0,
(st8*)"LD_RPK_BF01"
,
(st8*)"LD_RPK_BF01"
,
(st8 *)0xA5,
(st8 *)0x0,
(st8*)"LD_RPK_BF23"
,
(st8*)"LD_RPK_BF23"
,
(st8 *)0xA6,
(st8 *)0x0,
(st8*)"LD_RPK_BF45"
,
(st8*)"LD_RPK_BF45"
,
(st8 *)0xA7,
(st8 *)0x0,
(st8*)"LD_RPK_BF67"
,
(st8*)"LD_RPK_BF67"
,
(st8 *)0xA8,
(st8 *)0x0,
(st8*)"LD_RPK_BFC"
,
(st8*)"LD_RPK_BFC"
,
(st8 *)0xA9,
(st8 *)0x0,
(st8*)"LD_RPK_SP"
,
(st8*)"LD_RPK_SP"
,
(st8 *)0xAA,
(st8*)"OOOOOOOO-/%aaaaap--------CCcccccKKKKKKKKKKKKKKKK"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``%,(``/,(``CCccccc,MRx` * `KKKKKKKKKKKKKKKK``/,)``%,)``q_SAT,)`"
,
(st8*)"MPYK`/``q_SAT``%` `KKKKKKKKKKKKKKKK`, `CCccccc,MRx`, `aaaaa,ACx`"
,
(st8 *)0xAB,
(st8*)"OOOOOOOO-/%aaaaap--ccccc-DDdddddKKKKKKKKKKKKKKKK"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``%,(``ccccc,ACx` + `/,(``DDddddd,MRx` * `KKKKKKKKKKKKKKKK``/,)``%,)``q_SAT,)`"
,
(st8*)"MACK`/``q_SAT``%` `KKKKKKKKKKKKKKKK`, `DDddddd,MRx`, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0xAC,
(st8*)"OOOOOOOop--aaaaap--cccccKKKKKKKKKKKKKKKK"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` + (`KKKKKKKKKKKKKKKK` << #16)`q_SAT,)`"
,
(st8*)"ADD`q_SAT` `KKKKKKKKKKKKKKKK` << #16, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0xAD,
(st8*)"OOOOOOOop--aaaaap--cccccKKKKKKKKKKKKKKKK"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` - (`KKKKKKKKKKKKKKKK` << #16)`q_SAT,)`"
,
(st8*)"SUB`q_SAT` `KKKKKKKKKKKKKKKK` << #16, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0xAE,
(st8*)"OOOOOOOop--aaaaap--ccccckkkkkkkkkkkkkkkk"
,
(st8*)"`aaaaa,ACx` = `ccccc,ACx` & (`kkkkkkkkkkkkkkkk` <<< #16)"
,
(st8*)"AND `kkkkkkkkkkkkkkkk` << #16, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0xAF,
(st8*)"OOOOOOOop--aaaaap--ccccckkkkkkkkkkkkkkkk"
,
(st8*)"`aaaaa,ACx` = `ccccc,ACx` | (`kkkkkkkkkkkkkkkk` <<< #16)"
,
(st8*)"OR `kkkkkkkkkkkkkkkk` << #16, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0xB0,
(st8*)"OOOOOOOop--aaaaap--ccccckkkkkkkkkkkkkkkk"
,
(st8*)"`aaaaa,ACx` = `ccccc,ACx` ^ (`kkkkkkkkkkkkkkkk` <<< #16)"
,
(st8*)"XOR `kkkkkkkkkkkkkkkk` << #16, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0xB1,
(st8*)"OOOOOOOop--aaaaap-------KKKKKKKKKKKKKKKK"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``KKKKKKKKKKKKKKKK` << #16`q_SAT,)`"
,
(st8*)"MOV`q_SAT` `KKKKKKKKKKKKKKKK` << #16, `aaaaa,ACx`"
,
(st8 *)0xB2,
(st8*)"OOOOOOOOppqq----"
,
(st8*)"idle"
,
(st8*)"IDLE"
,
(st8 *)0xB3,
(st8*)"OOOOOOOopAAaaaaapCCcccccKKKKKKKKKKKKKKKK"
,
(st8*)"`AAaaaaa,Rx` = `q_SAT,(``CCccccc,Rx` + `KKKKKKKKKKKKKKKK``q_SAT,)`"
,
(st8*)"ADD`q_SAT` `KKKKKKKKKKKKKKKK`, `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(st8 *)0xB4,
(st8*)"OOOOOOOopAAaaaaapCCcccccKKKKKKKKKKKKKKKK"
,
(st8*)"`AAaaaaa,Rx` = `q_SAT,(``CCccccc,Rx` - `KKKKKKKKKKKKKKKK``q_SAT,)`"
,
(st8*)"SUB`q_SAT` `KKKKKKKKKKKKKKKK`, `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(st8 *)0xB5,
(st8*)"OOOOOOOopAAaaaaapCCccccckkkkkkkkkkkkkkkk"
,
(st8*)"`AAaaaaa,Rx` = `CCccccc,Rx` & `kkkkkkkkkkkkkkkk`"
,
(st8*)"AND `kkkkkkkkkkkkkkkk`, `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(st8 *)0xB6,
(st8*)"OOOOOOOopAAaaaaapCCccccckkkkkkkkkkkkkkkk"
,
(st8*)"`AAaaaaa,Rx` = `CCccccc,Rx` | `kkkkkkkkkkkkkkkk`"
,
(st8*)"OR `kkkkkkkkkkkkkkkk`, `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(st8 *)0xB7,
(st8*)"OOOOOOOopAAaaaaapCCccccckkkkkkkkkkkkkkkk"
,
(st8*)"`AAaaaaa,Rx` = `CCccccc,Rx` ^ `kkkkkkkkkkkkkkkk`"
,
(st8*)"XOR `kkkkkkkkkkkkkkkk`, `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(st8 *)0xB8,
(st8 *)0x0,
(st8*)"LMVM_MM_L"
,
(st8*)"LMVM_MM_L"
,
(st8 *)0xB9,
(st8 *)0x0,
(st8*)"MVM_MM_YX"
,
(st8*)"MVM_MM_YX"
,
(st8 *)0xBA,
(st8*)"OOOOOOOO-XXXxxxxp--ccccc-YYYyyyy"
,
(st8*)"`XXXxxxx,w` = LO(`ccccc,ACx`), `YYYyyyy,w` = HI(`ccccc,ACx`)"
,
(st8*)"MOV `ccccc,ACx`, `XXXxxxx,w`, `YYYyyyy,w`"
,
(st8 *)0xBB,
(st8*)"OOOOOOOOpXXXxxxxp00aaaaa-YYYyyyy"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(`(`XXXxxxx,r` << #16) + (`YYYyyyy,r` << #16)`q_SAT,)`"
,
(st8*)"ADD`q_SAT` `XXXxxxx,r` << #16, `YYYyyyy,r` << #16, `aaaaa,ACx`"
,
(st8 *)0xBC,
(st8*)"OOOOOOOOpXXXxxxxp00aaaaa-YYYyyyy"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(`(`XXXxxxx,r` << #16) - (`YYYyyyy,r` << #16)`q_SAT,)`"
,
(st8*)"SUB`q_SAT` `XXXxxxx,r` << #16, `YYYyyyy,r` << #16, `aaaaa,ACx`"
,
(st8 *)0xBD,
(st8*)"OOOOOOOO-XXXxxxxp--aaaaa-YYYyyyy"
,
(st8*)"LO(`aaaaa,ACx`) = `q_SAT,(``XXXxxxx,r``q_SAT,)`, HI(`aaaaa,ACx`) = `q_SAT,(``YYYyyyy,r``q_SAT,)`"
,
(st8*)"MOV`q_SAT` `XXXxxxx,r`, `YYYyyyy,r`, `aaaaa,ACx`"
,
(st8 *)0xBE,
(st8*)"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"MPY`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` :: MPY`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx`"
,
(st8 *)0xBF,
(st8*)"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"MAC`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` :: MPY`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx`"
,
(st8 *)0xC0,
(st8*)"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"MAS`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` :: MPY`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx`"
,
(st8 *)0xC1,
(st8*)"OOOOOOO-pXXXxxxxp4$-----%YYYyyyyqq#aaaaa/ZZZzzzz"
,
(st8*)"mar(`XXXxxxx,r`), `aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``YYYyyyy,r``$,)` * `#,(``ZZZzzzz,r``#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"AMAR `XXXxxxx,r` :: MPY`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``ZZZzzzz,r``#,)`, `aaaaa,ACx`"
,
(st8 *)0xC2,
(st8*)"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` + `/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"MAC`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx`"
,
(st8 *)0xC3,
(st8*)"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` + `/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"MAS`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx`"
,
(st8 *)0xC4,
(st8*)"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(`(`aaaaa,ACx` >> #16) + `/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` + `/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"MAC`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` >> #16 :: MAC`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx`"
,
(st8 *)0xC5,
(st8*)"OOOOOOO-pXXXxxxxp4$-----%YYYyyyyqq#aaaaa/ZZZzzzz"
,
(st8*)"mar(`XXXxxxx,r`), `aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/,(``$,(``YYYyyyy,r``$,)` * `#,(``ZZZzzzz,r``#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"AMAR `XXXxxxx,r` :: MAC`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``ZZZzzzz,r``#,)`, `aaaaa,ACx`"
,
(st8 *)0xC6,
(st8*)"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(`(`bbbbb,ACx` >> #16) + `/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"MAS`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx` >> #16"
,
(st8 *)0xC7,
(st8*)"OOOOOOO-pXXXxxxxp4$-----%YYYyyyyqq#aaaaa/ZZZzzzz"
,
(st8*)"mar(`XXXxxxx,r`), `aaaaa,ACx` = `q_SAT,(``4,(``%,(`(`aaaaa,ACx` >> #16) + `/,(``$,(``YYYyyyy,r``$,)` * `#,(``ZZZzzzz,r``#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"AMAR `XXXxxxx,r` :: MAC`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``ZZZzzzz,r``#,)`, `aaaaa,ACx` >> #16"
,
(st8 *)0xC8,
(st8*)"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(`(`bbbbb,ACx` >> #16) + `/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"MPY`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx` >> #16"
,
(st8 *)0xC9,
(st8*)"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(`(`aaaaa,ACx` >> #16) + `/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(`(`bbbbb,ACx` >> #16) + `/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"MAC`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` >> #16 :: MAC`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx` >> #16"
,
(st8 *)0xCA,
(st8*)"OOOOOOO-pXXXxxxxp4$-----%YYYyyyyqq#aaaaa/ZZZzzzz"
,
(st8*)"mar(`XXXxxxx,r`), `aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/,(``$,(``YYYyyyy,r``$,)` * `#,(``ZZZzzzz,r``#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"AMAR `XXXxxxx,r` :: MAS`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``ZZZzzzz,r``#,)`, `aaaaa,ACx`"
,
(st8 *)0xCB,
(st8*)"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` - `/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"MAS`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` :: MAS`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx`"
,
(st8 *)0xCC,
(st8*)"OOOOOOO-pXXXxxxxp--------YYYyyyyqq-------ZZZzzzz"
,
(st8*)"mar(`XXXxxxx,r`), mar(`YYYyyyy,r`), mar(`ZZZzzzz,r`)"
,
(st8*)"AMAR `XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`"
,
(st8 *)0xCD,
(st8*)"OOOOOOO-pXXXxxxxp0-aaaaa0YYYyyyyqq-bbbbb/ZZZzzzz"
,
(st8*)"firs`/,a``q_SAT,a`(`XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`, `aaaaa,ACx`, `bbbbb,ACx`)"
,
(st8*)"FIRSADD`/``q_SAT` `XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`, `aaaaa,ACx`, `bbbbb,ACx`"
,
(st8 *)0xCE,
(st8*)"OOOOOOO-pXXXxxxxp0-aaaaa0YYYyyyyqq-bbbbb/ZZZzzzz"
,
(st8*)"firsn`/,a``q_SAT,a`(`XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`, `aaaaa,ACx`, `bbbbb,ACx`)"
,
(st8*)"FIRSSUB`/``q_SAT` `XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`, `aaaaa,ACx`, `bbbbb,ACx`"
,
(st8 *)0xCF,
(st8*)"OOOOOOO3pXXXxxxxp4$aaaaa%YYYyyyy/-#-----"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``XXXxxxx,r``$,)` * `#,(``YYYyyyy,r``#,)``/,)``%,)``4,)``q_SAT,)``XXXxxxx3,3r`"
,
(st8*)"MPYM`/``q_SAT``%``4` `3``$,(``XXXxxxx,r``$,)`, `#,(``YYYyyyy,r``#,)`, `aaaaa,ACx`"
,
(st8 *)0xD0,
(st8*)"OOOOOOO3pXXXxxxxp4$aaaaa%YYYyyyy/-#ccccc"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``ccccc,ACx` + `/,(``$,(``XXXxxxx,r``$,)` * `#,(``YYYyyyy,r``#,)``/,)``%,)``4,)``q_SAT,)``XXXxxxx3,3r`"
,
(st8*)"MACM`/``q_SAT``%``4` `3``$,(``XXXxxxx,r``$,)`, `#,(``YYYyyyy,r``#,)`, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0xD1,
(st8*)"OOOOOOO3pXXXxxxxp4$aaaaa%YYYyyyy/-#ccccc"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(`(`ccccc,ACx` >> #16) + `/,(``$,(``XXXxxxx,r``$,)` * `#,(``YYYyyyy,r``#,)``/,)``%,)``4,)``q_SAT,)``XXXxxxx3,3r`"
,
(st8*)"MACM`/``q_SAT``%``4` `3``$,(``XXXxxxx,r``$,)`, `#,(``YYYyyyy,r``#,)`, `ccccc,ACx` >> #16, `aaaaa,ACx`"
,
(st8 *)0xD2,
(st8*)"OOOOOOO3pXXXxxxxp4$aaaaa%YYYyyyy/-#ccccc"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``ccccc,ACx` - `/,(``$,(``XXXxxxx,r``$,)` * `#,(``YYYyyyy,r``#,)``/,)``%,)``4,)``q_SAT,)``XXXxxxx3,3r`"
,
(st8*)"MASM`/``q_SAT``%``4` `3``$,(``XXXxxxx,r``$,)`, `#,(``YYYyyyy,r``#,)`, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0xD3,
(st8*)"OOOOOOO3pXXXxxxxp-oaaaaa%YYYyyyy/ccbbbbb"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``%,(``aaaaa,ACx` - `/`(`cc,Tx` * `XXXxxxx,r`)`%,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``YYYyyyy,r` << #16`q_SAT,)``XXXxxxx3,3r`"
,
(st8*)"MASM`/``q_SAT``%` `XXXxxxx3,3r`, `cc,Tx`, `aaaaa,ACx` :: MOV`q_SAT` `YYYyyyy,r` << #16, `bbbbb,ACx`"
,
(st8 *)0xD4,
(st8*)"OOOOOOO3pXXXxxxxp-oaaaaa%YYYyyyy/ccbbbbb"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``%,(``aaaaa,ACx` + `/`(`cc,Tx` * `XXXxxxx,r`)`%,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``YYYyyyy,r` << #16`q_SAT,)``XXXxxxx3,3r`"
,
(st8*)"MACM`/``q_SAT``%` `XXXxxxx3,3r`, `cc,Tx`, `aaaaa,ACx` :: MOV`q_SAT` `YYYyyyy,r` << #16, `bbbbb,ACx`"
,
(st8 *)0xD5,
(st8*)"OOOOOOOOpXXXxxxxp--aaaaa1YYYyyyy/--bbbbb"
,
(st8*)"lms`/,a``q_SAT,a`(`XXXxxxx,r`, `YYYyyyy,r`, `aaaaa,ACx`, `bbbbb,ACx`)"
,
(st8*)"LMS`/``q_SAT` `XXXxxxx,r`, `YYYyyyy,r`, `aaaaa,ACx`, `bbbbb,ACx`"
,
(st8 *)0xD6,
(st8*)"OOOOOOOOpXXXxxxxp--aaaaa0YYYyyyy/--bbbbb"
,
(st8*)"sqdst`/,a``q_SAT,a`(`XXXxxxx,r`, `YYYyyyy,r`, `aaaaa,ACx`, `bbbbb,ACx`)"
,
(st8*)"SQDST`/``q_SAT` `XXXxxxx,r`, `YYYyyyy,r`, `aaaaa,ACx`, `bbbbb,ACx`"
,
(st8 *)0xD7,
(st8*)"OOOOOOOOpXXXxxxxp--aaaaa0YYYyyyy/--bbbbb"
,
(st8*)"abdst`/,a``q_SAT,a`(`XXXxxxx,r`, `YYYyyyy,r`, `aaaaa,ACx`, `bbbbb,ACx`)"
,
(st8*)"ABDST`/``q_SAT` `XXXxxxx,r`, `YYYyyyy,r`, `aaaaa,ACx`, `bbbbb,ACx`"
,
(st8 *)0xD8,
(st8*)"OOOOOOO3pXXXxxxxp-oaaaaa%YYYyyyy/ccddddd"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``%,(``/,(``cc,Tx` * `XXXxxxx,r``/,)``%,)``q_SAT,)`, `YYYyyyy,w` = `q_SAT,(`HI(`ccccc,ACx` << T2)`q_SAT,)``XXXxxxx3,3r`"
,
(st8*)"MPYM`/``q_SAT``%` `XXXxxxx3,3r`, `cc,Tx`, `aaaaa,ACx` :: MOV`q_SAT` HI(`ccccc,ACx` << T2), `YYYyyyy,w`"
,
(st8 *)0xD9,
(st8*)"OOOOOOO3pXXXxxxxp-oaaaaa%YYYyyyy/ccddddd"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``%,(``aaaaa,ACx` + `/`(`cc,Tx` * `XXXxxxx,r`)`%,)``q_SAT,)`, `YYYyyyy,w` = `q_SAT,(`HI(`ccccc,ACx` << T2)`q_SAT,)``XXXxxxx3,3r`"
,
(st8*)"MACM`/``q_SAT``%` `XXXxxxx3,3r`, `cc,Tx`, `aaaaa,ACx` :: MOV`q_SAT` HI(`ccccc,ACx` << T2), `YYYyyyy,w`"
,
(st8 *)0xDA,
(st8*)"OOOOOOO3pXXXxxxxp-oaaaaa%YYYyyyy/ccddddd"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``%,(``aaaaa,ACx` - `/`(`cc,Tx` * `XXXxxxx,r`)`%,)``q_SAT,)`, `YYYyyyy,w` = `q_SAT,(`HI(`ccccc,ACx` << T2)`q_SAT,)``XXXxxxx3,3r`"
,
(st8*)"MASM`/``q_SAT``%` `XXXxxxx3,3r`, `cc,Tx`, `aaaaa,ACx` :: MOV`q_SAT` HI(`ccccc,ACx` << T2), `YYYyyyy,w`"
,
(st8 *)0xDB,
(st8*)"OOOOOOOOpXXXxxxxp--aaaaa-YYYyyyy---ccccc"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` + (`XXXxxxx,r` << #16)`q_SAT,)`, `YYYyyyy,w` = `q_SAT,(`HI(`aaaaa,ACx` << T2)`q_SAT,)`"
,
(st8*)"ADD`q_SAT` `XXXxxxx,r` << #16, `ccccc,ACx`, `aaaaa,ACx` :: MOV`q_SAT` HI(`aaaaa,ACx` << T2), `YYYyyyy,w`"
,
(st8 *)0xDC,
(st8*)"OOOOOOOOpXXXxxxxp--aaaaa-YYYyyyy---ccccc"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(`(`XXXxxxx,r` << #16) - `ccccc,ACx``q_SAT,)`, `YYYyyyy,w` = `q_SAT,(`HI(`aaaaa,ACx` << T2)`q_SAT,)`"
,
(st8*)"SUB`q_SAT` `ccccc,ACx`, `XXXxxxx,r` << #16, `aaaaa,ACx` :: MOV`q_SAT` HI(`aaaaa,ACx` << T2), `YYYyyyy,w`"
,
(st8 *)0xDD,
(st8*)"OOOOOOOOpXXXxxxxp--aaaaa-YYYyyyy---ccccc"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``XXXxxxx,r` << #16`q_SAT,)`, `YYYyyyy,w` = `q_SAT,(`HI(`ccccc,ACx` << T2)`q_SAT,)`"
,
(st8*)"MOV`q_SAT` `XXXxxxx,r` << #16, `aaaaa,ACx` :: MOV`q_SAT` HI(`ccccc,ACx` << T2), `YYYyyyy,w`"
,
(st8 *)0xDE,
(st8 *)0x0,
(st8*)"SDUAL__"
,
(st8*)"SDUAL__"
,
(st8 *)0xDF,
(st8*)"OOOOOOOOpGFccccc"
,
(st8*)"`q_SAT,n`goto `ccccc,ACx``G``F`"
,
(st8*)"`q_SAT,N`B `ccccc,ACx``G``F`"
,
(st8 *)0xE0,
(st8*)"OOOOOOOOpGFccccc"
,
(st8*)"call `ccccc,ACx``G``F`"
,
(st8*)"CALL `ccccc,ACx``G``F`"
,
(st8 *)0xE1,
(st8 *)0x0,
(st8*)"SWT_P_DA"
,
(st8*)"SWT_P_DA"
,
(st8 *)0xE2,
(st8*)"OOOOOOOOppqq----"
,
(st8*)"reset"
,
(st8*)"RESET"
,
(st8 *)0xE3,
(st8*)"OOOOOOOOpp-kkkkk"
,
(st8*)"intr(`kkkkk`)"
,
(st8*)"INTR `kkkkk`"
,
(st8 *)0xE4,
(st8*)"OOOOOOOOpp-kkkkk"
,
(st8*)"trap(`kkkkk`)"
,
(st8*)"TRAP `kkkkk`"
,
(st8 *)0xE5,
(st8 *)0x0,
(st8*)"XCN_PMC_S"
,
(st8*)"XCN_PMC_S"
,
(st8 *)0xE6,
(st8 *)0x0,
(st8*)"XCN_PMU_S"
,
(st8*)"XCN_PMU_S"
,
(st8 *)0xE7,
(st8*)"OOOOOOpp"
,
(st8*)"estop_0"
,
(st8*)"ESTOP_BYTE"
,
(st8 *)0xE8,
(st8*)"OOOOOOpp"
,
(st8*)"MMAP"
,
(st8*)"MMAP"
,
(st8 *)0xE9,
(st8*)"OOOOOOpp"
,
(st8*)"PORT_READ"
,
(st8*)"PORT_READ"
,
(st8 *)0xEA,
(st8*)"OOOOOOpp"
,
(st8*)"PORT_WRITE"
,
(st8*)"PORT_WRITE"
,
(st8 *)0xEB,
(st8 *)0x0,
(st8*)"copr(`kkkkkkkk`, `aa,ACx`, `bb,ACx`)"
,
(st8*)"COPR__"
,
(st8 *)0xEC,
(st8*)"OOOOOOpp"
,
(st8*)"LINR"
,
(st8*)"LINR"
,
(st8 *)0xED,
(st8*)"OOOOOOpp"
,
(st8*)"CIRC"
,
(st8*)"CIRC"
,
(st8 *)0xEE,
(st8*)"OOOOOOppHHHhhhhh"
,
(st8*)"if (`HHHhhhhh`) execute (AD_Unit)"
,
(st8*)"XCC `HHHhhhhh`"
,
(st8 *)0xEF,
(st8*)"OOOOOOppHHHhhhhh"
,
(st8*)"if (`HHHhhhhh`) execute (D_Unit)"
,
(st8*)"XCCPART `HHHhhhhh`"
,
(st8 *)0xF0,
(st8*)"OOOOOOppHHHhhhhh"
,
(st8*)"if (`HHHhhhhh`) execute (AD_Unit)"
,
(st8*)"XCC `HHHhhhhh`"
,
(st8 *)0xF1,
(st8*)"OOOOOOppHHHhhhhh"
,
(st8*)"if (`HHHhhhhh`) execute (D_Unit)"
,
(st8*)"XCCPART `HHHhhhhh`"
,
(st8 *)0xF2,
(st8 *)0x0,
(st8*)"LD_RGM"
,
(st8*)"LD_RGM"
,
(st8 *)0xF3,
(st8*)"OOOOOOqqMMMMxxxxmm-aaaaa"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``MMMMxxxxmm,r` << #16`q_SAT,)`"
,
(st8*)"MOV`q_SAT` `MMMMxxxxmm,r` << #16, `aaaaa,ACx`"
,
(st8 *)0xF4,
(st8*)"OOOOOOOOMMMMxxxxmmq--o--"
,
(st8*)"mar(`MMMMxxxxmm,r`)"
,
(st8*)"AMAR `MMMMxxxxmm,r`"
,
(st8 *)0xF5,
(st8*)"OOOOOOOOMMMMxxxxmmq-p---"
,
(st8*)"push(`MMMMxxxxmm,r`)"
,
(st8*)"PSH `MMMMxxxxmm,r`"
,
(st8 *)0xF6,
(st8*)"OOOOOOOOMMMMxxxxmm------"
,
(st8*)"delay(`MMMMxxxxmm`)"
,
(st8*)"DELAY `MMMMxxxxmm`"
,
(st8 *)0xF7,
(st8*)"OOOOOOOOMMMMxxxxmmq-p---"
,
(st8*)"push(dbl(`MMMMxxxxmm,dr`))"
,
(st8*)"PSH dbl(`MMMMxxxxmm,dr`)"
,
(st8 *)0xF8,
(st8*)"OOOOOOOOMMMMxxxxmmq-p---"
,
(st8*)"dbl(`MMMMxxxxmm,dw`) = pop()"
,
(st8*)"POP dbl(`MMMMxxxxmm,dw`)"
,
(st8 *)0xF9,
(st8*)"OOOOOOOOMMMMxxxxmmq-p---"
,
(st8*)"`MMMMxxxxmm,w` = pop()"
,
(st8*)"POP `MMMMxxxxmm,w`"
,
(st8 *)0xFA,
(st8 *)0x0,
(st8*)"STH_RDM"
,
(st8*)"STH_RDM"
,
(st8 *)0xFB,
(st8 *)0x0,
(st8*)"ST_RGM"
,
(st8*)"ST_RGM"
,
(st8 *)0xFC,
(st8*)"OOOOOOO3MMMMxxxxmm%aaaaapp$-------#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/,(``$,(``MMMMxxxxmm``$,)` * `#,(``ZZZzzzz``#,)``/,)``%,)``4,)``q_SAT,)``MMMMxxxxmm3,3`, delay(`MMMMxxxxmm`)"
,
(st8*)"MACMZ`/``q_SAT``%``4` `3``$,(``MMMMxxxxmm,r``$,)`, `#,(``ZZZzzzz,r``#,)`, `aaaaa,ACx`"
,
(st8 *)0xFD,
(st8 *)0x0,
(st8*)"MPY_R_MWK"
,
(st8*)"MPY_R_MWK"
,
(st8 *)0xFE,
(st8 *)0x0,
(st8*)"MAC_R_MP"
,
(st8*)"MAC_R_MP"
,
(st8 *)0xFF,
(st8 *)0x0,
(st8*)"MAS_R_MP"
,
(st8*)"MAS_R_MP"
,
(st8 *)0x100,
(st8 *)0x0,
(st8*)"MAC_R_RM_A"
,
(st8*)"MAC_R_RM_A"
,
(st8 *)0x101,
(st8 *)0x0,
(st8*)"MAS_R_RM_A"
,
(st8*)"MAS_R_RM_A"
,
(st8 *)0x102,
(st8*)"OOOOOOO3MMMMxxxxmm%aaaaapp/ccccc"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``%,(``ccccc,ACx` + `/`(`MMMMxxxxmm,r` * `MMMMxxxxmm,r`)`%,)``q_SAT,)``MMMMxxxxmm3,3r`"
,
(st8*)"SQAM`/``q_SAT``%` `3``MMMMxxxxmm,r`, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x103,
(st8*)"OOOOOOO3MMMMxxxxmm%aaaaapp/ccccc"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``%,(``ccccc,ACx` - `/`(`MMMMxxxxmm,r` * `MMMMxxxxmm,r`)`%,)``q_SAT,)``MMMMxxxxmm3,3r`"
,
(st8*)"SQSM`/``q_SAT``%` `3``MMMMxxxxmm,r`, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x104,
(st8 *)0x0,
(st8*)"MPY_R_RM_L"
,
(st8*)"MPY_R_RM_L"
,
(st8 *)0x105,
(st8*)"OOOOOOO3MMMMxxxxmm%aaaaapp/-----"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``%,(``/,(``MMMMxxxxmm,r` * `MMMMxxxxmm,r``/,)``%,)``q_SAT,)``MMMMxxxxmm3,3r`"
,
(st8*)"SQRM`/``q_SAT``%` `3``MMMMxxxxmm,r`, `aaaaa,ACx`"
,
(st8 *)0x106,
(st8*)"OOOOOOO3MMMMxxxxmm%aaaaapp$-----/CCccccc"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``%,(``/,(``$,(``CCccccc,MRx` * `MMMMxxxxmm,r``$,)``/,)``%,)``q_SAT,)``MMMMxxxxmm3,3r`"
,
(st8*)"MPYM`/``q_SAT``%``$` `3``MMMMxxxxmm,r`, `CCccccc,MRx`, `aaaaa,ACx`"
,
(st8 *)0x107,
(st8*)"OOOOOOO3MMMMxxxxmm%aaaaapp$ccccc/DDddddd"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``%,(``ccccc,ACx` + `/,(``$,(``DDddddd,MRx` * `MMMMxxxxmm,r``$,)``/,)``%,)``q_SAT,)``MMMMxxxxmm3,3r`"
,
(st8*)"MACM`/``q_SAT``%``$` `3``MMMMxxxxmm,r`, `DDddddd,MRx`, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x108,
(st8*)"OOOOOOO3MMMMxxxxmm%aaaaapp$ccccc/DDddddd"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``%,(``ccccc,ACx` - `/,(``$,(``DDddddd,MRx` * `MMMMxxxxmm,r``$,)``/,)``%,)``q_SAT,)``MMMMxxxxmm3,3r`"
,
(st8*)"MASM`/``q_SAT``%``$` `3``MMMMxxxxmm,r`, `DDddddd,MRx`, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x109,
(st8*)"OOOOOoppMMMMxxxxmmAaaaaaACCccccc"
,
(st8*)"`AaaaaaA,!` = `q_SAT,(``CCccccc,Rx` + `MMMMxxxxmm,r``q_SAT,)`"
,
(st8*)"ADD`q_SAT` `MMMMxxxxmm,r`, `CCccccc,Rx`, `AaaaaaA,!`"
,
(st8 *)0x10A,
(st8*)"OOOOOoppMMMMxxxxmmAaaaaaACCccccc"
,
(st8*)"`AaaaaaA,!` = `q_SAT,(``CCccccc,Rx` - `MMMMxxxxmm,r``q_SAT,)`"
,
(st8*)"SUB`q_SAT` `MMMMxxxxmm,r`, `CCccccc,Rx`, `AaaaaaA,!`"
,
(st8 *)0x10B,
(st8*)"OOOOOoppMMMMxxxxmmAaaaaaACCccccc"
,
(st8*)"`AaaaaaA,!` = `q_SAT,(``MMMMxxxxmm,r` - `CCccccc,Rx``q_SAT,)`"
,
(st8*)"SUB`q_SAT` `CCccccc,Rx`, `MMMMxxxxmm,r`, `AaaaaaA,!`"
,
(st8 *)0x10C,
(st8*)"OOOOOoppMMMMxxxxmmAaaaaaACCccccc"
,
(st8*)"`AaaaaaA,!` = `CCccccc,Rx` & `MMMMxxxxmm,r`"
,
(st8*)"AND`q_SAT` `MMMMxxxxmm,r`, `CCccccc,Rx`, `AaaaaaA,!`"
,
(st8 *)0x10D,
(st8*)"OOOOOoppMMMMxxxxmmAaaaaaACCccccc"
,
(st8*)"`AaaaaaA,!` = `CCccccc,Rx` | `MMMMxxxxmm,r`"
,
(st8*)"OR`q_SAT` `MMMMxxxxmm,r`, `CCccccc,Rx`, `AaaaaaA,!`"
,
(st8 *)0x10E,
(st8*)"OOOOOoppMMMMxxxxmmAaaaaaACCccccc"
,
(st8*)"`AaaaaaA,!` = `CCccccc,Rx` ^ `MMMMxxxxmm,r`"
,
(st8*)"XOR`q_SAT` `MMMMxxxxmm,r`, `CCccccc,Rx`, `AaaaaaA,!`"
,
(st8 *)0x10F,
(st8*)"OOOOOOOOMMMMxxxxmmTppo------kkkk"
,
(st8*)"`T` = bit(`MMMMxxxxmm,r`, `kkkk`)"
,
(st8*)"BTST `kkkk`, `MMMMxxxxmm,r`, `T`"
,
(st8 *)0x110,
(st8 *)0x0,
(st8*)"BIT_MBT_K2"
,
(st8*)"BIT_MBT_K2"
,
(st8 *)0x111,
(st8 *)0x0,
(st8*)"LD_DP"
,
(st8*)"LD_DP"
,
(st8 *)0x112,
(st8 *)0x0,
(st8*)"LD_CDP"
,
(st8*)"LD_CDP"
,
(st8 *)0x113,
(st8 *)0x0,
(st8*)"LD_BOF01"
,
(st8*)"LD_BOF01"
,
(st8 *)0x114,
(st8 *)0x0,
(st8*)"LD_BOF23"
,
(st8*)"LD_BOF23"
,
(st8 *)0x115,
(st8 *)0x0,
(st8*)"LD_BOF45"
,
(st8*)"LD_BOF45"
,
(st8 *)0x116,
(st8 *)0x0,
(st8*)"LD_BOF67"
,
(st8*)"LD_BOF67"
,
(st8 *)0x117,
(st8 *)0x0,
(st8*)"LD_BOFC"
,
(st8*)"LD_BOFC"
,
(st8 *)0x118,
(st8 *)0x0,
(st8*)"LD_SP"
,
(st8*)"LD_SP"
,
(st8 *)0x119,
(st8 *)0x0,
(st8*)"LD_SSP"
,
(st8*)"LD_SSP"
,
(st8 *)0x11A,
(st8 *)0x0,
(st8*)"LD_BK03"
,
(st8*)"LD_BK03"
,
(st8 *)0x11B,
(st8 *)0x0,
(st8*)"LD_BK47"
,
(st8*)"LD_BK47"
,
(st8 *)0x11C,
(st8 *)0x0,
(st8*)"LD_BKC"
,
(st8*)"LD_BKC"
,
(st8 *)0x11D,
(st8 *)0x0,
(st8*)"LD_MDP"
,
(st8*)"LD_MDP"
,
(st8 *)0x11E,
(st8 *)0x0,
(st8*)"LD_MDP05"
,
(st8*)"LD_MDP05"
,
(st8 *)0x11F,
(st8 *)0x0,
(st8*)"LD_MDP67"
,
(st8*)"LD_MDP67"
,
(st8 *)0x120,
(st8 *)0x0,
(st8*)"LD_PDP"
,
(st8*)"LD_PDP"
,
(st8 *)0x121,
(st8 *)0x0,
(st8*)"LD_CSR"
,
(st8*)"LD_CSR"
,
(st8 *)0x122,
(st8 *)0x0,
(st8*)"LD_BRC0"
,
(st8*)"LD_BRC0"
,
(st8 *)0x123,
(st8 *)0x0,
(st8*)"LD_BRC1"
,
(st8*)"LD_BRC1"
,
(st8 *)0x124,
(st8 *)0x0,
(st8*)"LD_TRN0"
,
(st8*)"LD_TRN0"
,
(st8 *)0x125,
(st8 *)0x0,
(st8*)"LD_TRN1"
,
(st8*)"LD_TRN1"
,
(st8 *)0x126,
(st8*)"OOOOOOOOMMMMxxxxmm-aaaaa-p-ccccc-NNnnnnn"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` + (`MMMMxxxxmm,r` << `NNnnnnn,SRx`)`q_SAT,)`"
,
(st8*)"ADD`q_SAT` `MMMMxxxxmm,r` << `NNnnnnn,SRx`, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x127,
(st8*)"OOOOOOOOMMMMxxxxmm-aaaaa-p-ccccc-NNnnnnn"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` - (`MMMMxxxxmm,r` << `NNnnnnn,SRx`)`q_SAT,)`"
,
(st8*)"SUB`q_SAT` `MMMMxxxxmm,r` << `NNnnnnn,SRx`, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x128,
(st8*)"OOOOOOOOMMMMxxxxmm-aaaaapp-ccccc-NNnnnnn"
,
(st8*)"`aaaaa,ACx` = ads2c`q_SAT,a`(`MMMMxxxxmm,r`, `ccccc,ACx`, `NNnnnnn,SRx`, TC1, TC2)"
,
(st8*)"ADDSUB2CC`q_SAT` `MMMMxxxxmm,r`, `ccccc,ACx`, `NNnnnnn,SRx`, TC1, TC2, `aaaaa,ACx`"
,
(st8 *)0x129,
(st8*)"OOOOOOOOMMMMxxxxmm%aaaaa-p$----q-NNnnnnn"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``%,(``$,(``MMMMxxxxmm,r``$,)` << `NNnnnnn,SRx``%,)``q_SAT,)`"
,
(st8*)"MOV`q_SAT` `%,(``$,(``MMMMxxxxmm,r``$,)` << `NNnnnnn,SRx``%,)`, `aaaaa,ACx`"
,
(st8 *)0x12A,
(st8*)"OOOOOOOOMMMMxxxxmmTaaaaapp-ccccc--------"
,
(st8*)"`aaaaa,ACx` = adsc`q_SAT,a`(`MMMMxxxxmm,r`, `ccccc,ACx`, `T`)"
,
(st8*)"ADDSUBCC`q_SAT` `MMMMxxxxmm,r`, `ccccc,ACx`, `T`, `aaaaa,ACx`"
,
(st8 *)0x12B,
(st8 *)0x0,
(st8*)"ADSC_RM_2"
,
(st8*)"ADSC_RM_2"
,
(st8 *)0x12C,
(st8*)"OOOOOOOOMMMMxxxxmm-aaaaapp-ccccc--------"
,
(st8*)"`aaaaa,ACx` = adsc`q_SAT,a`(`MMMMxxxxmm,r`, `ccccc,ACx`, TC1, TC2)"
,
(st8*)"ADDSUBCC`q_SAT` `MMMMxxxxmm,r`, `ccccc,ACx`, TC1, TC2, `aaaaa,ACx`"
,
(st8 *)0x12D,
(st8*)"OOOOOOOOMMMMxxxxmm-aaaaapp-ccccc--------"
,
(st8*)"subc(`MMMMxxxxmm,r`, `ccccc,ACx`, `aaaaa,ACx`)"
,
(st8*)"SUBC `MMMMxxxxmm,r`, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x12E,
(st8*)"OOOOOOOOMMMMxxxxmm-aaaaapp-ccccc"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` + (`MMMMxxxxmm,r` << #16)`q_SAT,)`"
,
(st8*)"ADD`q_SAT` `MMMMxxxxmm,r` << #16, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x12F,
(st8*)"OOOOOOOOMMMMxxxxmm-aaaaapp-ccccc"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` - (`MMMMxxxxmm,r` << #16)`q_SAT,)`"
,
(st8*)"SUB`q_SAT` `MMMMxxxxmm,r` << #16, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x130,
(st8*)"OOOOOOOOMMMMxxxxmm-aaaaapp-ccccc"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(`(`MMMMxxxxmm,r` << #16) - `ccccc,ACx``q_SAT,)`"
,
(st8*)"SUB`q_SAT` `ccccc,ACx`, `MMMMxxxxmm,r` << #16, `aaaaa,ACx`"
,
(st8 *)0x131,
(st8*)"OOOOOOOOMMMMxxxxmmqaaaaa-po100cc"
,
(st8*)"HI(`aaaaa,ACx`) = `q_SAT,(``MMMMxxxxmm,r` + `cc,Tx``q_SAT,)`, LO(`aaaaa,ACx`) = `q_SAT,(``MMMMxxxxmm,r` - `cc,Tx``q_SAT,)`"
,
(st8*)"ADDSUB`q_SAT` `cc,Tx`, `MMMMxxxxmm,r`, `aaaaa,ACx`"
,
(st8 *)0x132,
(st8*)"OOOOOOOOMMMMxxxxmmqaaaaa-po100cc"
,
(st8*)"HI(`aaaaa,ACx`) = `q_SAT,(``MMMMxxxxmm,r` - `cc,Tx``q_SAT,)`, LO(`aaaaa,ACx`) = `q_SAT,(``MMMMxxxxmm,r` + `cc,Tx``q_SAT,)`"
,
(st8*)"SUBADD`q_SAT` `cc,Tx`, `MMMMxxxxmm,r`, `aaaaa,ACx`"
,
(st8 *)0x133,
(st8*)"OOOOOOOOMMMMxxxxmmqaaaaapp$---AA"
,
(st8*)"`AAaaaaa,Rx` = `$,(`high_byte(`MMMMxxxxmm,r`)`$,)`"
,
(st8*)"MOV `$,(`high_byte(`MMMMxxxxmm,r`)`$,)`, `AAaaaaa,Rx`"
,
(st8 *)0x134,
(st8*)"OOOOOOOOMMMMxxxxmmqaaaaapp$---AA"
,
(st8*)"`AAaaaaa,Rx` = `$,(`low_byte(`MMMMxxxxmm,r`)`$,)`"
,
(st8*)"MOV `$,(`low_byte(`MMMMxxxxmm,r`)`$,)`, `AAaaaaa,Rx`"
,
(st8 *)0x135,
(st8*)"OOOOOOqqMMMMxxxxmm$aaaaa"
,
(st8*)"`aaaaa,ACx` = `$,(``MMMMxxxxmm,r``$,)`"
,
(st8*)"MOV `$,(``MMMMxxxxmm,r``$,)`, `aaaaa,ACx`"
,
(st8 *)0x136,
(st8*)"OOOOOOOOMMMMxxxxmm$aaaaappoccccc"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` + `$,(``MMMMxxxxmm,r``$,)` + Carry`q_SAT,)`"
,
(st8*)"ADD`q_SAT` `$,(``MMMMxxxxmm,r``$,)`, CARRY, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x137,
(st8*)"OOOOOOOOMMMMxxxxmm$aaaaappoccccc"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` - uns(`MMMMxxxxmm,r`) - Borrow`q_SAT,)`"
,
(st8*)"SUB`q_SAT` `$,(``MMMMxxxxmm,r``$,)`, BORROW, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x138,
(st8*)"OOOOOOOOMMMMxxxxmm1aaaaappoccccc"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` + uns(`MMMMxxxxmm,r`)`q_SAT,)`"
,
(st8*)"ADD`q_SAT` uns(`MMMMxxxxmm,r`), `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x139,
(st8*)"OOOOOOOOMMMMxxxxmm1aaaaappoccccc"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` - uns(`MMMMxxxxmm,r`)`q_SAT,)`"
,
(st8*)"SUB`q_SAT` uns(`MMMMxxxxmm,r`), `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x13A,
(st8*)"OOOOOOOOMMMMxxxxmmTcccccppo---CC"
,
(st8*)"`T` = bit(`MMMMxxxxmm,r`, `CCccccc,RLHx`)"
,
(st8*)"BTST `CCccccc,RLHx`, `MMMMxxxxmm,r`, `T`"
,
(st8 *)0x13B,
(st8*)"OOOOOOOOMMMMxxxxmm-aaaaa-p-----q--SSSSSS"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(`low_byte(`MMMMxxxxmm,r`) << `SSSSSS``q_SAT,)`"
,
(st8*)"MOV`q_SAT` low_byte(`MMMMxxxxmm,r`) << `SSSSSS`, `aaaaa,ACx`"
,
(st8 *)0x13C,
(st8*)"OOOOOOOOMMMMxxxxmm-aaaaa-p-----q--SSSSSS"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(`high_byte(`MMMMxxxxmm,r`) << `SSSSSS``q_SAT,)`"
,
(st8*)"MOV`q_SAT` high_byte(`MMMMxxxxmm,r`) << `SSSSSS`, `aaaaa,ACx`"
,
(st8 *)0x13D,
(st8*)"OOOOOOOOMMMMxxxxmmTppo------kkkk"
,
(st8*)"`T` = bit(`MMMMxxxxmm,rw`, `kkkk`), bit(`MMMMxxxxmm,rw`, `kkkk`) = #1"
,
(st8*)"BTSTSET `kkkk`, `MMMMxxxxmm,rw`, `T`"
,
(st8 *)0x13E,
(st8 *)0x0,
(st8*)"SMBX_MS_2"
,
(st8*)"SMBX_MS_2"
,
(st8 *)0x13F,
(st8*)"OOOOOOOOMMMMxxxxmmTppo------kkkk"
,
(st8*)"`T` = bit(`MMMMxxxxmm,rw`, `kkkk`), bit(`MMMMxxxxmm,rw`, `kkkk`) = #0"
,
(st8*)"BTSTCLR `kkkk`, `MMMMxxxxmm,rw`, `T`"
,
(st8 *)0x140,
(st8 *)0x0,
(st8*)"RMBX_MR_2"
,
(st8*)"RMBX_MR_2"
,
(st8 *)0x141,
(st8*)"OOOOOOOOMMMMxxxxmmTppo------kkkk"
,
(st8*)"`T` = bit(`MMMMxxxxmm,rw`, `kkkk`), cbit(`MMMMxxxxmm,rw`, `kkkk`)"
,
(st8*)"BTSTNOT `kkkk`, `MMMMxxxxmm,rw`, `T`"
,
(st8 *)0x142,
(st8 *)0x0,
(st8*)"CMBX_MC_2"
,
(st8*)"CMBX_MC_2"
,
(st8 *)0x143,
(st8*)"OOOOOOOOMMMMxxxxmmqcccccppo---CC"
,
(st8*)"bit(`MMMMxxxxmm,r`, `CCccccc,RLHx`) = #1"
,
(st8*)"BSET `CCccccc,RLHx`, `MMMMxxxxmm,r`"
,
(st8 *)0x144,
(st8*)"OOOOOOOOMMMMxxxxmmqcccccppo---CC"
,
(st8*)"bit(`MMMMxxxxmm,r`, `CCccccc,RLHx`) = #0"
,
(st8*)"BCLR `CCccccc,RLHx`, `MMMMxxxxmm,r`"
,
(st8 *)0x145,
(st8*)"OOOOOOOOMMMMxxxxmm-cccccppo---CC"
,
(st8*)"cbit(`MMMMxxxxmm,rw`, `CCccccc,RLHx`)"
,
(st8*)"BNOT `CCccccc,RLHx`, `MMMMxxxxmm,rw`"
,
(st8 *)0x146,
(st8*)"OOOOOOOOMMMMxxxxmm-ccccc-p----CC"
,
(st8*)"push(`CCccccc,RLHx`, `MMMMxxxxmm,r`)"
,
(st8*)"PSH `CCccccc,RLHx`, `MMMMxxxxmm,r`"
,
(st8 *)0x147,
(st8*)"OOOOOOOOMMMMxxxxmm-aaaaa-p----AA"
,
(st8*)"`AAaaaaa,RLHx`, `MMMMxxxxmm,w` = pop()"
,
(st8*)"POP `AAaaaaa,RLHx`, `MMMMxxxxmm,w`"
,
(st8 *)0x148,
(st8 *)0x0,
(st8*)"ST_COPR"
,
(st8*)"ST_COPR"
,
(st8 *)0x149,
(st8*)"OOOOOOOOMMMMxxxxmmqcccccpp----CC"
,
(st8*)"high_byte(`MMMMxxxxmm,w`) = `CCccccc,Rx`"
,
(st8*)"MOV `CCccccc,Rx`, high_byte(`MMMMxxxxmm,w`)"
,
(st8 *)0x14A,
(st8*)"OOOOOOOOMMMMxxxxmmqcccccpp----CC"
,
(st8*)"low_byte(`MMMMxxxxmm,w`) = `CCccccc,Rx`"
,
(st8*)"MOV `CCccccc,Rx`, low_byte(`MMMMxxxxmm,w`)"
,
(st8 *)0x14B,
(st8 *)0x0,
(st8*)"ST_DP"
,
(st8*)"ST_DP"
,
(st8 *)0x14C,
(st8 *)0x0,
(st8*)"ST_CDP"
,
(st8*)"ST_CDP"
,
(st8 *)0x14D,
(st8 *)0x0,
(st8*)"ST_BOF01"
,
(st8*)"ST_BOF01"
,
(st8 *)0x14E,
(st8 *)0x0,
(st8*)"ST_BOF23"
,
(st8*)"ST_BOF23"
,
(st8 *)0x14F,
(st8 *)0x0,
(st8*)"ST_BOF45"
,
(st8*)"ST_BOF45"
,
(st8 *)0x150,
(st8 *)0x0,
(st8*)"ST_BOF67"
,
(st8*)"ST_BOF67"
,
(st8 *)0x151,
(st8 *)0x0,
(st8*)"ST_BOFC"
,
(st8*)"ST_BOFC"
,
(st8 *)0x152,
(st8 *)0x0,
(st8*)"ST_SP"
,
(st8*)"ST_SP"
,
(st8 *)0x153,
(st8 *)0x0,
(st8*)"ST_SSP"
,
(st8*)"ST_SSP"
,
(st8 *)0x154,
(st8 *)0x0,
(st8*)"ST_BK03"
,
(st8*)"ST_BK03"
,
(st8 *)0x155,
(st8 *)0x0,
(st8*)"ST_BK47"
,
(st8*)"ST_BK47"
,
(st8 *)0x156,
(st8 *)0x0,
(st8*)"ST_BKC"
,
(st8*)"ST_BKC"
,
(st8 *)0x157,
(st8 *)0x0,
(st8*)"ST_MDP"
,
(st8*)"ST_MDP"
,
(st8 *)0x158,
(st8 *)0x0,
(st8*)"ST_MDP05"
,
(st8*)"ST_MDP05"
,
(st8 *)0x159,
(st8 *)0x0,
(st8*)"ST_MDP67"
,
(st8*)"ST_MDP67"
,
(st8 *)0x15A,
(st8 *)0x0,
(st8*)"ST_PDP"
,
(st8*)"ST_PDP"
,
(st8 *)0x15B,
(st8 *)0x0,
(st8*)"ST_CSR"
,
(st8*)"ST_CSR"
,
(st8 *)0x15C,
(st8 *)0x0,
(st8*)"ST_BRC0"
,
(st8*)"ST_BRC0"
,
(st8 *)0x15D,
(st8 *)0x0,
(st8*)"ST_BRC1"
,
(st8*)"ST_BRC1"
,
(st8 *)0x15E,
(st8 *)0x0,
(st8*)"ST_TRN0"
,
(st8*)"ST_TRN0"
,
(st8 *)0x15F,
(st8 *)0x0,
(st8*)"ST_TRN1"
,
(st8*)"ST_TRN1"
,
(st8 *)0x160,
(st8*)"OOOOOoKKMMMMxxxxmmKKKKKK"
,
(st8*)"`MMMMxxxxmm,w` = `KKKKKKKK`"
,
(st8*)"MOV `KKKKKKKK`, `MMMMxxxxmm,w`"
,
(st8 *)0x161,
(st8 *)0x0,
(st8*)"ST_RM_ASM"
,
(st8*)"ST_RM_ASM"
,
(st8 *)0x162,
(st8 *)0x0,
(st8*)"STH_R_RM_ASM"
,
(st8*)"STH_R_RM_ASM"
,
(st8 *)0x163,
(st8*)"OOOOOOOOMMMMxxxxmm%ccccc@p$---Iq-NNnnnnn"
,
(st8*)"`MMMMxxxxmm,w` = `I`(`@,(``$,(``%,(``ccccc,ACx` << `NNnnnnn,SRx``%,)``$,)``@,)`)"
,
(st8*)"MOV `$,(``%,(``I`(`@,(``ccccc,ACx` << `NNnnnnn,SRx``@,)`)`%,)``$,)`, `MMMMxxxxmm,w`"
,
(st8 *)0x164,
(st8 *)0x0,
(st8*)"STH_R_RM"
,
(st8*)"STH_R_RM"
,
(st8 *)0x165,
(st8*)"OOOOOOOOMMMMxxxxmm%ccccc@p$---Iq"
,
(st8*)"`MMMMxxxxmm,w` = `I`(`@,(``$,(``%,(``ccccc,ACx``%,)``$,)``@,)`)"
,
(st8*)"MOV `$,(``%,(``I`(`@,(``ccccc,ACx``@,)`)`%,)``$,)`, `MMMMxxxxmm,w`"
,
(st8 *)0x166,
(st8 *)0x0,
(st8*)"ST_RM_SH"
,
(st8*)"ST_RM_SH"
,
(st8 *)0x167,
(st8 *)0x0,
(st8*)"STH_RM_SH"
,
(st8*)"STH_RM_SH"
,
(st8 *)0x168,
(st8 *)0x0,
(st8*)"DST_COPR"
,
(st8*)"DST_COPR"
,
(st8 *)0x169,
(st8 *)0x0,
(st8*)"DST_RPC"
,
(st8*)"DST_RPC"
,
(st8 *)0x16A,
(st8 *)0x0,
(st8*)"DST_XR"
,
(st8*)"DST_XR"
,
(st8 *)0x16B,
(st8 *)0x0,
(st8*)"DST_RDLM"
,
(st8*)"DST_RDLM"
,
(st8 *)0x16C,
(st8*)"OOOOOOOOMMMMxxxxmm%ccccc@p$----q"
,
(st8*)"dbl(`MMMMxxxxmm,dw`) = `@,(``$,(``%,(``ccccc,ACx``%,)``$,)``@,)`"
,
(st8*)"MOV `$,(``%,(``@,(``ccccc,ACx``@,)``%,)``$,)`, dbl(`MMMMxxxxmm,dw`)"
,
(st8 *)0x16D,
(st8*)"OOOOOOOOMMMMxxxxmmqccccc-p----CC"
,
(st8*)"HI(`MMMMxxxxmm,dw`) = `CCccccc,RL`, LO(`MMMMxxxxmm,dw`) = `CCccccc,RLP`"
,
(st8*)"MOV pair(`CCccccc,RLHx`), dbl(`MMMMxxxxmm,dw`)"
,
(st8 *)0x16E,
(st8*)"OOOOOOOOMMMMxxxxmm-ccccc"
,
(st8*)"HI(`MMMMxxxxmm,w`) = HI(`ccccc,ACx`) >> #1, LO(`MMMMxxxxmm,w`) = LO(`ccccc,ACx`) >> #1"
,
(st8*)"MOV `ccccc,ACx` >> #1, dbl(`MMMMxxxxmm,w`)"
,
(st8 *)0x16F,
(st8 *)0x0,
(st8*)"DST_RDLM_HI"
,
(st8*)"DST_RDLM_HI"
,
(st8 *)0x170,
(st8 *)0x0,
(st8*)"DST_RDLM_LO"
,
(st8*)"DST_RDLM_LO"
,
(st8 *)0x171,
(st8*)"OOOOOOOOMMMMxxxxmmqaaaaappo---AA"
,
(st8*)"bit(`AAaaaaa,Rx`, `MMMMxxxxmm,baddr`) = #1"
,
(st8*)"BSET `MMMMxxxxmm,baddr`, `AAaaaaa,Rx`"
,
(st8 *)0x172,
(st8*)"OOOOOOOOMMMMxxxxmmqaaaaappo---AA"
,
(st8*)"bit(`AAaaaaa,Rx`, `MMMMxxxxmm,baddr`) = #0"
,
(st8*)"BCLR `MMMMxxxxmm,baddr`, `AAaaaaa,Rx`"
,
(st8 *)0x173,
(st8*)"OOOOOOOOMMMMxxxxmm-cccccppo---CC"
,
(st8*)"TC1,TC2 = bit(`CCccccc,Rx`, `MMMMxxxxmm,baddr`)"
,
(st8*)"BTSTP `MMMMxxxxmm,baddr`, `CCccccc,Rx`"
,
(st8 *)0x174,
(st8*)"OOOOOOOOMMMMxxxxmm-aaaaappo---AA"
,
(st8*)"cbit(`AAaaaaa,Rx`, `MMMMxxxxmm,baddr`)"
,
(st8*)"BNOT `MMMMxxxxmm,baddr`, `AAaaaaa,Rx`"
,
(st8 *)0x175,
(st8*)"OOOOOOOOMMMMxxxxmmTcccccppo---CC"
,
(st8*)"`T` = bit(`CCccccc,Rx`, `MMMMxxxxmm,baddr`)"
,
(st8*)"BTST `MMMMxxxxmm,baddr`, `CCccccc,Rx`, `T`"
,
(st8 *)0x176,
(st8*)"OOOOOOOOMMMMxxxxmmoaaaaa"
,
(st8*)"`aaaaa,XDAx` = mar(`MMMMxxxxmm,r`)"
,
(st8*)"AMAR `MMMMxxxxmm,r`, `aaaaa,XDAx`"
,
(st8 *)0x177,
(st8*)"OOOOOOOOMMMMxxxxmm-aaaaapp-ccccc"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` + dbl(`MMMMxxxxmm,dr`)`q_SAT,)`"
,
(st8*)"ADD`q_SAT` dbl(`MMMMxxxxmm,dr`), `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x178,
(st8*)"OOOOOOOOMMMMxxxxmm-aaaaapp-ccccc"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` - dbl(`MMMMxxxxmm,dr`)`q_SAT,)`"
,
(st8*)"SUB`q_SAT` dbl(`MMMMxxxxmm,dr`), `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x179,
(st8*)"OOOOOOOOMMMMxxxxmm-aaaaapp-ccccc"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(`dbl(`MMMMxxxxmm,dr`) - `ccccc,ACx``q_SAT,)`"
,
(st8*)"SUB`q_SAT` `ccccc,ACx`, dbl(`MMMMxxxxmm,dr`), `aaaaa,ACx`"
,
(st8 *)0x17A,
(st8 *)0x0,
(st8*)"DLD_RPC"
,
(st8*)"DLD_RPC"
,
(st8 *)0x17B,
(st8*)"OOOOOOOOMMMMxxxxmm4aaaaa"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(`dbl(`MMMMxxxxmm,dr`)`4,)``q_SAT,)`"
,
(st8*)"MOV`q_SAT``4` dbl(`MMMMxxxxmm,dr`), `aaaaa,ACx`"
,
(st8 *)0x17C,
(st8*)"OOOOOOOOMMMMxxxxmmqaaaaa-p----00"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(`HI(`MMMMxxxxmm,dr`)<<#16`q_SAT,)`, `aaaaa,ACxP` = `q_SAT,(`LO(`MMMMxxxxmm,dr`)<<#16`q_SAT,)`"
,
(st8*)"MOV`q_SAT` dbl(`MMMMxxxxmm,dr`), pair(HI(`aaaaa,ACx`))"
,
(st8 *)0x17D,
(st8 *)0x0,
(st8*)"DLD_RDLM_LO"
,
(st8*)"DLD_RDLM_LO"
,
(st8 *)0x17E,
(st8*)"OOOOOOOOMMMMxxxxmmqaaaaa-p----AA"
,
(st8*)"`AAaaaaa,Rx` = HI(`MMMMxxxxmm,dr`), `AAaaaaa,RxP` = LO(`MMMMxxxxmm,dr`)"
,
(st8*)"MOV dbl(`MMMMxxxxmm,dr`), pair(`AAaaaaa,RLHx`)"
,
(st8 *)0x17F,
(st8 *)0x0,
(st8*)"DLD_XR"
,
(st8*)"DLD_XR"
,
(st8 *)0x180,
(st8*)"OOOOOOOOMMMMxxxxmm-aaaaappoccccc"
,
(st8*)"HI(`aaaaa,ACx`) = `q_SAT,(`HI(`MMMMxxxxmm,r`) + HI(`ccccc,ACx`)`q_SAT,)`, LO(`aaaaa,ACx`) = `q_SAT,(`LO(`MMMMxxxxmm,r`) + LO(`ccccc,ACx`)`q_SAT,)`"
,
(st8*)"ADD`q_SAT` dual(`MMMMxxxxmm,r`), `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x181,
(st8*)"OOOOOOOOMMMMxxxxmm-aaaaappoccccc"
,
(st8*)"HI(`aaaaa,ACx`) = `q_SAT,(`HI(`ccccc,ACx`) - HI(`MMMMxxxxmm,r`)`q_SAT,)`, LO(`aaaaa,ACx`) = `q_SAT,(`LO(`ccccc,ACx`) - LO(`MMMMxxxxmm,r`)`q_SAT,)`"
,
(st8*)"SUB`q_SAT` dual(`MMMMxxxxmm,r`), `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x182,
(st8*)"OOOOOOOOMMMMxxxxmm-aaaaappoccccc"
,
(st8*)"HI(`aaaaa,ACx`) = `q_SAT,(`HI(`MMMMxxxxmm,r`) - HI(`ccccc,ACx`)`q_SAT,)`, LO(`aaaaa,ACx`) = `q_SAT,(`LO(`MMMMxxxxmm,r`) - LO(`ccccc,ACx`)`q_SAT,)`"
,
(st8*)"SUB`q_SAT` `ccccc,ACx`, dual(`MMMMxxxxmm,r`), `aaaaa,ACx`"
,
(st8 *)0x183,
(st8*)"OOOOOOOOMMMMxxxxmm-aaaaappo100cc"
,
(st8*)"HI(`aaaaa,ACx`) = `q_SAT,(``cc,Tx` - HI(`MMMMxxxxmm,r`)`q_SAT,)`, LO(`aaaaa,ACx`) = `q_SAT,(``cc,Tx` - LO(`MMMMxxxxmm,r`)`q_SAT,)`"
,
(st8*)"SUB`q_SAT` dual(`MMMMxxxxmm,r`), `cc,Tx`, `aaaaa,ACx`"
,
(st8 *)0x184,
(st8*)"OOOOOOOOMMMMxxxxmm-aaaaappo100cc"
,
(st8*)"HI(`aaaaa,ACx`) = `q_SAT,(`HI(`MMMMxxxxmm,r`) + `cc,Tx``q_SAT,)`, LO(`aaaaa,ACx`) = `q_SAT,(`LO(`MMMMxxxxmm,r`) + `cc,Tx``q_SAT,)`"
,
(st8*)"ADD`q_SAT` dual(`MMMMxxxxmm,r`), `cc,Tx`, `aaaaa,ACx`"
,
(st8 *)0x185,
(st8*)"OOOOOOOOMMMMxxxxmm-aaaaappo100cc"
,
(st8*)"HI(`aaaaa,ACx`) = `q_SAT,(`HI(`MMMMxxxxmm,r`) - `cc,Tx``q_SAT,)`, LO(`aaaaa,ACx`) = `q_SAT,(`LO(`MMMMxxxxmm,r`) - `cc,Tx``q_SAT,)`"
,
(st8*)"SUB`q_SAT` `cc,Tx`, dual(`MMMMxxxxmm,r`), `aaaaa,ACx`"
,
(st8 *)0x186,
(st8*)"OOOOOOOOMMMMxxxxmmqaaaaa-po100cc"
,
(st8*)"HI(`aaaaa,ACx`) = `q_SAT,(`HI(`MMMMxxxxmm,r`) + `cc,Tx``q_SAT,)`, LO(`aaaaa,ACx`) = `q_SAT,(`LO(`MMMMxxxxmm,r`) - `cc,Tx``q_SAT,)`"
,
(st8*)"ADDSUB`q_SAT` `cc,Tx`, dual(`MMMMxxxxmm,r`), `aaaaa,ACx`"
,
(st8 *)0x187,
(st8*)"OOOOOOOOMMMMxxxxmmqaaaaa-po100cc"
,
(st8*)"HI(`aaaaa,ACx`) = `q_SAT,(`HI(`MMMMxxxxmm,r`) - `cc,Tx``q_SAT,)`, LO(`aaaaa,ACx`) = `q_SAT,(`LO(`MMMMxxxxmm,r`) + `cc,Tx``q_SAT,)`"
,
(st8*)"SUBADD`q_SAT` `cc,Tx`, dual(`MMMMxxxxmm,r`), `aaaaa,ACx`"
,
(st8 *)0x188,
(st8*)"OOOOOOOOMMMMxxxxmmq-po---YYYyyyy"
,
(st8*)"`MMMMxxxxmm,w` = `YYYyyyy,r`"
,
(st8*)"MOV `YYYyyyy,r`, `MMMMxxxxmm,w`"
,
(st8 *)0x189,
(st8*)"OOOOOOOOMMMMxxxxmmq-po---YYYyyyy"
,
(st8*)"`YYYyyyy,w` = `MMMMxxxxmm,r`"
,
(st8*)"MOV `MMMMxxxxmm,r`, `YYYyyyy,w`"
,
(st8 *)0x18A,
(st8*)"OOOOOOOOMMMMxxxxmmq-po---YYYyyyy"
,
(st8*)"dbl(`MMMMxxxxmm,dw`) = dbl(`YYYyyyy,r`)"
,
(st8*)"MOV dbl(`YYYyyyy,r`), dbl(`MMMMxxxxmm,dw`)"
,
(st8 *)0x18B,
(st8*)"OOOOOOOOMMMMxxxxmmq-po---YYYyyyy"
,
(st8*)"dbl(`YYYyyyy,w`) = dbl(`MMMMxxxxmm,dr`)"
,
(st8*)"MOV dbl(`MMMMxxxxmm,dr`), dbl(`YYYyyyy,w`)"
,
(st8 *)0x18C,
(st8*)"OOOOOOOOMMMMxxxxmmT-poJJKKKKKKKKKKKKKKKK"
,
(st8*)"`T` = (`MMMMxxxxmm,r` `JJ` `KKKKKKKKKKKKKKKK`)"
,
(st8*)"CMP `MMMMxxxxmm,r` `JJ` `KKKKKKKKKKKKKKKK`, `T`"
,
(st8 *)0x18D,
(st8 *)0x0,
(st8*)"CMPM_MWK_2"
,
(st8*)"CMPM_MWK_2"
,
(st8 *)0x18E,
(st8*)"OOOOOOOOMMMMxxxxmmT-p---kkkkkkkkkkkkkkkk"
,
(st8*)"`T` = `MMMMxxxxmm,r` & `kkkkkkkkkkkkkkkk`"
,
(st8*)"BAND `MMMMxxxxmm,r`, `kkkkkkkkkkkkkkkk`, `T`"
,
(st8 *)0x18F,
(st8 *)0x0,
(st8*)"BITF_MWK_2"
,
(st8*)"BITF_MWK_2"
,
(st8 *)0x190,
(st8*)"OOOOOOOOMMMMxxxxmmqppo--kkkkkkkkkkkkkkkk"
,
(st8*)"`MMMMxxxxmm,rw` = `MMMMxxxxmm,rw` & `kkkkkkkkkkkkkkkk`"
,
(st8*)"AND `kkkkkkkkkkkkkkkk`, `MMMMxxxxmm,rw`"
,
(st8 *)0x191,
(st8*)"OOOOOOOOMMMMxxxxmmqppo--kkkkkkkkkkkkkkkk"
,
(st8*)"`MMMMxxxxmm,rw` = `MMMMxxxxmm,rw` | `kkkkkkkkkkkkkkkk`"
,
(st8*)"OR `kkkkkkkkkkkkkkkk`, `MMMMxxxxmm,rw`"
,
(st8 *)0x192,
(st8*)"OOOOOOOOMMMMxxxxmmqppo--kkkkkkkkkkkkkkkk"
,
(st8*)"`MMMMxxxxmm,rw` = `MMMMxxxxmm,rw` ^ `kkkkkkkkkkkkkkkk`"
,
(st8*)"XOR `kkkkkkkkkkkkkkkk`, `MMMMxxxxmm,rw`"
,
(st8 *)0x193,
(st8*)"OOOOOOOOMMMMxxxxmmqppo--KKKKKKKKKKKKKKKK"
,
(st8*)"`MMMMxxxxmm,rw` = `q_SAT,(``MMMMxxxxmm,rw` + `KKKKKKKKKKKKKKKK``q_SAT,)`"
,
(st8*)"ADD`q_SAT` `KKKKKKKKKKKKKKKK`, `MMMMxxxxmm,rw`"
,
(st8 *)0x194,
(st8*)"OOOOOOO3MMMMxxxxmm%aaaaa-p/-----KKKKKKKK"
,
(st8*)"`aaaaa,ACx` = `%,(``/,(``MMMMxxxxmm,r` * `KKKKKKKK``/,)``%,)``MMMMxxxxmm3,3r`"
,
(st8*)"MPYMK`/``%` `3``MMMMxxxxmm,r`, `KKKKKKKK`, `aaaaa,ACx`"
,
(st8 *)0x195,
(st8*)"OOOOOOO3MMMMxxxxmm%aaaaa-p/cccccKKKKKKKK"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``%,(``ccccc,ACx` + `/,(``MMMMxxxxmm,r` * `KKKKKKKK``/,)``%,)``q_SAT,)``MMMMxxxxmm3,3r`"
,
(st8*)"MACMK`/``q_SAT``%` `3``MMMMxxxxmm,r`, `KKKKKKKK`, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x196,
(st8*)"OOOOOOOOMMMMxxxxmm$aaaaapp-cccccqqSSSSSS"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` + (`$,(``MMMMxxxxmm,r``$,)` << `SSSSSS`)`q_SAT,)`"
,
(st8*)"ADD`q_SAT` `$,(``MMMMxxxxmm,r``$,)` << `SSSSSS`, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x197,
(st8*)"OOOOOOOOMMMMxxxxmm$aaaaapp-cccccqqSSSSSS"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` - (`$,(``MMMMxxxxmm,r``$,)` << `SSSSSS`)`q_SAT,)`"
,
(st8*)"SUB`q_SAT` `$,(``MMMMxxxxmm,r``$,)` << `SSSSSS`, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x198,
(st8*)"OOOOOOOOMMMMxxxxmm$aaaaapp------qqSSSSSS"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``$,(``MMMMxxxxmm,r``$,)` << `SSSSSS``q_SAT,)`"
,
(st8*)"MOV`q_SAT` `$,(``MMMMxxxxmm,r``$,)` << `SSSSSS`, `aaaaa,ACx`"
,
(st8 *)0x199,
(st8 *)0x0,
(st8*)"STHS_RM_SHS"
,
(st8*)"STHS_RM_SHS"
,
(st8 *)0x19A,
(st8*)"OOOOOOOOMMMMxxxxmm%ccccc@p$---Iq--SSSSSS"
,
(st8*)"`MMMMxxxxmm,w` = `I`(`@,(``$,(``%,(``ccccc,ACx` << `SSSSSS``%,)``$,)``@,)`)"
,
(st8*)"MOV `$,(``%,(``I`(`@,(``ccccc,ACx` << `SSSSSS``@,)`)`%,)``$,)`, `MMMMxxxxmm,w`"
,
(st8 *)0x19B,
(st8*)"OOOOOOOOMMMMxxxxmmqppo--iiiiiiiiiiiiiiii"
,
(st8*)"`MMMMxxxxmm,w` = `iiiiiiiiiiiiiiii`"
,
(st8*)"MOV `iiiiiiiiiiiiiiii`, `MMMMxxxxmm,w`"
,
(st8 *)0x19C,
(st8*)"OOOOOOOOMMMMxxxxmm------LLLLLLLLLLLLLLLL"
,
(st8*)"if (`MMMMxxxxmm,r` != #0) goto `LLLLLLLLLLLLLLLL`"
,
(st8*)"BCC `LLLLLLLLLLLLLLLL`, `MMMMxxxxmm,r` != #0"
,
(st8 *)0x19D,
(st8*)"OOOOOOOop-Aaaaaap-Cccccc"
,
(st8*)"`Aaaaaa,XRx` = `Cccccc,XRx`"
,
(st8*)"MOV `Cccccc,XRx`, `Aaaaaa,XRx`"
,
(st8 *)0x19E,
(st8 *)0x0,
(st8*)"FAR"
,
(st8*)"FAR"
,
(st8 *)0x19F,
(st8 *)0x0,
(st8*)"LOCAL"
,
(st8*)"LOCAL"
,
(st8 *)0x1A0,
(st8 *)0x0,
(st8*)"MAR_XAR_AX"
,
(st8*)"MAR_XAR_AX"
,
(st8 *)0x1A1,
(st8 *)0x0,
(st8*)"MAR_XAR_MX"
,
(st8*)"MAR_XAR_MX"
,
(st8 *)0x1A2,
(st8 *)0x0,
(st8*)"MAR_XAR_SX"
,
(st8*)"MAR_XAR_SX"
,
(st8 *)0x1A3,
(st8 *)0x0,
(st8*)"MAR_XAR_AY"
,
(st8*)"MAR_XAR_AY"
,
(st8 *)0x1A4,
(st8 *)0x0,
(st8*)"MAR_XAR_MY"
,
(st8*)"MAR_XAR_MY"
,
(st8 *)0x1A5,
(st8 *)0x0,
(st8*)"MAR_XAR_SY"
,
(st8*)"MAR_XAR_SY"
,
(st8 *)0x1A6,
(st8 *)0x0,
(st8*)"USR"
,
(st8*)"USR"
,
(st8 *)0x1A7,
(st8 *)0x0,
(st8*)"MMAP_USR"
,
(st8*)"MMAP_USR"
,
(st8 *)0x1A8,
(st8*)"OOOOOOpp"
,
(st8*)"LOCK"
,
(st8*)"LOCK"
,
(st8 *)0x1A9,
(st8 *)0x0,
(st8*)"BR_USR"
,
(st8*)"BR_USR"
,
(st8 *)0x1AA,
(st8*)"OOOOOOOOpXXXxxxxp--aaaaa1YYYyyyy/--bbbbb"
,
(st8*)"lmsf`/,a``q_SAT,a`(`XXXxxxx,r`, `YYYyyyy,r`, `aaaaa,ACx`, `bbbbb,ACx`)"
,
(st8*)"LMSF`/``q_SAT` `XXXxxxx,r`, `YYYyyyy,r`, `aaaaa,ACx`, `bbbbb,ACx`"
,
(st8 *)0x1AB,
(st8*)"OOOOOOO3MMMMxxxxmm%aaaaapp$-------#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``MMMMxxxxmm,r``$,)` * `#,(``ZZZzzzz,r``#,)``/,)``%,)``4,)``q_SAT,)``MMMMxxxxmm3,3r`"
,
(st8*)"MPYM`/``q_SAT``%``4` `3``$,(``MMMMxxxxmm,r``$,)`, `#,(``ZZZzzzz,r``#,)`, `aaaaa,ACx`"
,
(st8 *)0x1AC,
(st8*)"OOOOOOO3MMMMxxxxmm%aaaaapp$-------#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/,(``$,(``MMMMxxxxmm,r``$,)` * `#,(``ZZZzzzz,r``#,)``/,)``%,)``4,)``q_SAT,)``MMMMxxxxmm3,3r`"
,
(st8*)"MACM`/``q_SAT``%``4` `3``$,(``MMMMxxxxmm,r``$,)`, `#,(``ZZZzzzz,r``#,)`, `aaaaa,ACx`"
,
(st8 *)0x1AD,
(st8*)"OOOOOOO3MMMMxxxxmm%aaaaapp$-------#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/,(``$,(``MMMMxxxxmm,r``$,)` * `#,(``ZZZzzzz,r``#,)``/,)``%,)``4,)``q_SAT,)``MMMMxxxxmm3,3r`"
,
(st8*)"MASM`/``q_SAT``%``4` `3``$,(``MMMMxxxxmm,r``$,)`, `#,(``ZZZzzzz,r``#,)`, `aaaaa,ACx`"
,
(st8 *)0x1AE,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"MPY`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MPY`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(st8 *)0x1AF,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"MAC`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MPY`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(st8 *)0x1B0,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` + `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
(st8*)"MPY`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(st8 *)0x1B1,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"MAS`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MPY`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(st8 *)0x1B2,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` - `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
(st8*)"MPY`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAS`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(st8 *)0x1B3,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` + `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
(st8*)"MAC`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(st8 *)0x1B4,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` + `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
(st8*)"MAS`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(st8 *)0x1B5,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` - `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
(st8*)"MAC`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAS`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(st8 *)0x1B6,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(`(`aaaaa,ACx` >> #16) + `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` + `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
(st8*)"MAC`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` >> #16 :: MAC`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(st8 *)0x1B7,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(`(`bbbbb,ACx` >> #16) + `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
(st8*)"MAS`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx` >> #16"
,
(st8 *)0x1B8,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(`(`bbbbb,ACx` >> #16) + `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
(st8*)"MPY`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx` >> #16"
,
(st8 *)0x1B9,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(`(`aaaaa,ACx` >> #16) + `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(`(`bbbbb,ACx` >> #16) + `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
(st8*)"MAC`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` >> #16 :: MAC`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx` >> #16"
,
(st8 *)0x1BA,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` - `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
(st8*)"MAS`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAS`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(st8 *)0x1BB,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"MPY`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MPY`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(st8 *)0x1BC,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/`(`$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"MAC`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MPY`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(st8 *)0x1BD,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` + `/`(`$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
(st8*)"MPY`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(st8 *)0x1BE,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/`(`$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"MAS`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MPY`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(st8 *)0x1BF,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` - `/`(`$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
(st8*)"MPY`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAS`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(st8 *)0x1C0,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/`(`$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` + `/`(`$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
(st8*)"MAC`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(st8 *)0x1C1,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/`(`$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` + `/`(`$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
(st8*)"MAS`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(st8 *)0x1C2,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/`(`$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` - `/`(`$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
(st8*)"MAC`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAS`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(st8 *)0x1C3,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(`(`aaaaa,ACx` >> #16) + `/`(`$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` + `/`(`$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
(st8*)"MAC`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` >> #16 :: MAC`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(st8 *)0x1C4,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/`(`$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(`(`bbbbb,ACx` >> #16) + `/`(`$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
(st8*)"MAS`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx` >> #16"
,
(st8 *)0x1C5,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(`(`bbbbb,ACx` >> #16) + `/`(`$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
(st8*)"MPY`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx` >> #16"
,
(st8 *)0x1C6,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(`(`aaaaa,ACx` >> #16) + `/`(`$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(`(`bbbbb,ACx` >> #16) + `/`(`$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
(st8*)"MAC`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` >> #16 :: MAC`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx` >> #16"
,
(st8 *)0x1C7,
(st8*)"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/`(`$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` - `/`(`$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
(st8*)"MAS`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAS`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(st8 *)0x1C8,
(st8 *)0x0,
(st8*)"DBLCOEF"
,
(st8*)"DBLCOEF"
,
(st8 *)0x1C9,
(st8*)"OOOOOOOOpp-aaaaakkkkkkkkkkkkkkkkkkkkkkkk"
,
(st8*)"mar(`aaaaa,XDAx` + `kkkkkkkkkkkkkkkkkkkkkkkk`)"
,
(st8*)"AADD `kkkkkkkkkkkkkkkkkkkkkkkk`, `aaaaa,XDAx`"
,
(st8 *)0x1CA,
(st8*)"OOOOOOOOpp-aaaaakkkkkkkkkkkkkkkkkkkkkkkk"
,
(st8*)"mar(`aaaaa,XDAx` = `kkkkkkkkkkkkkkkkkkkkkkkk`)"
,
(st8*)"AMOV `kkkkkkkkkkkkkkkkkkkkkkkk`, `aaaaa,XDAx`"
,
(st8 *)0x1CB,
(st8*)"OOOOOOOOpp-aaaaakkkkkkkkkkkkkkkkkkkkkkkk"
,
(st8*)"mar(`aaaaa,XDAx` - `kkkkkkkkkkkkkkkkkkkkkkkk`)"
,
(st8*)"ASUB `kkkkkkkkkkkkkkkkkkkkkkkk`, `aaaaa,XDAx`"
,
(st8 *)0x1CC,
(st8*)"OOOOOOOOMMMMxxxxmmq--o--"
,
(st8*)"mar(byte(`MMMMxxxxmm,br`))"
,
(st8*)"AMAR byte(`MMMMxxxxmm,br`)"
,
(st8 *)0x1CD,
(st8*)"OOOOOOO$JCCcccccJDDdddddLLLLLLLLLLLLLLLL"
,
(st8*)"compare (`$,(``CCccccc,RAx` `JJ` `DDddddd,RAx``$,)`) goto `LLLLLLLLLLLLLLLL`"
,
(st8*)"BCC`$` `LLLLLLLLLLLLLLLL`, `CCccccc,RAx` `JJ` `DDddddd,RAx`"
,
(st8 *)0x1CE,
(st8*)"OOOOOOqqMMMMxxxxmm$aaaaa"
,
(st8*)"HI(`aaaaa,ACx`) = `q_SAT,(``$,(``MMMMxxxxmm,r``$,)``q_SAT,)`"
,
(st8*)"MOV`q_SAT` `$,(``MMMMxxxxmm,r``$,)`, `aaaaa,ACx`.H"
,
(st8 *)0x1CF,
(st8*)"OOOOOOqqMMMMxxxxmm$aaaaa"
,
(st8*)"LO(`aaaaa,ACx`) = `q_SAT,(``$,(``MMMMxxxxmm,r``$,)``q_SAT,)`"
,
(st8*)"MOV`q_SAT` `$,(``MMMMxxxxmm,r``$,)`, `aaaaa,ACx`.L"
,
(st8 *)0x1D0,
(st8*)"OOOOOpAAMMMMxxxxmmAaaaaa"
,
(st8*)"copy(`AAAaaaaa,ALLx` = `AAAaaaaa,d(ALLx``MMMMxxxxmm,!AAAaaaaa!r``AAAaaaaa,)ALLx`)"
,
(st8*)"COPY `AAAaaaaa,d(ALLx``MMMMxxxxmm,!AAAaaaaa!r``AAAaaaaa,)ALLx`, `AAAaaaaa,ALLx`"
,
(st8 *)0x1D1,
(st8*)"OOOOOOOOAAAaaaaakkkkkkkkkkkkkkkk"
,
(st8*)"`AAAaaaaa,ADRx` = `kkkkkkkkkkkkkkkk`"
,
(st8*)"MOV `kkkkkkkkkkkkkkkk`, `AAAaaaaa,ADRx`"
,
(st8 *)0x1D2,
(st8*)"OOOOOOOpAAAaaaaakkkkkkkkkkkkkkkkkkkkkkkk"
,
(st8*)"copy(`AAAaaaaa,ALLx` = `AAAaaaaa,d(ALLx``kkkkkkkkkkkkkkkkkkkkkkkk,m``AAAaaaaa,)ALLx`)"
,
(st8*)"COPY `AAAaaaaa,d(ALLx``kkkkkkkkkkkkkkkkkkkkkkkk,m``AAAaaaaa,)ALLx`, `AAAaaaaa,ALLx`"
,
(st8 *)0x1D3,
(st8*)"OOOOOOOOMMMMxxxxmm-aaaaapp$---AA"
,
(st8*)"`AAaaaaa,RA` = `$,(`byte(`MMMMxxxxmm,br`)`$,)`"
,
(st8*)"MOV `$,(`byte(`MMMMxxxxmm,br`)`$,)`, `AAaaaaa,RA`"
,
(st8 *)0x1D4,
(st8 *)0x0,
(st8*)"MV_COPR"
,
(st8*)"MV_COPR"
,
(st8 *)0x1D5,
(st8*)"OOOOOOOop00aaaaapCCccccc"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``CCccccc,RLHx` << #16`q_SAT,)`"
,
(st8*)"MOV`q_SAT` `CCccccc,RLHx` << #16, `aaaaa,ACx`"
,
(st8 *)0x1D6,
(st8*)"OOOOOOOOMMMMxxxxmmq-po---YYYyyyy"
,
(st8*)"byte(`MMMMxxxxmm,bw`) = byte(`YYYyyyy,r`)"
,
(st8*)"MOV byte(`YYYyyyy,r`), byte(`MMMMxxxxmm,bw`)"
,
(st8 *)0x1D7,
(st8*)"OOOOOOOOMMMMxxxxmmq-po---YYYyyyy"
,
(st8*)"byte(`YYYyyyy,w`) = byte(`MMMMxxxxmm,br`)"
,
(st8*)"MOV byte(`MMMMxxxxmm,br`), byte(`YYYyyyy,w`)"
,
(st8 *)0x1D8,
(st8*)"OOOOOOOOpCCcccccpkkkkkkko-$-JJ-T"
,
(st8*)"`T` = `$`(`CCccccc,Rx` `JJ` `kkkkkkk`)"
,
(st8*)"CMP`$` `CCccccc,Rx` `JJ` `kkkkkkk`, `T`"
,
(st8 *)0x1D9,
(st8*)"OOOOOOOOpXXXxxxxp1Aaaaaa-YYYyyyy"
,
(st8*)"`Aaaaaa,ACLHx` = `q_SAT,(``XXXxxxx,r` + `YYYyyyy,r``q_SAT,)`"
,
(st8*)"ADD`q_SAT` `XXXxxxx,r`, `YYYyyyy,r`, `Aaaaaa,ACLHx`"
,
(st8 *)0x1DA,
(st8*)"OOOOOOOOpXXXxxxxp1Aaaaaa-YYYyyyy"
,
(st8*)"`Aaaaaa,ACLHx` = `q_SAT,(``XXXxxxx,r` - `YYYyyyy,r``q_SAT,)`"
,
(st8*)"SUB`q_SAT` `XXXxxxx,r`, `YYYyyyy,r`, `Aaaaaa,ACLHx`"
,
(st8 *)0x1DB,
(st8*)"OOOOOOOOppqq----"
,
(st8*)"return || far()"
,
(st8*)"FRET"
,
(st8 *)0x1DC,
(st8*)"OOOOOOpp"
,
(st8*)"SAT"
,
(st8*)"SAT"
,
(st8 *)0x1DD,
(st8*)"OOOOOpCCMMMMxxxxmmCccccc"
,
(st8*)"`CCCccccc,d(ALLx``MMMMxxxxmm,!CCCccccc!w``CCCccccc,)ALLx` = `CCCccccc,ALLx`"
,
(st8*)"MOV `CCCccccc,ALLx`, `CCCccccc,d(ALLx``MMMMxxxxmm,!CCCccccc!w``CCCccccc,)ALLx`"
,
(st8 *)0x1DE,
(st8*)"OOOOOOOpCCCccccckkkkkkkkkkkkkkkkkkkkkkkk"
,
(st8*)"`CCCccccc,d(ALLx``kkkkkkkkkkkkkkkkkkkkkkkk,m``CCCccccc,)ALLx` = `CCCccccc,ALLx`"
,
(st8*)"MOV `CCCccccc,ALLx`, `CCCccccc,d(ALLx``kkkkkkkkkkkkkkkkkkkkkkkk,m``CCCccccc,)ALLx`"
,
(st8 *)0x1DF,
(st8*)"OOOOOoiiMMMMxxxxmmiiiiii"
,
(st8*)"byte(`MMMMxxxxmm,bw`) = `iiiiiiii`"
,
(st8*)"MOV `iiiiiiii`, byte(`MMMMxxxxmm,bw`)"
,
(st8 *)0x1E0,
(st8*)"OOOOOOOOMMMMxxxxmm-cccccpp----CC"
,
(st8*)"byte(`MMMMxxxxmm,bw`) = `CCccccc,RA`"
,
(st8*)"MOV `CCccccc,RA`, byte(`MMMMxxxxmm,bw`)"
,
(st8 *)0x1E1,
(st8*)"OOOOOOpp"
,
(st8*)"if (!TC1) execute(D_unit) ||"
,
(st8*)"XCCPART !TC1 ||"
,
(st8 *)0x1E2,
(st8*)"OOOOOOpp"
,
(st8*)"if (TC1) execute(D_unit) ||"
,
(st8*)"XCCPART TC1 ||"
,
(st8 *)0x1E3,
(st8*)"OOOOOOpp"
,
(st8*)"XPORT_READ"
,
(st8*)"XPORT_READ"
,
(st8 *)0x1E4,
(st8*)"OOOOOOpp"
,
(st8*)"XPORT_WRITE"
,
(st8*)"XPORT_WRITE"
,
(st8 *)0x1E5,
(st8*)"OOOOOOOOppqq----"
,
(st8*)"to_word()"
,
(st8*)"to_word"
,
(st8 *)0x1E6,
(st8*)"OOOOOOOOppqq----"
,
(st8*)"to_byte()"
,
(st8*)"to_byte"
,
(st8 *)0x1E7,
(st8*)"OOOOOOOOkkkkkkkk"
,
(st8*)"ecopr(`kkkkkkkk`)"
,
(st8*)"ECOPR__"
,
(st8 *)0x1E8,
(st8*)"OOOOOOOOp-------p0-000cc0-------qq-000aa0-------kkkkkkkk"
,
(st8*)"`aa,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `cc,ACx`, `aa,ACx`)"
,
(st8*)"COPR_1`q_SAT` `kkkkkkkk`, `cc,ACx`, `aa,ACx`"
,
(st8 *)0x1E9,
(st8*)"OOOOOOOOp-------p0-000aa0-------qq-000bb0-------kkkkkkkk"
,
(st8*)"`aa,ACx`, `bb,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `aa,ACx`, `bb,ACx`)"
,
(st8*)"COPR_2`q_SAT` `kkkkkkkk`, `aa,ACx`, `bb,ACx`"
,
(st8 *)0x1EA,
(st8*)"OOOOOOOOMMMMxxxxmm-000ccpp-000aaqq------0-------kkkkkkkk"
,
(st8*)"`aa,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `cc,ACx`, `MMMMxxxxmm,r`)"
,
(st8*)"COPR_M`q_SAT` `kkkkkkkk`, `cc,ACx`, `MMMMxxxxmm,r`, `aa,ACx`"
,
(st8 *)0x1EB,
(st8*)"OOOOOOOOMMMMxxxxmm1000aapp-000bbqq------1ZZZzzzzkkkkkkkk"
,
(st8*)"`aa,ACx`, `bb,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `MMMMxxxxmm,r`, dbl(`ZZZzzzz,r`))"
,
(st8*)"COPR_MZ`q_SAT` `kkkkkkkk`, `MMMMxxxxmm,r`, dbl(`ZZZzzzz,r`), `aa,ACx`, `bb,ACx`"
,
(st8 *)0x1EC,
(st8*)"OOOOOOOOMMMMxxxxmm-000ccpp-000aaqq------0-------kkkkkkkk"
,
(st8*)"`aa,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `cc,ACx`, dbl(`MMMMxxxxmm,dr`))"
,
(st8*)"COPR_LM`q_SAT` `kkkkkkkk`, `cc,ACx`, dbl(`MMMMxxxxmm,dr`), `aa,ACx`"
,
(st8 *)0x1ED,
(st8*)"OOOOOOOOMMMMxxxxmm1000aapp-000bbqq------1ZZZzzzzkkkkkkkk"
,
(st8*)"`aa,ACx`, `bb,ACx` = copr`q_SAT,a`(`kkkkkkkk`, dbl(`MMMMxxxxmm,dr`), dbl(`ZZZzzzz,r`))"
,
(st8*)"COPR_LMZ1`q_SAT` `kkkkkkkk`, dbl(`MMMMxxxxmm,dr`), dbl(`ZZZzzzz,r`), `aa,ACx`, `bb,ACx`"
,
(st8 *)0x1EE,
(st8*)"OOOOOOOOMMMMxxxxmm1000aapp-000bbqq------1ZZZzzzzkkkkkkkk"
,
(st8*)"`aa,ACx`, `bb,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `aa,ACx`, `bb,ACx`, dbl(`MMMMxxxxmm,r`), dbl(`ZZZzzzz,dr`))"
,
(st8*)"COPR_LMZ2`q_SAT` `kkkkkkkk`, `aa,ACx`, `bb,ACx`, dbl(`MMMMxxxxmm,dr`), dbl(`ZZZzzzz,r`), `aa,ACx`, `bb,ACx`"
,
(st8 *)0x1EF,
(st8*)"OOOOOOOOpXXXxxxxp1-000cc1YYYyyyyqq-000aa0-------kkkkkkkk"
,
(st8*)"`aa,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `cc,ACx`, `XXXxxxx,r`, `YYYyyyy,r`)"
,
(st8*)"COPR_XY1`q_SAT` `kkkkkkkk`, `cc,ACx`, `XXXxxxx,r`, `YYYyyyy,r`, `aa,ACx`"
,
(st8 *)0x1F0,
(st8*)"OOOOOOOOpXXXxxxxp1-000aa1YYYyyyyqq-000bb0-------kkkkkkkk"
,
(st8*)"`aa,ACx`, `bb,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `aa,ACx`, `bb,ACx`, `XXXxxxx,r`, `YYYyyyy,r`)"
,
(st8*)"COPR_XY2`q_SAT` `kkkkkkkk`, `aa,ACx`, `bb,ACx`, `XXXxxxx,r`, `YYYyyyy,r`, `aa,ACx`, `bb,ACx`"
,
(st8 *)0x1F1,
(st8*)"OOOOOOOOpXXXxxxxp10000aa1YYYyyyyqq-000bb1ZZZzzzzkkkkkkkk"
,
(st8*)"`aa,ACx`, `bb,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`)"
,
(st8*)"COPR_XYZ1`q_SAT` `kkkkkkkk`, `XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`, `aa,ACx`, `bb,ACx`"
,
(st8 *)0x1F2,
(st8*)"OOOOOOOOpXXXxxxxp10000aa1YYYyyyyqq-000bb1ZZZzzzzkkkkkkkk"
,
(st8*)"`aa,ACx`, `bb,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `aa,ACx`, `XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`)"
,
(st8*)"COPR_XYZ2`q_SAT` `kkkkkkkk`, `aa,ACx`, `XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`, `aa,ACx`, `bb,ACx`"
,
(st8 *)0x1F3,
(st8*)"OOOOOOOOpXXXxxxxp10000aa1YYYyyyyqq-000bb1ZZZzzzzkkkkkkkk"
,
(st8*)"`aa,ACx`, `bb,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `bb,ACx`, `XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`)"
,
(st8*)"COPR_XYZ3`q_SAT` `kkkkkkkk`, `bb,ACx`, `XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`, `aa,ACx`, `bb,ACx`"
,
(st8 *)0x1F4,
(st8*)"OOOOOOOOpXXXxxxxp10000aa1YYYyyyyqq-000bb1ZZZzzzzkkkkkkkk"
,
(st8*)"`aa,ACx`, `bb,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `aa,ACx`, `bb,ACx`, `XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`)"
,
(st8*)"COPR_XYZ4`q_SAT` `kkkkkkkk`, `aa,ACx`, `bb,ACx`, `XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`, `aa,ACx`, `bb,ACx`"
,
(st8 *)0x1F5,
(st8*)"OOOOOOOOpXXXxxxxp10000aa1YYYyyyyqq-000001ZZZzzzzkkkkkkkk"
,
(st8*)"`aa,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `YYYyyyy,r`, `ZZZzzzz,r`), mar(`XXXxxxx,r`)"
,
(st8*)"COPR_MARXYZ1`q_SAT` `kkkkkkkk`, `YYYyyyy,r`, `ZZZzzzz,r`, `aa,ACx` :: AMAR `XXXxxxx,r`"
,
(st8 *)0x1F6,
(st8*)"OOOOOOOOpXXXxxxxp10000aa1YYYyyyyqq-000001ZZZzzzzkkkkkkkk"
,
(st8*)"`aa,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `aa,ACx`, `YYYyyyy,r`, `ZZZzzzz,r`), mar(`XXXxxxx,r`)"
,
(st8*)"COPR_MARXYZ2`q_SAT` `kkkkkkkk`, `aa,ACx`, `YYYyyyy,r`, `ZZZzzzz,r`, `aa,ACx` :: AMAR `XXXxxxx,r`"
,
(st8 *)0x1F7,
(st8*)"OOOOOOOOMMMMxxxxmmAaaaaa-pCcccccqqDddddd"
,
(st8*)"`Aaaaaa,ACLHx` = field_extract_r(`Cccccc,ACLHx`, `Dddddd,ACLHx`, `MMMMxxxxmm,baddr`)"
,
(st8*)"BFXTR `Cccccc,ACLHx`, `Dddddd,ACLHx`, `MMMMxxxxmm,baddr`, `Aaaaaa,ACLHx`"
,
(st8 *)0x1F8,
(st8*)"OOOOOOOOMMMMxxxxmmAaaaaa-pCcccccqqDddddd"
,
(st8*)"`Aaaaaa,ACLHx` = field_extract_l(`Cccccc,ACLHx`, `Dddddd,ACLHx`, `MMMMxxxxmm,baddr`)"
,
(st8*)"BFXTL `Cccccc,ACLHx`, `Dddddd,ACLHx`, `MMMMxxxxmm,baddr`, `Aaaaaa,ACLHx`"
,
(st8 *)0x1F9,
(st8*)"OOOOOOOOMMMMxxxxmm-aaaaa-p-cccccqq-ddddd"
,
(st8*)"`aaaaa,ACx` = field_extract_r(`ccccc,ACx`, `ddddd,ACx`, `MMMMxxxxmm,baddr`)"
,
(st8*)"DBFXTR `ccccc,ACx`, `ddddd,ACx`, `MMMMxxxxmm,baddr`, `aaaaa,ACx`"
,
(st8 *)0x1FA,
(st8*)"OOOOOOOOMMMMxxxxmm-aaaaa-p-cccccqq-ddddd"
,
(st8*)"`aaaaa,ACx` = field_extract_l(`ccccc,ACx`, `ddddd,ACx`, `MMMMxxxxmm,baddr`)"
,
(st8*)"DBFXTL `ccccc,ACx`, `ddddd,ACx`, `MMMMxxxxmm,baddr`, `aaaaa,ACx`"
,
(st8 *)0x1FB,
(st8*)"OOOOOOOOMMMMxxxxmmAaaaaa-pCcccccqqDddddd"
,
(st8*)"`Aaaaaa,ACLHx` = field_insert(`Cccccc,ACLHx`, `Dddddd,ACLHx`, `MMMMxxxxmm,baddr`)"
,
(st8*)"BFINS `Cccccc,ACLHx`, `Dddddd,ACLHx`, `MMMMxxxxmm,baddr`, `Aaaaaa,ACLHx`"
,
(st8 *)0x1FC,
(st8*)"OOOOOOOWp-%aaaaap--bbbbb--$cccccqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(`LO(`ccccc,ACx`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(`HI(`ccccc,ACx`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"MPY`/``q_SAT``%``4` `$,(`LO(`ccccc,ACx`)`$,)`, `#,(`LO(`ZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MPY`/``q_SAT``%``4` `$,(`HI(`ccccc,ACx`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(st8 *)0x1FD,
(st8*)"OOOOOOOWp-%aaaaap--bbbbb--$cccccqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/,(``$,(`LO(`ccccc,ACx`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` +`/,(``$,(`HI(`ccccc,ACx`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"MAC`/``q_SAT``%``4` `$,(`LO(`ccccc,ACx`)`$,)`, `#,(`LO(`ZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(`HI(`ccccc,ACx`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(st8 *)0x1FE,
(st8*)"OOOOOOOWp-%aaaaap--bbbbb--$cccccqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/,(``$,(`LO(`ccccc,ACx`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` -`/,(``$,(`HI(`ccccc,ACx`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"MAC`/``q_SAT``%``4` `$,(`LO(`ccccc,ACx`)`$,)`, `#,(`LO(`ZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAS`/``q_SAT``%``4` `$,(`HI(`ccccc,ACx`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(st8 *)0x1FF,
(st8*)"OOOOOOOWp-%aaaaap--bbbbb--$cccccqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/,(``$,(`LO(`ccccc,ACx`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` +`/,(``$,(`HI(`ccccc,ACx`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"MAS`/``q_SAT``%``4` `$,(`LO(`ccccc,ACx`)`$,)`, `#,(`LO(`ZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(`HI(`ccccc,ACx`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(st8 *)0x200,
(st8*)"OOOOOOOWp-%aaaaap--bbbbb--$cccccqq#4----/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/,(``$,(`LO(`ccccc,ACx`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` -`/,(``$,(`HI(`ccccc,ACx`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"MAS`/``q_SAT``%``4` `$,(`LO(`ccccc,ACx`)`$,)`, `#,(`LO(`ZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAS`/``q_SAT``%``4` `$,(`HI(`ccccc,ACx`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(st8 *)0x201,
(st8*)"OOOOOOk$JCCcccccJkkkkkkkLLLLLLLLLLLLLLLL"
,
(st8*)"compare (uns(`CCccccc,RAx` `JJ` `kkkkkkkk`)) goto `LLLLLLLLLLLLLLLL`"
,
(st8*)"BCCU `LLLLLLLLLLLLLLLL`, `CCccccc,RAx` `JJ` `kkkkkkkk`"
,
(st8 *)0x202,
(st8 *)0x0,
(st8*)"DLD_R_ABS"
,
(st8*)"DLD_R_ABS"
,
(st8 *)0x203,
(st8 *)0x0,
(st8*)"DST_R_ABS"
,
(st8*)"DST_R_ABS"
,
(st8 *)0x204,
(st8 *)0x0,
(st8*)"SUB_MWK"
,
(st8*)"SUB_MWK"
,
(st8 *)0x205,
(st8 *)0x0,
(st8*)"DPSHR_SPW"
,
(st8*)"DPSHR_SPW"
,
(st8 *)0x206,
(st8 *)0x0,
(st8*)"DPOPR_SPR"
,
(st8*)"DPOPR_SPR"
,
(st8 *)0x207,
(st8 *)0x0,
(st8*)"DST_R"
,
(st8*)"DST_R"
,
(st8 *)0x208,
(st8 *)0x0,
(st8*)"DLD_R"
,
(st8*)"DLD_R"
,
(st8 *)0x209,
(st8*)"OOOOOOOOMMMMxxxxmmoaaaaa"
,
(st8*)"`aaaaa,XDAx` = mar(byte(`MMMMxxxxmm,r`))"
,
(st8*)"AMAR byte(`MMMMxxxxmm,r`), `aaaaa,XDAx`"
,
(st8 *)0x20A,
(st8*)"OOOOOOOOMMMMxxxxmmqppo--KKKKKKKKKKKKKKKK"
,
(st8*)"dbl(`MMMMxxxxmm,rw`) = `q_SAT,(`dbl(`MMMMxxxxmm,rw`) + `KKKKKKKKKKKKKKKK``q_SAT,)`"
,
(st8*)"ADD`q_SAT` `KKKKKKKKKKKKKKKK`, dbl(`MMMMxxxxmm,rw`)"
,
(st8 *)0x20B,
(st8*)"OOOOOOOOMMMMxxxxmmqppo--iiiiiiiiiiiiiiii"
,
(st8*)"dbl(`MMMMxxxxmm,w`) = `iiiiiiiiiiiiiiii`"
,
(st8*)"MOV `iiiiiiiiiiiiiiii`, dbl(`MMMMxxxxmm,w`)"
,
(st8 *)0x20C,
(st8*)"OOOOOOOOMMMMxxxxmmqppo--kkkkkkkkkkkkkkkk"
,
(st8*)"dbl(`MMMMxxxxmm,rw`) = dbl(`MMMMxxxxmm,rw`) & `kkkkkkkkkkkkkkkk`"
,
(st8*)"AND `kkkkkkkkkkkkkkkk`, dbl(`MMMMxxxxmm,rw`)"
,
(st8 *)0x20D,
(st8*)"OOOOOOOOMMMMxxxxmmqppo--kkkkkkkkkkkkkkkk"
,
(st8*)"dbl(`MMMMxxxxmm,rw`) = dbl(`MMMMxxxxmm,rw`) | `kkkkkkkkkkkkkkkk`"
,
(st8*)"OR `kkkkkkkkkkkkkkkk`, dbl(`MMMMxxxxmm,rw`)"
,
(st8 *)0x20E,
(st8*)"OOOOOOOOMMMMxxxxmmqppo--kkkkkkkkkkkkkkkk"
,
(st8*)"dbl(`MMMMxxxxmm,rw`) = dbl(`MMMMxxxxmm,rw`) ^ `kkkkkkkkkkkkkkkk`"
,
(st8*)"XOR `kkkkkkkkkkkkkkkk`, dbl(`MMMMxxxxmm,rw`)"
,
(st8 *)0x20F,
(st8*)"OOOOOOOOMMMMxxxxmm$aaaaapp-cccccqqSSSSSS"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` + (`$,(`dbl(`MMMMxxxxmm,r`)`$,)` << `SSSSSS`)`q_SAT,)`"
,
(st8*)"ADD`q_SAT` `$,(`dbl(`MMMMxxxxmm,r`)`$,)` << `SSSSSS`, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x210,
(st8*)"OOOOOOOOMMMMxxxxmm$aaaaapp-cccccqqSSSSSS"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` - (`$,(`dbl(`MMMMxxxxmm,r`)`$,)` << `SSSSSS`)`q_SAT,)`"
,
(st8*)"SUB`q_SAT` `$,(`dbl(`MMMMxxxxmm,r`)`$,)` << `SSSSSS`, `ccccc,ACx`, `aaaaa,ACx`"
,
(st8 *)0x211,
(st8*)"OOOOOOOOMMMMxxxxmm$aaaaapp------qqSSSSSS"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``$,(`dbl(`MMMMxxxxmm,r`)`$,)` << `SSSSSS``q_SAT,)`"
,
(st8*)"MOV`q_SAT` `$,(`dbl(`MMMMxxxxmm,r`)`$,)` << `SSSSSS`, `aaaaa,ACx`"
,
(st8 *)0x212,
(st8*)"OOOOOOOOMMMMxxxxmm%ccccc@p$----q-NNnnnnn"
,
(st8*)"dbl(`MMMMxxxxmm,w`) = `@,(``$,(``%,(``ccccc,ACx` << `NNnnnnn,SRx``%,)``$,)``@,)`"
,
(st8*)"MOV `$,(``%,(``@,(``ccccc,ACx` << `NNnnnnn,SRx``@,)``%,)``$,)`), dbl(`MMMMxxxxmm,w`"
,
(st8 *)0x213,
(st8*)"OOOOOOOOMMMMxxxxmm%ccccc@p$----q--SSSSSS"
,
(st8*)"dbl(`MMMMxxxxmm,w`) = `@,(``$,(``%,(``ccccc,ACx` << `SSSSSS``%,)``$,)``@,)`"
,
(st8*)"MOV `$,(``%,(``@,(``ccccc,ACx` << `SSSSSS``@,)``%,)``$,)`), dbl(`MMMMxxxxmm,w`"
,
(st8 *)0x214,
(st8*)"OOOOOOOOMMMMxxxxmmT-poJJKKKKKKKKKKKKKKKK"
,
(st8*)"`T` = (dbl(`MMMMxxxxmm,r`) `JJ` `KKKKKKKKKKKKKKKK`)"
,
(st8*)"CMP dbl(`MMMMxxxxmm,r`) `JJ` `KKKKKKKKKKKKKKKK`, `T`"
,
(st8 *)0x215,
(st8*)"OOOOOOOOMMMMxxxxmmTppo-----kkkkk"
,
(st8*)"`T` = bit(dbl(`MMMMxxxxmm,rw`), `kkkkk`), bit(dbl(`MMMMxxxxmm,rw`), `kkkkk`) = #0"
,
(st8*)"BTSTCLR `kkkkk`, dbl(`MMMMxxxxmm,rw`), `T`"
,
(st8 *)0x216,
(st8*)"OOOOOOOOMMMMxxxxmmTppo-----kkkkk"
,
(st8*)"`T` = bit(dbl(`MMMMxxxxmm,rw`), `kkkkk`), bit(dbl(`MMMMxxxxmm,rw`), `kkkkk`) = #1"
,
(st8*)"BTSTSET `kkkkk`, dbl(`MMMMxxxxmm,rw`), `T`"
,
(st8 *)0x217,
(st8*)"OOOOOOOOMMMMxxxxmmTppo-----kkkkk"
,
(st8*)"`T` = bit(dbl(`MMMMxxxxmm,r`), `kkkkk`)"
,
(st8*)"BTST `kkkkk`, dbl(`MMMMxxxxmm,r`), `T`"
,
(st8 *)0x218,
(st8*)"OOOOOOOOMMMMxxxxmmTppo-----kkkkk"
,
(st8*)"`T` = bit(dbl(`MMMMxxxxmm,rw`), `kkkkk`), cbit(dbl(`MMMMxxxxmm,rw`), `kkkkk`)"
,
(st8*)"BTSTNOT `kkkkk`, dbl(`MMMMxxxxmm,rw`), `T`"
,
(st8 *)0x219,
(st8*)"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` + `/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"MPY`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx`"
,
(st8 *)0x21A,
(st8*)"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` - `/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"MPY`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` :: MAS`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx`"
,
(st8 *)0x21B,
(st8*)"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
(st8*)"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` - `/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
(st8*)"MAC`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` :: MAS`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx`"
,
(st8 *)0x21C,
(st8*)"OOOOOOOOppppqqqq"
,
(st8*)"debug_data()"
,
(st8*)"debug_data"
,
(st8 *)0x21D,
(st8*)"OOOOOOOOppppqqqq"
,
(st8*)"debug_prog()"
,
(st8*)"debug_prog"
,
(st8 *)0x223,
(st8 *)0x0,
(st8*)"NO_OF_INSTR"
,
(st8*)"NO_OF_INSTR"
,
(st8 *)0x224,
(st8 *)0x0,
(st8*)"FIELDMASK"
,
(st8*)"FIELDMASK"
,
(st8 *)0x225,
(st8 *)0x0,
(st8*)"REPEAT_LOCAL_END"
,
(st8*)"REPEAT_LOCAL_END"
,
(st8 *)0x226,
(st8 *)0x0,
(st8*)"REPEAT_BLOCK_END"
,
(st8*)"REPEAT_BLOCK_END"
,
(st8 *)0x227,
(st8 *)0x0,
(st8*)"REPEAT_STMT_END"
,
(st8*)"REPEAT_STMT_END"
,
(st8 *)0x228,
(st8 *)0x0,
(st8*)"PARALLEL"
,
(st8*)"PARALLEL"
,
(st8 *)0x22E,
(st8 *)0x0,
(st8*)"FILLER"
,
(st8*)"FILLER"
,
(st8 *)0x22F,
(st8 *)0x0,
(st8*)"ILLOP"
,
(st8*)"ILLOP"
,
(st8 *)0x230,
(st8 *)0x0,
(st8*)"MAX_INSTR_COUNT"
,
(st8*)"MAX_INSTR_COUNT"
,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8 *)0x0,
(st8*)"@(#) $Id: dasm_header,v 1.51 2007/01/31 21:42:44 brett Exp $"
,
(st8*)"@(#) $Id: tbl_encoding,v 1.9 2007/01/31 21:42:44 brett Exp $"
,
(st8*)"@(#) $Id: tbl_lengths,v 1.7 2007/01/31 21:42:44 brett Exp $"
,
(st8*)"@(#) $Id: tbl_opcodes,v 1.10 2007/01/31 21:42:44 brett Exp $"
,
(st8*)"@(#) $Id: dasm_vars,v 1.3 2004/09/24 19:48:27 brett Exp $"

};
