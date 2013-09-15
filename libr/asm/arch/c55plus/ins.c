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
(char *)0x0,
"OOOOOOppHHHhhhhhkkkkkkkk"
,
"while (`HHHhhhhh` && (RPTC < `kkkkkkkk`)) repeat"
,
"RPTCC `kkkkkkkk`, `HHHhhhhh`"
,
(char *)0x1,
"OOOOOOOOHHHhhhhh"
,
"if (`HHHhhhhh`) return"
,
"RETCC `HHHhhhhh`"
,
(char *)0x2,
"OOOOOOOpLLLLLLLLHHHhhhhh"
,
"if (`HHHhhhhh`) goto `LLLLLLLL`"
,
"BCC `LLLLLLLL`, `HHHhhhhh`"
,
(char *)0x3,
"OOOOOOOpLLLLLLLLLLLLLLLL"
,
"`q_SAT,n`goto `LLLLLLLLLLLLLLLL`"
,
"`q_SAT,N`B `LLLLLLLLLLLLLLLL`"
,
(char *)0x4,
"OOOOOOOpLLLLLLLLLLLLLLLL"
,
"call `LLLLLLLLLLLLLLLL`"
,
"CALL `LLLLLLLLLLLLLLLL`"
,
(char *)0x5,
(char *)0x0,
"RPTL_P_64"
,
"RPTL_P_64"
,
(char *)0x6,
"OOOOOOppkkkkkkkkkkkkkkkk"
,
"repeat(`kkkkkkkkkkkkkkkk`)"
,
"RPT `kkkkkkkkkkkkkkkk`"
,
(char *)0x7,
"OOOOOOppllllllllllllllll"
,
"blockrepeat { `llllllllllllllll,i`"
,
"RPTB `llllllllllllllll`"
,
(char *)0x8,
"OOOOOOOOpAAaaaaapCCccccco-SSSSSS"
,
"`AAaaaaa,WACx` = `AAaaaaa,WACx` & (`CCccccc,WACx` <<< `SSSSSS`)"
,
"AND `CCccccc,WACx` << `SSSSSS`, `AAaaaaa,WACx`"
,
(char *)0x9,
"OOOOOOOOpAAaaaaapCCccccco-SSSSSS"
,
"`AAaaaaa,WACx` = `AAaaaaa,WACx` | (`CCccccc,WACx` <<< `SSSSSS`)"
,
"OR `CCccccc,WACx` << `SSSSSS`, `AAaaaaa,WACx`"
,
(char *)0xA,
"OOOOOOOOpAAaaaaapCCccccco-SSSSSS"
,
"`AAaaaaa,WACx` = `AAaaaaa,WACx` ^ (`CCccccc,WACx` <<< `SSSSSS`)"
,
"XOR `CCccccc,WACx` << `SSSSSS`, `AAaaaaa,WACx`"
,
(char *)0xB,
"OOOOOOOOpAAaaaaapCCccccco-SSSSSS"
,
"`AAaaaaa,WACx` = `q_SAT,(``AAaaaaa,WACx` + (`CCccccc,WACx` << `SSSSSS`)`q_SAT,)`"
,
"ADD`q_SAT` `CCccccc,WACx` << `SSSSSS`, `AAaaaaa,WACx`"
,
(char *)0xC,
"OOOOOOOOpAAaaaaapCCccccco-SSSSSS"
,
"`AAaaaaa,WACx` = `q_SAT,(``AAaaaaa,WACx` - (`CCccccc,WACx` << `SSSSSS`)`q_SAT,)`"
,
"SUB`q_SAT` `CCccccc,WACx` << `SSSSSS`, `AAaaaaa,WACx`"
,
(char *)0xD,
"OOOOOOOOpAAaaaaapCCccccco-SSSSSS"
,
"`AAaaaaa,WACx` = `q_SAT,(``CCccccc,WACx` << `SSSSSS``q_SAT,)`"
,
"SFTS`q_SAT` `CCccccc,WACx`, `SSSSSS`, `AAaaaaa,WACx`"
,
(char *)0xE,
"OOOOOOOOpAAaaaaapCCccccco-SSSSSS"
,
"`AAaaaaa,WACx` = `q_SAT,(``CCccccc,WACx` <<C `SSSSSS``q_SAT,)`"
,
"SFTSC`q_SAT` `CCccccc,WACx`, `SSSSSS`, `AAaaaaa,WACx`"
,
(char *)0xF,
"OOOOOOOOpAAaaaaapCCccccco-SSSSSS"
,
"`AAaaaaa,WACx` = `CCccccc,WACx` <<< `SSSSSS`"
,
"SFTL `CCccccc,WACx`, `SSSSSS`, `AAaaaaa,WACx`"
,
(char *)0x10,
"OOOOOOOOpAAaaaaap----------ccccc"
,
"`AAaaaaa,RLHx` = exp(`ccccc,ACx`)"
,
"EXP `ccccc,ACx`, `AAaaaaa,RLHx`"
,
(char *)0x11,
"OOOOOOOOpAAaaaaap--bbbbb---ccccc"
,
"`bbbbb,ACx` = mant(`ccccc,ACx`), `AAaaaaa,RLHx` = exp(`ccccc,ACx`)"
,
"MANT `ccccc,ACx`, `bbbbb,ACx` :: NEXP `ccccc,ACx`, `AAaaaaa,RLHx`"
,
(char *)0x12,
"OOOOOOOOpAAaaaaap-Tccccc---ddddd"
,
"`AAaaaaa,RLHx` = count(`ccccc,ACx`, `ddddd,ACx`, `T`)"
,
"BCNT `ccccc,ACx`, `ddddd,ACx`, `T`, `AAaaaaa,RLHx`"
,
(char *)0x13,
"OOOOOOOOp--aaaaap--bbbbb---cccccrrrddddd"
,
"max_diff`q_SAT,a`(`ccccc,ACx`, `ddddd,ACx`, `aaaaa,ACx`, `bbbbb,ACx`, pair(`rrr`))"
,
"MAXDIFF`q_SAT` `ccccc,ACx`, `ddddd,ACx`, `aaaaa,ACx`, `bbbbb,ACx`, pair(`rrr`)"
,
(char *)0x14,
"OOOOOOOOp--aaaaap--bbbbb---cccccrrrddddd"
,
"max_diff_dbl`q_SAT,a`(`ccccc,ACx`, `ddddd,ACx`, `aaaaa,ACx`, `bbbbb,ACx`, `rrr`)"
,
"DMAXDIFF`q_SAT` `ccccc,ACx`, `ddddd,ACx`, `aaaaa,ACx`, `bbbbb,ACx`, `rrr`"
,
(char *)0x15,
"OOOOOOOOp--aaaaap--bbbbb---cccccrrrddddd"
,
"min_diff`q_SAT,a`(`ccccc,ACx`, `ddddd,ACx`, `aaaaa,ACx`, `bbbbb,ACx`, pair(`rrr`))"
,
"MINDIFF`q_SAT` `ccccc,ACx`, `ddddd,ACx`, `aaaaa,ACx`, `bbbbb,ACx`, pair(`rrr`)"
,
(char *)0x16,
"OOOOOOOOp--aaaaap--bbbbb---cccccrrrddddd"
,
"min_diff_dbl`q_SAT,a`(`ccccc,ACx`, `ddddd,ACx`, `aaaaa,ACx`, `bbbbb,ACx`, `rrr`)"
,
"DMINDIFF`q_SAT` `ccccc,ACx`, `ddddd,ACx`, `aaaaa,ACx`, `bbbbb,ACx`, `rrr`"
,
(char *)0x17,
"OOOOOOOOpCCcccccpDDdddddo-$-JJ-T"
,
"`T` = `$`(`CCccccc,Rx` `JJ` `DDddddd,Rx`)"
,
"CMP`$` `CCccccc,Rx` `JJ` `DDddddd,Rx`, `T`"
,
(char *)0x18,
"OOOOOOOOpCCcccccpDDdddddo-$-JJTT"
,
"`TT,2` = `TT,1` & `$`(`CCccccc,Rx` `JJ` `DDddddd,Rx`)"
,
"CMPAND`$` `CCccccc,Rx` `JJ` `DDddddd,Rx`, `TT,1`, `TT,2`"
,
(char *)0x19,
"OOOOOOOOpCCcccccpDDdddddo-$-JJTT"
,
"`TT,2` = !`TT,1` & `$`(`CCccccc,Rx` `JJ` `DDddddd,Rx`)"
,
"CMPAND`$` `CCccccc,Rx` `JJ` `DDddddd,Rx`, !`TT,1`, `TT,2`"
,
(char *)0x1A,
"OOOOOOOOpCCcccccpDDdddddo-$-JJTT"
,
"`TT,2` = `TT,1` | `$`(`CCccccc,Rx` `JJ` `DDddddd,Rx`)"
,
"CMPOR`$` `CCccccc,Rx` `JJ` `DDddddd,Rx`, `TT,1`, `TT,2`"
,
(char *)0x1B,
"OOOOOOOOpCCcccccpDDdddddo-$-JJTT"
,
"`TT,2` = !`TT,1` | `$`(`CCccccc,Rx` `JJ` `DDddddd,Rx`)"
,
"CMPOR`$` `CCccccc,Rx` `JJ` `DDddddd,Rx`, !`TT,1`, `TT,2`"
,
(char *)0x1C,
"OOOOOOOO-AAaaaaapCCccccc------VV"
,
"`AAaaaaa,Rx` = `VV,2` \\ `CCccccc,Rx` \\ `VV,1`"
,
"ROL `VV,2`, `CCccccc,Rx`, `VV,1`, `AAaaaaa,Rx`"
,
(char *)0x1D,
"OOOOOOOO-AAaaaaapCCccccc------VV"
,
"`AAaaaaa,Rx` = `VV,1` // `CCccccc,Rx` // `VV,2`"
,
"ROR `VV,1`, `CCccccc,Rx`, `VV,2`, `AAaaaaa,Rx`"
,
(char *)0x1E,
"OOOOOOOOp-Aaaaaap-Cccccc"
,
"mar(`q_CIRC,(``q_LINR,(``Aaaaaa,WDAx` + `Cccccc,WDAx``q_CIRC,)``q_LINR,)`)"
,
"AADD`q_CIRC``q_LINR` `Cccccc,WDAx`, `Aaaaaa,WDAx`"
,
(char *)0x1F,
"OOOOOOOOp-Aaaaaap-Cccccc"
,
"mar(`q_CIRC,(``q_LINR,(``Aaaaaa,WDAx` = `Cccccc,WDAx``q_CIRC,)``q_LINR,)`)"
,
"AMOV`q_CIRC``q_LINR` `Cccccc,WDAx`, `Aaaaaa,WDAx`"
,
(char *)0x20,
"OOOOOOOOp-Aaaaaap-Cccccc"
,
"mar(`q_CIRC,(``q_LINR,(``Aaaaaa,WDAx` - `Cccccc,WDAx``q_CIRC,)``q_LINR,)`)"
,
"ASUB`q_CIRC``q_LINR` `Cccccc,WDAx`, `Aaaaaa,WDAx`"
,
(char *)0x21,
"OOOOOOOOppAaaaaakkkkkkkkkkkkkkkk"
,
"mar(`q_CIRC,(``q_LINR,(``Aaaaaa,WDAx` + `kkkkkkkkkkkkkkkk``q_CIRC,)``q_LINR,)`)"
,
"AADD`q_CIRC``q_LINR` `kkkkkkkkkkkkkkkk`, `Aaaaaa,WDAx`"
,
(char *)0x22,
(char *)0x0,
"MAR_K_MX"
,
"MAR_K_MX"
,
(char *)0x23,
"OOOOOOOOppAaaaaakkkkkkkkkkkkkkkk"
,
"mar(`q_CIRC,(``q_LINR,(``Aaaaaa,WDAx` - `kkkkkkkkkkkkkkkk``q_CIRC,)``q_LINR,)`)"
,
"ASUB`q_CIRC``q_LINR` `kkkkkkkkkkkkkkkk`, `Aaaaaa,WDAx`"
,
(char *)0x24,
(char *)0x0,
"MAR_DA_AY"
,
"MAR_DA_AY"
,
(char *)0x25,
(char *)0x0,
"MAR_DA_MY"
,
"MAR_DA_MY"
,
(char *)0x26,
(char *)0x0,
"MAR_DA_SY"
,
"MAR_DA_SY"
,
(char *)0x27,
(char *)0x0,
"MAR_K_AY"
,
"MAR_K_AY"
,
(char *)0x28,
(char *)0x0,
"MAR_K_MY"
,
"MAR_K_MY"
,
(char *)0x29,
(char *)0x0,
"MAR_K_SY"
,
"MAR_K_SY"
,
(char *)0x2A,
(char *)0x0,
"LD_RPK_MDP"
,
"LD_RPK_MDP"
,
(char *)0x2B,
(char *)0x0,
"LD_RPK_MDP05"
,
"LD_RPK_MDP05"
,
(char *)0x2C,
(char *)0x0,
"LD_RPK_MDP67"
,
"LD_RPK_MDP67"
,
(char *)0x2D,
(char *)0x0,
"LD_RPK_PDP"
,
"LD_RPK_PDP"
,
(char *)0x2E,
(char *)0x0,
"LD_BK_03"
,
"LD_BK_03"
,
(char *)0x2F,
(char *)0x0,
"LD_BK_47"
,
"LD_BK_47"
,
(char *)0x30,
(char *)0x0,
"LD_BK_C"
,
"LD_BK_C"
,
(char *)0x31,
(char *)0x0,
"LD_BK_CSR"
,
"LD_BK_CSR"
,
(char *)0x32,
(char *)0x0,
"LD_BK_BR0"
,
"LD_BK_BR0"
,
(char *)0x33,
(char *)0x0,
"LD_BK_BR1"
,
"LD_BK_BR1"
,
(char *)0x34,
"OOOOOOOOpp-kkkkk"
,
"sim_trig"
,
"SIM_TRIG"
,
(char *)0x35,
(char *)0x0,
"AND_RBK"
,
"AND_RBK"
,
(char *)0x36,
(char *)0x0,
"OR_RBK"
,
"OR_RBK"
,
(char *)0x37,
(char *)0x0,
"XOR_RBK"
,
"XOR_RBK"
,
(char *)0x38,
"OOOOOOOO-/%aaaaap--------CCcccccKKKKKKKK"
,
"`aaaaa,ACx` = `%,(``/,(``CCccccc,MRx` * `KKKKKKKK``/,)``%,)`"
,
"MPYK`/``q_SAT``%` `KKKKKKKK`, `CCccccc,MRx`, `aaaaa,ACx`"
,
(char *)0x39,
"OOOOOOOO-/%aaaaap--ccccc-DDdddddKKKKKKKK"
,
"`aaaaa,ACx` = `q_SAT,(``%,(``ccccc,ACx` + `/,(``DDddddd,MRx` * `KKKKKKKK``/,)``%,)``q_SAT,)`"
,
"MACK`/``q_SAT``%` `KKKKKKKK`, `DDddddd,MRx`, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x3A,
"OOOOOOpp"
,
"nop"
,
"NOP"
,
(char *)0x3B,
"OOOOOOOopAAaaaaapCCccccc"
,
"`AAaaaaa,RAx` = `q_SAT,(``CCccccc,RAx``q_SAT,)`"
,
"MOV`q_SAT` `CCccccc,RAx`, `AAaaaaa,RAx`"
,
(char *)0x3C,
"OOOOOOOopAAaaaaapCCccccc"
,
"`AAaaaaa,Rx` = `q_SAT,(``AAaaaaa,Rx` + `CCccccc,Rx``q_SAT,)`"
,
"ADD`q_SAT` `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(char *)0x3D,
"OOOOOOOopAAaaaaapCCccccc"
,
"`AAaaaaa,Rx` = `q_SAT,(``AAaaaaa,Rx` - `CCccccc,Rx``q_SAT,)`"
,
"SUB`q_SAT` `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(char *)0x3E,
"OOOOOOOopAAaaaaapCCccccc"
,
"`AAaaaaa,Rx` = `AAaaaaa,Rx` & `CCccccc,Rx`"
,
"AND `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(char *)0x3F,
"OOOOOOOopAAaaaaapCCccccc"
,
"`AAaaaaa,Rx` = `AAaaaaa,Rx` | `CCccccc,Rx`"
,
"OR `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(char *)0x40,
"OOOOOOOopAAaaaaapCCccccc"
,
"`AAaaaaa,Rx` = `AAaaaaa,Rx` ^ `CCccccc,Rx`"
,
"XOR `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(char *)0x41,
"OOOOOOOopAAaaaaapCCccccc"
,
"`AAaaaaa,Rx` = max(`CCccccc,Rx`, `AAaaaaa,Rx`)"
,
"MAX `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(char *)0x42,
"OOOOOOOopAAaaaaapCCccccc"
,
"`AAaaaaa,Rx` = min(`CCccccc,Rx`, `AAaaaaa,Rx`)"
,
"MIN `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(char *)0x43,
"OOOOOOOopAAaaaaapCCccccc"
,
"`AAaaaaa,Rx` = `q_SAT,(`|`CCccccc,Rx`|`q_SAT,)`"
,
"ABS`q_SAT` `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(char *)0x44,
"OOOOOOOopAAaaaaapCCccccc"
,
"`AAaaaaa,Rx` = `q_SAT,(`-`CCccccc,Rx``q_SAT,)`"
,
"NEG`q_SAT` `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(char *)0x45,
"OOOOOOOopAAaaaaapCCccccc"
,
"`AAaaaaa,Rx` = ~`CCccccc,Rx`"
,
"NOT `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(char *)0x46,
"OOOOOOOp-CCccccc-DDddddd"
,
"push(`CCccccc,RLHx`, `DDddddd,RLHx`)"
,
"PSH `CCccccc,RLHx`, `DDddddd,RLHx`"
,
(char *)0x47,
"OOOOOOOp-AAaaaaa-BBbbbbb"
,
"`AAaaaaa,RLHx`, `BBbbbbb,RLHx` = pop()"
,
"POP `AAaaaaa,RLHx`, `BBbbbbb,RLHx`"
,
(char *)0x48,
"OOOOOOOOpAAaaaaap-o-kkkk"
,
"`AAaaaaa,Rx` = `kkkk`"
,
"MOV `kkkk`, `AAaaaaa,Rx`"
,
(char *)0x49,
"OOOOOOOOpAAaaaaap-o-kkkk"
,
"`AAaaaaa,Rx` = `kkkk,-`"
,
"MOV `kkkk,-`, `AAaaaaa,Rx`"
,
(char *)0x4A,
"OOOOOOOOpAAaaaaap-o-kkkk"
,
"`AAaaaaa,Rx` = `q_SAT,(``AAaaaaa,Rx` + `kkkk``q_SAT,)`"
,
"ADD`q_SAT` `kkkk`, `AAaaaaa,Rx`"
,
(char *)0x4B,
"OOOOOOOOpAAaaaaap-o-kkkk"
,
"`AAaaaaa,Rx` = `q_SAT,(``AAaaaaa,Rx` - `kkkk``q_SAT,)`"
,
"SUB`q_SAT` `kkkk`, `AAaaaaa,Rx`"
,
(char *)0x4C,
(char *)0x0,
"MV_AC_R"
,
"MV_AC_R"
,
(char *)0x4D,
"OOOOOOOOpAAaaaaap-o-----"
,
"`AAaaaaa,Rx` = `q_SAT,(``AAaaaaa,Rx` >> #1`q_SAT,)`"
,
"SFTS `AAaaaaa,Rx`, #-1"
,
(char *)0x4E,
"OOOOOOOOpAAaaaaap-o-----"
,
"`AAaaaaa,Rx` = `q_SAT,(``AAaaaaa,Rx` << #1`q_SAT,)`"
,
"SFTS`q_SAT` `AAaaaaa,Rx`, #1"
,
(char *)0x4F,
(char *)0x0,
"MV_SP_R"
,
"MV_SP_R"
,
(char *)0x50,
(char *)0x0,
"MV_SSP_R"
,
"MV_SSP_R"
,
(char *)0x51,
(char *)0x0,
"MV_CDP_R"
,
"MV_CDP_R"
,
(char *)0x52,
(char *)0x0,
"MV_BRC0_R"
,
"MV_BRC0_R"
,
(char *)0x53,
(char *)0x0,
"MV_BRC1_R"
,
"MV_BRC1_R"
,
(char *)0x54,
(char *)0x0,
"MV_RPTC_R"
,
"MV_RPTC_R"
,
(char *)0x55,
"OOOOOOOOppq-kkkk"
,
"bit(ST0, #`kkkk,ST0`) = #0"
,
"BCLR `kkkk,ST0`, ST0_55"
,
(char *)0x56,
"OOOOOOOOppq-kkkk"
,
"bit(ST0, #`kkkk,ST0`) = #1"
,
"BSET `kkkk,ST0`, ST0_55"
,
(char *)0x57,
"OOOOOOOOppq-kkkk"
,
"bit(ST1, #`kkkk,ST1`) = #0"
,
"BCLR `kkkk,ST1`, ST1_55"
,
(char *)0x58,
"OOOOOOOOppq-kkkk"
,
"bit(ST1, #`kkkk,ST1`) = #1"
,
"BSET `kkkk,ST1`, ST1_55"
,
(char *)0x59,
"OOOOOOOOppq-kkkk"
,
"bit(ST2, #`kkkk,ST2`) = #0"
,
"BCLR `kkkk,ST2`, ST2_55"
,
(char *)0x5A,
"OOOOOOOOppq-kkkk"
,
"bit(ST2, #`kkkk,ST2`) = #1"
,
"BSET `kkkk,ST2`, ST2_55"
,
(char *)0x5B,
"OOOOOOOOppq-kkkk"
,
"bit(ST3, #`kkkk,ST3`) = #0"
,
"BCLR `kkkk,ST3`, ST3_55"
,
(char *)0x5C,
"OOOOOOOOppq-kkkk"
,
"bit(ST3, #`kkkk,ST3`) = #1"
,
"BSET `kkkk,ST3`, ST3_55"
,
(char *)0x5D,
(char *)0x0,
"eallow()"
,
"EALLOW__"
,
(char *)0x5E,
(char *)0x0,
"edis()"
,
"EDIS__"
,
(char *)0x5F,
"OOOOOOOOppqq----"
,
"aborti()"
,
"ABORTI__"
,
(char *)0x60,
"OOOOOOOOppqq----"
,
"estop_1()"
,
"ESTOP_INC"
,
(char *)0x61,
"OOOOOOOOpp------"
,
"repeat(CSR) "
,
"RPT CSR"
,
(char *)0x62,
"OOOOOOOOpp-ccccc"
,
"repeat(CSR), CSR += `ccccc,DAx`"
,
"RPTADD CSR, `ccccc,DAx`"
,
(char *)0x63,
"OOOOOOOOpp--kkkk"
,
"repeat(CSR), CSR += `kkkk`"
,
"RPTADD CSR, `kkkk`"
,
(char *)0x64,
"OOOOOOOOpp--kkkk"
,
"repeat(CSR), CSR -= `kkkk`"
,
"RPTSUB CSR, `kkkk`"
,
(char *)0x65,
"OOOOOOpp"
,
"return"
,
"RET"
,
(char *)0x66,
"OOOOOOOOppqq----"
,
"return_int"
,
"RETI"
,
(char *)0x67,
(char *)0x0,
"SWT_P_RPT"
,
"SWT_P_RPT"
,
(char *)0x68,
(char *)0x0,
"BR_P_S"
,
"BR_P_S"
,
(char *)0x69,
"OOOOOOpp--------llllllll"
,
"localrepeat { `llllllll,i`"
,
"RPTBLOCAL `llllllll`"
,
(char *)0x6A,
(char *)0x0,
"RPT_P_BK"
,
"RPT_P_BK"
,
(char *)0x6B,
"OOOOOOOOKKKKKKKK"
,
"SP = SP + `KKKKKKKK`"
,
"AADD `KKKKKKKK`, SP"
,
(char *)0x6C,
"OOOOOOOOpAAaaaaap-o-----"
,
"`AAaaaaa,Rx` = `AAaaaaa,Rx` <<< #1"
,
"SFTL `AAaaaaa,Rx`, #1"
,
(char *)0x6D,
"OOOOOOOOpAAaaaaap-o-----"
,
"`AAaaaaa,Rx` = `AAaaaaa,Rx` >>> #1"
,
"SFTL `AAaaaaa,Rx`, #-1"
,
(char *)0x6E,
"OOOOOOOpAAAaaaaa"
,
"`AAAaaaaa,ALLx` = `AAAaaaaa,d(ALLx`pop()`AAAaaaaa,)ALLx`"
,
"POP `AAAaaaaa,d(ALLx``AAAaaaaa,ALLx``AAAaaaaa,)ALLx`"
,
(char *)0x6F,
(char *)0x0,
"DPOPR_SPR_DB"
,
"DPOPR_SPR_DB"
,
(char *)0x70,
"OOOOOOOOp-Aaaaaa"
,
"`Aaaaaa,XRx` = popboth()"
,
"POPBOTH `Aaaaaa,XRx`"
,
(char *)0x71,
"OOOOOOOOp-Cccccc"
,
"pshboth(`Cccccc,XRx`)"
,
"PSHBOTH `Cccccc,XRx`"
,
(char *)0x72,
"OOOOOOOpCCCccccc"
,
"`CCCccccc,d(ALLx`push(`CCCccccc,ALLx`)`CCCccccc,)ALLx`"
,
"PSH `CCCccccc,d(ALLx``CCCccccc,ALLx``CCCccccc,)ALLx`"
,
(char *)0x73,
(char *)0x0,
"DPSHR_SPW_DB"
,
"DPSHR_SPW_DB"
,
(char *)0x74,
(char *)0x0,
"MV_R_ACH"
,
"MV_R_ACH"
,
(char *)0x75,
(char *)0x0,
"MV_R_SP"
,
"MV_R_SP"
,
(char *)0x76,
(char *)0x0,
"MV_R_SSP"
,
"MV_R_SSP"
,
(char *)0x77,
(char *)0x0,
"MV_R_CDP"
,
"MV_R_CDP"
,
(char *)0x78,
(char *)0x0,
"MV_R_CSR"
,
"MV_R_CSR"
,
(char *)0x79,
(char *)0x0,
"MV_R_BRC1"
,
"MV_R_BRC1"
,
(char *)0x7A,
(char *)0x0,
"MV_R_BRC0"
,
"MV_R_BRC0"
,
(char *)0x7B,
"OOOOOOOOp/%aaaaapCCccccc"
,
"`aaaaa,ACx` = `q_SAT,(``%,(``aaaaa,ACx` + `/,(`|`CCccccc,MAx`|`/,)``%,)``q_SAT,)`"
,
"ADD`/``q_SAT``%`V `CCccccc,MAx`, `aaaaa,ACx`"
,
(char *)0x7C,
(char *)0x0,
"SQURA_R_RR"
,
"SQURA_R_RR"
,
(char *)0x7D,
(char *)0x0,
"SQURS_R_RR"
,
"SQURS_R_RR"
,
(char *)0x7E,
(char *)0x0,
"MPY_R_RR_AC"
,
"MPY_R_RR_AC"
,
(char *)0x7F,
(char *)0x0,
"SQUR_R_RR"
,
"SQUR_R_RR"
,
(char *)0x80,
"OOOOOOOOp-%aaaaap--ccccc"
,
"`aaaaa,ACx` = `q_SAT,(`rnd(`ccccc,ACx`)`q_SAT,)`"
,
"ROUND`q_SAT` `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x81,
"OOOOOOOOp-%aaaaap--ccccc"
,
"`aaaaa,ACx` = saturate(`%,(``ccccc,ACx``%,)`)"
,
"SAT`%` `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x82,
"OOOOOOO$p/%aaaaapCCccccc#DDddddd"
,
"`aaaaa,ACx` = `q_SAT,(``%,(``aaaaa,ACx` + `/,(``$,(``CCccccc,MRx``$,)` * `#,(``DDddddd,MAx``#,)``/,)``%,)``q_SAT,)`"
,
"MAC`/``q_SAT``%` `$,(``CCccccc,MRx``$,)`, `#,(``DDddddd,MAx``#,)`, `aaaaa,ACx`"
,
(char *)0x83,
"OOOOOOO$p/%aaaaapCCccccc#DDddddd"
,
"`aaaaa,ACx` = `q_SAT,(``%,(``aaaaa,ACx` - `/,(``$,(``CCccccc,MRx``$,)` * `#,(``DDddddd,MAx``#,)``/,)``%,)``q_SAT,)`"
,
"MAS`/``q_SAT``%` `#,(``DDddddd,MAx``#,)`, `$,(``CCccccc,MRx``$,)`, `aaaaa,ACx`"
,
(char *)0x84,
"OOOOOOO$p/%aaaaapCCccccc#DDddddd"
,
"`aaaaa,ACx` = `q_SAT,(``%,(``/,(``$,(``CCccccc,MRx``$,)` * `#,(``DDddddd,MAx``#,)``/,)``%,)``q_SAT,)`"
,
"MPY`/``q_SAT``%` `#,(``DDddddd,MAx``#,)`, `$,(``CCccccc,MRx``$,)`, `aaaaa,ACx`"
,
(char *)0x85,
"OOOOOOO-p/%aaaaapDDddddd---ccccc"
,
"`aaaaa,ACx` = `q_SAT,(``%,(``ccccc,ACx` + `/,(``DDddddd,MRx` * `aaaaa,ACx``/,)``%,)``q_SAT,)`"
,
"MAC`/``q_SAT``%` `aaaaa,ACx`, `DDddddd,MRx`, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x86,
"OOOOOOOOpAAaaaaapCCcccccoNNnnnnn"
,
"`AAaaaaa,WACx` = `q_SAT,(``AAaaaaa,WACx` + (`CCccccc,WACx` << `NNnnnnn,SRx`)`q_SAT,)`"
,
"ADD`q_SAT` `CCccccc,WACx` << `NNnnnnn,SRx`, `AAaaaaa,WACx`"
,
(char *)0x87,
"OOOOOOOOpAAaaaaapCCcccccoNNnnnnn"
,
"`AAaaaaa,WACx` = `q_SAT,(``AAaaaaa,WACx` - (`CCccccc,WACx` << `NNnnnnn,SRx`)`q_SAT,)`"
,
"SUB`q_SAT` `CCccccc,WACx` << `NNnnnnn,SRx`, `AAaaaaa,WACx`"
,
(char *)0x88,
"OOOOOOOOp00aaaaap-Taaaaa--------"
,
"`aaaaa,ACx` = sftc(`aaaaa,ACx`, `T`)"
,
"SFTCC `aaaaa,ACx`, `T`"
,
(char *)0x89,
"OOOOOOOOpAAaaaaapCCcccccoNNnnnnn"
,
"`AAaaaaa,WACx` = `CCccccc,WACx` <<< `NNnnnnn,SRx`"
,
"SFTL `CCccccc,WACx`, `NNnnnnn,SRx`, `AAaaaaa,WACx`"
,
(char *)0x8A,
"OOOOOOOOpAAaaaaapCCcccccoNNnnnnn"
,
"`AAaaaaa,WACx` = `q_SAT,(``CCccccc,WACx` << `NNnnnnn,SRx``q_SAT,)`"
,
"SFTS`q_SAT` `CCccccc,WACx`, `NNnnnnn,SRx`, `AAaaaaa,WACx`"
,
(char *)0x8B,
"OOOOOOOOpAAaaaaapCCcccccoNNnnnnn"
,
"`AAaaaaa,WACx` = `q_SAT,(``CCccccc,WACx` <<C `NNnnnnn,SRx``q_SAT,)`"
,
"SFTSC`q_SAT` `CCccccc,WACx`, `NNnnnnn,SRx`, `AAaaaaa,WACx`"
,
(char *)0x8C,
"OOOOOOOOpp-kkkkk"
,
"swap(`kkkkk,!`)"
,
"SWAP `kkkkk,!`"
,
(char *)0x8D,
(char *)0x0,
"COPR_16"
,
"COPR_16"
,
(char *)0x8E,
"OOOOOOOOppqq----"
,
"nop_16"
,
"NOP_16"
,
(char *)0x8F,
(char *)0x0,
"BRC_P_SD"
,
"BRC_P_SD"
,
(char *)0x90,
"OOOOOOOpllllllllllllllllllllllllHHHhhhhh"
,
"if (`HHHhhhhh`) goto `llllllllllllllllllllllll`"
,
"BCC `llllllllllllllllllllllll`, `HHHhhhhh`"
,
(char *)0x91,
"OOOOOOOpllllllllllllllllllllllllHHHhhhhh"
,
"if (`HHHhhhhh`) call `llllllllllllllllllllllll`"
,
"CALLCC `llllllllllllllllllllllll`, `HHHhhhhh`"
,
(char *)0x92,
"OOOOOOFpllllllllllllllllllllllll"
,
"`q_SAT,n`goto `llllllllllllllllllllllll``F`"
,
"`q_SAT,N`B `llllllllllllllllllllllll``F`"
,
(char *)0x93,
"OOOOOOFpllllllllllllllllllllllll"
,
"call `llllllllllllllllllllllll``F`"
,
"CALL `llllllllllllllllllllllll``F`"
,
(char *)0x94,
"OOOOOOOpLLLLLLLLLLLLLLLLHHHhhhhh"
,
"if (`HHHhhhhh`) goto `LLLLLLLLLLLLLLLL`"
,
"BCC `LLLLLLLLLLLLLLLL`, `HHHhhhhh`"
,
(char *)0x95,
"OOOOOOOpLLLLLLLLLLLLLLLLHHHhhhhh"
,
"if (`HHHhhhhh`) call `LLLLLLLLLLLLLLLL`"
,
"CALLCC `LLLLLLLLLLLLLLLL`, `HHHhhhhh`"
,
(char *)0x96,
"OOOOOOK$JCCcccccJKKKKKKKLLLLLLLLLLLLLLLL"
,
"compare (`$,(``CCccccc,RAx` `JJ` `KKKKKKKK``$,)`) goto `LLLLLLLLLLLLLLLL`"
,
"BCC`$` `LLLLLLLLLLLLLLLL`, `CCccccc,RAx` `JJ` `KKKKKKKK`"
,
(char *)0x97,
"OOOOOOOopssaaaaapsscccccKKKKKKKKKKKKKKKK"
,
"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` + (`KKKKKKKKKKKKKKKK` << `ssss`)`q_SAT,)`"
,
"ADD`q_SAT` `KKKKKKKKKKKKKKKK` << `ssss`, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x98,
"OOOOOOOopssaaaaapsscccccKKKKKKKKKKKKKKKK"
,
"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` - (`KKKKKKKKKKKKKKKK` << `ssss`)`q_SAT,)`"
,
"SUB`q_SAT` `KKKKKKKKKKKKKKKK` << `ssss`, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x99,
"OOOOOOOopssaaaaapssccccckkkkkkkkkkkkkkkk"
,
"`aaaaa,ACx` = `ccccc,ACx` & (`kkkkkkkkkkkkkkkk` <<< `ssss`)"
,
"AND `kkkkkkkkkkkkkkkk` << `ssss`, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x9A,
"OOOOOOOopssaaaaapssccccckkkkkkkkkkkkkkkk"
,
"`aaaaa,ACx` = `ccccc,ACx` | (`kkkkkkkkkkkkkkkk` <<< `ssss`)"
,
"OR `kkkkkkkkkkkkkkkk` << `ssss`, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x9B,
"OOOOOOOopssaaaaapssccccckkkkkkkkkkkkkkkk"
,
"`aaaaa,ACx` = `ccccc,ACx` ^ (`kkkkkkkkkkkkkkkk` <<< `ssss`)"
,
"XOR `kkkkkkkkkkkkkkkk` << `ssss`, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x9C,
"OOOOOOOopssaaaaapss-----KKKKKKKKKKKKKKKK"
,
"`aaaaa,ACx` = `KKKKKKKKKKKKKKKK` << `ssss`"
,
"MOV `KKKKKKKKKKKKKKKK` << `ssss`, `aaaaa,ACx`"
,
(char *)0x9D,
"OOOOOOOO-AAaaaaap11ccccckkkkkkkkkkkkkkkk"
,
"`AAaaaaa,Rx` = field_extract(`ccccc,ACx`.L, `kkkkkkkkkkkkkkkk`)"
,
"BFXTR `kkkkkkkkkkkkkkkk`, `ccccc,ACx`, `AAaaaaa,Rx`"
,
(char *)0x9E,
"OOOOOOOO-AAaaaaap11ccccckkkkkkkkkkkkkkkk"
,
"`AAaaaaa,Rx` = field_expand(`ccccc,ACx`.L, `kkkkkkkkkkkkkkkk`)"
,
"BFXPA `kkkkkkkkkkkkkkkk`, `ccccc,ACx`, `AAaaaaa,Rx`"
,
(char *)0x9F,
"OOOOOOOO-AAaaaaaKKKKKKKKKKKKKKKK"
,
"`AAaaaaa,Rx` = `q_SAT,(``KKKKKKKKKKKKKKKK``q_SAT,)`"
,
"MOV`q_SAT` `KKKKKKKKKKKKKKKK`, `AAaaaaa,Rx`"
,
(char *)0xA0,
"OOOOOOOOpp-aaaaakkkkkkkkkkkkkkkk"
,
"mar(`aaaaa,DAx` = `kkkkkkkkkkkkkkkk`)"
,
"AMOV `kkkkkkkkkkkkkkkk`, `aaaaa,DAx`"
,
(char *)0xA1,
(char *)0x0,
"LD_RPK_DP"
,
"LD_RPK_DP"
,
(char *)0xA2,
(char *)0x0,
"LD_RPK_SSP"
,
"LD_RPK_SSP"
,
(char *)0xA3,
(char *)0x0,
"LD_RPK_CDP"
,
"LD_RPK_CDP"
,
(char *)0xA4,
(char *)0x0,
"LD_RPK_BF01"
,
"LD_RPK_BF01"
,
(char *)0xA5,
(char *)0x0,
"LD_RPK_BF23"
,
"LD_RPK_BF23"
,
(char *)0xA6,
(char *)0x0,
"LD_RPK_BF45"
,
"LD_RPK_BF45"
,
(char *)0xA7,
(char *)0x0,
"LD_RPK_BF67"
,
"LD_RPK_BF67"
,
(char *)0xA8,
(char *)0x0,
"LD_RPK_BFC"
,
"LD_RPK_BFC"
,
(char *)0xA9,
(char *)0x0,
"LD_RPK_SP"
,
"LD_RPK_SP"
,
(char *)0xAA,
"OOOOOOOO-/%aaaaap--------CCcccccKKKKKKKKKKKKKKKK"
,
"`aaaaa,ACx` = `q_SAT,(``%,(``/,(``CCccccc,MRx` * `KKKKKKKKKKKKKKKK``/,)``%,)``q_SAT,)`"
,
"MPYK`/``q_SAT``%` `KKKKKKKKKKKKKKKK`, `CCccccc,MRx`, `aaaaa,ACx`"
,
(char *)0xAB,
"OOOOOOOO-/%aaaaap--ccccc-DDdddddKKKKKKKKKKKKKKKK"
,
"`aaaaa,ACx` = `q_SAT,(``%,(``ccccc,ACx` + `/,(``DDddddd,MRx` * `KKKKKKKKKKKKKKKK``/,)``%,)``q_SAT,)`"
,
"MACK`/``q_SAT``%` `KKKKKKKKKKKKKKKK`, `DDddddd,MRx`, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0xAC,
"OOOOOOOop--aaaaap--cccccKKKKKKKKKKKKKKKK"
,
"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` + (`KKKKKKKKKKKKKKKK` << #16)`q_SAT,)`"
,
"ADD`q_SAT` `KKKKKKKKKKKKKKKK` << #16, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0xAD,
"OOOOOOOop--aaaaap--cccccKKKKKKKKKKKKKKKK"
,
"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` - (`KKKKKKKKKKKKKKKK` << #16)`q_SAT,)`"
,
"SUB`q_SAT` `KKKKKKKKKKKKKKKK` << #16, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0xAE,
"OOOOOOOop--aaaaap--ccccckkkkkkkkkkkkkkkk"
,
"`aaaaa,ACx` = `ccccc,ACx` & (`kkkkkkkkkkkkkkkk` <<< #16)"
,
"AND `kkkkkkkkkkkkkkkk` << #16, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0xAF,
"OOOOOOOop--aaaaap--ccccckkkkkkkkkkkkkkkk"
,
"`aaaaa,ACx` = `ccccc,ACx` | (`kkkkkkkkkkkkkkkk` <<< #16)"
,
"OR `kkkkkkkkkkkkkkkk` << #16, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0xB0,
"OOOOOOOop--aaaaap--ccccckkkkkkkkkkkkkkkk"
,
"`aaaaa,ACx` = `ccccc,ACx` ^ (`kkkkkkkkkkkkkkkk` <<< #16)"
,
"XOR `kkkkkkkkkkkkkkkk` << #16, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0xB1,
"OOOOOOOop--aaaaap-------KKKKKKKKKKKKKKKK"
,
"`aaaaa,ACx` = `q_SAT,(``KKKKKKKKKKKKKKKK` << #16`q_SAT,)`"
,
"MOV`q_SAT` `KKKKKKKKKKKKKKKK` << #16, `aaaaa,ACx`"
,
(char *)0xB2,
"OOOOOOOOppqq----"
,
"idle"
,
"IDLE"
,
(char *)0xB3,
"OOOOOOOopAAaaaaapCCcccccKKKKKKKKKKKKKKKK"
,
"`AAaaaaa,Rx` = `q_SAT,(``CCccccc,Rx` + `KKKKKKKKKKKKKKKK``q_SAT,)`"
,
"ADD`q_SAT` `KKKKKKKKKKKKKKKK`, `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(char *)0xB4,
"OOOOOOOopAAaaaaapCCcccccKKKKKKKKKKKKKKKK"
,
"`AAaaaaa,Rx` = `q_SAT,(``CCccccc,Rx` - `KKKKKKKKKKKKKKKK``q_SAT,)`"
,
"SUB`q_SAT` `KKKKKKKKKKKKKKKK`, `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(char *)0xB5,
"OOOOOOOopAAaaaaapCCccccckkkkkkkkkkkkkkkk"
,
"`AAaaaaa,Rx` = `CCccccc,Rx` & `kkkkkkkkkkkkkkkk`"
,
"AND `kkkkkkkkkkkkkkkk`, `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(char *)0xB6,
"OOOOOOOopAAaaaaapCCccccckkkkkkkkkkkkkkkk"
,
"`AAaaaaa,Rx` = `CCccccc,Rx` | `kkkkkkkkkkkkkkkk`"
,
"OR `kkkkkkkkkkkkkkkk`, `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(char *)0xB7,
"OOOOOOOopAAaaaaapCCccccckkkkkkkkkkkkkkkk"
,
"`AAaaaaa,Rx` = `CCccccc,Rx` ^ `kkkkkkkkkkkkkkkk`"
,
"XOR `kkkkkkkkkkkkkkkk`, `CCccccc,Rx`, `AAaaaaa,Rx`"
,
(char *)0xB8,
(char *)0x0,
"LMVM_MM_L"
,
"LMVM_MM_L"
,
(char *)0xB9,
(char *)0x0,
"MVM_MM_YX"
,
"MVM_MM_YX"
,
(char *)0xBA,
"OOOOOOOO-XXXxxxxp--ccccc-YYYyyyy"
,
"`XXXxxxx,w` = LO(`ccccc,ACx`), `YYYyyyy,w` = HI(`ccccc,ACx`)"
,
"MOV `ccccc,ACx`, `XXXxxxx,w`, `YYYyyyy,w`"
,
(char *)0xBB,
"OOOOOOOOpXXXxxxxp00aaaaa-YYYyyyy"
,
"`aaaaa,ACx` = `q_SAT,(`(`XXXxxxx,r` << #16) + (`YYYyyyy,r` << #16)`q_SAT,)`"
,
"ADD`q_SAT` `XXXxxxx,r` << #16, `YYYyyyy,r` << #16, `aaaaa,ACx`"
,
(char *)0xBC,
"OOOOOOOOpXXXxxxxp00aaaaa-YYYyyyy"
,
"`aaaaa,ACx` = `q_SAT,(`(`XXXxxxx,r` << #16) - (`YYYyyyy,r` << #16)`q_SAT,)`"
,
"SUB`q_SAT` `XXXxxxx,r` << #16, `YYYyyyy,r` << #16, `aaaaa,ACx`"
,
(char *)0xBD,
"OOOOOOOO-XXXxxxxp--aaaaa-YYYyyyy"
,
"LO(`aaaaa,ACx`) = `q_SAT,(``XXXxxxx,r``q_SAT,)`, HI(`aaaaa,ACx`) = `q_SAT,(``YYYyyyy,r``q_SAT,)`"
,
"MOV`q_SAT` `XXXxxxx,r`, `YYYyyyy,r`, `aaaaa,ACx`"
,
(char *)0xBE,
"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
"MPY`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` :: MPY`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx`"
,
(char *)0xBF,
"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
"MAC`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` :: MPY`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx`"
,
(char *)0xC0,
"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
"MAS`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` :: MPY`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx`"
,
(char *)0xC1,
"OOOOOOO-pXXXxxxxp4$-----%YYYyyyyqq#aaaaa/ZZZzzzz"
,
"mar(`XXXxxxx,r`), `aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``YYYyyyy,r``$,)` * `#,(``ZZZzzzz,r``#,)``/,)``%,)``4,)``q_SAT,)`"
,
"AMAR `XXXxxxx,r` :: MPY`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``ZZZzzzz,r``#,)`, `aaaaa,ACx`"
,
(char *)0xC2,
"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` + `/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
"MAC`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx`"
,
(char *)0xC3,
"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` + `/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
"MAS`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx`"
,
(char *)0xC4,
"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(`(`aaaaa,ACx` >> #16) + `/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` + `/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
"MAC`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` >> #16 :: MAC`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx`"
,
(char *)0xC5,
"OOOOOOO-pXXXxxxxp4$-----%YYYyyyyqq#aaaaa/ZZZzzzz"
,
"mar(`XXXxxxx,r`), `aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/,(``$,(``YYYyyyy,r``$,)` * `#,(``ZZZzzzz,r``#,)``/,)``%,)``4,)``q_SAT,)`"
,
"AMAR `XXXxxxx,r` :: MAC`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``ZZZzzzz,r``#,)`, `aaaaa,ACx`"
,
(char *)0xC6,
"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(`(`bbbbb,ACx` >> #16) + `/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
"MAS`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx` >> #16"
,
(char *)0xC7,
"OOOOOOO-pXXXxxxxp4$-----%YYYyyyyqq#aaaaa/ZZZzzzz"
,
"mar(`XXXxxxx,r`), `aaaaa,ACx` = `q_SAT,(``4,(``%,(`(`aaaaa,ACx` >> #16) + `/,(``$,(``YYYyyyy,r``$,)` * `#,(``ZZZzzzz,r``#,)``/,)``%,)``4,)``q_SAT,)`"
,
"AMAR `XXXxxxx,r` :: MAC`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``ZZZzzzz,r``#,)`, `aaaaa,ACx` >> #16"
,
(char *)0xC8,
"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(`(`bbbbb,ACx` >> #16) + `/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
"MPY`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx` >> #16"
,
(char *)0xC9,
"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(`(`aaaaa,ACx` >> #16) + `/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(`(`bbbbb,ACx` >> #16) + `/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
"MAC`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` >> #16 :: MAC`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx` >> #16"
,
(char *)0xCA,
"OOOOOOO-pXXXxxxxp4$-----%YYYyyyyqq#aaaaa/ZZZzzzz"
,
"mar(`XXXxxxx,r`), `aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/,(``$,(``YYYyyyy,r``$,)` * `#,(``ZZZzzzz,r``#,)``/,)``%,)``4,)``q_SAT,)`"
,
"AMAR `XXXxxxx,r` :: MAS`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``ZZZzzzz,r``#,)`, `aaaaa,ACx`"
,
(char *)0xCB,
"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` - `/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
"MAS`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` :: MAS`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx`"
,
(char *)0xCC,
"OOOOOOO-pXXXxxxxp--------YYYyyyyqq-------ZZZzzzz"
,
"mar(`XXXxxxx,r`), mar(`YYYyyyy,r`), mar(`ZZZzzzz,r`)"
,
"AMAR `XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`"
,
(char *)0xCD,
"OOOOOOO-pXXXxxxxp0-aaaaa0YYYyyyyqq-bbbbb/ZZZzzzz"
,
"firs`/,a``q_SAT,a`(`XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`, `aaaaa,ACx`, `bbbbb,ACx`)"
,
"FIRSADD`/``q_SAT` `XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`, `aaaaa,ACx`, `bbbbb,ACx`"
,
(char *)0xCE,
"OOOOOOO-pXXXxxxxp0-aaaaa0YYYyyyyqq-bbbbb/ZZZzzzz"
,
"firsn`/,a``q_SAT,a`(`XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`, `aaaaa,ACx`, `bbbbb,ACx`)"
,
"FIRSSUB`/``q_SAT` `XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`, `aaaaa,ACx`, `bbbbb,ACx`"
,
(char *)0xCF,
"OOOOOOO3pXXXxxxxp4$aaaaa%YYYyyyy/-#-----"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``XXXxxxx,r``$,)` * `#,(``YYYyyyy,r``#,)``/,)``%,)``4,)``q_SAT,)``XXXxxxx3,3r`"
,
"MPYM`/``q_SAT``%``4` `3``$,(``XXXxxxx,r``$,)`, `#,(``YYYyyyy,r``#,)`, `aaaaa,ACx`"
,
(char *)0xD0,
"OOOOOOO3pXXXxxxxp4$aaaaa%YYYyyyy/-#ccccc"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``ccccc,ACx` + `/,(``$,(``XXXxxxx,r``$,)` * `#,(``YYYyyyy,r``#,)``/,)``%,)``4,)``q_SAT,)``XXXxxxx3,3r`"
,
"MACM`/``q_SAT``%``4` `3``$,(``XXXxxxx,r``$,)`, `#,(``YYYyyyy,r``#,)`, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0xD1,
"OOOOOOO3pXXXxxxxp4$aaaaa%YYYyyyy/-#ccccc"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(`(`ccccc,ACx` >> #16) + `/,(``$,(``XXXxxxx,r``$,)` * `#,(``YYYyyyy,r``#,)``/,)``%,)``4,)``q_SAT,)``XXXxxxx3,3r`"
,
"MACM`/``q_SAT``%``4` `3``$,(``XXXxxxx,r``$,)`, `#,(``YYYyyyy,r``#,)`, `ccccc,ACx` >> #16, `aaaaa,ACx`"
,
(char *)0xD2,
"OOOOOOO3pXXXxxxxp4$aaaaa%YYYyyyy/-#ccccc"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``ccccc,ACx` - `/,(``$,(``XXXxxxx,r``$,)` * `#,(``YYYyyyy,r``#,)``/,)``%,)``4,)``q_SAT,)``XXXxxxx3,3r`"
,
"MASM`/``q_SAT``%``4` `3``$,(``XXXxxxx,r``$,)`, `#,(``YYYyyyy,r``#,)`, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0xD3,
"OOOOOOO3pXXXxxxxp-oaaaaa%YYYyyyy/ccbbbbb"
,
"`aaaaa,ACx` = `q_SAT,(``%,(``aaaaa,ACx` - `/`(`cc,Tx` * `XXXxxxx,r`)`%,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``YYYyyyy,r` << #16`q_SAT,)``XXXxxxx3,3r`"
,
"MASM`/``q_SAT``%` `XXXxxxx3,3r`, `cc,Tx`, `aaaaa,ACx` :: MOV`q_SAT` `YYYyyyy,r` << #16, `bbbbb,ACx`"
,
(char *)0xD4,
"OOOOOOO3pXXXxxxxp-oaaaaa%YYYyyyy/ccbbbbb"
,
"`aaaaa,ACx` = `q_SAT,(``%,(``aaaaa,ACx` + `/`(`cc,Tx` * `XXXxxxx,r`)`%,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``YYYyyyy,r` << #16`q_SAT,)``XXXxxxx3,3r`"
,
"MACM`/``q_SAT``%` `XXXxxxx3,3r`, `cc,Tx`, `aaaaa,ACx` :: MOV`q_SAT` `YYYyyyy,r` << #16, `bbbbb,ACx`"
,
(char *)0xD5,
"OOOOOOOOpXXXxxxxp--aaaaa1YYYyyyy/--bbbbb"
,
"lms`/,a``q_SAT,a`(`XXXxxxx,r`, `YYYyyyy,r`, `aaaaa,ACx`, `bbbbb,ACx`)"
,
"LMS`/``q_SAT` `XXXxxxx,r`, `YYYyyyy,r`, `aaaaa,ACx`, `bbbbb,ACx`"
,
(char *)0xD6,
"OOOOOOOOpXXXxxxxp--aaaaa0YYYyyyy/--bbbbb"
,
"sqdst`/,a``q_SAT,a`(`XXXxxxx,r`, `YYYyyyy,r`, `aaaaa,ACx`, `bbbbb,ACx`)"
,
"SQDST`/``q_SAT` `XXXxxxx,r`, `YYYyyyy,r`, `aaaaa,ACx`, `bbbbb,ACx`"
,
(char *)0xD7,
"OOOOOOOOpXXXxxxxp--aaaaa0YYYyyyy/--bbbbb"
,
"abdst`/,a``q_SAT,a`(`XXXxxxx,r`, `YYYyyyy,r`, `aaaaa,ACx`, `bbbbb,ACx`)"
,
"ABDST`/``q_SAT` `XXXxxxx,r`, `YYYyyyy,r`, `aaaaa,ACx`, `bbbbb,ACx`"
,
(char *)0xD8,
"OOOOOOO3pXXXxxxxp-oaaaaa%YYYyyyy/ccddddd"
,
"`aaaaa,ACx` = `q_SAT,(``%,(``/,(``cc,Tx` * `XXXxxxx,r``/,)``%,)``q_SAT,)`, `YYYyyyy,w` = `q_SAT,(`HI(`ccccc,ACx` << T2)`q_SAT,)``XXXxxxx3,3r`"
,
"MPYM`/``q_SAT``%` `XXXxxxx3,3r`, `cc,Tx`, `aaaaa,ACx` :: MOV`q_SAT` HI(`ccccc,ACx` << T2), `YYYyyyy,w`"
,
(char *)0xD9,
"OOOOOOO3pXXXxxxxp-oaaaaa%YYYyyyy/ccddddd"
,
"`aaaaa,ACx` = `q_SAT,(``%,(``aaaaa,ACx` + `/`(`cc,Tx` * `XXXxxxx,r`)`%,)``q_SAT,)`, `YYYyyyy,w` = `q_SAT,(`HI(`ccccc,ACx` << T2)`q_SAT,)``XXXxxxx3,3r`"
,
"MACM`/``q_SAT``%` `XXXxxxx3,3r`, `cc,Tx`, `aaaaa,ACx` :: MOV`q_SAT` HI(`ccccc,ACx` << T2), `YYYyyyy,w`"
,
(char *)0xDA,
"OOOOOOO3pXXXxxxxp-oaaaaa%YYYyyyy/ccddddd"
,
"`aaaaa,ACx` = `q_SAT,(``%,(``aaaaa,ACx` - `/`(`cc,Tx` * `XXXxxxx,r`)`%,)``q_SAT,)`, `YYYyyyy,w` = `q_SAT,(`HI(`ccccc,ACx` << T2)`q_SAT,)``XXXxxxx3,3r`"
,
"MASM`/``q_SAT``%` `XXXxxxx3,3r`, `cc,Tx`, `aaaaa,ACx` :: MOV`q_SAT` HI(`ccccc,ACx` << T2), `YYYyyyy,w`"
,
(char *)0xDB,
"OOOOOOOOpXXXxxxxp--aaaaa-YYYyyyy---ccccc"
,
"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` + (`XXXxxxx,r` << #16)`q_SAT,)`, `YYYyyyy,w` = `q_SAT,(`HI(`aaaaa,ACx` << T2)`q_SAT,)`"
,
"ADD`q_SAT` `XXXxxxx,r` << #16, `ccccc,ACx`, `aaaaa,ACx` :: MOV`q_SAT` HI(`aaaaa,ACx` << T2), `YYYyyyy,w`"
,
(char *)0xDC,
"OOOOOOOOpXXXxxxxp--aaaaa-YYYyyyy---ccccc"
,
"`aaaaa,ACx` = `q_SAT,(`(`XXXxxxx,r` << #16) - `ccccc,ACx``q_SAT,)`, `YYYyyyy,w` = `q_SAT,(`HI(`aaaaa,ACx` << T2)`q_SAT,)`"
,
"SUB`q_SAT` `ccccc,ACx`, `XXXxxxx,r` << #16, `aaaaa,ACx` :: MOV`q_SAT` HI(`aaaaa,ACx` << T2), `YYYyyyy,w`"
,
(char *)0xDD,
"OOOOOOOOpXXXxxxxp--aaaaa-YYYyyyy---ccccc"
,
"`aaaaa,ACx` = `q_SAT,(``XXXxxxx,r` << #16`q_SAT,)`, `YYYyyyy,w` = `q_SAT,(`HI(`ccccc,ACx` << T2)`q_SAT,)`"
,
"MOV`q_SAT` `XXXxxxx,r` << #16, `aaaaa,ACx` :: MOV`q_SAT` HI(`ccccc,ACx` << T2), `YYYyyyy,w`"
,
(char *)0xDE,
(char *)0x0,
"SDUAL__"
,
"SDUAL__"
,
(char *)0xDF,
"OOOOOOOOpGFccccc"
,
"`q_SAT,n`goto `ccccc,ACx``G``F`"
,
"`q_SAT,N`B `ccccc,ACx``G``F`"
,
(char *)0xE0,
"OOOOOOOOpGFccccc"
,
"call `ccccc,ACx``G``F`"
,
"CALL `ccccc,ACx``G``F`"
,
(char *)0xE1,
(char *)0x0,
"SWT_P_DA"
,
"SWT_P_DA"
,
(char *)0xE2,
"OOOOOOOOppqq----"
,
"reset"
,
"RESET"
,
(char *)0xE3,
"OOOOOOOOpp-kkkkk"
,
"intr(`kkkkk`)"
,
"INTR `kkkkk`"
,
(char *)0xE4,
"OOOOOOOOpp-kkkkk"
,
"trap(`kkkkk`)"
,
"TRAP `kkkkk`"
,
(char *)0xE5,
(char *)0x0,
"XCN_PMC_S"
,
"XCN_PMC_S"
,
(char *)0xE6,
(char *)0x0,
"XCN_PMU_S"
,
"XCN_PMU_S"
,
(char *)0xE7,
"OOOOOOpp"
,
"estop_0"
,
"ESTOP_BYTE"
,
(char *)0xE8,
"OOOOOOpp"
,
"MMAP"
,
"MMAP"
,
(char *)0xE9,
"OOOOOOpp"
,
"PORT_READ"
,
"PORT_READ"
,
(char *)0xEA,
"OOOOOOpp"
,
"PORT_WRITE"
,
"PORT_WRITE"
,
(char *)0xEB,
(char *)0x0,
"copr(`kkkkkkkk`, `aa,ACx`, `bb,ACx`)"
,
"COPR__"
,
(char *)0xEC,
"OOOOOOpp"
,
"LINR"
,
"LINR"
,
(char *)0xED,
"OOOOOOpp"
,
"CIRC"
,
"CIRC"
,
(char *)0xEE,
"OOOOOOppHHHhhhhh"
,
"if (`HHHhhhhh`) execute (AD_Unit)"
,
"XCC `HHHhhhhh`"
,
(char *)0xEF,
"OOOOOOppHHHhhhhh"
,
"if (`HHHhhhhh`) execute (D_Unit)"
,
"XCCPART `HHHhhhhh`"
,
(char *)0xF0,
"OOOOOOppHHHhhhhh"
,
"if (`HHHhhhhh`) execute (AD_Unit)"
,
"XCC `HHHhhhhh`"
,
(char *)0xF1,
"OOOOOOppHHHhhhhh"
,
"if (`HHHhhhhh`) execute (D_Unit)"
,
"XCCPART `HHHhhhhh`"
,
(char *)0xF2,
(char *)0x0,
"LD_RGM"
,
"LD_RGM"
,
(char *)0xF3,
"OOOOOOqqMMMMxxxxmm-aaaaa"
,
"`aaaaa,ACx` = `q_SAT,(``MMMMxxxxmm,r` << #16`q_SAT,)`"
,
"MOV`q_SAT` `MMMMxxxxmm,r` << #16, `aaaaa,ACx`"
,
(char *)0xF4,
"OOOOOOOOMMMMxxxxmmq--o--"
,
"mar(`MMMMxxxxmm,r`)"
,
"AMAR `MMMMxxxxmm,r`"
,
(char *)0xF5,
"OOOOOOOOMMMMxxxxmmq-p---"
,
"push(`MMMMxxxxmm,r`)"
,
"PSH `MMMMxxxxmm,r`"
,
(char *)0xF6,
"OOOOOOOOMMMMxxxxmm------"
,
"delay(`MMMMxxxxmm`)"
,
"DELAY `MMMMxxxxmm`"
,
(char *)0xF7,
"OOOOOOOOMMMMxxxxmmq-p---"
,
"push(dbl(`MMMMxxxxmm,dr`))"
,
"PSH dbl(`MMMMxxxxmm,dr`)"
,
(char *)0xF8,
"OOOOOOOOMMMMxxxxmmq-p---"
,
"dbl(`MMMMxxxxmm,dw`) = pop()"
,
"POP dbl(`MMMMxxxxmm,dw`)"
,
(char *)0xF9,
"OOOOOOOOMMMMxxxxmmq-p---"
,
"`MMMMxxxxmm,w` = pop()"
,
"POP `MMMMxxxxmm,w`"
,
(char *)0xFA,
(char *)0x0,
"STH_RDM"
,
"STH_RDM"
,
(char *)0xFB,
(char *)0x0,
"ST_RGM"
,
"ST_RGM"
,
(char *)0xFC,
"OOOOOOO3MMMMxxxxmm%aaaaapp$-------#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/,(``$,(``MMMMxxxxmm``$,)` * `#,(``ZZZzzzz``#,)``/,)``%,)``4,)``q_SAT,)``MMMMxxxxmm3,3`, delay(`MMMMxxxxmm`)"
,
"MACMZ`/``q_SAT``%``4` `3``$,(``MMMMxxxxmm,r``$,)`, `#,(``ZZZzzzz,r``#,)`, `aaaaa,ACx`"
,
(char *)0xFD,
(char *)0x0,
"MPY_R_MWK"
,
"MPY_R_MWK"
,
(char *)0xFE,
(char *)0x0,
"MAC_R_MP"
,
"MAC_R_MP"
,
(char *)0xFF,
(char *)0x0,
"MAS_R_MP"
,
"MAS_R_MP"
,
(char *)0x100,
(char *)0x0,
"MAC_R_RM_A"
,
"MAC_R_RM_A"
,
(char *)0x101,
(char *)0x0,
"MAS_R_RM_A"
,
"MAS_R_RM_A"
,
(char *)0x102,
"OOOOOOO3MMMMxxxxmm%aaaaapp/ccccc"
,
"`aaaaa,ACx` = `q_SAT,(``%,(``ccccc,ACx` + `/`(`MMMMxxxxmm,r` * `MMMMxxxxmm,r`)`%,)``q_SAT,)``MMMMxxxxmm3,3r`"
,
"SQAM`/``q_SAT``%` `3``MMMMxxxxmm,r`, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x103,
"OOOOOOO3MMMMxxxxmm%aaaaapp/ccccc"
,
"`aaaaa,ACx` = `q_SAT,(``%,(``ccccc,ACx` - `/`(`MMMMxxxxmm,r` * `MMMMxxxxmm,r`)`%,)``q_SAT,)``MMMMxxxxmm3,3r`"
,
"SQSM`/``q_SAT``%` `3``MMMMxxxxmm,r`, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x104,
(char *)0x0,
"MPY_R_RM_L"
,
"MPY_R_RM_L"
,
(char *)0x105,
"OOOOOOO3MMMMxxxxmm%aaaaapp/-----"
,
"`aaaaa,ACx` = `q_SAT,(``%,(``/,(``MMMMxxxxmm,r` * `MMMMxxxxmm,r``/,)``%,)``q_SAT,)``MMMMxxxxmm3,3r`"
,
"SQRM`/``q_SAT``%` `3``MMMMxxxxmm,r`, `aaaaa,ACx`"
,
(char *)0x106,
"OOOOOOO3MMMMxxxxmm%aaaaapp$-----/CCccccc"
,
"`aaaaa,ACx` = `q_SAT,(``%,(``/,(``$,(``CCccccc,MRx` * `MMMMxxxxmm,r``$,)``/,)``%,)``q_SAT,)``MMMMxxxxmm3,3r`"
,
"MPYM`/``q_SAT``%``$` `3``MMMMxxxxmm,r`, `CCccccc,MRx`, `aaaaa,ACx`"
,
(char *)0x107,
"OOOOOOO3MMMMxxxxmm%aaaaapp$ccccc/DDddddd"
,
"`aaaaa,ACx` = `q_SAT,(``%,(``ccccc,ACx` + `/,(``$,(``DDddddd,MRx` * `MMMMxxxxmm,r``$,)``/,)``%,)``q_SAT,)``MMMMxxxxmm3,3r`"
,
"MACM`/``q_SAT``%``$` `3``MMMMxxxxmm,r`, `DDddddd,MRx`, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x108,
"OOOOOOO3MMMMxxxxmm%aaaaapp$ccccc/DDddddd"
,
"`aaaaa,ACx` = `q_SAT,(``%,(``ccccc,ACx` - `/,(``$,(``DDddddd,MRx` * `MMMMxxxxmm,r``$,)``/,)``%,)``q_SAT,)``MMMMxxxxmm3,3r`"
,
"MASM`/``q_SAT``%``$` `3``MMMMxxxxmm,r`, `DDddddd,MRx`, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x109,
"OOOOOoppMMMMxxxxmmAaaaaaACCccccc"
,
"`AaaaaaA,!` = `q_SAT,(``CCccccc,Rx` + `MMMMxxxxmm,r``q_SAT,)`"
,
"ADD`q_SAT` `MMMMxxxxmm,r`, `CCccccc,Rx`, `AaaaaaA,!`"
,
(char *)0x10A,
"OOOOOoppMMMMxxxxmmAaaaaaACCccccc"
,
"`AaaaaaA,!` = `q_SAT,(``CCccccc,Rx` - `MMMMxxxxmm,r``q_SAT,)`"
,
"SUB`q_SAT` `MMMMxxxxmm,r`, `CCccccc,Rx`, `AaaaaaA,!`"
,
(char *)0x10B,
"OOOOOoppMMMMxxxxmmAaaaaaACCccccc"
,
"`AaaaaaA,!` = `q_SAT,(``MMMMxxxxmm,r` - `CCccccc,Rx``q_SAT,)`"
,
"SUB`q_SAT` `CCccccc,Rx`, `MMMMxxxxmm,r`, `AaaaaaA,!`"
,
(char *)0x10C,
"OOOOOoppMMMMxxxxmmAaaaaaACCccccc"
,
"`AaaaaaA,!` = `CCccccc,Rx` & `MMMMxxxxmm,r`"
,
"AND`q_SAT` `MMMMxxxxmm,r`, `CCccccc,Rx`, `AaaaaaA,!`"
,
(char *)0x10D,
"OOOOOoppMMMMxxxxmmAaaaaaACCccccc"
,
"`AaaaaaA,!` = `CCccccc,Rx` | `MMMMxxxxmm,r`"
,
"OR`q_SAT` `MMMMxxxxmm,r`, `CCccccc,Rx`, `AaaaaaA,!`"
,
(char *)0x10E,
"OOOOOoppMMMMxxxxmmAaaaaaACCccccc"
,
"`AaaaaaA,!` = `CCccccc,Rx` ^ `MMMMxxxxmm,r`"
,
"XOR`q_SAT` `MMMMxxxxmm,r`, `CCccccc,Rx`, `AaaaaaA,!`"
,
(char *)0x10F,
"OOOOOOOOMMMMxxxxmmTppo------kkkk"
,
"`T` = bit(`MMMMxxxxmm,r`, `kkkk`)"
,
"BTST `kkkk`, `MMMMxxxxmm,r`, `T`"
,
(char *)0x110,
(char *)0x0,
"BIT_MBT_K2"
,
"BIT_MBT_K2"
,
(char *)0x111,
(char *)0x0,
"LD_DP"
,
"LD_DP"
,
(char *)0x112,
(char *)0x0,
"LD_CDP"
,
"LD_CDP"
,
(char *)0x113,
(char *)0x0,
"LD_BOF01"
,
"LD_BOF01"
,
(char *)0x114,
(char *)0x0,
"LD_BOF23"
,
"LD_BOF23"
,
(char *)0x115,
(char *)0x0,
"LD_BOF45"
,
"LD_BOF45"
,
(char *)0x116,
(char *)0x0,
"LD_BOF67"
,
"LD_BOF67"
,
(char *)0x117,
(char *)0x0,
"LD_BOFC"
,
"LD_BOFC"
,
(char *)0x118,
(char *)0x0,
"LD_SP"
,
"LD_SP"
,
(char *)0x119,
(char *)0x0,
"LD_SSP"
,
"LD_SSP"
,
(char *)0x11A,
(char *)0x0,
"LD_BK03"
,
"LD_BK03"
,
(char *)0x11B,
(char *)0x0,
"LD_BK47"
,
"LD_BK47"
,
(char *)0x11C,
(char *)0x0,
"LD_BKC"
,
"LD_BKC"
,
(char *)0x11D,
(char *)0x0,
"LD_MDP"
,
"LD_MDP"
,
(char *)0x11E,
(char *)0x0,
"LD_MDP05"
,
"LD_MDP05"
,
(char *)0x11F,
(char *)0x0,
"LD_MDP67"
,
"LD_MDP67"
,
(char *)0x120,
(char *)0x0,
"LD_PDP"
,
"LD_PDP"
,
(char *)0x121,
(char *)0x0,
"LD_CSR"
,
"LD_CSR"
,
(char *)0x122,
(char *)0x0,
"LD_BRC0"
,
"LD_BRC0"
,
(char *)0x123,
(char *)0x0,
"LD_BRC1"
,
"LD_BRC1"
,
(char *)0x124,
(char *)0x0,
"LD_TRN0"
,
"LD_TRN0"
,
(char *)0x125,
(char *)0x0,
"LD_TRN1"
,
"LD_TRN1"
,
(char *)0x126,
"OOOOOOOOMMMMxxxxmm-aaaaa-p-ccccc-NNnnnnn"
,
"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` + (`MMMMxxxxmm,r` << `NNnnnnn,SRx`)`q_SAT,)`"
,
"ADD`q_SAT` `MMMMxxxxmm,r` << `NNnnnnn,SRx`, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x127,
"OOOOOOOOMMMMxxxxmm-aaaaa-p-ccccc-NNnnnnn"
,
"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` - (`MMMMxxxxmm,r` << `NNnnnnn,SRx`)`q_SAT,)`"
,
"SUB`q_SAT` `MMMMxxxxmm,r` << `NNnnnnn,SRx`, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x128,
"OOOOOOOOMMMMxxxxmm-aaaaapp-ccccc-NNnnnnn"
,
"`aaaaa,ACx` = ads2c`q_SAT,a`(`MMMMxxxxmm,r`, `ccccc,ACx`, `NNnnnnn,SRx`, TC1, TC2)"
,
"ADDSUB2CC`q_SAT` `MMMMxxxxmm,r`, `ccccc,ACx`, `NNnnnnn,SRx`, TC1, TC2, `aaaaa,ACx`"
,
(char *)0x129,
"OOOOOOOOMMMMxxxxmm%aaaaa-p$----q-NNnnnnn"
,
"`aaaaa,ACx` = `q_SAT,(``%,(``$,(``MMMMxxxxmm,r``$,)` << `NNnnnnn,SRx``%,)``q_SAT,)`"
,
"MOV`q_SAT` `%,(``$,(``MMMMxxxxmm,r``$,)` << `NNnnnnn,SRx``%,)`, `aaaaa,ACx`"
,
(char *)0x12A,
"OOOOOOOOMMMMxxxxmmTaaaaapp-ccccc--------"
,
"`aaaaa,ACx` = adsc`q_SAT,a`(`MMMMxxxxmm,r`, `ccccc,ACx`, `T`)"
,
"ADDSUBCC`q_SAT` `MMMMxxxxmm,r`, `ccccc,ACx`, `T`, `aaaaa,ACx`"
,
(char *)0x12B,
(char *)0x0,
"ADSC_RM_2"
,
"ADSC_RM_2"
,
(char *)0x12C,
"OOOOOOOOMMMMxxxxmm-aaaaapp-ccccc--------"
,
"`aaaaa,ACx` = adsc`q_SAT,a`(`MMMMxxxxmm,r`, `ccccc,ACx`, TC1, TC2)"
,
"ADDSUBCC`q_SAT` `MMMMxxxxmm,r`, `ccccc,ACx`, TC1, TC2, `aaaaa,ACx`"
,
(char *)0x12D,
"OOOOOOOOMMMMxxxxmm-aaaaapp-ccccc--------"
,
"subc(`MMMMxxxxmm,r`, `ccccc,ACx`, `aaaaa,ACx`)"
,
"SUBC `MMMMxxxxmm,r`, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x12E,
"OOOOOOOOMMMMxxxxmm-aaaaapp-ccccc"
,
"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` + (`MMMMxxxxmm,r` << #16)`q_SAT,)`"
,
"ADD`q_SAT` `MMMMxxxxmm,r` << #16, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x12F,
"OOOOOOOOMMMMxxxxmm-aaaaapp-ccccc"
,
"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` - (`MMMMxxxxmm,r` << #16)`q_SAT,)`"
,
"SUB`q_SAT` `MMMMxxxxmm,r` << #16, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x130,
"OOOOOOOOMMMMxxxxmm-aaaaapp-ccccc"
,
"`aaaaa,ACx` = `q_SAT,(`(`MMMMxxxxmm,r` << #16) - `ccccc,ACx``q_SAT,)`"
,
"SUB`q_SAT` `ccccc,ACx`, `MMMMxxxxmm,r` << #16, `aaaaa,ACx`"
,
(char *)0x131,
"OOOOOOOOMMMMxxxxmmqaaaaa-po100cc"
,
"HI(`aaaaa,ACx`) = `q_SAT,(``MMMMxxxxmm,r` + `cc,Tx``q_SAT,)`, LO(`aaaaa,ACx`) = `q_SAT,(``MMMMxxxxmm,r` - `cc,Tx``q_SAT,)`"
,
"ADDSUB`q_SAT` `cc,Tx`, `MMMMxxxxmm,r`, `aaaaa,ACx`"
,
(char *)0x132,
"OOOOOOOOMMMMxxxxmmqaaaaa-po100cc"
,
"HI(`aaaaa,ACx`) = `q_SAT,(``MMMMxxxxmm,r` - `cc,Tx``q_SAT,)`, LO(`aaaaa,ACx`) = `q_SAT,(``MMMMxxxxmm,r` + `cc,Tx``q_SAT,)`"
,
"SUBADD`q_SAT` `cc,Tx`, `MMMMxxxxmm,r`, `aaaaa,ACx`"
,
(char *)0x133,
"OOOOOOOOMMMMxxxxmmqaaaaapp$---AA"
,
"`AAaaaaa,Rx` = `$,(`high_byte(`MMMMxxxxmm,r`)`$,)`"
,
"MOV `$,(`high_byte(`MMMMxxxxmm,r`)`$,)`, `AAaaaaa,Rx`"
,
(char *)0x134,
"OOOOOOOOMMMMxxxxmmqaaaaapp$---AA"
,
"`AAaaaaa,Rx` = `$,(`low_byte(`MMMMxxxxmm,r`)`$,)`"
,
"MOV `$,(`low_byte(`MMMMxxxxmm,r`)`$,)`, `AAaaaaa,Rx`"
,
(char *)0x135,
"OOOOOOqqMMMMxxxxmm$aaaaa"
,
"`aaaaa,ACx` = `$,(``MMMMxxxxmm,r``$,)`"
,
"MOV `$,(``MMMMxxxxmm,r``$,)`, `aaaaa,ACx`"
,
(char *)0x136,
"OOOOOOOOMMMMxxxxmm$aaaaappoccccc"
,
"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` + `$,(``MMMMxxxxmm,r``$,)` + Carry`q_SAT,)`"
,
"ADD`q_SAT` `$,(``MMMMxxxxmm,r``$,)`, CARRY, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x137,
"OOOOOOOOMMMMxxxxmm$aaaaappoccccc"
,
"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` - uns(`MMMMxxxxmm,r`) - Borrow`q_SAT,)`"
,
"SUB`q_SAT` `$,(``MMMMxxxxmm,r``$,)`, BORROW, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x138,
"OOOOOOOOMMMMxxxxmm1aaaaappoccccc"
,
"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` + uns(`MMMMxxxxmm,r`)`q_SAT,)`"
,
"ADD`q_SAT` uns(`MMMMxxxxmm,r`), `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x139,
"OOOOOOOOMMMMxxxxmm1aaaaappoccccc"
,
"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` - uns(`MMMMxxxxmm,r`)`q_SAT,)`"
,
"SUB`q_SAT` uns(`MMMMxxxxmm,r`), `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x13A,
"OOOOOOOOMMMMxxxxmmTcccccppo---CC"
,
"`T` = bit(`MMMMxxxxmm,r`, `CCccccc,RLHx`)"
,
"BTST `CCccccc,RLHx`, `MMMMxxxxmm,r`, `T`"
,
(char *)0x13B,
"OOOOOOOOMMMMxxxxmm-aaaaa-p-----q--SSSSSS"
,
"`aaaaa,ACx` = `q_SAT,(`low_byte(`MMMMxxxxmm,r`) << `SSSSSS``q_SAT,)`"
,
"MOV`q_SAT` low_byte(`MMMMxxxxmm,r`) << `SSSSSS`, `aaaaa,ACx`"
,
(char *)0x13C,
"OOOOOOOOMMMMxxxxmm-aaaaa-p-----q--SSSSSS"
,
"`aaaaa,ACx` = `q_SAT,(`high_byte(`MMMMxxxxmm,r`) << `SSSSSS``q_SAT,)`"
,
"MOV`q_SAT` high_byte(`MMMMxxxxmm,r`) << `SSSSSS`, `aaaaa,ACx`"
,
(char *)0x13D,
"OOOOOOOOMMMMxxxxmmTppo------kkkk"
,
"`T` = bit(`MMMMxxxxmm,rw`, `kkkk`), bit(`MMMMxxxxmm,rw`, `kkkk`) = #1"
,
"BTSTSET `kkkk`, `MMMMxxxxmm,rw`, `T`"
,
(char *)0x13E,
(char *)0x0,
"SMBX_MS_2"
,
"SMBX_MS_2"
,
(char *)0x13F,
"OOOOOOOOMMMMxxxxmmTppo------kkkk"
,
"`T` = bit(`MMMMxxxxmm,rw`, `kkkk`), bit(`MMMMxxxxmm,rw`, `kkkk`) = #0"
,
"BTSTCLR `kkkk`, `MMMMxxxxmm,rw`, `T`"
,
(char *)0x140,
(char *)0x0,
"RMBX_MR_2"
,
"RMBX_MR_2"
,
(char *)0x141,
"OOOOOOOOMMMMxxxxmmTppo------kkkk"
,
"`T` = bit(`MMMMxxxxmm,rw`, `kkkk`), cbit(`MMMMxxxxmm,rw`, `kkkk`)"
,
"BTSTNOT `kkkk`, `MMMMxxxxmm,rw`, `T`"
,
(char *)0x142,
(char *)0x0,
"CMBX_MC_2"
,
"CMBX_MC_2"
,
(char *)0x143,
"OOOOOOOOMMMMxxxxmmqcccccppo---CC"
,
"bit(`MMMMxxxxmm,r`, `CCccccc,RLHx`) = #1"
,
"BSET `CCccccc,RLHx`, `MMMMxxxxmm,r`"
,
(char *)0x144,
"OOOOOOOOMMMMxxxxmmqcccccppo---CC"
,
"bit(`MMMMxxxxmm,r`, `CCccccc,RLHx`) = #0"
,
"BCLR `CCccccc,RLHx`, `MMMMxxxxmm,r`"
,
(char *)0x145,
"OOOOOOOOMMMMxxxxmm-cccccppo---CC"
,
"cbit(`MMMMxxxxmm,rw`, `CCccccc,RLHx`)"
,
"BNOT `CCccccc,RLHx`, `MMMMxxxxmm,rw`"
,
(char *)0x146,
"OOOOOOOOMMMMxxxxmm-ccccc-p----CC"
,
"push(`CCccccc,RLHx`, `MMMMxxxxmm,r`)"
,
"PSH `CCccccc,RLHx`, `MMMMxxxxmm,r`"
,
(char *)0x147,
"OOOOOOOOMMMMxxxxmm-aaaaa-p----AA"
,
"`AAaaaaa,RLHx`, `MMMMxxxxmm,w` = pop()"
,
"POP `AAaaaaa,RLHx`, `MMMMxxxxmm,w`"
,
(char *)0x148,
(char *)0x0,
"ST_COPR"
,
"ST_COPR"
,
(char *)0x149,
"OOOOOOOOMMMMxxxxmmqcccccpp----CC"
,
"high_byte(`MMMMxxxxmm,w`) = `CCccccc,Rx`"
,
"MOV `CCccccc,Rx`, high_byte(`MMMMxxxxmm,w`)"
,
(char *)0x14A,
"OOOOOOOOMMMMxxxxmmqcccccpp----CC"
,
"low_byte(`MMMMxxxxmm,w`) = `CCccccc,Rx`"
,
"MOV `CCccccc,Rx`, low_byte(`MMMMxxxxmm,w`)"
,
(char *)0x14B,
(char *)0x0,
"ST_DP"
,
"ST_DP"
,
(char *)0x14C,
(char *)0x0,
"ST_CDP"
,
"ST_CDP"
,
(char *)0x14D,
(char *)0x0,
"ST_BOF01"
,
"ST_BOF01"
,
(char *)0x14E,
(char *)0x0,
"ST_BOF23"
,
"ST_BOF23"
,
(char *)0x14F,
(char *)0x0,
"ST_BOF45"
,
"ST_BOF45"
,
(char *)0x150,
(char *)0x0,
"ST_BOF67"
,
"ST_BOF67"
,
(char *)0x151,
(char *)0x0,
"ST_BOFC"
,
"ST_BOFC"
,
(char *)0x152,
(char *)0x0,
"ST_SP"
,
"ST_SP"
,
(char *)0x153,
(char *)0x0,
"ST_SSP"
,
"ST_SSP"
,
(char *)0x154,
(char *)0x0,
"ST_BK03"
,
"ST_BK03"
,
(char *)0x155,
(char *)0x0,
"ST_BK47"
,
"ST_BK47"
,
(char *)0x156,
(char *)0x0,
"ST_BKC"
,
"ST_BKC"
,
(char *)0x157,
(char *)0x0,
"ST_MDP"
,
"ST_MDP"
,
(char *)0x158,
(char *)0x0,
"ST_MDP05"
,
"ST_MDP05"
,
(char *)0x159,
(char *)0x0,
"ST_MDP67"
,
"ST_MDP67"
,
(char *)0x15A,
(char *)0x0,
"ST_PDP"
,
"ST_PDP"
,
(char *)0x15B,
(char *)0x0,
"ST_CSR"
,
"ST_CSR"
,
(char *)0x15C,
(char *)0x0,
"ST_BRC0"
,
"ST_BRC0"
,
(char *)0x15D,
(char *)0x0,
"ST_BRC1"
,
"ST_BRC1"
,
(char *)0x15E,
(char *)0x0,
"ST_TRN0"
,
"ST_TRN0"
,
(char *)0x15F,
(char *)0x0,
"ST_TRN1"
,
"ST_TRN1"
,
(char *)0x160,
"OOOOOoKKMMMMxxxxmmKKKKKK"
,
"`MMMMxxxxmm,w` = `KKKKKKKK`"
,
"MOV `KKKKKKKK`, `MMMMxxxxmm,w`"
,
(char *)0x161,
(char *)0x0,
"ST_RM_ASM"
,
"ST_RM_ASM"
,
(char *)0x162,
(char *)0x0,
"STH_R_RM_ASM"
,
"STH_R_RM_ASM"
,
(char *)0x163,
"OOOOOOOOMMMMxxxxmm%ccccc@p$---Iq-NNnnnnn"
,
"`MMMMxxxxmm,w` = `I`(`@,(``$,(``%,(``ccccc,ACx` << `NNnnnnn,SRx``%,)``$,)``@,)`)"
,
"MOV `$,(``%,(``I`(`@,(``ccccc,ACx` << `NNnnnnn,SRx``@,)`)`%,)``$,)`, `MMMMxxxxmm,w`"
,
(char *)0x164,
(char *)0x0,
"STH_R_RM"
,
"STH_R_RM"
,
(char *)0x165,
"OOOOOOOOMMMMxxxxmm%ccccc@p$---Iq"
,
"`MMMMxxxxmm,w` = `I`(`@,(``$,(``%,(``ccccc,ACx``%,)``$,)``@,)`)"
,
"MOV `$,(``%,(``I`(`@,(``ccccc,ACx``@,)`)`%,)``$,)`, `MMMMxxxxmm,w`"
,
(char *)0x166,
(char *)0x0,
"ST_RM_SH"
,
"ST_RM_SH"
,
(char *)0x167,
(char *)0x0,
"STH_RM_SH"
,
"STH_RM_SH"
,
(char *)0x168,
(char *)0x0,
"DST_COPR"
,
"DST_COPR"
,
(char *)0x169,
(char *)0x0,
"DST_RPC"
,
"DST_RPC"
,
(char *)0x16A,
(char *)0x0,
"DST_XR"
,
"DST_XR"
,
(char *)0x16B,
(char *)0x0,
"DST_RDLM"
,
"DST_RDLM"
,
(char *)0x16C,
"OOOOOOOOMMMMxxxxmm%ccccc@p$----q"
,
"dbl(`MMMMxxxxmm,dw`) = `@,(``$,(``%,(``ccccc,ACx``%,)``$,)``@,)`"
,
"MOV `$,(``%,(``@,(``ccccc,ACx``@,)``%,)``$,)`, dbl(`MMMMxxxxmm,dw`)"
,
(char *)0x16D,
"OOOOOOOOMMMMxxxxmmqccccc-p----CC"
,
"HI(`MMMMxxxxmm,dw`) = `CCccccc,RL`, LO(`MMMMxxxxmm,dw`) = `CCccccc,RLP`"
,
"MOV pair(`CCccccc,RLHx`), dbl(`MMMMxxxxmm,dw`)"
,
(char *)0x16E,
"OOOOOOOOMMMMxxxxmm-ccccc"
,
"HI(`MMMMxxxxmm,w`) = HI(`ccccc,ACx`) >> #1, LO(`MMMMxxxxmm,w`) = LO(`ccccc,ACx`) >> #1"
,
"MOV `ccccc,ACx` >> #1, dbl(`MMMMxxxxmm,w`)"
,
(char *)0x16F,
(char *)0x0,
"DST_RDLM_HI"
,
"DST_RDLM_HI"
,
(char *)0x170,
(char *)0x0,
"DST_RDLM_LO"
,
"DST_RDLM_LO"
,
(char *)0x171,
"OOOOOOOOMMMMxxxxmmqaaaaappo---AA"
,
"bit(`AAaaaaa,Rx`, `MMMMxxxxmm,baddr`) = #1"
,
"BSET `MMMMxxxxmm,baddr`, `AAaaaaa,Rx`"
,
(char *)0x172,
"OOOOOOOOMMMMxxxxmmqaaaaappo---AA"
,
"bit(`AAaaaaa,Rx`, `MMMMxxxxmm,baddr`) = #0"
,
"BCLR `MMMMxxxxmm,baddr`, `AAaaaaa,Rx`"
,
(char *)0x173,
"OOOOOOOOMMMMxxxxmm-cccccppo---CC"
,
"TC1,TC2 = bit(`CCccccc,Rx`, `MMMMxxxxmm,baddr`)"
,
"BTSTP `MMMMxxxxmm,baddr`, `CCccccc,Rx`"
,
(char *)0x174,
"OOOOOOOOMMMMxxxxmm-aaaaappo---AA"
,
"cbit(`AAaaaaa,Rx`, `MMMMxxxxmm,baddr`)"
,
"BNOT `MMMMxxxxmm,baddr`, `AAaaaaa,Rx`"
,
(char *)0x175,
"OOOOOOOOMMMMxxxxmmTcccccppo---CC"
,
"`T` = bit(`CCccccc,Rx`, `MMMMxxxxmm,baddr`)"
,
"BTST `MMMMxxxxmm,baddr`, `CCccccc,Rx`, `T`"
,
(char *)0x176,
"OOOOOOOOMMMMxxxxmmoaaaaa"
,
"`aaaaa,XDAx` = mar(`MMMMxxxxmm,r`)"
,
"AMAR `MMMMxxxxmm,r`, `aaaaa,XDAx`"
,
(char *)0x177,
"OOOOOOOOMMMMxxxxmm-aaaaapp-ccccc"
,
"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` + dbl(`MMMMxxxxmm,dr`)`q_SAT,)`"
,
"ADD`q_SAT` dbl(`MMMMxxxxmm,dr`), `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x178,
"OOOOOOOOMMMMxxxxmm-aaaaapp-ccccc"
,
"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` - dbl(`MMMMxxxxmm,dr`)`q_SAT,)`"
,
"SUB`q_SAT` dbl(`MMMMxxxxmm,dr`), `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x179,
"OOOOOOOOMMMMxxxxmm-aaaaapp-ccccc"
,
"`aaaaa,ACx` = `q_SAT,(`dbl(`MMMMxxxxmm,dr`) - `ccccc,ACx``q_SAT,)`"
,
"SUB`q_SAT` `ccccc,ACx`, dbl(`MMMMxxxxmm,dr`), `aaaaa,ACx`"
,
(char *)0x17A,
(char *)0x0,
"DLD_RPC"
,
"DLD_RPC"
,
(char *)0x17B,
"OOOOOOOOMMMMxxxxmm4aaaaa"
,
"`aaaaa,ACx` = `q_SAT,(``4,(`dbl(`MMMMxxxxmm,dr`)`4,)``q_SAT,)`"
,
"MOV`q_SAT``4` dbl(`MMMMxxxxmm,dr`), `aaaaa,ACx`"
,
(char *)0x17C,
"OOOOOOOOMMMMxxxxmmqaaaaa-p----00"
,
"`aaaaa,ACx` = `q_SAT,(`HI(`MMMMxxxxmm,dr`)<<#16`q_SAT,)`, `aaaaa,ACxP` = `q_SAT,(`LO(`MMMMxxxxmm,dr`)<<#16`q_SAT,)`"
,
"MOV`q_SAT` dbl(`MMMMxxxxmm,dr`), pair(HI(`aaaaa,ACx`))"
,
(char *)0x17D,
(char *)0x0,
"DLD_RDLM_LO"
,
"DLD_RDLM_LO"
,
(char *)0x17E,
"OOOOOOOOMMMMxxxxmmqaaaaa-p----AA"
,
"`AAaaaaa,Rx` = HI(`MMMMxxxxmm,dr`), `AAaaaaa,RxP` = LO(`MMMMxxxxmm,dr`)"
,
"MOV dbl(`MMMMxxxxmm,dr`), pair(`AAaaaaa,RLHx`)"
,
(char *)0x17F,
(char *)0x0,
"DLD_XR"
,
"DLD_XR"
,
(char *)0x180,
"OOOOOOOOMMMMxxxxmm-aaaaappoccccc"
,
"HI(`aaaaa,ACx`) = `q_SAT,(`HI(`MMMMxxxxmm,r`) + HI(`ccccc,ACx`)`q_SAT,)`, LO(`aaaaa,ACx`) = `q_SAT,(`LO(`MMMMxxxxmm,r`) + LO(`ccccc,ACx`)`q_SAT,)`"
,
"ADD`q_SAT` dual(`MMMMxxxxmm,r`), `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x181,
"OOOOOOOOMMMMxxxxmm-aaaaappoccccc"
,
"HI(`aaaaa,ACx`) = `q_SAT,(`HI(`ccccc,ACx`) - HI(`MMMMxxxxmm,r`)`q_SAT,)`, LO(`aaaaa,ACx`) = `q_SAT,(`LO(`ccccc,ACx`) - LO(`MMMMxxxxmm,r`)`q_SAT,)`"
,
"SUB`q_SAT` dual(`MMMMxxxxmm,r`), `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x182,
"OOOOOOOOMMMMxxxxmm-aaaaappoccccc"
,
"HI(`aaaaa,ACx`) = `q_SAT,(`HI(`MMMMxxxxmm,r`) - HI(`ccccc,ACx`)`q_SAT,)`, LO(`aaaaa,ACx`) = `q_SAT,(`LO(`MMMMxxxxmm,r`) - LO(`ccccc,ACx`)`q_SAT,)`"
,
"SUB`q_SAT` `ccccc,ACx`, dual(`MMMMxxxxmm,r`), `aaaaa,ACx`"
,
(char *)0x183,
"OOOOOOOOMMMMxxxxmm-aaaaappo100cc"
,
"HI(`aaaaa,ACx`) = `q_SAT,(``cc,Tx` - HI(`MMMMxxxxmm,r`)`q_SAT,)`, LO(`aaaaa,ACx`) = `q_SAT,(``cc,Tx` - LO(`MMMMxxxxmm,r`)`q_SAT,)`"
,
"SUB`q_SAT` dual(`MMMMxxxxmm,r`), `cc,Tx`, `aaaaa,ACx`"
,
(char *)0x184,
"OOOOOOOOMMMMxxxxmm-aaaaappo100cc"
,
"HI(`aaaaa,ACx`) = `q_SAT,(`HI(`MMMMxxxxmm,r`) + `cc,Tx``q_SAT,)`, LO(`aaaaa,ACx`) = `q_SAT,(`LO(`MMMMxxxxmm,r`) + `cc,Tx``q_SAT,)`"
,
"ADD`q_SAT` dual(`MMMMxxxxmm,r`), `cc,Tx`, `aaaaa,ACx`"
,
(char *)0x185,
"OOOOOOOOMMMMxxxxmm-aaaaappo100cc"
,
"HI(`aaaaa,ACx`) = `q_SAT,(`HI(`MMMMxxxxmm,r`) - `cc,Tx``q_SAT,)`, LO(`aaaaa,ACx`) = `q_SAT,(`LO(`MMMMxxxxmm,r`) - `cc,Tx``q_SAT,)`"
,
"SUB`q_SAT` `cc,Tx`, dual(`MMMMxxxxmm,r`), `aaaaa,ACx`"
,
(char *)0x186,
"OOOOOOOOMMMMxxxxmmqaaaaa-po100cc"
,
"HI(`aaaaa,ACx`) = `q_SAT,(`HI(`MMMMxxxxmm,r`) + `cc,Tx``q_SAT,)`, LO(`aaaaa,ACx`) = `q_SAT,(`LO(`MMMMxxxxmm,r`) - `cc,Tx``q_SAT,)`"
,
"ADDSUB`q_SAT` `cc,Tx`, dual(`MMMMxxxxmm,r`), `aaaaa,ACx`"
,
(char *)0x187,
"OOOOOOOOMMMMxxxxmmqaaaaa-po100cc"
,
"HI(`aaaaa,ACx`) = `q_SAT,(`HI(`MMMMxxxxmm,r`) - `cc,Tx``q_SAT,)`, LO(`aaaaa,ACx`) = `q_SAT,(`LO(`MMMMxxxxmm,r`) + `cc,Tx``q_SAT,)`"
,
"SUBADD`q_SAT` `cc,Tx`, dual(`MMMMxxxxmm,r`), `aaaaa,ACx`"
,
(char *)0x188,
"OOOOOOOOMMMMxxxxmmq-po---YYYyyyy"
,
"`MMMMxxxxmm,w` = `YYYyyyy,r`"
,
"MOV `YYYyyyy,r`, `MMMMxxxxmm,w`"
,
(char *)0x189,
"OOOOOOOOMMMMxxxxmmq-po---YYYyyyy"
,
"`YYYyyyy,w` = `MMMMxxxxmm,r`"
,
"MOV `MMMMxxxxmm,r`, `YYYyyyy,w`"
,
(char *)0x18A,
"OOOOOOOOMMMMxxxxmmq-po---YYYyyyy"
,
"dbl(`MMMMxxxxmm,dw`) = dbl(`YYYyyyy,r`)"
,
"MOV dbl(`YYYyyyy,r`), dbl(`MMMMxxxxmm,dw`)"
,
(char *)0x18B,
"OOOOOOOOMMMMxxxxmmq-po---YYYyyyy"
,
"dbl(`YYYyyyy,w`) = dbl(`MMMMxxxxmm,dr`)"
,
"MOV dbl(`MMMMxxxxmm,dr`), dbl(`YYYyyyy,w`)"
,
(char *)0x18C,
"OOOOOOOOMMMMxxxxmmT-poJJKKKKKKKKKKKKKKKK"
,
"`T` = (`MMMMxxxxmm,r` `JJ` `KKKKKKKKKKKKKKKK`)"
,
"CMP `MMMMxxxxmm,r` `JJ` `KKKKKKKKKKKKKKKK`, `T`"
,
(char *)0x18D,
(char *)0x0,
"CMPM_MWK_2"
,
"CMPM_MWK_2"
,
(char *)0x18E,
"OOOOOOOOMMMMxxxxmmT-p---kkkkkkkkkkkkkkkk"
,
"`T` = `MMMMxxxxmm,r` & `kkkkkkkkkkkkkkkk`"
,
"BAND `MMMMxxxxmm,r`, `kkkkkkkkkkkkkkkk`, `T`"
,
(char *)0x18F,
(char *)0x0,
"BITF_MWK_2"
,
"BITF_MWK_2"
,
(char *)0x190,
"OOOOOOOOMMMMxxxxmmqppo--kkkkkkkkkkkkkkkk"
,
"`MMMMxxxxmm,rw` = `MMMMxxxxmm,rw` & `kkkkkkkkkkkkkkkk`"
,
"AND `kkkkkkkkkkkkkkkk`, `MMMMxxxxmm,rw`"
,
(char *)0x191,
"OOOOOOOOMMMMxxxxmmqppo--kkkkkkkkkkkkkkkk"
,
"`MMMMxxxxmm,rw` = `MMMMxxxxmm,rw` | `kkkkkkkkkkkkkkkk`"
,
"OR `kkkkkkkkkkkkkkkk`, `MMMMxxxxmm,rw`"
,
(char *)0x192,
"OOOOOOOOMMMMxxxxmmqppo--kkkkkkkkkkkkkkkk"
,
"`MMMMxxxxmm,rw` = `MMMMxxxxmm,rw` ^ `kkkkkkkkkkkkkkkk`"
,
"XOR `kkkkkkkkkkkkkkkk`, `MMMMxxxxmm,rw`"
,
(char *)0x193,
"OOOOOOOOMMMMxxxxmmqppo--KKKKKKKKKKKKKKKK"
,
"`MMMMxxxxmm,rw` = `q_SAT,(``MMMMxxxxmm,rw` + `KKKKKKKKKKKKKKKK``q_SAT,)`"
,
"ADD`q_SAT` `KKKKKKKKKKKKKKKK`, `MMMMxxxxmm,rw`"
,
(char *)0x194,
"OOOOOOO3MMMMxxxxmm%aaaaa-p/-----KKKKKKKK"
,
"`aaaaa,ACx` = `%,(``/,(``MMMMxxxxmm,r` * `KKKKKKKK``/,)``%,)``MMMMxxxxmm3,3r`"
,
"MPYMK`/``%` `3``MMMMxxxxmm,r`, `KKKKKKKK`, `aaaaa,ACx`"
,
(char *)0x195,
"OOOOOOO3MMMMxxxxmm%aaaaa-p/cccccKKKKKKKK"
,
"`aaaaa,ACx` = `q_SAT,(``%,(``ccccc,ACx` + `/,(``MMMMxxxxmm,r` * `KKKKKKKK``/,)``%,)``q_SAT,)``MMMMxxxxmm3,3r`"
,
"MACMK`/``q_SAT``%` `3``MMMMxxxxmm,r`, `KKKKKKKK`, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x196,
"OOOOOOOOMMMMxxxxmm$aaaaapp-cccccqqSSSSSS"
,
"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` + (`$,(``MMMMxxxxmm,r``$,)` << `SSSSSS`)`q_SAT,)`"
,
"ADD`q_SAT` `$,(``MMMMxxxxmm,r``$,)` << `SSSSSS`, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x197,
"OOOOOOOOMMMMxxxxmm$aaaaapp-cccccqqSSSSSS"
,
"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` - (`$,(``MMMMxxxxmm,r``$,)` << `SSSSSS`)`q_SAT,)`"
,
"SUB`q_SAT` `$,(``MMMMxxxxmm,r``$,)` << `SSSSSS`, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x198,
"OOOOOOOOMMMMxxxxmm$aaaaapp------qqSSSSSS"
,
"`aaaaa,ACx` = `q_SAT,(``$,(``MMMMxxxxmm,r``$,)` << `SSSSSS``q_SAT,)`"
,
"MOV`q_SAT` `$,(``MMMMxxxxmm,r``$,)` << `SSSSSS`, `aaaaa,ACx`"
,
(char *)0x199,
(char *)0x0,
"STHS_RM_SHS"
,
"STHS_RM_SHS"
,
(char *)0x19A,
"OOOOOOOOMMMMxxxxmm%ccccc@p$---Iq--SSSSSS"
,
"`MMMMxxxxmm,w` = `I`(`@,(``$,(``%,(``ccccc,ACx` << `SSSSSS``%,)``$,)``@,)`)"
,
"MOV `$,(``%,(``I`(`@,(``ccccc,ACx` << `SSSSSS``@,)`)`%,)``$,)`, `MMMMxxxxmm,w`"
,
(char *)0x19B,
"OOOOOOOOMMMMxxxxmmqppo--iiiiiiiiiiiiiiii"
,
"`MMMMxxxxmm,w` = `iiiiiiiiiiiiiiii`"
,
"MOV `iiiiiiiiiiiiiiii`, `MMMMxxxxmm,w`"
,
(char *)0x19C,
"OOOOOOOOMMMMxxxxmm------LLLLLLLLLLLLLLLL"
,
"if (`MMMMxxxxmm,r` != #0) goto `LLLLLLLLLLLLLLLL`"
,
"BCC `LLLLLLLLLLLLLLLL`, `MMMMxxxxmm,r` != #0"
,
(char *)0x19D,
"OOOOOOOop-Aaaaaap-Cccccc"
,
"`Aaaaaa,XRx` = `Cccccc,XRx`"
,
"MOV `Cccccc,XRx`, `Aaaaaa,XRx`"
,
(char *)0x19E,
(char *)0x0,
"FAR"
,
"FAR"
,
(char *)0x19F,
(char *)0x0,
"LOCAL"
,
"LOCAL"
,
(char *)0x1A0,
(char *)0x0,
"MAR_XAR_AX"
,
"MAR_XAR_AX"
,
(char *)0x1A1,
(char *)0x0,
"MAR_XAR_MX"
,
"MAR_XAR_MX"
,
(char *)0x1A2,
(char *)0x0,
"MAR_XAR_SX"
,
"MAR_XAR_SX"
,
(char *)0x1A3,
(char *)0x0,
"MAR_XAR_AY"
,
"MAR_XAR_AY"
,
(char *)0x1A4,
(char *)0x0,
"MAR_XAR_MY"
,
"MAR_XAR_MY"
,
(char *)0x1A5,
(char *)0x0,
"MAR_XAR_SY"
,
"MAR_XAR_SY"
,
(char *)0x1A6,
(char *)0x0,
"USR"
,
"USR"
,
(char *)0x1A7,
(char *)0x0,
"MMAP_USR"
,
"MMAP_USR"
,
(char *)0x1A8,
"OOOOOOpp"
,
"LOCK"
,
"LOCK"
,
(char *)0x1A9,
(char *)0x0,
"BR_USR"
,
"BR_USR"
,
(char *)0x1AA,
"OOOOOOOOpXXXxxxxp--aaaaa1YYYyyyy/--bbbbb"
,
"lmsf`/,a``q_SAT,a`(`XXXxxxx,r`, `YYYyyyy,r`, `aaaaa,ACx`, `bbbbb,ACx`)"
,
"LMSF`/``q_SAT` `XXXxxxx,r`, `YYYyyyy,r`, `aaaaa,ACx`, `bbbbb,ACx`"
,
(char *)0x1AB,
"OOOOOOO3MMMMxxxxmm%aaaaapp$-------#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``MMMMxxxxmm,r``$,)` * `#,(``ZZZzzzz,r``#,)``/,)``%,)``4,)``q_SAT,)``MMMMxxxxmm3,3r`"
,
"MPYM`/``q_SAT``%``4` `3``$,(``MMMMxxxxmm,r``$,)`, `#,(``ZZZzzzz,r``#,)`, `aaaaa,ACx`"
,
(char *)0x1AC,
"OOOOOOO3MMMMxxxxmm%aaaaapp$-------#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/,(``$,(``MMMMxxxxmm,r``$,)` * `#,(``ZZZzzzz,r``#,)``/,)``%,)``4,)``q_SAT,)``MMMMxxxxmm3,3r`"
,
"MACM`/``q_SAT``%``4` `3``$,(``MMMMxxxxmm,r``$,)`, `#,(``ZZZzzzz,r``#,)`, `aaaaa,ACx`"
,
(char *)0x1AD,
"OOOOOOO3MMMMxxxxmm%aaaaapp$-------#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/,(``$,(``MMMMxxxxmm,r``$,)` * `#,(``ZZZzzzz,r``#,)``/,)``%,)``4,)``q_SAT,)``MMMMxxxxmm3,3r`"
,
"MASM`/``q_SAT``%``4` `3``$,(``MMMMxxxxmm,r``$,)`, `#,(``ZZZzzzz,r``#,)`, `aaaaa,ACx`"
,
(char *)0x1AE,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`"
,
"MPY`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MPY`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(char *)0x1AF,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`"
,
"MAC`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MPY`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(char *)0x1B0,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` + `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
"MPY`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(char *)0x1B1,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`"
,
"MAS`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MPY`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(char *)0x1B2,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` - `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
"MPY`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAS`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(char *)0x1B3,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` + `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
"MAC`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(char *)0x1B4,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` + `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
"MAS`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(char *)0x1B5,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` - `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
"MAC`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAS`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(char *)0x1B6,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(`(`aaaaa,ACx` >> #16) + `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` + `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
"MAC`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` >> #16 :: MAC`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(char *)0x1B7,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(`(`bbbbb,ACx` >> #16) + `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
"MAS`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx` >> #16"
,
(char *)0x1B8,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(`(`bbbbb,ACx` >> #16) + `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
"MPY`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx` >> #16"
,
(char *)0x1B9,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(`(`aaaaa,ACx` >> #16) + `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(`(`bbbbb,ACx` >> #16) + `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
"MAC`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` >> #16 :: MAC`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx` >> #16"
,
(char *)0x1BA,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` - `/`(`$,(``MMMMxxxxmm,r``$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
"MAS`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAS`/``q_SAT``%``4` `$,(``MMMMxxxxmm,r``$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(char *)0x1BB,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`"
,
"MPY`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MPY`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(char *)0x1BC,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/`(`$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`"
,
"MAC`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MPY`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(char *)0x1BD,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` + `/`(`$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
"MPY`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(char *)0x1BE,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/`(`$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`"
,
"MAS`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MPY`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(char *)0x1BF,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` - `/`(`$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
"MPY`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAS`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(char *)0x1C0,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/`(`$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` + `/`(`$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
"MAC`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(char *)0x1C1,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/`(`$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` + `/`(`$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
"MAS`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(char *)0x1C2,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/`(`$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` - `/`(`$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
"MAC`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAS`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(char *)0x1C3,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(`(`aaaaa,ACx` >> #16) + `/`(`$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` + `/`(`$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
"MAC`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` >> #16 :: MAC`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(char *)0x1C4,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/`(`$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(`(`bbbbb,ACx` >> #16) + `/`(`$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
"MAS`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx` >> #16"
,
(char *)0x1C5,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(`(`bbbbb,ACx` >> #16) + `/`(`$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
"MPY`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx` >> #16"
,
(char *)0x1C6,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(`(`aaaaa,ACx` >> #16) + `/`(`$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(`(`bbbbb,ACx` >> #16) + `/`(`$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
"MAC`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` >> #16 :: MAC`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx` >> #16"
,
(char *)0x1C7,
"OOOOOOOoMMMMxxxxmm%aaaaapp$bbbbbqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/`(`$,(`LO(`MMMMxxxxmm,r`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` - `/`(`$,(`HI(`MMMMxxxxmm,r`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)`)`%,)``4,)``q_SAT,)`"
,
"MAS`/``q_SAT``%``4` `$,(`LO(`MMMMxxxxmm,r`)`$,)`, `#,(`LO(`ZZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAS`/``q_SAT``%``4` `$,(`HI(`MMMMxxxxmm,r`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(char *)0x1C8,
(char *)0x0,
"DBLCOEF"
,
"DBLCOEF"
,
(char *)0x1C9,
"OOOOOOOOpp-aaaaakkkkkkkkkkkkkkkkkkkkkkkk"
,
"mar(`aaaaa,XDAx` + `kkkkkkkkkkkkkkkkkkkkkkkk`)"
,
"AADD `kkkkkkkkkkkkkkkkkkkkkkkk`, `aaaaa,XDAx`"
,
(char *)0x1CA,
"OOOOOOOOpp-aaaaakkkkkkkkkkkkkkkkkkkkkkkk"
,
"mar(`aaaaa,XDAx` = `kkkkkkkkkkkkkkkkkkkkkkkk`)"
,
"AMOV `kkkkkkkkkkkkkkkkkkkkkkkk`, `aaaaa,XDAx`"
,
(char *)0x1CB,
"OOOOOOOOpp-aaaaakkkkkkkkkkkkkkkkkkkkkkkk"
,
"mar(`aaaaa,XDAx` - `kkkkkkkkkkkkkkkkkkkkkkkk`)"
,
"ASUB `kkkkkkkkkkkkkkkkkkkkkkkk`, `aaaaa,XDAx`"
,
(char *)0x1CC,
"OOOOOOOOMMMMxxxxmmq--o--"
,
"mar(byte(`MMMMxxxxmm,br`))"
,
"AMAR byte(`MMMMxxxxmm,br`)"
,
(char *)0x1CD,
"OOOOOOO$JCCcccccJDDdddddLLLLLLLLLLLLLLLL"
,
"compare (`$,(``CCccccc,RAx` `JJ` `DDddddd,RAx``$,)`) goto `LLLLLLLLLLLLLLLL`"
,
"BCC`$` `LLLLLLLLLLLLLLLL`, `CCccccc,RAx` `JJ` `DDddddd,RAx`"
,
(char *)0x1CE,
"OOOOOOqqMMMMxxxxmm$aaaaa"
,
"HI(`aaaaa,ACx`) = `q_SAT,(``$,(``MMMMxxxxmm,r``$,)``q_SAT,)`"
,
"MOV`q_SAT` `$,(``MMMMxxxxmm,r``$,)`, `aaaaa,ACx`.H"
,
(char *)0x1CF,
"OOOOOOqqMMMMxxxxmm$aaaaa"
,
"LO(`aaaaa,ACx`) = `q_SAT,(``$,(``MMMMxxxxmm,r``$,)``q_SAT,)`"
,
"MOV`q_SAT` `$,(``MMMMxxxxmm,r``$,)`, `aaaaa,ACx`.L"
,
(char *)0x1D0,
"OOOOOpAAMMMMxxxxmmAaaaaa"
,
"copy(`AAAaaaaa,ALLx` = `AAAaaaaa,d(ALLx``MMMMxxxxmm,!AAAaaaaa!r``AAAaaaaa,)ALLx`)"
,
"COPY `AAAaaaaa,d(ALLx``MMMMxxxxmm,!AAAaaaaa!r``AAAaaaaa,)ALLx`, `AAAaaaaa,ALLx`"
,
(char *)0x1D1,
"OOOOOOOOAAAaaaaakkkkkkkkkkkkkkkk"
,
"`AAAaaaaa,ADRx` = `kkkkkkkkkkkkkkkk`"
,
"MOV `kkkkkkkkkkkkkkkk`, `AAAaaaaa,ADRx`"
,
(char *)0x1D2,
"OOOOOOOpAAAaaaaakkkkkkkkkkkkkkkkkkkkkkkk"
,
"copy(`AAAaaaaa,ALLx` = `AAAaaaaa,d(ALLx``kkkkkkkkkkkkkkkkkkkkkkkk,m``AAAaaaaa,)ALLx`)"
,
"COPY `AAAaaaaa,d(ALLx``kkkkkkkkkkkkkkkkkkkkkkkk,m``AAAaaaaa,)ALLx`, `AAAaaaaa,ALLx`"
,
(char *)0x1D3,
"OOOOOOOOMMMMxxxxmm-aaaaapp$---AA"
,
"`AAaaaaa,RA` = `$,(`byte(`MMMMxxxxmm,br`)`$,)`"
,
"MOV `$,(`byte(`MMMMxxxxmm,br`)`$,)`, `AAaaaaa,RA`"
,
(char *)0x1D4,
(char *)0x0,
"MV_COPR"
,
"MV_COPR"
,
(char *)0x1D5,
"OOOOOOOop00aaaaapCCccccc"
,
"`aaaaa,ACx` = `q_SAT,(``CCccccc,RLHx` << #16`q_SAT,)`"
,
"MOV`q_SAT` `CCccccc,RLHx` << #16, `aaaaa,ACx`"
,
(char *)0x1D6,
"OOOOOOOOMMMMxxxxmmq-po---YYYyyyy"
,
"byte(`MMMMxxxxmm,bw`) = byte(`YYYyyyy,r`)"
,
"MOV byte(`YYYyyyy,r`), byte(`MMMMxxxxmm,bw`)"
,
(char *)0x1D7,
"OOOOOOOOMMMMxxxxmmq-po---YYYyyyy"
,
"byte(`YYYyyyy,w`) = byte(`MMMMxxxxmm,br`)"
,
"MOV byte(`MMMMxxxxmm,br`), byte(`YYYyyyy,w`)"
,
(char *)0x1D8,
"OOOOOOOOpCCcccccpkkkkkkko-$-JJ-T"
,
"`T` = `$`(`CCccccc,Rx` `JJ` `kkkkkkk`)"
,
"CMP`$` `CCccccc,Rx` `JJ` `kkkkkkk`, `T`"
,
(char *)0x1D9,
"OOOOOOOOpXXXxxxxp1Aaaaaa-YYYyyyy"
,
"`Aaaaaa,ACLHx` = `q_SAT,(``XXXxxxx,r` + `YYYyyyy,r``q_SAT,)`"
,
"ADD`q_SAT` `XXXxxxx,r`, `YYYyyyy,r`, `Aaaaaa,ACLHx`"
,
(char *)0x1DA,
"OOOOOOOOpXXXxxxxp1Aaaaaa-YYYyyyy"
,
"`Aaaaaa,ACLHx` = `q_SAT,(``XXXxxxx,r` - `YYYyyyy,r``q_SAT,)`"
,
"SUB`q_SAT` `XXXxxxx,r`, `YYYyyyy,r`, `Aaaaaa,ACLHx`"
,
(char *)0x1DB,
"OOOOOOOOppqq----"
,
"return || far()"
,
"FRET"
,
(char *)0x1DC,
"OOOOOOpp"
,
"SAT"
,
"SAT"
,
(char *)0x1DD,
"OOOOOpCCMMMMxxxxmmCccccc"
,
"`CCCccccc,d(ALLx``MMMMxxxxmm,!CCCccccc!w``CCCccccc,)ALLx` = `CCCccccc,ALLx`"
,
"MOV `CCCccccc,ALLx`, `CCCccccc,d(ALLx``MMMMxxxxmm,!CCCccccc!w``CCCccccc,)ALLx`"
,
(char *)0x1DE,
"OOOOOOOpCCCccccckkkkkkkkkkkkkkkkkkkkkkkk"
,
"`CCCccccc,d(ALLx``kkkkkkkkkkkkkkkkkkkkkkkk,m``CCCccccc,)ALLx` = `CCCccccc,ALLx`"
,
"MOV `CCCccccc,ALLx`, `CCCccccc,d(ALLx``kkkkkkkkkkkkkkkkkkkkkkkk,m``CCCccccc,)ALLx`"
,
(char *)0x1DF,
"OOOOOoiiMMMMxxxxmmiiiiii"
,
"byte(`MMMMxxxxmm,bw`) = `iiiiiiii`"
,
"MOV `iiiiiiii`, byte(`MMMMxxxxmm,bw`)"
,
(char *)0x1E0,
"OOOOOOOOMMMMxxxxmm-cccccpp----CC"
,
"byte(`MMMMxxxxmm,bw`) = `CCccccc,RA`"
,
"MOV `CCccccc,RA`, byte(`MMMMxxxxmm,bw`)"
,
(char *)0x1E1,
"OOOOOOpp"
,
"if (!TC1) execute(D_unit) ||"
,
"XCCPART !TC1 ||"
,
(char *)0x1E2,
"OOOOOOpp"
,
"if (TC1) execute(D_unit) ||"
,
"XCCPART TC1 ||"
,
(char *)0x1E3,
"OOOOOOpp"
,
"XPORT_READ"
,
"XPORT_READ"
,
(char *)0x1E4,
"OOOOOOpp"
,
"XPORT_WRITE"
,
"XPORT_WRITE"
,
(char *)0x1E5,
"OOOOOOOOppqq----"
,
"to_word()"
,
"to_word"
,
(char *)0x1E6,
"OOOOOOOOppqq----"
,
"to_byte()"
,
"to_byte"
,
(char *)0x1E7,
"OOOOOOOOkkkkkkkk"
,
"ecopr(`kkkkkkkk`)"
,
"ECOPR__"
,
(char *)0x1E8,
"OOOOOOOOp-------p0-000cc0-------qq-000aa0-------kkkkkkkk"
,
"`aa,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `cc,ACx`, `aa,ACx`)"
,
"COPR_1`q_SAT` `kkkkkkkk`, `cc,ACx`, `aa,ACx`"
,
(char *)0x1E9,
"OOOOOOOOp-------p0-000aa0-------qq-000bb0-------kkkkkkkk"
,
"`aa,ACx`, `bb,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `aa,ACx`, `bb,ACx`)"
,
"COPR_2`q_SAT` `kkkkkkkk`, `aa,ACx`, `bb,ACx`"
,
(char *)0x1EA,
"OOOOOOOOMMMMxxxxmm-000ccpp-000aaqq------0-------kkkkkkkk"
,
"`aa,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `cc,ACx`, `MMMMxxxxmm,r`)"
,
"COPR_M`q_SAT` `kkkkkkkk`, `cc,ACx`, `MMMMxxxxmm,r`, `aa,ACx`"
,
(char *)0x1EB,
"OOOOOOOOMMMMxxxxmm1000aapp-000bbqq------1ZZZzzzzkkkkkkkk"
,
"`aa,ACx`, `bb,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `MMMMxxxxmm,r`, dbl(`ZZZzzzz,r`))"
,
"COPR_MZ`q_SAT` `kkkkkkkk`, `MMMMxxxxmm,r`, dbl(`ZZZzzzz,r`), `aa,ACx`, `bb,ACx`"
,
(char *)0x1EC,
"OOOOOOOOMMMMxxxxmm-000ccpp-000aaqq------0-------kkkkkkkk"
,
"`aa,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `cc,ACx`, dbl(`MMMMxxxxmm,dr`))"
,
"COPR_LM`q_SAT` `kkkkkkkk`, `cc,ACx`, dbl(`MMMMxxxxmm,dr`), `aa,ACx`"
,
(char *)0x1ED,
"OOOOOOOOMMMMxxxxmm1000aapp-000bbqq------1ZZZzzzzkkkkkkkk"
,
"`aa,ACx`, `bb,ACx` = copr`q_SAT,a`(`kkkkkkkk`, dbl(`MMMMxxxxmm,dr`), dbl(`ZZZzzzz,r`))"
,
"COPR_LMZ1`q_SAT` `kkkkkkkk`, dbl(`MMMMxxxxmm,dr`), dbl(`ZZZzzzz,r`), `aa,ACx`, `bb,ACx`"
,
(char *)0x1EE,
"OOOOOOOOMMMMxxxxmm1000aapp-000bbqq------1ZZZzzzzkkkkkkkk"
,
"`aa,ACx`, `bb,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `aa,ACx`, `bb,ACx`, dbl(`MMMMxxxxmm,r`), dbl(`ZZZzzzz,dr`))"
,
"COPR_LMZ2`q_SAT` `kkkkkkkk`, `aa,ACx`, `bb,ACx`, dbl(`MMMMxxxxmm,dr`), dbl(`ZZZzzzz,r`), `aa,ACx`, `bb,ACx`"
,
(char *)0x1EF,
"OOOOOOOOpXXXxxxxp1-000cc1YYYyyyyqq-000aa0-------kkkkkkkk"
,
"`aa,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `cc,ACx`, `XXXxxxx,r`, `YYYyyyy,r`)"
,
"COPR_XY1`q_SAT` `kkkkkkkk`, `cc,ACx`, `XXXxxxx,r`, `YYYyyyy,r`, `aa,ACx`"
,
(char *)0x1F0,
"OOOOOOOOpXXXxxxxp1-000aa1YYYyyyyqq-000bb0-------kkkkkkkk"
,
"`aa,ACx`, `bb,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `aa,ACx`, `bb,ACx`, `XXXxxxx,r`, `YYYyyyy,r`)"
,
"COPR_XY2`q_SAT` `kkkkkkkk`, `aa,ACx`, `bb,ACx`, `XXXxxxx,r`, `YYYyyyy,r`, `aa,ACx`, `bb,ACx`"
,
(char *)0x1F1,
"OOOOOOOOpXXXxxxxp10000aa1YYYyyyyqq-000bb1ZZZzzzzkkkkkkkk"
,
"`aa,ACx`, `bb,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`)"
,
"COPR_XYZ1`q_SAT` `kkkkkkkk`, `XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`, `aa,ACx`, `bb,ACx`"
,
(char *)0x1F2,
"OOOOOOOOpXXXxxxxp10000aa1YYYyyyyqq-000bb1ZZZzzzzkkkkkkkk"
,
"`aa,ACx`, `bb,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `aa,ACx`, `XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`)"
,
"COPR_XYZ2`q_SAT` `kkkkkkkk`, `aa,ACx`, `XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`, `aa,ACx`, `bb,ACx`"
,
(char *)0x1F3,
"OOOOOOOOpXXXxxxxp10000aa1YYYyyyyqq-000bb1ZZZzzzzkkkkkkkk"
,
"`aa,ACx`, `bb,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `bb,ACx`, `XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`)"
,
"COPR_XYZ3`q_SAT` `kkkkkkkk`, `bb,ACx`, `XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`, `aa,ACx`, `bb,ACx`"
,
(char *)0x1F4,
"OOOOOOOOpXXXxxxxp10000aa1YYYyyyyqq-000bb1ZZZzzzzkkkkkkkk"
,
"`aa,ACx`, `bb,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `aa,ACx`, `bb,ACx`, `XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`)"
,
"COPR_XYZ4`q_SAT` `kkkkkkkk`, `aa,ACx`, `bb,ACx`, `XXXxxxx,r`, `YYYyyyy,r`, `ZZZzzzz,r`, `aa,ACx`, `bb,ACx`"
,
(char *)0x1F5,
"OOOOOOOOpXXXxxxxp10000aa1YYYyyyyqq-000001ZZZzzzzkkkkkkkk"
,
"`aa,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `YYYyyyy,r`, `ZZZzzzz,r`), mar(`XXXxxxx,r`)"
,
"COPR_MARXYZ1`q_SAT` `kkkkkkkk`, `YYYyyyy,r`, `ZZZzzzz,r`, `aa,ACx` :: AMAR `XXXxxxx,r`"
,
(char *)0x1F6,
"OOOOOOOOpXXXxxxxp10000aa1YYYyyyyqq-000001ZZZzzzzkkkkkkkk"
,
"`aa,ACx` = copr`q_SAT,a`(`kkkkkkkk`, `aa,ACx`, `YYYyyyy,r`, `ZZZzzzz,r`), mar(`XXXxxxx,r`)"
,
"COPR_MARXYZ2`q_SAT` `kkkkkkkk`, `aa,ACx`, `YYYyyyy,r`, `ZZZzzzz,r`, `aa,ACx` :: AMAR `XXXxxxx,r`"
,
(char *)0x1F7,
"OOOOOOOOMMMMxxxxmmAaaaaa-pCcccccqqDddddd"
,
"`Aaaaaa,ACLHx` = field_extract_r(`Cccccc,ACLHx`, `Dddddd,ACLHx`, `MMMMxxxxmm,baddr`)"
,
"BFXTR `Cccccc,ACLHx`, `Dddddd,ACLHx`, `MMMMxxxxmm,baddr`, `Aaaaaa,ACLHx`"
,
(char *)0x1F8,
"OOOOOOOOMMMMxxxxmmAaaaaa-pCcccccqqDddddd"
,
"`Aaaaaa,ACLHx` = field_extract_l(`Cccccc,ACLHx`, `Dddddd,ACLHx`, `MMMMxxxxmm,baddr`)"
,
"BFXTL `Cccccc,ACLHx`, `Dddddd,ACLHx`, `MMMMxxxxmm,baddr`, `Aaaaaa,ACLHx`"
,
(char *)0x1F9,
"OOOOOOOOMMMMxxxxmm-aaaaa-p-cccccqq-ddddd"
,
"`aaaaa,ACx` = field_extract_r(`ccccc,ACx`, `ddddd,ACx`, `MMMMxxxxmm,baddr`)"
,
"DBFXTR `ccccc,ACx`, `ddddd,ACx`, `MMMMxxxxmm,baddr`, `aaaaa,ACx`"
,
(char *)0x1FA,
"OOOOOOOOMMMMxxxxmm-aaaaa-p-cccccqq-ddddd"
,
"`aaaaa,ACx` = field_extract_l(`ccccc,ACx`, `ddddd,ACx`, `MMMMxxxxmm,baddr`)"
,
"DBFXTL `ccccc,ACx`, `ddddd,ACx`, `MMMMxxxxmm,baddr`, `aaaaa,ACx`"
,
(char *)0x1FB,
"OOOOOOOOMMMMxxxxmmAaaaaa-pCcccccqqDddddd"
,
"`Aaaaaa,ACLHx` = field_insert(`Cccccc,ACLHx`, `Dddddd,ACLHx`, `MMMMxxxxmm,baddr`)"
,
"BFINS `Cccccc,ACLHx`, `Dddddd,ACLHx`, `MMMMxxxxmm,baddr`, `Aaaaaa,ACLHx`"
,
(char *)0x1FC,
"OOOOOOOWp-%aaaaap--bbbbb--$cccccqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(`LO(`ccccc,ACx`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(`HI(`ccccc,ACx`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`"
,
"MPY`/``q_SAT``%``4` `$,(`LO(`ccccc,ACx`)`$,)`, `#,(`LO(`ZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MPY`/``q_SAT``%``4` `$,(`HI(`ccccc,ACx`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(char *)0x1FD,
"OOOOOOOWp-%aaaaap--bbbbb--$cccccqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/,(``$,(`LO(`ccccc,ACx`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` +`/,(``$,(`HI(`ccccc,ACx`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`"
,
"MAC`/``q_SAT``%``4` `$,(`LO(`ccccc,ACx`)`$,)`, `#,(`LO(`ZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(`HI(`ccccc,ACx`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(char *)0x1FE,
"OOOOOOOWp-%aaaaap--bbbbb--$cccccqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/,(``$,(`LO(`ccccc,ACx`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` -`/,(``$,(`HI(`ccccc,ACx`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`"
,
"MAC`/``q_SAT``%``4` `$,(`LO(`ccccc,ACx`)`$,)`, `#,(`LO(`ZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAS`/``q_SAT``%``4` `$,(`HI(`ccccc,ACx`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(char *)0x1FF,
"OOOOOOOWp-%aaaaap--bbbbb--$cccccqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/,(``$,(`LO(`ccccc,ACx`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` +`/,(``$,(`HI(`ccccc,ACx`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`"
,
"MAS`/``q_SAT``%``4` `$,(`LO(`ccccc,ACx`)`$,)`, `#,(`LO(`ZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(`HI(`ccccc,ACx`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(char *)0x200,
"OOOOOOOWp-%aaaaap--bbbbb--$cccccqq#4----/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` - `/,(``$,(`LO(`ccccc,ACx`)`$,)` * `#,(`LO(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` -`/,(``$,(`HI(`ccccc,ACx`)`$,)` * `#,(`HI(`ZZZzzzz,r`)`#,)``/,)``%,)``4,)``q_SAT,)`"
,
"MAS`/``q_SAT``%``4` `$,(`LO(`ccccc,ACx`)`$,)`, `#,(`LO(`ZZzzzz,r`)`#,)`, `aaaaa,ACx` :: MAS`/``q_SAT``%``4` `$,(`HI(`ccccc,ACx`)`$,)`, `#,(`HI(`ZZZzzzz,r`)`#,)`, `bbbbb,ACx`"
,
(char *)0x201,
"OOOOOOk$JCCcccccJkkkkkkkLLLLLLLLLLLLLLLL"
,
"compare (uns(`CCccccc,RAx` `JJ` `kkkkkkkk`)) goto `LLLLLLLLLLLLLLLL`"
,
"BCCU `LLLLLLLLLLLLLLLL`, `CCccccc,RAx` `JJ` `kkkkkkkk`"
,
(char *)0x202,
(char *)0x0,
"DLD_R_ABS"
,
"DLD_R_ABS"
,
(char *)0x203,
(char *)0x0,
"DST_R_ABS"
,
"DST_R_ABS"
,
(char *)0x204,
(char *)0x0,
"SUB_MWK"
,
"SUB_MWK"
,
(char *)0x205,
(char *)0x0,
"DPSHR_SPW"
,
"DPSHR_SPW"
,
(char *)0x206,
(char *)0x0,
"DPOPR_SPR"
,
"DPOPR_SPR"
,
(char *)0x207,
(char *)0x0,
"DST_R"
,
"DST_R"
,
(char *)0x208,
(char *)0x0,
"DLD_R"
,
"DLD_R"
,
(char *)0x209,
"OOOOOOOOMMMMxxxxmmoaaaaa"
,
"`aaaaa,XDAx` = mar(byte(`MMMMxxxxmm,r`))"
,
"AMAR byte(`MMMMxxxxmm,r`), `aaaaa,XDAx`"
,
(char *)0x20A,
"OOOOOOOOMMMMxxxxmmqppo--KKKKKKKKKKKKKKKK"
,
"dbl(`MMMMxxxxmm,rw`) = `q_SAT,(`dbl(`MMMMxxxxmm,rw`) + `KKKKKKKKKKKKKKKK``q_SAT,)`"
,
"ADD`q_SAT` `KKKKKKKKKKKKKKKK`, dbl(`MMMMxxxxmm,rw`)"
,
(char *)0x20B,
"OOOOOOOOMMMMxxxxmmqppo--iiiiiiiiiiiiiiii"
,
"dbl(`MMMMxxxxmm,w`) = `iiiiiiiiiiiiiiii`"
,
"MOV `iiiiiiiiiiiiiiii`, dbl(`MMMMxxxxmm,w`)"
,
(char *)0x20C,
"OOOOOOOOMMMMxxxxmmqppo--kkkkkkkkkkkkkkkk"
,
"dbl(`MMMMxxxxmm,rw`) = dbl(`MMMMxxxxmm,rw`) & `kkkkkkkkkkkkkkkk`"
,
"AND `kkkkkkkkkkkkkkkk`, dbl(`MMMMxxxxmm,rw`)"
,
(char *)0x20D,
"OOOOOOOOMMMMxxxxmmqppo--kkkkkkkkkkkkkkkk"
,
"dbl(`MMMMxxxxmm,rw`) = dbl(`MMMMxxxxmm,rw`) | `kkkkkkkkkkkkkkkk`"
,
"OR `kkkkkkkkkkkkkkkk`, dbl(`MMMMxxxxmm,rw`)"
,
(char *)0x20E,
"OOOOOOOOMMMMxxxxmmqppo--kkkkkkkkkkkkkkkk"
,
"dbl(`MMMMxxxxmm,rw`) = dbl(`MMMMxxxxmm,rw`) ^ `kkkkkkkkkkkkkkkk`"
,
"XOR `kkkkkkkkkkkkkkkk`, dbl(`MMMMxxxxmm,rw`)"
,
(char *)0x20F,
"OOOOOOOOMMMMxxxxmm$aaaaapp-cccccqqSSSSSS"
,
"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` + (`$,(`dbl(`MMMMxxxxmm,r`)`$,)` << `SSSSSS`)`q_SAT,)`"
,
"ADD`q_SAT` `$,(`dbl(`MMMMxxxxmm,r`)`$,)` << `SSSSSS`, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x210,
"OOOOOOOOMMMMxxxxmm$aaaaapp-cccccqqSSSSSS"
,
"`aaaaa,ACx` = `q_SAT,(``ccccc,ACx` - (`$,(`dbl(`MMMMxxxxmm,r`)`$,)` << `SSSSSS`)`q_SAT,)`"
,
"SUB`q_SAT` `$,(`dbl(`MMMMxxxxmm,r`)`$,)` << `SSSSSS`, `ccccc,ACx`, `aaaaa,ACx`"
,
(char *)0x211,
"OOOOOOOOMMMMxxxxmm$aaaaapp------qqSSSSSS"
,
"`aaaaa,ACx` = `q_SAT,(``$,(`dbl(`MMMMxxxxmm,r`)`$,)` << `SSSSSS``q_SAT,)`"
,
"MOV`q_SAT` `$,(`dbl(`MMMMxxxxmm,r`)`$,)` << `SSSSSS`, `aaaaa,ACx`"
,
(char *)0x212,
"OOOOOOOOMMMMxxxxmm%ccccc@p$----q-NNnnnnn"
,
"dbl(`MMMMxxxxmm,w`) = `@,(``$,(``%,(``ccccc,ACx` << `NNnnnnn,SRx``%,)``$,)``@,)`"
,
"MOV `$,(``%,(``@,(``ccccc,ACx` << `NNnnnnn,SRx``@,)``%,)``$,)`), dbl(`MMMMxxxxmm,w`"
,
(char *)0x213,
"OOOOOOOOMMMMxxxxmm%ccccc@p$----q--SSSSSS"
,
"dbl(`MMMMxxxxmm,w`) = `@,(``$,(``%,(``ccccc,ACx` << `SSSSSS``%,)``$,)``@,)`"
,
"MOV `$,(``%,(``@,(``ccccc,ACx` << `SSSSSS``@,)``%,)``$,)`), dbl(`MMMMxxxxmm,w`"
,
(char *)0x214,
"OOOOOOOOMMMMxxxxmmT-poJJKKKKKKKKKKKKKKKK"
,
"`T` = (dbl(`MMMMxxxxmm,r`) `JJ` `KKKKKKKKKKKKKKKK`)"
,
"CMP dbl(`MMMMxxxxmm,r`) `JJ` `KKKKKKKKKKKKKKKK`, `T`"
,
(char *)0x215,
"OOOOOOOOMMMMxxxxmmTppo-----kkkkk"
,
"`T` = bit(dbl(`MMMMxxxxmm,rw`), `kkkkk`), bit(dbl(`MMMMxxxxmm,rw`), `kkkkk`) = #0"
,
"BTSTCLR `kkkkk`, dbl(`MMMMxxxxmm,rw`), `T`"
,
(char *)0x216,
"OOOOOOOOMMMMxxxxmmTppo-----kkkkk"
,
"`T` = bit(dbl(`MMMMxxxxmm,rw`), `kkkkk`), bit(dbl(`MMMMxxxxmm,rw`), `kkkkk`) = #1"
,
"BTSTSET `kkkkk`, dbl(`MMMMxxxxmm,rw`), `T`"
,
(char *)0x217,
"OOOOOOOOMMMMxxxxmmTppo-----kkkkk"
,
"`T` = bit(dbl(`MMMMxxxxmm,r`), `kkkkk`)"
,
"BTST `kkkkk`, dbl(`MMMMxxxxmm,r`), `T`"
,
(char *)0x218,
"OOOOOOOOMMMMxxxxmmTppo-----kkkkk"
,
"`T` = bit(dbl(`MMMMxxxxmm,rw`), `kkkkk`), cbit(dbl(`MMMMxxxxmm,rw`), `kkkkk`)"
,
"BTSTNOT `kkkkk`, dbl(`MMMMxxxxmm,rw`), `T`"
,
(char *)0x219,
"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` + `/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
"MPY`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` :: MAC`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx`"
,
(char *)0x21A,
"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` - `/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
"MPY`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` :: MAS`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx`"
,
(char *)0x21B,
"OOOOOOOWpXXXxxxxp4$aaaaa%YYYyyyyqq#bbbbb/ZZZzzzz"
,
"`aaaaa,ACx` = `q_SAT,(``4,(``%,(``aaaaa,ACx` + `/,(``$,(``XXXxxxx,r``$,)` * `#,(``W,L(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`, `bbbbb,ACx` = `q_SAT,(``4,(``%,(``bbbbb,ACx` - `/,(``$,(``YYYyyyy,r``$,)` * `#,(``W,H(``ZZZzzzz,r``W,)``#,)``/,)``%,)``4,)``q_SAT,)`"
,
"MAC`/``q_SAT``%``4` `$,(``XXXxxxx,r``$,)`, `#,(``W,L(``ZZZzzzz,r``W,)``#,)`, `aaaaa,ACx` :: MAS`/``q_SAT``%``4` `$,(``YYYyyyy,r``$,)`, `#,(``W,H(``ZZZzzzz,r``W,)``#,)`, `bbbbb,ACx`"
,
(char *)0x21C,
"OOOOOOOOppppqqqq"
,
"debug_data()"
,
"debug_data"
,
(char *)0x21D,
"OOOOOOOOppppqqqq"
,
"debug_prog()"
,
"debug_prog"
,
(char *)0x223,
(char *)0x0,
"NO_OF_INSTR"
,
"NO_OF_INSTR"
,
(char *)0x224,
(char *)0x0,
"FIELDMASK"
,
"FIELDMASK"
,
(char *)0x225,
(char *)0x0,
"REPEAT_LOCAL_END"
,
"REPEAT_LOCAL_END"
,
(char *)0x226,
(char *)0x0,
"REPEAT_BLOCK_END"
,
"REPEAT_BLOCK_END"
,
(char *)0x227,
(char *)0x0,
"REPEAT_STMT_END"
,
"REPEAT_STMT_END"
,
(char *)0x228,
(char *)0x0,
"PARALLEL"
,
"PARALLEL"
,
(char *)0x22E,
(char *)0x0,
"FILLER"
,
"FILLER"
,
(char *)0x22F,
(char *)0x0,
"ILLOP"
,
"ILLOP"
,
(char *)0x230,
(char *)0x0,
"MAX_INSTR_COUNT"
,
"MAX_INSTR_COUNT"
,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
(char *)0x0,
"@(#) $Id: dasm_header,v 1.51 2007/01/31 21:42:44 brett Exp $"
,
"@(#) $Id: tbl_encoding,v 1.9 2007/01/31 21:42:44 brett Exp $"
,
"@(#) $Id: tbl_lengths,v 1.7 2007/01/31 21:42:44 brett Exp $"
,
"@(#) $Id: tbl_opcodes,v 1.10 2007/01/31 21:42:44 brett Exp $"
,
"@(#) $Id: dasm_vars,v 1.3 2004/09/24 19:48:27 brett Exp $"

};
