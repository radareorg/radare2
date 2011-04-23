/* radare - GPL3 - Copyright 2009-2010 */

enum fmt_inst {
	fmt00 = 0,					// None
	fmtop,						// op
	fmtopvAvB,					// op vA, vB
	fmtopvAcB,					// op vA, #+B
	fmtopvAA,					// op vAA
	fmtoppAA,					// op +AA
	fmtopAAtBBBB,				// op AA, thing@BBBB
	fmtoppAAAA,					// op +AAAA
	fmtopvAAvBBBB,				// op vAA, vBBBB
	fmtopvAApBBBB,				// op vAA, +BBBB
	fmtopvAAcBBBB,				// op vAA, #+BBBB
	fmtopvAAcBBBB0000,			// op vAA, #+BBBB00000[00000000]
	fmtopvAAtBBBB,				// op vAA, thing@BBBB
	fmtopvAAvBBvCC,				// op vAA, vBB, vCC
	fmtopvAAvBBcCC,				// op vAA, vBB, #+CC
	fmtopvAvBpCCCC,				// op vA, vB, +CCCC
	fmtopvAvBcCCCC,				// op vA, vB, #+CCCC
	fmtopvAvBtCCCC,				// op vA, vB, thing@CCCC
	fmtoptopvAvBoCCCC,			// [opt] op vA, vB, field offset CCCC
	fmtopvAAAAvBBBB,			// op vAAAA, vBBBB
	fmtoppAAAAAAAA,				// op +AAAAAAAA
	fmtopvAApBBBBBBBB,			// op vAA, +BBBBBBBB
	fmtopvAAcBBBBBBBB,			// op vAA, #+BBBBBBBB
	fmtopvAAtBBBBBBBB,			// op vAA, thing@BBBBBBBB
	fmtopvXtBBBB,				// op {vC, vD, vE, vF, vG}, thing@BBBB (B: count, A: vG)
	fmtoptinvokeVS,				// [opt] invoke-virtual+super
	fmtoptinvokeI,				// [opt] invoke-interface
	fmtopvCCCCmBBBB,			// op {vCCCC .. v(CCCC+AA-1)}, meth@BBBB
	fmtoptinvokeVSR,			// [opt] invoke-virtual+super/range
	fmtoptinvokeIR,				// [opt] invoke-interface/range
	fmtoptinlineI,				// [opt] inline invoke
	fmtoptinlineIR,				// [opt] inline invoke/range
	fmtopvAAcBBBBBBBBBBBBBBBB,	// op vAA, #+BBBBBBBBBBBBBBBB
};

struct dalvik_opcodes_t {
	char *name;
	int len;
	int fmt;
};

static const struct dalvik_opcodes_t dalvik_opcodes[256] = {
	{"nop", 2, fmtop}, /* 0x00 */
	{"move", 2, fmtopvAvB},
	{"move/from16", 4, fmtopvAAvBBBB},
	{"move/16", 6, fmtopvAAAAvBBBB},
	{"move-wide", 2, fmtopvAvB},
	{"move-wide/from16", 4, fmtopvAAvBBBB},
	{"move-wide/16", 6, fmtopvAAAAvBBBB},
	{"move-object", 2, fmtopvAvB},
	{"move-object/from16", 4, fmtopvAAvBBBB},
	{"move-object/16", 6, fmtopvAAAAvBBBB},
	{"move-result", 2, fmtopvAA},
	{"move-result-wide", 2, fmtopvAA},
	{"move-result-object", 2, fmtopvAA},
	{"move-exception", 2, fmtopvAA},
	{"return-void", 2, fmtop},
	{"return", 2, fmtopvAA},
	{"return-wide", 2, fmtopvAA}, /* 0x10 */
	{"return-object", 2, fmtopvAA},
	{"const/4", 2, fmtopvAcB},
	{"const/16", 4, fmtopvAAcBBBB},
	{"const", 6, fmtopvAAcBBBBBBBB},
	{"const/high16", 4, fmtopvAAcBBBB0000},
	{"const-wide/16", 4, fmtopvAAcBBBB},
	{"const-wide/32", 6, fmtopvAAcBBBBBBBB},
	{"const-wide", 10, fmtopvAAcBBBBBBBBBBBBBBBB},
	{"const-wide/high16", 4, fmtopvAAcBBBB0000},
	{"const-string", 4, fmtopvAAtBBBB},
	{"const-string/jumbo", 6, fmtopvAAtBBBBBBBB},
	{"const-class", 4, fmtopvAAtBBBB},
	{"monitor-enter", 2, fmtopvAA},
	{"monitor-exit", 2, fmtopvAA},
	{"check-cast", 4, fmtopvAAtBBBB},
	{"instance-of", 4, fmtopvAvBtCCCC}, /* 0x20 */
	{"array-length", 2, fmtopvAvB},
	{"new-instance", 4, fmtopvAAtBBBB},
	{"new-array", 4, fmtopvAvBtCCCC},
	{"filled-new-array", 6, fmtopvXtBBBB},
	{"filled-new-array/range", 6, fmtopvCCCCmBBBB},
	{"fill-array-data", 6, fmtopvAApBBBBBBBB},
	{"throw", 2, fmtopvAA},
	{"goto", 2, fmtoppAA},
	{"goto/16", 4, fmtoppAAAA},
	{"goto/32", 6, fmtoppAAAAAAAA},
	{"packed-switch", 6, fmtopvAApBBBBBBBB},
	{"sparse-switch", 6, fmtopvAApBBBBBBBB},
	{"cmpl-float", 4, fmtopvAAvBBvCC},
	{"cmpg-float", 4, fmtopvAAvBBvCC},
	{"cmpl-double", 4, fmtopvAAvBBvCC},
	{"cmpg-double", 4, fmtopvAAvBBvCC}, /* 0x30 */
	{"cmp-long", 4, fmtopvAAvBBvCC},
	{"if-eq", 4, fmtopvAvBpCCCC},
	{"if-ne", 4, fmtopvAvBpCCCC},
	{"if-lt", 4, fmtopvAvBpCCCC},
	{"if-ge", 4, fmtopvAvBpCCCC},
	{"if-gt", 4, fmtopvAvBpCCCC},
	{"if-le", 4, fmtopvAvBpCCCC},
	{"if-eqz", 4, fmtopvAApBBBB},
	{"if-nez", 4, fmtopvAApBBBB},
	{"if-ltz", 4, fmtopvAApBBBB},
	{"if-gez", 4, fmtopvAApBBBB},
	{"if-gtz", 4, fmtopvAApBBBB},
	{"if-lez", 4, fmtopvAApBBBB},
	{"UNUSED", 0, fmt00},
	{"UNUSED", 0, fmt00},
	{"UNUSED", 0, fmt00}, /* 0x40 */
	{"UNUSED", 0, fmt00},
	{"UNUSED", 0, fmt00},
	{"UNUSED", 0, fmt00},
	{"aget", 4, fmtopvAAvBBvCC},
	{"aget-wide", 4, fmtopvAAvBBvCC},
	{"aget-object", 4, fmtopvAAvBBvCC},
	{"aget-boolean", 4, fmtopvAAvBBvCC},
	{"aget-byte", 4, fmtopvAAvBBvCC},
	{"aget-char", 4, fmtopvAAvBBvCC},
	{"aget-short", 4, fmtopvAAvBBvCC},
	{"aput", 4, fmtopvAAvBBvCC},
	{"aput-wide", 4, fmtopvAAvBBvCC},
	{"aput-object", 4, fmtopvAAvBBvCC},
	{"aput-boolean", 4, fmtopvAAvBBvCC},
	{"aput-byte", 4, fmtopvAAvBBvCC},
	{"aput-char", 4, fmtopvAAvBBvCC}, /* 0x50 */
	{"aput-short", 4, fmtopvAAvBBvCC},
	{"iget", 4, fmtopvAvBtCCCC},
	{"iget-wide", 4, fmtopvAvBtCCCC},
	{"iget-object", 4, fmtopvAvBtCCCC},
	{"iget-boolean", 4, fmtopvAvBtCCCC},
	{"iget-byte", 4, fmtopvAvBtCCCC},
	{"iget-char", 4, fmtopvAvBtCCCC},
	{"iget-short", 4, fmtopvAvBtCCCC},
	{"iput", 4, fmtopvAvBtCCCC},
	{"iput-wide", 4, fmtopvAvBtCCCC},
	{"iput-object", 4, fmtopvAvBtCCCC},
	{"iput-boolean", 4, fmtopvAvBtCCCC},
	{"iput-byte", 4, fmtopvAvBtCCCC},
	{"iput-char", 4, fmtopvAvBtCCCC},
	{"iput-short", 4, fmtopvAvBtCCCC},
	{"sget", 4, fmtopvAAtBBBB}, /* 0x60 */
	{"sget-wide", 4, fmtopvAAtBBBB},
	{"sget-object", 4, fmtopvAAtBBBB},
	{"sget-boolean", 4, fmtopvAAtBBBB},
	{"sget-byte", 4, fmtopvAAtBBBB},
	{"sget-char", 4, fmtopvAAtBBBB},
	{"sget-short", 4, fmtopvAAtBBBB},
	{"sput", 4, fmtopvAAtBBBB},
	{"sput-wide", 4, fmtopvAAtBBBB},
	{"sput-object", 4, fmtopvAAtBBBB},
	{"sput-boolean", 4, fmtopvAAtBBBB},
	{"sput-byte", 4, fmtopvAAtBBBB},
	{"sput-char", 4, fmtopvAAtBBBB},
	{"sput-short", 4, fmtopvAAtBBBB},
	{"invoke-virtual", 6, fmtopvXtBBBB},
	{"invoke-super", 6, fmtopvXtBBBB},
	{"invoke-direct", 6, fmtopvXtBBBB}, /* 0x70 */
	{"invoke-static", 6, fmtopvXtBBBB},
	{"invoke-interface", 6, fmtopvXtBBBB}, //XXX: Maybe use opt invoke-interface ??
	{"UNUSED", 0, fmt00},
	{"invoke-virtual/range", 6, fmtopvCCCCmBBBB},
	{"invoke-super/range", 6, fmtopvCCCCmBBBB},
	{"invoke-direct/range", 6, fmtopvCCCCmBBBB},
	{"invoke-static/range", 6, fmtopvCCCCmBBBB},
	{"invoke-interface/range", 6, fmtopvCCCCmBBBB},
	{"UNUSED", 0, fmt00},
	{"UNUSED", 0, fmt00},
	{"neg-int", 2, fmtopvAvB},
	{"not-int", 2, fmtopvAvB},
	{"neg-long", 2, fmtopvAvB},
	{"not-long", 2, fmtopvAvB},
	{"neg-float", 2, fmtopvAvB},
	{"neg-double", 2, fmtopvAvB}, /* 0x80 */
	{"int-to-long", 2, fmtopvAvB},
	{"int-to-float", 2, fmtopvAvB},
	{"int-to-double", 2, fmtopvAvB},
	{"long-to-int", 2, fmtopvAvB},
	{"long-to-float", 2, fmtopvAvB},
	{"long-to-double", 2, fmtopvAvB},
	{"float-to-int", 2, fmtopvAvB},
	{"float-to-long", 2, fmtopvAvB},
	{"float-to-double", 2, fmtopvAvB},
	{"double-to-int", 2, fmtopvAvB},
	{"double-to-long", 2, fmtopvAvB},
	{"double-to-float", 2, fmtopvAvB},
	{"int-to-byte", 2, fmtopvAvB},
	{"int-to-char", 2, fmtopvAvB},
	{"int-to-short", 2, fmtopvAvB},
	{"add-int", 4, fmtopvAAvBBvCC}, /* 0x90 */
	{"sub-int", 4, fmtopvAAvBBvCC},
	{"mul-int", 4, fmtopvAAvBBvCC},
	{"div-int", 4, fmtopvAAvBBvCC},
	{"rem-int", 4, fmtopvAAvBBvCC},
	{"and-int", 4, fmtopvAAvBBvCC},
	{"or-int", 4, fmtopvAAvBBvCC},
	{"xor-int", 4, fmtopvAAvBBvCC},
	{"shl-int", 4, fmtopvAAvBBvCC},
	{"shr-int", 4, fmtopvAAvBBvCC},
	{"ushr-int", 4, fmtopvAAvBBvCC},
	{"add-long", 4, fmtopvAAvBBvCC},
	{"sub-long", 4, fmtopvAAvBBvCC},
	{"mul-long", 4, fmtopvAAvBBvCC},
	{"div-long", 4, fmtopvAAvBBvCC},
	{"rem-long", 4, fmtopvAAvBBvCC},
	{"and-long", 4, fmtopvAAvBBvCC}, /* 0xa0 */
	{"or-long", 4, fmtopvAAvBBvCC},
	{"xor-long", 4, fmtopvAAvBBvCC},
	{"shl-long", 4, fmtopvAAvBBvCC},
	{"shr-long", 4, fmtopvAAvBBvCC},
	{"ushr-long", 4, fmtopvAAvBBvCC},
	{"add-float", 4, fmtopvAAvBBvCC},
	{"sub-float", 4, fmtopvAAvBBvCC},
	{"mul-float", 4, fmtopvAAvBBvCC},
	{"div-float", 4, fmtopvAAvBBvCC},
	{"rem-float", 4, fmtopvAAvBBvCC},
	{"sub-double", 4, fmtopvAAvBBvCC},
	{"add-double", 4, fmtopvAAvBBvCC},
	{"mul-double", 4, fmtopvAAvBBvCC},
	{"div-double", 4, fmtopvAAvBBvCC},
	{"rem-double", 4, fmtopvAAvBBvCC},
	{"add-int/2addr", 2, fmtopvAvB}, /* 0xb0 */
	{"sub-int/2addr", 2, fmtopvAvB},
	{"mul-int/2addr", 2, fmtopvAvB},
	{"div-int/2addr", 2, fmtopvAvB},
	{"rem-int/2addr", 2, fmtopvAvB},
	{"and-int/2addr", 2, fmtopvAvB},
	{"or-int/2addr", 2, fmtopvAvB},
	{"xor-int/2addr", 2, fmtopvAvB},
	{"shl-int/2addr", 2, fmtopvAvB},
	{"shr-int/2addr", 2, fmtopvAvB},
	{"ushr-int/2addr", 2, fmtopvAvB},
	{"add-long/2addr", 2, fmtopvAvB},
	{"sub-long/2addr", 2, fmtopvAvB},
	{"mul-long/2addr", 2, fmtopvAvB},
	{"div-long/2addr", 2, fmtopvAvB},
	{"rem-long/2addr", 2, fmtopvAvB},
	{"and-long/2addr", 2, fmtopvAvB}, /* 0xc0 */
	{"or-long/2addr", 2, fmtopvAvB},
	{"xor-long/2addr", 2, fmtopvAvB},
	{"shl-long/2addr", 2, fmtopvAvB},
	{"shr-long/2addr", 2, fmtopvAvB},
	{"ushr-long/2addr", 2, fmtopvAvB},
	{"add-float/2addr", 2, fmtopvAvB},
	{"sub-float/2addr", 2, fmtopvAvB},
	{"mul-float/2addr", 2, fmtopvAvB},
	{"div-float/2addr", 2, fmtopvAvB},
	{"rem-float/2addr", 2, fmtopvAvB},
	{"add-double/2addr", 2, fmtopvAvB},
	{"sub-double/2addr", 2, fmtopvAvB},
	{"mul-double/2addr", 2, fmtopvAvB},
	{"div-double/2addr", 2, fmtopvAvB},
	{"rem-double/2addr", 2, fmtopvAvB},
	{"add-int/lit16", 4, fmtopvAvBcCCCC}, /* 0xd0 */
	{"rsub-int", 4, fmtopvAvBcCCCC},
	{"mul-int/lit16", 4, fmtopvAvBcCCCC},
	{"div-int/lit16", 4, fmtopvAvBcCCCC},
	{"rem-int/lit16", 4, fmtopvAvBcCCCC},
	{"and-int/lit16", 4, fmtopvAvBcCCCC},
	{"or-int/lit16", 4, fmtopvAvBcCCCC},
	{"xor-int/lit16", 4, fmtopvAvBcCCCC},
	{"add-int/lit8", 4, fmtopvAAvBBcCC},
	{"rsub-int/lit8", 4, fmtopvAAvBBcCC},
	{"mul-int/lit8", 4, fmtopvAAvBBcCC},
	{"div-int/lit8", 4, fmtopvAAvBBcCC},
	{"rem-int/lit8", 4, fmtopvAAvBBcCC},
	{"and-int/lit8", 4, fmtopvAAvBBcCC},
	{"or-int/lit8", 4, fmtopvAAvBBcCC},
	{"xor-int/lit8", 4, fmtopvAAvBBcCC},
	{"shl-int/lit8", 4, fmtopvAAvBBcCC}, /* 0xe0 */
	{"shr-int/lit8", 4, fmtopvAAvBBcCC},
	{"ushr-int/lit8", 4, fmtopvAAvBBcCC},
	{"+iget-volatile", 4, fmtopvAvBtCCCC},
	{"+iput-volatile", 4, fmtopvAvBtCCCC},
	{"+sget-volatile", 4, fmtopvAvBtCCCC},
	{"+sput-volatile", 4, fmtopvAvBtCCCC},
	{"+iget-object-volatile", 4, fmtopvAvBtCCCC},
	{"+iget-wide-volatile", 4, fmtopvAvBtCCCC},
	{"+iput-wide-volatile", 4, fmtopvAvBtCCCC},
	{"+sget-wide-volatile", 4, fmtopvAvBtCCCC},
	{"+sput-wide-volatile", 4, fmtopvAvBtCCCC},
	{"^breakpoint", 4, fmtopvAvBtCCCC},
	{"^throw-verification-error", 4, fmtopAAtBBBB},
	{"+execute-inline", 6, fmtoptinlineI},
	{"+execute-inline/range", 6, fmtoptinlineIR},
	{"+invoke-direct-empty", 6, fmtopvXtBBBB}, /* 0xf0 */
	{"UNUSED", 0, fmt00},
	{"+iget-quick", 4, fmtoptopvAvBoCCCC},
	{"+iget-wide-quick", 4, fmtoptopvAvBoCCCC},
	{"+iget-object-quick", 4, fmtoptopvAvBoCCCC},
	{"+iput-quick", 4, fmtoptopvAvBoCCCC},
	{"+iput-wide-quick", 4, fmtoptopvAvBoCCCC},
	{"+iput-object-quick", 4, fmtoptopvAvBoCCCC},
	{"+invoke-virtual-quick", 6, fmtoptinvokeVS},
	{"+invoke-virtual-quick/range", 6, fmtoptinvokeVSR},
	{"+invoke-super-quick", 6, fmtoptinvokeVS},
	{"+invoke-super-quick/range", 6, fmtoptinvokeVSR},
	{"+iput-object-volatile", 4, fmtopvAvBtCCCC},
	{"+sget-object-volatile", 4, fmtopvAAtBBBB},
	{"+sput-object-volatile", 4, fmtopvAAtBBBB},
	{"UNUSED", 0, fmt00}
};
