#define BA2_INSTR_MAXLEN	20

struct op_cmd {
	char	instr[BA2_INSTR_MAXLEN];
	char	operands[BA2_INSTR_MAXLEN];
};

static unsigned int revbits(unsigned int bits, unsigned int nbits)
{
	unsigned int r = 0;
	unsigned int cntb;
	for(cntb=0;cntb<nbits;cntb++){
		r <<= 1;
		r |= bits & 1;
		bits >>= 1;
	}
	return r;
}

// esilprintf
static int ba2_decode_opcode(ut64 pc, const ut8 *bytes, int len, struct op_cmd *cmd, RStrBuf * esil, RAnalOp * anal)
{
	if(0){
//@instruction("bt.trap", "G", "0x0 0000 0000 GGGG")
	}else if(((bytes[0]&0xFF)==0x00) && ((bytes[1]&0xF0)==0x00)){
		int g = revbits(bytes[1]&0x0F, 4);
		strcpy(cmd->instr, "b.trap");
		snprintf(cmd->operands, sizeof(cmd->operands), "0x%x", g);
//		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,=", d, g);}
		if(anal){
			anal->type = R_ANAL_OP_TYPE_SWI;
			anal->val  = g;
		}
		return 2;
//@instruction("bt.nop", "G", "0x0 00 00 0001 GGGG")
	}else if(((bytes[0]&0xFF)==0x00) && ((bytes[1]&0xF0)==0x10)){
		int g = bytes[1]&0x0F;
		strcpy(cmd->instr, "b.nop");
		snprintf(cmd->operands, sizeof(cmd->operands), "%d", g);
//		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,=", d, g);}
		if(anal){
			anal->type = R_ANAL_OP_TYPE_NOP;
			anal->val  = g;
		}
		return 2;
//@instruction("bt.movi", "rD,G", "0x0 00 DD DDD0 GGGG", "{G},r{D},=")
	}else if(((bytes[0]&0xFC)==0x00) && ((bytes[1]&0x10)==0x00)){
		int g = revbits(bytes[1]&0x0F, 4);
		int d = ((bytes[0]&0x03) << 3) | ((bytes[1]&0xE0) >> 5);
		strcpy(cmd->instr, "b.movi");
		if(g & (1 << 3)){
			g = g - (1 << 4);
			snprintf(cmd->operands, sizeof(cmd->operands), "r%d, -0x%x", d, -g);
		}else{
			snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x", d, g);
		}
		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,=", g, d);}
		if(anal){
			anal->type = R_ANAL_OP_TYPE_MOV;
		}
		return 2;
//@instruction("bt.addi", "rD,rD,G", "0x0 00 DD DDD1 GGGG", "{G},r{D},+,r{D},=")
	}else if(((bytes[0]&0xFC)==0x00) && ((bytes[1]&0x10)==0x10)){
		int g = revbits(bytes[1]&0x0F, 4);
		int d = ((bytes[0]&0x03) << 3) | ((bytes[1]&0xE0) >> 5);
		strcpy(cmd->instr, "b.addi");
		if(g & (1 << 3)){
			g = g - (1 << 4);
			snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, -0x%x", d, d, -g);
		}else{
			snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, 0x%x", d, d, g);
		}
		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,+,r%d,=", g, d, d);}
		if(anal){
			anal->type = R_ANAL_OP_TYPE_ADD;
		}
		return 2;

//@instruction("bt.rfe", "", "0x0 01 00 0000 0000")
	}else if(((bytes[0]&0xFF)==0x04) && ((bytes[1]&0xFF)==0x00)){
		strcpy(cmd->instr, "b.rfe");
		snprintf(cmd->operands, sizeof(cmd->operands), "");
		return 2;
//@instruction("bt.ei", "", "0x0 01 00 0000 0001")
	}else if(((bytes[0]&0xFF)==0x04) && ((bytes[1]&0xFF)==0x01)){
		strcpy(cmd->instr, "b.ei");
		snprintf(cmd->operands, sizeof(cmd->operands), "");
		return 2;
//@instruction("bt.di", "", "0x0 01 00 0000 0010")
	}else if(((bytes[0]&0xFF)==0x04) && ((bytes[1]&0xFF)==0x02)){
		strcpy(cmd->instr, "b.di");
		snprintf(cmd->operands, sizeof(cmd->operands), "");
		return 2;
//@instruction("bt.sys", "", "0x0 01 00 0000 0011")
	}else if(((bytes[0]&0xFF)==0x04) && ((bytes[1]&0xFF)==0x03)){
		strcpy(cmd->instr, "b.sys");
		snprintf(cmd->operands, sizeof(cmd->operands), "");
		return 2;

//@instruction("bt.mov", "rD,rA", "0x0 01 DD DDDA AAAA", "r{A},r{D},=")
	}else if(((bytes[0]&0xFC)==0x04)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		strcpy(cmd->instr, "b.mov");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d", d, a);
		if(esil){r_strbuf_appendf(esil, "r%d,r%d,=", a, d);}
		if(anal){
			anal->type = R_ANAL_OP_TYPE_MOV;
		}
		return 2;

//@instruction("bt.add", "rD,rD,rA", "0x0 10 DD DDDA AAAA", "r{A},r{D},+,r{D},=")
	}else if(((bytes[0]&0xFC)==0x08)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		strcpy(cmd->instr, "b.add");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, r%d", d, d, a);
		if(esil){r_strbuf_appendf(esil, "r%d,r%d,+,r%d,=", a, d, d);}
		if(anal){
			anal->type = R_ANAL_OP_TYPE_ADD;
		}
		return 2;


//@instruction("bt.j", "T", "0x0 11 TT TTTT TTTT", "2,{T},-,pc,+=")
	}else if(((bytes[0]&0xFC)==0x0C)){
		int t = revbits(((bytes[0]&0x03) << 8) | (bytes[1]&0xFF), 10);
		if(t & (1 << 9)){ t = t - (1 << 10); }
		strcpy(cmd->instr, "b.j");
		snprintf(cmd->operands, sizeof(cmd->operands), "%x", (unsigned int)(pc+t));
		if(esil){r_strbuf_appendf(esil, "2,0x%x,-,pc,+=", t);}
		if(anal){
			anal->type = R_ANAL_OP_TYPE_JMP;
			anal->jump = pc + t;
			anal->fail = pc + 2;
		}
		return 2;

//@instruction("bn.sb", "N(rA),rB", "0x2 00 BB BBBA AAAA NNNN NNNN",  "r{B},{N},r{A},+,=[1]")
	}else if(((bytes[0]&0xFC)==0x20)){
		int a = ((bytes[1]&0x1F) >>  0);
		int b = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int n = revbits(bytes[2]&0xFF, 8);
		strcpy(cmd->instr, "b.sb");
		snprintf(cmd->operands, sizeof(cmd->operands), "0x%x(r%d), r%d", n, a, b);
		if(esil){r_strbuf_appendf(esil, "r%d,0x%x,r%d,+,=[1]", b, n, a);}
		if(anal){
//???			anal->type = R_ANAL_OP_TYPE_ADD;
		}
		return 3;

//#TODO: zero extend
//@instruction("bn.lbz", "rD,N(rA)", "0x2 01 DD DDDA AAAA NNNN NNNN", "{N},r{A},+,[1],r{D},=")
	}else if(((bytes[0]&0xFC)==0x24)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int n = revbits(bytes[2]&0xFF, 8);
		strcpy(cmd->instr, "b.lbz");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x(r%d)", d, n, a);
		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,+,[1],r%d,=", n, a, d);}
		return 3;

//@instruction("bn.sh", "M(rA),rB", "0x2 10 BB BBBA AAAA 0MMM MMMM", "r{B},{M},r{A},+,=[2]")
	}else if(((bytes[0]&0xFC)==0x28) && ((bytes[2]&0x80)==0x00)){
		int a = ((bytes[1]&0x1F) >>  0);
		int b = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int m = revbits(bytes[2]&0x7F, 7);
		strcpy(cmd->instr, "b.sh");
		snprintf(cmd->operands, sizeof(cmd->operands), "0x%x(r%d), r%d", 2*m, a, b);
		if(esil){r_strbuf_appendf(esil, "r%d,0x%x,r%d,+,=[2]", b, 2*m, a);}
		return 3;

//#TODO: zero extend
//@instruction("bn.lhz", "rD,M(rA)", "0x2 10 DD DDDA AAAA 1MMM MMMM", "{M},r{A},+,[2],r{D},=")
	}else if(((bytes[0]&0xFC)==0x28) && ((bytes[2]&0x80)==0x80)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int m = revbits(bytes[2]&0x7F, 7);
		strcpy(cmd->instr, "b.lhz");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x(r%d)", d, 2*m, a);
		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,+,[2],r%d,=", d, 2*m, a);}
		return 3;

//@instruction("bn.sw", "K(rA),rB", "0x2 11 BB BBBA AAAA 00KK KKKK", "r{B},{K},r{A},+,=[4]")
	}else if(((bytes[0]&0xFC)==0x2C) && ((bytes[2]&0xC0)==0x00)){
		int a = ((bytes[1]&0x1F) >>  0);
		int b = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int k = revbits(bytes[2]&0x3F, 6);
		strcpy(cmd->instr, "b.sw");
		snprintf(cmd->operands, sizeof(cmd->operands), "0x%x(r%d), r%d", k*4, a, b);
		if(esil){r_strbuf_appendf(esil, "r%d,0x%x,r%d,+,=[4]", b, k, a);}
		return 3;

//#TODO: zero extend
//@instruction("bn.lwz", "rD,K(rA)", "0x2 11 DD DDDA AAAA 01KK KKKK", "{K},r{A},+,[4],r{D},=")
	}else if(((bytes[0]&0xFC)==0x2C) && ((bytes[2]&0xC0)==0x40)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int k = revbits(bytes[2]&0x3F, 6);
		strcpy(cmd->instr, "b.lwz");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x(r%d)", d, k*4, a);
		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,+,[4],r%d,=", k, a, d);}				// -->> WARNING: r_anal_cc_arg: assertion 'anal && convention' failed (line 103) ???
		return 3;


//@instruction("bn.addi", "rD,rA,O", "0x3 00 DD DDDA AAAA OOOO OOOO", "{O},r{A},+,r{D},=")
	}else if(((bytes[0]&0xFC)==0x30)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int o = revbits(bytes[2]&0xFF, 8);
		strcpy(cmd->instr, "b.addi");
		if(o & (1 << 7)){
			o = o - (1 << 8);
			snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, -0x%x", d, a, -o);			
		}else{
			snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, 0x%x", d, a, o);
		}
		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,+,r%d,=", o, a, d);}
		if(anal){
			anal->type = R_ANAL_OP_TYPE_ADD;
		}
		return 3;


//@instruction("bn.andi", "rD,rA,N", "0x3 01 DD DDDA AAAA NNNN NNNN", "{N},r{A},&,r{D},=")
	}else if(((bytes[0]&0xFC)==0x34)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int n = revbits(bytes[2]&0xFF, 8);
		strcpy(cmd->instr, "b.andi");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, 0x%x", d, a, n);
		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,&,r%d,=", n, a, d);}
		return 3;

//@instruction("bn.ori", "rD,rA,N", "0x3 10 DD DDDA AAAA NNNN NNNN", "{N},r{A},|,r{D},=")
	}else if(((bytes[0]&0xFC)==0x38)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int n = revbits(bytes[2]&0xFF, 8);
		strcpy(cmd->instr, "b.ori");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, 0x%x", d, a, n);
		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,|,r%d,=", n, a, d);}
		if(anal){
			anal->type = R_ANAL_OP_TYPE_OR;
		}
		return 3;

//@instruction("bn.sfeqi", "rA,O",  "0x3 11 00 000A AAAA OOOO OOOO", "0,fl,=,r{A},{O},==,$z,?{{,1,fl,}}")
	}else if(((bytes[0]&0xFF)==0x3C) && ((bytes[1]&0xE0)==0x00)){
		int a = ((bytes[1]&0x1F) >>  0);
		int o = revbits(bytes[2]&0xFF, 8);
		strcpy(cmd->instr, "b.sfeqi");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x", a, o);
		if(esil){r_strbuf_appendf(esil, "0,fl,=,r%d,0x%x,==,$z,?{{,1,fl,}}", a, o);}
		return 3;

//#TODO: sign extend
//@instruction("bn.sfgtui", "rA,O",  "0x3 11 00 101A AAAA OOOO OOOO", "0,fl,=,{O},r{A},>,?{{,1,fl,}}")
	}else if(((bytes[0]&0xFF)==0x3C) && ((bytes[1]&0xE0)==0xA0)){
		int a = ((bytes[1]&0x1F) >>  0);
		int o = revbits(bytes[2]&0xFF, 8);
		strcpy(cmd->instr, "b.sfgtui");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x", a, o);
		if(esil){r_strbuf_appendf(esil, "0,fl,=,0x%x,r%d,>,?{,1,fl,}", o, a);}
		return 3;

//#TODO: sign extend
//@instruction("bn.sfleui", "rA,O",  "0x3 11 00 111A AAAA OOOO OOOO", "0,fl,=,{O},r{A},<=,?{{,1,fl,}}")
	}else if(((bytes[0]&0xFF)==0x3C) && ((bytes[1]&0xE0)==0xE0)){
		int a = ((bytes[1]&0x1F) >>  0);
		int o = revbits(bytes[2]&0xFF, 8);
		strcpy(cmd->instr, "b.sfleui");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x", a, o);
		return 3;

//@instruction("bn.sfnei", "rA,O",  "0x3 11 00 001A AAAA OOOO OOOO", "0,fl,=,r{A},{O},==,$z,!,?{{,1,fl,}}")
	}else if(((bytes[0]&0xFF)==0x3C) && ((bytes[1]&0xE0)==0x20)){
		int a = ((bytes[1]&0x1F) >>  0);
		int o = revbits(bytes[2]&0xFF, 8);
		strcpy(cmd->instr, "b.sfnei");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x", a, o);
		if(esil){r_strbuf_appendf(esil, "0,fl,=,r%d,0x%x,==,$z,!,?{,1,fl,}", a, o);}
		return 3;

//@instruction("bn.sfltsi", "rA,O",  "0x3 11 01 000A AAAA OOOO OOOO", "0,fl,=,{O},r{A},<,?{{,1,fl,}}")
	}else if(((bytes[0]&0xFF)==0x3D) && ((bytes[1]&0xE0)==0x00)){
		int a = ((bytes[1]&0x1F) >>  0);
		int o = ((bytes[2]&0xFF) >>  0);
		strcpy(cmd->instr, "b.sfltsi");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x", a, o);
		if(esil){r_strbuf_appendf(esil, "0,fl,=,0x%x,r%d,<,?{,1,fl,}", o, a);}
		return 3;

//#TODO: sign extend
//@instruction("bn.sfltui", "rA,O",  "0x3 11 01 001A AAAA OOOO OOOO", "0,fl,=,{O},r{A},<,?{{,1,fl,}}")
	}else if(((bytes[0]&0xFF)==0x3D) && ((bytes[1]&0xE0)==0x20)){
		int a = ((bytes[1]&0x1F) >>  0);
		int o = ((bytes[2]&0xFF) >>  0);
		strcpy(cmd->instr, "b.sfltui");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x", a, o);
		if(esil){r_strbuf_appendf(esil, "0,fl,=,0x%x,r%d,<,?{,1,fl,}", o, a);}
		return 3;

//@instruction("bn.sfeq", "rA,rB", "0x3 11 01 010A AAAA BBBB B---", "0,fl,=,r{B},r{A},==,$z,?{{,1,fl,}}")
	}else if(((bytes[0]&0xFF)==0x3D) && ((bytes[1]&0xE0)==0x40)){
		int a = ((bytes[1]&0x1F) >>  0);
		int b = ((bytes[2]&0xF8) >>  3);
		strcpy(cmd->instr, "b.sfeq");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d", a, b);
		if(esil){r_strbuf_appendf(esil, "0,fl,=,r%d,r%d,==,$z,?{,1,fl,}", b, a);}
		return 3;

//@instruction("bn.sfne", "rA,rB", "0x3 11 01 011A AAAA BBBB B---", "0,fl,=,r{B},r{A},==,$z,!,?{{,1,fl,}}")
	}else if(((bytes[0]&0xFF)==0x3D) && ((bytes[1]&0xE0)==0x60)){
		int a = ((bytes[1]&0x1F) >>  0);
		int b = ((bytes[2]&0xF8) >>  3);
		strcpy(cmd->instr, "b.sfne");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d", a, b);
		if(esil){r_strbuf_appendf(esil, "0,fl,=,r%d,r%d,==,$z,!,?{,1,fl,}", b, a);}
		return 3;

//@instruction("bn.sfges", "rA,rB", "0x3 11 01 100A AAAA BBBB B---", "0,fl,=,r{B},r{A},>=,?{{,1,fl,}}")
	}else if(((bytes[0]&0xFF)==0x3D) && ((bytes[1]&0xE0)==0x80)){
		int a = ((bytes[1]&0x1F) >>  0);
		int b = ((bytes[2]&0xF8) >>  3);
		strcpy(cmd->instr, "b.sfges");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d", a, b);
		if(esil){r_strbuf_appendf(esil, "0,fl,=,r%d,r%d,==,$z,!,?{,1,fl,}", b, a);}
		return 3;

//#TODO: sign extend
//@instruction("bn.sfgeu", "rA,rB", "0x3 11 01 101A AAAA BBBB B---", "0,fl,=,r{B},r{A},>=,?{{,1,fl,}}")
	}else if(((bytes[0]&0xFF)==0x3D) && ((bytes[1]&0xE0)==0xA0)){
		int a = ((bytes[1]&0x1F) >>  0);
		int b = ((bytes[2]&0xF8) >>  3);
		strcpy(cmd->instr, "b.sfgeu");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d", a, b);
		if(esil){r_strbuf_appendf(esil, "0,fl,=,r%d,r%d,>=,?{,1,fl,}", b, a);}
		return 3;

//@instruction("bn.sfgts", "rA,rB", "0x3 11 01 110A AAAA BBBB B---", "0,fl,=,r{B},r{A},>,?{{,1,fl,}}")
	}else if(((bytes[0]&0xFF)==0x3D) && ((bytes[1]&0xE0)==0xC0)){
		int a = ((bytes[1]&0x1F) >>  0);
		int b = ((bytes[2]&0xF8) >>  3);
		strcpy(cmd->instr, "b.sfgts");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d", a, b);
		if(esil){r_strbuf_appendf(esil, "0,fl,=,r%d,r%d,>,?{,1,fl,}", b, a);}
		return 3;

//#TODO: sign extend
//@instruction("bn.sfgtu", "rA,rB", "0x3 11 01 111A AAAA BBBB B---", "0,fl,=,r{B},r{A},>,?{{,1,fl,}}")
	}else if(((bytes[0]&0xFF)==0x3D) && ((bytes[1]&0xE0)==0xE0)){
		int a = ((bytes[1]&0x1F) >>  0);
		int b = ((bytes[2]&0xF8) >>  3);
		strcpy(cmd->instr, "b.sfgtu");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d", a, b);
		if(esil){r_strbuf_appendf(esil, "0,fl,=,r%d,r%d,>,?{,1,fl,}", b, a);}
		return 3;

//@instruction("bn.extbz", "rD,rA", "0x3 11 10 -00A AAAA DDDD D000", "0xff,r{A},&,r{D},=,")
	}else if(((bytes[0]&0xFF)==0x3E) && ((bytes[1]&0x60)==0x00) && ((bytes[2]&0x07)==0x00)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[2]&0xF8) >>  3);
		strcpy(cmd->instr, "b.extbz");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d", d, a);
		if(esil){r_strbuf_appendf(esil, "0xff,r%d,&,r%d,=,", a, d);}
		return 3;

//@instruction("bn.extbs", "rD,rA", "0x3 11 10 -00A AAAA DDDD D001", "0,r{D},=,r{A},0x80,&,0x80,==,?{{,0xffffff00,r{D},=,}},0xff,r{A},&,r{D},|=,")
	}else if(((bytes[0]&0xFF)==0x3E) && ((bytes[1]&0x60)==0x00) && ((bytes[2]&0x07)==0x01)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[2]&0xF8) >>  3);
		strcpy(cmd->instr, "b.extbs");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d", d, a);
		if(esil){r_strbuf_appendf(esil, "0,r%d,=,r%d,0x80,&,0x80,==,?{,0xffffff00,r%d,=,},0xff,r%d,&,r%d,|=,", d, a, d, a, d);}
		return 3;

//@instruction("bn.exthz", "rD,rA", "0x3 11 10 -00A AAAA DDDD D010", "0xffff,r{A},&,r{D},=,")
	}else if(((bytes[0]&0xFF)==0x3E) && ((bytes[1]&0x60)==0x00) && ((bytes[2]&0x07)==0x02)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[2]&0xF8) >>  3);
		strcpy(cmd->instr, "b.exthz");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d", d, a);
		if(esil){r_strbuf_appendf(esil, "0xffff,r{A},&,r{D},=,", a, d);}
		return 3;

//@instruction("bn.exths", "rD,rA", "0x3 11 10 -00A AAAA DDDD D011", "0,r{D},=,r{A},0x8000,&,0x8000,==,?{{,0xffff0000,r{D},=,}},0xffff,r{A},&,r{D},|=,")
	}else if(((bytes[0]&0xFF)==0x3E) && ((bytes[1]&0x60)==0x00) && ((bytes[2]&0x07)==0x03)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[2]&0xF8) >>  3);
		strcpy(cmd->instr, "b.exths");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d", d, a);
		return 3;

//#TODO: tricky, find index of first 1 bit, starting from LSB
//@instruction("bn.ff1", "rD,rA", "0x3 11 10 -00A AAAA DDDD D100")
	}else if(((bytes[0]&0xFF)==0x3E) && ((bytes[1]&0x60)==0x00) && ((bytes[2]&0x07)==0x04)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[2]&0xF8) >>  3);
		strcpy(cmd->instr, "b.ff1");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d", d, a);
		return 3;

//@instruction("bn.beqi", "rB,E,P", "0x4 00 00 EEEB BBBB PPPP PPPP", "{E},r{B},==,$z,?{{,3,{P},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0x40)){
		int p = revbits(bytes[2]&0xFF, 8);
		int b = bytes[1]&0x1F;
		int e = revbits(((bytes[1]&0xE0) >> 5), 3);
		if(p & (1 << 7)){ p = p - (1 << 8); }
		strcpy(cmd->instr, "b.beqi");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x, %x", b, e, (unsigned int)(pc+p));
		if(esil){r_strbuf_appendf(esil, "%d,r%d,==,$z,?{,3,%d,-,pc,+=,}", e, b, p);}
		if(anal){
			anal->type = R_ANAL_OP_TYPE_CJMP;
			anal->jump = pc + p;
			anal->fail = pc + 3;
		}
		return 3;

//@instruction("bn.bnei", "rB,E,P", "0x4 00 01 EEEB BBBB PPPP PPPP", "{E},r{B},==,$z,!,?{{,3,{P},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0x41)){
		int p = revbits(bytes[2]&0xFF, 8);
		int b = bytes[1]&0x1F;
		int e = revbits(((bytes[1]&0xE0) >> 5), 3);
		if(p & (1 << 7)){ p = p - (1 << 8); }
		strcpy(cmd->instr, "b.bnei");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x, %x", b, e, (unsigned int)(pc+p));
		if(esil){r_strbuf_appendf(esil, "%d,r%d,==,$z,!,?{,3,%d,-,pc,+=,}", e, b, p);}
		if(anal){
			anal->type = R_ANAL_OP_TYPE_CJMP;
			anal->jump = pc + p;
			anal->fail = pc + 3;
		}
		return 3;

//@instruction("bn.bgesi", "rB,E,P", "0x4 00 10 EEEB BBBB PPPP PPPP", "{E},r{B},>=,?{{,3,{P},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0x42)){
		int p = bytes[2]&0xFF;
		int b = bytes[1]&0x1F;
		int e = ((bytes[1]&0xE0) >> 5);
		strcpy(cmd->instr, "b.bgesi");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, %d, %d [+PC]", b, e, p);
		return 3;

//@instruction("bn.bgtsi", "rB,E,P", "0x4 00 11 EEEB BBBB PPPP PPPP", "{E},r{B},>,?{{,3,{P},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0x43)){
		int p = bytes[2]&0xFF;
		int b = bytes[1]&0x1F;
		int e = ((bytes[1]&0xE0) >> 5);
		strcpy(cmd->instr, "b.bgtsi");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, %d, %d [+PC]", b, e, p);
		return 3;

//@instruction("bn.bltsi", "rB,E,P", "0x4 01 01 EEEB BBBB PPPP PPPP", "{E},r{B},<,?{{,3,{P},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0x45)){
		int p = bytes[2]&0xFF;
		int b = bytes[1]&0x1F;
		int e = ((bytes[1]&0xE0) >> 5);
		strcpy(cmd->instr, "b.bltsi");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, %d, %d [+PC]", b, e, p);
		return 3;

//@instruction("bn.j", "Z",  "0x4 01 10 ZZZZ ZZZZ ZZZZ ZZZZ", "{Z},pc,=")
	}else if(((bytes[0]&0xFF)==0x46)){
		int z = revbits(((bytes[1]&0xFF) << 8) | ((bytes[2]&0xFF) << 0), 16);
		strcpy(cmd->instr, "b.j");
		if(z & (1 << 15)){ z = z - (1 << 16); }
		snprintf(cmd->operands, sizeof(cmd->operands), "%x", (unsigned int)(pc+z));
		return 3;

	}else if(((bytes[0]&0xFF)==0x47) && ((bytes[1]&0xF0)==0xA0)){
//#TODO: function prologue - frame construction
//# Push F GPRs (beginning with $lr/R9) onto the stack, then reduce the $sp/R1 by
//# an additional N 32-bit words.
//@instruction("bn.entri", "F,N",  "0x4 01 11 1010 FFFF NNNN NNNN")
//		int n = revbits[bytes[2]&0xFF];
//		int f = revbits[(bytes[1]&0x0F) << 4];
		int n = revbits(bytes[2]&0xFF, 8);
		int f = revbits(bytes[1]&0x0F, 4);
		strcpy(cmd->instr, "b.entri");
//		snprintf(cmd->operands, sizeof(cmd->operands), "%d, %d", f, n);
		snprintf(cmd->operands, sizeof(cmd->operands), "0x%x, 0x%x", f, n);
		if(esil){
			int reg = 9;
			while(f>0){
				r_strbuf_appendf(esil, "4,sp,-=,r%d,sp,=[4],", reg);
				reg++;
				f--;
			}
			r_strbuf_appendf(esil, "%d,sp,-=", n*4);
		}
		return 3;

//#TODO: function epilogue - frame deconstruction
//# Increase the $sp/R1 by N 32-bit words, then pop F GPRs (ending with $lr/R9)
//# Possibly returns, as well? (based on the fact that it's the final instruction of many functions)
//@instruction("bn.reti", "F,N",  "0x4 01 11 1011 FFFF NNNN NNNN")
	}else if(((bytes[0]&0xFF)==0x47) && ((bytes[1]&0xF0)==0xB0)){
		int n = revbits(bytes[2]&0xFF, 8);
		int f = revbits(bytes[1]&0x0F, 4);
		strcpy(cmd->instr, "b.reti");
		snprintf(cmd->operands, sizeof(cmd->operands), "0x%x, 0x%x", f, n);
		if(esil){
			r_strbuf_appendf(esil, "%d,sp,+=", n*4);
			int reg = 9+f-1;
			while(f>0){
				r_strbuf_appendf(esil, "sp,[4],r%d,=4,sp,+=,", reg);
				reg--;
				f--;
			}
		}
		return 3;

//#TODO: unknown... function epilogue - stack ops
//@instruction("bn.rtnei", "F,N",  "0x4 01 11 1100 FFFF NNNN NNNN")
	}else if(((bytes[0]&0xFF)==0x47) && ((bytes[1]&0xF0)==0xC0)){
		int n = revbits(bytes[2]&0xFF, 8);
		int f = revbits(bytes[1]&0x0F, 4);
		strcpy(cmd->instr, "b.rtnei");
		snprintf(cmd->operands, sizeof(cmd->operands), "0x%x, 0x%x", f, n);
		return 3;

//@instruction("bn.jalr", "rA",  "0x4 01 11 1101 --01 AAAA A---", "pc,lr,=,r{A},pc,=")
	}else if(((bytes[0]&0xFF)==0x47) && ((bytes[1]&0xF3)==0xD1)){
		int a = (bytes[2]&0xF8) >> 3;
		strcpy(cmd->instr, "b.jalr");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d", a);
		if(esil){r_strbuf_appendf(esil, "pc,lr,=,r%d,pc,=", a);}
		if(anal){
			anal->type = R_ANAL_OP_TYPE_UJMP;
//			anal->jump = addr + (4 * ((d[0] >> 4) | (d[1] << 8) | (d[2] << 16)));
//			anal->fail = addr + 4;
		}
		return 3;

//@instruction("bn.jr", "rA",  "0x4 01 11 1101 --10 AAAA A---", "r{A},pc,=")
	}else if(((bytes[0]&0xFF)==0x47) && ((bytes[1]&0xF3)==0xD2)){
		int a = (bytes[2]&0xF8) >> 3;
		strcpy(cmd->instr, "b.jr");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d", a);
		if(esil){r_strbuf_appendf(esil, "r%d,pc,=", a);}
		if(anal){
			anal->type = R_ANAL_OP_TYPE_UJMP;
		}
		return 3;
		
//@instruction("bn.bf", "S",  "0x4 01 11 0010 SSSS SSSS SSSS", "fl,1,==,?{{,3,{S},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0x47) && ((bytes[1]&0xF0)==0x20)){
		int s = revbits(((bytes[1]&0x0F) <<  8) | ((bytes[2]&0xFF) >>  0), 12);
		strcpy(cmd->instr, "b.bf");
		if(s & (1 << 11)){
			s = s - (1 << 12);
//			snprintf(cmd->operands, sizeof(cmd->operands), "-0x%x [+PC]", -s);
		}else{
//			snprintf(cmd->operands, sizeof(cmd->operands), "0x%x [+PC]", s);
		}
		snprintf(cmd->operands, sizeof(cmd->operands), "%x", (unsigned int)(pc+s));
		if(esil){r_strbuf_appendf(esil, "fl,1,==,?{,3,{S},-,pc,+=,}", s);}
		return 3;

//@instruction("bn.bnf", "S",  "0x4 01 11 0011 SSSS SSSS SSSS", "fl,0,==,?{{,3,{S},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0x47) && ((bytes[1]&0xF0)==0x30)){
		int s = revbits(((bytes[1]&0x0F) <<  8) | ((bytes[2]&0xFF) >>  0), 12);
		strcpy(cmd->instr, "b.bnf");
		if(s & (1 << 11)){
			s = s - (1 << 12);
//			snprintf(cmd->operands, sizeof(cmd->operands), "-0x%x [+PC]", -s);
		}else{
//			snprintf(cmd->operands, sizeof(cmd->operands), "0x%x [+PC]", s);
		}
		snprintf(cmd->operands, sizeof(cmd->operands), "0x%x", (unsigned int)(pc+s));
		if(esil){r_strbuf_appendf(esil, "fl,0,==,?{,3,0x%x,-,pc,+=,}", s);}
		return 3;

	}else if(((bytes[0]&0xFC)==0x48)){
//@instruction("bn.jal", "s",  "0x4 10 ss ssss ssss ssss ssss", "pc,lr,=,3,{s},-,pc,+=")
		int s = revbits(((bytes[0]&0x03) << 16) | ((bytes[1]&0xFF) <<  8) | ((bytes[2]&0xFF) <<  0), 18);
//		if(s & (1<<17)){s = s - (1<<18);}
		strcpy(cmd->instr, "b.jal");
// Must add PC (a->pc)
		if(s & (1<<17)){
			s = s - (1<<18);
//			snprintf(cmd->operands, sizeof(cmd->operands), "-0x%x [+PC]", -s);
		}else{
//			snprintf(cmd->operands, sizeof(cmd->operands), "0x%x [+PC]", s);
		}
		snprintf(cmd->operands, sizeof(cmd->operands), "0x%x", (unsigned int)(pc+s));
		if(esil){r_strbuf_appendf(esil, "pc,lr,=,3,0x%x,-,pc,+=", s);}
		if(anal){
			anal->type = R_ANAL_OP_TYPE_CALL;
			anal->jump = pc + s;
			anal->fail = pc + 3;
		}
		return 3;

//#TODO: unknown
//@instruction("bn.mlwz", "rD,K(rA),C", "0x5 00 DD DDDA AAAA CCKK KKKK")
	}else if(((bytes[0]&0xFC)==0x50)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int c = revbits(((bytes[2]&0xC0) >> 6), 2);
		int k = revbits(((bytes[2]&0x3F) >> 0), 6);
		strcpy(cmd->instr, "b.mlwz");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x(r%d), 0x%x", d, 4*k, a, c);
		return 3;

//#TODO: unknown
//@instruction("bn.msw", "K(rA),rB,C", "0x5 01 BB BBBA AAAA CCKK KKKK")
	}else if(((bytes[0]&0xFC)==0x54)){
		int a = ((bytes[1]&0x1F) >>  0);
		int b = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int c = revbits(((bytes[2]&0xC0) >> 6), 2);
		int k = revbits(((bytes[2]&0x3F) >> 0), 6);
		strcpy(cmd->instr, "b.msw");
		snprintf(cmd->operands, sizeof(cmd->operands), "0x%x(r%d), r%d, 0x%x", 4*k, a, b, c);
		return 3;

//#TODO: unknown
//@instruction("bn.mld", "rD,H(rA),C", "0x5 10 DD DDDA AAAA CC0H HHHH")
	}else if(((bytes[0]&0xFC)==0x58) && ((bytes[2]&0x20) == 0x00)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int c = revbits(((bytes[2]&0xC0) >> 6), 2);
		int h = revbits(((bytes[2]&0x1F) >> 0), 5);
//		strcpy(cmd->instr, "b.mld");
		strcpy(cmd->instr, "bn.mld");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x(r%d), 0x%x", d, h, a, c);
		return 3;

//@instruction("bn.and", "rD,rA,rB", "0x6 00 DD DDDA AAAA BBBB B000", "r{B},r{A},&,r{D},=")
	}else if(((bytes[0]&0xFC)==0x60) && ((bytes[2]&0x07)==0x00)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int b = ((bytes[2]&0xF8) >> 3);
		strcpy(cmd->instr, "b.and");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, r%d", d, a, b);
		if(esil){r_strbuf_appendf(esil, "r%d,r%d,&,r%d,=", b, a, d);}
		if(anal){
			anal->type = R_ANAL_OP_TYPE_AND;
		}
		return 3;
//@instruction("bn.or", "rD,rA,rB", "0x6 00 DD DDDA AAAA BBBB B001", "r{B},r{A},|,r{D},=")
	}else if(((bytes[0]&0xFC)==0x60) && ((bytes[2]&0x07)==0x01)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int b = ((bytes[2]&0xF8) >> 3);
		strcpy(cmd->instr, "b.or");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, r%d", d, a, b);
		if(esil){r_strbuf_appendf(esil, "r%d,r%d,|,r%d,=", b, a, d);}
		if(anal){
			anal->type = R_ANAL_OP_TYPE_OR;
		}
		return 3;
//@instruction("bn.xor", "rD,rA,rB", "0x6 00 DD DDDA AAAA BBBB B010", "r{B},r{A},^,r{D},=")
	}else if(((bytes[0]&0xFC)==0x60) && ((bytes[2]&0x07)==0x02)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int b = ((bytes[2]&0xF8) >> 3);
		strcpy(cmd->instr, "b.xor");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, r%d", d, a, b);
		return 3;

//@instruction("bn.nand", "rD,rA,rB", "0x6 00 DD DDDA AAAA BBBB B011", "r{B},r{A},&,!,r{D},=")
	}else if(((bytes[0]&0xFC)==0x60) && ((bytes[2]&0x07)==0x03)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int b = ((bytes[2]&0xF8) >> 3);
		strcpy(cmd->instr, "b.nand");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, r%d", d, a, b);
		if(esil){r_strbuf_appendf(esil, "r%d,r%d,&,!,r%d,=", b, a, d);}
		return 3;

//#TODO: set carry/overflow
//@instruction("bn.add", "rD,rA,rB", "0x6 00 DD DDDA AAAA BBBB B100", "r{B},r{A},+,r{D},=")
	}else if(((bytes[0]&0xFC)==0x60) && ((bytes[2]&0x07)==0x04)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int b = ((bytes[2]&0xF8) >> 3);
		strcpy(cmd->instr, "b.add");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, r%d", d, a, b);
		if(esil){r_strbuf_appendf(esil, "r%d,r%d,+,r%d,=", b, a, d);}
		if(anal){
			anal->type = R_ANAL_OP_TYPE_ADD;
		}
		return 3;

//#TODO: set carry/overflow
//@instruction("bn.sub", "rD,rA,rB", "0x6 00 DD DDDA AAAA BBBB B101", "r{B},r{A},-,r{D},=")
	}else if(((bytes[0]&0xFC)==0x60) && ((bytes[2]&0x07)==0x05)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int b = ((bytes[2]&0xF8) >> 3);
		strcpy(cmd->instr, "b.sub");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, r%d", d, a, b);
		if(esil){r_strbuf_appendf(esil, "r%d,r%d,-,r%d,=", b, a, d);}
		return 3;

//#TODO: should be logical
//@instruction("bn.sll", "rD,rA,rB", "0x6 00 DD DDDA AAAA BBBB B110", "r{B},r{A},<<,r{D},=")
	}else if(((bytes[0]&0xFC)==0x60) && ((bytes[2]&0x07)==0x06)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int b = ((bytes[2]&0xF8) >> 3);
		strcpy(cmd->instr, "b.sll");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, r%d", d, a, b);
		return 3;

//#TODO: should be logical
//@instruction("bn.srl", "rD,rA,rB", "0x6 00 DD DDDA AAAA BBBB B111", "r{B},r{A},>>,r{D},=")
	}else if(((bytes[0]&0xFC)==0x60) && ((bytes[2]&0x07)==0x07)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int b = ((bytes[2]&0xF8) >> 3);
		strcpy(cmd->instr, "b.srl");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, r%d", d, a, b);
		if(esil){r_strbuf_appendf(esil, "r%d,r%d,>>,r%d,=", b, a, d);}
		return 3;

//#TODO: should be arithmetic
//@instruction("bn.sra", "rD,rA,rB", "0x6 01 DD DDDA AAAA BBBB B000", "r{B},r{A},>>,r{D},=")
	}else if(((bytes[0]&0xFC)==0x64) && ((bytes[2]&0x07)==0x00)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int b = ((bytes[2]&0xF8) >> 3);
		strcpy(cmd->instr, "b.sra");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, r%d", d, a, b);
		return 3;

//@instruction("bn.cmov", "rD,rA,rB", "0x6 01 DD DDDA AAAA BBBB B010", "r{B},r{D},=,fl,1,==,?{{,r{A},r{D},=,}}")
	}else if(((bytes[0]&0xFC)==0x64) && ((bytes[2]&0x07)==0x02)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int b = ((bytes[2]&0xF8) >> 3);
		strcpy(cmd->instr, "b.cmov");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, r%d", d, a, b);
		if(esil){r_strbuf_appendf(esil, "r%d,r%d,=,fl,1,==,?{,r%d,r%d,=,}", b, d, a, d);}
		return 3;

//#TODO: set overflow, treat as signed
//@instruction("bn.mul", "rD,rA,rB", "0x6 01 DD DDDA AAAA BBBB B011", "r{B},r{A},*,r{D},=")
	}else if(((bytes[0]&0xFC)==0x64) && ((bytes[2]&0x07)==0x03)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int b = ((bytes[2]&0xF8) >> 3);
		strcpy(cmd->instr, "b.mul");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, r%d", d, a, b);
		if(esil){r_strbuf_appendf(esil, "r%d,r%d,*,r%d,=", b, a, d);}
		return 3;

//#TODO: should be logical
//@instruction("bn.slli", "rD,rA,H", "0x6 11 DD DDDA AAAA HHHH H-00", "{H},r{A},<<,r{D},=")
	}else if(((bytes[0]&0xFC)==0x6C) && ((bytes[2]&0x03)==0x00)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int h = revbits(((bytes[2]&0xF8) >>  3), 5);
		strcpy(cmd->instr, "b.slli");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, 0x%x", d, a, h);
		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,<<,r%d,=", h, a, d);}
		return 3;

//#TODO: should be logical
//@instruction("bn.srli", "rD,rA,H", "0x6 11 DD DDDA AAAA HHHH H-01", "{H},r{A},>>,r{D},=")
	}else if(((bytes[0]&0xFC)==0x6C) && ((bytes[2]&0x03)==0x01)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int h = revbits(((bytes[2]&0xF8) >>  3), 5);
		strcpy(cmd->instr, "b.srli");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, 0x%x", d, a, h);
		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,>>,r%d,=", h, a, d);}
		return 3;

//#TODO: should be arithmetic
//@instruction("bn.srai", "rD,rA,H", "0x6 11 DD DDDA AAAA HHHH H-10", "{H},r{A},>>,r{D},=")
	}else if(((bytes[0]&0xFC)==0x6C) && ((bytes[2]&0x03)==0x02)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int h = revbits(((bytes[2]&0xF8) >>  3), 5);
		strcpy(cmd->instr, "b.srai");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, 0x%x", d, a, h);
		return 3;

//#TODO: should be logical; signed?
//@instruction("bn.slls", "rD,rA,rB", "0x7 10 DD DDDA AAAA BBBB B-00", "r{B},r{A},<<,r{D},=")
	}else if(((bytes[0]&0xFC)==0x78) && ((bytes[2]&0x03)==0x00)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int b = ((bytes[2]&0xF8) >>  3);
		strcpy(cmd->instr, "b.slls");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, r%d", d, a, b);
		return 3;


//@instruction("bw.sb", "h(rA),rB", "0x8 00 BB BBBA AAAA hhhh hhhh hhhh hhhh hhhh hhhh hhhh hhhh", "r{B},{h},r{A},+,=[1]")
	}else if(((bytes[0]&0xFC)==0x80)){
		int a = ((bytes[1]&0x1F) >>  0);
		int b = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int h = revbits(((bytes[2]&0xFF) << 24) | ((bytes[3]&0xFF) << 16) | ((bytes[4]&0xFF) <<  8) | ((bytes[5]&0xFF) <<  0), 32);
		strcpy(cmd->instr, "b.sb");
		snprintf(cmd->operands, sizeof(cmd->operands), "0x%x(r%d), r%d", h, a, b);
		if(esil){r_strbuf_appendf(esil, "r%d,0x%x,r%d,+,=[1]", b, h, a);}
		return 6;

//#TODO: zero extend
//@instruction("bw.lbz", "rD,h(rA)", "0x8 01 DD DDDA AAAA hhhh hhhh hhhh hhhh hhhh hhhh hhhh hhhh", "{h},r{A},+,[1],r{D},=")
	}else if(((bytes[0]&0xFC)==0x84)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int h = revbits(((bytes[2]&0xFF) << 24) | ((bytes[3]&0xFF) << 16) | ((bytes[4]&0xFF) <<  8) | ((bytes[5]&0xFF) <<  0), 32);
		strcpy(cmd->instr, "b.lbz");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x(r%d)", d, h, a);
		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,+,[1],r%d,=", h, a, d);}
		return 6;


//@instruction("bw.sh", "i(rA),rB", "0x8 10 BB BBBA AAAA 0iii iiii iiii iiii iiii iiii iiii iiii", "r{B},{i},r{A},+,=[2]")
	}else if(((bytes[0]&0xFC)==0x88) && ((bytes[2]&0x80)==0x00)){
		int a = ((bytes[1]&0x1F) >>  0);
		int b = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int i = revbits(((bytes[2]&0x7F) << 24) | ((bytes[3]&0xFF) << 16) | ((bytes[4]&0xFF) <<  8) | ((bytes[5]&0xFF) <<  0), 31);
		strcpy(cmd->instr, "b.sh");
		snprintf(cmd->operands, sizeof(cmd->operands), "0x%x(r%d), r%d", i*2, a, b);
		if(esil){r_strbuf_appendf(esil, "r%d,0x%x,r%d,+,=[2]", b, i, a);}
		return 6;
		
//#TODO: zero extend
//@instruction("bw.lhz", "rD,i(rA)", "0x8 10 DD DDDA AAAA 1iii iiii iiii iiii iiii iiii iiii iiii", "{i},r{A},+,[2],r{D},=")
	}else if(((bytes[0]&0xFC)==0x88) && ((bytes[2]&0x80)==0x80)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int i = revbits(((bytes[2]&0x7F) << 24) | ((bytes[3]&0xFF) << 16) | ((bytes[4]&0xFF) <<  8) | ((bytes[5]&0xFF) <<  0), 31);
		strcpy(cmd->instr, "b.lhz");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x(r%d)", d, i*2, a);
		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,+,[2],r%d,=", i, a, d);}
		return 6;

//@instruction("bw.sw", "w(rA),rB", "0x8 11 BB BBBA AAAA 00ww wwww wwww wwww wwww wwww wwww wwww", "r{B},{w},r{A},+,=[4]")
	}else if(((bytes[0]&0xFC)==0x8C) && ((bytes[2]&0xC0)==0x00)){
		int a = ((bytes[1]&0x1F) >>  0);
		int b = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int w = revbits(((bytes[2]&0x3F) << 24) | ((bytes[3]&0xFF) << 16) | ((bytes[4]&0xFF) <<  8) | ((bytes[5]&0xFF) <<  0), 30);
		strcpy(cmd->instr, "b.sw");
		if(w & (1 << 14)){
			w = w - (1 << 15);
			snprintf(cmd->operands, sizeof(cmd->operands), "-0x%x(r%d), r%d", -w*4, a, b);
		}else{
			snprintf(cmd->operands, sizeof(cmd->operands), "0x%x(r%d), r%d", w*4, a, b);
		}
		if(esil){r_strbuf_appendf(esil, "r%d,0x%x,r%d,+,=[4]", b, w, a);}
		return 6;

//@instruction("bw.lwz", "rD,w(rA)", "0x8 11 DD DDDA AAAA 01ww wwww wwww wwww wwww wwww wwww wwww", "{w},r{A},+,[4],r{D},=")
	}else if(((bytes[0]&0xFC)==0x8C) && ((bytes[2]&0xC0)==0x40)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int w = revbits(((bytes[2]&0x3F) << 24) | ((bytes[3]&0xFF) << 16) | ((bytes[4]&0xFF) <<  8) | ((bytes[5]&0xFF) <<  0), 30);
		strcpy(cmd->instr, "b.lwz");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x(r%d)", d, w*4, a);
		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,+,[4],r%d,=", w, a, d);}
		if(anal){
			anal->type = R_ANAL_OP_TYPE_MOV;
		}
		return 6;

//@instruction("bw.addi", "rD,rA,g", "0x9 00 DD DDDA AAAA gggg gggg gggg gggg gggg gggg gggg gggg", "{g},r{A},+,r{D},=")
	}else if(((bytes[0]&0xFC)==0x90)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int g = revbits(((bytes[2]&0xFF) << 24) | ((bytes[3]&0xFF) << 16) | ((bytes[4]&0xFF) <<  8) | ((bytes[5]&0xFF) <<  0), 32);
		strcpy(cmd->instr, "b.addi");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, 0x%x", d, a, g);
		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,+,r%d,=", g, a, d);}
		if(anal){
			anal->type = R_ANAL_OP_TYPE_ADD;
		}
		return 6;

// @instruction("f.abs.s", "rD,rA", "0x9 01 DD DDDA AAAA 1111 1111 1111 1111 1111 1111 1111 1110", "0x7fffffff,r{A},&,r{D},=")
	}else if(((bytes[0]&0xFC)==0x94) && ((bytes[2]&0xFF)==0xFF) && ((bytes[3]&0xFF)==0xFF) && ((bytes[4]&0xFF)==0xFF) && ((bytes[5]&0xFF)==0xFE)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		strcpy(cmd->instr, "f.abs.s");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d", d, a);
		return 6;

//@instruction("bw.andi", "rD,rA,h", "0x9 01 DD DDDA AAAA hhhh hhhh hhhh hhhh hhhh hhhh hhhh hhhh", "{h},r{A},&,r{D},=")
	}else if(((bytes[0]&0xFC)==0x94)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int h = revbits(((bytes[2]&0xFF) << 24) | ((bytes[3]&0xFF) << 16) | ((bytes[4]&0xFF) <<  8) | ((bytes[5]&0xFF) <<  0), 32);
		strcpy(cmd->instr, "b.andi");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, 0x%x", d, a, h);
		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,&,r%d,=", h, a, d);}
		return 6;


//@instruction("bw.ori", "rD,rA,h", "0x9 10 DD DDDA AAAA hhhh hhhh hhhh hhhh hhhh hhhh hhhh hhhh", "{h},r{A},|,r{D},=")
	}else if(((bytes[0]&0xFC)==0x98)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int h = revbits(((bytes[2]&0xFF) << 24) | ((bytes[3]&0xFF) << 16) | ((bytes[4]&0xFF) <<  8) | ((bytes[5]&0xFF) <<  0), 32);
		strcpy(cmd->instr, "b.ori");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, 0x%x", d, a, h);
		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,|,r%d,=", h, a, d);}
		if(anal){
			anal->type = R_ANAL_OP_TYPE_OR;
		}
		return 6;

//@instruction("bw.sfeqi", "rA,g",  "0x9 11 01 10-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", "0,fl,=,r{A},{g},==,$z,?{{,1,fl,}}")
	}else if(((bytes[0]&0xFF)==0x9D) && ((bytes[1]&0xC0)==0x80)){
		int a = ((bytes[1]&0x1F) >>  0);
		int g = revbits(((bytes[2]&0xFF) << 24) | ((bytes[3]&0xFF) << 16) | ((bytes[4]&0xFF) <<  8) | ((bytes[5]&0xFF) <<  0), 32);
		strcpy(cmd->instr, "b.sfeqi");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x", a, g);
		if(esil){r_strbuf_appendf(esil, "0,fl,=,r%d,0x%x,==,$z,?{{,1,fl,}}", a, g);}
		return 6;

//@instruction("bw.sfnei", "rA,g",  "0x9 11 01 11-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", "0,fl,=,r{A},{g},==,$z,!,?{{,1,fl,}}")
	}else if(((bytes[0]&0xFF)==0x9D) && ((bytes[1]&0xC0)==0xC0)){
		int a = ((bytes[1]&0x1F) >>  0);
		int g = revbits(((bytes[2]&0xFF) << 24) | ((bytes[3]&0xFF) << 16) | ((bytes[4]&0xFF) <<  8) | ((bytes[5]&0xFF) <<  0), 32);
		strcpy(cmd->instr, "b.sfnei");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x", a, g);
		if(esil){r_strbuf_appendf(esil, "0,fl,=,r%d,0x%x,==,$z,!,?{,1,fl,}", a, g);}
		return 6;

//#TODO: sign extend
//@instruction("bw.sfgtui", "rA,g",  "0x9 11 10 11-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", "0,fl,=,{g},r{A},>,?{{,1,fl,}}")
	}else if(((bytes[0]&0xFF)==0x9E) && ((bytes[1]&0xC0)==0xC0)){
		int a = ((bytes[1]&0x1F) >>  0);
		int g = revbits(((bytes[2]&0xFF) << 24) | ((bytes[3]&0xFF) << 16) | ((bytes[4]&0xFF) <<  8) | ((bytes[5]&0xFF) <<  0), 32);
		strcpy(cmd->instr, "b.sfgtui");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x", a, g);
		if(esil){r_strbuf_appendf(esil, "0,fl,=,0x%x,r%d,>,?{,1,fl,}", g, a);}
		return 6;

//@instruction("bw.sflesi", "rA,g",  "0x9 11 11 00-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", "0,fl,=,{g},r{A},<=,?{{,1,fl,}}")
	}else if(((bytes[0]&0xFF)==0x9F) && ((bytes[1]&0xC0)==0x00)){
		int a = ((bytes[1]&0x1F) >>  0);
		int g = revbits(((bytes[2]&0xFF) << 24) | ((bytes[3]&0xFF) << 16) | ((bytes[4]&0xFF) <<  8) | ((bytes[5]&0xFF) <<  0), 32);
		strcpy(cmd->instr, "b.sflesi");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x", a, g);
		return 6;

/*
//#TODO: zero extend
//@instruction("bw.lwz", "rD,w(rA)", "0x8 11 DD DDDA AAAA 01ww wwww wwww wwww wwww wwww wwww wwww", "{w},r{A},+,[4],r{D},=")
	}else if(((bytes[0]&0xFC)==0xCC) && ((bytes[2]&0xC0)==0x40)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int w = revbits(((bytes[2]&0x3F) << 24) | ((bytes[3]&0xFF) << 16) | ((bytes[4]&0xFF) <<  8) | ((bytes[5]&0xFF) <<  0), 30);
		strcpy(cmd->instr, "b.lwz");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x(r%d)", d, w*4, a);
		return 6;
*/

//@instruction("bw.beqi", "rB,I,u", "0xa 00 00 00II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "{I},r{B},==,$z,?{{,6,{u},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0xA0) && ((bytes[1]&0xC0)==0x00)){
		int i = revbits(((bytes[1]&0x3E) >>  1), 5);
		int b = ((bytes[1]&0x01) <<  4) | ((bytes[2]&0xF0) >>  4);
		int u = revbits(((bytes[2]&0x0F) << 24) | ((bytes[3]&0xFF) << 16) | ((bytes[4]&0xFF) <<  8) | ((bytes[5]&0xFF) <<  0), 28);
		strcpy(cmd->instr, "b.beqi");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x, %x", b, i, (unsigned int)(pc+u));
		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,==,$z,?{,6,0x%x,-,pc,+=,}", i, b, u);}
		if(anal){
			anal->type = R_ANAL_OP_TYPE_CJMP;
			anal->jump = pc + u;
			anal->fail = pc + 6;
		}
		return 6;


//@instruction("bw.bnei", "rB,I,u", "0xa 00 00 01II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "{I},r{B},==,$z,!,?{{,6,{u},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0xA0) && ((bytes[1]&0xC0)==0x40)){
		int i = ((bytes[1]&0x3E) >>  1);
		int b = ((bytes[1]&0x01) <<  4) | ((bytes[2]&0xF0) >>  4);
		int u = revbits(((bytes[2]&0x0F) << 24) | ((bytes[3]&0xFF) << 16) | ((bytes[4]&0xFF) <<  8) | ((bytes[5]&0xFF) <<  0), 28);
		strcpy(cmd->instr, "b.bnei");
// Must add PC (a->pc)
		if(u & (1 << 27)){ u = u - (1 << 28);}
//		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x, %x [+PC]", b, i, u);
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x, %x", b, i, (unsigned int)(pc+u));
		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,==,$z,!,?{,6,0x%x,-,pc,+=,}", i, b, u);}
		if(anal){
			anal->type = R_ANAL_OP_TYPE_CJMP;
			anal->jump = pc + u;
			anal->fail = pc + 6;
		}
		return 6;

//@instruction("bw.beq", "rA,rB,u", "0xa 00 10 10AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "r{B},r{A},==,$z,?{{,6,{u},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0xA2) && ((bytes[1]&0xC0)==0x80)){
		int a = ((bytes[1]&0x3E) >>  1);
		int b = ((bytes[1]&0x01) <<  4) | ((bytes[2]&0xF0) >>  4);
		int u = revbits(((bytes[2]&0x0F) << 24) | ((bytes[3]&0xFF) << 16) | ((bytes[4]&0xFF) <<  8) | ((bytes[5]&0xFF) <<  0), 28);
		strcpy(cmd->instr, "b.beq");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, %x [+PC]", a, b, u);
		if(esil){r_strbuf_appendf(esil, "r%d,r%d,==,$z,?{,6,0x%x,-,pc,+=,}", b, a, u);}
		return 6;

//@instruction("bw.bne", "rA,rB,u", "0xa 00 10 11AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "r{B},r{A},==,$z,!,?{{,6,{u},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0xA2) && ((bytes[1]&0xC0)==0xC0)){
		int a = ((bytes[1]&0x3E) >>  1);
		int b = ((bytes[1]&0x01) <<  4) | ((bytes[2]&0xF0) >>  4);
		int u = revbits(((bytes[2]&0x0F) << 24) | ((bytes[3]&0xFF) << 16) | ((bytes[4]&0xFF) <<  8) | ((bytes[5]&0xFF) <<  0), 28);
		strcpy(cmd->instr, "b.bne");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, %x [+PC]", a, b, u);
		if(esil){r_strbuf_appendf(esil, "r%d,r%d,==,$z,!,?{,6,0x%x,-,pc,+=,}", b, a, u);}
		return 6;

//@instruction("bw.bgts", "rA,rB,u", "0xa 00 11 01AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "r{B},r{A},>,?{{,6,{u},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0xA3) && ((bytes[1]&0xC0)==0x40)){
		int a = ((bytes[1]&0x3E) >>  1);
		int b = ((bytes[1]&0x01) <<  4) | ((bytes[2]&0xF0) >>  4);
		int u = revbits(((bytes[2]&0x0F) << 24) | ((bytes[3]&0xFF) << 16) | ((bytes[4]&0xFF) <<  8) | ((bytes[5]&0xFF) <<  0), 28);
		strcpy(cmd->instr, "b.bgts");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, %x [+PC]", a, b, u);
		return 6;

//#TODO: treat as unsigned
//@instruction("bw.bgeu", "rA,rB,u", "0xa 00 11 10AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "r{B},r{A},>=,?{{,6,{u},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0xA3) && ((bytes[1]&0xC0)==0x80)){
		int a = ((bytes[1]&0x3E) >>  1);
		int b = ((bytes[1]&0x01) <<  4) | ((bytes[2]&0xF0) >>  4);
		int u = revbits(((bytes[2]&0x0F) << 24) | ((bytes[3]&0xFF) << 16) | ((bytes[4]&0xFF) <<  8) | ((bytes[5]&0xFF) <<  0), 28);
		strcpy(cmd->instr, "b.bgeu");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, %x [+PC]", a, b, u);
		return 6;


//#TODO: jump absolute
//@instruction("bw.ja", "g",  "0xa 01 01 00-- ---- gggg gggg gggg gggg gggg gggg gggg gggg")
	}else if(((bytes[0]&0xFF)==0xA5) && ((bytes[1]&0xC0)==0x00)){
		int g = revbits(((bytes[2]&0xFF) << 24) | ((bytes[3]&0xFF) << 16) | ((bytes[4]&0xFF) <<  8) | ((bytes[5]&0xFF) <<  0), 32);
		strcpy(cmd->instr, "b.ja");
		snprintf(cmd->operands, sizeof(cmd->operands), "0x%x", g);
		return 6;

//@instruction("bw.mfspr", "rD,rA,o", "0xa 10 DD DDDA AAAA oooo oooo oooo oooo oooo oooo ---- -000")
	}else if(((bytes[0]&0xFC)==0xA8) && ((bytes[5]&0x07)==0x00)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int o = revbits(((bytes[2]&0xFF) << 16) | ((bytes[3]&0xFF) <<  8) | ((bytes[4]&0xFF) <<  0), 24);
		strcpy(cmd->instr, "b.mfspr");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, 0x%x", d, a, o);
		if(esil){r_strbuf_appendf(esil, "0xDEADBEEF,r%d,=", d);}							// TODO: MFSPR
		return 6;

//@instruction("bw.mtspr", "rA,rB,o", "0xa 10 BB BBBA AAAA oooo oooo oooo oooo oooo oooo ---- -001")
	}else if(((bytes[0]&0xFC)==0xA8) && ((bytes[5]&0x07)==0x01)){
		int a = ((bytes[1]&0x1F) >>  0);
		int b = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int o = revbits(((bytes[2]&0xFF) << 16) | ((bytes[3]&0xFF) <<  8) | ((bytes[4]&0xFF) <<  0), 24);
		strcpy(cmd->instr, "b.mtspr");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, 0x%x", a, b, o);
		if(esil){r_strbuf_appendf(esil, "r%d,r%d,=", b, b);}								// TODO: MTSPR
		return 6;

//@instruction("bw.mulas", "rD,rA,rB,H", "0xa 11 DD DDDA AAAA BBBB BHHH HH-- ---- ---- ---- --00 0000")
	}else if(((bytes[0]&0xFC)==0xAC) && ((bytes[5]&0x3F)==0x00)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int b = ((bytes[2]&0xF8) >>  3);
		int h = revbits(((bytes[2]&0x07) << 2) | ((bytes[3]&0xC0) >> 3), 5);
		strcpy(cmd->instr, "b.mulas");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, r%d, 0x%x", d, a, b, h);
		return 6;

//@instruction("bw.smadtt", "rD,rA,rB,rR", "0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 0000")
	}else if(((bytes[0]&0xFC)==0xAC) && ((bytes[5]&0x3F)==0x30)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int b = ((bytes[2]&0xF8) >>  3);
		int r = revbits(((bytes[2]&0x07) << 2) | ((bytes[3]&0xC0) >> 3), 5);
		strcpy(cmd->instr, "b.smadtt");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, r%d, r%d", d, a, b, r);
		return 6;

//@instruction("bw.copdss", "rD,rA,rB,y", "0xb 00 DD DDDA AAAA BBBB Byyy yyyy yyyy yyyy yyyy yyyy yyyy")
	}else if(((bytes[0]&0xFC)==0xB0) && ((bytes[5]&0x07)==0x00)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int b = ((bytes[2]&0xF8) >>  3);
		int y = revbits(((bytes[2]&0x07) << 24) | ((bytes[3]&0xFF) << 16) | ((bytes[4]&0xFF) <<  8) | ((bytes[5]&0xFF) <<  0), 27);
		strcpy(cmd->instr, "b.copdss");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, r%d, 0x%x", d, a, b, y);
		return 6;

//@instruction("bw.cop", "g,x",  "0xb 10 xx xxxx xxxx gggg gggg gggg gggg gggg gggg gggg gggg")
	}else if(((bytes[0]&0xFC)==0xB8)){
		int x = ((bytes[0]&0x03) <<  8) | ((bytes[1]&0xFF) >>  0);
		int g = revbits(((bytes[2]&0xFF) << 24) | ((bytes[3]&0xFF) << 16) | ((bytes[4]&0xFF) <<  8) | ((bytes[5]&0xFF) <<  0), 32);
		strcpy(cmd->instr, "b.cop");
		snprintf(cmd->operands, sizeof(cmd->operands), "0x%x, 0x%x", g, x);
		return 6;

//@instruction("bg.sb", "Y(rA),rB", "0xc 00 BB BBBA AAAA YYYY YYYY YYYY YYYY",  "r{B},{Y},r{A},+,=[1]")
	}else if(((bytes[0]&0xFC)==0xC0)){
		int a = ((bytes[1]&0x1F) >>  0);
		int b = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int y = revbits(((bytes[2]&0xFF) <<  8) | ((bytes[3]&0xFF) <<  0), 16);
//		if(y & (1<<15)){y = y - (1<<16);}
		strcpy(cmd->instr, "b.sb");
		if(y & (1<<15)){
			y = y - (1<<16);
			snprintf(cmd->operands, sizeof(cmd->operands), "-0x%x(r%d), r%d", -y, a, b);
		}else{
			snprintf(cmd->operands, sizeof(cmd->operands), "0x%x(r%d), r%d", y, a, b);
		}
		if(esil){r_strbuf_appendf(esil, "r%d,0x%x,r%d,+,=[1]", b, y, a);}
		return 4;

//@instruction("bg.lbz", "rD,Y(rA)", "0xc 01 DD DDDA AAAA YYYY YYYY YYYY YYYY", "{Y},r{A},+,[1],r{D},=")
	}else if(((bytes[0]&0xFC)==0xC4)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int y = revbits(((bytes[2]&0xFF) <<  8) | ((bytes[3]&0xFF) <<  0), 16);
		strcpy(cmd->instr, "b.lbz");
		if(y & (1<<15)){
			y = y - (1<<16);
			snprintf(cmd->operands, sizeof(cmd->operands), "r%d, -0x%x(r%d)", d, -y, a);
		}else{
			snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x(r%d)", d, y, a);
		}
		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,+,[1],r%d,=", y, a, d);}
		return 4;

//@instruction("bg.sh", "X(rA),rB", "0xc 10 BB BBBA AAAA 0XXX XXXX XXXX XXXX",  "r{B},{X},r{A},+,=[2]")
	}else if(((bytes[0]&0xFC)==0xC8) && ((bytes[2]&0x80)==0x00)){
		int a = ((bytes[1]&0x1F) >>  0);
		int b = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int x = revbits(((bytes[2]&0x7F) <<  8) | ((bytes[3]&0xFF) <<  0), 15);
		strcpy(cmd->instr, "b.sh");
		snprintf(cmd->operands, sizeof(cmd->operands), "0x%x(r%d), r%d", x, a, b);
		if(esil){r_strbuf_appendf(esil, "r%d,0x&x,r%d,+,=[2]", b, x, a);}
		return 4;

//@instruction("bg.lhz", "rD,X(rA)", "0xc 10 DD DDDA AAAA 1XXX XXXX XXXX XXXX", "{X},r{A},+,[2],r{D},=")
	}else if(((bytes[0]&0xFC)==0xC8) && ((bytes[2]&0x80)==0x80)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int x = revbits(((bytes[2]&0x7F) <<  8) | ((bytes[3]&0xFF) <<  0), 15);
		strcpy(cmd->instr, "b.lhz");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x(r%d)",d, 2*x, a);
		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,+,[2],r%d,=", x, a, d);}
		return 4;

//@instruction("bg.sw", "W(rA),rB", "0xc 11 BB BBBA AAAA 00WW WWWW WWWW WWWW", "r{B},{W},r{A},+,=[4]")
	}else if(((bytes[0]&0xFC)==0xCC) && ((bytes[2]&0xC0)==0x00)){
		int a = ((bytes[1]&0x1F) >>  0);
		int b = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int w = revbits(((bytes[2]&0x3F) <<  8) | ((bytes[3]&0xFF) <<  0), 14);
//		if(w & (1<<13)){w = w - (1<<14);}
		strcpy(cmd->instr, "b.sw");
		if(w & (1<<13)){
			w = w - (1<<14);
			snprintf(cmd->operands, sizeof(cmd->operands), "-0x%x(r%d), r%d", -w*4, a, b);
		}else{
			snprintf(cmd->operands, sizeof(cmd->operands), "0x%x(r%d), r%d", w*4, a, b);
		}
		if(esil){r_strbuf_appendf(esil, "r%d,0x%x,r%d,+,=[4]", b, w, a);}
		if(len<4){snprintf(cmd->operands, sizeof(cmd->operands), "len=%d", len);}
		return 4;

//#TODO: zero extend
//@instruction("bg.lwz", "rD,W(rA)", "0xc 11 DD DDDA AAAA 01WW WWWW WWWW WWWW", "{W},r{A},+,[4],r{D},=")
	}else if(((bytes[0]&0xFC)==0xCC) && ((bytes[2]&0xC0)==0x40)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int w = revbits(((bytes[2]&0x3F) <<  8) | ((bytes[3]&0xFF) <<  0), 14);
//		if(w & (1<<13)){w = w - (1<<14);}
		strcpy(cmd->instr, "b.lwz");
		if(w & (1<<13)){
			w = w - (1<<14);
			snprintf(cmd->operands, sizeof(cmd->operands), "r%d, -0x%x(r%d)", d, -w*4, a);
		}else{
			snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x(r%d)", d, w*4, a);
		}
		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,+,[4],r%d,=", w, a, d);}
		return 4;

//@instruction("bg.beqi", "rB,I,U", "0xd 00 00 00II IIIB BBBB UUUU UUUU UUUU", "{I},r{B},==,$z,?{{,4,{U},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0xD0) && ((bytes[1]&0xC0)==0x00)){
		int i = ((bytes[1]&0x3E) >>  1);
		int b = ((bytes[1]&0x01) <<  4) | ((bytes[2]&0xF0) >>  4);
		int u = revbits(((bytes[2]&0x0F) <<  8) | ((bytes[3]&0xFF) <<  0), 12);
		if(u & (1 << 11)){ u = u - (1 << 12); }
		strcpy(cmd->instr, "b.beqi");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x, %x", b, i, (unsigned int)(pc+u));
		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,==,$z,?{,4,0x%x,-,pc,+=,}", i, b, u);}
		if(anal){
			anal->type = R_ANAL_OP_TYPE_CJMP;
			anal->jump = pc + u;
			anal->fail = pc + 4;
		}
		return 4;

//@instruction("bg.bnei", "rB,I,U", "0xd 00 00 01II IIIB BBBB UUUU UUUU UUUU", "{I},r{B},==,$z,!,?{{,4,{U},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0xD0) && ((bytes[1]&0xC0)==0x40)){
		int i = ((bytes[1]&0x3E) >>  1);
		int b = ((bytes[1]&0x01) <<  4) | ((bytes[2]&0xF0) >>  4);
		int u = revbits(((bytes[2]&0x0F) <<  8) | ((bytes[3]&0xFF) <<  0), 12);
		if(u & (1 << 11)){ u = u - (1 << 12); }
		strcpy(cmd->instr, "b.bnei");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x, %x", b, i, (unsigned int)(pc+u));
		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,==,$z,!,?{,4,0x%x,-,pc,+=,}", i, b, u);}
		if(anal){
			anal->type = R_ANAL_OP_TYPE_CJMP;
			anal->jump = pc + u;
			anal->fail = pc + 4;
		}
		return 4;

//@instruction("bg.bgesi", "rB,I,U", "0xd 00 00 10II IIIB BBBB UUUU UUUU UUUU", "{I},r{B},>=,?{{,4,{U},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0xD0) && ((bytes[1]&0xC0)==0x80)){
		int i = ((bytes[1]&0x3E) >>  1);
		int b = ((bytes[1]&0x01) <<  4) | ((bytes[2]&0xF0) >>  4);
		int u = revbits(((bytes[2]&0x0F) <<  8) | ((bytes[3]&0xFF) <<  0), 12);
		if(u & (1 << 11)){ u = u - (1 << 12); }
		strcpy(cmd->instr, "b.bgesi?");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x, %x", b, i, (unsigned int)(pc+u));
		return 4;

//@instruction("bg.blesi", "rB,I,U", "0xd 00 01 00II IIIB BBBB UUUU UUUU UUUU", "{I},r{B},<=,?{{,4,{U},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0xD1) && ((bytes[1]&0xC0)==0x00)){
		int i = ((bytes[1]&0x3E) >>  1);
		int b = ((bytes[1]&0x01) <<  4) | ((bytes[2]&0xF0) >>  4);
		int u = revbits(((bytes[2]&0x0F) <<  8) | ((bytes[3]&0xFF) <<  0), 12);
		if(u & (1 << 11)){ u = u - (1 << 12); }
		strcpy(cmd->instr, "b.blesi?");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x, %x", b, i, (unsigned int)(pc+u));
		return 4;

//#TODO: sign extend
//@instruction("bg.bgtui", "rB,I,U", "0xd 00 01 11II IIIB BBBB UUUU UUUU UUUU", "{I},r{B},>,?{{,4,{U},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0xD1) && ((bytes[1]&0xC0)==0xC0)){
		int i = revbits(((bytes[1]&0x3E) >>  1), 5);
		int b = ((bytes[1]&0x01) <<  4) | ((bytes[2]&0xF0) >>  4);
		int u = revbits(((bytes[2]&0x0F) <<  8) | ((bytes[3]&0xFF) <<  0), 12);
		if(u & (1 << 11)){ u = u - (1 << 12); }
		strcpy(cmd->instr, "b.bgtui");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, 0x%x, %x", b, i, (unsigned int)(pc+u));
		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,>,?{,4,0x%x,-,pc,+=,}", i, b, u);}
		return 4;

//@instruction("bg.beq", "rA,rB,U", "0xd 00 10 10AA AAAB BBBB UUUU UUUU UUUU", "r{B},r{A},==,$z,?{{,4,{U},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0xD2) && ((bytes[1]&0xC0)==0x80)){
		int a = ((bytes[1]&0x3E) >>  1);
		int b = ((bytes[1]&0x01) <<  4) | ((bytes[2]&0xF0) >>  4);
		int u = revbits(((bytes[2]&0x0F) <<  8) | ((bytes[3]&0xFF) <<  0), 12);
		if(u & (1 << 11)){ u = u - (1 << 12); }
		strcpy(cmd->instr, "b.beq");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, %x", a, b, (unsigned int)(pc+u));
		if(esil){r_strbuf_appendf(esil, "r%d,r%d,==,$z,?{,4,0x%x,-,pc,+=,}", b, a, u);}
		return 4;

//@instruction("bg.bne", "rA,rB,U", "0xd 00 10 11AA AAAB BBBB UUUU UUUU UUUU", "r{B},r{A},==,$z,!,?{{,4,{U},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0xD2) && ((bytes[1]&0xC0)==0xC0)){
		int a = ((bytes[1]&0x3E) >>  1);
		int b = ((bytes[1]&0x01) <<  4) | ((bytes[2]&0xF0) >>  4);
		int u = revbits(((bytes[2]&0x0F) <<  8) | ((bytes[3]&0xFF) <<  0), 12);
		if(u & (1 << 11)){ u = u - (1 << 12); }
		strcpy(cmd->instr, "b.bne");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, %x", a, b, (unsigned int)(pc+u));
		if(esil){r_strbuf_appendf(esil, "r%d,r%d,==,$z,!,?{,4,0x%x,-,pc,+=,}", b, a, u);}
		return 4;

//@instruction("bg.bges", "rA,rB,U", "0xd 00 11 00AA AAAB BBBB UUUU UUUU UUUU", "r{B},r{A},>=,?{{,4,{U},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0xD3) && ((bytes[1]&0xC0)==0x00)){
		int a = ((bytes[1]&0x3E) >>  1);
		int b = ((bytes[1]&0x01) <<  4) | ((bytes[2]&0xF0) >>  4);
		int u = revbits(((bytes[2]&0x0F) <<  8) | ((bytes[3]&0xFF) <<  0), 12);
		strcpy(cmd->instr, "b.bges");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, %x", a, b, (unsigned int)(pc+u));
		if(esil){r_strbuf_appendf(esil, "r%d,r%d,>=,?{,4,0x%x,-,pc,+=,}", b, a, u);}
		return 4;


//@instruction("bg.bgts", "rA,rB,U", "0xd 00 11 01AA AAAB BBBB UUUU UUUU UUUU", "r{B},r{A},>,?{{,4,{U},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0xD3) && ((bytes[1]&0xC0)==0x40)){
		int a = ((bytes[1]&0x3E) >>  1);
		int b = ((bytes[1]&0x01) <<  4) | ((bytes[2]&0xF0) >>  4);
		int u = revbits(((bytes[2]&0x0F) <<  8) | ((bytes[3]&0xFF) <<  0), 12);
		if(u & (1 << 11)){ u = u - (1 << 12); }
		strcpy(cmd->instr, "b.bgts");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, %x", a, b, (unsigned int)(pc+u));
		if(esil){r_strbuf_appendf(esil, "r%d,r%d,>,?{,4,0x%x,-,pc,+=,}", b, a, u);}
		return 4;

//#TODO: sign extend
//@instruction("bg.bgeu", "rA,rB,U", "0xd 00 11 10AA AAAB BBBB UUUU UUUU UUUU", "r{B},r{A},>=,?{{,4,{U},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0xD3) && ((bytes[1]&0xC0)==0x80)){
		int a = ((bytes[1]&0x3E) >>  1);
		int b = ((bytes[1]&0x01) <<  4) | ((bytes[2]&0xF0) >>  4);
		int u = revbits(((bytes[2]&0x0F) <<  8) | ((bytes[3]&0xFF) <<  0), 12);
		if(u & (1 << 11)){ u = u - (1 << 12); }
		strcpy(cmd->instr, "b.bgeu?");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, %x", a, b, (unsigned int)(pc+u));
		if(esil){r_strbuf_appendf(esil, "r%d,r%d,>=,?{,4,0x%x,-,pc,+=,}", b, a, u);}
		return 4;

//#TODO: sign extend
//@instruction("bg.bgtu", "rA,rB,U", "0xd 00 11 11AA AAAB BBBB UUUU UUUU UUUU", "r{B},r{A},>,?{{,4,{U},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0xD3) && ((bytes[1]&0xC0)==0xC0)){
		int a = ((bytes[1]&0x3E) >>  1);
		int b = ((bytes[1]&0x01) <<  4) | ((bytes[2]&0xF0) >>  4);
		int u = revbits(((bytes[2]&0x0F) <<  8) | ((bytes[3]&0xFF) <<  0), 12);
		if(u & (1 << 11)){ u = u - (1 << 12); }
		strcpy(cmd->instr, "b.bgtu");
		snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, %x", a, b, (unsigned int)(pc+u));
		if(esil){r_strbuf_appendf(esil, "r%d,r%d,>,?{,4,0x%x,-,pc,+=,}", b, a, u);}
		return 4;

//@instruction("bg.jal", "t",  "0xd 01 00 tttt tttt tttt tttt tttt tttt", "pc,lr,=,4,{t},-,pc,+=")
	}else if(((bytes[0]&0xFF)==0xD4)){
		int t = revbits(((bytes[1]&0xFF) << 16) | ((bytes[2]&0xFF) <<  8) | ((bytes[3]&0xFF) <<  0), 24);
		strcpy(cmd->instr, "b.jal");
		if(t & (1 << 23)){
			t = t - (1 << 24);
//			snprintf(cmd->operands, sizeof(cmd->operands), "-%x [+PC]", -t);
		}else{
//			snprintf(cmd->operands, sizeof(cmd->operands), "%x [+PC]", t);
		}
		snprintf(cmd->operands, sizeof(cmd->operands), "%x", (unsigned int)(pc+t));
		if(esil){r_strbuf_appendf(esil, "pc,lr,=,4,0x%x,-,pc,+=", t);}
		return 4;

//@instruction("bg.bf", "t",  "0xd 01 10 tttt tttt tttt tttt tttt tttt", "fl,1,==,?{{,4,{t},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0xD6)){
		int t = revbits(((bytes[1]&0xFF) << 16) | ((bytes[2]&0xFF) <<  8) | ((bytes[3]&0xFF) <<  0), 24);
		strcpy(cmd->instr, "b.bf");
//		snprintf(cmd->operands, sizeof(cmd->operands), "%x [+PC]", t);
		snprintf(cmd->operands, sizeof(cmd->operands), "%x", (unsigned int)(pc+t));
		if(esil){r_strbuf_appendf(esil, "fl,1,==,?{,4,0x%x,-,pc,+=,}", t);}
		return 4;

//@instruction("bg.bnf", "t",  "0xd 01 11 tttt tttt tttt tttt tttt tttt", "fl,0,==,?{{,4,{t},-,pc,+=,}}")
	}else if(((bytes[0]&0xFF)==0xD7)){
		int t = revbits(((bytes[1]&0xFF) << 16) | ((bytes[2]&0xFF) <<  8) | ((bytes[3]&0xFF) <<  0), 24);
		strcpy(cmd->instr, "b.bnf");
		snprintf(cmd->operands, sizeof(cmd->operands), "%x", (unsigned int)(pc + t));
		if(esil){r_strbuf_appendf(esil, "fl,0,==,?{,4,0x%x,-,pc,+=,}", t);}
		return 4;

//@instruction("bg.addi", "rD,rA,Y", "0xd 10 DD DDDA AAAA YYYY YYYY YYYY YYYY", "{Y},r{A},+,r{D},=")
	}else if(((bytes[0]&0xFC)==0xD8)){
		int a = ((bytes[1]&0x1F) >>  0);
		int d = ((bytes[0]&0x03) <<  3) | ((bytes[1]&0xE0) >>  5);
		int y = revbits(((bytes[2]&0xFF) <<  8) | ((bytes[3]&0xFF) <<  0), 16);
		strcpy(cmd->instr, "b.addi");
		if(y & (1 << 15)){
			y = y - (1 << 16);
			snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, -0x%x", d, a, -y);
		}else{
			snprintf(cmd->operands, sizeof(cmd->operands), "r%d, r%d, 0x%x", d, a, y);
		}
		if(esil){r_strbuf_appendf(esil, "0x%x,r%d,+,r%d,=", y, a, d);}
		if(anal){
			anal->type = R_ANAL_OP_TYPE_ADD;
		}
		return 4;

	}
	return 0;
}

