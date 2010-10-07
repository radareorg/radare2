/* 
 * This code is a port in C of the C++ THUMB ARM disassembler done by KennyTM
 *   http://networkpx.googlecode.com
 * This code is licensed under the GPL
 * 
 * Author: KennyTM
 * -- pancake<nopcode.org> Copyright 2010
 */

// TODO: remove/integrate code analysis stuff

#include <stdio.h>
#include <string.h>

// TODO: move into r_types.h .. _() is used by gettext() can conflict ?
#define $1111 15
#define $1110 14
#define $1101 13
#define $1100 12
#define $1011 11
#define $1010 10
#define $1001 9
#define $1000 8
#define $0111 7
#define $0110 6
#define $0101 5
#define $0100 4
#define $0011 3
#define $0010 2
#define _(a,b,c,d) ((a<<12)|(b<<8)|(c<<4)|(d))

#define regname(x) (x>=0&&x<16)?regNames[x]:"r?"
static const char* regNames[] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
	"r8", "r9", "sl", "fp", "ip", "sp", "lr", "pc"
};
static const char* ops_cond[] = {
	"eq","ne","cs","cc","mi","pl","vs","vc","hi",
	"ls","ge","lt","gt","le","al","??"
};
static const char* ops_dp3[] = {"mov", "cmp", "add", "sub"};
static const char* ops_dp4[] = {"lsl", "lsr", "asr"};
static const char* ops_dp5[] = {
	"and", "eor", "lsl", "lsr", "asr", "adc", "sbc", "ror",
	"tst", "neg", "cmp", "cmn", "orr", "mul", "bic", "mvn"
};
static const char* ops_dp8[] = {"add", "cmp", "mov"};
static const char* ops_ls1[] = {"str", "ldr", "strb", "ldrb", "strh", "ldrh"};
static const char* ops_ls2[] = {
	"str", "strh", "strb", "ldrsb", "ldr", "ldrh", "ldrb", "ldrsh"
};
static const char* ops_rev[] = {"rev", "rev16", "rev??", "revsh"};
static const char* ops_xt[] = {"sxth", "sxtb", "uxth", "uxtb"};

static inline unsigned int ror (unsigned int value, int shift) {
	shift &= 31;
	return (value >> shift) | (value << (32 - shift));
}

static char tmpbuf[4*16+1];
static const char* compute_reg_list (unsigned list) {
        int i, idx = 1, mark = 0;
	const char *name;
        tmpbuf[0] = '{';
        for (i = 0; i<16; i++) {
                if (list & (1<<i)) {
                        if (mark) {
                                tmpbuf[idx++] = ',';
                                tmpbuf[idx++] = ' ';
                        } else mark = 1;
                        name = regname(i);
                        tmpbuf[idx++] = name[0];
                        tmpbuf[idx++] = name[1];
                }
        }
        tmpbuf[idx++] = '}';
        tmpbuf[idx++] = '\0';
        return tmpbuf;
}

int armthumb_length(unsigned int ins) {
        if ((ins & _($1110,$1000,0,0)) == _($1110,0,0,0))
                if (ins & _(1,$1000,0,0))
			return 4;
	return 2;
}

int armthumb_disassemble(char *buf, unsigned long pc, unsigned int ins) {
	unsigned int delta, imm, jump, op_code, instr2 = ins >> 16;
        const char* op;
	pc += 4;
        ins &= 0xFFFF;

        // Conditional branch
        if ( (ins & _($1111,0,0,0)) == _($1101,0,0,0) ) {
                op_code = (ins & _(0,$1111,0,0)) >> 8;
                op = ops_cond[op_code];
                imm = (ins & _(0,0,$1111,$1111));
                delta = imm << 1;
                if (imm & (1<<7))
                        delta |= ~_(0,1,$1111,$1111);
                jump = pc + delta;
                sprintf(buf, "b%s 0x%x", op, jump);
                // Unconditional branch
        } else if ( (ins & _($1110,$1000,0,0)) == _($1110,0,0,0) ) {
                op_code = (ins & _(1,$1000,0,0));
                imm = (ins & _(0,$0111,$1111,$1111));
                delta = imm << 1;
                if (imm & (1<<10))
                        delta |= ~_(0,$1111,$1111,$1111);
                if (!op_code) {
                        jump = pc + delta;
                        sprintf (buf, "b 0x%x", jump);
                } else {
                        // need to read one more ins.
                        ins |= instr2 << 16;
                        if ( (instr2 & _($1110,$1000,0,0)) == _($1110,$1000,0,0) ) {
                                op_code = instr2 & (1<<12);
                                jump = (delta << 11 | (instr2&_(0,$0111,$1111,$1111))<<1) + pc;
                                if (!op_code) jump &= ~3;
                                sprintf(buf, "%s 0x%x", op_code?"bl":"blx", jump);
                        } else return 0;
                        return 4;
                }
                // Branch with Exchange
        } else if ( (ins & _($1111,$1111,0,0)) == _($0100,$0111,0,0) ) {
                unsigned int Rm = (ins & _(0,0,$0111,$1000)) >> 3;
                op_code = (ins & (1<<7));
                sprintf(buf, "blx %s", regname(Rm));
                // Data-processing, format 1
        } else if ( (ins & _($1111,$1100,0,0)) == _(1,$1000,0,0) ) {
                unsigned int Rm = (ins & _(0,1,$1100,0)) >> 6;
                unsigned int Rn = (ins & _(0,0,$0011,$1000)) >> 3;
                unsigned int Rd = (ins & _(0,0,0,$0111));
                op = (ins&(1<<9))? "sub" : "add";
                sprintf(buf, "%s %s, %s, %s", op, regname(Rd), regname(Rn), regname(Rm));
                // Data-processing, format 2
        } else if ( (ins & _($1111,$1100,0,0)) == _(1,$1100,0,0) ) {
                unsigned imm = (ins & _(0,1,$1100,0)) >> 6;
                unsigned Rn  = (ins & _(0,0,$0011,$1000)) >> 3;
                unsigned Rd  = (ins & _(0,0,0,$0111));
                op = (ins & (1<<9)) ? "sub" : "add";
                sprintf(buf, "%s %s, %s, #%d", op, regname(Rd), regname(Rn), imm);
                // Data-processing, format 3
        } else if ( (ins & _($1110,0,0,0)) == _($0010,0,0,0) ) {
                unsigned RdRn = (ins & _(0,$0111,0,0)) >> 8;
                unsigned imm = (ins & _(0,0,$1111,$1111));
                op = ops_dp3[(ins & _(1,$1000,0,0)) >> 11];
                sprintf(buf, "%s %s, #%d", op, regname(RdRn), imm);
                // Data-processing, format 4
        } else if ( (ins & _($1110,0,0,0)) == _(0,0,0,0) ) {
                unsigned imm = (ins & _(0,$0111,$1100,0)) >> 6;
                unsigned Rm  = (ins & _(0,0,$0011,$1000)) >> 3;
                unsigned Rd  = (ins & _(0,0,0,$0111));
                op_code = (ins & _(1,$1000,0,0)) >> 11;
                op = ops_dp4[op_code];
                sprintf(buf, "%s %s, %s, #%d", op, regname(Rd), regname(Rm), imm);
                // Data-processing, format 5
        } else if ( (ins & _($1111,$1100,0,0)) == _($0100,0,0,0) ) {
                unsigned Rm = (ins & _(0,0,$0011,$1000)) >> 3;
                unsigned Rd = (ins & _(0,0,0,$0111));
                op_code = (ins & _(0,$0011,$1100,0)) >> 6;
                op = ops_dp5[op_code];
                sprintf(buf, "%s %s, %s", op, regname(Rd), regname(Rm));
		#if 0
                switch (op_code) {
		case 15: r[Rd] = ~r[Rm]; break;
			// FIXME: check carry flag.
		case 5: r[Rd] += r[Rm]; break;
		case 6: r[Rd] -= r[Rm]; break;
		case 9: r[Rd] = -r[Rm]; break;
		case 13: r[Rd] *= r[Rm]; break;
		case 2: r[Rd] <<= r[Rm]; break;
		case 3: r[Rd] = ((unsigned)r[Rd]) >> r[Rm]; break;
		case 4: r[Rd] >>= r[Rm]; break;
		case 7: r[Rd] = ror((unsigned)r[Rd], r[Rm]); break;
		case 0: r[Rd] &= r[Rm]; break;
		case 1: r[Rd] ^= r[Rm]; break;
		case 12: r[Rd] |= r[Rm]; break;
		case 14: r[Rd] &= ~r[Rm]; break;
                }
		#endif
                // Data-processing, format 6
        } else if ( (ins & _($1111,0,0,0)) == _($1010,0,0,0) ) {
                unsigned Rd =  (ins & _(0,$0111,0,0)) >> 8;
                unsigned imm = (ins & _(0,0,$1111,$1111)) * 4;
                op_code = (ins & (1<<11));
                sprintf(buf, "add %s, %s, #%d", regname(Rd), op_code?"sp":"pc", imm);
                // Data-processing, format 7
        } else if ( (ins & _($1111,$1111,0,0)) == _($1011,0,0,0) ) {
                op_code = (ins & (1<<7));
                imm = (ins & _(0,0,$0111,$1111)) * 4;
                sprintf(buf, "%s sp, sp, #%d", op_code ? "sub" : "add", imm);
                //if (op_code) sp -= imm; else sp += imm;
                // Data-processing, format 8
        } else if ( (ins & _($1111,$1100,0,0)) == _($0100,$0100,0,0) ) {
                unsigned Rm = (ins & _(0,0,$0111,$1000)) >> 3;
                unsigned RdRn = (ins & _(0,0,0,$0111)) | (ins & (1<<7))>>4;
                op_code = (ins & _(0,$0011,0,0)) >> 8;
                op = ops_dp8[op_code];
                sprintf (buf, "%s %s, %s", op, regname(RdRn), regname(Rm));
                // Load & Store, format 1
        } else if ( (op_code = ((ins & _($1111,$1000,0,0)) >> 11)) >= 12 && op_code <= 17 ) {
                unsigned int mask, imm = (ins & _(0,$0111,$1100,0)) >> 6;
                unsigned Rn = (ins & _(0,0,$0011,$1000)) >> 3;
                unsigned Rd = (ins & _(0,0,0,$0111));
                op_code -= 12;
                op = ops_ls1[op_code];

                switch (op_code & ~1) {
		case 0: imm *= 4; mask = 0xFFFFFFFF; break;
		case 4: imm *= 2; mask = 0xFFFF; break;
		default: mask = 0xFF; break;
                }
                sprintf(buf, "%s %s, [%s, #%d]", op, regname(Rd), regname(Rn), imm);
                //if (op_code & 1) this->load_reference(r[Rn]+imm, Rd, mask);
                //else this->store_reference(r[Rn]+imm, r[Rd], mask);
                // Load & Store, format 2
        } else if ( (ins & _($1111,0,0,0)) == _($0101,0,0,0) ) {
                unsigned Rm = (ins & _(0,1,$1100,0)) >> 6;
                unsigned Rn = (ins & _(0,0,$0011,$1000)) >> 3;
                unsigned Rd = (ins & _(0,0,0,$0111));
                op_code = (ins & _(0,$1110,0,0)) >> 9;
                op = ops_ls2[op_code];
                sprintf(buf, "%s %s, [%s, %s]", op, regname(Rd), regname(Rn), regname(Rm));
		#if 0
                int mask, isSigned = (op_code == 3 || op_code == 7);
                switch (op_code) {
		case 4: case 0: mask = 0xFFFFFFFF; break;
		case 5: case 7: case 1: mask = 0xFFFF; break;
		case 6: case 3: case 2: mask = 0xFF; break;
                }
                if (op_code >= 3) this->load_reference(r[Rn]+r[Rm], Rd, mask, isSigned);
                else this->store_reference(r[Rn]+r[Rm], r[Rd], mask);
		#endif
                // Load & Store, format 3
        } else if ( (ins & _($1111,$1000,0,0)) == _($0100,$1000,0,0) ) {
                unsigned Rd  = (ins & _(0,$0111,0,0)) >> 8;
                unsigned imm = (ins & _(0,0,$1111,$1111)) * 4;
                sprintf(buf, "ldr %s, [pc, #%d]", regname(Rd), imm);
                //this->load_reference((pc&~3) + imm, Rd);
                // Load & Store, format 4
        } else if ( (ins & _($1111,0,0,0)) == _($1001,0,0,0) ) {
                unsigned int Rd = (ins & _(0,$0111,0,0)) >> 8;
                unsigned int imm = (ins & _(0,0,$1111,$1111)) * 4;
                op_code = (ins & (1<<11));
                sprintf (buf, "%s %s, [sp, #%d]", op_code?"ldr":"str", regname(Rd), imm);
                // Load/Store multiple, format 1
        } else if ( (ins & _($1111,0,0,0)) == _($1100,0,0,0) ) {
                unsigned Rd = (ins & _(0,$0111,0,0)) >> 8;
                unsigned reglist = (ins & _(0,0,$1111,$1111));
                op_code = (ins & (1<<11));
                sprintf(buf, "%s %s, %s", op_code?"ldmia":"stmia", regname(Rd),
			compute_reg_list(reglist));
                // Load/Store multiple, format 2
        } else if ( (ins & _($1111,$0110,0,0)) == _($1011,$0100,0,0) ) {
                unsigned reglist = (ins & _(0,0,$1111,$1111));
                op_code = (ins & (1<<11));
                if (ins & (1<<8)) { // pop
                        if (op_code) reglist |= (1<<15);
                        else reglist |= (1<<14);
                }
                sprintf(buf, "%s %s", op_code?"pop":"push", compute_reg_list(reglist));
                //if (op_code) ldmia(13, reglist); else stmdb(13, reglist);
                // BKPT
        } else if ( (ins & _($1111,$1111,0,0)) == _($1011,$1110,0,0) ) {
                sprintf(buf, "bkpt %d", ins & 0xFF);
                // CPS
        } else if ( (ins & _($1111,$1111,$1110,$1000)) == _($1011,$0110,$0110,0) ) {
                sprintf(buf, "cpsi%c %s%s%s", (ins&(1<<4))?'d':'e',
			 (ins&(1<<2))?"a":"", (ins&(1<<1))?"i":"", (ins&(1<<0))?"f":"");
                // REV
        } else if ( (ins & _($1111,$1111,0,0)) == _($1011,$1010,0,0) ) {
                unsigned Rn = (ins & _(0,0,$0011,$1000)) >> 3;
                unsigned Rd = (ins & _(0,0,0,$0111));
                op_code = (ins & _(0,0,$1100,0)) >> 6;
                op = ops_rev[op_code];
                sprintf(buf, "%s %s, %s", op, regname(Rd), regname(Rn));
                // SETEND
                // FIXME: We're ignoring it.
        } else if ( (ins & _($1111,$1111,$1111,$0111)) == _($1011,$0110,$0101,0) ) {
                sprintf(buf, "setend %ce", ins&(1<<3)?'b':'l');
                // SWI
        } else if ( (ins & _($1111,$1111,0,0)) == _($1101,$1111,0,0)) {
                sprintf(buf, "swi %d", ins & 0xFF);
                // Signed/Unsigned extension.
        } else if ( (ins & _($1111,$1111,0,0)) == _($1011,$0010,0,0)) {
                unsigned int Rn = (ins & _(0,0,$0011,$1000)) >> 3;
                unsigned int Rd = (ins & _(0,0,0,$0111));
                op_code = (ins & _(0,0,$1100,0)) >> 6;
                op = ops_xt[op_code];
                sprintf(buf, "%s %s, %s", op, regname(Rd), regname(Rn));
		#if 0
                unsigned int mask = (op_code & 1) ? 0xFF : 0xFFFF;
                r[Rd] = r[Rn] & mask;
                if ((op_code & 2) && (r[Rd] & ((mask+1)>>1)))
                        r[Rd] |= ~mask;
		#endif
        } else return 0;
        return 2;
}

#if MAIN
int main (int argc, char* argv[]) {
	char op[80];
	int i, len;

	for (i=0; i<0xffff; i+=81) {
		len = thumb_disassemble (op, 0x4000, i);
		if(len>0) printf("%d  %s\n", len, op);
		else printf("?\n");
	}
        return 0;
}
#endif
