// Predicates - declare the predicate state
typedef enum {
	HEX_NOPRED, // no conditional execution
	HEX_PRED_TRUE, // if (Pd) ...
	HEX_PRED_FALSE, // if (!Pd) ...
	HEX_PRED_TRUE_NEW, // if (Pd.new) ...
	HEX_PRED_FALSE_NEW, // if (!Pd.new) ...
} HexPred;

// Pre/post-fixes, different types
typedef enum {
	HEX_PF_RND = 1, // :rnd
	HEX_PF_CRND = 1<<1, // :crnd
	HEX_PF_RAW = 1<<2, // :raw
	HEX_PF_CHOP = 1<<3, // :chop
	HEX_PF_SAT = 1<<4, // :sat
	HEX_PF_HI = 1<<5, // :hi
	HEX_PF_LO = 1<<6, // :lo
	HEX_PF_LSH1 = 1<<7, // :<<1
	HEX_PF_LSH16 = 1<<8, // :<<16
	HEX_PF_RSH1 = 1<<9, // :>>1
	HEX_PF_NEG = 1<<10, // :neg
	HEX_PF_POS = 1<<11, // :pos
	HEX_PF_SCALE = 1<<12, // :scale, for FMA instructions
	HEX_PF_DEPRECATED = 1<<15, // :deprecated
} HexPf;

typedef enum {
	HEX_OP_TYPE_IMM,
	HEX_OP_TYPE_REG,
	HEX_OP_TYPE_PREDICATE,
	HEX_OP_TYPE_CONTROL,
	HEX_OP_TYPE_SYSTEM,
	HEX_OP_TYPE_OPT, // Do not really use in the C code
} HexOpType;

// Attributes - .H/.L, const extender
typedef enum {
	HEX_OP_CONST_EXT = 1 << 0, // Constant extender marker for Immediate
	HEX_OP_REG_HI = 1 << 1, // Rn.H marker
	HEX_OP_REG_LO = 1 << 2, // Rn.L marker
	HEX_OP_REG_PAIR = 1 << 3, // Is this a register pair?
} HexOpAttr;

typedef struct {
	ut8 type;
	union {
		ut8 reg; // + additional Hi or Lo selector // + additional shift // + additional :brev //
		ut32 imm;
		ut8 pred; // predicates - P0-P3 registers
		ut8 cr; // control register
		ut8 sys; // system control register
	} op;
	ut8 attr;
} HexOp;

typedef struct {
	int instruction;
	ut32 mask;
	HexPred predicate; // predicate set if set
	ut16 pf; // additional prefixes (bitmap)
	bool duplex; // is part of duplex container?
	bool compound; // is part of compound instruction?
	bool last; // is last in instruction packet?
	int shift; // Optional shift left is it true?
	ut8 op_count;
	HexOp ops[6];
	char mnem[128]; // Instruction mnemonic
} HexInsn;

// Instruction container (currently only 2 instructions)
// Can handle duplexes
typedef struct {
	bool duplex;
	HexInsn ins[2]; // Or make it pointer + size?
} HexInsnCont;

// Instruction packet (Maximum - 4 instructions)
// Can handle up to 4 instructions or 1 duplex + 2 instructions
// Can have a loop marks
typedef struct {
	bool loop0; // :endloop0 marker
	bool loop1; // :endloop1 marker
	int cont_cnt;
	HexInsnCont ins[4]; // Or make it pointer + size?
} HexInsnPkt;

typedef enum {
	HEX_INSN_CLASS_CEXT = 0, // Constant extender
	HEX_INSN_CLASS_J1 = 1, // Jump
	HEX_INSN_CLASS_J2 = 2, // Jump
	HEX_INSN_CLASS_LD_ST = 3, // Load/Store
	HEX_INSN_CLASS_LD_ST_COND_GP = 4, // Load/Store conditional or GP relative
	HEX_INSN_CLASS_J3 = 5, // Jump
	HEX_INSN_CLASS_CR = 6, // Control register instructions
	HEX_INSN_CLASS_ALU32 = 7, // ALU32
	HEX_INSN_CLASS_XTYPE = 8, // XTYPE
	HEX_INSN_CLASS_LD = 9, // Just load instructions
	HEX_INSN_CLASS_ST = 10, // Just store instructions
	HEX_INSN_CLASS_ALU32_1 = 11, // ALU32
	HEX_INSN_CLASS_XTYPE_1 = 12, // XTYPE again
	HEX_INSN_CLASS_XTYPE_2 = 13, // XTYPE one more time
	HEX_INSN_CLASS_XTYPE_3 = 14, // And again, XTYPE
	HEX_INSN_CLASS_ALU32_2 = 12, // ALU32 again
} HEX_INSN_CLASS;

typedef enum {
	HEX_REG_R0 = 0,
	HEX_REG_R1 = 1,
	HEX_REG_R2 = 2,
	HEX_REG_R3 = 3,
	HEX_REG_R4 = 4,
	HEX_REG_R5 = 5,
	HEX_REG_R6 = 6,
	HEX_REG_R7 = 7,
	HEX_REG_R8 = 8,
	HEX_REG_R9 = 9,
	HEX_REG_R10 = 10,
	HEX_REG_R11 = 11,
	HEX_REG_R12 = 12,
	HEX_REG_R13 = 13,
	HEX_REG_R14 = 14,
	HEX_REG_R15 = 15,
	HEX_REG_R16 = 16,
	HEX_REG_R17 = 17,
	HEX_REG_R18 = 18,
	HEX_REG_R19 = 19,
	HEX_REG_R20 = 20,
	HEX_REG_R21 = 21,
	HEX_REG_R22 = 22,
	HEX_REG_R23 = 23,
	HEX_REG_R24 = 24,
	HEX_REG_R25 = 25,
	HEX_REG_R26 = 26,
	HEX_REG_R27 = 27,
	HEX_REG_R28 = 28,
	HEX_REG_R29 = 29,
	HEX_REG_R30 = 30,
	HEX_REG_R31 = 31,
} HEX_REG;

// TODO: Also add regpair values

// Control registers
typedef enum {
	// Loop registers
	HEX_REG_SA0 = 0, // C0
	HEX_REG_LC0 = 1, // C1
	HEX_REG_SA1 = 2, // C2
	HEX_REG_LC1 = 3, // C3
	HEX_REG_P = 4, // C4 - 4 of 8bit registers
	// C5 is reserved
	// Modifier registers
	HEX_REG_M0 = 6, // C6
	HEX_REG_M1 = 7, // C7
	HEX_REG_USR = 8, // C8 // User Status Register
	HEX_REG_PC = 9, // C9 // Program counter
	HEX_REG_UGP = 10, // C10 // User General Pointer
	HEX_REG_GP = 11, // C11 // Global Pointer
	// Circular Start registers
	HEX_REG_CS0 = 12, // C12
	HEX_REG_CS1 = 13, // C13
	// Cycle Count registers
	HEX_REG_UPCYCLELO = 14, // C14
	HEX_REG_UPCYCLEHI = 15, // C15
	HEX_REG_FRAMELIMIT = 16, // C16 // Stack Bounds register
	HEX_REG_FRAMEKEY = 17, // C17 // Stack Smash register
	// Packet Count registers
	HEX_REG_PKTCOUNTLO = 18, // C18
	HEX_REG_PKTCOUNTHI = 19, // C19
	// C20 - C29 are reserved
	// Qtimer registers
	HEX_REG_UTIMERLO = 30, // C30
	HEX_REG_UTIMERHI = 31, // C31
} HEX_CR_REG;

// Supervisor control registers
typedef enum {
	HEX_REG_SGP0 = 0, // S0
	HEX_REG_SGP1 = 1, // S1
	HEX_REG_STID = 2, // S2
	HEX_REG_ELR = 3, // S3
	HEX_REG_BADVA0 = 4, // S4
	HEX_REG_BADVA1 = 5, // S5
	HEX_REG_SSR = 6, // S6
	HEX_REG_CCR = 7, // S7
	HEX_REG_HTID = 8, // S8
	HEX_REG_BADVA = 9, // S9
	HEX_REG_IMASK = 10, // S10
	// S11 - S15 are reserved
	HEX_REG_EVB = 16, // S16
	HEX_REG_MODECTL = 17, // S17
	HEX_REG_SYSCFG = 18, // S18
	// S19 is reserved
	HEX_REG_IPEND = 20, // S20
	HEX_REG_VID = 21, // S21
	HEX_REG_IAD = 22, // S22
	// S23 is reserved
	HEX_REG_IEL = 24, // S24
	// S25 is reserved
	HEX_REG_IAHL = 26, // S26
	HEX_REG_CFGBASE = 27, // S27
	HEX_REG_DIAG = 28, // S28
	HEX_REG_REV = 29, // S29
	HEX_REG_PCYCLELO = 30,  // S30
	HEX_REG_PCYCLEHI = 31, // S31
	HEX_REG_ISDBST = 32, // S32
	HEX_REG_ISDBCFG0 = 33, // S33
	HEX_REG_ISDBCFG1 = 34, // S34
	// S35 is reserved
	HEX_REG_BRKPTPC0 = 36, // S36
	HEX_REG_BRKPTCFG0 = 37, // S37
	HEX_REG_BRKPTPC1 = 38, // S38
	HEX_REG_BRKPTCFG1 = 39, // S39
	HEX_REG_ISDBMBXIN = 40, // S40
	HEX_REG_ISDBMBXOUT = 41, // S41
	HEX_REG_ISDBEN = 42, // S42
	HEX_REG_ISDBGPR = 43, // S43
	// S44 - S47 are reserved
	HEX_REG_PMUCNT0 = 48, // S48
	HEX_REG_PMUCNT1 = 49, // S49
	HEX_REG_PMUCNT2 = 50, // S50
	HEX_REG_PMUCNT3 = 51, // S51
	HEX_REG_PMUEVTCFG = 52, // S52
	HEX_REG_PMUCFG = 53, // S53
	// S54 - S63 are reserved
} HEX_SYSCR_REG;

// Here are the register field values for subinstructions

typedef enum {
	HEX_SUB_REG_R0 = 0, // 0b0000
	HEX_SUB_REG_R1 = 1, // 0b0001
	HEX_SUB_REG_R2 = 2, // 0b0010
	HEX_SUB_REG_R3 = 3, // 0b0011
	HEX_SUB_REG_R4 = 4, // 0b0100
	HEX_SUB_REG_R5 = 5, // 0b0101
	HEX_SUB_REG_R6 = 6, // 0b0110
	HEX_SUB_REG_R7 = 7, // 0b0111
	HEX_SUB_REG_R16 = 8, // 0b1000
	HEX_SUB_REG_R17 = 9, // 0b1001
	HEX_SUB_REG_R18 = 10, // 0b1010
	HEX_SUB_REG_R19 = 11, // 0b1011
	HEX_SUB_REG_R20 = 12, // 0b1100
	HEX_SUB_REG_R21 = 13, // 0b1101
	HEX_SUB_REG_R22 = 14, // 0b1110
	HEX_SUB_REG_R23 = 15, // 0b1111
} HEX_SUB_REG;


typedef enum {
	HEX_SUB_REGPAIR_R1_R0 = 0, // 0b000
	HEX_SUB_REGPAIR_R3_R2 = 1, // 0b001
	HEX_SUB_REGPAIR_R5_R4 = 2, // 0b010
	HEX_SUB_REGPAIR_R7_R6 = 3, // 0b011
	HEX_SUB_REGPAIR_R17_R16 = 4, // 0b100
	HEX_SUB_REGPAIR_R19_R18 = 5, // 0b101
	HEX_SUB_REGPAIR_R21_R20 = 6, // 0b110
	HEX_SUB_REGPAIR_R23_R22 = 7, // 0b111
} HEX_SUB_REGPAIR;


#define BIT_MASK(len) (BIT(len)-1)
#define BF_MASK(start, len) (BIT_MASK(len)<<(start))
#define BF_PREP(x, start, len) (((x)&BIT_MASK(len))<<(start))
#define BF_GET(y, start, len) (((y)>>(start)) & BIT_MASK(len))
#define BF_GETB(y, start, end) (BF_GET((y), (start), (end) - (start) + 1)

char* hex_get_cntl_reg(int opreg);
char* hex_get_sys_reg(int opreg);
char* hex_get_sub_reg(int opreg);
char* hex_get_sub_regpair(int opreg);
bool hex_if_duplex(ut32 insn_word);
void hex_op_extend(HexOp *op);
void hex_op_extend_off(HexOp *op, int offset);
int hexagon_disasm_instruction(ut32 hi_u32, HexInsn *hi, ut32 addr);

