// code from: z0mbie @ 2002
// http://vx.netlux.org/lib/vzo16.html

#define DWORD unsigned long
#define BYTE  unsigned char

// disasm_flag values:
#define C_66           0x00000001       // 66-prefix
#define C_67           0x00000002       // 67-prefix
#define C_LOCK         0x00000004       // lock
#define C_REP          0x00000008       // repz/repnz
#define C_SEG          0x00000010       // seg-prefix
#define C_OPCODE2      0x00000020       // 2nd opcode present (1st==0F)
#define C_MODRM        0x00000040       // modrm present
#define C_SIB          0x00000080       // sib present
#define C_ANYPREFIX    (C_66|C_67|C_LOCK|C_REP|C_SEG)

int dislen(BYTE* opcode0, int limit);
