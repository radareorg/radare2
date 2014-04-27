/*

handling exceptions

  http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0311d/I30195.html

//-----//

Flags

  Conditional instructions:
	EQ = Z
	NE = z
	CS HS = C
	CC LO = c
	MI = N // negative
	PL = n // positive
	VS = V // overflow
	VC = v // no overflow
	
	// unsigned
	HI = zC                (!z && c)
	LS = Z || c            (z || !c)

	// signed
	GE = NV || nv          ((n&&v) || (!n&&!v))
	GT = NzV || nzv        ((n&&!z&&v) || (!n&&!z&&!v))
	LT = Nv || nV          ((n&&!v)|| (!n&&v))
	LE = Z || Nv || nV     z || (n&&!v) || (!n && v)

	// INTEL X86 additions
	// - Parity flag (lsb A)
	// - counter register value != 0 (cx/ecx)

  http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0153n/CHDJEBEC.html

  Fields:
  =======
	31  n - negative (msb bit set)
	30  z - zero (== 0)
	29  c - carry
	28  v - signed overflow
	27  q - underflow
	...
	24  j - Jazzele mode
	...
	19  ge3 - ??
	18  ge2 - ??
	17  ge1 - ??
	16  ge0 - ??
	...
	 9  e - Endianness (big endian if set)
	 8  a - if set disables the impreceise aborts
	 7  i - IRQs disabled if set
	 6  f - FIQ interrupts disabled if set
	 5  t - Thumb mode if set
	...
	 4  m4 - ??
	 3  m3
	 2  m2
	 1  m1
	 0  m0

int armflag_N = (Cpsr>>31)&1;
int armflag_Z = (Cpsr>>30)&1;
int armflag_C = (Cpsr>>29)&1;
int armflag_V = (Cpsr>>28)&1;
int armflag_Q = (Cpsr>>27)&1;
int armflag_J = (Cpsr>>24)&1;
int armflag_GE = (Cpsr>>16)&7;
int armflag_E = (Cpsr>>9)&1;
int armflag_A = (Cpsr>>8)&1;
int armflag_I = (Cpsr>>7)&1;
int armflag_F = (Cpsr>>6)&1;
int armflag_T = (Cpsr>>5)&1;
int armflag_M = (Cpsr>>0)&15;

  state: JT bits: 
	ARM	0 (t)	0 (j)
	Thumb	1 (T)	0 (j)
	Btecode	0 (t)	1 (J)
	ThumbEE	1 (T)	1 (J)

*/

BX LR = {
	int tbit = reg[14] & 1;
	reg[15] = reg[14] & ~1;
	if (tbit) reg[16] |= 1<<5;
}
