// code from: z0mbie @ 2002
// http://vx.netlux.org/lib/vzo16.html

#include "dislen.h"

DWORD disasm_len;                       // 0 if error
DWORD disasm_flag;                      // C_xxx
DWORD disasm_memsize;                   // value = disasm_mem
DWORD disasm_datasize;                  // value = disasm_data
DWORD disasm_defdata;                   // == C_66 ? 2 : 4
DWORD disasm_defmem;                    // == C_67 ? 2 : 4

BYTE  disasm_seg;                       // CS DS ES SS FS GS
BYTE  disasm_rep;                       // REPZ/REPNZ
BYTE  disasm_opcode;                    // opcode
BYTE  disasm_opcode2;                   // used when opcode==0F
BYTE  disasm_modrm;                     // modxxxrm
BYTE  disasm_sib;                       // scale-index-base
BYTE  disasm_mem[8];                    // mem addr value
BYTE  disasm_data[8];                   // data value

// returns: 1 if success
//          0 if error

int dislen(BYTE* opcode0, int limit)
{
	BYTE* opcode = opcode0;
	DWORD i;

	disasm_len = 0;
	disasm_flag = 0;
	disasm_datasize = 0;
	disasm_memsize = 0;
	disasm_defdata = 4;
	disasm_defmem = 4;

retry:
	if (!limit--)
		return 0;

	disasm_opcode = *opcode++;

	switch (disasm_opcode)
	{
		case 0x00: case 0x01: case 0x02: case 0x03:
		case 0x08: case 0x09: case 0x0A: case 0x0B:
		case 0x10: case 0x11: case 0x12: case 0x13:
		case 0x18: case 0x19: case 0x1A: case 0x1B:
		case 0x20: case 0x21: case 0x22: case 0x23:
		case 0x28: case 0x29: case 0x2A: case 0x2B:
		case 0x30: case 0x31: case 0x32: case 0x33:
		case 0x38: case 0x39: case 0x3A: case 0x3B:
		case 0x62: case 0x63:
		case 0x84: case 0x85: case 0x86: case 0x87:
		case 0x88: case 0x89: case 0x8A: case 0x8B:
		case 0x8C: case 0x8D: case 0x8E: case 0x8F:
		case 0xC4: case 0xC5:
		case 0xD0: case 0xD1: case 0xD2: case 0xD3:
		case 0xD8: case 0xD9: case 0xDA: case 0xDB:
		case 0xDC: case 0xDD: case 0xDE: case 0xDF:
		case 0xFE: case 0xFF:
			disasm_flag |= C_MODRM;
			break;
		case 0xCD: disasm_datasize += *opcode==0x20 ? 1+4 : 1;
			   break;
		case 0xF6:
		case 0xF7: disasm_flag |= C_MODRM;
			   if (*opcode & 0x38) break;
			   // continue if <test ..., xx>
		case 0x04: case 0x05: case 0x0C: case 0x0D:
		case 0x14: case 0x15: case 0x1C: case 0x1D:
		case 0x24: case 0x25: case 0x2C: case 0x2D:
		case 0x34: case 0x35: case 0x3C: case 0x3D:
			   if (disasm_opcode & 1)
				   disasm_datasize += disasm_defdata;
			   else
				   disasm_datasize++;
			   break;
		case 0x6A:
		case 0xA8:
		case 0xB0: case 0xB1: case 0xB2: case 0xB3:
		case 0xB4: case 0xB5: case 0xB6: case 0xB7:
		case 0xD4: case 0xD5:
		case 0xE4: case 0xE5: case 0xE6: case 0xE7:
		case 0x70: case 0x71: case 0x72: case 0x73:
		case 0x74: case 0x75: case 0x76: case 0x77:
		case 0x78: case 0x79: case 0x7A: case 0x7B:
		case 0x7C: case 0x7D: case 0x7E: case 0x7F:
		case 0xEB:
		case 0xE0: case 0xE1: case 0xE2: case 0xE3:
			   disasm_datasize++;
			   break;
		case 0x26: case 0x2E: case 0x36: case 0x3E:
		case 0x64: case 0x65:
			   if (disasm_flag & C_SEG) return 0;
			   disasm_flag |= C_SEG;
			   disasm_seg = disasm_opcode;
			   goto retry;
		case 0xF0:
			   if (disasm_flag & C_LOCK) return 0;
			   disasm_flag |= C_LOCK;
			   goto retry;
		case 0xF2: case 0xF3:
			   if (disasm_flag & C_REP) return 0;
			   disasm_flag |= C_REP;
			   disasm_rep = disasm_opcode;
			   goto retry;
		case 0x66:
			   if (disasm_flag & C_66) return 0;
			   disasm_flag |= C_66;
			   disasm_defdata = 2;
			   goto retry;
		case 0x67:
			   if (disasm_flag & C_67) return 0;
			   disasm_flag |= C_67;
			   disasm_defmem = 2;
			   goto retry;
		case 0x6B:
		case 0x80:
		case 0x82:
		case 0x83:
		case 0xC0:
		case 0xC1:
		case 0xC6: disasm_datasize++;
			   disasm_flag |= C_MODRM;
			   break;
		case 0x69:
		case 0x81:
		case 0xC7:
			   disasm_datasize += disasm_defdata;
			   disasm_flag |= C_MODRM;
			   break;
		case 0x9A:
		case 0xEA: disasm_datasize += 2 + disasm_defdata;
			   break;
		case 0xA0:
		case 0xA1:
		case 0xA2:
		case 0xA3: disasm_memsize += disasm_defmem;
			   break;
		case 0x68:
		case 0xA9:
		case 0xB8: case 0xB9: case 0xBA: case 0xBB:
		case 0xBC: case 0xBD: case 0xBE: case 0xBF:
		case 0xE8:
		case 0xE9:
			   disasm_datasize += disasm_defdata;
			   break;
		case 0xC2:
		case 0xCA: disasm_datasize += 2;
			   break;
		case 0xC8:
			   disasm_datasize += 3;
			   break;
		case 0xF1:
			   return 0;
		case 0x0F:
			   disasm_flag |= C_OPCODE2;
			   disasm_opcode2 = *opcode++;
			   switch (disasm_opcode2)
			   {
				   case 0x00: case 0x01: case 0x02: case 0x03:
				   case 0x90: case 0x91: case 0x92: case 0x93:
				   case 0x94: case 0x95: case 0x96: case 0x97:
				   case 0x98: case 0x99: case 0x9A: case 0x9B:
				   case 0x9C: case 0x9D: case 0x9E: case 0x9F:
				   case 0xA3:
				   case 0xA5:
				   case 0xAB:
				   case 0xAD:
				   case 0xAF:
				   case 0xB0: case 0xB1: case 0xB2: case 0xB3:
				   case 0xB4: case 0xB5: case 0xB6: case 0xB7:
				   case 0xBB:
				   case 0xBC: case 0xBD: case 0xBE: case 0xBF:
				   case 0xC0:
				   case 0xC1:
					   disasm_flag |= C_MODRM;
					   break;
				   case 0x06:
				   case 0x08: case 0x09: case 0x0A: case 0x0B:
				   case 0xA0: case 0xA1: case 0xA2: case 0xA8:
				   case 0xA9:
				   case 0xAA:
				   case 0xC8: case 0xC9: case 0xCA: case 0xCB:
				   case 0xCC: case 0xCD: case 0xCE: case 0xCF:
				case 0x31: // rdtsc
					   break;
				   case 0x80: case 0x81: case 0x82: case 0x83:
				   case 0x84: case 0x85: case 0x86: case 0x87:
				   case 0x88: case 0x89: case 0x8A: case 0x8B:
				   case 0x8C: case 0x8D: case 0x8E: case 0x8F:
					   disasm_datasize += disasm_defdata;
					   break;
				   case 0xA4:
				   case 0xAC:
				   case 0xBA:
					   disasm_datasize++;
					   disasm_flag |= C_MODRM;
					   break;
				   default:
					   return 0;
			   } // 0F-switch
			   break;

	} //switch

	if (disasm_flag & C_MODRM)
	{
		if (limit<4)
			return 0;
		disasm_modrm = *opcode++;
		BYTE mod = disasm_modrm & 0xC0;
		BYTE rm  = disasm_modrm & 0x07;
		if (mod != 0xC0)
		{
			if (mod == 0x40) disasm_memsize++;
			if (mod == 0x80) disasm_memsize += disasm_defmem;
			if (disasm_defmem == 2)           // modrm16
			{
				if ((mod == 0x00)&&(rm == 0x06)) disasm_memsize+=2;
			}
			else                              // modrm32
			{
				if (rm==0x04)
				{
					disasm_flag |= C_SIB;
					disasm_sib = *opcode++;
					rm = disasm_sib & 0x07;
				}
				if ((rm==0x05)&&(mod==0x00)) disasm_memsize+=4;
			}
		}
	} // C_MODRM

	for(i=0; i<disasm_memsize; i++)
		disasm_mem[i] = *opcode++;
	for(i=0; i<disasm_datasize; i++)
		disasm_data[i] = *opcode++;

	disasm_len = opcode - opcode0;

	return disasm_len;
} //disasm

