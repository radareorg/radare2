#ifndef AVR_DISASSEMBLER_H
#define AVR_DISASSEMBLER_H

typedef struct r_asm_t RAsm;

int avr_decode(RArchSession *as, char *out, int out_size, ut64 addr, cut8 *buf, int len);
int avr_anal(RArchSession *as, char *out, int out_size, ut64 addr, cut8 *buf, int len);

#endif /* AVR_DISASSEMBLER_H */
