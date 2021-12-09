#ifndef AVR_DISASSEMBLER_H
#define AVR_DISASSEMBLER_H

int avr_decode(RAsm *a, char *out, int out_size, ut64 addr, cut8 *buf, int len);
int avr_anal(RAnal *a, char *out, int out_size, ut64 addr, cut8 *buf, int len);

#endif /* AVR_DISASSEMBLER_H */
