#ifndef _INCLUDE_ARMASS_H_
#define _INCLUDE_ARMASS_H_

#define B1111 15
#define B1110 14
#define B1101 13
#define B1100 12
#define B1011 11
#define B1010 10
#define B1001 9
#define B1000 8
#define B0111 7
#define B0110 6
#define B0101 5
#define B0100 4
#define B0011 3
#define B0010 2
#define _(a,b,c,d) ((a<<12)|(b<<8)|(c<<4)|(d))

int armass_assemble(const char *str, unsigned long off, int thumb);

#endif
