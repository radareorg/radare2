/*! \file */
#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stdio.h>


uint8_t cmd_checksum(const char* command);
uint64_t unpack_uint64(char *buff, int len);
uint64_t unpack_uint64_co(char* buff, int len);
int unpack_hex(char* src, ut64 len, char* dst);
int pack_hex(char* src, ut64 len, char* dst);
int hex2int(int ch);
int int2hex(int i);
void hexdump(void* ptr, ut64 len, ut64 offset);

#endif
