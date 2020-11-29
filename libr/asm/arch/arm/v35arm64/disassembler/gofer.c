#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#include "operations.h"
#include "encodings.h"
#include "arm64dis.h"

void disassemble(uint32_t addr, uint8_t *data, int len, char *result, bool verbose)
{
	Instruction instr;
	memset(&instr, 0, sizeof(instr));

	aarch64_decompose(*(uint32_t *)data, &instr, addr);

	if(verbose)
		print_instruction(&instr);

	aarch64_disassemble(&instr, result, 1024);
}

uint32_t get_encoding(uint8_t *data)
{
	Instruction instr;
	//printf("sizeof(instr): %lu\n", sizeof(instr));
	//printf("sizeof(instr.encoding): %lu\n", sizeof(instr.encoding));
	memset(&instr, 0, sizeof(instr));
	aarch64_decompose(*(uint32_t *)data, &instr, 0);
	return instr.encoding;
}
