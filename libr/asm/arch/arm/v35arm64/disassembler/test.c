/*
	lldb ./cmdline -- single d503201f
	b decode
	r
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#include "operations.h"
#include "encodings.h"
#include "arm64dis.h"

int disassemble(uint64_t address, uint32_t insword, char *result)
{
	int rc;
	Instruction instr;
	memset(&instr, 0, sizeof(instr));

	rc = aarch64_decompose(insword, &instr, address);
	printf("aarch64_decompose() returned %d\n", rc);
	if(rc) return rc;

	rc = aarch64_disassemble(&instr, result, 1024);
	printf("aarch64_disassemble() returned %d\n", rc);
	if(rc) return rc;

	return 0;
}

/* main */
int main(int ac, char **av)
{
	char instxt[1024]={'\0'};

	if(ac <= 1) {
		printf("example usage:\n");
		printf("\t%s d503201f\n", av[0]);
		return -1;
	}

	if(!strcmp(av[1], "speed")) {
		srand(0xCAFE);
		for(int i=0; i<10000000; i++) {
			uint32_t insword = (rand() << 16) ^ rand();
			disassemble(0, insword, instxt);
			//printf("%08X: %s\n", 0, instxt);
		}
		return 0;
	}

	if(!strcmp(av[1], "test")) {
		srand(0xCAFE);
		while(1) {
			Instruction instr;
			memset(&instr, 0, sizeof(instr));
			uint32_t insword = (rand() << 16) ^ rand();
			aarch64_decompose(insword, &instr, 0);
			printf("%08X: %d\n", insword, instr.encoding);
		}
	}

	else {
		uint32_t insword = strtoul(av[1], NULL, 16);
		if(disassemble(0, insword, instxt) == 0)
			printf("%08X: %s\n", insword, instxt);
	}
}
