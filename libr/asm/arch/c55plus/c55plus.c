#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include "decode.h"

// TODO : split into get/set... we need a way to create binary masks from asm buffers
// -- move this shit into r_anal.. ??

//extern char *ins_str[];
extern char *ins_buff;
extern unsigned int ins_buff_len;

int debug = 0;

#if 0
void read_ins()
{
	FILE *fd;

	fd = fopen("test2.obj", "r");
	if(!fd) {
		fprintf(stderr, "can not open test2.obj!");
		exit(1);
	}
		

	fseek(fd, 0x56, SEEK_SET);
	fread(&ins_buff_len, sizeof(ins_buff_len), 1, fd); 

	ins_buff = (char *)malloc(ins_buff_len);
	if(!ins_buff) {
		perror("malloc");
		exit(1);
	}

	fseek(fd, 0x18A, SEEK_SET);
	fread(ins_buff, ins_buff_len, 1, fd); 

	fclose(fd);
}

void disasm()
{
	int ins_pos = 0;
	unsigned int next_ins_pos = 0;
	char *ins_str;

	printf("Disassembly:\n\n");
	while((ins_str = decode(ins_pos, &next_ins_pos)) != NULL) {
		printf(" %s\n", ins_str);
		ins_pos += next_ins_pos;
	}

}
#endif

int c55plus_disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len)
{
	unsigned int next_ins_pos;
	char *ins_decoded;

	ins_buff = buf;
	ins_buff_len = len;

	next_ins_pos = 0;

	// decode instruction
	ins_decoded = decode(0, &next_ins_pos);
	if(!ins_decoded) {
		op->inst_len = 0;
		return 0;
	}

	// opcode length
	op->inst_len = next_ins_pos;
	
	snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s", ins_decoded);

	free(ins_decoded);
	
	return next_ins_pos;
}
#if 0
int main(int argc, char **argv)
{

	if(argc > 1 && !strcmp(argv[1], "-d")) 
		debug = 1;
/*
	unsigned int hashcode;
	char *ins;

	hashcode = get_hashcode(0);
	printf("hashcode : 0x%x\n", hashcode);
        ins = ins_str[(1 + hashcode * 4)];
	printf("%s\n", ins);

	hashcode = get_hashcode(3);
	printf("hashcode : 0x%x\n", hashcode);
        ins = ins_str[(1 + hashcode * 4)];
	printf("%s\n", ins);
*/
	//read_ins();
	//disasm();

	return 0;
}
#endif
