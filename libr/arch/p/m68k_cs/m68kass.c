/* radare2 - MIT - Copyright 2024 - pancake */

#include <r_util.h>

// Define the assembler function pointer type
typedef int (*AssemblerFunc)(char tokens[][256], int num_tokens, unsigned char* output_buffer, int buffer_length);

// Instruction struct to hold mnemonic and its assembler function
typedef struct {
	const char* mnemonic;
	AssemblerFunc assemble;
} Instruction;

// Function to tokenize a string into tokens
static int tokenize(const char* str, char tokens[][256], int max_tokens) {
	int num_tokens = 0;
	const char* p = str;
	while (*p != '\0' && num_tokens < max_tokens) {
		// Skip leading delimiters
		while (*p == ' ' || *p == '\t' || *p == ',') p++;
		if (*p == '\0') break;

		// Copy the token into tokens[num_tokens]
		int len = 0;
		while (*p != '\0' && *p != ' ' && *p != '\t' && *p != ',') {
			if (len < 255) {
				tokens[num_tokens][len++] = *p;
			}
			p++;
		}
		tokens[num_tokens][len] = '\0';
		num_tokens++;
	}
	return num_tokens;
}

// Function to map register name to register number
static int parse_register(const char* reg_str) {
	if (reg_str[0] == 'D' || reg_str[0] == 'd') {
		int reg_num = atoi(reg_str + 1);
		if (reg_num >= 0 && reg_num <= 7) {
			return reg_num;
		}
	}
	return -1; // Invalid register
}

// Implement assembler functions for each instruction
static int assemble_nop(char tokens[][256], int num_tokens, unsigned char* output_buffer, int buffer_length) {
	if (buffer_length < 2) {
		return 0; // Cannot assemble, buffer too small
	}

	// NOP opcode is 0x4E71
	output_buffer[0] = 0x4E;
	output_buffer[1] = 0x71;
	return 2;
}

static int assemble_moveq(char tokens[][256], int num_tokens, unsigned char* output_buffer, int buffer_length) {
	if (buffer_length < 2 || num_tokens != 3) {
		return 0;
	}

	// tokens[0] = "MOVEQ"
	// tokens[1] = "#<data>"
	// tokens[2] = "D<reg>"

	if (tokens[1][0] != '#') {
		return 0; // Immediate value expected
	}

	int immediate_value = atoi(tokens[1] + 1); // Skip the '#'
	if (immediate_value < -128 || immediate_value > 127) {
		return 0; // Immediate value out of range
	}

	int register_number = parse_register(tokens[2]);
	if (register_number < 0) {
		return 0; // Invalid register
	}

	// Opcode: 0x7000 | (Dn << 9) | (immediate_value & 0xFF)
	unsigned short opcode = 0x7000;
	opcode |= (register_number << 9);
	opcode |= (immediate_value & 0xFF);

	output_buffer[0] = (opcode >> 8) & 0xFF;
	output_buffer[1] = opcode & 0xFF;

	return 2;
}

static int assemble_addq(char tokens[][256], int num_tokens, unsigned char* output_buffer, int buffer_length) {
	if (buffer_length < 2 || num_tokens !=3) return 0;

	// tokens[0] = "ADDQ"
	// tokens[1] = "#<data>"
	// tokens[2] = "D<reg>"

	if (tokens[1][0] != '#') return 0;

	int immediate_value = atoi(tokens[1]+1);
	if (immediate_value < 1 || immediate_value > 8) {
		return 0;
	}
	if (immediate_value == 8) immediate_value = 0;

	int register_number = parse_register(tokens[2]);
	if (register_number < 0) {
		return 0; // Invalid register
	}

	unsigned short opcode = 0x5000;
	opcode |= (immediate_value & 0x7) << 9;
	opcode |= (1 <<6); // Size code: word size (01)
	opcode |= (0 << 3); // Mode code for data register direct
	opcode |= register_number & 0x7;

	output_buffer[0] = (opcode>>8) & 0xFF;
	output_buffer[1] = opcode & 0xFF;
	return 2;
}

static int assemble_subq(char tokens[][256], int num_tokens, unsigned char* output_buffer, int buffer_length) {
	if (buffer_length < 2 || num_tokens !=3) return 0;

	// tokens[0] = "SUBQ"
	// tokens[1] = "#<data>"
	// tokens[2] = "D<reg>"

	if (tokens[1][0] != '#') return 0;

	int immediate_value = atoi(tokens[1]+1);
	if (immediate_value < 1 || immediate_value > 8) {
		return 0;
	}
	if (immediate_value ==8) immediate_value = 0;

	int register_number = parse_register(tokens[2]);
	if (register_number < 0) {
		return 0; // Invalid register
	}

	unsigned short opcode = 0x5100;
	opcode |= (immediate_value & 0x7) << 9;
	opcode |= (1 <<6); // Size code: word size (01)
	opcode |= (0 << 3); // Mode code for data register direct
	opcode |= register_number & 0x7;

	output_buffer[0] = (opcode>>8) & 0xFF;
	output_buffer[1] = opcode & 0xFF;
	return 2;
}

static int assemble_bne(char tokens[][256], int num_tokens, unsigned char* output_buffer, int buffer_length) {
	if (num_tokens !=2) return 0;

	// tokens[0] = "BNE"
	// tokens[1] = "<offset>"

	int offset = atoi(tokens[1]);

	if (offset >= -128 && offset <= 127) {
		if (buffer_length <2) return 0;
		unsigned short opcode = 0x6600 | (offset & 0xFF);
		output_buffer[0] = (opcode>>8) & 0xFF;
		output_buffer[1] = opcode & 0xFF;
		return 2;
	} else if (offset >= -32768 && offset <= 32767) {
		if (buffer_length <4) return 0;
		unsigned short opcode = 0x6600;
		output_buffer[0] = (opcode>>8) & 0xFF;
		output_buffer[1] = opcode & 0xFF;
		unsigned short displacement = offset & 0xFFFF;
		output_buffer[2] = (displacement >>8) & 0xFF;
		output_buffer[3] = displacement & 0xFF;
		return 4;
	} else {
		return 0; // Offset out of range
	}
}

static int assemble_eor(char tokens[][256], int num_tokens, unsigned char* output_buffer, int buffer_length) {
	if (buffer_length <2 || num_tokens !=3) return 0;

	// tokens[0] = "EOR"
	// tokens[1] = "D<src>"
	// tokens[2] = "D<dest>"

	int src_reg = parse_register(tokens[1]);
	int dest_reg = parse_register(tokens[2]);

	if (src_reg <0 || dest_reg <0) return 0;

	unsigned short opcode = 0xB100;
	opcode |= (src_reg << 9);
	opcode |= (1 <<6); // Size code: word size
	opcode |= (0 <<3); // dest_mode = 0 (data register direct)
	opcode |= dest_reg & 0x7;

	output_buffer[0] = (opcode>>8) & 0xFF;
	output_buffer[1] = opcode & 0xFF;
	return 2;
}

static int assemble_clr(char tokens[][256], int num_tokens, unsigned char* output_buffer, int buffer_length) {
	if (buffer_length <2 || num_tokens !=2) return 0;

	// tokens[0] = "CLR"
	// tokens[1] = "D<reg>"

	int dest_reg = parse_register(tokens[1]);
	if (dest_reg < 0) return 0;

	unsigned short opcode = 0x4200;
	opcode |= (1 <<6); // Size code: word size
	opcode |= (0 <<3); // dest_mode = 0 (data register direct)
	opcode |= dest_reg & 0x7;

	output_buffer[0] = (opcode>>8) & 0xFF;
	output_buffer[1] = opcode & 0xFF;
	return 2;
}

static int assemble_bchg(char tokens[][256], int num_tokens, unsigned char* output_buffer, int buffer_length) {
	if (buffer_length <2 || num_tokens !=3) return 0;

	// tokens[0] = "BCHG"
	// tokens[1] = "D<src>"
	// tokens[2] = "D<dest>"

	int src_reg = parse_register(tokens[1]);
	int dest_reg = parse_register(tokens[2]);

	if (src_reg < 0 || dest_reg < 0) return 0;

	unsigned short opcode = 0x0140;
	opcode |= (src_reg <<9);
	opcode |= (0 <<3); // dest_mode = 0 (data register direct)
	opcode |= dest_reg & 0x7;

	output_buffer[0] = (opcode>>8) & 0xFF;
	output_buffer[1] = opcode & 0xFF;
	return 2;
}

static int assemble_and(char tokens[][256], int num_tokens, unsigned char* output_buffer, int buffer_length) {
	if (buffer_length <2 || num_tokens !=3) return 0;

	// tokens[0] = "AND"
	// tokens[1] = "D<src>"
	// tokens[2] = "D<dest>"

	int src_reg = parse_register(tokens[1]);
	int dest_reg = parse_register(tokens[2]);

	if (src_reg < 0 || dest_reg < 0) return 0;

	unsigned short opcode = 0xC000;
	opcode |= (src_reg <<9);
	opcode |= (1 <<6); // Size code: word size
	opcode |= (0 <<3); // dest_mode = 0 (data register direct)
	opcode |= dest_reg & 0x7;

	output_buffer[0] = (opcode>>8) & 0xFF;
	output_buffer[1] = opcode & 0xFF;
	return 2;
}

static int assemble_or(char tokens[][256], int num_tokens, unsigned char* output_buffer, int buffer_length) {
	if (buffer_length <2 || num_tokens !=3) return 0;

	// tokens[0] = "OR"
	// tokens[1] = "D<src>"
	// tokens[2] = "D<dest>"

	int src_reg = parse_register(tokens[1]);
	int dest_reg = parse_register(tokens[2]);

	if (src_reg < 0 || dest_reg < 0) return 0;

	unsigned short opcode = 0x8000;
	opcode |= (src_reg <<9);
	opcode |= (1 <<6); // Size code: word size
	opcode |= (0 <<3); // dest_mode = 0 (data register direct)
	opcode |= dest_reg & 0x7;

	output_buffer[0] = (opcode>>8) & 0xFF;
	output_buffer[1] = opcode & 0xFF;
	return 2;
}

static int assemble_btst(char tokens[][256], int num_tokens, unsigned char* output_buffer, int buffer_length) {
	if (buffer_length <2 || num_tokens !=3) return 0;

	// tokens[0] = "BTST"
	// tokens[1] = "D<src>"
	// tokens[2] = "D<dest>"

	int src_reg = parse_register(tokens[1]);
	int dest_reg = parse_register(tokens[2]);

	if (src_reg < 0 || dest_reg < 0) return 0;

	unsigned short opcode = 0x0100;
	opcode |= (src_reg <<9);
	opcode |= (0 <<3); // dest_mode = 0
	opcode |= dest_reg & 0x7;

	output_buffer[0] = (opcode>>8) & 0xFF;
	output_buffer[1] = opcode & 0xFF;
	return 2;
}


// Global array of instructions
Instruction instruction_set[] = {
	{"NOP",   assemble_nop},
	{"MOVEQ", assemble_moveq},
	{"ADDQ",  assemble_addq},
	{"SUBQ",  assemble_subq},
	{"BNE",   assemble_bne},
	{"EOR",   assemble_eor},
	{"CLR",   assemble_clr},
	{"BCHG",  assemble_bchg},
	{"AND",   assemble_and},
	{"OR",    assemble_or},
	{"BTST",  assemble_btst},
	{NULL,    NULL} // Sentinel value to mark the end of the array
};

// Main assemble_instruction function
R_IPI int m68kass(const char* instruction_str, unsigned char* output_buffer, int buffer_length) {
	// Convert instruction_str to uppercase
	char instr_upper[256];
	int i = 0;
	while (instruction_str[i] != '\0' && i < sizeof(instr_upper) - 1) {
		instr_upper[i] = toupper((unsigned char)instruction_str[i]);
		i++;
	}
	instr_upper[i] = '\0';

	// TODO use r_str_split_list()
	// Tokenize the instruction string
	char tokens[10][256]; // Up to 10 tokens
	int num_tokens = tokenize (instr_upper, tokens, 10);
	if (num_tokens == 0) {
		return 0; // Cannot parse instruction
	}

	// Find the instruction in the instruction_set array
	for (i = 0; instruction_set[i].mnemonic != NULL; i++) {
		if (!strcmp (tokens[0], instruction_set[i].mnemonic)) {
			// Found the instruction, call its assembler function
			return instruction_set[i].assemble(tokens, num_tokens, output_buffer, buffer_length);
		}
	}

	// Instruction not found
	return 0;
}
#if 0
int main(int argc, char **argv) {
	unsigned char out[4];
	if (argc < 2) {
		printf ("usage %s [m68kop]\n", argv[0]);
		return 1;
	}
	const char *text = argv[1];
	int len = assemble_instruction (text, out, sizeof (out));
	if (len > 0) {
		int i;
		for (i = 0; i< len; i++) {
			printf ("%02x", out[i]);
		}
		printf ("\n");
	}
	return 0;
}
#endif
