/* libgdbr - LGPL - Copyright 2014 - defragger */

#include "libgdbr.h"
#include "core.h"
#include "packet.h"
#include "messages.h"

extern char hex2char(char* hex);

static registers_t x86_64[] = {
	{"rax",		0,		8},
	{"rbx",		8,		8},
	{"rcx",		16,		8},
	{"rdx",		24,		8},
	{"rsi",		32,		8},
	{"rdi",		40,		8},
	{"rbp",		48,		8},
	{"rsp",		56,		8},
	{"r8",		64,		8},
	{"r9",		72,		8},
	{"r10",		80,		8},
	{"r11",		88,		8},
	{"r12",		96,		8},
	{"r13",		104,	8},
	{"r14",		112,	8},
	{"r15",		120,	8},
	{"rip",		128,	8},
	{"eflags",136,	4},
	{"cs",		140,	4},
	{"ss",		144,	4},
	{"ds",		148,	4},
	{"es",		152,	4},
	{"fs",		156,	4},
	{"gs",		160,	4},
	{"st0",		164,	10},
	{"st1",		174,	10},
	{"st2",		184,	10},
	{"st3",		194,	10},
	{"st4",		204,	10},
	{"st5",		214,	10},
	{"st6",		224,	10},
	{"st7",		234,	10},
	{"fctrl",	244,	4},
	{"fstat",	248,	4},
	{"ftag",	252,	4},
	{"fiseg",	256,	4},
	{"fioff",	260,	4},
	{"foseg",	264,	4},
	{"fooff",	268,	4},
	{"fop",		272,	4},
	{"xmm0",	276,	16},
	{"xmm1",	292,	16},
	{"xmm2",	308,	16},
	{"xmm3",	324,	16},
	{"xmm4",	340,	16},
	{"xmm5",	356,	16},
	{"xmm6",	372,	16},
	{"xmm7",	388,	16},
	{"xmm8",	404,	16},
	{"xmm9",	420,	16},
	{"xmm10",	436,	16},
	{"xmm11",	452,	16},
	{"xmm12",	468,	16},
	{"xmm13",	484,	16},
	{"xmm14",	500,	16},
	{"xmm15",	516,	16},
	{"mxcsr",	532,	4},
	{"", 0, 0}
};


static registers_t x86_32[] = {
	{"eax",	0,	4},
	{"ecx",	4,	4},
	{"edx",	8,	4},
	{"ebx",	12,	4},
	{"esp",	16,	4},
	{"ebp",	20,	4},
	{"esi",	24,	4},
	{"edi",	28,	4},
	{"eip",	32,	4},
	{"eflags",	36,	4},
	{"cs",	40,	4},
	{"ss",	44,	4},
	{"ds",	48,	4},
	{"es",	52,	4},
	{"fs",	56,	4},
	{"gs",	60,	4},
	{"st0",	64,	10},
	{"st1",	74,	10},
	{"st2",	84,	10},
	{"st3",	94,	10},
	{"st4",	104,	10},
	{"st5",	114,	10},
	{"st6",	124,	10},
	{"st7",	134,	10},
	{"fctrl",	144,	4},
	{"fstat",	148,	4},
	{"ftag",	152,	4},
	{"fiseg",	156,	4},
	{"fioff",	160,	4},
	{"foseg",	164,	4},
	{"fooff",	168,	4},
	{"fop",	172,	4},
	{"xmm0",	176,	16},
	{"xmm1",	192,	16},
	{"xmm2",	208,	16},
	{"xmm3",	224,	16},
	{"xmm4",	240,	16},
	{"xmm5",	256,	16},
	{"xmm6",	272,	16},
	{"xmm7",	288,	16},
	{"mxcsr",	304,	4},
	{"",	0,	0}
};

static registers_t arm32[] = {
	{"r0",	0,	4},
	{"r1",	4,	4},
	{"r2",	8,	4},
	{"r3",	12,	4},
	{"r4",	16,	4},
	{"r5",	20,	4},
	{"r6",	24,	4},
	{"r7",	28,	4},
	{"r8",	32,	4},
	{"r9",	36,	4},
	{"r10",	40,	4},
	{"r11",	44,	4},
	{"r12",	48,	4},
	{"sp",	52,	4},
	{"lr",  56, 4},
	{"pc",	60,	4},
	{"f0",  64, 12},
	{"f1",  76, 12},
	{"f2",  88, 12},
	{"f3",  100, 12},
	{"f4",  112, 12},
	{"f5",  124, 12},
	{"f6",  136, 12},
	{"f7",  148, 12},
	{"fps", 160, 12},
	{"cpsr", 172,4},
	{"",	0,	0}
};


static registers_t aarch64[] = {
	{"x0",	0,	8},
	{"x1",	8,	8},
	{"x2",	16,	8},
	{"x3",	24,	8},
	{"x4",	32,	8},
	{"x5",	40,	8},
	{"x6",	48,	8},
	{"x7",	56,	8},
	{"x8",	64,	8},
	{"x9",	72,	8},
	{"x10",	80,	8},
	{"x11",	88,	8},
	{"x12",	96,	8},
	{"x13",	104,	8},
	{"x14",	112,	8},
	{"x15",	120,	8},
	{"x16",	128,	8},
	{"x17",	136,	8},
	{"x18",	144,	8},
	{"x19",	152,	8},
	{"x20",	160,	8},
	{"x21",	168,	8},
	{"x22",	176,	8},
	{"x23",	184,	8},
	{"x24",	192,	8},
	{"x25",	200,	8},
	{"x26",	208,	8},
	{"x27",	216,	8},
	{"x28",	224,	8},
	{"x29",	232,	8},
	{"x30",	240,	8},
	{"sp",	248,	8},
	{"pc",	256,	8},
	{"cpsr",	264,	4},
	{"v0",	268,	16},
	{"v1",	284,	16},
	{"v2",	300,	16},
	{"v3",	316,	16},
	{"v4",	332,	16},
	{"v5",	348,	16},
	{"v6",	364,	16},
	{"v7",	380,	16},
	{"v8",	396,	16},
	{"v9",	412,	16},
	{"v10",	428,	16},
	{"v11",	444,	16},
	{"v12",	460,	16},
	{"v13",	476,	16},
	{"v14",	492,	16},
	{"v15",	508,	16},
	{"v16",	524,	16},
	{"v17",	540,	16},
	{"v18",	556,	16},
	{"v19",	572,	16},
	{"v20",	588,	16},
	{"v21",	604,	16},
	{"v22",	620,	16},
	{"v23",	636,	16},
	{"v24",	652,	16},
	{"v25",	668,	16},
	{"v26",	684,	16},
	{"v27",	700,	16},
	{"v28",	716,	16},
	{"v29",	732,	16},
	{"v30",	748,	16},
	{"v31",	764,	16},
	{"fpsr",	780,	4},
	{"fpcr",	784,	4},
	{"",	0,	0}
};
static registers_t mips[] = {
    {"zero", 0,	0},
    {"at", 4,	0},
    {"v0", 8,	0},
    {"v1", 12,	8},
    {"a0", 16,	8},
    {"a1", 20,	8},
    {"a2", 24,	8},
    {"a3", 28,	8},
    {"t0", 32,	8},
    {"t1", 36,	8},
    {"t2", 40,	8},
    {"t3", 44,	8},
    {"t4", 48,	8},
    {"t5", 52,	8},
    {"t6", 56,	8},
    {"t7", 60,	8},
    {"s0", 64,	8},
    {"s1", 68,	8},
    {"s2", 72,	8},
    {"s3", 76,	8},
    {"s4", 80,	8},
    {"s5", 84,	8},
    {"s6", 88,	8},
    {"s7", 92,	8},
    {"t8", 96,	8},
    {"t9", 100,	8},
    {"k0", 104,	8},
    {"k1", 108,	8},
    {"gp", 112,	8},
    {"sp", 116,	8},
    {"s8", 120,	8},
    {"ra", 124,	8},
    {"sr", 128,	8},
    {"lo", 132,	8},
    {"hi", 134,	8},
    {"bad", 140,	8},
    {"cause", 144,	8},
    {"pc", 148,	8},
    {"f0", 152,	8},
    {"f1", 156,	8},
    {"f2", 160,	8},
    {"f3", 164,	8},
    {"f4", 168,	8},
    {"f5", 172,	8},
    {"f6", 176,	8},
    {"f7", 180,	8},
    {"f8", 184,	8},
    {"f9", 188,	8},
    {"f10", 192,	8},
    {"f11", 196,	8},
    {"f12", 200,	8},
    {"f13", 204,	8},
    {"f14", 208,	8},
    {"f15", 212,	8},
    {"f16", 216,	8},
    {"f17", 220,	8},
    {"f18", 224,	8},
    {"f19", 228,	8},
    {"f20", 232,	8},
    {"f21", 236,	8},
    {"f22", 240,	8},
    {"f23", 244,	8},
    {"f24", 248,	8},
    {"f25", 252,	8},
    {"f26", 256,	8},
    {"f27", 260,	8},
    {"f28", 264,	8},
    {"f29", 268,	8},
    {"f30", 272,	8},
    {"f31", 276,	8},
    {"fsr", 280,	8},
    {"fir", 284,	8},
    {"unknw", 288,	8},
	{"",	0,	0}
};

int gdbr_init(libgdbr_t* g) {
	memset (g ,0 , sizeof (libgdbr_t));
	g->send_buff = (char*) calloc (2500, sizeof (char));
	if (!g->send_buff) return -1;
	g->send_len = 0;
	g->send_max = 2500;
	g->read_buff = (char*) calloc (4096, sizeof (char));
	if (!g->read_buff) {
		free (g->send_buff);
		return -1;
	}
	g->read_len = 0;
	g->sock = r_socket_new (0);
	g->last_code = MSG_OK;
	g->read_max = 4096;
	g->connected = 0;
	g->data_len = 0;
	g->data = calloc (4096, sizeof (char));
	if (!g->data) {
		free (g->send_buff);
		free (g->read_buff);
		return -1;
	}
	g->data_max = 4096;
	return 0;
}


int gdbr_set_architecture(libgdbr_t* g, uint8_t architecture) {
	g->architecture = architecture;
	switch (architecture) {
		case ARCH_X86_32:
			g->registers = x86_32;
			break;
		case ARCH_X86_64:
			g->registers = x86_64;
			break;
		case ARCH_ARM_32:
			g->registers = arm32;
			break;
		case ARCH_ARM_64:
			g->registers = aarch64;
			break;
        case ARCH_MIPS:
			g->registers = mips;
			break;
		default:
			fprintf (stderr, "Error unknown architecture set\n");
	}
	return 0;
}

int gdbr_cleanup(libgdbr_t* g) {
	free (g->data);
	free (g->send_buff);
	g->send_len = 0;
	free (g->read_buff);
	g->read_len = 0;
	return 0;
}

int gdbr_connect(libgdbr_t* g, const char* host, int port) {
	int ret;
	char tmp[255];
	ret = snprintf (tmp, 255, "%d", port);
	if (!ret) return -1;
	ret = r_socket_connect_tcp (g->sock, host, tmp, 200);
	if (!ret) return -1;
	g->connected = 1;
	// TODO add config possibility here
	char* message = "qSupported:multiprocess+;qRelocInsn+";
	ret = send_command(g, message);
	if (ret < 0)
		return ret;
	read_packet(g);
	return handle_connect(g);
}

int gdbr_disconnect(libgdbr_t* g) {
	// TODO Disconnect maybe send something to gdbserver
	if (!r_socket_close (g->sock)) return -1;
	g->connected = 0;
	return 0;
}

int gdbr_read_registers(libgdbr_t* g) {
	send_command (g, CMD_READREGS);
	if ( read_packet (g) > 0) {
		parse_packet (g, 0);
		return handle_g (g);
	}
	return -1;
}

int gdbr_read_memory(libgdbr_t* g, ut64 address, ut64 len) {
	char command[255] = {};
	int ret = snprintf(command, 255, "%s%016"PFMT64x",%"PFMT64d, CMD_READMEM, address, len);
	if (ret < 0)
		return ret;
	ret = send_command(g, command);
	if (ret < 0)
		return ret;

	if (read_packet (g) > 0) { 
		parse_packet (g, 0);
		return handle_m (g);
	}
	return -1;
}

int gdbr_write_memory(libgdbr_t* g, ut64 address, const uint8_t* data, ut64 len) {
	char command[255] = {};
	int ret = 0;
	int command_len = snprintf(command, 255, "%s%016"PFMT64x",%"PFMT64d":", CMD_WRITEMEM, address, len);
	char* tmp = calloc(command_len + (len * 2), sizeof(ut8));
	if (!tmp)
		return -1;
	memcpy (tmp, command, command_len);
	pack_hex ((char*)data, len, (tmp + command_len));
	ret = send_command (g, tmp);
	free (tmp);
	if (ret < 0)
		return ret;

	if (read_packet (g) > 0) {
		parse_packet (g, 0);
		return handle_M (g);
	}
	return -1;
}

int gdbr_step(libgdbr_t* g, int thread_id) {
	return send_vcont (g, CMD_C_STEP, thread_id);
}


int gdbr_continue(libgdbr_t* g, int thread_id) {
	return send_vcont (g, CMD_C_CONT, thread_id);
}

int gdbr_send_command(libgdbr_t* g, char* command) {
	int ret;
	char* cmd = calloc ((strlen (command) * 2 + strlen (CMD_QRCMD) + 2), sizeof (char));
	if (!cmd) return -1;
	strcpy (cmd, CMD_QRCMD);
	pack_hex (command, strlen (command), (cmd + strlen (CMD_QRCMD)));
	ret = send_command (g, cmd);
	free (cmd);
	if (ret < 0) return ret;

	if (read_packet (g) > 0) {
		parse_packet (g, 1);
		return handle_cmd (g);
	}
	return -1;
}	

int gdbr_write_bin_registers(libgdbr_t* g){
	uint64_t buffer_size = g->data_len * 2 + 8;
	char* command = calloc (buffer_size, sizeof (char));
	if (!command) return -1;
	snprintf (command, buffer_size, "%s", CMD_WRITEREGS);
	pack_hex (g->data, g->data_len, command+1);
	if (send_command (g, command) < 0) {
		free (command);
		return -1;
	}
	read_packet (g);
	free (command);
	handle_G (g);
	return 0;
}

int gdbr_write_register(libgdbr_t* g, int index, char* value, int len) {
	char command[255] = {};
	int ret = snprintf (command, 255, "%s%d=", CMD_WRITEREG, index);
	memcpy(command + ret, value, len);
	pack_hex (value, len, (command + ret));
	if (send_command (g, command) < 0)
		return -1;
	if (read_packet (g) > 0) {
		parse_packet (g, 0);
		handle_P (g);
	}
	return 0;
}

int gdbr_write_reg(libgdbr_t* g, const char* name, char* value, int len) {
	// static variable that keeps the information if writing
	// register through packet <P> was possible
	static int P = 1;
	int i = 0;
	while ( g->registers[i].size > 0) {
		if (strcmp (g->registers[i].name, name) == 0) {
			break;
		}
		i++;
	}
	if (g->registers[i].size == 0) {
		fprintf(stderr, "Error registername <%s> not found in profile\n", name);
		return -1;
	}
	if (P) {
		gdbr_write_register (g, i, value, len);
		if (g->last_code == MSG_OK) {
			return 0;
		}
		P = 0;
	}
	gdbr_read_registers (g);
	memcpy (g->data + g->registers[i].offset, value, len);
	gdbr_write_bin_registers (g);
	return 0;
}

int gdbr_write_registers(libgdbr_t* g, char* registers) {
	uint64_t buffer_size;
	int ret, i = 0;
	unsigned int x, len;
	char* command, *reg, *buff;
	// read current register set

	gdbr_read_registers (g);
	len = strlen (registers);
	buff = calloc (len, sizeof(char));
	if (!buff)
		return -1;
	memcpy (buff, registers, len);
	reg = strtok(buff, ",");
	while ( reg != NULL ) {
		char* name_end = strchr (reg, '=');
		if (name_end == NULL) {
			fprintf (stderr, "Malformed argument: %s\n", reg);
			free (buff);
			return -1;
		}
		*name_end = '\0'; // change '=' to '\0'

		// time to find the current register
		while ( g->registers[i].size > 0) {
			if (strcmp(g->registers[i].name, reg) == 0) {
				const uint64_t register_size = g->registers[i].size;
				const uint64_t offset = g->registers[i].offset;
				char* value = malloc (register_size * 2);
				if (!value) {
					free (buff);
					return -1;
				}

				memset (value, '0', register_size * 2);
				name_end++; 
				// be able to take hex with and without 0x
				if (name_end[1] == 'x' || name_end[1] == 'X') name_end += 2;
				const int val_len = strlen (name_end); // size of the rest
				strcpy (value+(register_size * 2 - val_len), name_end);

				for (x=0; x < register_size; x++) {
					g->data[offset + register_size - x - 1] = hex2char(&value[x * 2]);
				}
				free(value);
			}
			i++;
		}
		reg = strtok (NULL, " ,");
	}

	free (buff);

	buffer_size = g->data_len * 2 + 8;
	command = calloc(buffer_size, sizeof(char));
	if (!command)
		return -1;
	snprintf (command, buffer_size, "%s", CMD_WRITEREGS);
	pack_hex (g->data, g->data_len, command+1);
	ret = send_command (g, command);
	if (ret < 0) {
		free (command);
		return ret;
	}
	read_packet (g);
	free (command);
	handle_G (g);
	return 0;
}

int test_command(libgdbr_t* g, const char* command) {
	int ret = send_command (g, command);
	if (ret < 0)
		return ret;
	read_packet (g);
	hexdump (g->read_buff, g->data_len, 0);
	return 0;
}

int send_vcont(libgdbr_t* g, const char* command, int thread_id) {
	char tmp[255] = {};
	int ret;
	if (thread_id < 0) {
		ret = snprintf (tmp, 255, "%s;%s", CMD_C, command);
	} else {
		ret = snprintf (tmp, 255, "%s;%s:%x", CMD_C, command, thread_id);
	}
	if (ret < 0) return ret;
	ret = send_command (g, tmp);
	if (ret < 0) return ret;
	if (read_packet (g) > 0) { 
		parse_packet (g, 0);
		return handle_cont (g);
	}
	return 0;
}

int set_bp(libgdbr_t* g, ut64 address, const char* conditions, enum Breakpoint type) {
	char tmp[255] = {};
	int ret = 0;
	switch (type) {
	case BREAKPOINT:
		ret = snprintf (tmp, sizeof (tmp)-1,
			"%s,%"PFMT64x",1", CMD_BP, address);
		break;
	case HARDWARE_BREAKPOINT:
		ret = snprintf (tmp, sizeof (tmp)-1,
			"%s,%"PFMT64x",1", CMD_HBP, address);
		break;
	case WRITE_WATCHPOINT:
		break;
	case READ_WATCHPOINT:
		break;
	case ACCESS_WATCHPOINT:
		break;
	default:
		break;
	}
	if (ret < 0) return ret;
	ret = send_command (g, tmp);
	if (ret < 0) return ret;

	if (read_packet (g) > 0) {
		parse_packet (g, 0);
		return handle_setbp (g);
	}
	return 0;
}

int gdbr_set_bp(libgdbr_t* g, ut64 address, const char* conditions) {
	return set_bp (g, address, conditions, BREAKPOINT);
}

int gdbr_set_hwbp(libgdbr_t* g, ut64 address, const char* conditions) {
	return set_bp (g, address, conditions, HARDWARE_BREAKPOINT);
}

int gdbr_remove_bp(libgdbr_t* g, ut64 address) {
	return remove_bp (g, address, BREAKPOINT);
}

int gdbr_remove_hwbp(libgdbr_t* g, ut64 address) {
	return remove_bp (g, address, HARDWARE_BREAKPOINT);
}

int remove_bp(libgdbr_t* g, ut64 address, enum Breakpoint type) {
	char tmp[255] = {};
	int ret = 0;
	switch (type) {
	case BREAKPOINT:
		ret = snprintf (tmp, sizeof (tmp)-1, "%s,%"PFMT64x",1", CMD_RBP, address);
		break;
	case HARDWARE_BREAKPOINT:
		ret = snprintf (tmp, sizeof (tmp)-1, "%s,%"PFMT64x",1", CMD_RHBP, address);
		break;
	case WRITE_WATCHPOINT:
		break;
	case READ_WATCHPOINT:
		break;
	case ACCESS_WATCHPOINT:
		break;
	default:
		break;
	}
	if (ret < 0) return ret;
	ret = send_command (g, tmp);
	if (ret < 0) return ret;

	if (read_packet (g) > 0) {
		parse_packet (g, 0);
		return handle_removebp (g);
	}
	return 0;
}

int send_ack(libgdbr_t* g) {
	g->send_buff[0] = '+';
	g->send_len = 1;
	send_packet (g);
	return 0;
}

int send_command(libgdbr_t* g, const char* command) {
	uint8_t checksum = cmd_checksum (command);
	int ret = snprintf(g->send_buff, g->send_max,
		"$%s#%.2x", command, checksum);
	if (ret >= 0) {
		g->send_len = ret;
		ret = send_packet (g);
		g->send_len = ret;
		return ret;
	}
	return -1;
}

