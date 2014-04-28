/* libgdbr - LGPL - Copyright 2014 - defragger */

#include "libgdbr.h"
#include "core.h"
#include "packet.h"
#include "messages.h"

extern char hex2char(char* hex);

static registers_t x86_64[] = {
	{"rax",		0,		8,	0},
	{"rbx",		8,		8,	0},
	{"rcx",		16,		8,	0},
	{"rdx",		24,		8,	0},
	{"rsi",		32,		8,	0},
	{"rdi",		40,		8,	0},
	{"rbp",		48,		8,	0},
	{"rsp",		56,		8,	0},
	{"r8",		64,		8,	0},
	{"r9",		72,		8,	0},
	{"r10",		80,		8,	0},
	{"r11",		88,		8,	0},
	{"r12",		96,		8,	0},
	{"r13",		104,	8,	0},
	{"r14",		112,	8,	0},
	{"r15",		120,	8,	0},
	{"rip",		128,	8,	0},
	{"eflags",136,	4,	0},
	{"cs",		140,	4,	0},
	{"ss",		144,	4,	0},
	{"ds",		148,	4,	0},
	{"es",		152,	4,	0},
	{"fs",		156,	4,	0},
	{"gs",		160,	4,	0},
	{"st0",		164,	10,	0},
	{"st1",		174,	10,	0},
	{"st2",		184,	10,	0},
	{"st3",		194,	10,	0},
	{"st4",		204,	10,	0},
	{"st5",		214,	10,	0},
	{"st6",		224,	10,	0},
	{"st7",		234,	10,	0},
	{"fctrl",	244,	4,	0},
	{"fstat",	248,	4,	0},
	{"ftag",	252,	4,	0},
	{"fiseg",	256,	4,	0},
	{"fioff",	260,	4,	0},
	{"foseg",	264,	4,	0},
	{"fooff",	268,	4,	0},
	{"fop",		272,	4,	0},
	{"xmm0",	276,	16,	0},
	{"xmm1",	292,	16,	0},
	{"xmm2",	308,	16,	0},
	{"xmm3",	324,	16,	0},
	{"xmm4",	340,	16,	0},
	{"xmm5",	356,	16,	0},
	{"xmm6",	372,	16,	0},
	{"xmm7",	388,	16,	0},
	{"xmm8",	404,	16,	0},
	{"xmm9",	420,	16,	0},
	{"xmm10",	436,	16,	0},
	{"xmm11",	452,	16,	0},
	{"xmm12",	468,	16,	0},
	{"xmm13",	484,	16,	0},
	{"xmm14",	500,	16,	0},
	{"xmm15",	516,	16,	0},
	{"mxcsr",	532,	4,	0},
	{"", 0, 0, 0}
};


static registers_t x86_32[] = {
	{"eax",	0,	4,	0},
	{"ecx",	4,	4,	0},
	{"edx",	8,	4,	0},
	{"ebx",	12,	4,	0},
	{"esp",	16,	4,	0},
	{"ebp",	20,	4,	0},
	{"esi",	24,	4,	0},
	{"edi",	28,	4,	0},
	{"eip",	32,	4,	0},
	{"eflags",	36,	4,	0},
	{"cs",	40,	4,	0},
	{"ss",	44,	4,	0},
	{"ds",	48,	4,	0},
	{"es",	52,	4,	0},
	{"fs",	56,	4,	0},
	{"gs",	60,	4,	0},
	{"st0",	64,	10,	0},
	{"st1",	74,	10,	0},
	{"st2",	84,	10,	0},
	{"st3",	94,	10,	0},
	{"st4",	104,	10,	0},
	{"st5",	114,	10,	0},
	{"st6",	124,	10,	0},
	{"st7",	134,	10,	0},
	{"fctrl",	144,	4,	0},
	{"fstat",	148,	4,	0},
	{"ftag",	152,	4,	0},
	{"fiseg",	156,	4,	0},
	{"fioff",	160,	4,	0},
	{"foseg",	164,	4,	0},
	{"fooff",	168,	4,	0},
	{"fop",	172,	4,	0},
	{"xmm0",	176,	16,	0},
	{"xmm1",	192,	16,	0},
	{"xmm2",	208,	16,	0},
	{"xmm3",	224,	16,	0},
	{"xmm4",	240,	16,	0},
	{"xmm5",	256,	16,	0},
	{"xmm6",	272,	16,	0},
	{"xmm7",	288,	16,	0},
	{"mxcsr",	304,	4,	0},
	{"",	0,	0,	0}
};


int gdbr_init(libgdbr_t* g) {
	memset(g,0, sizeof(libgdbr_t));
	g->send_buff = (char*) calloc(2500, sizeof(char));
	g->send_len = 0;
	g->send_max = 2500;
	g->read_buff = (char*) calloc(4096, sizeof(char));
	g->read_len = 0;
	g->read_max = 4096;
	g->connected = 0;
	g->data_len = 0;
	g->data = calloc(4096, sizeof(char));
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
		default:
			printf("Error unknown architecture set\n");
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
	int	fd;
	int	connected;
	struct protoent		*protocol;
	struct hostent		*hostaddr;
	struct sockaddr_in	socketaddr;
	
	protocol = getprotobyname("tcp");
	if (!protocol) {
		printf("Error prot\n");
		//TODO Error here
		return -1;
	}

	fd = socket( PF_INET, SOCK_STREAM, protocol->p_proto);
	if (fd == -1) {
		printf("Error sock\n");
		//TODO Error here
		return -1;
	}
	memset(&socketaddr, 0, sizeof(socketaddr));
	socketaddr.sin_family = AF_INET;
	socketaddr.sin_port = htons(port);
	hostaddr = (struct hostent *)gethostbyname(host);

	if (!hostaddr) {
		printf("Error host\n");
		//TODO Error here
		return -1;
	}
	
	connected = connect(fd, (struct sockaddr *) &socketaddr, sizeof(socketaddr));
	if (connected == -1) {
		printf("error conn\n");
		//TODO Error here
		return -1;
	}
	g->fd = fd;
	g->connected = 1;
	// TODO add config possibility here
	char* message = "qSupported:multiprocess+;qRelocInsn+";
	send_command(g, message);
	read_packet(g);
	return handle_connect(g);
}

int gdbr_disconnect(libgdbr_t* g) {
	// TODO Disconnect maybe send something to gdbserver
	close (g->fd);
	g->connected = 0;
	return 0;
}

int gdbr_read_registers(libgdbr_t* g) {
	send_command(g, CMD_READREGS);
	int read_len = read_packet(g);
	if (read_len > 0) {
		parse_packet(g, 0);
		return handle_g(g);
	}
	return -1;
}

int gdbr_read_memory(libgdbr_t* g, uint64_t address, uint64_t len) {
	char command[255] = {};
	int ret = snprintf(command, 255, "%s%016"PFMT64x",%"PFMT64d, CMD_READMEM, address, len);
	if (ret < 0) return ret;
	send_command(g, command);

	int read_len = read_packet(g);
	if (read_len > 0) { 
		parse_packet(g, 0);
		return handle_m(g);
	}
	return -1;
}

int gdbr_write_memory(libgdbr_t* g, uint64_t address, const uint8_t* data, uint64_t len) {
	char command[255] = {};
	int command_len = snprintf(command, 255, "%s%016"PFMT64x",%"PFMT64d":", CMD_WRITEMEM, address, len);
	char* tmp = calloc(command_len + (len * 2), sizeof(ut8));
	memcpy (tmp, command, command_len);
	// XXX: we should 
	pack_hex ((char*)data, len, (tmp + command_len));
	send_command (g, tmp);
	free (tmp);

	if (read_packet (g) > 0) {
		parse_packet(g, 0);
		return 0;
	}
	return -1;
}

int gdbr_step(libgdbr_t* g, int thread_id) {
	return send_vcont(g, CMD_C_STEP, thread_id);
}


int gdbr_continue(libgdbr_t* g, int thread_id) {
	return send_vcont(g, CMD_C_CONT, thread_id);
}

int gdbr_send_command(libgdbr_t* g, char* command) {
	int ret;
	char* cmd = calloc((strlen(command) * 2 + strlen(CMD_QRCMD) + 2), sizeof(char));
	strcpy (cmd, CMD_QRCMD);
	pack_hex (command, strlen(command), (cmd + strlen(CMD_QRCMD)));
	ret = send_command (g, cmd);
	free (cmd);
	if (ret < 0) return ret;

	if (read_packet (g) > 0) {
		parse_packet (g, 1);
		return handle_cmd (g);
	}
	return -1;
}	

int gdbr_write_bin_registers(libgdbr_t* g, char* registers) {
	gdbr_read_registers(g);

	uint64_t buffer_size = g->data_len * 2 + 8;
	char* command = calloc(buffer_size, sizeof(char));
	snprintf(command, buffer_size, "%s", CMD_WRITEREGS);
	pack_hex(g->data, g->data_len, command+1);
	send_command(g, command);
	free(command);
	return 0;
}

int gdbr_write_registers(libgdbr_t* g, char* registers) {
	// read current register set
	gdbr_read_registers(g);

	int x, len = strlen(registers);
	char* buff = calloc(len, sizeof(char));
	memcpy(buff, registers, len);
	char* reg = strtok(buff, ",");
	while ( reg != NULL ) {
		char* name_end = strchr(reg, '=');
		if (name_end == NULL) {
			printf("Malformed argument: %s\n", reg);
			free(buff);
			return -1;
		}
		*name_end = '\0'; // change '=' to '\0'

		// time to find the current register
		int i = 0;
		while ( g->registers[i].size > 0) {
			if (strcmp(g->registers[i].name, reg) == 0) {
				uint64_t register_size = g->registers[i].size;
				uint64_t offset = g->registers[i].offset;
				char* value = calloc (register_size * 2, sizeof(char));

				memset (value, '0', register_size * 2);
				name_end++; 
				// be able to take hex with and without 0x
				if (name_end[1] == 'x' || name_end[1] == 'X') name_end += 2;
				int val_len = strlen (name_end); // size of the rest
				strcpy (value+(register_size * 2 - val_len), name_end);

				for (x=0; x < register_size; x++) {
					g->data[offset + register_size - x - 1] = hex2char(&value[x * 2]);
				}
				free(value);
			}
			i++;
		}
		reg = strtok(NULL, " ,");
	}

	free(buff);

	uint64_t buffer_size = g->data_len * 2 + 8;
	char* command = calloc(buffer_size, sizeof(char));
	snprintf (command, buffer_size, "%s", CMD_WRITEREGS);
	pack_hex (g->data, g->data_len, command+1);
	send_command (g, command);
	read_packet (g);
	free (command);
	handle_G (g);
	return 0;
}

int test_command(libgdbr_t* g, char* command) {
	send_command (g, command);
	read_packet (g);
	hexdump (g->read_buff, g->data_len, 0);
	return 0;
}

int send_vcont(libgdbr_t* g, char* command, int thread_id) {
	char tmp[255] = {};
	int ret = snprintf(tmp, 255, "%s;%s:%x", CMD_C, command, thread_id);
	if (ret < 0) return ret;
	send_command (g, tmp);
	if (read_packet (g) > 0) { 
		parse_packet (g, 0);
		return handle_cont (g);
	}
	return 0;
}

int gdbr_set_breakpoint(libgdbr_t* g, uint64_t address, char* conditions) {
	char tmp[255] = {};
	int ret = snprintf (tmp, sizeof (tmp)-1, "%s,%llx,1", CMD_BP, address);
	if (ret < 0) return ret;
	send_command (g, tmp);
	if (read_packet (g) > 0) {
		parse_packet (g, 0);
		return handle_setbp (g);
	}
	return 0;
}

int gdbr_unset_breakpoint(libgdbr_t* g, uint64_t address) {
	char tmp[255];
	int ret = snprintf(tmp, sizeof (tmp)-1, "%s,%llx,1", CMD_RBP, address);
	if (ret < 0) return ret;
	send_command (g, tmp);
	if (read_packet (g)>0) {
		parse_packet (g, 0);
		return handle_unsetbp (g);
	}
	return 0;
}

int send_ack(libgdbr_t* g) {
	g->send_buff[0] = '+';
	g->send_len = 1;
	send_packet(g);
	return 0;
}

int send_command(libgdbr_t* g, char* command) {
	uint8_t checksum = cmd_checksum (command);
	int ret = snprintf(g->send_buff, g->send_max,
		"$%s#%.2x", command, checksum);
	if (ret >= 0) {
		g->send_len = ret;
		ret = send_packet (g);
	}
	return ret;
}
