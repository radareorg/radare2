#include "libgdbr.h"
#include "core.h"
#include "packet.h"
#include "messages.h"


int gdbr_init(libgdbr_t* instance) {
	memset(instance,0, sizeof(libgdbr_t));
	instance->send_buff = (char*) calloc(2500, sizeof(char));
	instance->send_len = 0;
	instance->send_max = 2500;
	instance->read_buff = (char*) calloc(4096, sizeof(char));
	instance->read_len = 0;
	instance->read_max = 4096;
	instance->connected = 0;
	instance->data_len = 0;
	instance->data = calloc(4096, sizeof(char));
	instance->data_max = 4096;
	return 0; 
}


int gdbr_set_architecture(libgdbr_t* instance, uint8_t architecture) {
	instance->architecture = architecture;
	switch (architecture) {
		case ARCH_X86_32:
			instance->registers = x86_32;
			break;
		case ARCH_X86_64:
			instance->registers = x86_64;
			break;
		default:
			printf("Error unknown architecture set\n");
	}
	return 0;
}


int gdbr_cleanup(libgdbr_t* instance) {
	free(instance->data);
	free(instance->send_buff);
	instance->send_len = 0;
	free(instance->read_buff);
	instance->read_len = 0;
	return 0;
}


int gdbr_connect(libgdbr_t* instance, const char* host, int port) {
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
	instance->fd = fd;
	instance->connected = 1;
	// TODO add config possibility here
	char* message = "qSupported:multiprocess+;qRelocInsn+";
	send_command(instance, message);
	read_packet(instance);
	return handle_connect(instance);
}


int gdbr_disconnect(libgdbr_t* instance) {
	// TODO Disconnect maybe send something to gdbserver
	close(instance->fd);
	instance->connected = 0;
	return 0;
}


int gdbr_read_registers(libgdbr_t* instance) {
	send_command(instance, CMD_READREGS);
	int read_len = read_packet(instance);
	if ( read_len > 0) {
		parse_packet(instance, 0);
		return handle_g(instance);
	}
	return -1;
}


int gdbr_read_memory(libgdbr_t* instance, uint64_t address, uint64_t len) {
	char command[255] = {};
	int ret = snprintf(command, 255, "%s%016lx,%ld", CMD_READMEM, address, len);
	if (ret < 0) return ret;
	send_command(instance, command);

	int read_len = read_packet(instance);
	if (read_len > 0) { 
		parse_packet(instance, 0);
		return handle_m(instance);
	}
	return -1;
}


int gdbr_write_memory(libgdbr_t* instance, uint64_t address, char* data, uint64_t len) {
	char command[255] = {};
	int command_len = snprintf(command, 255, "%s%016lx,%ld:", CMD_WRITEMEM, address, len);
	char* tmp = calloc(command_len + (len * 2), sizeof(char));
	memcpy(tmp, command, command_len);
	pack_hex(data, len, (tmp + command_len));
	send_command(instance, tmp);
	free(tmp);

	int read_len = read_packet(instance);
	if (read_len > 0) {
		parse_packet(instance, 0);
		return 0;
	}
	return -1;
}


int gdbr_step(libgdbr_t* instance, int thread_id) {
	return send_vcont(instance, CMD_C_STEP, thread_id);
}


int gdbr_continue(libgdbr_t* instance, int thread_id) {
	return send_vcont(instance, CMD_C_CONT, thread_id);
}


int gdbr_send_command(libgdbr_t* instance, char* command) {
	char* cmd = calloc((strlen(command) * 2 + strlen(CMD_QRCMD) + 2), sizeof(char));
	strcpy(cmd, CMD_QRCMD);
	pack_hex(command, strlen(command), (cmd + strlen(CMD_QRCMD)));
	int ret = send_command(instance, cmd);
	free(cmd);
	if (ret < 0) return ret;

	int read_len = read_packet(instance);
	if (read_len > 0) {
		parse_packet(instance, 1);
		return handle_cmd(instance);
	}
	return -1;
}	


int gdbr_write_bin_registers(libgdbr_t* instance, char* registers) {
	gdbr_read_registers(instance);

	uint64_t buffer_size = instance->data_len * 2 + 8;
	char* command = calloc(buffer_size, sizeof(char));
	snprintf(command, buffer_size, "%s", CMD_WRITEREGS);
	pack_hex(instance->data, instance->data_len, command+1);
	send_command(instance, command);
	free(command);
	return 0;
}


int gdbr_write_registers(libgdbr_t* instance, char* registers) {
	int ret = 0;
	// read current register set
	gdbr_read_registers(instance);

	int len = strlen(registers);
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
		while ( instance->registers[i].size > 0) {
			if (strcmp(instance->registers[i].name, reg) == 0) {

				uint64_t register_size = instance->registers[i].size;
				uint64_t offset = instance->registers[i].offset;

				char* value = calloc(register_size * 2, sizeof(char));

				memset(value, '0', register_size * 2);
								
				name_end++; 
				// be able to take hex with and without 0x
				if (name_end[1] == 'x' || name_end[1] == 'X') name_end += 2;
				int val_len = strlen(name_end); // size of the rest
				strcpy(value+(register_size * 2 - val_len), name_end);

				int x = 0;
				while (x < register_size) {
					instance->data[offset + register_size - x - 1] = hex2char(&value[x * 2]);
					x++;
				}
				free(value);
			}
			i++;
		}
		reg = strtok(NULL, " ,");
	}

	free(buff);

	uint64_t buffer_size = instance->data_len * 2 + 8;
	char* command = calloc(buffer_size, sizeof(char));
	snprintf(command, buffer_size, "%s", CMD_WRITEREGS);
	pack_hex(instance->data, instance->data_len, command+1);
	send_command(instance, command);
	read_packet(instance);
	free(command);
	handle_G(instance);
	return 0;
}


int test_command(libgdbr_t* instance, char* command) {
	send_command(instance, command);
	read_packet(instance);
	hexdump(instance->read_buff, instance->data_len, 0);
	return 0;
}


int send_vcont(libgdbr_t* instance, char* command, int thread_id) {
	char tmp[255] = {};
	int ret = snprintf(tmp, 255, "%s;%s:%x", CMD_C, command, thread_id);
	if (ret < 0) return ret;
	send_command(instance, tmp);

	int read_len = read_packet(instance);
	if (read_len > 0) { 
		parse_packet(instance, 0);
		return handle_cont(instance);
	}
	return 0;
}


int gdbr_set_breakpoint(libgdbr_t* instance, uint64_t address, char* conditions) {
	char tmp[255] = {};
	int ret = snprintf(tmp, 255, "%s,%llx,1", CMD_BP, address);
	if (ret < 0) return ret;
	send_command(instance, tmp);

	int read_len = read_packet(instance);
	if (read_len > 0) {
		parse_packet(instance, 0);
		return handle_setbp(instance);
	}
	return 0;
}


int gdbr_unset_breakpoint(libgdbr_t* instance, uint64_t address) {
	char tmp[255] = {};
	int ret = snprintf(tmp, 255, "%s,%llx,1", CMD_RBP, address);
	if (ret < 0) return ret;
	send_command(instance, tmp);

	int read_len = read_packet(instance);
	if (read_len > 0) {
		parse_packet(instance, 0);
		return handle_unsetbp(instance);
	}
	return 0;
}


int send_ack(libgdbr_t* instance) {
	instance->send_buff[0] = '+';
	instance->send_len = 1;
	send_packet(instance);
	return 0;
}

int send_command(libgdbr_t* instance, char* command) {
	uint8_t checksum = cmd_checksum(command);
	int ret = snprintf(instance->send_buff, instance->send_max, "$%s#%.2x", command, checksum);
	if (ret < 0) {
		return ret;
	}
	instance->send_len = ret;
	return send_packet(instance);
}

