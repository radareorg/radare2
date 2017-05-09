/* libgdbr - LGPL - Copyright 2014-2017 - defragger */

#include "gdbclient/responses.h"
#include "gdbclient/commands.h"
#include "gdbclient/core.h"
#include "arch.h"
#include "libgdbr.h"
#include "packet.h"
#include "r_util/r_strbuf.h"

extern char hex2char(char *hex);

int gdbr_connect(libgdbr_t *g, const char *host, int port) {
	const char *message = "qSupported:multiprocess+;qRelocInsn+";
	RStrBuf tmp;
	r_strbuf_init (&tmp);
	int ret;
	if (!g || !host) {
		return -1;
	}
	ret = snprintf (tmp.buf, sizeof (tmp.buf) - 1, "%d", port);
	if (!ret) {
		return -1;
	}
	ret = r_socket_connect_tcp (g->sock, host, tmp.buf, 200);
	if (!ret) {
		return -1;
	}
	read_packet (g);
	g->connected = 1;
	// TODO add config possibility here
	ret = send_command (g, message);
	if (ret < 0) {
		return ret;
	}
	read_packet (g);
	ret = handle_qSupported (g);
	if (ret < 0) {
		return ret;
	}
	// Check if trace is already running
	ret = send_command (g, "qTStatus");
	if (ret < 0) {
		return ret;
	}
	read_packet (g);
	ret = handle_qStatus (g);
	if (ret < 0) {
		// qTStatus unsupported for this gdbserver
		// return ret;
	}

	// Query the thread / process id
	ret = send_command (g, "qC");
	if (ret < 0) {
		return ret;
	}
	read_packet (g);
	ret = handle_qC (g);
	if (ret < 0) {
		// qC unsupported
		//return ret;
	}

	// Check if remote server attached to or created process
	if (g->stub_features.multiprocess) {
		char pid_buf[20] = { 0 };
		pack_hex_uint64 (g->pid, pid_buf);
		snprintf (tmp.buf, sizeof (tmp.buf) - 1, "qAttached:%s", pid_buf);
		ret = send_command (g, tmp.buf);
	} else {
		ret = send_command (g, "qAttached");
	}
	if (ret < 0) {
		return ret;
	}
	read_packet (g);
	g->attached = (g->data[0] == '1');
	ret = send_ack (g);
	if (ret < 0) {
		return ret;
	}

	// Set the filesystem to use to be the fs visible to current process
	if (g->stub_features.multiprocess) {
		char pid_buf[20] = { 0 };
		pack_hex_uint64 (g->pid, pid_buf);
		snprintf (tmp.buf, sizeof (tmp.buf), "vFile:setfs:%s", pid_buf);
		ret = send_command (g, tmp.buf);
		if (ret < 0) {
			return ret;
		}
	}
	read_packet (g);
	ret = send_ack (g);
	if (!*g->data || g->data[0] != 'F' || g->data[1] == '-') {
		eprintf ("handle gF\n");
		return 0;
		return -1;
	}
	if (ret < 0) {
		eprintf ("handle gF\n");
		// return ret;
	}

	// Get name of file being executed
	if (g->stub_features.multiprocess) {
		char pid_buf[20] = { 0 };
		pack_hex_uint64 (g->pid, pid_buf);
		snprintf (tmp.buf, sizeof (tmp.buf) - 1, "qXfer:exec-file:read:%s:0,fff", pid_buf);
		ret = send_command (g, tmp.buf);
	} else {
		ret = send_command (g, "qXfer:exec-file:read::0,fff");
	}
	if (ret < 0) {
		return ret;
	}
	read_packet (g);
	(void) handle_execFileRead (g);

	// Open the file
	char *file_to_hex = calloc (2, strlen (g->exec_file_name) + 1);
	if (!file_to_hex) {
		return -1;
	}
	pack_hex (g->exec_file_name, strlen (g->exec_file_name), file_to_hex);
	r_strbuf_setf (&tmp, "vFile:open:%s,0,0", file_to_hex);
	free (file_to_hex);
	if (tmp.ptr) {
		ret = send_command (g, tmp.ptr);
	} else {
		ret = send_command (g, tmp.buf);
	}
	r_strbuf_fini (&tmp);
	if (ret < 0) {
		return ret;
	}
	read_packet (g);
	ret = handle_fOpen (g);
	if (ret < 0) {
		return ret;
	}

	// Get fstat data for file
	snprintf (tmp.buf, sizeof (tmp.buf) - 1, "vFile:fstat:%"PFMT32x, g->exec_fd);
	ret = send_command (g, tmp.buf);
	if (ret < 0) {
		return ret;
	}
	read_packet (g);
	ret = handle_fstat (g);
	if (ret < 0) {
		return ret;
	}

	// Set pid/thread for next operations
	if (g->stub_features.multiprocess) {
		char pid_buf[20] = { 0 };
		char tid_buf[20] = { 0 };
		pack_hex_uint64 (g->pid, pid_buf);
		pack_hex_uint64 (g->tid, tid_buf);
		snprintf (tmp.buf, sizeof (tmp.buf) - 1, "Hgp%s.%s", pid_buf, tid_buf);
	} else {
		char tid_buf[20] = { 0 };
		pack_hex_uint64 (g->tid, tid_buf);
		snprintf (tmp.buf, sizeof (tmp.buf) - 1, "Hg%s", tid_buf);
	}
	ret = send_command (g, tmp.buf);
	if (ret < 0) {
		return ret;
	}
	read_packet (g);
	ret = send_ack (g);
	if (strncmp (g->data, "OK", 2)) {
		ret = -1;
	}
	return ret;
}

int gdbr_disconnect(libgdbr_t *g) {
	// TODO Disconnect maybe send something to gdbserver
	if (!g || !r_socket_close (g->sock)) {
		return -1;
	}
	g->connected = 0;
	return 0;
}

int gdbr_read_registers(libgdbr_t *g) {
	int ret = -1;
	if (!g) {
		return -1;
	}
	ret = send_command (g, CMD_READREGS);
	if (ret < 0) {
		return ret;
	}

	if (read_packet (g) >= 0) {
		return handle_g (g);
	}
	return -1;
}

int gdbr_read_memory(libgdbr_t *g, ut64 address, ut64 len) {
	char command[255] = {0};
	int ret;
	if (!g) {
		return -1;
	}
	ret = snprintf (command, sizeof (command),
		"%s%016"PFMT64x ",%"PFMT64d, CMD_READMEM, address, len);
	if (ret < 0) {
		return ret;
	}
	ret = send_command (g, command);
	if (ret < 0) {
		return ret;
	}

	if (read_packet (g) >= 0) {
		return handle_m (g);
	}
	return -1;
}

int gdbr_write_memory(libgdbr_t *g, ut64 address, const uint8_t *data, ut64 len) {
	char command[255] = {0};
	int ret = 0;
	int command_len;
	char *tmp;
	if (!g || !data) {
		return -1;
	}
	command_len = snprintf (command, sizeof (command) - 1,
		"%s%016"PFMT64x ",%"PFMT64d ":", CMD_WRITEMEM, address, len);
	tmp = calloc (command_len + (len * 2), sizeof (char));
	if (!tmp) {
		return -1;
	}
	memcpy (tmp, command, command_len);
	pack_hex ((char *) data, len, (tmp + command_len));
	ret = send_command (g, tmp);
	free (tmp);
	if (ret < 0) {
		return ret;
	}

	if (read_packet (g) >= 0) {
		return handle_M (g);
	}
	return -1;
}

int gdbr_step(libgdbr_t *g, int thread_id) {
	return send_vcont (g, CMD_C_STEP, thread_id);
}

int gdbr_continue(libgdbr_t *g, int thread_id) {
	return send_vcont (g, CMD_C_CONT, thread_id);
}

int gdbr_send_command(libgdbr_t *g, char *command) {
	int ret;
	char *cmd;
	if (!g || !command) {
		return -1;
	}
	cmd = calloc ((strlen (command) * 2 + strlen (CMD_QRCMD) + 2), sizeof (char));
	if (!cmd) {
		return -1;
	}
	strcpy (cmd, CMD_QRCMD);
	pack_hex (command, strlen (command), (cmd + strlen (CMD_QRCMD)));
	ret = send_command (g, cmd);
	free (cmd);
	if (ret < 0) {
		return ret;
	}

	if (read_packet (g) >= 0) {
		return handle_cmd (g);
	}
	return -1;
}

int gdbr_write_bin_registers(libgdbr_t *g){
	if (!g) {
		return -1;
	}
	uint64_t buffer_size = g->data_len * 2 + 8;
	char *command = calloc (buffer_size, sizeof (char));
	if (!command) {
		return -1;
	}
	snprintf (command, buffer_size, "%s", CMD_WRITEREGS);
	pack_hex (g->data, g->data_len, command + 1);
	if (send_command (g, command) < 0) {
		free (command);
		return -1;
	}
	read_packet (g);
	free (command);
	handle_G (g);
	return 0;
}

int gdbr_write_register(libgdbr_t *g, int index, char *value, int len) {
	int ret;
	char command[255] = { 0 };
	if (!g) {
		return -1;
	}
	ret = snprintf (command, 255, "%s%d=", CMD_WRITEREG, index);
	memcpy (command + ret, value, len);
	pack_hex (value, len, (command + ret));
	if (send_command (g, command) < 0) {
		return -1;
	}
	if (read_packet (g) >= 0) {
		handle_P (g);
	}
	return 0;
}

int gdbr_write_reg(libgdbr_t *g, const char *name, char *value, int len) {
	// static variable that keeps the information if writing
	// register through packet <P> was possible
	static int P = 1;
	int i = 0;
	if (!g) {
		return -1;
	}
	while (g->registers[i].size > 0) {
		if (!strcmp (g->registers[i].name, name)) {
			break;
		}
		i++;
	}
	if (g->registers[i].size == 0) {
		eprintf ("Error registername <%s> not found in profile\n", name);
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

int gdbr_write_registers(libgdbr_t *g, char *registers) {
	uint64_t buffer_size;
	int ret, i = 0;
	unsigned int x, len;
	char *command, *reg, *buff;
	// read current register set

	if (!g) {
		return -1;
	}
	gdbr_read_registers (g);
	len = strlen (registers);
	buff = calloc (len, sizeof (char));
	if (!buff) {
		return -1;
	}
	memcpy (buff, registers, len);
	reg = strtok (buff, ",");
	while (reg != NULL) {
		char *name_end = strchr (reg, '=');
		if (name_end == NULL) {
			eprintf ("Malformed argument: %s\n", reg);
			free (buff);
			return -1;
		}
		*name_end = '\0'; // change '=' to '\0'

		// time to find the current register
		while (g->registers[i].size > 0) {
			if (strcmp (g->registers[i].name, reg) == 0) {
				const ut64 register_size = g->registers[i].size;
				const ut64 offset = g->registers[i].offset;
				char *value = calloc (register_size + 1, 2);
				if (!value) {
					free (buff);
					return -1;
				}

				memset (value, '0', register_size * 2);
				name_end++;
				// be able to take hex with and without 0x
				if (name_end[1] == 'x' || name_end[1] == 'X') {
					name_end += 2;
				}
				const int val_len = strlen (name_end); // size of the rest
				strcpy (value + (register_size * 2 - val_len), name_end);

				for (x = 0; x < register_size; x++) {
					g->data[offset + register_size - x - 1] = hex2char (&value[x * 2]);
				}
				free (value);
			}
			i++;
		}
		reg = strtok (NULL, " ,");
	}

	free (buff);

	buffer_size = g->data_len * 2 + 8;
	command = calloc (buffer_size, sizeof(char));
	if (!command) {
		return -1;
	}
	snprintf (command, buffer_size, "%s", CMD_WRITEREGS);
	pack_hex (g->data, g->data_len, command + 1);
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

int test_command(libgdbr_t *g, const char *command) {
	int ret = send_command (g, command);
	if (ret < 0) {
		return ret;
	}
	read_packet (g);
	hexdump (g->read_buff, g->data_len, 0);
	return 0;
}

int send_vcont(libgdbr_t *g, const char *command, int thread_id) {
	char tmp[255] = {0};
	int ret;
	if (!g) {
		return -1;
	}
	if (thread_id < 0) {
		ret = snprintf (tmp, sizeof (tmp) - 1, "%s", command);
	} else {
		ret = snprintf (tmp, sizeof (tmp) - 1, "%s;%s:%x", CMD_C, command, thread_id);
	}
	if (ret < 0) {
		return ret;
	}
	ret = send_command (g, tmp);
	if (ret < 0) {
		return ret;
	}
	if (read_packet (g) >= 0) {
		return handle_cont (g);
	}
	return 0;
}

int set_bp(libgdbr_t *g, ut64 address, const char *conditions, enum Breakpoint type) {
	char tmp[255] = {0};
	int ret = 0;
	if (!g) {
		return -1;
	}
	switch (type) {
	case BREAKPOINT:
		ret = snprintf (tmp, sizeof (tmp) - 1,
			"%s,%"PFMT64x ",1", CMD_BP, address);
		break;
	case HARDWARE_BREAKPOINT:
		ret = snprintf (tmp, sizeof (tmp) - 1,
			"%s,%"PFMT64x ",1", CMD_HBP, address);
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
	if (ret < 0) {
		return ret;
	}
	ret = send_command (g, tmp);
	if (ret < 0) {
		return ret;
	}

	if (read_packet (g) >= 0) {
		return handle_setbp (g);
	}
	return 0;
}

int gdbr_set_bp(libgdbr_t *g, ut64 address, const char *conditions) {
	return set_bp (g, address, conditions, BREAKPOINT);
}

int gdbr_set_hwbp(libgdbr_t *g, ut64 address, const char *conditions) {
	return set_bp (g, address, conditions, HARDWARE_BREAKPOINT);
}

int gdbr_remove_bp(libgdbr_t *g, ut64 address) {
	return remove_bp (g, address, BREAKPOINT);
}

int gdbr_remove_hwbp(libgdbr_t *g, ut64 address) {
	return remove_bp (g, address, HARDWARE_BREAKPOINT);
}

int remove_bp(libgdbr_t *g, ut64 address, enum Breakpoint type) {
	char tmp[255] = {0};
	int ret = 0;
	if (!g) {
		return -1;
	}
	switch (type) {
	case BREAKPOINT:
		ret = snprintf (tmp, sizeof (tmp) - 1, "%s,%"PFMT64x ",1", CMD_RBP, address);
		break;
	case HARDWARE_BREAKPOINT:
		ret = snprintf (tmp, sizeof (tmp) - 1, "%s,%"PFMT64x ",1", CMD_RHBP, address);
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
	if (ret < 0) {
		return ret;
	}
	ret = send_command (g, tmp);
	if (ret < 0) {
		return ret;
	}
	if (read_packet (g) >= 0) {
		return handle_removebp (g);
	}
	return 0;
}

int send_ack(libgdbr_t *g) {
	if (g) {
		g->send_buff[0] = '+';
		g->send_len = 1;
		send_packet (g);
		return 0;
	}
	return -1;
}

int send_command(libgdbr_t *g, const char *command) {
	uint8_t checksum;
	int ret;

	if (!g || !command) {
		return -1;
	}
	checksum = cmd_checksum (command);
	ret = snprintf (g->send_buff, g->send_max,
		"$%s#%.2x", command, checksum);
	if (ret >= 0) {
		g->send_len = ret;
		ret = send_packet (g);
		g->send_len = ret;
		return ret;
	}
	return -1;
}
