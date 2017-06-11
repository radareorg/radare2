/* libgdbr - LGPL - Copyright 2014-2017 - defragger */

#include "gdbclient/responses.h"
#include "gdbclient/commands.h"
#include "gdbclient/core.h"
#include "arch.h"
#include "libgdbr.h"
#include "gdbr_common.h"
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
	// Initial max_packet_size for remote target (minimum so far for AVR = 16)
	g->stub_features.pkt_sz = 16;
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
	ret = send_msg (g, message);
	if (ret < 0) {
		return ret;
	}
	read_packet (g);
	ret = handle_qSupported (g);
	if (ret < 0) {
		return ret;
	}
	// Query the thread / process id
	g->stub_features.qC = true;
	g->pid = g->tid = 0;
	ret = send_msg (g, "qC");
	if (ret < 0) {
		return ret;
	}
	read_packet (g);
	ret = handle_qC (g);
	if (ret < 0) {
		g->stub_features.qC = false;
	}
	// Set pid/thread for operations other than "step" and "continue"
	if (g->stub_features.multiprocess) {
		snprintf (tmp.buf, sizeof (tmp.buf) - 1, "Hgp%x.%x", (ut32) g->pid, (ut32) g->tid);
	} else {
		snprintf (tmp.buf, sizeof (tmp.buf) - 1, "Hg%x", (ut32) g->tid);
	}
	ret = send_msg (g, tmp.buf);
	if (ret < 0) {
		return ret;
	}
	read_packet (g);
	ret = send_ack (g);
	if (strncmp (g->data, "OK", 2)) {
		// return -1;
	}
	// Set thread for "step" and "continue" operations
	snprintf (tmp.buf, sizeof (tmp.buf) - 1, "Hc-1");
	ret = send_msg (g, tmp.buf);
	if (ret < 0) {
		return ret;
	}
	read_packet (g);
	ret = send_ack (g);
	if (strncmp (g->data, "OK", 2)) {
		// return -1;
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

bool gdbr_kill(libgdbr_t *g) {
	char buf[20];
	int ret;
	if (!g || !g->sock) {
		return false;
	}
	if (g->stub_features.multiprocess) {
		if (!g->pid) {
			return false;
		}
		snprintf (buf, sizeof (buf) - 1, "vKill;%x", g->pid);
	} else {
		snprintf (buf, sizeof (buf) - 1, "k");
	}
	if ((ret = send_msg (g, buf)) < 0) {
		return false;
	}
	if (!g->stub_features.multiprocess) {
		return true;
	}
	read_packet (g);
	if ((ret = send_ack (g)) < 0) {
		return false;
	}
	if (strncmp (g->data, "OK", 2)) {
		return false;
	}
	return true;
}

int gdbr_read_registers(libgdbr_t *g) {
	int ret = -1;
	if (!g) {
		return -1;
	}
	ret = send_msg (g, CMD_READREGS);
	if (ret < 0) {
		return ret;
	}

	if (read_packet (g) >= 0) {
		return handle_g (g);
	}
	return -1;
}

int gdbr_read_memory(libgdbr_t *g, ut64 address, ut64 len) {
	char command[64] = {0};
	int ret;
	ut64 num_pkts, last, data_sz, ret_len;
	int pkt;
	if (!g) {
		return -1;
	}
	if (len > g->data_max) {
		eprintf ("%s: Requested read too long: (%d bytes)\n", __func__, (unsigned) len);
		return -1;
	}
	data_sz = g->stub_features.pkt_sz / 2;
	num_pkts = len / data_sz;
	last = len % data_sz;
	ret_len = 0;
	ret = 0;
	if (last) {
		if ((ret = snprintf (command, sizeof (command) - 1,
				     "%s%016"PFMT64x ",%"PFMT64d, CMD_READMEM,
				     address + (num_pkts * data_sz),
				     last)) < 0) {
			return -1;
		}
		if ((ret = send_msg (g, command)) < 0) {
			return -1;
		}
		if ((ret = read_packet (g)) < 0) {
			return -1;
		}
		if ((ret = handle_m (g)) < 0) {
			return -1;
		}
		if (num_pkts) {
			memmove (g->data + (num_pkts * data_sz), g->data, g->data_len);
		}
		ret_len += g->data_len;
	}
	for (pkt = num_pkts - 1; pkt >= 0; pkt--) {
		if ((ret = snprintf (command, sizeof (command) - 1,
				     "%s%016"PFMT64x ",%"PFMT64d, CMD_READMEM,
				     address + (pkt * data_sz),
				     data_sz)) < 0) {
			return -1;
		}
		if ((ret = send_msg (g, command)) < 0) {
			return -1;
		}
		if ((ret = read_packet (g)) < 0) {
			return -1;
		}
		if ((ret = handle_m (g)) < 0) {
			return -1;
		}
		if (pkt) {
			memmove (g->data + (pkt * data_sz), g->data, g->data_len);
		}
		ret_len += g->data_len;
        }
	g->data_len = ret_len;
	return ret;
}

int gdbr_write_memory(libgdbr_t *g, ut64 address, const uint8_t *data, ut64 len) {
	int ret = 0;
	int command_len, pkt, max_cmd_len = 64;
	ut64 num_pkts, last, data_sz;
	char *tmp;
	if (!g || !data) {
		return -1;
	}
	data_sz = g->stub_features.pkt_sz / 2;
	num_pkts = len / data_sz;
	last = len % data_sz;
	if (!(tmp = calloc (max_cmd_len + g->stub_features.pkt_sz, sizeof (char)))) {
		return -1;
	}
	for (pkt = num_pkts - 1; pkt >= 0; pkt--) {
		if ((command_len = snprintf (tmp, max_cmd_len,
					     "%s%016"PFMT64x ",%"PFMT64d ":", CMD_WRITEMEM,
					     address + (pkt * data_sz), data_sz)) < 0) {
			return -1;
		}
		pack_hex ((char *) data + (pkt * data_sz), data_sz, (tmp + command_len));
		if ((ret = send_msg (g, tmp)) < 0) {
			return -1;
		}
		if ((ret = read_packet (g)) < 0) {
			return -1;
		}
		if ((ret = handle_M (g)) < 0) {
			return -1;
		}
        }
	if (last) {
		if ((command_len = snprintf (tmp, max_cmd_len,
					     "%s%016"PFMT64x ",%"PFMT64d ":", CMD_WRITEMEM,
					     address + (num_pkts * data_sz), last)) < 0) {
			return -1;
		}
		pack_hex ((char *) data + (num_pkts * data_sz), last, (tmp + command_len));
		if ((ret = send_msg (g, tmp)) < 0) {
			return -1;
		}
		if ((ret = read_packet (g)) < 0) {
			return -1;
		}
		if ((ret = handle_M (g)) < 0) {
			return -1;
		}
	}
	free (tmp);
	return 0;
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
	ret = send_msg (g, cmd);
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
	if (send_msg (g, command) < 0) {
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
	if (send_msg (g, command) < 0) {
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
	ret = send_msg (g, command);
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
	int ret = send_msg (g, command);
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
	ret = send_msg (g, tmp);
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
	ret = send_msg (g, tmp);
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
	ret = send_msg (g, tmp);
	if (ret < 0) {
		return ret;
	}
	if (read_packet (g) >= 0) {
		return handle_removebp (g);
	}
	return 0;
}
