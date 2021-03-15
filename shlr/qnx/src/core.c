/* libqnxr - GPL - Copyright 2016 - defragger, madprogrammer, FSF Inc */

#include <errno.h>
#include <r_debug.h>
#include "libqnxr.h"
#include "core.h"
#include "signal.h"
#include "sigutil.h"
#include "packet.h"

#define MAX_TRAN_TRIES 3
#define HOST_QNX_PROTOVER_MAJOR 0
#define HOST_QNX_PROTOVER_MINOR 3

ptid_t null_ptid = {0, 0};

void nto_send_init (libqnxr_t *g, ut32 cmd, ut32 subcmd, ut32 chan);

ptid_t nto_parse_notify (libqnxr_t *g);
int nto_send_env (libqnxr_t *g, const char *env);
int nto_send_arg (libqnxr_t *g, const char *arg);
int nto_send (libqnxr_t *g, ut32 len, int report_errors);

static registers_t x86_32[] = {
	{"eax", 0, 4},
	{"ecx", 4, 4},
	{"edx", 8, 4},
	{"ebx", 12, 4},
	{"esp", 16, 4},
	{"ebp", 20, 4},
	{"esi", 24, 4},
	{"edi", 28, 4},
	{"eip", 32, 4},
	{"eflags", 36, 4},
	{"cs", 40, 4},
	{"ss", 44, 4},
#if 0
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
#endif
	{"", 0, 0}};

static registers_t arm32[] = {
	{"r0", 0, 4},
	{"r1", 4, 4},
	{"r2", 8, 4},
	{"r3", 12, 4},
	{"r4", 16, 4},
	{"r5", 20, 4},
	{"r6", 24, 4},
	{"r7", 28, 4},
	{"r8", 32, 4},
	{"r9", 36, 4},
	{"r10", 40, 4},
	{"r11", 44, 4},
	{"r12", 48, 4},
	{"sp", 52, 4},
	{"lr", 56, 4},
	{"pc", 60, 4},
	{"f0", 64, 12},
	{"f1", 76, 12},
	{"f2", 88, 12},
	{"f3", 100, 12},
	{"f4", 112, 12},
	{"f5", 124, 12},
	{"f6", 136, 12},
	{"f7", 148, 12},
	{"fps", 160, 12},
	{"cpsr", 172, 4},
	{"", 0, 0}};

int qnxr_init(libqnxr_t *g) {
	r_return_val_if_fail (g, -1);
	memset (g, 0, sizeof (libqnxr_t));
	g->send_len = 0;
	g->send_buff = (char *)calloc (DS_DATA_MAX_SIZE * 2, 1);
	if (!g->send_buff) {
		return -1;
	}
	g->read_buff = (char *)calloc (DS_DATA_MAX_SIZE * 2, 1);
	if (!g->read_buff) {
		R_FREE (g->send_buff);
		return -1;
	}
	g->registers = x86_32;
	return 0;
}

int qnxr_set_architecture(libqnxr_t *g, ut8 architecture) {
	if (!g) {
		return -1;
	}
	g->architecture = architecture;
	switch (architecture) {
	case ARCH_X86_32:
		g->registers = x86_32;
		break;
	case ARCH_ARM_32:
		g->registers = arm32;
		break;
	default:
		eprintf ("Error unknown architecture set\n");
	}
	return 0;
}

int qnxr_cleanup(libqnxr_t *g) {
	r_return_val_if_fail (g, -1);
	free (g->send_buff);
	g->send_len = 0;
	free (g->read_buff);
	return 0;
}

int qnxr_connect(libqnxr_t *g, const char *host, int port) {
	char tmp[255];
	int ret;
	if (!g || !host || g->connected) return -1;

	g->data_len = 0;
	g->read_len = 0;
	g->read_ptr = 0;
	g->sock = r_socket_new (0);
	g->connected = 0;
	g->mid = 0;


	memmove (g->host, host, strlen (host) + 1);
	g->port = port;

	ret = snprintf (tmp, sizeof (tmp) - 1, "%d", port);
	if (!ret) return -1;
	ret = r_socket_connect_tcp (g->sock, host, tmp, 200);
	if (!ret) return -1;
	g->connected = 1;

	qnxr_send_ch_reset (g);
	nto_send_init (g, DStMsg_connect, 0, SET_CHANNEL_DEBUG);
	g->tran.pkt.connect.major = HOST_QNX_PROTOVER_MAJOR;
	g->tran.pkt.connect.minor = HOST_QNX_PROTOVER_MINOR;
	nto_send (g, sizeof (g->tran.pkt.connect), 0);

	if (g->recv.pkt.hdr.cmd == DSrMsg_err) {
		eprintf ("%s: connection failed: %lld\n", __func__,
			 EXTRACT_SIGNED_INTEGER (&g->recv.pkt.err.err, 4));
		return -1;
	}

	/* Try to query pdebug for their version of the protocol */
	nto_send_init (g, DStMsg_protover, 0, SET_CHANNEL_DEBUG);
	g->tran.pkt.protover.major = HOST_QNX_PROTOVER_MAJOR;
	g->tran.pkt.protover.minor = HOST_QNX_PROTOVER_MINOR;
	nto_send (g, sizeof (g->tran.pkt.protover), 0);

	if ((g->recv.pkt.hdr.cmd == DSrMsg_err) && (EXTRACT_SIGNED_INTEGER (&g->recv.pkt.err.err, 4) == EINVAL)) {
		g->target_proto_major = 0;
		g->target_proto_minor = 0;
	} else if (g->recv.pkt.hdr.cmd == DSrMsg_okstatus) {
		g->target_proto_major = EXTRACT_SIGNED_INTEGER (&g->recv.pkt.okstatus.status, 4);
		g->target_proto_minor = EXTRACT_SIGNED_INTEGER (&g->recv.pkt.okstatus.status, 4);
		g->target_proto_major = (g->target_proto_major >> 8) & DSMSG_PROTOVER_MAJOR;
		g->target_proto_minor = g->target_proto_minor & DSMSG_PROTOVER_MINOR;
	} else {
		eprintf ("Connection failed (Protocol Version Query): %lld\n",
			 EXTRACT_SIGNED_INTEGER (&g->recv.pkt.err.err, 4));
		return -1;
	}

	return 0;
}

int qnxr_disconnect(libqnxr_t *g) {
	r_return_val_if_fail (g, -1);

	if (g->connected) {
		nto_send_init (g, DStMsg_disconnect, 0, SET_CHANNEL_DEBUG);
		nto_send (g, sizeof (g->tran.pkt.disconnect), 0);
		g->connected = 0;
		g->inferior_ptid = null_ptid;

		if (!r_socket_close (g->sock))
			return -1;
	}

	return 0;
}

ptid_t qnxr_attach (libqnxr_t *g, pid_t pid) {
	r_return_val_if_fail (g, null_ptid);

	if (g->inferior_ptid.pid != pid) {
		qnxr_disconnect (g);
		r_sys_sleep (1);
		qnxr_connect (g, g->host, g->port);
	}

	nto_send_init (g, DStMsg_attach, 0, SET_CHANNEL_DEBUG);
	g->tran.pkt.attach.pid = pid;
	g->tran.pkt.attach.pid = EXTRACT_SIGNED_INTEGER (&g->tran.pkt.attach.pid, 4);

	nto_send (g, sizeof (g->tran.pkt.attach), 0);
	if (g->recv.pkt.hdr.cmd != DSrMsg_okdata) {
		eprintf ("%s: failed to attach to %d\n", __func__, pid);
		return null_ptid;
	}

	g->inferior_ptid = ptid_build (
		EXTRACT_SIGNED_INTEGER (&g->recv.pkt.notify.pid, 4),
		EXTRACT_SIGNED_INTEGER (&g->recv.pkt.notify.tid, 4));

	return g->inferior_ptid;
}

ptid_t qnxr_run (libqnxr_t *g, const char *file, char **args, char **env) {
	ut32 argc = 0;
	ut32 envc = 0;

	char **argv, *p;
	int errors = 0;

	r_return_val_if_fail (g, null_ptid);

	nto_send_init (g, DStMsg_env, DSMSG_ENV_CLEARENV, SET_CHANNEL_DEBUG);
	nto_send (g, sizeof (DStMsg_env_t), 1);

	for (envc = 0; *env; env++, envc++)
		errors += !nto_send_env (g, *env);

	if (errors) {
		eprintf ("%s: error(s) occurred while sending environment\n", __func__);
	}

	nto_send_init (g, DStMsg_env, DSMSG_ENV_CLEARARGV, SET_CHANNEL_DEBUG);
	nto_send (g, sizeof (DStMsg_env_t), 1);

	if (file != NULL) {
		errors = !nto_send_arg (g, file);
		if (!errors)
			errors = !nto_send_arg (g, file);

		if (errors) {
			eprintf ("%s: failed to send executable file name\n", __func__);
			return null_ptid;
		}

		errors = 0;
		for (argv = args; *argv && **argv; argv++, argc++)
			errors |= !nto_send_arg (g, *argv);

		if (errors) {
			eprintf ("%s: error(s) occurred while sending args\n", __func__);
		}
	}

	if (errors) {
		return null_ptid;
	}

	nto_send_init (g, DStMsg_load, DSMSG_LOAD_DEBUG, SET_CHANNEL_DEBUG);
	p = g->tran.pkt.load.cmdline;

	g->tran.pkt.load.envc = 0;
	g->tran.pkt.load.argc = 0;

	if (file) {
		strncpy (p, file, sizeof (g->tran.pkt.load.cmdline) - 8);
		p += strlen (p);
	}
	*p++ = '\0';

	*p++ = '\0'; // stdin
	*p++ = '\0'; // stdout
	*p++ = '\0'; // stderr

	nto_send (g, offsetof (DStMsg_load_t, cmdline) + p - g->tran.pkt.load.cmdline + 1, 1);

	if (g->recv.pkt.hdr.cmd == DSrMsg_okdata) {
		ptid_t ptid = nto_parse_notify (g);
		eprintf ("%s: inferior pid: %d\n", __func__, ptid.pid);
		g->inferior_ptid = ptid;

		return ptid;
	}

	return null_ptid;
}

int qnxr_read_registers(libqnxr_t *g) {
	int i = 0;
	int len, rlen, regset;
	int n = 0;
	ut32 off;
	char buf[DS_DATA_MAX_SIZE];

	if (!g) return -1;

	while (g->registers[i].size > 0) {
		regset = i386nto_regset_id (i);
		len = i386nto_register_area (i, regset, &off);
		if (len < 1) {
			eprintf ("%s: unknown register %d\n", __func__, i);
			len = g->registers[i].size;
		}
		nto_send_init (g, DStMsg_regrd, regset, SET_CHANNEL_DEBUG);
		g->tran.pkt.regrd.offset = EXTRACT_SIGNED_INTEGER (&off, 2);
		g->tran.pkt.regrd.size = EXTRACT_SIGNED_INTEGER (&len, 2);
		rlen = nto_send (g, sizeof (g->tran.pkt.regrd), 1);

		if (rlen > 0) {
			if (g->recv.pkt.hdr.cmd == DSrMsg_okdata) {
				memcpy (buf + g->registers[i].offset,
					g->recv.pkt.okdata.data, len);
				n += len;
			} else {
				memset (buf + g->registers[i].offset,
					0, len);
			}
		} else {
			eprintf ("%s: couldn't read register %d\n", __func__, i);
			return -1;
		}
		i++;
	}

	memcpy (g->recv.data, buf, n);
	return n;
}

int qnxr_read_memory (libqnxr_t *g, ut64 address, ut8 *data, ut64 len) {
	int rcv_len, tot_len, ask_len;
	ut64 addr;

	if (!g || !data) return -1;

	tot_len = rcv_len = ask_len = 0;

	do {
		nto_send_init (g, DStMsg_memrd, 0, SET_CHANNEL_DEBUG);
		addr = address + tot_len;
		g->tran.pkt.memrd.addr = EXTRACT_UNSIGNED_INTEGER (&addr, 8);
		ask_len = ((len - tot_len) > DS_DATA_MAX_SIZE) ?
				  DS_DATA_MAX_SIZE :
				  (len - tot_len);

		g->tran.pkt.memrd.size = EXTRACT_SIGNED_INTEGER (&ask_len, 2);
		rcv_len = nto_send (g, sizeof (g->tran.pkt.memrd), 0) -
			  sizeof (g->recv.pkt.hdr);
		if (rcv_len <= 0) break;
		if (g->recv.pkt.hdr.cmd == DSrMsg_okdata) {
			memcpy (data + tot_len, g->recv.pkt.okdata.data, rcv_len);
			tot_len += rcv_len;
		} else
			break;
	} while (tot_len != len);

	return tot_len;
}

int qnxr_write_memory (libqnxr_t *g, ut64 address, const ut8 *data, ut64 len) {
	ut64 addr;

	if (!g || !data) return -1;

	nto_send_init (g, DStMsg_memwr, 0, SET_CHANNEL_DEBUG);
	addr = address;
	g->tran.pkt.memwr.addr = EXTRACT_UNSIGNED_INTEGER (&addr, 8);
	memcpy (g->tran.pkt.memwr.data, data, len);
	nto_send (g, offsetof (DStMsg_memwr_t, data) + len, 0);

	switch (g->recv.pkt.hdr.cmd) {
	case DSrMsg_ok:
		return len;
	case DSrMsg_okstatus:
		return EXTRACT_SIGNED_INTEGER (&g->recv.pkt.okstatus.status, 4);
	}

	return 0;
}

void qnxr_pidlist (libqnxr_t *g, void *ctx, pidlist_cb_t *cb) {
	struct dspidlist *pidlist = (void *)g->recv.pkt.okdata.data;
	pid_t pid, start_tid;
	char subcmd;

	if (!g) return;

	start_tid = 1;
	pid = 1;
	subcmd = DSMSG_PIDLIST_BEGIN;

	while (1) {
		nto_send_init (g, DStMsg_pidlist, subcmd, SET_CHANNEL_DEBUG);
		g->tran.pkt.pidlist.pid = EXTRACT_SIGNED_INTEGER (&pid, 4);
		g->tran.pkt.pidlist.tid = EXTRACT_SIGNED_INTEGER (&start_tid, 4);
		nto_send (g, sizeof (g->tran.pkt.pidlist), 0);

		if (g->recv.pkt.hdr.cmd == DSrMsg_err || g->recv.pkt.hdr.cmd != DSrMsg_okdata)
			return;

		pid = EXTRACT_SIGNED_INTEGER (&pidlist->pid, 4);
		if (cb != NULL)
			cb (ctx, pid, pidlist->name);
		subcmd = DSMSG_PIDLIST_NEXT;
	}
}

int qnxr_select (libqnxr_t *g, pid_t pid, int tid) {
	if (!g) return 0;

	/* TODO */
	tid = 1;

	nto_send_init (g, DStMsg_select, DSMSG_SELECT_SET, SET_CHANNEL_DEBUG);
	g->tran.pkt.select.pid = pid;
	g->tran.pkt.select.pid = EXTRACT_SIGNED_INTEGER (&g->tran.pkt.select.pid, 4);
	g->tran.pkt.select.tid = EXTRACT_SIGNED_INTEGER (&tid, 4);
	nto_send (g, sizeof (g->tran.pkt.select), 1);

	if (g->recv.pkt.hdr.cmd == DSrMsg_err) {
		eprintf ("%s: failed to select %d\n", __func__, pid);
		return 0;
	}

	return 1;
}

int qnxr_step (libqnxr_t *g, int thread_id) {
	return qnxr_send_vcont (g, 1, thread_id);
}

int qnxr_continue (libqnxr_t *g, int thread_id) {
	return qnxr_send_vcont (g, 0, thread_id);
}

int qnxr_write_register (libqnxr_t *g, int index, char *value, int len) {
	int tdep_len, regset;
	ut32 off;

	if (!g) return -1;

	regset = i386nto_regset_id (index);
	tdep_len = i386nto_register_area (index, regset, &off);
	if (len < 0 || tdep_len != len) {
		eprintf ("%s: invalid length\n", __func__);
		return -1;
	}

	nto_send_init (g, DStMsg_regwr, regset, SET_CHANNEL_DEBUG);
	g->tran.pkt.regwr.offset = EXTRACT_SIGNED_INTEGER (&off, 2);
	memcpy (g->tran.pkt.regwr.data, value, len);
	nto_send (g, offsetof (DStMsg_regwr_t, data) + len, 1);

	return 0;
}

int qnxr_write_reg (libqnxr_t *g, const char *name, char *value, int len) {
	int i = 0;

	if (!g) return -1;

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
	qnxr_write_register (g, i, value, len);

	return 0;
}

int qnxr_send_vcont (libqnxr_t *g, int step, int thread_id) {
	if (!g) return -1;

	nto_send_init (g, DStMsg_run, step ? DSMSG_RUN_COUNT : DSMSG_RUN,
		       SET_CHANNEL_DEBUG);
	g->tran.pkt.run.step.count = 1;
	nto_send (g, sizeof (g->tran.pkt.run), 1);
	return 0;
}

int qnxr_stop (libqnxr_t *g) {
	if (!g) return 0;

	eprintf ("%s: waiting for stop\n", __func__);
	g->waiting_for_stop = 1;
	nto_send_init (g, DStMsg_stop, DSMSG_STOP_PIDS, SET_CHANNEL_DEBUG);

	g->send_len = sizeof (g->tran.pkt.stop);
	qnxr_send_packet (g);

	return 1;
}

ptid_t qnxr_wait (libqnxr_t *g, pid_t pid) {
	if (!g || pid < 0) {
		return null_ptid;
	}
	ptid_t returned_ptid = g->inferior_ptid;
	if (g->inferior_ptid.pid != pid) {
		return null_ptid;
	}
	if (g->recv.pkt.hdr.cmd != DShMsg_notify) {
		int rlen;
		char waiting_for_notify = 1;

		eprintf ("%s: waiting for inferior\n", __func__);

		while (1) {
			rlen = qnxr_read_packet (g);
			if (rlen == -1) {
				if (g->waiting_for_stop) {
					eprintf ("%s: read eror while waiting for stop\n",
						 __func__);
					continue;
				} else {
					eprintf ("%s: read packet error or NAK\n", __func__);
					return null_ptid;
				}
			}
			if (g->channelrd == SET_CHANNEL_TEXT) {
				// TODO nto_incoming_text
			} else {
				g->recv.pkt.hdr.cmd &= ~DSHDR_MSG_BIG_ENDIAN;
				if (g->waiting_for_stop && g->recv.pkt.hdr.cmd == DSrMsg_ok) {
					g->waiting_for_stop = 0;
					eprintf ("%s: got stop response\n", __func__);
					if (!waiting_for_notify)
						break;
				} else if (g->recv.pkt.hdr.cmd == DShMsg_notify) {
					// acknowledge the notify
					g->tran.pkt.hdr.cmd = DSrMsg_ok;
					g->tran.pkt.hdr.channel = SET_CHANNEL_DEBUG;
					g->tran.pkt.hdr.mid = g->recv.pkt.hdr.mid;
					qnxr_send_ch_debug (g);

					g->send_len = sizeof (g->tran.pkt.ok);
					qnxr_send_packet (g);

					returned_ptid = nto_parse_notify (g);
					break;
				}
			}
		}
	}

	/* to make us wait the next time */
	g->recv.pkt.hdr.cmd = DSrMsg_ok;
	return returned_ptid;
}

int qnxr_set_bp (libqnxr_t *g, ut64 address, const char *conditions) {
	return _qnxr_set_bp (g, address, conditions, BREAKPOINT);
}

int qnxr_set_hwbp (libqnxr_t *g, ut64 address, const char *conditions) {
	return _qnxr_set_bp (g, address, conditions, HARDWARE_BREAKPOINT);
}

int qnxr_remove_bp (libqnxr_t *g, ut64 address) {
	return _qnxr_remove_bp (g, address, BREAKPOINT);
}

int qnxr_remove_hwbp (libqnxr_t *g, ut64 address) {
	return _qnxr_remove_bp (g, address, HARDWARE_BREAKPOINT);
}

int _qnxr_set_bp (libqnxr_t *g, ut64 address, const char *conditions, enum Breakpoint type) {
	if (!g) return -1;

	nto_send_init (g, DStMsg_brk, DSMSG_BRK_EXEC, SET_CHANNEL_DEBUG);
	g->tran.pkt.brk.addr = EXTRACT_UNSIGNED_INTEGER (&address, 4);
	g->tran.pkt.brk.size = 0;
	nto_send (g, sizeof (g->tran.pkt.brk), 0);

	if (g->recv.pkt.hdr.cmd == DSrMsg_err)
		return -1;
	return 0;
}

int _qnxr_remove_bp (libqnxr_t *g, ut64 address, enum Breakpoint type) {
	if (!g) return -1;

	nto_send_init (g, DStMsg_brk, DSMSG_BRK_EXEC, SET_CHANNEL_DEBUG);
	g->tran.pkt.brk.addr = EXTRACT_UNSIGNED_INTEGER (&address, 4);
	g->tran.pkt.brk.size = -1;
	nto_send (g, sizeof (g->tran.pkt.brk), 0);

	if (g->recv.pkt.hdr.cmd == DSrMsg_err)
		return -1;
	return 0;
}

void nto_send_init (libqnxr_t *g, ut32 cmd, ut32 subcmd, ut32 chan) {
	g->tran.pkt.hdr.cmd = cmd;
	g->tran.pkt.hdr.subcmd = subcmd;
	g->tran.pkt.hdr.mid = ((chan == SET_CHANNEL_DEBUG) ? g->mid++ : 0);
	g->tran.pkt.hdr.channel = chan;
}

ptid_t nto_parse_notify (libqnxr_t *g) {
	pid_t pid, tid;

	pid = EXTRACT_SIGNED_INTEGER (&g->recv.pkt.notify.pid, 4);
	tid = EXTRACT_SIGNED_INTEGER (&g->recv.pkt.notify.tid, 4);

	if (tid == 0) tid = 1;
	eprintf ("%s: parse notify %d\n", __func__, g->recv.pkt.hdr.subcmd);

	switch (g->recv.pkt.hdr.subcmd) {
	case DSMSG_NOTIFY_PIDUNLOAD:
		g->notify_type = R_DEBUG_REASON_DEAD;
		break;
	case DSMSG_NOTIFY_BRK:
		g->stop_flags = EXTRACT_UNSIGNED_INTEGER (&g->recv.pkt.notify.un.brk.flags, 4);
		g->stop_pc = EXTRACT_UNSIGNED_INTEGER (&g->recv.pkt.notify.un.brk.ip, 4);
		g->notify_type = R_DEBUG_REASON_BREAKPOINT;
		break;
	case DSMSG_NOTIFY_STEP:
		g->notify_type = R_DEBUG_REASON_STEP;
		break;
	case DSMSG_NOTIFY_SIGEV:
		g->notify_type = R_DEBUG_REASON_SIGNAL;
		g->signal = host_signal_from_nto (EXTRACT_SIGNED_INTEGER (&g->recv.pkt.notify.un.sigev.signo, 4));
		break;
	case DSMSG_NOTIFY_PIDLOAD:
		eprintf ("%s: notify type DSMSG_NOTIFY_PIDLOAD\n", __func__);
		g->notify_type = R_DEBUG_REASON_UNKNOWN;
		break;
	case DSMSG_NOTIFY_DLLLOAD:
	case DSMSG_NOTIFY_TIDLOAD:
	case DSMSG_NOTIFY_TIDUNLOAD:
	case DSMSG_NOTIFY_DLLUNLOAD:
		eprintf ("%s: notify type DSMSG_NOTIFY_DLLTID\n", __func__);
		g->notify_type = R_DEBUG_REASON_UNKNOWN;
		break;
	case DSMSG_NOTIFY_STOPPED:
		g->notify_type = R_DEBUG_REASON_SWI;
		break;
	default:
		eprintf ("%s: Unexpected notify type %d\n", __func__,
			 g->recv.pkt.hdr.subcmd);
		g->notify_type = R_DEBUG_REASON_UNKNOWN;
	}

	return ptid_build (pid, tid);
}

int nto_send_env (libqnxr_t *g, const char *env) {
	int len; /* Length including zero terminating char.  */
	int totlen = 0;

	if (!g) return 0;

	len = strlen (env) + 1;
	if (g->target_proto_minor >= 2) {
		while (len > DS_DATA_MAX_SIZE) {
			nto_send_init (g, DStMsg_env, DSMSG_ENV_SETENV_MORE,
				       SET_CHANNEL_DEBUG);
			memcpy (g->tran.pkt.env.data, env + totlen,
				DS_DATA_MAX_SIZE);
			if (!nto_send (g, offsetof (DStMsg_env_t, data) +
						  DS_DATA_MAX_SIZE,
				       1)) {
				/* An error occurred.  */
				return 0;
			}
			len -= DS_DATA_MAX_SIZE;
			totlen += DS_DATA_MAX_SIZE;
		}
	} else if (len > DS_DATA_MAX_SIZE) {
		/* Not supported by this protocol version.  */
		eprintf ("Protovers < 0.2 do not handle env vars longer than %d\n",
			 DS_DATA_MAX_SIZE - 1);
		return 0;
	}
	nto_send_init (g, DStMsg_env, DSMSG_ENV_SETENV, SET_CHANNEL_DEBUG);
	memcpy (g->tran.pkt.env.data, env + totlen, len);
	return nto_send (g, offsetof (DStMsg_env_t, data) + len, 1);
}

int nto_send_arg (libqnxr_t *g, const char *arg) {
	int len;

	if (!g) return 0;

	len = strlen (arg) + 1;
	if (len > DS_DATA_MAX_SIZE - 4) {
		eprintf ("Argument too long: %.40s...\n", arg);
		return 0;
	}
	nto_send_init (g, DStMsg_env, DSMSG_ENV_ADDARG, SET_CHANNEL_DEBUG);
	memcpy (g->tran.pkt.env.data, arg, len);
	return nto_send (g, offsetof (DStMsg_env_t, data) + len, 1);
}

int nto_send (libqnxr_t *g, ut32 len, st32 report_errors) {
	int rlen;
	ut8 tries = 0;

	if (!g || g->connected == 0) {
		return -1;
	}
	g->send_len = len;
	for (tries = 0;; tries++) {
		if (tries >= MAX_TRAN_TRIES) {
			eprintf ("%s: Remote exhausted %d retries.\n", __func__, tries);
			return -1;
		}
		qnxr_send_packet (g);
		for (;;) {
			rlen = qnxr_read_packet (g);
			if ((g->channelrd != SET_CHANNEL_TEXT) || (rlen == -1))
				break;
			//nto_incoming_text (rlen); TODO
		}
		if (rlen == -1) {
			eprintf ("%s: NAK received - resending\n", __func__);
			continue;
		}
		if ((rlen >= 0) && (g->recv.pkt.hdr.mid == g->tran.pkt.hdr.mid))
			break;
		eprintf ("%s: mid mismatch: %d/%d\n", __func__, g->recv.pkt.hdr.mid,
			 g->tran.pkt.hdr.mid);
	}

	switch (g->channelrd) {
	case SET_CHANNEL_DEBUG:
		g->recv.pkt.hdr.cmd &= ~DSHDR_MSG_BIG_ENDIAN;
		if (g->recv.pkt.hdr.cmd == DSrMsg_err) {
			if (report_errors) {
				int nerrno = errnoconvert (
					EXTRACT_SIGNED_INTEGER (&g->recv.pkt.err.err, 4));
				switch (g->recv.pkt.hdr.subcmd) {
				case PDEBUG_ENOERR:
					eprintf ("remote: error packet with errno %d\n", nerrno);
					break;
				case PDEBUG_ENOPTY:
					eprintf ("remote: no ptys available\n");
					break;
				case PDEBUG_ETHREAD:
					eprintf ("remote: thread start error\n");
					break;
				case PDEBUG_ECONINV:
					eprintf ("remote: invalid console number\n");
					break;
				case PDEBUG_ESPAWN:
					eprintf ("Remote (spawn error)\n");
					break;
				case PDEBUG_EPROCFS:
					eprintf ("Remote (procfs [/proc] error)\n");
					break;
				case PDEBUG_EPROCSTOP:
					eprintf ("Remote (devctl PROC_STOP error)\n");
					break;
				case PDEBUG_EQPSINFO:
					eprintf ("Remote (psinfo error)\n");
					break;
				case PDEBUG_EQMEMMODEL:
					eprintf ("Remote (invalid memory model [not flat])\n");
					break;
				case PDEBUG_EQPROXY:
					eprintf ("Remote (proxy error)\n");
					break;
				case PDEBUG_EQDBG:
					eprintf ("Remote (__nto_debug_* error)\n");
					break;
				default:
					eprintf ("Remote error\n");
				}
			}
		}
		break;
	case SET_CHANNEL_TEXT:
	case SET_CHANNEL_RESET:
		break;
	}
	return rlen;
}
