/* io_r2k - radare2 - LGPL - Copyright 2016-2024 - pancake, SkUaTeR, panda */

#ifndef __GNU__

#include "io_r2k_linux.h"

#define FSET(num, shift) ((((num) & (((ut64) 1) << (shift))) == 0) ? 0 : 1)

#if __i386__ || __x86_64__
static void append_ctrl_reg_details(RStrBuf *sb, struct r2k_control_reg ctrl) {
	r_strbuf_appendf (sb, "CR0: 0x%"PFMT64x"\n", (ut64) ctrl.cr0);
	r_strbuf_appendf (sb, " [*] PG:    %d\n"
		       " [*] CD:    %d\n"
		       " [*] NW:    %d\n"
		       " [*] AM:    %d\n"
		       " [*] WP:    %d\n"
		       " [*] NE:    %d\n"
		       " [*] ET:    %d\n"
		       " [*] TS:    %d\n"
		       " [*] EM:    %d\n"
		       " [*] MP:    %d\n"
		       " [*] PE:    %d\n",
		       FSET (ctrl.cr0, 31), FSET (ctrl.cr0, 30), FSET (ctrl.cr0, 29), FSET (ctrl.cr0, 18),
		       FSET (ctrl.cr0, 16), FSET (ctrl.cr0, 5), FSET (ctrl.cr0, 4), FSET (ctrl.cr0, 3),
		       FSET (ctrl.cr0, 2), FSET (ctrl.cr0, 1), FSET (ctrl.cr0, 1));
	r_strbuf_append (sb, "\n");

	r_strbuf_appendf (sb, "CR2: 0x%"PFMT64x"\n", (ut64) ctrl.cr2);
	r_strbuf_appendf (sb, "Page-Fault Linear Address: 0x%"PFMT64x"\n", (ut64) ctrl.cr2);
	r_strbuf_append (sb, "\n");

	r_strbuf_appendf (sb, "CR3: 0x%"PFMT64x"\n", (ut64) ctrl.cr3);
	r_strbuf_appendf (sb, " [*] Page-Directory Base:    0x%"PFMT64x"\n"
		       " [*] PCD:                    %d\n"
		       " [*] PWT:                    %d\n",
		       (((ut64) ctrl.cr3) & 0xfffffffffffff000), FSET (ctrl.cr3, 4), FSET (ctrl.cr3, 3));
	r_strbuf_append (sb, "\n");

	r_strbuf_appendf (sb, "CR4: 0x%"PFMT64x"\n", (ut64) ctrl.cr4);
	r_strbuf_appendf (sb, " [*] PKE:         %d\n"
		       " [*] SMAP:        %d\n"
		       " [*] SMEP:        %d\n"
		       " [*] OSXSAVE:     %d\n"
		       " [*] PCIDE:       %d\n"
		       " [*] FSGSBASE:    %d\n"
		       " [*] SMXE:        %d\n"
		       " [*] VMXE:        %d\n"
		       " [*] UMIP:        %d\n"
		       " [*] OSXMMEXCPT:  %d\n"
		       " [*] OSFXSR:      %d\n"
		       " [*] PCE:         %d\n"
		       " [*] PGE:         %d\n"
		       " [*] MCE:         %d\n"
		       " [*] PAE:         %d\n"
		       " [*] PSE:         %d\n"
		       " [*] DE:          %d\n"
		       " [*] TSD:         %d\n"
		       " [*] PVI:         %d\n"
		       " [*] VME:         %d\n",
		       FSET (ctrl.cr4, 22), FSET (ctrl.cr4, 21), FSET (ctrl.cr4, 20), FSET (ctrl.cr4, 18),
		       FSET (ctrl.cr4, 17), FSET (ctrl.cr4, 16), FSET (ctrl.cr4, 14), FSET (ctrl.cr4, 13),
		       FSET (ctrl.cr4, 11), FSET (ctrl.cr4, 10), FSET (ctrl.cr4, 9), FSET (ctrl.cr4, 8),
		       FSET (ctrl.cr4, 7), FSET (ctrl.cr4, 6), FSET (ctrl.cr4, 5), FSET (ctrl.cr4, 4),
		       FSET (ctrl.cr4, 3), FSET (ctrl.cr4, 2), FSET (ctrl.cr4, 1), FSET (ctrl.cr4, 0));
	r_strbuf_append (sb, "\n");

#if __x86_64__
	r_strbuf_appendf (sb, "CR8: 0x%"PFMT64x"\n", (ut64) ctrl.cr8);
	r_strbuf_appendf (sb, " [*] TPL:    %u\n", (ut32)(ctrl.cr8 & 0xf));
#endif
}

#elif __arm__
static void append_ctrl_reg_details(RStrBuf *sb, struct r2k_control_reg ctrl) {
	r_strbuf_appendf (sb, "TTBR0: 0x%"PFMT64x"\n", (ut64) ctrl.ttbr0);
	r_strbuf_appendf (sb, " [*] Translation table base 0:  0x%"PFMT64x"\n"
		       " [*] UNP/SBZ:                   0x%"PFMT64x"\n"
		       " [*] RGN:                       0x%"PFMT64x"\n"
		       " [*] P:                         %d\n"
		       " [*] S:                         %d\n"
		       " [*] C:                         %d\n",
		       (ut64) ((ctrl.ttbr0 & (0xffffffff << (14 - (ctrl.ttbcr & 7)))) >> (14 - (ctrl.ttbcr & 7))),
		       (ut64) ((ctrl.ttbr0 & ((1 << (13 - (ctrl.ttbcr & 7) + 1)) - (1 << 5))) >> 6),
		       (ut64) ((ctrl.ttbr0 & 0x18) >> 3), FSET (ctrl.ttbr0, 2), FSET (ctrl.ttbr0, 1), FSET (ctrl.ttbr0, 0));
	r_strbuf_append (sb, "\n");

	r_strbuf_appendf (sb, "TTBR1: 0x%"PFMT64x"\n", (ut64) ctrl.ttbr1);
	r_strbuf_appendf (sb, " [*] Translation table base 1:  0x%"PFMT64x"\n"
		       " [*] UNP/SBZ:                   0x%"PFMT64x"\n"
		       " [*] RGN:                       0x%"PFMT64x"\n"
		       " [*] P:                         %d\n"
		       " [*] S:                         %d\n"
		       " [*] C:                         %d\n",
		       (ut64) ((ctrl.ttbr1 & (0xffffffff << 14)) >> 14), (ut64) ((ctrl.ttbr1 & ((1 << (13 + 1)) - (1 << 5))) >> 6),
		       (ut64) ((ctrl.ttbr1 & 0x18) >> 3), FSET (ctrl.ttbr1, 2), FSET (ctrl.ttbr1, 1), FSET (ctrl.ttbr1, 0));
	r_strbuf_append (sb, "\n");

	r_strbuf_appendf (sb, "TTBCR: 0x%"PFMT64x"\n", (ut64) ctrl.ttbcr);
	r_strbuf_appendf (sb, " [*] N:    %d\n", ctrl.ttbcr & 7);
	r_strbuf_append (sb, "\n");

	r_strbuf_appendf (sb, "C1: 0x%"PFMT64x"\n", (ut64) ctrl.c1);
	r_strbuf_appendf (sb, " [*] AFE:    %d\n"
		       " [*] TRE:    %d\n"
		       " [*] EE:     %d\n"
		       " [*] VE:     %d\n"
		       " [*] XP:     %d\n"
		       " [*] U:      %d\n"
		       " [*] FI:     %d\n"
		       " [*] IT:     %d\n"
		       " [*] DT:     %d\n"
		       " [*] L4:     %d\n"
		       " [*] RR:     %d\n"
		       " [*] V:      %d\n"
		       " [*] I:      %d\n"
		       " [*] Z:      %d\n"
		       " [*] F:      %d\n"
		       " [*] R:      %d\n"
		       " [*] S:      %d\n"
		       " [*] B:      %d\n"
		       " [*] W:      %d\n"
		       " [*] C:      %d\n"
		       " [*] A:      %d\n"
		       " [*] M:      %d\n",
		       FSET (ctrl.c1, 29), FSET (ctrl.c1, 28), FSET (ctrl.c1, 25), FSET (ctrl.c1, 24),
		       FSET (ctrl.c1, 23), FSET (ctrl.c1, 22), FSET (ctrl.c1, 21), FSET (ctrl.c1, 18),
		       FSET (ctrl.c1, 16), FSET (ctrl.c1, 15), FSET (ctrl.c1, 14), FSET (ctrl.c1, 13),
		       FSET (ctrl.c1, 12), FSET (ctrl.c1, 11), FSET (ctrl.c1, 10), FSET (ctrl.c1, 9),
		       FSET (ctrl.c1, 8), FSET (ctrl.c1, 7), FSET (ctrl.c1, 3), FSET (ctrl.c1, 2),
		       FSET (ctrl.c1, 1), FSET (ctrl.c1, 0));
	r_strbuf_append (sb, "\n");

	r_strbuf_appendf (sb, "C3: 0x%"PFMT64x"\n", (ut64) ctrl.c3);
}

#elif __arm64__ || __aarch64__
/*ARM Cortex-A57 and ARM Cortex-A72. This might show some wrong values for other processor.*/
static void append_ctrl_reg_details(RStrBuf *sb, struct r2k_control_reg ctrl) {
	r_strbuf_appendf (sb, "SCTLR_EL1: 0x%"PFMTSZx"\n", ctrl.sctlr_el1);
	r_strbuf_appendf (sb, " [*] UCI:     %d\n"
		       " [*] EE:      %d\n"
		       " [*] E0E:     %d\n"
		       " [*] WXN:     %d\n"
		       " [*] nTWE:    %d\n"
		       " [*] nTWI:    %d\n"
		       " [*] UCT:     %d\n"
		       " [*] DZE:     %d\n"
		       " [*] I:       %d\n"
		       " [*] UMA:     %d\n"
		       " [*] SED:     %d\n"
		       " [*] ITD:     %d\n"
		       " [*] THEE:    %d\n"
		       " [*] CP15BEN: %d\n"
		       " [*] SAO:     %d\n"
		       " [*] SA:      %d\n"
		       " [*] C:       %d\n"
		       " [*] A:       %d\n"
		       " [*] M:       %d\n",
		       FSET (ctrl.sctlr_el1, 26), FSET (ctrl.sctlr_el1, 25), FSET (ctrl.sctlr_el1, 24), FSET (ctrl.sctlr_el1, 19),
		       FSET (ctrl.sctlr_el1, 18), FSET (ctrl.sctlr_el1, 16), FSET (ctrl.sctlr_el1, 15), FSET (ctrl.sctlr_el1, 14),
		       FSET (ctrl.sctlr_el1, 12), FSET (ctrl.sctlr_el1, 9), FSET (ctrl.sctlr_el1, 8), FSET (ctrl.sctlr_el1, 7),
		       FSET (ctrl.sctlr_el1, 6), FSET (ctrl.sctlr_el1, 5), FSET (ctrl.sctlr_el1, 4), FSET (ctrl.sctlr_el1, 3),
		       FSET (ctrl.sctlr_el1, 2), FSET (ctrl.sctlr_el1, 1), FSET (ctrl.sctlr_el1, 0));
	r_strbuf_append (sb, "\n");

	r_strbuf_appendf (sb, "TTBR0_EL1: 0x%"PFMTSZx"\n", ctrl.ttbr0_el1);
	r_strbuf_appendf (sb, " [*] ASID [63:48]:    0x%"PFMT64x"\n"
		       " [*] BADDR [47:10]:   0x%"PFMT64x"\n",
		       (ut64)(ctrl.ttbr0_el1 & 0xffff000000000000LLU) >> 48, (ctrl.ttbr0_el1 & ((((ut64) 1) << (47 + 1)) - (1 << 10))) >> 10);
	r_strbuf_append (sb, "\n");

	r_strbuf_appendf (sb, "TTBR1_EL1: 0x%"PFMTSZx"\n", ctrl.ttbr1_el1);
	r_strbuf_appendf (sb, " [*] ASID [63:48]:    0x%"PFMT64x"\n"
		       " [*] BADDR [47:10]:   0x%"PFMT64x"\n",
		       (ut64)(ctrl.ttbr1_el1 & 0xffff000000000000LLU) >> 48, (ctrl.ttbr1_el1 & ((((ut64) 1) << (47 + 1)) - (1 << 10))) >> 10);
	r_strbuf_append (sb, "\n");

	r_strbuf_appendf (sb, "TCR_EL1: 0x%"PFMTSZx"\n", ctrl.tcr_el1);
	r_strbuf_appendf (sb, " [*] TBI1:    %d\n"
		       " [*] TBI0:    %d\n"
		       " [*] AS:      %d\n"
		       " [*] IPS:     %d\n"
		       " [*] TG1:     %d\n"
		       " [*] SH1:     %d\n"
		       " [*] ORGN1:   %d\n"
		       " [*] IRGN1:   %d\n"
		       " [*] EPD1:    %d\n"
		       " [*] A1:      %d\n"
		       " [*] T1SZ:    %d\n"
		       " [*] TG0:     %d\n"
		       " [*] SH0:     %d\n"
		       " [*] ORGN0:   %d\n"
		       " [*] IRGN0:   %d\n"
		       " [*] EPD0:    %d\n"
		       " [*] T0SZ:    %d\n",
		       FSET (ctrl.tcr_el1, 38), FSET (ctrl.tcr_el1, 37), FSET (ctrl.tcr_el1, 36),
		       (int)(ctrl.tcr_el1 >> 32) & 0x7, FSET (ctrl.tcr_el1, 30), (int)(ctrl.tcr_el1 >> 28) & 0x3,
		       (int)(ctrl.tcr_el1 >> 26) & 0x3, (int)(ctrl.tcr_el1 >> 24) & 0x3, FSET (ctrl.tcr_el1, 23),
		       FSET (ctrl.tcr_el1, 22), (int)(ctrl.tcr_el1 >> 16) & 0x3f, FSET (ctrl.tcr_el1, 14),
		       (int)(ctrl.tcr_el1 >> 12) & 0x3, (int)(ctrl.tcr_el1 >> 10) & 0x3, (int)(ctrl.tcr_el1 >> 8) & 0x3,
		       FSET (ctrl.tcr_el1, 7), (int)ctrl.tcr_el1 & 0x3f);
}
#endif

// Consume one integer token without narrowing native-width kernel addresses.
static bool parse_number(const char **args, size_t *value, size_t max) {
	const char *str = r_str_trim_head_ro (*args);
	char *end;
	errno = 0;
	ut64 number = strtoull (str, &end, 0);
	if (!*str || *str == '-' || end == str || errno == ERANGE || number > max || (*end && !IS_WHITECHAR (*end))) {
		return false;
	}
	*value = number;
	*args = r_str_trim_head_ro (end);
	return true;
}

static void append_help(RStrBuf *sb, const char *cmd, bool p_usage) {
	size_t i, cmd_len = cmd? strlen (cmd): 0;
	const char *help[] = {
		":dm [pid]        Print kernel memory map (or process if r2k.io==1)",
		":dr              Print control registers",
		":dR              Print control registers in detailed mode",
		":dp [pid]        Print current selected pid or change it",
		":e r2k.io=[012]  Read/Write from 0: Linear, 1: Process, 2: Physical addresses",
		":e r2k.wp=[01]   Honor arch write protection (enabled by default)",
		":M                      Print kernel memory map",
		":b      beid [pid]      Change r2k backend. pid is required when beid is 1.",
		"                         0: linear address; 1: process address; 2: physical address",
		":p[*]   pid             Print process information (or flags with *)",
		":rl     addr len        Read from linear address",
		":rp     pid addr len    Read from process address",
		":rP     addr len        Read physical address",
		":R[p]                   Print control registers. Use :Rp for detailed description",
		":wl[x]  addr input      Write at linear address. Use :wlx for input in hex",
		":wp[x]  pid addr input  Write at process address. Use :wpx for input in hex",
		":wP[x]  addr input      Write at physical address. Use :wPx for input in hex",
		":W      1|0             Honor arch write protect (1 enable WP, 0 disable WP)"
	};
	if (p_usage) {
		r_strbuf_append (sb, "Usage: :command [args...]\n");
	}
	if (cmd_len == 3 && cmd[0] == 'w' && cmd[2] == 'x') {
		cmd_len = 2;
	}
	if (cmd_len == 2 && !strcmp (cmd, "p*")) {
		cmd_len = 1;
	}
	for (i = 0; i < R_ARRAY_SIZE (help); i++) {
		if (!cmd || !strncmp (cmd, help[i] + 1, cmd_len)) {
			r_strbuf_appendf (sb, "%s\n", help[i]);
		}
	}
}

int ReadMemory(RIO *io, RIODesc *iodesc, int ioctl_n, size_t pid, size_t address, ut8 *buf, int len) {
	int ret = -1;
	int pagesize, newlen;
	ut64 pageaddr, offset;
	bool flag = 0;
	ut8 garbage;

	if (iodesc && iodesc->data > 0 && buf) {
		struct r2k_data data;

		data.pid = pid;
		data.addr = address;
		data.len = len;
		data.buff = (ut8 *) calloc (len, 1);
		if (!data.buff) {
			return -1;
		}

		ret = ioctl ((int)(size_t)iodesc->data, ioctl_n, &data);
		if (!ret) {
			memcpy (buf, data.buff, len);
			ret = len;
		} else {
			garbage = 0xff;
			flag = 0;
			offset = 0;
			pagesize = getpagesize();
			pageaddr = address + pagesize;
			pageaddr -= (pageaddr % pagesize);
			if ((len - (int)(pageaddr - address)) > 0) {
				data.len = pageaddr - address;
				ret = ioctl ((int)(size_t)iodesc->data, ioctl_n, &data);
				if (!ret) {
					memcpy (buf + offset, data.buff, pageaddr - address);
					flag = 1;
				} else {
					memset (buf + offset, garbage, pageaddr - address);
				}

				offset = pageaddr - address;
				newlen = len - offset;
				while (newlen >= pagesize) {
					data.addr = pageaddr;
					data.len = pagesize;

					ret = ioctl ((int)(size_t)iodesc->data, ioctl_n, &data);
					if (!ret) {
						memcpy (buf + offset, data.buff, pagesize);
						flag = 1;
					} else {
						memset (buf + offset, garbage, pagesize);
					}
					pageaddr += pagesize;
					offset += pagesize;
					newlen -= pagesize;
				}

				data.addr = pageaddr;
				data.len = newlen;
				ret = ioctl ((int)(size_t)iodesc->data, ioctl_n, &data);
				if (!ret) {
					memcpy (buf + offset, data.buff, newlen);
					flag = 1;
				} else {
					memset (buf + offset, garbage, newlen);
				}
			}
			ret = flag ? len : -1;
		}

		free (data.buff);
	} else if (!buf) {
		R_LOG_ERROR ("Invalid input buffer");
	} else {
		R_LOG_WARN ("IOCTL device not initialized");
	}
	return ret;
}

int WriteMemory(RIO *io, RIODesc *iodesc, int ioctl_n, size_t pid, ut64 address, const ut8 *buf, int len) {
	int ret = -1;

	if (iodesc && iodesc->data > 0 && buf) {
		struct r2k_data data;

		data.pid = pid;
		data.addr = address;
		data.len = len;
		data.buff = (ut8 *) calloc (len, 1);
		data.wp = r2k_struct.wp;

		if (!data.buff) {
			return -1;
		}

		memcpy (data.buff, buf, len);
		ret = ioctl ((int)(size_t)iodesc->data, ioctl_n, &data);
		if (!ret) {
			ret = len;
		} else {
			R_LOG_ERROR ("Write failed. ioctl err: %s", strerror (errno));
			ret = -1;
		}

		free (data.buff);
	} else if (!buf) {
		R_LOG_ERROR ("Invalid input buffer");
	} else {
		R_LOG_WARN ("IOCTL device not initialized");
	}
	return ret;
}

static void append_process_info(int fd, RStrBuf *sb, int pid, bool fflag) {
	struct r2k_proc_info data = { .pid = pid };
	if (ioctl (fd, IOCTL_PRINT_PROC_INFO, &data)) {
		R_LOG_ERROR ("ioctl: %s", strerror (errno));
		return;
	}
	struct r2k_proc_info *pd = &data;
	const ut64 count = R_ARRAY_SIZE (pd->vmareastruct);
	if (!fflag) {
		r_strbuf_appendf (sb, "pid = %d\nprocess name = %.16s\n", pd->pid, pd->comm);
		r_strbuf_appendf (sb, "task_struct = 0x%08"PFMT64x"\n", (ut64)pd->task);
	}
	ut64 i = 0;
	int j = 0;
	while (i + 7 < count) {
		if (!pd->vmareastruct[i] && !pd->vmareastruct[i + 1]) {
			break;
		}
		const char *name = (const char *)&pd->vmareastruct[i + 7];
		const size_t maxbytes = (count - (i + 7)) * sizeof (size_t);
		const size_t namelen = r_str_nlen (name, maxbytes);
		if (namelen == 0 || namelen >= maxbytes) {
			break;
		}
		const ut64 nextstart = i + 7 + (namelen - 1 + sizeof (size_t)) / sizeof (size_t);
		if (nextstart <= i || nextstart > count) {
			break;
		}
		if (fflag) {
			r_strbuf_appendf (sb, "'f pid.%d.%s.%d.start=0x%"PFMT64x"\n", pd->pid, name, j, (ut64) pd->vmareastruct[i]);
			r_strbuf_appendf (sb, "'f pid.%d.%s.%d.end=0x%"PFMT64x"\n", pd->pid, name, j, (ut64) pd->vmareastruct[i + 1]);
		} else {
			const size_t flags = pd->vmareastruct[i + 2];
			r_strbuf_appendf (sb, "0x%08"PFMT64x" - 0x%08"PFMT64x" %c%c%c%c 0x%08"PFMT64x" %02zu:%02zu %-8"PFMT64u"  %s\n",
				(ut64) pd->vmareastruct[i], (ut64) pd->vmareastruct[i + 1],
				(flags & VM_READ) ? 'r' : '-',
				(flags & VM_WRITE) ? 'w' : '-',
				(flags & VM_EXEC) ? 'x' : '-',
				(flags & VM_MAYSHARE) ? 's' : 'p',
				(ut64) pd->vmareastruct[i + 3], pd->vmareastruct[i + 4],
				pd->vmareastruct[i + 5], (ut64) pd->vmareastruct[i + 6], name);
		}
		j++;
		i = nextstart;
	}
	if (fflag) {
		r_strbuf_appendf (sb, "'f pid.%d.task_struct = 0x%08"PFMT64x"\n", pd->pid, (ut64)pd->task);
	} else {
		r_strbuf_appendf (sb, "STACK BASE ADDRESS = 0x%"PFMT64x"\n", (ut64)pd->stack);
	}
}

static void append_kernel_map(int fd, RStrBuf *sb) {
	int i, j;
	struct r2k_kernel_maps map_data = {0};
	struct r2k_kernel_map_info *info;
	long page_size = sysconf (_SC_PAGESIZE);

	int ret = ioctl (fd, IOCTL_GET_KERNEL_MAP, &map_data);
	if (ret < 0) {
		R_LOG_ERROR ("ioctl: %s", strerror (errno));
		return;
	}
	r_strbuf_appendf (sb, "map_data.size: %d, map_data.n_entries: %d\n", map_data.size, map_data.n_entries);
	if (map_data.size <= 0 || map_data.n_entries < 0 ||
			(size_t)map_data.n_entries > (size_t)map_data.size / sizeof (*info)) {
		R_LOG_ERROR ("Invalid kernel map size");
		return;
	}
	info = mmap (0, map_data.size, PROT_READ, MAP_SHARED, fd, 0);
	if (info == MAP_FAILED) {
		R_LOG_ERROR ("mmap: %s", strerror (errno));
		return;
	}

	for (i = 0; i < map_data.n_entries; i++) {
		struct r2k_kernel_map_info *in = &info[i];
		r_strbuf_appendf (sb, "start_addr: 0x%"PFMT64x"\n", (ut64) in->start_addr);
		r_strbuf_appendf (sb, "end_addr: 0x%"PFMT64x"\n", (ut64) in->end_addr);
		r_strbuf_appendf (sb, "n_pages: %d (%ld Kbytes)\n", in->n_pages, (in->n_pages * page_size) / 1024);
		r_strbuf_appendf (sb, "n_phys_addr: %d\n", in->n_phys_addr);
		for (j = 0; j < R_MIN (in->n_phys_addr, MAX_PHYS_ADDR); j++) {
			r_strbuf_appendf (sb, "  phys_addr: 0x%"PFMT64x"\n", (ut64) in->phys_addr[j]);
		}
		r_strbuf_append (sb, "\n");
	}

	if (munmap (info, map_data.size) == -1) {
		R_LOG_ERROR ("munmap failed");
	}
}

static void append_ctrl_regs(int fd, RStrBuf *sb, bool pretty) {
	struct r2k_control_reg reg_data = {0};
	int ret = ioctl (fd, IOCTL_READ_CONTROL_REG, &reg_data);
	if (ret) {
		R_LOG_ERROR ("ioctl err: %s", strerror (errno));
		return;
	}

#if __i386__ || __x86_64__
	//Print cr1 as null instead of random value from kernel land.
	reg_data.cr1 = 0;
	if (pretty) {
		append_ctrl_reg_details (sb, reg_data);
	} else {
		r_strbuf_appendf (sb, "cr0 = 0x%"PFMT64x"\n", (ut64) reg_data.cr0);
		r_strbuf_appendf (sb, "cr1 = 0x%"PFMT64x"\n", (ut64) reg_data.cr1);
		r_strbuf_appendf (sb, "cr2 = 0x%"PFMT64x"\n", (ut64) reg_data.cr2);
		r_strbuf_appendf (sb, "cr3 = 0x%"PFMT64x"\n", (ut64) reg_data.cr3);
		r_strbuf_appendf (sb, "cr4 = 0x%"PFMT64x"\n", (ut64) reg_data.cr4);
#if __x86_64__
		r_strbuf_appendf (sb, "cr8 = 0x%"PFMT64x"\n", (ut64) reg_data.cr8);
#endif
	}
#elif __arm__
	if (pretty) {
		append_ctrl_reg_details (sb, reg_data);
	} else {
		r_strbuf_appendf (sb, "ttbr0 = 0x%"PFMT64x"\n", (ut64) reg_data.ttbr0);
		r_strbuf_appendf (sb, "ttbr1 = 0x%"PFMT64x"\n", (ut64) reg_data.ttbr1);
		r_strbuf_appendf (sb, "ttbcr = 0x%"PFMT64x"\n", (ut64) reg_data.ttbcr);
		r_strbuf_appendf (sb, "c1    = 0x%"PFMT64x"\n", (ut64) reg_data.c1);
		r_strbuf_appendf (sb, "c3    = 0x%"PFMT64x"\n", (ut64) reg_data.c3);
	}
#elif __arm64__ || __aarch64__
	if (pretty) {
		append_ctrl_reg_details (sb, reg_data);
	} else {
		r_strbuf_appendf (sb, "sctlr_el1 = 0x%"PFMT64x"\n", (ut64) reg_data.sctlr_el1);
		r_strbuf_appendf (sb, "ttbr0_el1 = 0x%"PFMT64x"\n", (ut64) reg_data.ttbr0_el1);
		r_strbuf_appendf (sb, "ttbr1_el1 = 0x%"PFMT64x"\n", (ut64) reg_data.ttbr1_el1);
		r_strbuf_appendf (sb, "tcr_el1   = 0x%"PFMT64x"\n", (ut64) reg_data.tcr_el1);
	}
#endif
}

static void run_command(RIO *io, RIODesc *iodesc, RStrBuf *sb, const char *cmd, const char *args) {
	int fd = (int)(size_t)iodesc->data;
	size_t value, pid = r2k_struct.pid;
	if (!strcmp (cmd, "M") || (!strcmp (cmd, "dm") && !*args && r2k_struct.beid != 1)) {
		if (*args) {
			goto invalid;
		}
		append_kernel_map (fd, sb);
	} else if (!strcmp (cmd, "p") || !strcmp (cmd, "p*") || !strcmp (cmd, "dm")) {
		if ((*args || strcmp (cmd, "dm")) && !parse_number (&args, &pid, INT_MAX)) {
			goto invalid;
		}
		if (*args) {
			goto invalid;
		}
		append_process_info (fd, sb, pid, !strcmp (cmd, "p*"));
	} else if (!strcmp (cmd, "R") || !strcmp (cmd, "Rp") || !strcmp (cmd, "dr") || !strcmp (cmd, "dR")) {
		if (*args) {
			goto invalid;
		}
		append_ctrl_regs (fd, sb, !strcmp (cmd, "Rp") || !strcmp (cmd, "dR"));
	} else if (!strcmp (cmd, "dp")) {
		if (*args) {
			if (!parse_number (&args, &pid, INT_MAX) || *args) {
				goto invalid;
			}
			r2k_struct.pid = pid;
		}
		r_strbuf_appendf (sb, "%d\n", r2k_struct.pid);
	} else if (!strcmp (cmd, "b")) {
		if (!*args) {
			r_strbuf_appendf (sb, "beid: %d\npid:  %d\nUsage:\n", r2k_struct.beid, r2k_struct.pid);
			append_help (sb, cmd, false);
			return;
		}
		if (!parse_number (&args, &value, 2) ||
				((value == 1 || *args) && !parse_number (&args, &pid, INT_MAX)) || *args) {
			goto invalid;
		}
		r2k_struct.beid = value;
		r2k_struct.pid = value == 1? pid: 0;
		io->coreb.cmdf (io->coreb.core, "s 0x%"PFMT64x, io->off);
	} else if (!strcmp (cmd, "W")) {
		if (!*args) {
			r_strbuf_appendf (sb, "Write Protect: %d\nUsage:\n", r2k_struct.wp);
			append_help (sb, cmd, false);
		} else if (parse_number (&args, &value, 1) && !*args) {
			r2k_struct.wp = value;
		} else {
			goto invalid;
		}
	} else if (!strcmp (cmd, "e")) {
		bool wp = r_str_startswith (args, "r2k.wp");
		if (!wp && !r_str_startswith (args, "r2k.io")) {
			goto invalid;
		}
		args = r_str_trim_head_ro (args + 6);
		if (*args == '?' && !*r_str_trim_head_ro (args + 1)) {
			r_strbuf_append (sb, wp
				? "<bool> enable write protection (enabled by default)\n"
				: "0: Linear memory\n1: Process memory\n2: Physical memory\n");
			return;
		}
		if (*args) {
			if (*args++ != '=' || !parse_number (&args, &value, wp? 1: 2) || *args) {
				goto invalid;
			}
			if (wp) {
				r2k_struct.wp = value;
			} else {
				r2k_struct.beid = value;
				if (value != 1) {
					r2k_struct.pid = 0;
				}
				io->coreb.cmdf (io->coreb.core, "s 0x%"PFMT64x, io->off);
			}
		}
		if (wp) {
			r_strbuf_appendf (sb, "%s\n", r_str_bool (r2k_struct.wp));
		} else {
			r_strbuf_appendf (sb, "%d\n", r2k_struct.beid);
		}
	} else if ((*cmd == 'r' || *cmd == 'w') && cmd[1]) {
		bool write = *cmd == 'w';
		bool hex = write && cmd[2] == 'x';
		int request;
		switch (cmd[1]) {
		case 'l': request = write? IOCTL_WRITE_KERNEL_MEMORY: IOCTL_READ_KERNEL_MEMORY; break;
		case 'p': request = write? IOCTL_WRITE_PROCESS_ADDR: IOCTL_READ_PROCESS_ADDR; break;
		case 'P': request = write? IOCTL_WRITE_PHYSICAL_ADDR: IOCTL_READ_PHYSICAL_ADDR; break;
		default: goto invalid;
		}
		size_t addr, len;
		pid = 0;
		if (cmd[hex? 3: 2] || (cmd[1] == 'p' && !parse_number (&args, &pid, INT_MAX)) ||
				!parse_number (&args, &addr, SIZE_MAX) || !*args) {
			goto invalid;
		}
		if (write) {
			if (strlen (args) > INT_MAX) {
				goto invalid;
			}
			ut8 *data = (ut8 *)strdup (args);
			if (!data) {
				return;
			}
			int count = hex? r_hex_str2bin (args, data): r_str_unescape ((char *)data);
			bool valid = count > 0 && (size_t)count - 1 <= SIZE_MAX - addr;
			if (valid) {
				WriteMemory (io, iodesc, request, pid, addr, data, count);
			}
			free (data);
			if (!valid) {
				goto invalid;
			}
		} else {
			if (!parse_number (&args, &len, INT_MAX) || !len || *args || len - 1 > SIZE_MAX - addr) {
				goto invalid;
			}
			ut8 *data = malloc (len);
			if (!data) {
				R_LOG_ERROR ("Failed to allocate buffer");
				return;
			}
			int count = ReadMemory (io, iodesc, request, pid, addr, data, len);
			if (count > 0) {
				RPrint *print = r_print_new ();
				print->flags &= ~R_PRINT_FLAGS_COLOR;
				r_print_hexdump_strbuf (print, sb, addr, data, count, 16, 1, 1);
				r_print_free (print);
			}
			free (data);
		}
	} else {
		append_help (sb, NULL, true);
	}
	return;
invalid:
	R_LOG_ERROR ("Invalid r2k command arguments");
	append_help (sb, cmd, false);
}

char *run_ioctl_command(RIO *io, RIODesc *iodesc, const char *buf) {
	char *cmd = strdup (r_str_trim_head_ro (buf));
	if (!cmd) {
		return NULL;
	}
	char *args = cmd + strcspn (cmd, " \t\r\n");
	if (*args) {
		*args++ = 0;
	}
	RStrBuf *sb = r_strbuf_new ("");
	run_command (io, iodesc, sb, cmd, r_str_trim_head_ro (args));
	free (cmd);
	return r_strbuf_drain (sb);
}

#endif
