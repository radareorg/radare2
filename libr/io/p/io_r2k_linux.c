#ifndef __GNU__

#include "io_r2k_linux.h"

#define fset(num, shift) ((((num) & (((ut64) 1) << (shift))) == 0) ? 0 : 1)

#if __i386__ || __x86_64__
static void x86_ctrl_reg_pretty_print(RIO *io, struct r2k_control_reg ctrl) {
	io->cb_printf ("CR0: 0x%"PFMT64x"\n", (ut64) ctrl.cr0);
	io->cb_printf (" [*] PG:    %d\n"
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
		       fset (ctrl.cr0, 31), fset (ctrl.cr0, 30), fset (ctrl.cr0, 29), fset (ctrl.cr0, 18),
		       fset (ctrl.cr0, 16), fset (ctrl.cr0, 5), fset (ctrl.cr0, 4), fset (ctrl.cr0, 3),
		       fset (ctrl.cr0, 2), fset (ctrl.cr0, 1), fset (ctrl.cr0, 1));
	io->cb_printf ("\n");

	io->cb_printf ("CR2: 0x%"PFMT64x"\n", (ut64) ctrl.cr2);
	io->cb_printf ("Page-Fault Linear Address: 0x%"PFMT64x"\n", (ut64) ctrl.cr2);
	io->cb_printf ("\n");

	io->cb_printf ("CR3: 0x%"PFMT64x"\n", (ut64) ctrl.cr3);
	io->cb_printf (" [*] Page-Directory Base:    0x%"PFMT64x"\n"
		       " [*] PCD:                    %d\n"
		       " [*] PWT:                    %d\n",
		       (((ut64) ctrl.cr3) & 0xfffffffffffff000), fset (ctrl.cr3, 4), fset (ctrl.cr3, 3));
	io->cb_printf ("\n");

	io->cb_printf ("CR4: 0x%"PFMT64x"\n", (ut64) ctrl.cr4);
	io->cb_printf (" [*] PKE:         %d\n"
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
		       fset (ctrl.cr4, 22), fset (ctrl.cr4, 21), fset (ctrl.cr4, 20), fset (ctrl.cr4, 18),
		       fset (ctrl.cr4, 17), fset (ctrl.cr4, 16), fset (ctrl.cr4, 14), fset (ctrl.cr4, 13),
		       fset (ctrl.cr4, 11), fset (ctrl.cr4, 10), fset (ctrl.cr4, 9), fset (ctrl.cr4, 8),
		       fset (ctrl.cr4, 7), fset (ctrl.cr4, 6), fset (ctrl.cr4, 5), fset (ctrl.cr4, 4),
		       fset (ctrl.cr4, 3), fset (ctrl.cr4, 2), fset (ctrl.cr4, 1), fset (ctrl.cr4, 0));
	io->cb_printf ("\n");

#if __x86_64__
	io->cb_printf ("CR8: 0x%"PFMT64x"\n", (ut64) ctrl.cr8);
	io->cb_printf (" [*] TPL:    %u\n", (ut32)(ctrl.cr8 & 0xf));
#endif
}

#elif __arm__
static void arm_ctrl_reg_pretty_print(RIO *io, struct r2k_control_reg ctrl) {
	io->cb_printf ("TTBR0: 0x%"PFMT64x"\n", (ut64) ctrl.ttbr0);
	io->cb_printf (" [*] Translation table base 0:  0x%"PFMT64x"\n"
		       " [*] UNP/SBZ:                   0x%"PFMT64x"\n"
		       " [*] RGN:                       0x%"PFMT64x"\n"
		       " [*] P:                         %d\n"
		       " [*] S:                         %d\n"
		       " [*] C:                         %d\n",
		       (ut64) ((ctrl.ttbr0 & (0xffffffff << (14 - (ctrl.ttbcr & 7)))) >> (14 - (ctrl.ttbcr & 7))),
		       (ut64) ((ctrl.ttbr0 & ((1 << (13 - (ctrl.ttbcr & 7) + 1)) - (1 << 5))) >> 6),
		       (ut64) ((ctrl.ttbr0 & 0x18) >> 3), fset (ctrl.ttbr0, 2), fset (ctrl.ttbr0, 1), fset (ctrl.ttbr0, 0));
	io->cb_printf ("\n");

	io->cb_printf ("TTBR1: 0x%"PFMT64x"\n", (ut64) ctrl.ttbr1);
	io->cb_printf (" [*] Translation table base 1:  0x%"PFMT64x"\n"
		       " [*] UNP/SBZ:                   0x%"PFMT64x"\n"
		       " [*] RGN:                       0x%"PFMT64x"\n"
		       " [*] P:                         %d\n"
		       " [*] S:                         %d\n"
		       " [*] C:                         %d\n",
		       (ut64) ((ctrl.ttbr1 & (0xffffffff << 14)) >> 14), (ut64) ((ctrl.ttbr1 & ((1 << (13 + 1)) - (1 << 5))) >> 6),
		       (ut64) ((ctrl.ttbr1 & 0x18) >> 3), fset (ctrl.ttbr1, 2), fset (ctrl.ttbr1, 1), fset (ctrl.ttbr1, 0));
	io->cb_printf ("\n");

	io->cb_printf ("TTBCR: 0x%"PFMT64x"\n", (ut64) ctrl.ttbcr);
	io->cb_printf (" [*] N:    %d\n", ctrl.ttbcr & 7);
	io->cb_printf ("\n");

	io->cb_printf ("C1: 0x%"PFMT64x"\n", (ut64) ctrl.c1);
	io->cb_printf (" [*] AFE:    %d\n"
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
		       fset (ctrl.c1, 29), fset (ctrl.c1, 28), fset (ctrl.c1, 25), fset (ctrl.c1, 24),
		       fset (ctrl.c1, 23), fset (ctrl.c1, 22), fset (ctrl.c1, 21), fset (ctrl.c1, 18),
		       fset (ctrl.c1, 16), fset (ctrl.c1, 15), fset (ctrl.c1, 14), fset (ctrl.c1, 13),
		       fset (ctrl.c1, 12), fset (ctrl.c1, 11), fset (ctrl.c1, 10), fset (ctrl.c1, 9),
		       fset (ctrl.c1, 8), fset (ctrl.c1, 7), fset (ctrl.c1, 3), fset (ctrl.c1, 2),
		       fset (ctrl.c1, 1), fset (ctrl.c1, 0));
	io->cb_printf ("\n");

	io->cb_printf ("C3: 0x%"PFMT64x"\n", (ut64) ctrl.c3);
}

#elif __arm64__ || __aarch64__
/*ARM Cortex-A57 and ARM Cortex-A72. This might show some wrong values for other processor.*/
static void arm64_ctrl_reg_pretty_print(RIO *io, struct r2k_control_reg ctrl) {
	io->cb_printf ("SCTLR_EL1: 0x%"PFMTSZx"\n", ctrl.sctlr_el1);
	io->cb_printf (" [*] UCI:     %d\n"
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
		       fset (ctrl.sctlr_el1, 26), fset (ctrl.sctlr_el1, 25), fset (ctrl.sctlr_el1, 24), fset (ctrl.sctlr_el1, 19),
		       fset (ctrl.sctlr_el1, 18), fset (ctrl.sctlr_el1, 16), fset (ctrl.sctlr_el1, 15), fset (ctrl.sctlr_el1, 14),
		       fset (ctrl.sctlr_el1, 12), fset (ctrl.sctlr_el1, 9), fset (ctrl.sctlr_el1, 8), fset (ctrl.sctlr_el1, 7),
		       fset (ctrl.sctlr_el1, 6), fset (ctrl.sctlr_el1, 5), fset (ctrl.sctlr_el1, 4), fset (ctrl.sctlr_el1, 3),
		       fset (ctrl.sctlr_el1, 2), fset (ctrl.sctlr_el1, 1), fset (ctrl.sctlr_el1, 0));
	io->cb_printf ("\n");

	io->cb_printf ("TTBR0_EL1: 0x%"PFMTSZx"\n", ctrl.ttbr0_el1);
	io->cb_printf (" [*] ASID [63:48]:    0x%"PFMT64x"\n"
		       " [*] BADDR [47:10]:   0x%"PFMT64x"\n",
		       (ut64)(ctrl.ttbr0_el1 & 0xffff000000000000LLU) >> 48, (ctrl.ttbr0_el1 & ((((ut64) 1) << (47 + 1)) - (1 << 10))) >> 10);
	io->cb_printf ("\n");

	io->cb_printf ("TTBR1_EL1: 0x%"PFMTSZx"\n", ctrl.ttbr1_el1);
	io->cb_printf (" [*] ASID [63:48]:    0x%"PFMT64x"\n"
		       " [*] BADDR [47:10]:   0x%"PFMT64x"\n",
		       (ut64)(ctrl.ttbr1_el1 & 0xffff000000000000LLU) >> 48, (ctrl.ttbr1_el1 & ((((ut64) 1) << (47 + 1)) - (1 << 10))) >> 10);
	io->cb_printf ("\n");

	io->cb_printf ("TCR_EL1: 0x%"PFMTSZx"\n", ctrl.tcr_el1);
	io->cb_printf (" [*] TBI1:    %d\n"
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
		       fset (ctrl.tcr_el1, 38), fset (ctrl.tcr_el1, 37), fset (ctrl.tcr_el1, 36),
		       (int)(ctrl.tcr_el1 >> 32) & 0x7, fset (ctrl.tcr_el1, 30), (int)(ctrl.tcr_el1 >> 28) & 0x3,
		       (int)(ctrl.tcr_el1 >> 26) & 0x3, (int)(ctrl.tcr_el1 >> 24) & 0x3, fset (ctrl.tcr_el1, 23),
		       fset (ctrl.tcr_el1, 22), (int)(ctrl.tcr_el1 >> 16) & 0x3f, fset (ctrl.tcr_el1, 14),
		       (int)(ctrl.tcr_el1 >> 12) & 0x3, (int)(ctrl.tcr_el1 >> 10) & 0x3, (int)(ctrl.tcr_el1 >> 8) & 0x3,
		       fset (ctrl.tcr_el1, 7), (int)ctrl.tcr_el1 & 0x3f);
}
#endif

static const char* getargpos(const char *buf, int pos) {
	int i;
	for (i = 0; buf && i < pos; i++) {
		buf = strchr (buf, ' ');
		if (!buf) {
			break;
		}
		buf = r_str_ichr ((char *) buf, ' ');
	}
	return buf;
}

static size_t getvalue(const char *buf, int pos) {
	size_t ret;
	buf = getargpos (buf, pos);
	if (buf) {
		ret = strtoul (buf, 0, 0);
	} else {
		ret = -1;
	}
	return ret;
}

static void print_help(RIO *io, char *cmd, int p_usage) {
	int i = 0;
	int cmd_len = cmd ? strlen (cmd) : 0;
	const char* usage = "Usage: :[MprRw][lpP] [args...]";
	const char* help_msg[] = {
		":dm              Print kernel memory map (or process if r2k.io==1)",
		":dr              Print control registers",
		":dR              Print control registers in detailed mode",
		":dp [pid]        Print current selected pid or change it",
		":e r2k.io=[012]  Read/Write from 0: Linear, 1: Process, 2: Physical addresses"
	};
	RCoreHelpMessage help_msg_old = {
		":M                      Print kernel memory map",
		":b      beid [pid]      Change r2k backend. pid is required when beid is 1.",
		"                         0: linear address; 1: process address; 2: physical address",
		":p      pid             Print process information",
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
		io->cb_printf ("%s\n", usage);
	}
	for (i = 0; i < (sizeof (help_msg) / sizeof (char*)); i++) {
		if (!cmd || !strncmp (cmd, help_msg[i] + 1, cmd_len)) {
			io->cb_printf ("%s\n", help_msg[i]);
		}
	}
	io->cb_printf ("\nOld Commands: (deprecated)\n");
	for (i = 0; i < (sizeof (help_msg_old) / sizeof (char*)); i++) {
		if (!cmd || !strncmp (cmd, help_msg_old[i] + 1, cmd_len)) {
			io->cb_printf ("%s\n", help_msg_old[i]);
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
		data.buff = (ut8 *) calloc (len + 1, 1);
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
		io->cb_printf ("Invalid input buffer.\n");
	} else {
		io->cb_printf ("IOCTL device not initialized.\n");
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
		data.buff = (ut8 *) calloc (len + 1, 1);
		data.wp = r2k_struct.wp;

		if (!data.buff) {
			return -1;
		}

		memcpy (data.buff, buf, len);
		ret = ioctl ((int)(size_t)iodesc->data, ioctl_n, &data);
		if (!ret) {
			ret = len;
		} else {
			io->cb_printf ("Write failed. ioctl err: %s\n", strerror (errno));
			ret = -1;
		}

		free (data.buff);
	} else if (!buf) {
		io->cb_printf ("Invalid input buffer.\n");
	} else {
		io->cb_printf ("IOCTL device not initialized.\n");
	}
	return ret;
}

int run_old_command(RIO *io, RIODesc *iodesc, const char *buf) {
	int ret, inphex, ioctl_n;
	size_t pid, addr, len;
	ut8 *databuf = NULL;
	switch (*buf) {
	case 'W':
		{
			if (buf[1] != ' ') {
				io->cb_printf ("Write Protect: %d\n", r2k_struct.wp);
				io->cb_printf ("Usage:\n");
				print_help (io, "W", 0);
				break;
			}

			int wp = getvalue (buf, 1);
			if (wp < 0 || wp > 1) {
				io->cb_printf ("Invalid usage of W\n");
				print_help (io, "W", 0);
				break;
			}
			r2k_struct.wp = (ut8)wp;
		}
		break;
	case 'b':
		{
			if (buf[1] != ' ') {
				io->cb_printf ("beid: %d\n", r2k_struct.beid);
				io->cb_printf ("pid:  %d\n", r2k_struct.pid);
				io->cb_printf ("Usage:\n");
				print_help (io, "b", 0);
				goto end;
			}
			int beid = getvalue (buf, 1);
			int pid = getvalue (buf, 2);
			if (beid < 0 || beid > 2) {
				io->cb_printf ("Invalid usage of b\n");
				print_help (io, "b", 0);
				break;
			}
			if (beid == 1 && pid < 0) {
				io->cb_printf ("Invalid pid read.\n");
				print_help (io, "b", 0);
				break;
			}
			r2k_struct.beid = beid;
			r2k_struct.pid = (beid == 1) ? pid : 0;
			io->coreb.cmdf (io->coreb.core, "s 0x%"PFMT64x, io->off);
		}
		break;
	case 'r':
		{
			RPrint *print = r_print_new ();
			switch (buf[1]) {
			case 'l':
				//read linear address
				//: rl addr len
				if (buf[2] != ' ') {
					print_help (io, "rl", 0);
					goto end;
				}
				pid = 0;
				addr = getvalue (buf, 1);
				len = getvalue (buf, 2);
				if (addr == -1 || len == -1) {
					io->cb_printf ("Invalid number of arguments.\n");
					print_help (io, "rl", 0);
					goto end;
				}
				ioctl_n = IOCTL_READ_KERNEL_MEMORY;
				break;
			case 'p':
				//read process address
				//: rp pid address len
				if (buf[2] != ' ') {
					print_help (io, "rp", 0);
					goto end;
				}
				pid = getvalue (buf, 1);
				addr = getvalue (buf, 2);
				len = getvalue (buf, 3);
				if (pid == -1 || addr == -1 || len == -1) {
					io->cb_printf ("Invalid number of arguments.\n");
					print_help (io, "rp", 0);
					goto end;
				}
				ioctl_n = IOCTL_READ_PROCESS_ADDR;
				break;
			case 'P':
				//read physical address
				//: rP address len
				if (buf[2] != ' ') {
					print_help (io, "rP", 0);
					goto end;
				}
				pid = 0;
				addr = getvalue (buf, 1);
				len = getvalue (buf, 2);
				if (addr == -1 || len == -1) {
					io->cb_printf ("Invalid number of arguments.\n");
					print_help (io, "rP", 0);
					goto end;
				}
				ioctl_n = IOCTL_READ_PHYSICAL_ADDR;
				break;
			default:
				print_help(io, "r", 0);
				r_print_free (print);
				goto end;
			}
			databuf = (ut8 *) calloc (len + 1, 1);
			if (databuf) {
				ret = ReadMemory (io, iodesc, ioctl_n, pid, addr, databuf, len);
				if (ret > 0) {
					r_print_hexdump (print, addr, (const ut8 *) databuf, ret, 16, 1, 1);
				}
			} else {
				io->cb_printf ("Failed to allocate buffer\n");
			}
			r_print_free (print);
		}
		break;
	case 'w':
		inphex = (buf[2] == 'x') ? 1 : 0;
		switch (buf[1]) {
		case 'l':
			//write linear address
			//: wl addr str
			if ((inphex && buf[3] != ' ') || (!inphex && buf[2] != ' ')) {
				print_help (io, "wl", 0);
				goto end;
			}
			pid = 0;
			addr = getvalue (buf, 1);
			buf = getargpos (buf, 2);
			if (addr == -1 || !buf) {
				io->cb_printf ("Invalid number of arguments.\n");
				print_help (io, "wl", 0);
				goto end;
			}
			ioctl_n = IOCTL_WRITE_KERNEL_MEMORY;
			break;
		case 'p':
			//write process address
			//: wp pid address str
			if ((inphex && buf[3] != ' ') || (!inphex && buf[2] != ' ')) {
				print_help (io, "wp", 0);
				goto end;
			}
			pid = getvalue (buf, 1);
			addr = getvalue (buf, 2);
			buf = getargpos (buf, 3);
			if (pid == -1 || addr == -1 || !buf) {
				io->cb_printf ("Invalid number of arguments.\n");
				print_help (io, "wp", 0);
				goto end;
			}
			ioctl_n = IOCTL_WRITE_PROCESS_ADDR;
			break;
		case 'P':
			//write physical address
			//: wP address str
			if ((inphex && buf[3] != ' ') || (!inphex && buf[2] != ' ')) {
				print_help (io, "wP", 0);
				goto end;
			}
			pid = 0;
			addr = getvalue (buf, 1);
			buf = getargpos (buf, 2);
			if (addr == -1 || !buf) {
				io->cb_printf ("Invalid number of arguments.\n");
				print_help (io, "wP", 0);
				goto end;
			}
			ioctl_n = IOCTL_WRITE_PHYSICAL_ADDR;
			break;
		default:
			print_help (io, "w", 0);
			goto end;
		}
		// coverity says this cant happen, but it doesnt hurts to add a check
		if (!buf) {
			break;
		}
		len = strlen (buf);
		databuf = (ut8 *) calloc (len + 1, 1);
		if (databuf) {
			if (inphex) {
				len = r_hex_str2bin (buf, databuf);
			} else {
				memcpy (databuf, buf, strlen (buf) + 1);
				len = r_str_unescape ((char *) databuf);
			}
			ret = WriteMemory (io, iodesc, ioctl_n, pid, addr, (const ut8 *) databuf, len);
		}
		break;
	case 'M':
		{
			//Print kernel memory map.
			//: M
			int i, j;
			struct r2k_kernel_maps map_data;
			struct r2k_kernel_map_info *info;
			long page_size = sysconf (_SC_PAGESIZE);

			ioctl_n = IOCTL_GET_KERNEL_MAP;
			ret = ioctl ((int)(size_t)iodesc->data, ioctl_n, &map_data);
			if (ret < 0) {
				io->cb_printf ("ioctl err: %s\n", strerror (errno));
				break;
			}
			io->cb_printf ("map_data.size: %d, map_data.n_entries: %d\n", map_data.size, map_data.n_entries);
			info = mmap (0, map_data.size, PROT_READ, MAP_SHARED, (int)(size_t)iodesc->data, 0);
			if (info == MAP_FAILED) {
				io->cb_printf ("mmap err: %s\n", strerror (errno));
				break;
			}

			for (i = 0; i < map_data.n_entries; i++) {
				struct r2k_kernel_map_info *in = &info[i];
				io->cb_printf ("start_addr: 0x%"PFMT64x"\n", (ut64) in->start_addr);
				io->cb_printf ("end_addr: 0x%"PFMT64x"\n", (ut64) in->end_addr);
				io->cb_printf ("n_pages: %d (%ld Kbytes)\n", in->n_pages, (in->n_pages * page_size) / 1024);
				io->cb_printf ("n_phys_addr: %d\n", in->n_phys_addr);
				for (j = 0; j < in->n_phys_addr; j++) {
					io->cb_printf ("  phys_addr: 0x%"PFMT64x"\n", (ut64) in->phys_addr[j]);
				}
				io->cb_printf ("\n");
			}

			if (munmap (info, map_data.size) == -1) {
				io->cb_printf ("munmap failed.\n");
			}
		}
		break;
	case 'R':
		{
			//Read control registers
			//: R[p]
			struct r2k_control_reg reg_data;
			ioctl_n = IOCTL_READ_CONTROL_REG;
			ret = ioctl ((int)(size_t)iodesc->data, ioctl_n, &reg_data);

			if (ret) {
				io->cb_printf ("ioctl err: %s\n", strerror (errno));
				break;
			}

#if __i386__ || __x86_64__
			//Print cr1 as null instead of random value from kernel land.
			reg_data.cr1 = 0;
			if (buf[1] != 0 && buf[1] == 'p') {
				x86_ctrl_reg_pretty_print (io, reg_data);
			} else {
				io->cb_printf ("cr0 = 0x%"PFMT64x"\n", (ut64) reg_data.cr0);
				io->cb_printf ("cr1 = 0x%"PFMT64x"\n", (ut64) reg_data.cr1);
				io->cb_printf ("cr2 = 0x%"PFMT64x"\n", (ut64) reg_data.cr2);
				io->cb_printf ("cr3 = 0x%"PFMT64x"\n", (ut64) reg_data.cr3);
				io->cb_printf ("cr4 = 0x%"PFMT64x"\n", (ut64) reg_data.cr4);
#if __x86_64__
				io->cb_printf ("cr8 = 0x%"PFMT64x"\n", (ut64) reg_data.cr8);
#endif
			}
#elif __arm__
			if (buf[1] != 0 && buf[1] == 'p') {
				arm_ctrl_reg_pretty_print(io, reg_data);
			} else {
				io->cb_printf ("ttbr0 = 0x%"PFMT64x"\n", (ut64) reg_data.ttbr0);
				io->cb_printf ("ttbr1 = 0x%"PFMT64x"\n", (ut64) reg_data.ttbr1);
				io->cb_printf ("ttbcr = 0x%"PFMT64x"\n", (ut64) reg_data.ttbcr);
				io->cb_printf ("c1    = 0x%"PFMT64x"\n", (ut64) reg_data.c1);
				io->cb_printf ("c3    = 0x%"PFMT64x"\n", (ut64) reg_data.c3);
			}
#elif __arm64__ || __aarch64__
			if (buf[1] != 0 && buf[1] == 'p') {
				arm64_ctrl_reg_pretty_print(io, reg_data);
			} else {
				io->cb_printf ("sctlr_el1 = 0x%"PFMT64x"\n", (ut64) reg_data.sctlr_el1);
				io->cb_printf ("ttbr0_el1 = 0x%"PFMT64x"\n", (ut64) reg_data.ttbr0_el1);
				io->cb_printf ("ttbr1_el1 = 0x%"PFMT64x"\n", (ut64) reg_data.ttbr1_el1);
				io->cb_printf ("tcr_el1   = 0x%"PFMT64x"\n", (ut64) reg_data.tcr_el1);
			}
#endif
		}
		break;
	case 'p':
		{
			//Print process info
			//: p pid
			ut64 i;
			ut64 nextstart;
			ut64 buffsize;
			bool fflag = 0;
			struct r2k_proc_info proc_data = {0};

			if (*(buf + 1) == '*') {
				fflag = 1;
			}
			switch (*(buf + 1)) {
			case '*':
				fflag = 1;
				if (*(buf + 2) != ' ') {
					print_help (io, "p*", 0);
					goto end;
				}
				break;
			case ' ':
				break;
			default:
				print_help (io, "p", 0);
				goto end;
			}

			pid = getvalue (buf, 1);
			if (pid == -1) {
				io->cb_printf ("Invalid number of arguments.\n");
				print_help (io, "p", 0);
				break;
			}
			proc_data.pid = pid;
			ioctl_n = IOCTL_PRINT_PROC_INFO;

			ret = ioctl ((int)(size_t)iodesc->data, ioctl_n, &proc_data);
			if (ret) {
				io->cb_printf ("ioctl err: %s\n", strerror (errno));
				break;
			}

			buffsize = (ut64) (sizeof (proc_data.vmareastruct) / sizeof (proc_data.vmareastruct[0]));
			if (fflag) {
				int j = 0;
				for (i = 0; i + 1 < buffsize;) {
					nextstart = 0;
					if (i + 7 < buffsize) {
						nextstart = i + 7 + (strlen ((const char *)&(proc_data.vmareastruct[i + 7])) - 1 + sizeof (size_t)) / sizeof (size_t);
					}
					if (!proc_data.vmareastruct[i] && (i + 1 < buffsize) &&
						!proc_data.vmareastruct[i + 1] &&
					    nextstart > 0 && nextstart - 1 < buffsize) {
						break;
					}
					io->cb_printf ("f pid.%d.%s.%d.start=0x%"PFMT64x"\n", proc_data.pid, (char*)&(proc_data.vmareastruct[i + 7]), j, (ut64) proc_data.vmareastruct[i]);
					io->cb_printf ("f pid.%d.%s.%d.end=0x%"PFMT64x"\n", proc_data.pid, (char*)&(proc_data.vmareastruct[i + 7]), j, (ut64) proc_data.vmareastruct[i + 1]);
					j += 1;
					i = nextstart;
				}
				io->cb_printf ("f pid.%d.task_struct = 0x%08zu\n", proc_data.pid, proc_data.task);
			} else {
				io->cb_printf ("pid = %d\nprocess name = %s\n", proc_data.pid, proc_data.comm);
				io->cb_printf ("task_struct = 0x%08zu\n", proc_data.task);
				for (i = 0; i < buffsize && i  + 8 < sizeof (proc_data.vmareastruct) ;) {
					nextstart = 0;
					if (i + 7 < buffsize) {
						nextstart = i + 7 + (strlen ((const char *)&(proc_data.vmareastruct[i + 7])) - 1 + sizeof (size_t)) / sizeof (size_t);
					}
					if (!proc_data.vmareastruct[i] && !proc_data.vmareastruct[i + 1] &&
					    nextstart > 0 && nextstart - 1 < buffsize) {
						break;
					}
					io->cb_printf ("0x%08"PFMT64x" - 0x%08"PFMT64x" %c%c%c%c 0x%08"PFMT64x" %02zu:%02zu %-8"PFMT64u"",
							(ut64) proc_data.vmareastruct[i], (ut64) proc_data.vmareastruct[i+1],
							proc_data.vmareastruct[i + 2] & VM_READ ? 'r' : '-',
							proc_data.vmareastruct[i + 2] & VM_WRITE ? 'w' : '-',
							proc_data.vmareastruct[i + 2] & VM_EXEC ? 'x' : '-',
							proc_data.vmareastruct[i + 2] & VM_MAYSHARE ? 's' : 'p',
							(ut64) proc_data.vmareastruct[i + 3], proc_data.vmareastruct[i + 4],
							proc_data.vmareastruct[i + 5], (ut64) proc_data.vmareastruct[i + 6]);
					io->cb_printf ("  %s\n", (char*)&(proc_data.vmareastruct[i + 7]));
					i = nextstart;
				}
				io->cb_printf ("STACK BASE ADDRESS = 0x%p\n", (void*)proc_data.stack);
			}
		}
		break;
	default:
		print_help (io, NULL, 1);
		break;
	}
 end:
	free (databuf);
	return 0;
}

int run_new_command(RIO *io, RIODesc *iodesc, const char *buf) {
	if (r_str_startswith (buf, "dm")) {
		if (buf[2] == ' ') {
			// use \p pid
			char *cmd = r_str_newf ("p %d", atoi (buf + 2));
			run_old_command (io, iodesc, cmd);
			free (cmd);
		} else if (r2k_struct.beid == 1) {
			// use \p pid
			char *cmd = r_str_newf ("p %d", r2k_struct.pid);
			run_old_command (io, iodesc, cmd);
			free (cmd);
		} else {
			// use \M
			run_old_command (io, iodesc, "M");
		}
		return 1;
	}
	if (r_str_startswith (buf, "dr")) {
		run_old_command (io, iodesc, "R");
		return 1;
	}
	if (r_str_startswith (buf, "dR")) {
		run_old_command (io, iodesc, "Rp");
		return 1;
	}
	if (r_str_startswith (buf, "dp")) {
		if (buf[2] == ' ') {
			r2k_struct.pid = atoi (buf + 3);
		} else {
			io->cb_printf ("%d\n", r2k_struct.pid);
		}
		return 1;
	}
	if (r_str_startswith (buf, "e r2k.io")) {
		if (strchr (buf, '?')) {
			io->cb_printf ("0: Linear memory\n");
			io->cb_printf ("1: Process memory\n");
			io->cb_printf ("2: Physical memory\n");
			return 1;
		}
		const char *eq = strchr (buf, '=');
		if (eq) {
			int v = atoi (eq + 1);
			int p = r2k_struct.pid;
			char *cmd = r_str_newf ("b %d %d", v, p);
			run_old_command (io, iodesc, cmd);
			free (cmd);
		} else {
			run_new_command (io, iodesc, "dp");
		}
		return 1;
	}
	if (r_str_startswith (buf, "e r2k.wp")) {
		if (strchr (buf, '?')) {
			io->cb_printf ("<bool> enable write protection (disabled by default)\n");
			return 1;
		}
		const char *eq = strchr (buf, '=');
		if (eq) {
			int v = atoi (eq + 1);
			r2k_struct.wp = (ut8)v;
		} else {
			io->cb_printf ("%s", r_str_bool (r2k_struct.wp));
		}
		return 1;
	}
	return 0;
}

int run_ioctl_command(RIO *io, RIODesc *iodesc, const char *buf) {
	buf = r_str_ichr ((char *) buf, ' ');

	if (!run_new_command (io, iodesc, buf)) {
		return run_old_command (io, iodesc, buf);
	}
	return 0;
}

#endif
