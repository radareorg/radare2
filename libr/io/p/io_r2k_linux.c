#include "io_r2k_linux.h"

static char* getargpos (const char *buf, int pos) {
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

static size_t getvalue (const char *buf, int pos) {
	size_t ret;
	buf = getargpos (buf, pos);
	if (buf) {
		ret = strtoul (buf, 0, 0);
	} else {
		ret = -1;
	}
	return ret;
}

static void print_help (RIO *io, ut64 num, int p_usage) {
	int i = 0;
	const char* usage = "Usage:   =![MprRw][lpP] [args...]";
	const char* help_msg[] = {"=!M                      Print kernel memory map",
				  "=!p      pid             Print process information",
				  "=!rl     addr len        Read from linear address",
				  "=!rp     pid addr len    Read from process address",
				  "=!rP     addr len        Read physical address",
				  "=!R                      Print control registers",
				  "=!wl[x]  addr input      Write at linear address. Use =!wlx for input in hex",
				  "=!wp[x]  pid addr input  Write at process address. Use =!wpx for input in hex",
				  "=!wP[x]  addr input      Write at physical address. Use =!wPx for input in hex"};
	if (p_usage) {
		io->cb_printf ("%s\n", usage);
	}
	for (i = 0; i < sizeof (ut64) * 8 && i < (sizeof (help_msg) / sizeof (char*)); i++) {
		if (num & (1<<i)) {
			io->cb_printf ("%s\n", help_msg[i]);
		}
	}
}

int ReadMemory (RIO *io, RIODesc *iodesc, int ioctl_n, size_t pid, size_t address, ut8 *buf, int len) {
	int ret = -1;
	if (iodesc && iodesc->fd > 0 && buf) {
		struct r2k_data data;

		data.pid = pid;
		data.addr = address;
		data.len = len;
		data.buff = (ut8 *) calloc (len + 1, 1);
		if (!data.buff) {
			return -1;
		}

		ret = ioctl (iodesc->fd, ioctl_n, &data);
		if (!ret) {
			memcpy (buf, data.buff, len);
			ret = len;
		} else {
			//eprintf ("Read failed. ioctl err: %s\n", strerror (errno));
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

int WriteMemory (RIO *io, RIODesc *iodesc, int ioctl_n, size_t pid, ut64 address, const ut8 *buf, int len) {
	int ret = -1;
	if (iodesc && iodesc->fd > 0 && buf) {
		struct r2k_data data;

		data.pid = pid;
		data.addr = address;
		data.len = len;
		data.buff = (ut8 *) calloc (len + 1, 1);
		if (!data.buff) {
			return -1;
		}

		memcpy (data.buff, buf, len);
		ret = ioctl (iodesc->fd, ioctl_n, &data);
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

int run_ioctl_command(RIO *io, RIODesc *iodesc, const char *buf) {
	int ret, inphex, ioctl_n;
	size_t pid, addr, len;
	ut8 *databuf = NULL;
	buf = r_str_ichr ((char *) buf, ' ');

	switch (*buf) {
	case 'r':
		{
			RPrint *print = r_print_new ();
			switch (buf[1]) {
			case 'l':
				//read linear address
				//=! rl addr len
				if (buf[2] != ' ') {
					print_help (io, 0x4, 0);
					goto end;
				} else {
					pid = 0;
					addr = getvalue (buf, 1);
					len = getvalue (buf, 2);
					if (addr == -1 || len == -1) {
						io->cb_printf ("Invalid number of arguments.\n");
						print_help (io, 0x4, 0);
						goto end;
					}
					ioctl_n = IOCTL_READ_KERNEL_MEMORY;
					break;
				}
			case 'p':
				//read process address
				//=! rp pid address len
				if (buf[2] != ' ') {
					print_help (io, 0x8, 0);
					goto end;
				} else {
					pid = getvalue (buf, 1);
					addr = getvalue (buf, 2);
					len = getvalue (buf, 3);
					if (pid == -1 || addr == -1 || len == -1) {
						io->cb_printf ("Invalid number of arguments.\n");
						print_help (io, 0x8, 0);
						goto end;;
					}
					ioctl_n = IOCTL_READ_PROCESS_ADDR;
					break;
				}
			case 'P':
				//read physical address
				//=! rP address len
				if (buf[2] != ' ') {
					print_help (io, 0x10, 0);
					goto end;
				} else {
					pid = 0;
					addr = getvalue (buf, 1);
					len = getvalue (buf, 2);
					if (addr == -1 || len == -1) {
						io->cb_printf ("Invalid number of arguments.\n");
						print_help (io, 0x10, 0);
						goto end;
					}
					ioctl_n = IOCTL_READ_PHYSICAL_ADDR;
					break;
				}
			default:
				print_help(io, 0x1c, 0);
				r_print_free (print);
				goto end;
			}
			databuf = (ut8 *) calloc (len + 1, 1);
			if (databuf) {
				ret = ReadMemory (io, iodesc, ioctl_n, pid, addr, databuf, len);
				if (ret > 0) {
					r_print_hexdump (print, addr, (const ut8 *) databuf, ret, 16, 1);
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
			//=! wl addr str
			if ((inphex && buf[3] != ' ') || (!inphex && buf[2] != ' ')) {
				print_help (io, 0x40, 0);
				goto end;
			} else {
				pid = 0;
				addr = getvalue (buf, 1);
				buf = getargpos (buf, 2);
				if (addr == -1 || !buf) {
					io->cb_printf ("Invalid number of arguments.\n");
					print_help (io, 0x40, 0);
					goto end;
				}
				ioctl_n = IOCTL_WRITE_KERNEL_MEMORY;
				break;
			}
		case 'p':
			//write process address
			//=! wp pid address str
			if ((inphex && buf[3] != ' ') || (!inphex && buf[2] != ' ')) {
				print_help (io, 0x80, 0);
				goto end;
			} else {
				pid = getvalue (buf, 1);
				addr = getvalue (buf, 2);
				buf = getargpos (buf, 3);
				if (pid == -1 || addr == -1 || !buf) {
					io->cb_printf ("Invalid number of arguments.\n");
					print_help (io, 0x80, 0);
					goto end;
				}
				ioctl_n = IOCTL_WRITE_PROCESS_ADDR;
				break;
			}
		case 'P':
			//write physical address
			//=! wP address str
			if ((inphex && buf[3] != ' ') || (!inphex && buf[2] != ' ')) {
				print_help (io, 0x100, 0);
				goto end;
			} else {
				pid = 0;
				addr = getvalue (buf, 1);
				buf = getargpos (buf, 2);
				if (addr == -1 || !buf) {
					io->cb_printf ("Invalid number of arguments.\n");
					print_help (io, 0x100, 0);
					goto end;
				}
				ioctl_n = IOCTL_WRITE_PHYSICAL_ADDR;
				break;
			}
		default:
			print_help(io, 0x1c0, 0);
			goto end;
		}
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
		} else {
			eprintf ("Failed to allocate buffer.\n");
		}
		break;
	case 'M':
		{
			//Print kernel memory map.
			//=! M
			if ((buf[1] == ' ' && getargpos (buf, 1)) || (buf[1] && buf[1] != ' ')) {
				print_help (io, 0x1, 0);
				goto end;
			}
			int i, j;
			struct r2k_kernel_maps map_data;
			struct r2k_kernel_map_info *info;
			long page_size = sysconf (_SC_PAGESIZE);

			ioctl_n = IOCTL_GET_KERNEL_MAP;
			ret = ioctl (iodesc->fd, ioctl_n, &map_data);

			if (ret < 0) {
				io->cb_printf ("ioctl err: %s\n", strerror (errno));
				break;
			}

			io->cb_printf ("map_data.size: %d, map_data.n_entries: %d\n", map_data.size, map_data.n_entries);
			info = mmap (0, map_data.size, PROT_READ, MAP_SHARED, iodesc->fd, 0);
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
					io->cb_printf ("\tphys_addr: 0x%"PFMT64x"\n", (ut64) in->phys_addr[j]);
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
			//=! R
			if (getargpos (buf, 1)) {
				print_help (io, 0x20, 0);
				goto end;
			}
			struct r2k_control_reg reg_data;
			ioctl_n = IOCTL_READ_CONTROL_REG;
			ret = ioctl (iodesc->fd, ioctl_n, &reg_data);

			if (ret) {
				io->cb_printf ("ioctl err: %s\n", strerror (errno));
				break;
			}

#if __i386__ || __x86_64__
			//Print cr1 as null instead of random value from kernel land.
			reg_data.cr1 = 0;
			io->cb_printf ("cr0 = 0x%"PFMT64x"\n", (ut64) reg_data.cr0);
			io->cb_printf ("cr1 = 0x%"PFMT64x"\n", (ut64) reg_data.cr1);
			io->cb_printf ("cr2 = 0x%"PFMT64x"\n", (ut64) reg_data.cr2);
			io->cb_printf ("cr3 = 0x%"PFMT64x"\n", (ut64) reg_data.cr3);
			io->cb_printf ("cr4 = 0x%"PFMT64x"\n", (ut64) reg_data.cr4);
#if __x86_64__
			io->cb_printf ("cr8 = 0x%"PFMT64x"\n", (ut64) reg_data.cr8);
#endif
#elif __arm__
			io->cb_printf ("ttbr0 = 0x%"PFMT64x"\n", (ut64) reg_data.ttbr0);
			io->cb_printf ("ttbr1 = 0x%"PFMT64x"\n", (ut64) reg_data.ttbr1);
			io->cb_printf ("ttbcr = 0x%"PFMT64x"\n", (ut64) reg_data.ttbcr);
			io->cb_printf ("c1    = 0x%"PFMT64x"\n", (ut64) reg_data.c1);
			io->cb_printf ("c3    = 0x%"PFMT64x"\n", (ut64) reg_data.c3);
#elif __arm64__ || __aarch64__
			io->cb_printf ("sctlr_el1 = 0x%"PFMT64x"\n", (ut64) reg_data.sctlr_el1);
			io->cb_printf ("ttbr0_el1 = 0x%"PFMT64x"\n", (ut64) reg_data.ttbr0_el1);
			io->cb_printf ("ttbr1_el1 = 0x%"PFMT64x"\n", (ut64) reg_data.ttbr1_el1);
			io->cb_printf ("tcr_el1   = 0x%"PFMT64x"\n", (ut64) reg_data.tcr_el1);
#endif
		}
		break;
	case 'p':
		{
			//Print process info
			//=! p pid
			if (*(buf + 1) != ' ') {
				print_help (io, 0x2, 0);
				goto end;
			}
			int i;
			struct r2k_proc_info proc_data;
			pid = getvalue (buf, 1);
			if (pid == -1) {
				io->cb_printf ("Invalid number of arguments.\n");
				print_help (io, 0x2, 0);
				break;
			}
			proc_data.pid = pid;
			ioctl_n = IOCTL_PRINT_PROC_INFO;

			ret = ioctl (iodesc->fd, ioctl_n, &proc_data);
			if (ret) {
				io->cb_printf ("ioctl err: %s\n", strerror (errno));
				break;
			}

			io->cb_printf ("pid = %d\nprocess name = %s\n", proc_data.pid, proc_data.comm);
			for (i = 0; i < 4096;) {
				if (!proc_data.vmareastruct[i] && !proc_data.vmareastruct[i+1]) {
					break;
				}
				io->cb_printf ("%08"PFMT64x"-%08"PFMT64x" %c%c%c%c %08"PFMT64x" %02x:%02x %-8"PFMT64u"",
						(ut64) proc_data.vmareastruct[i], (ut64) proc_data.vmareastruct[i+1],
						proc_data.vmareastruct[i+2] & VM_READ ? 'r' : '-',
						proc_data.vmareastruct[i+2] & VM_WRITE ? 'w' : '-',
						proc_data.vmareastruct[i+2] & VM_EXEC ? 'x' : '-',
						proc_data.vmareastruct[i+2] & VM_MAYSHARE ? 's' : 'p',
						(ut64) proc_data.vmareastruct[i+3], proc_data.vmareastruct[i+4],
						proc_data.vmareastruct[i+5], (ut64) proc_data.vmareastruct[i+6]);
				i += 7;
				io->cb_printf ("\t%s\n", &(proc_data.vmareastruct[i]));
				i += (strlen(&(proc_data.vmareastruct[i])) - 1 + sizeof (size_t)) / sizeof (size_t);
			}
			io->cb_printf ("STACK BASE ADDRESS = 0x%"PFMT64x"\n", (void *) proc_data.stack);
		}
		break;
	default:
		{
			print_help (io, 0x1ff, 1);
		}
	}
 end:
	free (databuf);
	return 0;
}
