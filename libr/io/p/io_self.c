/* radare - LGPL - Copyright 2014-2020 - pancake */

#include <r_userconf.h>
#include <r_io.h>
#include <r_lib.h>
#include <r_cons.h>

#if DEBUGGER
#if __APPLE__
#include <mach/vm_map.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_interface.h>
#include <mach/mach_traps.h>
#include <mach/mach_types.h>
//#include <mach/mach_vm.h>
#include <mach/mach_error.h>
#include <mach/task.h>
#include <mach/task_info.h>
void macosx_debug_regions (RIO *io, task_t task, mach_vm_address_t address, int max);
#elif __BSD__
#if __FreeBSD__
#include <sys/sysctl.h>
#include <sys/user.h>
#include <libutil.h>
#elif __OpenBSD__ || __NetBSD__
#include <sys/sysctl.h>
#elif __DragonFly__
#include <sys/types.h>
#include <sys/user.h>
#include <sys/sysctl.h>
#include <kvm.h>
#endif
#include <errno.h>
bool bsd_proc_vmmaps(RIO *io, int pid);
#endif
#ifdef __HAIKU__
#include <kernel/image.h>
#endif
#if defined __sun && defined _LP64
#define _STRUCTURED_PROC 1 // to access newer proc data with additional fields
#include <sys/procfs.h>
#include <libproc.h>
#endif
#ifdef _MSC_VER
#include <process.h>  // to compile getpid for msvc windows
#include <psapi.h>
#endif

typedef struct {
	char *name;
	ut64 from;
	ut64 to;
	int perm;
} RIOSelfSection;

static RIOSelfSection self_sections[1024];
static int self_sections_count = 0;
static bool mameio = false;

static int self_in_section(RIO *io, ut64 addr, int *left, int *perm) {
	int i;
	for (i = 0; i < self_sections_count; i++) {
		if (addr >= self_sections[i].from && addr < self_sections[i].to) {
			if (left) {
				*left = self_sections[i].to-addr;
			}
			if (perm) {
				*perm = self_sections[i].perm;
			}
			return true;
		}
	}
	return false;
}

static int update_self_regions(RIO *io, int pid) {
	self_sections_count = 0;
#if __APPLE__
	mach_port_t task;
	kern_return_t rc;
	rc = task_for_pid (mach_task_self (), pid, &task);
	if (rc) {
		eprintf ("task_for_pid failed\n");
		return false;
	}
	macosx_debug_regions (io, task, (size_t)1, 1000);
	return true;
#elif __linux__
	char *pos_c;
	int i, l, perm;
	char path[1024], line[1024];
	char region[100], region2[100], perms[5];
	snprintf (path, sizeof (path) - 1, "/proc/%d/maps", pid);
	FILE *fd = r_sandbox_fopen (path, "r");
	if (!fd) {
		return false;
	}

	while (!feof (fd)) {
		line[0]='\0';
		if (!fgets (line, sizeof (line), fd)) {
			break;
		}
		if (line[0] == '\0') {
			break;
		}
		path[0]='\0';
		strcpy (region, "0x");
		sscanf (line, "%s %s %*s %*s %*s %[^\n]", region + 2, perms, path);
		pos_c = strchr (region + 2, '-');
		if (pos_c) {
			*pos_c++ = 0;
			memcpy (region2, "0x", 2);
			l = strlen (pos_c);
			memcpy (region2 + 2, pos_c, l);
			region2[2 + l] = 0;
		} else {
			region2[0] = 0;
		}
		perm = 0;
		for (i = 0; i < 4 && perms[i]; i++) {
			switch (perms[i]) {
			case 'r': perm |= R_PERM_R; break;
			case 'w': perm |= R_PERM_W; break;
			case 'x': perm |= R_PERM_X; break;
			}
		}
		self_sections[self_sections_count].from = r_num_get (NULL, region);
		self_sections[self_sections_count].to = r_num_get (NULL, region2);
		self_sections[self_sections_count].name = strdup (path);
		self_sections[self_sections_count].perm = perm;
		self_sections_count++;
		r_num_get (NULL, region2);
	}
	fclose (fd);

	return true;
#elif __BSD__
	return bsd_proc_vmmaps(io, pid);
#elif __HAIKU__
	image_info ii;
	int32_t cookie = 0;

	while (get_next_image_info (0, &cookie, &ii) == B_OK) {
		self_sections[self_sections_count].from = (ut64)ii.text;
		self_sections[self_sections_count].to = (ut64)((char*)ii.text + ii.text_size);
		self_sections[self_sections_count].name = strdup (ii.name);
		self_sections[self_sections_count].perm = 0;
		self_sections_count++;
	}
	return true;
#elif __sun && defined _LP64
	char path[PATH_MAX];
	int err;
	pid_t self = getpid ();
	struct ps_prochandle *Pself = Pgrab(self, PGRAB_RDONLY, &err);

	if (!Pself) {
		return false;
	}

	snprintf (path, sizeof (path), "/proc/%d/map",  self);
	size_t hint = (1 << 20);
	int fd = open (path, O_RDONLY);

	if (fd == -1) {
		return false;
	}

	ssize_t rd;
	prmap_t *c, *map = malloc (hint);

	if (!map) {
		return false;
	}

	while (hint > 0 && (rd = pread (fd, map, hint, 0)) == hint) {
		hint <<= 1;
		prmap_t *tmp = realloc (map, hint);
		if (!tmp) {
			free (map);
			return false;
		}

		map = tmp;
	}

	for (c = map; rd > 0; c ++, rd -= sizeof (prmap_t)) {
		char name[PATH_MAX];
		Pobjname (Pself, c->pr_vaddr, name, sizeof (name));

		if (name[0] == '\0') {
			// If no name, it is an anonymous map
			strcpy (name, "[anon]");
		}

		int perm = 0;

		if ((c->pr_mflags & MA_READ)) {
			perm |= R_PERM_R;
		}
		if ((c->pr_mflags & MA_WRITE)) {
			perm |= R_PERM_W;
		}
		if ((c->pr_mflags & MA_EXEC)) {
			perm |= R_PERM_X;
		}

		self_sections[self_sections_count].from = (ut64)c->pr_vaddr;
		self_sections[self_sections_count].to = (ut64)(c->pr_vaddr + c->pr_size);
		self_sections[self_sections_count].name = strdup (name);
		self_sections[self_sections_count].perm = perm;
		self_sections_count++;
	}

	free (map);
	close (fd);
	return true;
#else
#ifdef _MSC_VER
	int perm;
	const size_t name_size = 1024;
	PVOID to = NULL;
	MEMORY_BASIC_INFORMATION mbi;
	HANDLE h = OpenProcess (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
	LPTSTR name = calloc (name_size, sizeof (TCHAR));
	if (!name) {
		R_LOG_ERROR ("io_self/update_self_regions: Failed to allocate memory.\n");
		CloseHandle (h);
		return false;
	}
	while (VirtualQuery (to, &mbi, sizeof (mbi))) {
		to = (PBYTE) mbi.BaseAddress + mbi.RegionSize;
		perm = 0;
		perm |= mbi.Protect & PAGE_READONLY ? R_PERM_R : 0;
		perm |= mbi.Protect & PAGE_READWRITE ? R_PERM_RW : 0;
		perm |= mbi.Protect & PAGE_EXECUTE ? R_PERM_X : 0;
		perm |= mbi.Protect & PAGE_EXECUTE_READ ? R_PERM_RX : 0;
		perm |= mbi.Protect & PAGE_EXECUTE_READWRITE ? R_PERM_RWX : 0;
		perm = mbi.Protect & PAGE_NOACCESS ? 0 : perm;
		if (perm && !GetMappedFileName (h, (LPVOID) mbi.BaseAddress, name, name_size)) {
			name[0] = '\0';
		}
		self_sections[self_sections_count].from = (ut64) mbi.BaseAddress;
		self_sections[self_sections_count].to = (ut64) to;
		self_sections[self_sections_count].name = r_sys_conv_win_to_utf8 (name);
		self_sections[self_sections_count].perm = perm;
		self_sections_count++;
		name[0] = '\0';
	}
	free (name);
	CloseHandle (h);
	return true;
#else
	#warning not yet implemented for this platform
#endif
	return false;
#endif
}

static bool __plugin_open(RIO *io, const char *file, bool many) {
	return (!strncmp (file, "self://", 7));
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	int ret, pid = getpid ();
	if (r_sandbox_enable (0)) {
		return NULL;
	}
	io->va = true; // nop
	ret = update_self_regions (io, pid);
	if (ret) {
		return r_io_desc_new (io, &r_io_plugin_self,
			file, rw, mode, NULL);
	}
	return NULL;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len) {
	int left, perm;
	if (self_in_section (io, io->off, &left, &perm)) {
		if (perm & R_PERM_R) {
			int newlen = R_MIN (len, left);
			ut8 *ptr = (ut8*)(size_t)io->off;
			memcpy (buf, ptr, newlen);
			return newlen;
		}
	}
	return 0;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	if (fd->perm & R_PERM_W) {
		int left, perm;
		if (self_in_section (io, io->off, &left, &perm)) {
			int newlen = R_MIN (len, left);
			ut8 *ptr = (ut8*)(size_t)io->off;
			if (newlen > 0) {
				memcpy (ptr, buf, newlen);
			}
			return newlen;
		}
	}
	return -1;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case SEEK_SET: return offset;
	case SEEK_CUR: return io->off + offset;
	case SEEK_END: return UT64_MAX;
	}
	return offset;
}

static int __close(RIODesc *fd) {
	return 0;
}

static void got_alarm(int sig) {
#if !defined(__WINDOWS__)
	// !!! may die if not running from r2preload !!! //
	kill (getpid (), SIGUSR1);
#endif
}

static char *__system(RIO *io, RIODesc *fd, const char *cmd) {
	if (!strcmp (cmd, "pid")) {
		return r_str_newf ("%d", fd->fd);
	} else if (!strncmp (cmd, "pid", 3)) {
		/* do nothing here */
#if !defined(__WINDOWS__)
	} else if (!strncmp (cmd, "kill", 4)) {
		if (r_sandbox_enable (false)) {
			eprintf ("This is unsafe, so disabled by the sandbox\n");
			return NULL;
		}
		/* do nothing here */
		kill (getpid (), SIGKILL);
#endif
	} else if (!strncmp (cmd, "call ", 5)) {
		size_t cbptr = 0;
		if (r_sandbox_enable (false)) {
			eprintf ("This is unsafe, so disabled by the sandbox\n");
			return NULL;
		}
		ut64 result = 0;
		char *argv = strdup (cmd + 5);
		int argc = r_str_word_set0 (argv);
		if (argc == 0) {
			eprintf ("Usage: =!call [fcnptr] [a0] [a1] ...\n");
			free (argv);
			return NULL;
		}
		const char *sym = r_str_word_get0 (argv, 0);
		if (sym) {
			const char *symbol = cmd + 6;
			void *lib = r_lib_dl_open (NULL);
			void *ptr = r_lib_dl_sym (lib, symbol);
			if (ptr) {
				cbptr = (ut64)(size_t)ptr;
			} else {
				cbptr = r_num_math (NULL, symbol);
			}
			r_lib_dl_close (lib);
		}
		if (argc == 1) {
			size_t (*cb)() = (size_t(*)())cbptr;
			if (cb) {
				result = cb ();
			} else {
				eprintf ("No callback defined\n");
			}
		} else if (argc == 2) {
			size_t (*cb)(size_t a0) = (size_t(*)(size_t))cbptr;
			if (cb) {
				ut64 a0 = r_num_math (NULL, r_str_word_get0 (argv, 1));
				result = cb (a0);
			} else {
				eprintf ("No callback defined\n");
			}
		} else if (argc == 3) {
			size_t (*cb)(size_t a0, size_t a1) = (size_t(*)(size_t,size_t))cbptr;
			ut64 a0 = r_num_math (NULL, r_str_word_get0 (argv, 1));
			ut64 a1 = r_num_math (NULL, r_str_word_get0 (argv, 2));
			if (cb) {
				result = cb (a0, a1);
			} else {
				eprintf ("No callback defined\n");
			}
		} else if (argc == 4) {
			size_t (*cb)(size_t a0, size_t a1, size_t a2) = \
				(size_t(*)(size_t,size_t,size_t))cbptr;
			ut64 a0 = r_num_math (NULL, r_str_word_get0 (argv, 1));
			ut64 a1 = r_num_math (NULL, r_str_word_get0 (argv, 2));
			ut64 a2 = r_num_math (NULL, r_str_word_get0 (argv, 3));
			if (cb) {
				result = cb (a0, a1, a2);
			} else {
				eprintf ("No callback defined\n");
			}
		} else if (argc == 5) {
			size_t (*cb)(size_t a0, size_t a1, size_t a2, size_t a3) = \
				(size_t(*)(size_t,size_t,size_t,size_t))cbptr;
			ut64 a0 = r_num_math (NULL, r_str_word_get0 (argv, 1));
			ut64 a1 = r_num_math (NULL, r_str_word_get0 (argv, 2));
			ut64 a2 = r_num_math (NULL, r_str_word_get0 (argv, 3));
			ut64 a3 = r_num_math (NULL, r_str_word_get0 (argv, 4));
			if (cb) {
				result = cb (a0, a1, a2, a3);
			} else {
				eprintf ("No callback defined\n");
			}
		} else if (argc == 6) {
			size_t (*cb)(size_t a0, size_t a1, size_t a2, size_t a3, size_t a4) = \
				(size_t(*)(size_t,size_t,size_t,size_t,size_t))cbptr;
			ut64 a0 = r_num_math (NULL, r_str_word_get0 (argv, 1));
			ut64 a1 = r_num_math (NULL, r_str_word_get0 (argv, 2));
			ut64 a2 = r_num_math (NULL, r_str_word_get0 (argv, 3));
			ut64 a3 = r_num_math (NULL, r_str_word_get0 (argv, 4));
			ut64 a4 = r_num_math (NULL, r_str_word_get0 (argv, 5));
			if (cb) {
				result = cb (a0, a1, a2, a3, a4);
			} else {
				eprintf ("No callback defined\n");
			}
		} else {
			eprintf ("Unsupported number of arguments in call\n");
		}
		eprintf ("RES %"PFMT64d"\n", result);
		free (argv);
#if !defined(__WINDOWS__)
	} else if (!strncmp (cmd, "alarm ", 6)) {
		struct itimerval tmout;
		int secs = atoi (cmd + 6);
		r_return_val_if_fail (secs >= 0, NULL);

		tmout.it_value.tv_sec = secs;
		tmout.it_value.tv_usec = 0;
		r_sys_signal (SIGALRM, got_alarm);
		setitimer (ITIMER_REAL, &tmout, NULL);
#else
#ifdef _MSC_VER
#pragma message ("self:// alarm is not implemented for this platform yet")
#else
	#warning "self:// alarm is not implemented for this platform yet"
#endif
#endif
	} else if (!strncmp (cmd, "dlsym ", 6)) {
		const char *symbol = cmd + 6;
		void *lib = r_lib_dl_open (NULL);
		void *ptr = r_lib_dl_sym (lib, symbol);
		eprintf ("(%s) 0x%08"PFMT64x"\n", symbol, (ut64)(size_t)ptr);
		r_lib_dl_close (lib);
	} else if (!strcmp (cmd, "mameio")) {
		void *lib = r_lib_dl_open (NULL);
		void *ptr = r_lib_dl_sym (lib, "_ZN12device_debug2goEj");
	//	void *readmem = dlsym (lib, "_ZN23device_memory_interface11memory_readE16address_spacenumjiRy");
		// readmem(0, )
		if (ptr) {
		//	gothis =
			eprintf ("TODO: No MAME IO implemented yet\n");
			mameio = true;
		} else {
			eprintf ("This process is not a MAME!");
		}
		r_lib_dl_close (lib);
	} else if (!strcmp (cmd, "maps")) {
		int i;
		for (i = 0; i < self_sections_count; i++) {
			eprintf ("0x%08"PFMT64x" - 0x%08"PFMT64x" %s %s\n",
				self_sections[i].from, self_sections[i].to,
				r_str_rwx_i (self_sections[i].perm),
				self_sections[i].name);
		}
	} else {
		eprintf ("|Usage: =![cmd] [args]\n");
		eprintf ("| =!pid               show getpid()\n");
		eprintf ("| =!maps              show map regions\n");
		eprintf ("| =!kill              commit suicide\n");
#if !defined(__WINDOWS__)
		eprintf ("| =!alarm [secs]      setup alarm signal to raise r2 prompt\n");
#endif
		eprintf ("| =!dlsym [sym]       dlopen\n");
		eprintf ("| =!call [sym] [...]  nativelly call a function\n");
		eprintf ("| =!mameio            enter mame IO mode\n");
	}
	return NULL;
}

RIOPlugin r_io_plugin_self = {
	.name = "self",
	.desc = "Read memory from self",
	.uris = "self://",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.write = __write,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_mach,
	.version = R2_VERSION
};
#endif

#if __APPLE__
// mach/mach_vm.h not available for iOS
kern_return_t mach_vm_region_recurse (
        vm_map_t target_task,
        mach_vm_address_t *address,
        mach_vm_size_t *size,
        natural_t *depth,
        vm_region_recurse_info_t info,
        mach_msg_type_number_t *infoCnt
);
// TODO: unify that implementation in a single reusable place
void macosx_debug_regions (RIO *io, task_t task, mach_vm_address_t address, int max) {
	kern_return_t kret;

	struct vm_region_submap_info_64 info;
	mach_vm_size_t size;

	natural_t nsubregions = 1;
	mach_msg_type_number_t count;

	int num_printed = 0;
	static const char *share_mode[] = {
		"null",
		"cow",
		"private",
		"empty",
		"shared",
		"true shared",
		"prv aliased",
		"shm aliased",
		"large",
	};

	for (;;) {
		count = VM_REGION_SUBMAP_INFO_COUNT_64;
		kret = mach_vm_region_recurse (task, &address, &size, &nsubregions,
				(vm_region_recurse_info_t) &info, &count);
		if (kret != KERN_SUCCESS) {
			if (!num_printed) {
				eprintf ("mach_vm_region_recurse: Error %d - %s", kret, mach_error_string(kret));
			}
			break;
		}

		if (!info.is_submap) {
			int print_size;
			char *print_size_unit;
			int perm = 0;

			io->cb_printf (num_printed? "   ... ": "Region ");
			//findListOfBinaries(task, prev_address, prev_size);
			/* Quick hack to show size of segment, which GDB does not */
			print_size = size;
			if (print_size > 1024) { print_size /= 1024; print_size_unit = "K"; }
			if (print_size > 1024) { print_size /= 1024; print_size_unit = "M"; }
			if (print_size > 1024) { print_size /= 1024; print_size_unit = "G"; }
			/* End Quick hack */
			io->cb_printf (" %p - %p [%d%s](%x/%x; %d, %s, %u p. res, %u p. swp, %u p. drt, %u ref)",
					(void*)(size_t)(address),
					(void*)(size_t)(address + size),
					print_size,
					print_size_unit,
					info.protection,
					info.max_protection,
					info.inheritance,
					share_mode[info.share_mode],
					info.pages_resident,
					info.pages_swapped_out,
					info.pages_dirtied,
					info.ref_count);

			if (info.protection & VM_PROT_READ) {
				perm |= R_PERM_R;
			}
			if (info.protection & VM_PROT_WRITE) {
				perm |= R_PERM_W;
			}
			if (info.protection & VM_PROT_EXECUTE) {
				perm |= R_PERM_X;
			}

			self_sections[self_sections_count].from = address;
			self_sections[self_sections_count].to = address+size;
			self_sections[self_sections_count].perm = perm;
			self_sections_count++;
			if (nsubregions > 1) {
				io->cb_printf (" (%d sub-regions)", nsubregions);
			}
			io->cb_printf ("\n");

			num_printed++;
			address += size;
			size = 0;
		} else {
			nsubregions++;
		}

		if ((max > 0) && (num_printed >= max)) {
			eprintf ("Max %d num_printed %d\n", max, num_printed);
			break;
		}
	}
}
#elif __BSD__
bool bsd_proc_vmmaps(RIO *io, int pid) {
#if __FreeBSD__
	size_t size;
	bool ret = false;
	int mib[4] = {
		CTL_KERN, KERN_PROC, KERN_PROC_VMMAP, pid
	};
	int s = sysctl (mib, 4, NULL, &size, NULL, 0);
	if (s == -1) {
		eprintf ("sysctl failed: %s\n", strerror (errno));
		return false;
	}

	size = size * 4 / 3;
	ut8 *p = malloc (size);
	if (p) {
		s = sysctl (mib, 4, p, &size, NULL, 0);
		if (s == -1) {
			eprintf ("sysctl failed: %s\n", strerror (errno));
			goto exit;
		}
		ut8 *p_start = p;
		ut8 *p_end = p + size;

		while (p_start < p_end) {
			struct kinfo_vmentry *entry = (struct kinfo_vmentry *)p_start;
			size_t sz = entry->kve_structsize;
			int perm = 0;
			if (sz == 0) {
				break;
			}

			if (entry->kve_protection & KVME_PROT_READ) {
				perm |= R_PERM_R;
			}
			if (entry->kve_protection & KVME_PROT_WRITE) {
				perm |= R_PERM_W;
			}
			if (entry->kve_protection & KVME_PROT_EXEC) {
				perm |= R_PERM_X;
			}

			if (entry->kve_path[0] != '\0') {
				io->cb_printf (" %p - %p %s (%s)\n",
						(void *)entry->kve_start,
						(void *)entry->kve_end,
						r_str_rwx_i (perm),
						entry->kve_path);
			}

			self_sections[self_sections_count].from = entry->kve_start;
			self_sections[self_sections_count].to = entry->kve_end;
			self_sections[self_sections_count].name = strdup (entry->kve_path);
			self_sections[self_sections_count].perm = perm;
			self_sections_count++;
			p_start += sz;
		}

		ret = true;
	} else {
		eprintf ("buffer allocation failed\n");
	}

exit:
	free (p);
	return ret;
#elif __OpenBSD__
	size_t size = sizeof (struct kinfo_vmentry);
	struct kinfo_vmentry entry = { .kve_start = 0 };
	ut64 endq = 0;
	int mib[3] = {
		CTL_KERN, KERN_PROC_VMMAP, pid
	};
	int s = sysctl (mib, 3, &entry, &size, NULL, 0);
	if (s == -1) {
		eprintf ("sysctl failed: %s\n", strerror (errno));
		return false;
	}
	endq = size;

	while (sysctl (mib, 3, &entry, &size, NULL, 0) != -1) {
		int perm = 0;
		if (entry.kve_end == endq) {
			break;
		}

		if (entry.kve_protection & KVE_PROT_READ) {
			perm |= R_PERM_R;
		}
		if (entry.kve_protection & KVE_PROT_WRITE) {
			perm |= R_PERM_W;
		}
		if (entry.kve_protection & KVE_PROT_EXEC) {
			perm |= R_PERM_X;
		}

		io->cb_printf (" %p - %p %s [off. %zu]\n",
				(void *)entry.kve_start,
				(void *)entry.kve_end,
				r_str_rwx_i (perm),
				entry.kve_offset);

		self_sections[self_sections_count].from = entry.kve_start;
		self_sections[self_sections_count].to = entry.kve_end;
		self_sections[self_sections_count].perm = perm;
		self_sections_count++;
		entry.kve_start = entry.kve_start + 1;
	}

	return true;
#elif __NetBSD__
	size_t size;
	bool ret = false;
	int mib[5] = {
		CTL_VM, VM_PROC, VM_PROC_MAP, pid, sizeof (struct kinfo_vmentry)
	};
	int s = sysctl (mib, 5, NULL, &size, NULL, 0);
	if (s == -1) {
		eprintf ("sysctl failed: %s\n", strerror (errno));
		return false;
	}

	size = size * 4 / 3;
	ut8 *p = malloc (size);
	if (p) {
		s = sysctl (mib, 5, p, &size, NULL, 0);
		if (s == -1) {
			eprintf ("sysctl failed: %s\n", strerror (errno));
			goto exit;
		}
		ut8 *p_start = p;
		ut8 *p_end = p + size;

		while (p_start < p_end) {
			struct kinfo_vmentry *entry = (struct kinfo_vmentry *)p_start;
			size_t sz = sizeof(*entry);
			int perm = 0;
			if (sz == 0) {
				break;
			}

			if (entry->kve_protection & KVME_PROT_READ) {
				perm |= R_PERM_R;
			}
			if (entry->kve_protection & KVME_PROT_WRITE) {
				perm |= R_PERM_W;
			}
			if (entry->kve_protection & KVME_PROT_EXEC) {
				perm |= R_PERM_X;
			}

			if (entry->kve_path[0] != '\0') {
				io->cb_printf (" %p - %p %s (%s)\n",
					(void *)entry->kve_start,
					(void *)entry->kve_end,
				 	r_str_rwx_i (perm),
					entry->kve_path);
			}

			self_sections[self_sections_count].from = entry->kve_start;
			self_sections[self_sections_count].to = entry->kve_end;
			self_sections[self_sections_count].name = strdup (entry->kve_path);
			self_sections[self_sections_count].perm = perm;
			self_sections_count++;
			p_start += sz;
		}

		ret = true;
	} else {
		eprintf ("buffer allocation failed\n");
	}

exit:
	free (p);
	return ret;
#elif __DragonFly__
	struct kinfo_proc *proc;
	struct vmspace vs;
	struct vm_map *map;
	struct vm_map_entry entry, *ep;
	struct proc p;
	int nm;
	char e[_POSIX2_LINE_MAX];

	kvm_t *k = kvm_openfiles (NULL, NULL, NULL, O_RDONLY, e);
	if (!k) {
		eprintf ("kvm_openfiles: `%s`\n", e);
		return false;
	}

	proc = kvm_getprocs (k, KERN_PROC_PID, pid, &nm);

	kvm_read (k, (uintptr_t)proc->kp_paddr, (ut8 *)&p, sizeof (p));
	kvm_read (k, (uintptr_t)p.p_vmspace, (ut8 *)&vs, sizeof (vs));

	map = &vs.vm_map;
	ep = kvm_vm_map_entry_first (k, map, &entry);

	while (ep) {
		int perm = 0;
		if (entry.protection & VM_PROT_READ) {
			perm |= R_PERM_R;
		}
		if (entry.protection & VM_PROT_WRITE) {
			perm |= R_PERM_W;
		}

		if (entry.protection & VM_PROT_EXECUTE) {
			perm |= R_PERM_X;
		}

		io->cb_printf (" %p - %p %s [off. %zu]\n",
				(void *)entry.ba.start,
				(void *)entry.ba.end,
				r_str_rwx_i (perm),
				entry.ba.offset);

		self_sections[self_sections_count].from = entry.ba.start;
		self_sections[self_sections_count].to = entry.ba.end;
		self_sections[self_sections_count].perm = perm;
		self_sections_count++;
		ep = kvm_vm_map_entry_next (k, ep, &entry);
	}

	kvm_close (k);
	return true;
#endif
}
#endif

#else // DEBUGGER
RIOPlugin r_io_plugin_self = {
	.name = "self",
	.desc = "read memory from myself using 'self://' (UNSUPPORTED)",
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_mach,
	.version = R2_VERSION
};
#endif
#endif
