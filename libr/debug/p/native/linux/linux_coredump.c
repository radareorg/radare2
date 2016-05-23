/* radare - LGPL - Copyright 2016 - Oscar Salvador */

#include <r_debug.h>
#include <sys/uio.h>
#include <bits/uio.h>
#include <sys/ptrace.h>
#include "linux_coredump.h"

static map_file_t mapping_file = { 0, 0 };

static inline char *prpsinfo_get_fname(char *buffer) {
	/* buffer contains: str\0str1\0str2\0... Here we're only interested in the first part of string, and strdup copies till it reaches a \0 */
	return strdup (buffer);
}

/* XXX looks like a dupe of isValidSection */
static bool is_a_kernel_mapping(char *map_name) {
	if (!strcmp (map_name, "[vsyscall]") ||
		!strcmp (map_name, "[vvar]")  ||
		!strcmp (map_name, "[vdso]")) {
		return true;
	}
	return false;
}

/* isn't checking if name[0] != '[' */
static bool isValidSection(const char *name) {
	return (name
		&& strcmp (name, "[vdso]")
		&& strcmp (name, "[vsyscall]")
		&& strcmp (name, "[vvar]")
		&& strcmp (name, "[stack]")
		&& strcmp (name, "[heap]"));
}

static const char *get_basename(const char *pfname, int len) {
	const char *p;
	for (p = pfname + len; p != pfname; p--) {
		if (*p == '/') {
			return (p + 1);
		}
	}
	return p;
}

static char *prpsinfo_get_psargs(char *buffer, char *pfname, int size_psargs, int len) {
	char paux[ELF_PRARGSZ];
	int i, bytes_left;
	char *p = r_mem_dup (pfname, size_psargs);
	if (!p) {
		return NULL;
	}
	bytes_left = strlen (pfname);
	buffer = strchr (buffer, '\0');

	for (i = 0; i + bytes_left < len && i + bytes_left < (size_psargs - 1); i++) {
		if (!buffer[i]) {
			buffer[i] = ' ';
		}
		paux[i] = buffer[i];
	}
	paux[i] = '\0';
	strncat (p, paux, size_psargs - bytes_left - 1);
	return p;
}

static void debug_print_prpsinfo(prpsinfo_t *p) {
	eprintf ("prpsinfo.pr_state: %d\n", p->pr_state);
	eprintf ("prpsinfo.pr_sname: %c\n", p->pr_sname);
	eprintf ("prpsinfo.pr_zomb: %d\n", p->pr_zomb);
	eprintf ("prpsinfo.pr_nice: %d\n", p->pr_nice);
	eprintf ("prpsinfo.pr_flags: %ld\n", p->pr_flag);
	eprintf ("prpsinfo.pr_uid: %d\n", p->pr_uid);
	eprintf ("prpsinfo.pr_gid: %d\n", p->pr_gid);
	eprintf ("prpsinfo.pr_pid: %d\n", p->pr_pid);
	eprintf ("prpsinfo.pr_ppid: %d\n", p->pr_ppid);
	eprintf ("prpsinfo.pr_pgrp: %d\n", p->pr_pgrp);
	eprintf ("prpsinfo.pr_sid: %d\n", p->pr_sid);
	eprintf ("prpsinfo.pr_fname: %s\n", p->pr_fname);
	eprintf ("prpsinfo.pr_psargs: %s\n", p->pr_psargs);
}

static prpsinfo_t *linux_get_prpsinfo(RDebug *dbg, proc_stat_content_t *proc_data) {
	const char *prog_states = "RSDTZW"; /* fs/binfmt_elf.c from kernel */
	const char *basename = NULL; /* pr_fname stores just the exec, withouth the path */
	char *buffer, *pfname = NULL, *ppsargs = NULL, *file = NULL;
	prpsinfo_t *p;
	pid_t mypid;
	int len;

	p = R_NEW0 (prpsinfo_t);
	if (!p) {
		eprintf ("Couldn't allocate memory for prpsinfo_t\n");
		return NULL;
	}

	p->pr_pid = mypid = dbg->pid;
	/* Start filling pr_fname and pr_psargs */
	file = r_str_newf ("/proc/%d/cmdline", mypid);
	buffer = r_file_slurp (file, &len);
	if (!buffer) {
		eprintf ("buffer NULL\n");
		goto error;
	}
	R_FREE (file);
	pfname = prpsinfo_get_fname (buffer);
	if (!pfname) {
		eprintf ("prpsinfo_get_fname: couldn't allocate memory\n");
		goto error;
	}
	basename = get_basename (pfname, strlen (pfname));
	strncpy (p->pr_fname, basename, sizeof (p->pr_fname));
	ppsargs = prpsinfo_get_psargs (buffer, pfname, sizeof (p->pr_psargs), len);
	if (!ppsargs) {
		eprintf ("prpsinfo_get_psargs: couldn't allocate memory\n");
		goto error;
	}

	strncpy (p->pr_psargs, ppsargs, sizeof (p->pr_psargs));
	free (buffer);
	free (ppsargs);
	free (pfname);
	p->pr_sname = proc_data->s_name;
	p->pr_zomb = (p->pr_sname == 'Z') ? 1 : 0;
	p->pr_state = strchr (prog_states, p->pr_sname) - prog_states;
	p->pr_ppid = proc_data->ppid;
	p->pr_pgrp = proc_data->pgrp;
	p->pr_sid = proc_data->sid;
	p->pr_flag = proc_data->flag;
	p->pr_nice = proc_data->nice;
	p->pr_uid = proc_data->uid;
	p->pr_gid = proc_data->gid;

	debug_print_prpsinfo (p);
	eprintf ("linux_get_prpsinfo: end\n");
	return p;
error:
	free (p);
	free (file);
	free (buffer);
	free (pfname);
	free (ppsargs);
	return NULL;
}

void debug_prstatus(prstatus_t *p) {
	eprintf ("\n== debug_prstatus ==\n");
	eprintf ("p->pr_cursig: %d\n", p->pr_cursig);
	eprintf ("p->pr_info.si_signo: %d\n", p->pr_info.si_signo);
	eprintf ("p->pr_pid: %d\n", p->pr_pid);
	eprintf ("p->pr_ppid: %d\n", p->pr_ppid);
	eprintf ("p->pr_pgrp: %d\n", p->pr_pgrp);
	eprintf ("p->pr_sid: %d\n", p->pr_sid);
	eprintf ("p->pr_sigpend: %ld\n", p->pr_sigpend);
	eprintf ("p->pr_sighold: %ld\n", p->pr_sighold);
}

static prstatus_t *linux_get_prstatus(RDebug *dbg, proc_stat_content_t *proc_data, short int signr) {
	size_t size_gp_regset;
	prstatus_t *p;
	int rbytes;

	ut8 *reg_buff = calloc (sizeof (struct user_regs_struct), 1);
	if (!reg_buff) {
		return NULL;
	}
	size_gp_regset = sizeof (elf_gregset_t);
	rbytes = linux_reg_read (dbg, R_REG_TYPE_GPR, reg_buff, size_gp_regset);
	if (rbytes != size_gp_regset) { /* something went wrong */
		eprintf ("linux_get_prstatus: error in (rbytes != size_gp_regset)\n");
		free (reg_buff);
		return NULL;
	}

	/* http://lxr.free-electrons.com/source/arch/x86/include/asm/signal.h#L24 */
	p = R_NEW0 (prstatus_t);
	if (!p) {
		free (reg_buff);
		return NULL;
	}
	p->pr_cursig = p->pr_info.si_signo = signr;
	p->pr_pid = dbg->pid;
	p->pr_ppid = proc_data->ppid;
	p->pr_pgrp = proc_data->pgrp;
	p->pr_sid = proc_data->sid;
	p->pr_sigpend = proc_data->sigpend;
	p->pr_sighold = proc_data->sighold;
	/* TODO: p->pr_cutime p->pr_cstime p->pr_utime p->pr_stime */
	debug_prstatus (p);
	memcpy (p->pr_reg, reg_buff, rbytes);
	return p;
}

static elf_fpregset_t *linux_get_fp_regset(RDebug *dbg) {
	size_t size_fp_regset;
	elf_fpregset_t *p;
	int rbytes;

	ut8 *reg_buff = (ut8 *)R_NEW0 (struct user_fpregs_struct);
	if (!reg_buff) {
		return NULL;
	}
	size_fp_regset = sizeof (elf_fpregset_t);
	rbytes = linux_reg_read (dbg, R_REG_TYPE_FPU, reg_buff, size_fp_regset);
	if (rbytes != size_fp_regset) {
		eprintf ("linux_get_fp_regset: error in (rbytes != size_gp_regset)\n");
		goto fail;
	}
	if ((p = R_NEW0 (elf_fpregset_t))) {
		return memcpy (p, reg_buff, rbytes);
	}
fail:
	free (reg_buff);
	return NULL;
}

static siginfo_t *linux_get_siginfo(RDebug *dbg) {
	siginfo_t *siginfo = R_NEW0 (siginfo_t);
	if (!siginfo) return NULL;
	int ret = ptrace (PTRACE_GETSIGINFO, dbg->pid, 0, siginfo);
	if (ret == -1 || !siginfo->si_signo) {
		free (siginfo);
		return NULL;
	}
	return siginfo;
}

static void get_map_address_space(char *pstr, ut64 *start_addr, ut64 *end_addr) {
	char *pp = pstr;
	*start_addr = strtoul (pp, &pp, 16);
	pp++;   /*Skip '-' */
	*end_addr = strtoul (pp, &pp, 16);
}

static void get_map_perms(char *pstr, ut8 *fl_perms) {
	char *p_pstr;
	ut8 flags = 0;

	for (p_pstr = pstr ; *p_pstr ; p_pstr++) {
		switch (*p_pstr) {
		case 'r':
			flags |= R_MEM;
			break;
		case 'w':
			flags |= W_MEM;
			break;
		case 'x':
			flags |= X_MEM;
			break;
		case 'p':
			flags |= P_MEM;
			break;
		case 's':
			flags |= S_MEM;
			break;
		case '-':
			break;
		}
	}
	*fl_perms = flags;
	if (((flags & P_MEM) && (flags & S_MEM)) || (!(flags & R_MEM) && !(flags & W_MEM))) {
		eprintf ("setting WRG_PERM\n");
		*fl_perms = WRG_PERM;
	}
}

static void get_map_offset(char *pstr, ut64 *offset) {
	char *pp = pstr;
	*offset = strtoul (pp, &pp, 16);
}

static bool has_map_deleted_part(char *name) {
	const char deleted_str[] = "(deleted)";
	int len_name = strlen (name);
	int len_suffx = strlen (deleted_str);
	return !strncmp (name + len_name - len_suffx, deleted_str, len_suffx);
}

static bool getAnonymousValue(char *keyw) {
	for (keyw = strchr (keyw, ' '); isspace (*keyw); keyw ++) {
		/* nothing here */
	}
	return *keyw != '0';
}

static char *isAnonymousKeyword(const char *pp) {
	if (!pp) return NULL;
	char *keyw = strstr (pp, "Anonymous:");
	if (!keyw) keyw = strstr (pp, "AnonHugePages:");
	return keyw;
}

static bool has_map_anonymous_content(char *buff_smaps, ut64 start_addr, ut64 end_addr) {
	char *p, *pp, *extern_tok, *keyw;
	bool is_anonymous;

	char *identity = r_str_newf ("%08"PFMT64x"-%08"PFMT64x"", start_addr, end_addr);
	char *str = strdup (buff_smaps);

	p = strtok_r (str, "\n", &extern_tok);
	for (; p; p = strtok_r (NULL, "\n", &extern_tok)) {
		if (strstr (p, identity)) {
			pp = strtok_r (NULL, "\n", &extern_tok);
			for (; pp ; pp = strtok_r (NULL, "\n", &extern_tok)) {
				if ((keyw = isAnonymousKeyword (pp))) {
					is_anonymous = getAnonymousValue (keyw);
					free (str);
					return is_anonymous;
				}
			}
		}
	}
	free (str);
	return 0;
}

static bool dump_this_map(char *buff_smaps, ut64 start_addr, ut64 end_addr, bool file_backed, bool anonymous, ut8 perms, ut8 filter_flags) {
	char *identity, *aux, *p, *pp, *ppp, *extern_tok, *flags_str;
	bool found = false;
	ut8 vmflags;

	/* if the map doesn't have r/w quit right here */
	if (perms & WRG_PERM) {
		eprintf ("[dump_this_map] wrong perm detected on %"PFMT64x"-%"PFMT64x"\n",
				start_addr, end_addr);
		return false;
	}
#if 0
	eprintf ("[dump_this_map] %"PFMT64x"-%"PFMT64x": file: %d - anonymous - %d - flags: 0%x\n",
			start_addr, end_addr, file_backed, anonymous, filter_flags);
#endif
	identity = r_str_newf ("%08"PFMT64x"-%08"PFMT64x"", start_addr, end_addr);
	vmflags = 0;
	flags_str = NULL;
	aux = strdup (buff_smaps);

	pp = strtok_r (aux, "\n", &extern_tok);
	for (; pp ; pp = strtok_r (NULL, "\n", &extern_tok)) {
		if (strstr (pp, identity)) {
			ppp = strtok_r (NULL, "\n", &extern_tok);
			for (; ppp ; ppp = strtok_r (NULL, "\n", &extern_tok)) {
				if ((flags_str = strstr (ppp, "VmFlags:"))) {
					found = true;
					break;
				}
			}
		}
	}

	if (!flags_str && !found) {
		eprintf ("VmFlags: not found\n");
		return true;	/* if we don't have VmFlags, just dump it. I'll fix it later on */
	}

	flags_str = strchr (flags_str, ' ');
	while (*flags_str++ == ' ') {
		/* nothing here */
	}
	flags_str--;

	p = strtok (flags_str, " ");
	while (p) {
		//eprintf ("dump_this_map: %s\n", p);
		if (!strncmp (p, "sh", 2)) {
		//	eprintf ("vmflags |= SH_FLAG\n");
			vmflags |= SH_FLAG;
		}
		if (!strncmp (p, "io", 2)) {
		//	eprintf ("vmflags |= IO_FLAG\n");
			vmflags |= IO_FLAG;
		}
		if (!strncmp (p, "ht", 2)) {
			//eprintf ("vmflags |= HT_FLAG\n");
			 vmflags |= HT_FLAG;
		}
		if (!strncmp (p, "dd", 2)) {
			//eprintf ("vmflags |= DD_FLAG\n");
			vmflags |= DD_FLAG;
		}
		p = strtok (NULL, " ");
	}

	if (!(vmflags & SH_FLAG)) {
		vmflags |= PV_FLAG;
	}
	eprintf ("vmflags: %u\n", vmflags);
	/* first check for dd and io flags */
	if ((vmflags & DD_FLAG) || (vmflags & IO_FLAG)) {
		return false;
	}

	if (vmflags & HT_FLAG) {
		if ((filter_flags & MAP_HUG_PRIV) && anonymous) {
			eprintf ("filter_flags & MAP_HUG_PRIV\n");
			return true;
		}
		if (filter_flags & MAP_HUG_SHR) {
			eprintf ("filter_flags & MAP_HUG_SHR\n");
			return true;
		}
	}

	if (vmflags & SH_FLAG) {
		if (filter_flags & MAP_ANON_SHR) {
			eprintf ("filter_flags & MAP_ANON_SHR\n");
			return true;
		}
		if (filter_flags & MAP_HUG_SHR) {
			eprintf ("filter_flags & MAP_HUG_SHR\n");
			return true;
		}
	}

	if (vmflags & PV_FLAG) {
		if ((filter_flags & MAP_ANON_PRIV) && anonymous) {
			eprintf ("filter_flags & MAP_ANON_PRIV\n");
			return true;
		}
		if ((filter_flags & MAP_HUG_PRIV) && anonymous) {
			eprintf ("filter_flags & MAP_HUG_PRIV\n");
			return true;
		}
	}
	if (file_backed) {
		if (filter_flags & MAP_FILE_PRIV) {
			eprintf ("filter_flags & MAP_FILE_PRIV\n");
			return true;
		}
		if (filter_flags & MAP_FILE_SHR) {
			eprintf ("filter_flags & MAP_FILE_PRIV\n");
			return true;
		}
	}

	eprintf ("dump_this_map: nothing found, returning false\n");
	return false;
}

static void clean_maps(linux_map_entry_t *h) {
	linux_map_entry_t *aux, *p = h;
	while (p) {
		aux = p;
		p = p->n;
		free (aux);
	}
}

static linux_map_entry_t *linux_get_mapped_files(RDebug *dbg, ut8 filter_flags) {
	char *buff, *buff_smaps, *file, *name, *p, *end_line, *end_token;
	linux_map_entry_t *me_head, *me_tail;
	ut64 start_addr, end_addr, offset;
	linux_map_entry_t *pmentry;
	int size_file, len_name;
	MAPS_FIELD maps_current;
	bool is_anonymous;
	ut8 flag_perm;
	pid_t mypid;

	me_head = me_tail = NULL;
	name = NULL;
	mypid = dbg->pid;
	file = r_str_newf ("/proc/%d/smaps", mypid);
	buff_smaps = r_file_slurp (file, &size_file);
	if (!buff_smaps) {
		eprintf ("r_file_slurp buff_smaps == NULL\n");
		goto error;
	}
	free (file);
	/* This can be really big depening on the process */
	file = r_str_newf ("/proc/%d/maps", mypid);
	buff = r_file_slurp (file, &size_file);
	if (!buff) {
		eprintf ("r_file_slurp buff == NULL\n");
		goto error;
	}

	free (file);

	p = strtok_r (buff, "\n", &end_line);
	while (p) {
		char *pp;
		pp = strtok_r (p, " ", &end_token);
		maps_current = ADDR;
		while (pp) {
			switch (maps_current) {
			case ADDR:
				get_map_address_space (pp, &start_addr, &end_addr);
				break;
			case PERM:
				get_map_perms (pp, &flag_perm);
				break;
			case OFFSET:
				get_map_offset (pp, &offset);
				break;
			case DEV:
				maps_current++;
				pp = strtok_r (NULL, " ", &end_token);
				/* fallthrough */
			case INODE:
				maps_current++;
				pp = strtok_r (NULL, " ", &end_token);
				/* fallthrough */
			case NAME:
				/* Has this map a name? */
				if (pp) name = strdup (pp);
				break;
			}
			maps_current++;
			pp = strtok_r (NULL, " ", &end_token);
		}

		if (start_addr == 0 || end_addr == 0) {
			eprintf ("linux_get_mapped_files: BREAKING!\n");
			break;
		}

		pmentry = R_NEW0 (linux_map_entry_t);
		if (!pmentry) {
			goto error;
		}
		pmentry->start_addr = start_addr;
		pmentry->end_addr = end_addr;
		pmentry->perms = flag_perm;
		pmentry->offset = offset;
		pmentry->name = NULL;
		pmentry->inode = 0;

		if (name) {
			pmentry->name = strdup (name);
			len_name = strlen (pmentry->name) + 1;
			R_FREE (name);
		}

		eprintf ("[checking] %"PFMT64x"-%"PFMT64x"\n", pmentry->start_addr, pmentry->end_addr);
		/* Check if the map comes from the kernel (vsyscall, vvar, vdso) (they are always dumped, but not vvar) */
		if (pmentry->name && is_a_kernel_mapping (pmentry->name)) {
			pmentry->anonymous = pmentry->kernel_mapping = true;
			eprintf ("kernel_mapping: %d\n", pmentry->anonymous);
		} else {
			/* Check if map has anonymous content by checking Anonymous and AnonHugePages */
			is_anonymous = has_map_anonymous_content (buff_smaps, start_addr, end_addr);
			eprintf ("has_map_anonymous_content: %d\n", is_anonymous);
			/* Check if pathname has a (deleted) part. Actually what kernel does is: file_inode(vma->vm_file)->i_nlink == 0 */
			if (!is_anonymous && pmentry->name) {
				is_anonymous = has_map_deleted_part (pmentry->name);
				eprintf ("has_map_deleted_part called: %d\n", is_anonymous);
			}
			pmentry->anonymous = is_anonymous;
		}

		if (!pmentry->kernel_mapping) {
			if (pmentry->name && strcmp (pmentry->name, "[stack]") && strcmp (pmentry->name, "[heap]")) {
				if (!pmentry->kernel_mapping)
					pmentry->file_backed = true;
			}
			pmentry->dumpeable = dump_this_map (buff_smaps, pmentry->start_addr, pmentry->end_addr, pmentry->file_backed, pmentry->anonymous, pmentry->perms, filter_flags);
			eprintf (" %"PFMT64x"-%"PFMT64x" - anonymous: %d, kernel_mapping: %d, file_backed: %d, dumpeable: %d\n\n",
					pmentry->start_addr, pmentry->end_addr,
					pmentry->anonymous, pmentry->kernel_mapping,
					pmentry->file_backed, pmentry->dumpeable);

			if (pmentry->file_backed) {
				eprintf ("pmentry->name adding: %s as a SIZE_NT_FILE_DESCSZ\n", pmentry->name);
				mapping_file.size += SIZE_NT_FILE_DESCSZ + len_name;
				mapping_file.count++;
			}
		} else {
			/* kernel mappings are always dumped */
			pmentry->dumpeable = 1;
		}
		ADD_MAP_NODE (pmentry);
		p = strtok_r (NULL, "\n", &end_line);
	}

	mapping_file.size += sizeof (ut64) * 2; /* number of mappings and page size */
	eprintf ("mapping_file.size: %d\n", mapping_file.size);
	free (buff);
	free (buff_smaps);

	return me_head;
error:
	free (buff);
	free (buff_smaps);
	clean_maps (me_head);
	return NULL;
}

static auxv_buff_t *linux_get_auxv(RDebug *dbg) {
	char *buff;
	auxv_buff_t *auxv = NULL;
	int auxv_entries;
	int size;

	const char *file = sdb_fmt (0, "/proc/%d/auxv", dbg->pid);
	eprintf ("linux_get_auxv: file: %s\n", file);
	buff = r_file_slurp (file, &size);
	if (!buff) {
		eprintf ("linux_get_auxv: r_file_slurp error\n");
		return NULL;
	}

	auxv_entries = size / sizeof (Elf64_auxv_t);
	if (auxv_entries > 0) {
		auxv = R_NEW0 (auxv_buff_t);
		if (!auxv) {
			return NULL;
		}
		auxv->size = size;
		auxv->data = strdup (buff);
		if (!auxv->data) {
			free (buff);
			free (auxv);
			return NULL;
		}
	}
	free (buff);
	return auxv;
}

static Elf64_Ehdr *build_elf_hdr(int n_segments) {
	int pad_byte;
	int ph_size;
	int ph_offset;
	Elf64_Ehdr *h = R_NEW0 (Elf64_Ehdr);
	if (!h) {
		return NULL;
	}

	ph_offset = ELF_HDR_SIZE;
	ph_size = sizeof (Elf64_Phdr);
	h->e_ident[EI_MAG0] = ELFMAG0;
	h->e_ident[EI_MAG1] = ELFMAG1;
	h->e_ident[EI_MAG2] = ELFMAG2;
	h->e_ident[EI_MAG3] = ELFMAG3;
	h->e_ident[EI_CLASS] = ELFCLASS64;     /*64bits */
	h->e_ident[EI_DATA] = ELFDATA2LSB;
	h->e_ident[EI_VERSION] = EV_CURRENT;
	h->e_ident[EI_OSABI] = ELFOSABI_NONE;
	h->e_ident[EI_ABIVERSION] = 0x0;

	for (pad_byte = EI_PAD; pad_byte < EI_NIDENT; pad_byte++) {
		h->e_ident[pad_byte] = '\0';
	}
	h->e_ident[EI_NIDENT] = EI_NIDENT;
	h->e_type = ET_CORE; /* CORE */
	h->e_machine = EM_X86_64;
	h->e_version = EV_CURRENT;
	h->e_entry = 0x0;
	h->e_ehsize = ELF_HDR_SIZE;
	h->e_phoff = ph_offset; /* Program header table's file offset */
	h->e_phentsize = ph_size;
	h->e_phnum = (n_segments + 1) > PN_XNUM ? PN_XNUM : n_segments + 1; /* n_segments  + NOTE segment */
	h->e_flags = 0x0;
	/* Coredump contains no sections */
	h->e_shoff = 0x0;
	h->e_shentsize = 0x0;
	h->e_shnum = 0x0;
	h->e_shstrndx = 0x0;
	return h;
}

static int get_n_mappings(linux_map_entry_t *me_head) {
	linux_map_entry_t *p;
	int n_entries;
	for (n_entries = 0, p = me_head; p; p = p->n) {
		/* We don't count maps which does not have r/w perms */
		if ((p->perms & R_MEM) || (p->perms & W_MEM))
			n_entries++;
	}
	return n_entries;
}

static bool dump_elf_header(RBuffer *dest, Elf64_Ehdr *hdr) {
	bool ret = r_buf_append_bytes (dest, (const ut8*)hdr, hdr->e_ehsize);
	if (!ret) {
		perror ("dump_elf_header: error");
	}
	return ret;
}

static void *get_nt_data(linux_map_entry_t *head, size_t *nt_file_size) {
	char *maps_data, *pp;
	linux_map_entry_t *p;
	ut64 n_pag, n_segments;
	size_t size = mapping_file.size;

	if ((int)size < 1) {
		return NULL;
	}
	eprintf ("get_nt_size: %ld\n", size);
	n_segments = mapping_file.count;
	eprintf ("n_segments: %"PFMT64d"\n", n_segments);
	n_pag = 1;
	pp = maps_data = malloc (size);
	if (!maps_data)	{
		return NULL;
	}
	memcpy (maps_data, &n_segments, sizeof (n_segments));
	memcpy (maps_data + sizeof (n_segments), &n_pag, sizeof (n_pag));
	pp += sizeof (n_segments) + sizeof (n_pag);

	for (p = head; p; p = p->n) {
		if (isValidSection (p->name)) {
			memcpy (pp, &p->start_addr, sizeof (p->start_addr));
			pp += sizeof (p->start_addr);
			memcpy (pp, &p->end_addr, sizeof (p->end_addr));
			pp += sizeof (p->end_addr);
			memcpy (pp, &p->offset, sizeof (p->offset));
			pp += sizeof (p->offset);
		}
	}

	for (p = head; p; p = p->n) {
		if (isValidSection (p->name)) {
			strncpy (pp, p->name, size - (pp - maps_data));
			pp += strlen (p->name) + 1;
		}
	}
	*nt_file_size = size;
	return maps_data;
}

static ut8 *build_note_section(linux_elf_note_t *sec_note, size_t *size_note_section) {
	const char *n_core = "CORE";
	elf_fpregset_t *fp_regset;
	linux_map_entry_t *maps;
	prpsinfo_t *prpsinfo;
	prstatus_t *prstatus;
	siginfo_t *siginfo;
	auxv_buff_t *auxv;
	Elf64_Nhdr note_hdr;
	ut8 *note_data;
	char *maps_data;
	size_t size_elf_fpregset;
	size_t size_nt_file_pad;
	size_t size_core_name;
	size_t note_hdr_size;
	size_t size_prpsinfo;
	size_t size_prstatus;
	size_t size_siginfo;
	size_t size_nt_file;
	size_t i_size_core;
	size_t size_auxv;
	size_t size;
	int i;

	i_size_core = size_core_name = 0;
	i_size_core = sizeof (n_core) + ((4 - (sizeof (n_core) % 4)) % 4);

	for (i = 0; i < n_notes ; i++) {
		size_core_name += sizeof (n_core) + ((4 - (sizeof (n_core) % 4)) % 4);
	}

	auxv = sec_note->auxv;
	maps = sec_note->maps;
	note_hdr_size = sizeof (Elf64_Nhdr) * n_notes;
	size_prpsinfo = sizeof (prpsinfo_t) + ((4 - (sizeof (prpsinfo_t) % 4)) % 4);
	size_prstatus = sizeof (prstatus_t) + ((4 - (sizeof (prstatus_t) % 4)) % 4);
	size_siginfo = sizeof (siginfo_t) + ((4 - (sizeof (siginfo_t) % 4)) % 4);
	size_elf_fpregset = sizeof (elf_fpregset_t) + ((4 - (sizeof (elf_fpregset_t) % 4)) % 4);
	size_auxv = auxv->size + ((4 - (auxv->size % 4)) % 4);
	maps_data = get_nt_data (maps, &size_nt_file);
	if (!maps_data) {
		return NULL;
	}
	size_nt_file_pad = size_nt_file + ((4 - (size_nt_file % 4)) % 4);
	size = 0;
	size += size_core_name;
	size += size_prpsinfo;
	eprintf ("sizeof(prpsinfo_t) 0x%08"PFMT64x"\n", (ut64)size_prpsinfo);
	size += size_prstatus;
	eprintf ("sizeof(prstatus_t) 0x%08"PFMT64x"\n", (ut64)size_prstatus);
	size += size_elf_fpregset;
	eprintf ("sizeof(elf_fpregset_t) 0x%08"PFMT64x"\n", (ut64)size_elf_fpregset);
	size += size_siginfo;
	eprintf ("sizeof(siginfo_t) 0x%08"PFMT64x"\n", (ut64)size_siginfo);
	size += size_auxv;
	eprintf ("sizeof(auxv_t) 0x%08"PFMT64x"\n", (ut64)size_auxv);
	size += size_nt_file_pad;
	eprintf ("size_nt_file: 0x%08"PFMT64x"\n", (ut64)size_nt_file_pad);
	size += note_hdr_size;
	size += ((4 - (size % 4)) % 4);
	eprintf ("total_size: 0x%08"PFMT64x"\n", (ut64)size);
	*size_note_section = size;

	/******************** Start creating note **********************/
	note_data = malloc (size);
	if (!note_data) {
		free (maps_data);
		return NULL;
	}

	/* prpsinfo */
	prpsinfo = sec_note->prpsinfo;
	note_hdr.n_namesz = sizeof (n_core);
	note_hdr.n_descsz = sizeof (prpsinfo_t);
	note_hdr.n_type = NT_PRPSINFO;
	memcpy (note_data, (void *)&note_hdr, sizeof (note_hdr));
	note_data += sizeof (note_hdr);
	memcpy (note_data, n_core, i_size_core);
	note_data += i_size_core;
	memcpy (note_data, prpsinfo, size_prpsinfo);
	note_data += size_prpsinfo;

	/* prstatus */
	prstatus = sec_note->prstatus;
	note_hdr.n_namesz = sizeof (n_core);
	note_hdr.n_descsz = sizeof (prstatus_t);
	note_hdr.n_type = NT_PRSTATUS;
	memcpy (note_data, (void *)&note_hdr, sizeof (note_hdr));
	note_data += sizeof (note_hdr);
	memcpy (note_data, n_core, i_size_core);
	note_data += i_size_core;
	memcpy (note_data, prstatus, size_prstatus);
	note_data += size_prstatus;

	/* fpregset */
	fp_regset = sec_note->fp_regset;
	note_hdr.n_namesz = sizeof (n_core);
	note_hdr.n_descsz = sizeof (elf_fpregset_t);
	note_hdr.n_type = NT_FPREGSET;
	memcpy (note_data, (void *)&note_hdr, sizeof (note_hdr));
	note_data += sizeof (note_hdr);
	memcpy (note_data, n_core, i_size_core);
	note_data += i_size_core;
	memcpy (note_data, fp_regset, size_elf_fpregset);
	note_data += size_elf_fpregset;

	/* auxv */
	note_hdr.n_namesz = sizeof (n_core);
	note_hdr.n_descsz = auxv->size;
	note_hdr.n_type = NT_AUXV;
	memcpy (note_data, (void *)&note_hdr, sizeof (note_hdr));
	note_data += sizeof (note_hdr);
	memcpy (note_data, n_core, i_size_core);
	note_data += i_size_core;
	memcpy (note_data, auxv->data, size_auxv);
	note_data += size_auxv;

	/* siginfo */
	siginfo = sec_note->siginfo;
	note_hdr.n_namesz = sizeof (n_core);
	note_hdr.n_descsz = sizeof (siginfo_t);
	note_hdr.n_type = NT_SIGINFO;
	memcpy (note_data, (void *)&note_hdr, sizeof (note_hdr));
	note_data += sizeof (note_hdr);
	memcpy (note_data, n_core, i_size_core);
	note_data += i_size_core;
	memcpy (note_data, siginfo, size_siginfo);
	note_data += size_siginfo;

	/* nt_file */
	note_hdr.n_namesz = sizeof (n_core);
	note_hdr.n_descsz = size_nt_file;
	note_hdr.n_type = NT_FILE;
	memcpy (note_data, (void *)&note_hdr, sizeof (note_hdr));
	note_data += sizeof (note_hdr);
	memcpy (note_data, n_core, i_size_core);
	note_data += i_size_core;
	memcpy (note_data, maps_data, size_nt_file_pad);
	note_data += size_nt_file_pad;
	return note_data;
}

static bool dump_elf_pheaders(RBuffer *dest, linux_elf_note_t *sec_note, st64 *offset) {
	Elf64_Phdr phdr;
	linux_map_entry_t *me_p;
	size_t note_section_size;
	ut8 *note_data;
	bool ret;
	st64 offset_to_next;

	eprintf ("offset_to_note: %"PFMT64d"\n", *offset);
	note_data = build_note_section (sec_note, &note_section_size);
	if (!note_data)	return false;
	eprintf ("note_section_size : %ld\n", note_section_size);

	/* Start with note */
	phdr.p_type = PT_NOTE;
	phdr.p_flags = PF_R;
	phdr.p_offset = *offset;
	phdr.p_vaddr = 0x0;
	phdr.p_paddr = 0x0;
	phdr.p_filesz = note_section_size;
	phdr.p_memsz = 0x0;
	phdr.p_align = 0x1;

	if (!r_buf_append_bytes (dest, (const ut8 *)&phdr, sizeof (Elf64_Phdr))) {
		eprintf ("dump_elf_pheaders: r_buf_append_bytes error!\n");
		free (note_data);
		return false;
	}

	offset_to_next = *offset + note_section_size;

	/* write program headers */
	for (me_p = sec_note->maps; me_p; me_p = me_p->n) {
		if (!(me_p->perms & R_MEM) && !(me_p->perms & W_MEM)) {
			continue;
		}
		phdr.p_type = PT_LOAD;
		phdr.p_flags = me_p->perms;
		phdr.p_vaddr = me_p->start_addr;
		phdr.p_paddr = 0x0;
		phdr.p_memsz = me_p->end_addr - me_p->start_addr;
		phdr.p_filesz = me_p->dumpeable == 0 ? 0 : phdr.p_memsz;
		phdr.p_offset = offset_to_next;
		phdr.p_align = 0x1;
		offset_to_next += phdr.p_filesz == 0 ? 0 : phdr.p_filesz;
		ret = r_buf_append_bytes (dest, (const ut8*)&phdr, sizeof (Elf64_Phdr));
		if (!ret) {
			eprintf ("dump_elf_pheaders: r_buf_append_bytes error!\n");
			free (note_data);
			return false;
		}
		memset (&phdr, '\0', sizeof (Elf64_Phdr));
	}

	*offset = offset_to_next;
	eprintf ("pheaders writen\n");

	ret = r_buf_append_bytes (dest, (const ut8*)note_data, note_section_size);
	if (!ret) {
		eprintf ("dump_elf_pheaders: r_buf_append_bytes error!\n");
		free (note_data);
		return false;
	}
	eprintf ("note writen\n");
	return true;
}

static void show_maps(linux_map_entry_t *head) {
	linux_map_entry_t *p = head;
	eprintf ("SHOW MAPS ===================\n");
	while (p) {
		if (p->name) {
			eprintf ("p->name: %s\n", p->name);
		}
		eprintf ("p->start_addr - %"PFMT64x", p->end_addr - %"PFMT64x"\n", p->start_addr, p->end_addr);
		p = p->n;
	}
	eprintf ("SHOW MAPS ===================\n");
}

static bool dump_elf_map_content(RBuffer *dest, linux_map_entry_t *head, pid_t pid) {
	linux_map_entry_t *p;
	struct iovec local;
	struct iovec remote;
	char *map_content;
	size_t size;
	size_t rbytes;

	for (p = head; p; p = p->n) {
		//eprintf ("Trying to dump: %s - %"PFMT64x"\n", p->name, p->start_addr);
		if (p->dumpeable) {
			size = p->end_addr - p->start_addr;
			map_content = malloc (size);
			if (map_content == NULL) {
				eprintf ("dump_elf_map_content: map_content == NULL\n");
				return false;
			}

			eprintf ("p->name: %s - %"PFMT64x" to %p - size: %ld\n",
				p->name, p->start_addr, map_content, size);
			local.iov_base = (void *)map_content;
			local.iov_len = size;
			remote.iov_base = (void *)p->start_addr;
			remote.iov_len = size;
			rbytes = process_vm_readv (pid, &local, 1, &remote, 1, 0);
			eprintf ("dump_elf_map_content: rbytes: %ld\n", rbytes);
			if (rbytes != size) {
				eprintf ("dump_elf_map_content: size not equal\n");
				perror ("process_vm_readv");
			} else {
				r_buf_append_bytes (dest, (const ut8*)map_content, size);
			}
			free (map_content);
		}
	}
	return true;
}

static void print_p(proc_stat_content_t *p) {
	eprintf ("p->ppid: %d\n", p->ppid);
	eprintf ("p->pgrp: %d\n", p->pgrp);
	eprintf ("p->sid: %d\n", p->sid);
	eprintf ("p->s_name: %c\n", p->s_name);
	eprintf ("p->flags: %u\n", p->flag);
	eprintf ("p->utime: %"PFMT64u"\n", p->utime);
	eprintf ("p->stime: %"PFMT64u"\n", p->stime);
	eprintf ("p->cutime: %ld\n", p->cutime);
	eprintf ("p->cstime: %ld\n", p->cstime);
	eprintf ("p->nice: %ld\n", p->nice);
	eprintf ("p->num_threads: %ld\n", p->num_threads);
	eprintf ("p->sigpend: %"PFMT64u"\n", p->sigpend);
	eprintf ("p->sighold: %"PFMT64u"\n", p->sighold);
	eprintf ("p->uid: %u\n", p->uid);
	eprintf ("p->gid: %u\n", p->gid);
	eprintf ("p->coredump_filter: 0x%x\n", p->coredump_filter);
}

static proc_stat_content_t *get_proc_content(RDebug *dbg) {
	const char *s_sigpend = "SigPnd";
	const char *s_sighold = "SigBlk";
	char *temp_p_uid, *temp_p_gid, *p_uid, *p_gid;
	char *temp_p_sigpend, *temp_p_sighold;
	char *p_sigpend, *p_sighold;
	proc_stat_content_t *p;
	ut16 filter_flags;
	char *file, *buff;
	int size;

	file = r_str_newf ("/proc/%d/stat", dbg->pid);
	eprintf ("file: %s\n", file);

	buff = r_file_slurp (file, &size);
	if (!buff) {
		eprintf ("get_proc_stat: r_file_slurp error\n");
		return NULL;
	}

	free (file);
	p = R_NEW0 (proc_stat_content_t);
	if (!p) {
		eprintf ("get_proc_content: proc_stat_content_t\n");
		free (buff);
		return NULL;
	}

	/* /proc/[pid]/stat */
	{
		char no_str[128];
		long unsigned int no_lui;
		long int no_li;
		int no_num;
		sscanf (buff, "%d %s %c %d %d %d %d %d %u %lu %lu %lu %lu %"
				PFMT64u" %"PFMT64u" %ld %ld %ld %ld %ld",
			&p->pid, no_str, &p->s_name, &p->ppid, &p->pgrp, &no_num,
			&no_num, &p->sid, &p->flag, &no_lui, &no_lui, &no_lui,
			&no_lui, &p->utime, &p->stime, &p->cutime, &p->cstime,
			&no_li, &p->nice, &p->num_threads);
		free (buff);
	}

	/* /proc/[pid]/status for uid, gid, sigpend and sighold */
	file = sdb_fmt (0, "/proc/%d/status", dbg->pid);
	eprintf ("file: %s\n", file);
	buff = r_file_slurp (file, &size);
	if (!buff) {
		eprintf ("get_proc_stat: r_file_slurp error\n");
		free (p);
		return NULL;
	}

	temp_p_sigpend = strstr (buff, s_sigpend);
	temp_p_sighold = strstr (buff, s_sighold);

	/* sigpend */
	while (!isdigit (*temp_p_sigpend++)) {
		/* nothing here */
	}
	p_sigpend = temp_p_sigpend - 1;
	while (isdigit (*temp_p_sigpend++)) {
		/* nothing here */
	}
	p_sigpend[temp_p_sigpend - p_sigpend - 1] = '\0';
	/* sighold */
	while (!isdigit (*temp_p_sighold++)) {
		/* nothing here */
	}
	p_sighold = temp_p_sighold - 1;
	while (isdigit (*temp_p_sighold++)) {
		/* nothing here */
	}
	p_sighold[temp_p_sighold - p_sighold - 1] = '\0';
	p->sigpend = atoi (p_sigpend);
	p->sighold = atoi (p_sighold);
	temp_p_uid = strstr (buff, "Uid:");
	temp_p_gid = strstr (buff, "Gid:");
	while (!isdigit (*temp_p_uid++))  {}
	p_uid = temp_p_uid - 1;
	while (isdigit (*temp_p_uid++)) {}
	p_uid[temp_p_uid - p_uid - 1] = '\0';
	/* Do the same for Gid */
	while (!isdigit (*temp_p_gid++)) {}
	p_gid = temp_p_gid - 1;
	while (isdigit (*temp_p_gid++)) {}
	p_gid[temp_p_gid - p_gid - 1] = '\0';
	p->uid = atoi (p_uid);
	p->gid = atoi (p_gid);
	free (buff);

	/* Check the coredump_filter value */
	file = r_str_newf ("/proc/%d/coredump_filter", dbg->pid);
	buff = r_file_slurp (file, &size);
	if (!buff) {
		eprintf ("get_proc_stat: r_file_slurp error\n");
		free (p);
		return NULL;
	}
	sscanf (buff, "%hx", &filter_flags);
	p->coredump_filter = filter_flags;
	if (p->num_threads > 1) {
		eprintf ("Warning! No thread coredump support yet.\n");
	}
	return p;
}

static void may_clean_all(linux_elf_note_t *sec_note, proc_stat_content_t *proc_data, Elf64_Ehdr *elf_hdr) {
	free (sec_note->prpsinfo);
	free (sec_note->siginfo);
	free (sec_note->fp_regset);
	free (sec_note->prstatus);
	free (sec_note->auxv);
	clean_maps (sec_note->maps);
	free (sec_note);
	free (proc_data);
	free (elf_hdr);
}

static Elf64_Shdr *get_extra_sectionhdr(Elf64_Ehdr *elf_hdr, st64 offset, int n_segments) {
	Elf64_Shdr *shdr = R_NEW0 (Elf64_Shdr);
	if (!shdr) return NULL;
	eprintf ("get_extra_sectionhdr\n");
	elf_hdr->e_shoff = offset;
	elf_hdr->e_shentsize = sizeof (shdr);
	elf_hdr->e_shnum = 1;
	elf_hdr->e_shstrndx = SHN_UNDEF;
	shdr->sh_type = SHT_NULL;
	shdr->sh_size = elf_hdr->e_shnum;
	shdr->sh_link = elf_hdr->e_shstrndx;
	shdr->sh_info = n_segments + 1;
	return shdr;
}

static bool dump_elf_sheader_pxnum(RBuffer *dest, Elf64_Shdr *shdr) {
	return r_buf_append_bytes (dest, (const ut8 *)shdr, sizeof (*shdr));
}

bool linux_generate_corefile (RDebug *dbg, RBuffer *dest) {
	proc_stat_content_t *proc_data = NULL;
	linux_elf_note_t *sec_note = NULL;
	Elf64_Shdr *shdr_pxnum = NULL;
	Elf64_Ehdr *elf_hdr = NULL;
	bool error = false;
	int n_segments;
	ut32 hdr_size;
	st64 offset;

	sec_note = R_NEW0 (linux_elf_note_t);
	if (!sec_note) {
		return false;
	}
	proc_data = get_proc_content (dbg);
	if (!proc_data) {
		free (sec_note);
		return false;
	}
	print_p (proc_data);
	/* Let's start getting elf_prpsinfo */
	sec_note->prpsinfo = linux_get_prpsinfo (dbg, proc_data); /* NT_PRPSINFO */
	if (!sec_note->prpsinfo) {
		error = true;
		goto cleanup;
	}
	sec_note->siginfo = linux_get_siginfo (dbg); /* NT_SIGINFO */
	if (!sec_note->siginfo) {
		error = true;
		goto cleanup;
	}
	sec_note->fp_regset = linux_get_fp_regset (dbg); /* NT_FPREGSET */
	if (!sec_note->fp_regset) {
		error = true;
		goto cleanup;
	}
	/* NT_PRSTATUS */
	sec_note->prstatus = linux_get_prstatus (dbg, proc_data, sec_note->siginfo->si_signo);
	if (!sec_note->prstatus) {
		error = true;
		goto cleanup;
	}
	/* NT_X86_XSTATE */ /* stil missing */
	sec_note->auxv = linux_get_auxv (dbg); /* NT_AUXV */
	if (!sec_note->auxv) {
		error = true;
		goto cleanup;
	}
	/* NT_FILE */
        sec_note->maps = linux_get_mapped_files (dbg, proc_data->coredump_filter);
	if (!sec_note->maps) {
		error = true;
		goto cleanup;
	}
	n_segments = get_n_mappings (sec_note->maps);
	// show_maps (sec_note->maps);
	elf_hdr = build_elf_hdr (n_segments);
	if (!elf_hdr) {
		error = true;
		goto cleanup;
	}
	if (elf_hdr->e_phnum == PN_XNUM) {
		shdr_pxnum = get_extra_sectionhdr (elf_hdr, offset, n_segments);
	}
	hdr_size = (proc_data->coredump_filter & MAP_ELF_HDR) ? elf_hdr->e_ehsize : 0;

	if (hdr_size) {
		(void)dump_elf_header (dest, elf_hdr);
	}
	offset = hdr_size + (elf_hdr->e_phnum * elf_hdr->e_phentsize);
	/* Write to file */
	(void)dump_elf_pheaders (dest, sec_note, &offset);
	(void)dump_elf_map_content (dest, sec_note->maps, dbg->pid);
	if (elf_hdr->e_phnum == PN_XNUM) {
		(void)dump_elf_sheader_pxnum (dest, shdr_pxnum);
	}
cleanup:
	may_clean_all (sec_note, proc_data, elf_hdr);
	return !error;
}
