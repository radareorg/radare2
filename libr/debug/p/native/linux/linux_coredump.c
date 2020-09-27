/* radare - LGPL - Copyright 2016 - Oscar Salvador */

#include <r_debug.h>

#if DEBUGGER

#if __x86_64__ || __i386__ || __arm__ || __arm64__
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include "linux_coredump.h"
#include "linux_ptrace.h"

/* For compatibility */
#if __x86_64__ || __arm64__
typedef Elf64_auxv_t elf_auxv_t;
typedef Elf64_Ehdr elf_hdr_t;
typedef Elf64_Phdr elf_phdr_t;
typedef Elf64_Shdr elf_shdr_t;
typedef Elf64_Nhdr elf_nhdr_t;
typedef ut32 elf_offset_t;
#elif __i386__ || __arm__
typedef Elf32_auxv_t elf_auxv_t;
typedef Elf32_Ehdr elf_hdr_t;
typedef Elf32_Phdr elf_phdr_t;
typedef Elf32_Shdr elf_shdr_t;
typedef Elf32_Nhdr elf_nhdr_t;
typedef ut64 elf_offset_t;
#endif

#define fmt_addr "%08lx-%08lx"
#define ELF_HDR_SIZE sizeof(elf_hdr_t)

/*Some fields from note section must be padded to 4 or 8 bytes*/
#define round_up(a) ((((a) + (4) - (1)) / (4)) * (4))
#define sizeof_round_up(b) round_up(sizeof(b))

static map_file_t mapping_file = { 0, 0 };
static note_info_t note_info[NT_LENGHT_T];

static bool is_a_kernel_mapping(const char *name) {
	return !(name
		&& strcmp (name, "[vdso]")
		&& strcmp (name, "[vsyscall]")
		&& strcmp (name, "[vvar]")
		&& strcmp (name, "[heap]")
		&& strcmp (name, "[vectors]")
		&& strncmp (name, "[stack", strlen ("[stack")));
}

static char *prpsinfo_get_psargs(char *buffer, int len) {
	char paux[ELF_PRARGSZ];
	int i, bytes_left;
	char *p = r_mem_dup (buffer, len);
	if (!p) {
		return NULL;
	}
	bytes_left = strlen (buffer);
	buffer = strchr (buffer, '\0');
	if (!buffer) {
		free (p);
		return NULL;
	}

	for (i = 0; i + bytes_left < len && i + bytes_left < ELF_PRARGSZ - 1; i++) {
		if (!buffer[i]) {
			buffer[i] = ' ';
		}
		paux[i] = buffer[i];
	}
	paux[i] = '\0';
	strncat (p, paux, len - bytes_left - 1);
	return p;
}

static prpsinfo_t *linux_get_prpsinfo(RDebug *dbg, proc_per_process_t *proc_data) {
	const char *prog_states = "RSDTZW"; /* fs/binfmt_elf.c from kernel */
	const char *basename = NULL;
	char *buffer, *pfname = NULL, *ppsargs = NULL, *file = NULL;
	prpsinfo_t *p;
	pid_t mypid;
	size_t len;

	p = R_NEW0 (prpsinfo_t);
	if (!p) {
		eprintf ("Couldn't allocate memory for prpsinfo_t\n");
		return NULL;
	}

	p->pr_pid = mypid = dbg->pid;
	/* Start filling pr_fname and pr_psargs */
	file = sdb_fmt ("/proc/%d/cmdline", mypid);
	buffer = r_file_slurp (file, &len);
	if (!buffer) {
		eprintf ("buffer NULL\n");
		goto error;
	}
	buffer[len] = 0;
	pfname = strdup (buffer);
	if (!pfname) {
		goto error;
	}
	basename = r_file_basename (pfname);
	strncpy (p->pr_fname, basename, sizeof (p->pr_fname));
	p->pr_fname[sizeof (p->pr_fname) - 1] = 0;
	ppsargs = prpsinfo_get_psargs (buffer, (int)len);
	if (!ppsargs) {
		goto error;
	}

	strncpy (p->pr_psargs, ppsargs, sizeof (p->pr_psargs));
	p->pr_psargs[sizeof (p->pr_psargs)-1] = 0;
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
	return p;
error:
	free (p);
	free (buffer);
	free (pfname);
	free (ppsargs);
	return NULL;
}

static proc_per_thread_t *get_proc_thread_content(int pid, int tid) {
	char *temp_p_sigpend, *temp_p_sighold, *p_sigpend, *p_sighold;
	size_t size;
	const char * file = sdb_fmt ("/proc/%d/task/%d/stat", pid, tid);

	char *buff = r_file_slurp (file, &size);
	if (!buff) {
		return NULL;
	}

	proc_per_thread_t *t = R_NEW0 (proc_per_thread_t);
	if (!t) {
		free (buff);
		return NULL;
	}
	{
		char no_str[128];
		long unsigned int no_lui;
		int no_num;
		char no_char;
		ut32 no_ui;
		sscanf (buff,  "%d %s %c %d %d %d %d %d %u %lu %lu %lu %lu"
			"%"PFMT64x" %"PFMT64x" %ld %lu",
			&no_num, no_str, &no_char, &no_num, &no_num, &no_num,
			&no_num, &no_num, &no_ui, &no_lui, &no_lui, &no_lui,
			&no_lui, &t->utime, &t->stime, &t->cutime, &t->cstime);
		free (buff);
	}

        /* /proc/[pid]/status for uid, gid, sigpend and sighold */
	file = sdb_fmt ("/proc/%d/task/%d/status", pid, tid);
	buff = r_file_slurp (file, &size);
	if (!buff) {
		free (t);
		return NULL;
	}

	temp_p_sigpend = strstr (buff, "SigPnd");
	temp_p_sighold = strstr (buff, "SigBlk");
	if (!temp_p_sigpend || !temp_p_sighold) {
		free (buff);
		free (t);
		return NULL;
	}
	while (!isdigit ((ut8)*temp_p_sigpend++)) {
		//empty body
	}
	p_sigpend = temp_p_sigpend - 1;
	while (isdigit ((ut8)*temp_p_sigpend++)) {
		//empty body
	}
	p_sigpend[temp_p_sigpend - p_sigpend - 1] = '\0';
	while (!isdigit ((ut8)*temp_p_sighold++)) {
		//empty body
	}
	p_sighold = temp_p_sighold - 1;
	while (isdigit ((ut8)*temp_p_sighold++)) {
		//empty body
	}
	p_sighold[temp_p_sighold - p_sighold - 1] = '\0';
	t->sigpend = atoi (p_sigpend);
	t->sighold = atoi (p_sighold);
	free (buff);
	return t;
}

static prstatus_t *linux_get_prstatus(RDebug *dbg, int pid, int tid, proc_content_t *proc_data, short int signr) {
	elf_gregset_t regs;
	prstatus_t *p;

	proc_data->per_thread = get_proc_thread_content (pid, tid);
	if (!proc_data->per_thread) {
		return NULL;
	}
	p = R_NEW0 (prstatus_t);
	if (!p) {
		return NULL;
	}
	p->pr_cursig = p->pr_info.si_signo = signr;
	p->pr_pid = tid;
	p->pr_ppid = proc_data->per_process->ppid;
	p->pr_pgrp = proc_data->per_process->pgrp;
	p->pr_sid = proc_data->per_process->sid;
	p->pr_sigpend = proc_data->per_thread->sigpend;
	p->pr_sighold = proc_data->per_thread->sighold;
	p->pr_utime.tv_sec = proc_data->per_thread->utime / 1000;
	p->pr_utime.tv_usec = (proc_data->per_thread->utime % 1000) / 1000;
	p->pr_stime.tv_sec = proc_data->per_thread->stime / 1000;
	p->pr_stime.tv_usec = (proc_data->per_thread->stime % 1000) / 1000;
	p->pr_cutime.tv_sec = proc_data->per_thread->cutime / 1000;
	p->pr_cutime.tv_usec = (proc_data->per_thread->cutime % 1000) / 1000;
	p->pr_cstime.tv_sec = proc_data->per_thread->cstime / 1000;
	p->pr_cstime.tv_usec = (proc_data->per_thread->cstime % 1000) / 1000;

	if (r_debug_ptrace (dbg, PTRACE_GETREGS, tid, NULL, &regs) < 0) {
		perror ("PTRACE_GETREGS");
		R_FREE (proc_data->per_thread);
		free (p);
		return NULL;
	}
	memcpy (p->pr_reg, &regs, sizeof (regs));
	R_FREE (proc_data->per_thread);
	return p;
}

static elf_fpregset_t *linux_get_fp_regset(RDebug *dbg, int pid) {
	elf_fpregset_t *p = R_NEW0 (elf_fpregset_t);
	if (p) {
		if (r_debug_ptrace (dbg, PTRACE_GETFPREGS, pid, NULL, p) < 0) {
			perror ("PTRACE_GETFPREGS");
			free (p);
			return NULL;
		}
		return p;
	}
	return NULL;
}

static siginfo_t *linux_get_siginfo(RDebug *dbg, int pid) {
	siginfo_t *siginfo = R_NEW0 (siginfo_t);
	if (!siginfo) {
		return NULL;
	}
	int ret = r_debug_ptrace (dbg, PTRACE_GETSIGINFO, pid, 0, (r_ptrace_data_t)(size_t)siginfo);
	if (ret == -1 || !siginfo->si_signo) {
		perror ("PTRACE_GETSIGINFO");
		free (siginfo);
		return NULL;
	}
	return siginfo;
}

static bool has_map_deleted_part(char *name) {
	if (name) {
		const char deleted_str[] = "(deleted)";
		int len_name = strlen (name);
		int len_suffx = strlen (deleted_str);
		return !strncmp (name + len_name - len_suffx, deleted_str, len_suffx);
	}
	return false;
}

static bool getAnonymousValue(char *keyw) {
	if (!keyw) {
		return false;
	}
	keyw = strchr (keyw, ' ');
	if (!keyw) {
		return false;
	}
	while (*keyw && isspace ((ut8)*keyw)) {
		keyw ++;
	}
	return *keyw && *keyw != '0';
}

static char *isAnonymousKeyword(const char *pp) {
	if (!pp) {
		return NULL;
	}
	char *keyw = strstr (pp, "Anonymous:");
	if (!keyw) {
		keyw = strstr (pp, "AnonHugePages:");
	}
	return keyw;
}

static bool has_map_anonymous_content(char *buff_smaps, unsigned long start_addr, unsigned long end_addr) {
	char *p, *pp, *extern_tok, *keyw = NULL;
	char *identity = r_str_newf (fmt_addr, start_addr, end_addr);
	char *str = strdup (buff_smaps);
	bool is_anonymous;

	p = strtok_r (str, "\n", &extern_tok);
	for (; p; p = strtok_r (NULL, "\n", &extern_tok)) {
		if (strstr (p, identity)) {
			pp = strtok_r (NULL, "\n", &extern_tok);
			for (; pp ; pp = strtok_r (NULL, "\n", &extern_tok)) {
				if ((keyw = isAnonymousKeyword (pp))) {
					is_anonymous = getAnonymousValue (keyw);
					free (identity);
					free (str);
					return is_anonymous;
				}
			}
		}
	}
	free (identity);
	free (str);
	return 0;
}

static bool dump_this_map(char *buff_smaps, linux_map_entry_t *entry, ut8 filter_flags) {
	char *p, *pp, *ppp, *extern_tok, *flags_str = NULL;
	char *identity = r_str_newf (fmt_addr, entry->start_addr, entry->end_addr);
	bool found = false;
	char *aux = NULL;
	ut8 vmflags = 0, perms = entry->perms;

	if (!identity) {
		return false;
	}
	/* if the map doesn't have r/w quit right here */
	if ((!(perms & R_PERM_R) && !(perms & R_PERM_W))) {
		free (identity);
		return false;
	}
	aux = strdup (buff_smaps);
	if (!aux) {
		free (identity);
		return false;
	}

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

	if (entry->file_backed) {
		if (filter_flags & MAP_FILE_PRIV) {
			goto beach;
		}
		if (filter_flags & MAP_FILE_SHR) {
			goto beach;
		}
	}

	if (!flags_str || !found) {
		/* if we don't have VmFlags, let's check it out in another way */
		if (entry->kernel_mapping) {
			goto beach;
		}

		if (perms & !entry->shared) {
			if ((filter_flags & MAP_ANON_PRIV) && entry->anonymous) {
				goto beach;
			}
			if ((filter_flags & MAP_HUG_PRIV) && entry->anonymous) {
				goto beach;
			}
		}

		if (perms & entry->shared) {
			if (filter_flags & MAP_ANON_SHR) {
				goto beach;
			}
			if (filter_flags & MAP_HUG_SHR) {
				goto beach;
			}
		}
	} else {
		/* We have VmFlags */
		flags_str = strchr (flags_str, ' ');
		if (!flags_str) {
			goto fail;
		}
		while (*flags_str++ == ' ') {
			//empty body
		}
		flags_str--;
		p = strtok (flags_str, " ");
		while (p) {
			if (!strncmp (p, "sh", 2)) {
				vmflags |= SH_FLAG;
			}
			if (!strncmp (p, "io", 2)) {
				vmflags |= IO_FLAG;
			}
			if (!strncmp (p, "ht", 2)) {
				vmflags |= HT_FLAG;
			}
			if (!strncmp (p, "dd", 2)) {
				vmflags |= DD_FLAG;
			}
			p = strtok (NULL, " ");
		}

		if (!(vmflags & SH_FLAG)) {
			vmflags |= PV_FLAG;
		}
		/* first check for dd and io flags */
		if ((vmflags & DD_FLAG) || (vmflags & IO_FLAG)) {
			goto fail;
		}

		/* if current map comes from kernel and does not have DD flag, just stop checking */
		if (entry->kernel_mapping) {
			goto beach;
		}

		if (vmflags & HT_FLAG) {
			if ((filter_flags & MAP_HUG_PRIV) && entry->anonymous) {
				goto beach;
			}
			if (filter_flags & MAP_HUG_SHR) {
				goto beach;
			}
		}

		if (vmflags & SH_FLAG) {
			if (filter_flags & MAP_ANON_SHR) {
				goto beach;
			}
			if (filter_flags & MAP_HUG_SHR) {
				goto beach;
			}
		}

		if (vmflags & PV_FLAG) {
			if ((filter_flags & MAP_ANON_PRIV) && entry->anonymous) {
				goto beach;
			}
			if ((filter_flags & MAP_HUG_PRIV) && entry->anonymous) {
				goto beach;
			}
		}
	}

fail:
	free (identity);
	free (aux);
	return false;
beach:
	free (identity);
	free (aux);
	return true;
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
	linux_map_entry_t *me_head = NULL, *me_tail = NULL;
	RListIter *iter;
	RDebugMap *map;
	bool is_anonymous = false, is_deleted = false, ret = 0;
	char *file = NULL, *buff_maps= NULL, *buff_smaps = NULL;
	size_t size_file = 0;

	file = r_str_newf ("/proc/%d/smaps", dbg->pid);
	buff_smaps = r_file_slurp (file, &size_file);
	if (!buff_smaps) {
		goto error;
	}
	R_FREE (file);

	file = r_str_newf ("/proc/%d/maps", dbg->pid);
	buff_maps = r_file_slurp (file, &size_file);
	if (!buff_maps) {
		goto error;
	}
	R_FREE (file);

	ret = r_debug_map_sync (dbg);
	if (!ret) {
		goto error;
	}
	r_list_foreach (dbg->maps, iter, map) {
		linux_map_entry_t *pmentry = R_NEW0 (linux_map_entry_t);
		if (!pmentry) {
			goto error;
		}
		pmentry->start_addr = map->addr;
		pmentry->end_addr = map->addr_end;
		pmentry->offset = map->offset;
		pmentry->name = strncmp (map->name, "unk", strlen ("unk"))
					? strdup (map->name)
					: NULL;
		pmentry->perms = map->perm;
		pmentry->shared = map->shared;
		pmentry->kernel_mapping = false;
		/* Check if is a kernel mapping */
		if (pmentry->name && is_a_kernel_mapping (pmentry->name)) {
			pmentry->anonymous = pmentry->kernel_mapping = true;
		} else {
			/* Check if map has anonymous content by checking Anonymous and AnonHugePages */
			is_anonymous = has_map_anonymous_content (buff_smaps, pmentry->start_addr, pmentry->end_addr);
			if (!is_anonymous && pmentry->name) {
				is_anonymous = is_deleted = has_map_deleted_part (pmentry->name);
			}
			pmentry->anonymous = is_anonymous;
		}
		if (pmentry->name && !pmentry->kernel_mapping && !is_deleted) {
			pmentry->file_backed = true;
		}
		pmentry->dumpeable = dump_this_map (buff_smaps, pmentry, filter_flags);
		eprintf (fmt_addr" - anonymous: %d, kernel_mapping: %d, file_backed: %d, dumpeable: %d\n",
							pmentry->start_addr, pmentry->end_addr,
							pmentry->anonymous, pmentry->kernel_mapping,
							pmentry->file_backed, pmentry->dumpeable);
		if (pmentry->file_backed) {
			const char *name = pmentry->name;
			if (!name) {
				name = "";
			}
			mapping_file.size += SIZE_NT_FILE_DESCSZ + strlen (name) + 1;
			mapping_file.count++;
		}
		ADD_MAP_NODE (pmentry);
	}
	/* number of mappings and page size */
	mapping_file.size += sizeof (unsigned long) * 2;
	free (buff_maps);
	free (buff_smaps);

	return me_head;
error:
	free (buff_maps);
	free (buff_smaps);
	free (file);
	clean_maps (me_head);
	return NULL;
}

static auxv_buff_t *linux_get_auxv(RDebug *dbg) {
	char *buff = NULL;
	auxv_buff_t *auxv = NULL;
	int auxv_entries;
	size_t size;

	const char *file = sdb_fmt ("/proc/%d/auxv", dbg->pid);
	buff = r_file_slurp (file, &size);
	if (!buff) {
		return NULL;
	}

	auxv_entries = size / sizeof (elf_auxv_t);
	if (auxv_entries > 0) {
		auxv = R_NEW0 (auxv_buff_t);
		if (!auxv) {
			free (buff);
			return NULL;
		}
		auxv->size = size;
		auxv->data = r_mem_dup (buff, (int)size);
		if (!auxv->data) {
			free (buff);
			free (auxv);
			return NULL;
		}
	}
	free (buff);
	return auxv;
}

static elf_hdr_t *build_elf_hdr(int n_segments) {
	int pad_byte;
	int ph_size;
	int ph_offset;
	elf_hdr_t *h = R_NEW0 (elf_hdr_t);
	if (!h) {
		return NULL;
	}

	ph_offset = ELF_HDR_SIZE;
	ph_size = sizeof (elf_phdr_t);
	h->e_ident[EI_MAG0] = ELFMAG0;
	h->e_ident[EI_MAG1] = ELFMAG1;
	h->e_ident[EI_MAG2] = ELFMAG2;
	h->e_ident[EI_MAG3] = ELFMAG3;
#if __x86_64__ || __arm64__
	h->e_ident[EI_CLASS] = ELFCLASS64;     /*64bits */
#elif __i386__ || __arm__
	h->e_ident[EI_CLASS] = ELFCLASS32;
#endif
	h->e_ident[EI_DATA] = ELFDATA2LSB;
	h->e_ident[EI_VERSION] = EV_CURRENT;
	h->e_ident[EI_OSABI] = ELFOSABI_NONE;
	h->e_ident[EI_ABIVERSION] = 0x0;

	for (pad_byte = EI_PAD; pad_byte < EI_NIDENT; pad_byte++) {
		h->e_ident[pad_byte] = '\0';
	}
	h->e_type = ET_CORE;
#if __x86_64__
	h->e_machine = EM_X86_64;
#elif __i386__
	h->e_machine = EM_386;
#elif __arm__
	h->e_machine = EM_ARM;
#elif __arm64__
	h->e_machine = EM_AARCH64;
#endif
	h->e_version = EV_CURRENT;
	h->e_entry = 0x0;
	h->e_ehsize = ELF_HDR_SIZE;
	h->e_phoff = ph_offset;
	h->e_phentsize = ph_size;
	/* n_segments  + NOTE segment */
	h->e_phnum = (n_segments + 1) > PN_XNUM ? PN_XNUM : n_segments + 1;
	h->e_flags = 0x0;
	/* Coredump contains no sections */
	h->e_shoff = 0x0;
	h->e_shentsize = 0x0;
	h->e_shnum = 0x0;
	h->e_shstrndx = 0x0;
	return h;
}

static int get_info_mappings(linux_map_entry_t *me_head, size_t *maps_size) {
	linux_map_entry_t *p;
	int n_entries;
	for (n_entries = 0, p = me_head; p; p = p->n) {
		/* We don't count maps which does not have r/w perms */
		if (((p->perms & R_PERM_R) || (p->perms & R_PERM_W)) && p->dumpeable) {
			*maps_size += p->end_addr - p->start_addr;
			n_entries++;
		}
	}
	return n_entries;
}

static bool dump_elf_header(RBuffer *dest, elf_hdr_t *hdr) {
	return r_buf_append_bytes (dest, (const ut8*)hdr, hdr->e_ehsize);
}

static void *get_ntfile_data(linux_map_entry_t *head) {
	char *maps_data, *pp;
	linux_map_entry_t *p;
	unsigned long n_pag, n_segments;
	size_t size = mapping_file.size;

	if ((int)size < 1) {
		return NULL;
	}
	n_segments = mapping_file.count;
	n_pag = 1;
	pp = maps_data = malloc (size);
	if (!maps_data)	{
		return NULL;
	}
	memcpy (maps_data, &n_segments, sizeof (n_segments));
	memcpy (maps_data + sizeof (n_segments), &n_pag, sizeof (n_pag));
	pp += sizeof (n_segments) + sizeof (n_pag);

	for (p = head; p; p = p->n) {
		if (p->file_backed && !is_a_kernel_mapping (p->name)) {
			memcpy (pp, &p->start_addr, sizeof (p->start_addr));
			pp += sizeof (p->start_addr);
			memcpy (pp, &p->end_addr, sizeof (p->end_addr));
			pp += sizeof (p->end_addr);
			memcpy (pp, &p->offset, sizeof (p->offset));
			pp += sizeof (p->offset);
		}
	}
	for (p = head; p; p = p->n) {
		if (p->file_backed && !is_a_kernel_mapping (p->name)) {
			strncpy (pp, p->name, size - (pp - maps_data));
			pp += strlen (p->name) + 1;
		}
	}
	return maps_data;
}

static bool dump_elf_pheaders(RBuffer *dest, linux_map_entry_t *maps, elf_offset_t *offset, size_t note_section_size) {
	linux_map_entry_t *me_p;
	elf_offset_t offset_to_next;
	elf_phdr_t phdr;
	bool ret;

	/* Start with note */
	phdr.p_type = PT_NOTE;
	phdr.p_flags = PF_R;
	phdr.p_offset = *offset;
	phdr.p_vaddr = 0x0;
	phdr.p_paddr = 0x0;
	phdr.p_filesz = note_section_size;
	phdr.p_memsz = 0x0;
	phdr.p_align = 0x1;

	if (!r_buf_append_bytes (dest, (const ut8 *)&phdr, sizeof (elf_phdr_t))) {
		return false;
	}

	offset_to_next = *offset + note_section_size;

	/* write program headers */
	for (me_p = maps; me_p; me_p = me_p->n) {
		if ((!(me_p->perms & R_PERM_R) && !(me_p->perms & R_PERM_W)) || !me_p->dumpeable) {
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
		ret = r_buf_append_bytes (dest, (const ut8*)&phdr, sizeof (elf_phdr_t));
		if (!ret) {
			return false;
		}
		memset (&phdr, '\0', sizeof (elf_phdr_t));
	}

	*offset = offset_to_next;
	return true;
}

static bool dump_elf_note(RBuffer *dest, void *note_data, size_t note_section_size) {
	return r_buf_append_bytes (dest, (const ut8*)note_data, note_section_size);
}

static bool dump_elf_map_content(RDebug *dbg, RBuffer *dest, linux_map_entry_t *head, pid_t pid) {
	linux_map_entry_t *p;
	ut8 *map_content;
	size_t size;
	bool ret;

	eprintf ("dump_elf_map_content starting\n\n");

	for (p = head; p; p = p->n) {
		if (!p->dumpeable) {
			continue;
		}
		size = p->end_addr - p->start_addr;
		map_content = malloc (size);
		if (!map_content) {
			return false;
		}
		ret = dbg->iob.read_at (dbg->iob.io, p->start_addr, map_content, size);
		if (!ret) {
			eprintf ("Problems reading %"PFMTSZd" bytes at %"PFMT64x"\n", size, (ut64)p->start_addr);
		} else {
			ret = r_buf_append_bytes (dest, (const ut8*)map_content, size);
			if (!ret) {
				eprintf ("r_buf_append_bytes - failed\n");
			}
		}
		free (map_content);
	}
	eprintf ("dump_elf_map_content - done\n");
	return true;
}

static proc_per_process_t *get_proc_process_content (RDebug *dbg) {
	proc_per_process_t *p;
	char *temp_p_uid, *temp_p_gid, *p_uid, *p_gid;
	ut16 filter_flags, default_filter_flags = 0x33;
	char *buff;
	const char *file = sdb_fmt ("/proc/%d/stat", dbg->pid);
	size_t size;

	buff = r_file_slurp (file, &size);
	if (!buff) {
		return NULL;
	}

	p = R_NEW0 (proc_per_process_t);
	if (!p) {
		free (buff);
		return NULL;
	}

	/* /proc/[pid]/stat */
	/* we only need few fields which are process-wide */
	{
		char no_str[128];
		long unsigned int no_lui;
		long int no_li;
		int no_num;
		sscanf (buff, "%d %s %c %d %d %d %d %d %u %lu %lu %lu %lu"
				"%lu %lu %ld %ld %ld %ld %ld",
			&p->pid, no_str, &p->s_name, &p->ppid, &p->pgrp, &no_num,
			&no_num, &p->sid, &p->flag, &no_lui, &no_lui, &no_lui,
			&no_lui, &no_lui, &no_lui, &no_li, &no_li,
			&no_li, &p->nice, &p->num_threads);
		free (buff);
	}
	if (!p->num_threads || p->num_threads < 1) {
		free (p);
		eprintf ("Warning: number of threads is < 1\n");
		return NULL;
	}
	file = sdb_fmt ("/proc/%d/status", dbg->pid);
	buff = r_file_slurp (file, &size);
	if (!buff) {
		free (p);
		return NULL;
	}
	temp_p_uid = strstr (buff, "Uid:");
	temp_p_gid = strstr (buff, "Gid:");
	/* Uid */
	if (temp_p_uid) {
		while (!isdigit ((ut8)*temp_p_uid++))  {
			//empty body
		}
		p_uid = temp_p_uid - 1;
		while (isdigit ((ut8)*temp_p_uid++)) {
			//empty body
		}
		p_uid[temp_p_uid - p_uid - 1] = '\0';
	} else {
		p_uid = NULL;
	}
	p->uid = p_uid? atoi (p_uid): 0;

	/* Gid */
	if (temp_p_gid) {
		while (!isdigit ((ut8)*temp_p_gid++)) {
			//empty body
		}
		p_gid = temp_p_gid - 1;
		while (isdigit ((ut8)*temp_p_gid++)) {
			//empty body
		}
		p_gid[temp_p_gid - p_gid - 1] = '\0';
	} else {
		p_gid = NULL;
	}
	p->gid = p_gid? atoi (p_gid): 0;

	free (buff);
	/* Check the coredump_filter value if we have*/
	file = sdb_fmt ("/proc/%d/coredump_filter", dbg->pid);
	buff = r_file_slurp (file, &size);
	if (buff) {
		sscanf (buff, "%hx", &filter_flags);
		p->coredump_filter = filter_flags;
		free (buff);
	} else {
		/* Old kernels do not have coredump_filter, so just take the default one */
		p->coredump_filter = default_filter_flags;
	}
	return p;
}

static void may_clean_all(elf_proc_note_t *elf_proc_note, proc_content_t *proc_data, elf_hdr_t *elf_hdr) {
	R_FREE (elf_proc_note->prpsinfo);
	R_FREE (elf_proc_note->auxv);
	clean_maps (elf_proc_note->maps);
	free (elf_proc_note);
	R_FREE (proc_data->per_thread);
	R_FREE (proc_data->per_process);
	free (proc_data);
	free (elf_hdr);
}

static elf_shdr_t *get_extra_sectionhdr(elf_hdr_t *elf_hdr, st64 offset, int n_segments) {
	elf_shdr_t *shdr = R_NEW0 (elf_shdr_t);
	if (!shdr) {
		return NULL;
	}
	elf_hdr->e_shoff = offset;
	elf_hdr->e_shentsize = sizeof (elf_shdr_t);
	elf_hdr->e_shnum = 1;
	elf_hdr->e_shstrndx = SHN_UNDEF;
	shdr->sh_type = SHT_NULL;
	shdr->sh_size = elf_hdr->e_shnum;
	shdr->sh_link = elf_hdr->e_shstrndx;
	shdr->sh_info = n_segments + 1;
	return shdr;
}

static bool dump_elf_sheader_pxnum(RBuffer *dest, elf_shdr_t *shdr) {
	return r_buf_append_bytes (dest, (const ut8 *)shdr, sizeof (*shdr));
}

#if __i386__
static elf_fpxregset_t *linux_get_fpx_regset (RDebug *dbg, int tid) {
#ifdef PTRACE_GETREGSET
	struct iovec transfer;
	elf_fpxregset_t *fpxregset = R_NEW0 (elf_fpxregset_t);
	if (fpxregset) {
		transfer.iov_base = fpxregset;
		transfer.iov_len = sizeof (elf_fpxregset_t);
		if (r_debug_ptrace (dbg, PTRACE_GETREGSET, tid, (void *)NT_PRXFPREG, &transfer) < 0) {
			perror ("linux_get_fpx_regset");
			R_FREE (fpxregset);
		}
	}
	return fpxregset;
#else
	return NULL;
#endif
}
#endif

#if __i386__ || __x86_64__
void *linux_get_xsave_data (RDebug *dbg, int tid, ut32 size) {
#ifdef PTRACE_GETREGSET
	struct iovec transfer;
	char *xsave_data = calloc (size, 1);
	if (!xsave_data) {
		return NULL;
	}
	transfer.iov_base = xsave_data;
	transfer.iov_len = size;
	if (r_debug_ptrace (dbg, PTRACE_GETREGSET, tid, (void *)NT_X86_XSTATE, &transfer) < 0) {
		perror ("linux_get_xsave_data");
		free (xsave_data);
		return NULL;
	}
	return xsave_data;
#else
	return NULL;
#endif
}
#endif

#if __arm__ || __arm64__
void *linux_get_arm_vfp_data (RDebug *dbg, int tid) {
#ifdef PTRACE_GETVFPREGS
	char *vfp_data = calloc (ARM_VFPREGS_SIZE + 1, 1);
	if (!vfp_data) {
		return NULL;
	}

	if (r_debug_ptrace (dbg, PTRACE_GETVFPREGS, tid, 0, vfp_data) < 0) {
		perror ("linux_get_arm_vfp_data");
		free (vfp_data);
		return NULL;
	}
	return vfp_data;
#else
	return NULL;
#endif
}
#endif

void write_note_hdr (note_type_t type, ut8 **note_data) {
	elf_nhdr_t nhdr;
	static size_t size_note_hdr = sizeof (elf_nhdr_t);
	ut32 note_type;

	switch (type) {
	case NT_PRPSINFO_T:
		note_type = NT_PRPSINFO;
		nhdr.n_descsz = note_info[type].size;
		break;
	case NT_AUXV_T:
		note_type = NT_AUXV;
		nhdr.n_descsz = note_info[type].size;
		break;
	case NT_FILE_T:
		note_type = NT_FILE;
		nhdr.n_descsz = note_info[type].size;
		break;
	case NT_PRSTATUS_T:
		note_type = NT_PRSTATUS;
		nhdr.n_descsz = note_info[type].size;
		break;
	case NT_FPREGSET_T:
		note_type = NT_FPREGSET;
		nhdr.n_descsz = note_info[type].size;
		break;
#if __i386__
	case NT_PRXFPREG_T:
		note_type = NT_PRXFPREG;
		nhdr.n_descsz = note_info[type].size;
		break;
#endif
	case NT_SIGINFO_T:
		note_type = NT_SIGINFO;
		nhdr.n_descsz = note_info[type].size;
		break;
#if __i386__ || __x86_64__
	case NT_X86_XSTATE_T:
		note_type = NT_X86_XSTATE;
		nhdr.n_descsz = note_info[type].size;
		break;
#elif __arm__ || __arm64__
	case NT_ARM_VFP_T:
		note_type = NT_ARM_VFP;
		nhdr.n_descsz = note_info[type].size;
		break;
#endif
	default:
		/* shouldn't happen */
		memset (*note_data, 0, size_note_hdr);
		return;
	}

	nhdr.n_type = note_type;
	if (note_type == NT_X86_XSTATE || note_type == NT_ARM_VFP || note_type == NT_PRXFPREG) {
		nhdr.n_namesz = sizeof ("LINUX");
	} else {
		nhdr.n_namesz = sizeof ("CORE");
	}

	memcpy (*note_data, (void *)&nhdr, size_note_hdr);
	*note_data += size_note_hdr;
}

static int *get_unique_thread_id (RDebug *dbg, int n_threads) {
	RListIter *it;
	RList *list;
	RDebugPid *th;
	int *thread_id = NULL;
	int i = 0;
	bool found = false;

	if (dbg->h) {
		list = dbg->h->threads (dbg, dbg->pid);
		if (!list) {
			return NULL;
		}
		thread_id = calloc (sizeof (int), n_threads);
		if (!thread_id) {
			return NULL; /* free list */
		}
		r_list_foreach (list, it, th) {
			if (th->pid) {
				int j;
				for (j = 0; j < i && !found ; j++) {
					if (th->pid == thread_id[j]) {
						found = true;
						break;
					}
				}
				if (!found) {
					/* Adding to array and attaching to thread */
					thread_id[i] = th->pid;
					/* The main thread is already being traced */
					if (th->pid != dbg->pid) {
						if (r_debug_ptrace (dbg, PTRACE_ATTACH, thread_id[i], 0, 0) < 0) {
							perror ("Could not attach to thread");
						}
					}
					i++;
				}
				found = false;
			}
		}
		free (list);
	}
	return thread_id;
}

void detach_threads (RDebug *dbg, int *thread_id, int n_threads) {
	int i;
	for(i = 0; i < n_threads ; i++) {
		if (dbg->pid != thread_id[i]) {
			if (r_debug_ptrace (dbg, PTRACE_DETACH, thread_id[i], 0, 0) < 0) {
				perror ("PTRACE_DETACH");
			}
		}
	}
}

static ut8 *build_note_section(RDebug *dbg, elf_proc_note_t *elf_proc_note, proc_content_t *proc_data, size_t *section_size) {
	ut8 *note_data, *pnote_data;
	char *maps_data;
	int i, n_notes = 0, *thread_id;
	size_t size = 0;
	note_type_t type;
#if __i386__
	bool fpx_flag = false;
#endif
#if __i386__ || __x86_64__
	bool xsave_flag = false;
#elif __arm__ || __arm64__
	bool vfp_flag = false;
#endif

	maps_data = get_ntfile_data (elf_proc_note->maps);
	if (!maps_data) {
		return NULL;
	}

	thread_id = get_unique_thread_id (dbg, elf_proc_note->n_threads);
	if (!thread_id) {
		free (maps_data);
		return NULL;
	}

	/* NT_* per proc */
	/* NT_PRPSINFO */
	type = NT_PRPSINFO_T;
	size += note_info[type].size_roundedup;
	size += note_info[type].size_name;
	n_notes++;
	/* NT_AUXV */
	type = NT_AUXV_T;
	size += note_info[type].size_roundedup;
	size += note_info[type].size_name;
	n_notes++;
	/* NT_FILE */
	type = NT_FILE_T;
	size += note_info[type].size_roundedup;
	size += note_info[type].size_name;
	n_notes++;

	/* NT_* per thread: NT_PRSTATUS, NT_SIGINFO, NT_FPREGSET, (NT_PRXFPREG), NT_X86_XSTATE */
	for (i = 0; i < elf_proc_note->n_threads; i++) {
		type = NT_PRSTATUS_T;
		size += note_info[type].size_roundedup;
		size += note_info[type].size_name;
		n_notes++;
		type = NT_SIGINFO_T;
		size += note_info[type].size_roundedup;
		size += note_info[type].size_name;
		n_notes++;
		type = NT_FPREGSET_T;
		size += note_info[type].size_roundedup;
                size += note_info[type].size_name;
		n_notes++;
#if __i386__
		type = NT_PRXFPREG_T;
		if (note_info[type].size) {
			fpx_flag = true;
			size += note_info[type].size_roundedup;
        	        size += note_info[type].size_name;
			n_notes++;
		}
#endif
#if __i386__ || __x86_64__
		type = NT_X86_XSTATE_T;
		if (note_info[type].size) {
			xsave_flag = true;
			size += note_info[type].size_roundedup;
                	size += note_info[type].size_name;
			n_notes++;
		}
#endif
#if __arm__ || __arm64__
		type = NT_ARM_VFP_T;
		if (note_info[type].size) {
			vfp_flag = true;
			size += note_info[type].size_roundedup;
			size += note_info[type].size_name;
			n_notes++;
		}
#endif
	}
	size += round_up (n_notes * sizeof (elf_nhdr_t));
	*section_size = size;

	/* Start building note */
	note_data = calloc (1, size);
	if (!note_data) {
		free (thread_id);
		free (maps_data);
		return NULL;
	}
	pnote_data = note_data;
	/* prpsinfo */
	type = NT_PRPSINFO_T;
	write_note_hdr (type, &note_data);
	memcpy (note_data, note_info[type].name, note_info[type].size_name);
	note_data += note_info[type].size_name;
	memcpy (note_data, elf_proc_note->prpsinfo, note_info[type].size);
	note_data += note_info[type].size_roundedup;

	/* prstatus + fpregset + (prxfpreg) + siginfo + x86xstate per thread */
	{
		elf_proc_note->thread_note = R_NEW0 (thread_elf_note_t);
		if (!elf_proc_note->thread_note) {
			goto fail;
		}
		for (i = 0; i < elf_proc_note->n_threads; i++) {
			elf_proc_note->thread_note->siginfo = linux_get_siginfo (dbg, thread_id[i]);
			if (!elf_proc_note->thread_note->siginfo) {
				goto fail;
			}
			elf_proc_note->thread_note->prstatus = linux_get_prstatus (dbg, dbg->pid,
								thread_id[i], proc_data,
								elf_proc_note->thread_note->siginfo->si_signo);
			if (!elf_proc_note->thread_note->prstatus) {
				goto fail;
			}
			elf_proc_note->thread_note->fp_regset = linux_get_fp_regset (dbg, thread_id[i]);
			if (!elf_proc_note->thread_note->fp_regset) {
				goto fail;
			}
#if __i386__
			if (fpx_flag) {
				elf_proc_note->thread_note->fpx_regset = linux_get_fpx_regset (dbg, thread_id[i]);
				if (!elf_proc_note->thread_note->fpx_regset) {
					goto fail;
				}
			}
#endif
#if __i386__ || __x86_64__
			if (xsave_flag) {
				elf_proc_note->thread_note->xsave_data = linux_get_xsave_data (dbg, thread_id[i],
										note_info[NT_X86_XSTATE_T].size);
				if (!elf_proc_note->thread_note->xsave_data) {
					goto fail;
				}
			}
#elif __arm__ || __arm64__
			if (vfp_flag) {
				elf_proc_note->thread_note->arm_vfp_data = linux_get_arm_vfp_data (dbg, thread_id[i]);
				if (!elf_proc_note->thread_note->arm_vfp_data) {
					goto fail;
				}
			}
#endif
			type = NT_PRSTATUS_T;
			write_note_hdr (type, &note_data);
			memcpy (note_data, note_info[type].name, note_info[type].size_name);
			note_data += note_info[type].size_name;
			memcpy (note_data, elf_proc_note->thread_note->prstatus, note_info[type].size);
			note_data += note_info[type].size_roundedup;

			type = NT_FPREGSET_T;
			write_note_hdr (type, &note_data);
			memcpy (note_data, note_info[type].name, note_info[type].size_name);
			note_data += note_info[type].size_name;
			memcpy (note_data, elf_proc_note->thread_note->fp_regset, note_info[type].size);
			note_data += note_info[type].size_roundedup;
#if __i386__
			if (fpx_flag) {
				type = NT_PRXFPREG_T;
				write_note_hdr (type, &note_data);
				memcpy (note_data, note_info[type].name, note_info[type].size_name);
				note_data += note_info[type].size_name;
				memcpy (note_data, elf_proc_note->thread_note->fpx_regset, note_info[type].size);
				note_data += note_info[type].size_roundedup;
				R_FREE (elf_proc_note->thread_note->fpx_regset);
			}
#endif
			type = NT_SIGINFO_T;
			write_note_hdr (type, &note_data);
			memcpy (note_data, note_info[type].name, note_info[type].size_name);
			note_data += note_info[type].size_name;
			memcpy (note_data, elf_proc_note->thread_note->fp_regset, note_info[type].size);
			note_data += note_info[type].size_roundedup;

#if __arm__ || __arm64
			if (vfp_flag) {
				type = NT_ARM_VFP_T;
				write_note_hdr (type, &note_data);
				memcpy (note_data, note_info[type].name, note_info[type].size_name);
				note_data += note_info[type].size_name;
				memcpy (note_data, elf_proc_note->thread_note->arm_vfp_data, note_info[type].size);
				note_data += note_info[type].size_roundedup;
				R_FREE (elf_proc_note->thread_note->arm_vfp_data);
			}
#endif

#if __i386__ || __x86_64__
			if (xsave_flag) {
				type = NT_X86_XSTATE_T;
				write_note_hdr (type, &note_data);
				memcpy (note_data, note_info[type].name, note_info[type].size_name);
				note_data += note_info[type].size_name;
				memcpy (note_data, elf_proc_note->thread_note->xsave_data, note_info[type].size);
				note_data += note_info[type].size_roundedup;
				R_FREE (elf_proc_note->thread_note->xsave_data);
			}
#endif
			R_FREE (elf_proc_note->thread_note->siginfo);
			R_FREE (elf_proc_note->thread_note->prstatus);
			R_FREE (elf_proc_note->thread_note->fp_regset);
		}
		free (elf_proc_note->thread_note);
	}
	type = NT_AUXV_T;
	write_note_hdr (type, &note_data);
	memcpy (note_data, note_info[type].name, note_info[type].size_name);
	note_data += note_info[type].size_name;
	memcpy (note_data, elf_proc_note->auxv->data, note_info[type].size);
	note_data += note_info[type].size_roundedup;

	type = NT_FILE_T;
	write_note_hdr (type, &note_data);
	memcpy (note_data, note_info[type].name, note_info[type].size_name);
	note_data += note_info[type].size_name;
	memcpy (note_data, maps_data, note_info[type].size);
	note_data += note_info[type].size_roundedup;

	detach_threads (dbg, thread_id, elf_proc_note->n_threads);
	free (thread_id);
	free (maps_data);
	return pnote_data;
fail:
	if (elf_proc_note->thread_note) {
		free (elf_proc_note->thread_note->siginfo);
		free (elf_proc_note->thread_note->prstatus);
		free (elf_proc_note->thread_note->fp_regset);
#if __i386__
		free (elf_proc_note->thread_note->fpx_regset);
#endif
#if __i386__ || __x86_64__
		free (elf_proc_note->thread_note->xsave_data);
#elif __arm__ || __arm64__
		free (elf_proc_note->thread_note->arm_vfp_data);
#endif
	}
	free (pnote_data);
	free (maps_data);
	free (thread_id);
	return NULL;
}

#if __i386__ || __x86_64__
static int get_xsave_size(RDebug *dbg, int pid) {
#ifdef PTRACE_GETREGSET
	struct iovec local;
	unsigned long xstate_hdr[XSTATE_HDR_SIZE/sizeof(unsigned long)];
	unsigned long xcr0;

	/*We request with NT_X86_XSTATE. Maybe our PC does not have xsave flag. In that case errno would be -ENODEV.
	We could also check this by cpuid instruction https://en.wikipedia.org/wiki/CPUID#EAX.3D1:_Processor_Info_and_Feature_Bits*/
	local.iov_base = xstate_hdr;
	local.iov_len = sizeof (xstate_hdr);
	if (r_debug_ptrace (dbg, PTRACE_GETREGSET, pid, (void *)NT_X86_XSTATE, &local) < 0) {
		perror ("NT_X86_XSTATE");
		return 0;
	}

	xcr0 = xstate_hdr[XCR0_OFFSET/sizeof (unsigned long)];
	switch (xcr0) {
	case XSTATE_SSE_MASK:
		return XSTATE_SSE_SIZE;
	case XSTATE_AVX_MASK:
		return XSTATE_AVX_SIZE;
	case XSTATE_MPX_MASK:
		return XSTATE_MPX_SIZE;
	case XSTATE_AVX512_MASK:
		return XSTATE_FULL_SIZE;
	default:
		return 0;
	}
#else
	return 0;
#endif
}
#endif

#if __i386__
static int get_i386_fpx_size(void) {
#ifdef PTRACE_GETREGSET
	return sizeof (elf_fpxregset_t);
#else
	return 0;
#endif
}
#endif

#if __arm__ || __arm64__
static int get_arm_vfpregs_size(void) {
#ifdef PTRACE_GETVFPREGS
	return ARM_VFPREGS_SIZE;
#else
	return 0;
#endif
}
#endif

static void init_note_info_structure(RDebug *dbg, int pid, size_t auxv_size) {
	note_type_t type;
	int len_name_core = round_up (strlen ("CORE") + 1);
	int len_name_linux = round_up (strlen ("LINUX") + 1);

	/* NT_PRPSINFO_T */;
	type = NT_PRPSINFO_T;
	note_info[type].size = sizeof (prpsinfo_t);
	note_info[type].size_roundedup = sizeof_round_up (prpsinfo_t);
	note_info[type].size_name = len_name_core;
	strncpy (note_info[type].name, "CORE", sizeof (note_info[type].name));
	/* NT_AUXV_T */
	type = NT_AUXV_T;
	note_info[type].size = auxv_size;
	note_info[type].size_roundedup = round_up (auxv_size);
	note_info[type].size_name = len_name_core;
	strncpy (note_info[type].name, "CORE", sizeof (note_info[type].name));
	/* NT_FILE_T */
	type = NT_FILE_T;
	note_info[type].size = mapping_file.size;
	note_info[type].size_roundedup = round_up (mapping_file.size);
	note_info[type].size_name = len_name_core;
	strncpy (note_info[type].name, "CORE", sizeof (note_info[type].name));
	/* NT_PRSTATUS_T */
	type = NT_PRSTATUS_T;
	note_info[type].size = sizeof (prstatus_t);
	note_info[type].size_roundedup = sizeof_round_up (prstatus_t);
	note_info[type].size_name = len_name_core;
	strncpy (note_info[type].name, "CORE", sizeof (note_info[type].name));
	/* NT_SIGINFO_T */
	type = NT_SIGINFO_T;
	note_info[type].size = sizeof (siginfo_t);
	note_info[type].size_roundedup = sizeof_round_up (siginfo_t);
	note_info[type].size_name = len_name_core;
	strncpy (note_info[type].name, "CORE", sizeof (note_info[type].name));
	/* NT_FPREGSET_T */
	type = NT_FPREGSET_T;
	note_info[type].size = sizeof (elf_fpregset_t);
	note_info[type].size_roundedup = sizeof_round_up (elf_fpregset_t);
	note_info[type].size_name = len_name_core;
	strncpy (note_info[type].name, "CORE", sizeof (note_info[type].name));
#if __i386__
	type = NT_PRXFPREG_T;
	note_info[type].size = get_i386_fpx_size();
	note_info[type].size_roundedup = sizeof_round_up (elf_fpxregset_t);
	note_info[type].size_name = len_name_core;
	strncpy (note_info[type].name, "CORE", sizeof (note_info[type].name));
	type++;
#endif
#if __x86_64__ || __i386__
	/* NT_X86_XSTATE_T */
	type = NT_X86_XSTATE_T;
	note_info[type].size = get_xsave_size (dbg, pid);
	note_info[type].size_roundedup = round_up (note_info[type].size);
	note_info[type].size_name = len_name_linux;
	strncpy (note_info[type].name, "LINUX", sizeof (note_info[type].name));
#elif __arm__ || __arm64__
	/* NT_ARM_VFP_T */
	type = NT_ARM_VFP_T;
	note_info[type].size = get_arm_vfpregs_size();
	note_info[type].size_roundedup = round_up (note_info[type].size);
	note_info[type].size_name = len_name_linux;
	strncpy (note_info[type].name, "LINUX", sizeof (note_info[type].name));
#endif
}

bool linux_generate_corefile (RDebug *dbg, RBuffer *dest) {
	proc_content_t *proc_data = NULL;
	elf_proc_note_t *elf_proc_note = NULL;
	elf_shdr_t *shdr_pxnum = NULL;
	elf_hdr_t *elf_hdr = NULL;
	void *note_data = NULL;
	bool error = false;
	size_t note_section_size, maps_size = 0;
	int n_segments;
	ut32 hdr_size;
	elf_offset_t offset = 0;

	elf_proc_note = R_NEW0 (elf_proc_note_t);
	if (!elf_proc_note) {
		return false;
	}
	proc_data = R_NEW0 (proc_content_t);
	if (!proc_data) {
		free (elf_proc_note);
		return false;
	}
	proc_data->per_process = get_proc_process_content (dbg);
	if (!proc_data->per_process) {
		free (elf_proc_note);
		free (proc_data);
		return false;
	}
	elf_proc_note->n_threads = proc_data->per_process->num_threads;

	/* Get NT_ process_wide: AUXV, MAPS, PRPSINFO */
	/* NT_PRPSINFO */
	elf_proc_note->prpsinfo = linux_get_prpsinfo (dbg, proc_data->per_process);
	if (!elf_proc_note->prpsinfo) {
		error = true;
		goto cleanup;
	}
	/* NT_AUXV */
	elf_proc_note->auxv = linux_get_auxv (dbg);
	if (!elf_proc_note->auxv) {
		error = true;
		goto cleanup;
	}
	/* NT_FILE */
	elf_proc_note->maps = linux_get_mapped_files (dbg, proc_data->per_process->coredump_filter);
	if (!elf_proc_note->maps) {
		error = true;
		goto cleanup;
	}
	n_segments = get_info_mappings (elf_proc_note->maps, &maps_size);

	init_note_info_structure(dbg, dbg->pid, elf_proc_note->auxv->size);
	note_data = build_note_section (dbg, elf_proc_note, proc_data, &note_section_size);
	if (!note_data) {
		error = true;
		goto cleanup;
	}

	elf_hdr = build_elf_hdr (n_segments);
	if (!elf_hdr) {
		error = true;
		goto cleanup;
	}

	hdr_size = (proc_data->per_process->coredump_filter & MAP_ELF_HDR) ? elf_hdr->e_ehsize : 0;
	if (hdr_size) {
		if (elf_hdr->e_phnum == PN_XNUM) {
			elf_offset_t offset_shdr;
			/* Since extra section header must be placed at the end,
				we need to compute the total size to known at which position should be written */
			offset_shdr = hdr_size + (elf_hdr->e_phnum * elf_hdr->e_phentsize) + note_section_size + maps_size;
			shdr_pxnum = get_extra_sectionhdr (elf_hdr, offset_shdr, n_segments);
		}
		(void)dump_elf_header (dest, elf_hdr);
	}
	offset = hdr_size + (elf_hdr->e_phnum * elf_hdr->e_phentsize);

	/* Write to file */
	(void)dump_elf_pheaders (dest, elf_proc_note->maps, &offset, note_section_size);
	(void)dump_elf_note (dest, note_data, note_section_size);
	(void)dump_elf_map_content (dbg, dest, elf_proc_note->maps, dbg->pid);
	if (elf_hdr->e_phnum == PN_XNUM) {
		(void)dump_elf_sheader_pxnum (dest, shdr_pxnum);
	}
cleanup:
	may_clean_all (elf_proc_note, proc_data, elf_hdr);
	free (shdr_pxnum);
	free (note_data);
	return !error;
}
#endif

#endif
