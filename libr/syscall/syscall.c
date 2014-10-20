/* radare - Copyright 2008-2014 - LGPL -- pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_db.h>
#include <r_syscall.h>
#include <stdio.h>
#include <string.h>
#include "fastcall.h"

R_LIB_VERSION (r_syscall);

extern RSyscallPort sysport_x86[];

R_API RSyscall* r_syscall_new() {
	RSyscall *rs = R_NEW (RSyscall);
	if (rs) {
		rs->fd = NULL;
		rs->sysptr = NULL; //syscalls_linux_x86;
		rs->sysport = sysport_x86;
		rs->db = NULL;
		rs->printf = (PrintfCallback)printf;
		rs->regs = fastcall_x86_32;
	}
	return rs;
}

R_API void r_syscall_free(RSyscall *s) {
	sdb_free (s->db);
	memset (s, 0, sizeof (RSyscall));
	free (s);
}

/* return fastcall register argument 'idx' for a syscall with 'num' args */
R_API const char *r_syscall_reg(RSyscall *s, int idx, int num) {
	if (num<0 || num>=R_SYSCALL_ARGS || idx<0 || idx>=R_SYSCALL_ARGS)
		return NULL;
	return s->regs[num].arg[idx];
}

R_API int r_syscall_setup(RSyscall *s, const char *arch, const char *os, int bits) {
	const char *file;
	if (os == NULL || !*os)
		os = R_SYS_OS;
	if (arch == NULL)
		arch = R_SYS_ARCH;
	if (!strcmp (os, "any")) // ignored
		return R_TRUE;

	if (!strcmp (arch, "mips"))
		s->regs = fastcall_mips;
	else if (!strcmp (arch,"sh"))
		s->regs = fastcall_sh;
	else if (!strcmp (arch, "arm"))
		s->regs = fastcall_arm;
	else if (!strcmp (arch, "x86")) {
		switch (bits) {
		case 8:
			s->regs = fastcall_x86_8;
			break;
		case 32:
			s->regs = fastcall_x86_32;
			break;
		case 64:
			s->regs = fastcall_x86_64;
		}
	}

#define SYSCALLPATH R2_LIBDIR"/radare2/"R2_VERSION"/syscall"
	file = sdb_fmt (0, "%s/%s-%s-%d.sdb", 
		SYSCALLPATH, os, arch, bits);
	if (!r_file_exists (file)) {
		//eprintf ("r_syscall_setup: Cannot find '%s'\n", file);
		return R_FALSE;
	}

	//eprintf ("DBG098: syscall->db must be reindexed for k\n");
#if 0
	// TODO: use sdb_reset (s->db);
	/// XXX: memoization doesnt seems to work because RSyscall is recreated instead of configured :(
	sdb_close (s->db);
	sdb_reset (s->db);
	sdb_open (s->db, file);
#else
	sdb_close (s->db);
	sdb_free (s->db);
	s->db = sdb_new (0, file, 0);
#endif
	if (s->fd)
		fclose (s->fd);
	s->fd = NULL;
	return R_TRUE;
}

R_API int r_syscall_setup_file(RSyscall *s, const char *path) {
	if (s->fd)
		fclose (s->fd);
	s->fd = r_sandbox_fopen (path, "r");
	if (s->fd == NULL)
		return 1;
	/* TODO: load info from file */
	return 0;
}

R_API RSyscallItem *r_syscall_item_new_from_string(const char *name, const char *s) {
	RSyscallItem *si;
	char *o;
	if (!name || !s) return NULL;
	si = R_NEW0 (RSyscallItem);
	o = strdup (s);
	r_str_split (o, ',');
	si->name = strdup (name);
	si->swi = r_num_get (NULL, r_str_word_get0 (o, 0));
	si->num = r_num_get (NULL, r_str_word_get0 (o, 1));
	si->args = r_num_get (NULL, r_str_word_get0 (o, 2));
	si->sargs = strdup (r_str_word_get0 (o, 3));
	free (o);
	return si;
}

R_API void r_syscall_item_free(RSyscallItem *si) {
	if (!si) return;
	free (si->name);
	free (si->sargs);
	free (si);
}

static int getswi(Sdb *p, int swi) {
	if (p && swi == -1) {
		swi = (int)sdb_array_get_num (p, "_", 0, NULL);
		if (!swi)
			swi = 0x80; // default hardcoded?
	}
	return swi;
}

R_API RSyscallItem *r_syscall_get(RSyscall *s, int num, int swi) {
	const char *ret, *ret2, *key;
	RSyscallItem *si;
	if (!s || !s->db)
		return NULL;
	swi = getswi (s->db, swi);
	key = sdb_fmt (0, "0x%02x.%d", swi, num);
	ret = sdb_const_get (s->db, key, 0);
	if (ret == NULL)
		return NULL;
	ret2 = sdb_const_get (s->db, ret, 0);
	if (ret2 == NULL) {
		return NULL;
	}
	si = r_syscall_item_new_from_string (ret, ret2);
	return si;
}

R_API int r_syscall_get_num(RSyscall *s, const char *str) {
	if (!s || !s->db)
		return -1;
	return (int)sdb_array_get_num (s->db, str, 1, NULL);
}

R_API const char *r_syscall_get_i(RSyscall *s, int num, int swi) {
	char foo[32];
	if (!s || !s->db)
		return NULL;
	swi = getswi (s->db, swi);
	snprintf (foo, sizeof (foo), "0x%x.%d", swi, num);
	return sdb_const_get (s->db, foo, 0);
}

R_API const char *r_syscall_get_io(RSyscall *s, int ioport) {
	int i;
	if (!s) return NULL;
	for (i=0; s->sysport[i].name; i++) {
		if (ioport == s->sysport[i].port)
			return s->sysport[i].name;
	}
	return NULL;
}

static int callback_list(void *u, const char *k, const char *v) {
	RList *list = (RList*)u;
	if (!strchr (k, '.')) {
		RSyscallItem *si = r_syscall_item_new_from_string (k, v);
		if (!strchr (si->name, '.'))
			r_list_append (list, si);
	}
	return 1; // continue loop
}

R_API RList *r_syscall_list(RSyscall *s) {
	RList *list;
	if (!s || !s->db)
		return NULL;
	// show list of syscalls to stdout
	list = r_list_newf ((RListFree)r_syscall_item_free);
	sdb_foreach (s->db, callback_list, list);
	return list;
}
