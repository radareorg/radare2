/* radare 2008-2011 LGPL -- pancake <youterm.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_db.h>
#include <r_syscall.h>
#include <stdio.h>
#include <string.h>
#include "fastcall.h"

extern RSyscallPort sysport_x86[];

R_API RSyscall* r_syscall_new() {
	RSyscall *rs = R_NEW (RSyscall);
	if (rs) {
		rs->fd = NULL;
		rs->sysptr = NULL; //syscalls_linux_x86;
		rs->sysport = sysport_x86;
		rs->printf = (PrintfCallback)printf;
		rs->regs = fastcall_x86;
	}
	return rs;
}

R_API void r_syscall_free(RSyscall *ctx) {
	free (ctx);
}

/* return fastcall register argument 'idx' for a syscall with 'num' args */
R_API const char *r_syscall_reg(RSyscall *s, int idx, int num) {
	if (num<0 || num>=R_SYSCALL_ARGS || idx<0 || idx>=R_SYSCALL_ARGS)
		return NULL;
	return s->regs[num].arg[idx];
}

R_API int r_syscall_setup(RSyscall *ctx, const char *arch, const char *os, int bits) {
	char file[64];

#define SYSCALLPATH "lib/radare2/syscall"
	if (os == NULL)
		os = R_SYS_OS;
	if (arch == NULL)
		arch = R_SYS_ARCH;
	if (!strcmp (os, "any")) {
		// ignored
		return R_TRUE;
	}
	if (!strcmp (arch, "mips")) {
		ctx->regs = fastcall_mips;
	} else
	if (!strcmp (arch, "arm")) {
		ctx->regs = fastcall_arm;
	} else
	if (!strcmp (arch, "x86")) {
		ctx->regs = fastcall_x86;
	} else
	if (!strcmp (arch,"sh")) {
		ctx->regs = fastcall_sh;
	}

	snprintf (file, sizeof (file), PREFIX"/%s/%s-%s-%d.sdb", 
		SYSCALLPATH, os, arch, bits);
	if (!r_file_exist (file)) {
		eprintf ("Cannot find '%s'\n", file);
		return R_FALSE;
	}

	r_pair_free (ctx->syspair);
	ctx->syspair = r_pair_new_from_file (file);

	if (ctx->fd)
		fclose (ctx->fd);
	ctx->fd = NULL;
	return R_TRUE;
}

R_API int r_syscall_setup_file(RSyscall *ctx, const char *path) {
	if (ctx->fd)
		fclose (ctx->fd);
	ctx->fd = fopen (path, "r");
	if (ctx->fd == NULL)
		return 1;
	/* TODO: load info from file */
	return 0;
}

R_API RSyscallItem *r_syscall_item_new_from_string(const char *name, const char *s) {
	RSyscallItem *si = R_NEW0 (RSyscallItem);
	char *o = strdup (s);

	r_str_split (o, ',');

/*
	return r_syscall_item_new (name, 
			r_num_get (NULL, r_str_word_get0 (o, 0)),
			r_num_get (NULL, r_str_word_get0 (o, 1)),
			r_num_get (NULL, r_str_word_get0 (o, 2)),
			r_str_word_get0 (o, 3));
*/

	si->name = strdup (name);
	si->swi = r_num_get (NULL, r_str_word_get0 (o, 0));
	si->num = r_num_get (NULL, r_str_word_get0 (o, 1));
	si->args = r_num_get (NULL, r_str_word_get0 (o, 2));
	si->sargs = strdup (r_str_word_get0 (o, 3));
	free (o);
	return si;
}

R_API void r_syscall_item_free(RSyscallItem *si) {
	free (si->name);
	free (si->sargs);
	free (si);
}

R_API RSyscallItem *r_syscall_get(RSyscall *ctx, int num, int swi) {
	char *ret, *ret2, foo[32];
	RSyscallItem *si;
	if (!ctx->syspair)
		return NULL;
	snprintf (foo, sizeof (foo), "0x%x.%d", swi, num);
	ret = r_pair_get (ctx->syspair, foo);
	ret2 = r_pair_get (ctx->syspair, ret);
	free (ret);
	si = r_syscall_item_new_from_string (foo, ret2);
	free (ret2);
	return si;
}

R_API int r_syscall_get_num(RSyscall *ctx, const char *str) {
	char *o;
	int i;
	if (!ctx->syspair)
		return 0;
	o = r_pair_get (ctx->syspair, str);
	if (o && *o) {
		r_str_split (o, ',');
		i = r_num_get (NULL, r_str_word_get0 (o, 1));
	}
	free (o);
	return i;
}

// we can probably wrap all this with r_list getters
/* XXX: ugly iterator implementation */
R_API RSyscallItem *r_syscall_get_n(RSyscall *ctx, int n) {
	RList *l;
	if (!ctx->syspair)
		return NULL;
	l = r_pair_list (ctx->syspair, NULL);
// XXX: memory leak !!
	return r_list_get_n (l, n);
}

R_API char *r_syscall_get_i(RSyscall *ctx, int num, int swi) {
	char *ret, foo[32];
	if (!ctx->syspair)
		return NULL;
	if (swi==-1) {
		char *def = r_pair_get (ctx->syspair, "_");
		if (def && *def) {
			swi = r_num_get (NULL, def);
		} else swi = 0x80; // XXX hardcoded
	}
	snprintf (foo, sizeof (foo), "0x%x.%d", swi, num);
	ret = r_pair_get (ctx->syspair, foo);
	return ret;
}

R_API const char *r_syscall_get_io(RSyscall *ctx, int ioport) {
	int i;
	for (i=0; ctx->sysport[i].name; i++) {
		if (ioport == ctx->sysport[i].port)
			return ctx->sysport[i].name;
	}
	return NULL;
}

R_API void r_syscall_list(RSyscall *ctx) {
	int i;
// TODO: use r_pair here
	for (i=0; ctx->sysptr[i].name; i++) {
		ctx->printf ("%02x: %d = %s\n",
			ctx->sysptr[i].swi, ctx->sysptr[i].num, ctx->sysptr[i].name);
	}
}
