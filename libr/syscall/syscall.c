/* radare 2008-2013 LGPL -- pancake */

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
		rs->syspair = NULL;
		rs->printf = (PrintfCallback)printf;
		rs->regs = fastcall_x86_32;
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
	char file[256];

	if (os == NULL)
		os = R_SYS_OS;
	if (arch == NULL)
		arch = R_SYS_ARCH;
	if (!strcmp (os, "any")) // ignored
		return R_TRUE;
	if (!strcmp (arch, "mips"))
		ctx->regs = fastcall_mips;
	else if (!strcmp (arch, "arm"))
		ctx->regs = fastcall_arm;
	else if (!strcmp (arch, "x86")) {
		switch (bits) {
		case 8: ctx->regs = fastcall_x86_8;
		case 32: ctx->regs = fastcall_x86_32;
		case 64: ctx->regs = fastcall_x86_64;
		}
	} else if (!strcmp (arch,"sh")) {
		ctx->regs = fastcall_sh;
	}

#define SYSCALLPATH R2_LIBDIR"/radare2/"R2_VERSION"/syscall"
	snprintf (file, sizeof (file), "%s/%s-%s-%d.sdb", 
		SYSCALLPATH, os, arch, bits);
	if (!r_file_exists (file)) {
		//eprintf ("r_syscall_setup: Cannot find '%s'\n", file);
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
	ctx->fd = r_sandbox_fopen (path, "r");
	if (ctx->fd == NULL)
		return 1;
	/* TODO: load info from file */
	return 0;
}

R_API RSyscallItem *r_syscall_item_new_from_string(const char *name, const char *s) {
	RSyscallItem *si;
	char *o;

	if (!s) return NULL;
	si = R_NEW0 (RSyscallItem);
	o = strdup (s);

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

static int getswi(RPair *p, int swi) {
	char *def;
	if (swi == -1) {
		def = r_pair_get (p, "_");
		if (def && *def) {
			swi = r_num_get (NULL, def);
			free (def);
		} else swi = 0x80; // XXX hardcoded
	}
	return swi;
}

R_API RSyscallItem *r_syscall_get(RSyscall *ctx, int num, int swi) {
	char *ret, *ret2, foo[32];
	RSyscallItem *si;
	if (!ctx->syspair)
		return NULL;
	swi = getswi (ctx->syspair, swi);
	snprintf (foo, sizeof (foo), "0x%02x.%d", swi, num);
	ret = r_pair_get (ctx->syspair, foo);
	if (ret == NULL)
		return NULL;
	ret2 = r_pair_get (ctx->syspair, ret);
	if (ret2 == NULL)
		return NULL;
	si = r_syscall_item_new_from_string (ret, ret2);
	free (ret);
	free (ret2);
	return si;
}

R_API int r_syscall_get_num(RSyscall *ctx, const char *str) {
	char *o;
	int i = 0;
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

R_API char *r_syscall_get_i(RSyscall *ctx, int num, int swi) {
	char *ret, foo[32];
	if (!ctx->syspair)
		return NULL;
	swi = getswi (ctx->syspair, swi);
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

R_API RList *r_syscall_list(RSyscall *ctx) {
	RListIter *iter;
	RPairItem *o;
	RList *list = r_pair_list (ctx->syspair, NULL);

	RList *olist = r_list_new ();
	olist->free = (RListFree)r_syscall_item_free;
	r_list_foreach (list, iter, o) {
		RSyscallItem *si = r_syscall_item_new_from_string (o->k, o->v);
		if (!strchr (si->name, '.'))
			r_list_append (olist, si);
	}
	r_list_free (list);
	return olist;
}
