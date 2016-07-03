/* radare - Copyright 2016 - LGPL -- xvilka */

#include <r_types.h>
#include <r_util.h>
#include <r_syscall.h>
#include <stdio.h>
#include <string.h>

R_API RSysregs* r_sysregs_new() {
	RSysregs *rs = R_NEW0 (RSysregs);
	if (rs) {
		rs->arch = "x86";
		rs->cpu = "x86";
		rs->sysregs = NULL;
	}
	return rs;
}

R_API void r_sysregs_free(RSysregs *s) {
	sdb_free (s->db);
	free (s->arch);
	free (s->cpu);
	free (s->sysregs);
	memset (s, 0, sizeof (RSysregs));
	free (s);
}

R_API int r_sysregs_setup(RSysregs *s, const char *arch, const char *cpu) {
	const char *file;
	if (!arch) arch = R_SYS_ARCH;

	s->cpu = strdup (cpu);

	if (!strcmp (cpu, "any")) { // ignored
		return true;
	}

#define SYSREGSPATH R2_LIBDIR"/radare2/"R2_VERSION"/sysregs"
	file = sdb_fmt (0, "%s/%s-%s-%d.sdb",
		SYSREGSPATH, arch, cpu);
	if (!r_file_exists (file)) {
		//eprintf ("r_sysregs_setup: Cannot find '%s'\n", file);
		return false;
	}

	sdb_close (s->db);
	sdb_free (s->db);
	s->db = sdb_new (0, file, 0);
	if (s->fd) {
		fclose (s->fd);
	}
	s->fd = NULL;
	return true;
}

R_API void r_sysregs_item_free(RSysregsItem *si) {
	if (!si) return;
	free (si->name);
	free (si->description);
	free (si);
}

R_API RSysregsItem *r_sysregs_get(RSysregs *s, ut64 address, int type) {
	const char *name, *key;
	RSysregsItem *si;
	if (!s || !s->db) {
		return NULL;
	}
	key = sdb_fmt (0, "0x%08"PFMT64x".%d", address, type);
	name = sdb_const_get (s->db, key, 0);
	if (name == NULL) {
		return NULL;
	}
	si->name = name;
	return si;
}

