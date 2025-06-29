/* radare - Copyright 2008-2025 - LGPL -- pancake */

#include <r_syscall.h>

R_LIB_VERSION (r_syscall);

// TODO: now we use sdb
extern RSyscallPort sysport_x86[];
extern RSyscallPort sysport_avr[];

R_API RSyscall* r_syscall_ref(RSyscall *sc) {
	sc->refs++;
	return sc;
}

R_API RSyscall* r_syscall_new(void) {
	RSyscall *rs = R_NEW0 (RSyscall);
	if (rs) {
		rs->sysport = sysport_x86;
		rs->srdb = sdb_new0 (); // sysregs database
		rs->db = sdb_new0 ();
	}
	return rs;
}

R_API void r_syscall_free(RSyscall *s) {
	if (s) {
		if (s->refs > 0) {
			s->refs--;
			return;
		}
		sdb_free (s->srdb);
		sdb_free (s->db);
		free (s->os);
		free (s->cpu);
		free (s->arch);
		free (s);
	}
}

R_API SdbGperf *r_syscall_get_gperf(const char *k);

static Sdb *openDatabase(Sdb *db, const char *name) {
	SdbGperf *sg = r_syscall_get_gperf (name);
	if (sg) {
		sdb_reset (db);
		sdb_open_gperf (db, sg);
	} else {
		char *file = r_str_newf (R_JOIN_3_PATHS ("%s", R2_SDB, "%s.sdb"), r_sys_prefix (NULL), name);
		if (r_file_exists (file)) {
			if (db) {
				sdb_reset (db);
				sdb_open (db, file);
			} else {
				db = sdb_new (0, file, 0);
			}
		} else {
			sdb_free (db);
			db = sdb_new0 ();
		}
		free (file);
	}
	return db;
}

static inline bool syscall_reload_needed(RSyscall *s, const char *os, const char *arch, int bits) {
	if (!s->os || strcmp (s->os, os)) {
		return true;
	}
	if (!s->arch || strcmp (s->arch, arch)) {
		return true;
	}
	return s->bits != bits;
}

static inline bool sysregs_reload_needed(RSyscall *s, const char *arch, int bits, const char *cpu) {
	if (!s->arch || strcmp (s->arch, arch)) {
		return true;
	}
	if (s->bits != bits) {
		return true;
	}
	return !s->cpu || strcmp (s->cpu, cpu);
}

// TODO: should be renamed to r_syscall_use();
R_API bool r_syscall_setup(RSyscall *s, const char *arch, int bits, const char *cpu, const char *os) {
	R_RETURN_VAL_IF_FAIL (s, false);
	bool syscall_changed, sysregs_changed;

	if (!os || !*os) {
		os = R_SYS_OS;
	}
	if (!arch) {
		arch = R_SYS_ARCH;
	}
	if (!cpu) {
		cpu = arch;
	}
	syscall_changed = syscall_reload_needed (s, os, arch, bits);
	sysregs_changed = sysregs_reload_needed (s, arch, bits, cpu);

	free (s->os);
	s->os = strdup (os);

	free (s->cpu);
	s->cpu = strdup (cpu);

	free (s->arch);
	s->arch = strdup (arch);

	s->bits = bits;

	if (!strcmp (os, "any")) { // ignored
		return true;
	}
	if (!strcmp (arch, "avr")) {
		s->sysport = sysport_avr;
	}
	if (!strcmp (os, "darwin") || !strcmp (os, "osx") || !strcmp (os, "macos")) {
		os = "darwin";
	} else if (!strcmp (os, "android")) {
		os = "linux";
		syscall_changed = true;
	} else if (!strcmp (arch, "x86")) {
		s->sysport = sysport_x86;
	}
	if (r_str_startswith (arch, "arm") && bits == 16 && !strcmp (os, "linux")) {
	//	syscall_changed = true;
		bits = 32;
	}

	if (syscall_changed) {
		char *dbName = r_str_newf (R_JOIN_2_PATHS ("syscall", "%s-%s-%d"),
			os, arch, bits);
		if (dbName) {
			s->db = openDatabase (s->db, dbName);
			free (dbName);
		}
	}

	if (sysregs_changed) {
		char *dbName = r_str_newf (R_JOIN_2_PATHS ("sysregs", "%s-%d-%s"),
			arch, bits, cpu);
		if (dbName) {
			sdb_free (s->srdb);
			s->srdb = openDatabase (NULL, dbName);
			free (dbName);
		}
	}
	if (s->fd) {
		fclose (s->fd);
		s->fd = NULL;
	}
	return true;
}

R_API RSyscallItem *r_syscall_item_new_from_string(const char *name, const char *s) {
	R_RETURN_VAL_IF_FAIL (name && s, NULL);
	char *o = strdup (s);
	int cols = r_str_split (o, ',');
	if (cols < 2) {
		free (o);
		return NULL;
	}

	RSyscallItem *si = R_NEW0 (RSyscallItem);
	si->name = strdup (name);
	si->swi = (int)r_num_get (NULL, r_str_word_get0 (o, 0));
	si->num = (int)r_num_get (NULL, r_str_word_get0 (o, 1));
	if (cols > 2) {
		si->args = (int)r_num_get (NULL, r_str_word_get0 (o, 2));
	} else {
		si->args = 0;
	}
	si->sargs = calloc (si->args + 1, sizeof (char));
	if (!si->sargs) {
		free (si);
		free (o);
		return NULL;
	}
	if (cols > 3) {
		strncpy (si->sargs, r_str_word_get0 (o, 3), si->args);
	}
	free (o);
	return si;
}

R_API void r_syscall_item_free(RSyscallItem *si) {
	if (si) {
		free (si->name);
		free (si->sargs);
		free (si);
	}
}

static int getswi(RSyscall *s, int swi) {
	if (s && swi == -1) {
		return r_syscall_get_swi (s);
	}
	return swi;
}

R_API int r_syscall_get_swi(RSyscall *s) {
	R_RETURN_VAL_IF_FAIL (s, -1);
	return (int)sdb_num_get (s->db, "_", NULL);
}

R_API RSyscallItem *r_syscall_get(RSyscall *s, int num, int swi) {
	R_RETURN_VAL_IF_FAIL (s && s->db, NULL);
	char key[128];
	swi = getswi (s, swi);
	if (swi < 16) {
		snprintf (key, sizeof (key), "%d.%d", swi, num);
	} else {
		snprintf (key, sizeof (key), "0x%02x.%d", swi, num);
	}
	const char *ret = sdb_const_get (s->db, key, 0);
	if (!ret) {
		snprintf (key, sizeof (key), "0x%02x.0x%02x", swi, num); // Workaround until Syscall SDB is fixed
		ret = sdb_const_get (s->db, key, 0);
		if (!ret) {
			snprintf (key, sizeof (key), "0x%02x.%d", num, swi); // Workaround until Syscall SDB is fixed
			ret = sdb_const_get (s->db, key, 0);
			if (!ret) {
				return NULL;
			}
		}
	}
	const char *ret2 = sdb_const_get (s->db, ret, 0);
	return ret2? r_syscall_item_new_from_string (ret, ret2): NULL;
}

R_API int r_syscall_get_num(RSyscall *s, const char *str) {
	R_RETURN_VAL_IF_FAIL (s && str && s->db, -1);
	int sn = (int)sdb_array_get_num (s->db, str, 1, NULL);
	if (sn == 0) {
		return (int)sdb_array_get_num (s->db, str, 0, NULL);
	}
	return sn;
}

R_API const char *r_syscall_get_i(RSyscall *s, int num, int swi) {
	R_RETURN_VAL_IF_FAIL (s && s->db, NULL);
	char foo[32];
	swi = getswi (s, swi);
	snprintf (foo, sizeof (foo), "0x%x.%d", swi, num);
	return sdb_const_get (s->db, foo, 0);
}

static bool callback_list(void *u, const char *k, const char *v) {
	RList *list = (RList*)u;
	if (!strchr (k, '.')) {
		RSyscallItem *si = r_syscall_item_new_from_string (k, v);
		if (!si) {
			return true;
		}
		if (!strchr (si->name, '.')) {
			r_list_append (list, si);
		} else {
			r_syscall_item_free (si);
		}
	}
	return true; // continue loop
}

R_API RList *r_syscall_list(RSyscall *s) {
	R_RETURN_VAL_IF_FAIL (s && s->db, NULL);
	RList *list = r_list_newf ((RListFree)r_syscall_item_free);
	if (!list) {
		return NULL;
	}
	sdb_foreach (s->db, callback_list, list);
	return list;
}

/* io and sysregs */
R_API const char *r_syscall_get_io(RSyscall *s, int ioport) {
	R_RETURN_VAL_IF_FAIL (s, NULL);
	int i;
	const char *name = r_syscall_sysreg (s, "io", ioport);
	if (name) {
		return name;
	}
	for (i = 0; s->sysport[i].name; i++) {
		if (ioport == s->sysport[i].port) {
			return s->sysport[i].name;
		}
	}
	return NULL;
}

R_API const char* r_syscall_sysreg(RSyscall *s, const char *type, ut64 num) {
	R_RETURN_VAL_IF_FAIL (s && s->db, NULL);
	r_strf_var (key, 64, "%s,%"PFMT64d, type, num);
	return sdb_const_get (s->db, key, 0);
}
