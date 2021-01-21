/* radare - LGPL - Copyright 2020 - pancake */

// project class definition to be used by project.c

#include <r_core.h>

R_API RProject *r_project_new(void) {
	RProject *p = R_NEW0 (RProject);
	return p;
}

R_API bool r_project_rename(RProject *p, const char *newname) {
	if (!r_project_is_loaded (p)) {
		return false;
	}
	char *newprjdir = r_file_new (p->path, "..", newname, NULL);
	if (r_file_exists (newprjdir)) {
		eprintf ("Cannot rename.\n");
		free (newprjdir);
		return false;
	}
	r_file_move (p->path, newprjdir);
	free (p->path);
	p->path = newprjdir;
	free (p->name);
	p->name = strdup (newname);
	return false;
}

R_API bool r_project_is_git(RProject *p) {
	char *f = r_str_newf ("%s"R_SYS_DIR".git", p->path);
	bool ig = r_file_is_directory (f);
	free (f);
	return ig;
}

R_API void r_project_close(RProject *p) {
	// close the current project
	R_FREE (p->name);
	R_FREE (p->path);
}

R_API bool r_project_open(RProject *p, const char *name, const char *path) {
	r_return_val_if_fail (p && !R_STR_ISEMPTY (name), false);
	if (r_project_is_loaded (p)) {
		if (!strcmp (name, p->name)) {
			return true;
		}
		return false;
	}
	p->name = strdup (name);
	if (path) {
		p->path = strdup (path);
	}
	return true;
}

R_API void r_project_save(RProject *p) {
	// must call r_core_project_save()
}

R_API void r_project_free(RProject *p) {
	if (p) {
		free (p->name);
		free (p->path);
		free (p);
	}
}

R_API bool r_project_is_loaded(RProject *p) {
	return !R_STR_ISEMPTY (p->name);
}
