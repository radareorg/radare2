#include <r_core.h>
#include <rvc.h>
static bool copy_commits(const Rvc *repo, const char *dpath, const char *sname) {
	char *path, *name, *spath;
	spath = r_str_newf ("%s" R_SYS_DIR "branches" R_SYS_DIR "%s" R_SYS_DIR "commits", repo->path, sname);
	r_return_val_if_fail (spath, NULL);
	RList *files = r_sys_dir (spath);
	if (!files) {
		free (spath);
		return false;
	}
	RListIter *iter;
	ls_foreach (files, iter, name) {
		path = r_str_newf ("%s%s", spath, sname);
		if (!path) {
			free (spath);
			r_list_free (files);
			return false;
		}
		if (!r_file_copy (dpath, path)) {
			free (spath);
			free (path);
			r_list_free (files);
			return false;
		}
		free (path);
	}
	free (spath);
	r_list_free (files);
	return true;
}

static char *branch_mkdir(Rvc *repo, RvcBranch *b) {
	char *path = r_str_newf ("%s" R_SYS_DIR "branches" R_SYS_DIR"%s" R_SYS_DIR "commits" R_SYS_DIR,repo->path, b->name);
	r_return_val_if_fail (path, NULL);
	if (!r_sys_mkdirp (path)) {
		free (path);
		return NULL;
	}
	return path;
}

R_API bool rvc_branch(Rvc *repo, const char *name, const RvcBranch *parent) {
	char *bpath;
	RvcBranch *nb = R_NEW0 (RvcBranch);
	r_return_val_if_fail (nb, NULL);
	nb->head = NULL;
	nb->name = r_str_new (name);
	if (!nb->name) {
		free (nb);
		return false;
	}
	if (!r_list_append (repo->branches, nb)) {
		free (nb->name);
		free (nb);
		return false;
	}
	bpath = branch_mkdir (repo, nb);
	if (!bpath) {
		free (nb->name);
		free (nb);
		r_list_pop (repo->branches);
		return false;
	}
	if (parent) {
		nb->head = parent->head;
		if (!copy_commits (repo, parent->name, bpath)) {
			free (nb->name);
			free (nb);
		}
	}
	return true;
}

R_API Rvc *rvc_new(const char *path) {
	Rvc *repo;
	repo = R_NEW (Rvc);
	r_return_val_if_fail (repo, NULL);
	repo->path = r_str_newf ("%s" R_SYS_DIR ".rvc" R_SYS_DIR, path);
	if (!repo->path) {
		free (repo->path);
		free (repo);
	}
	if (!r_sys_mkdir (repo->path)) {
		free (repo->path);
		free (repo);
	}
	repo->branches = r_list_new ();
	if (!repo->branches) {
		free (repo);
		free (repo->path);
		return NULL;
	}
	rvc_branch (repo, "master", NULL);
	return repo;
}
