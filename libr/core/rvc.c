#include <rvc.h>
static bool copy_commits(const Rvc *repo, const char *dpath, const char *sname) {
	char *spath = r_str_newf ("%s" R_SYS_DIR "branches" R_SYS_DIR "%s" R_SYS_DIR "commits", repo->path, sname);
	r_return_val_if_fail (spath, false);
	char *path, *name;
	bool ret = true;
	RList *files = r_sys_dir (spath);
	if (!files) {
		free (spath);
		return false;
	}
	RListIter *iter;
	ls_foreach (files, iter, name) {
		path = r_str_newf ("%s" R_SYS_DIR "%s", spath, sname);
		if (!path) {
			ret = false;
			break;
		}
		ret = r_file_copy (dpath, path);
		free (path);
		if (!ret) {
			break;
		}
	}
	free (spath);
	r_list_free (files);
	return ret;
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
	if (!nb) {
		eprintf ("Failed To Allocate Branch Struct\n");
		return false;
	}
	nb->head = NULL;
	nb->name = r_str_new (name);
	if (!nb->name) {
		eprintf ("Failed To Allocate Branch Name\n");
		free (nb);
		return false;
	}
	if (!r_list_append (repo->branches, nb)) {
		eprintf ("Failed To Allocate Branch Struct\n");
		free (nb->name);
		free (nb);
		return false;
	}
	bpath = branch_mkdir (repo, nb);
	if (!bpath) {
		eprintf ("Failed To Create Branch Directory\n");
		free (nb->name);
		free (nb);
		r_list_pop (repo->branches);
		return false;
	}
	if (parent) {
		nb->head = parent->head;
		if (!copy_commits (repo, parent->name, bpath)) {
			eprintf ("Failed To Copy Commits From Parent\n");
			free (nb->name);
			free (nb);
			free (bpath);
			return false;
		}
	}
	free (bpath);
	return true;
}

R_API Rvc *rvc_new(const char *path) {
	Rvc *repo;
	repo = R_NEW (Rvc);
	if (!repo) {
		eprintf ("Failed To Allocate Repoistory Path\n");
	}
	repo->path = r_str_newf ("%s" R_SYS_DIR ".rvc" R_SYS_DIR, path);
	if (!repo->path) {
		eprintf ("Failed To Allocate Repository Path\n");
		free (repo);
		return NULL;
	}
	if (!r_sys_mkdir (repo->path)) {
		eprintf ("Failed To Create Repo Directory\n");
		free (repo->path);
		free (repo);
	}
	repo->branches = r_list_new ();
	if (!repo->branches) {
		eprintf ("Failed To Allocate Branches List\n");
		free (repo);
		free (repo->path);
		return NULL;
	}
	if (!rvc_branch (repo, "master", NULL)) {
		free (repo->path);
		r_list_free (repo->branches);
		free (repo);
		return NULL;
	}
	return repo;
}
