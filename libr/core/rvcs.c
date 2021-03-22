#include <r_core.h>
typedef struct blob {
	char *fname;
	char *hash;
} BLOB;

typedef struct commit {
	struct commit *prev;
	struct blob **blobs;
	char *author;
	int64_t *timestamp;
	char *hash;
	size_t next_num;
	RList *next; //next is an array so we can permit RVc revert
} COMMIT;

typedef struct branch {
	char *name;
	COMMIT *head;
} BRANCH;

typedef struct RVc {
	char *path;
	RList *branches;
} RVC;

static bool copy_commits(const RVC *repo, const char *dpath, const char *sname) {
	char *path, *name, *spath;
	spath = r_str_newf ("%s" R_SYS_DIR "branches" R_SYS_DIR "%s" R_SYS_DIR "commits", repo->path, sname);
	if (!spath) {
		return false;
	}
	RList *files = r_sys_dir (spath);
	if (!files) {
		return false;
	}
	RListIter *iter;
	ls_foreach (files, iter, name) {
		path = malloc (r_str_len_utf8 (spath) + r_str_len_utf8 (name) + 1);
		if (!path) {
			return false;
		}
		if (!r_file_copy (dpath, path)) {
			free (path);
			return false;
		}
		free (path);
	}
	return true;
}

static char *branch_mkdir(RVC *repo, BRANCH *b) {
	char *path = r_str_newf ("%s" R_SYS_DIR "branches" R_SYS_DIR"%s" R_SYS_DIR "commits" R_SYS_DIR,repo->path, b->name);
	if (!path) {
		return NULL;
	}
	if (!r_sys_mkdirp (path)) {
		free (path);
		return NULL;
	}
	return path;
}

R_API bool rvc_branch(RVC *repo, const char *name, const BRANCH *parent) {
	char *bpath;
	BRANCH *nb = malloc (sizeof (BRANCH));
	if (!nb) {
		return false;
	}
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

R_API RVC *rvc_new(const char *path) {
	RVC *repo;
	repo = malloc (sizeof (RVC));
	if (!repo) {
		return NULL;
	}
	repo->path = r_str_newf ("%s" R_SYS_DIR ".RVcs" R_SYS_DIR, path);
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
