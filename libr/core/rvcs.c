#include <r_core.h>
struct blob {
	char *fname;
	char *hash;
};
struct commit {
	struct commit *prev;
	struct blob **blobs;
	char *author;

	int64_t *timestamp;
	uint next_num;
	struct commit **next; //next is an array so we can permit rvc revert
};
struct branch {
	char *name;
	struct commit *head;
};
struct rvc {
	char *path;
	uint branch_num;
	struct branch **branches;
};
static inline bool copy_commits (const char *dpath, const char *spath, struct rvc *repo) {
	RList *files = r_sys_dir (spath);
	if (!files)
		return false;
	RListIter *iter;
	char *path;
	char *name;
	ls_foreach (files, iter, name) {
		path = malloc (r_str_len_utf8 (spath) + r_str_len_utf8 (name) + 1);
		if (!path)
			return false;
		if (!r_file_copy (dpath, path))
			return false;
		free (path);
	}
}
R_API bool rvc_branch (char *name, struct branch *parent, struct rvc *repo) {
	struct branch *nb;
	struct branch **tmp;
	char *bpath;
	nb = malloc (sizeof (struct branch));
	bool ret = false;
	if (!nb)
		return ret;
	nb->name = r_str_new (name);
	if (!nb->name) {
		free (nb);
		return ret;
	}
	bpath = malloc (r_str_len_utf8 (repo->path) + r_str_len_utf8 ("branches/") + r_str_len_utf8 (name) + r_str_len_utf8 ("/commits/") + 1);
	if (!bpath) {
		free (nb->name);
		free (nb);
		return ret;
	}
	sprintf (bpath, "%sbranches/%s/commits", repo->path, name);
	if (!parent) {
		nb->head = NULL;
		ret = r_sys_mkdirp (bpath);
		goto ret;
	}
	ret = copy_commits (bpath, parent->name, repo);
	if (!ret)
		goto ret;
	repo->branch_num++;
	tmp = realloc (repo->branches, repo->branch_num * sizeof (struct branch));
	if (!tmp) {
		repo->branch_num--;
		goto ret;
	}
	repo->branches[repo->branch_num - 1] = nb;
	ret = true;
	goto ret;
ret:
	free (nb->name);
	free (nb);
	free (bpath);
	return ret;
}
R_API struct rvc *rvc_init (const char *path) {
	struct rvc *repo;
	repo = malloc (sizeof (struct rvc));
	if (!repo)
		return NULL;
	repo->branch_num = 0;
	repo->path = malloc (r_str_len_utf8 (path) + r_str_len_utf8 ("/.rvcs/") + 1);
	if (!repo->path) {
		free (repo->path);
		free (repo);
	}
	sprintf (repo->path, "%s/.rvcs/", path);
	r_sys_mkdir (repo->path);
	return repo;
}
