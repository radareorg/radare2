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
	char *hash;
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
static inline bool copy_commits(const char *dpath, const char *sname, const struct rvc *repo) {
	char *spath = malloc (r_str_len_utf8 (repo->path) + r_str_len_utf8("branches/commits") + r_str_len_utf8(sname) + 1);
	sprintf (spath, "%s/branches/commits/%s/commits", repo->path, sname);
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
		if (!r_file_copy (dpath, path)) {
			free (path);
			return false;
		}
		free (path);
	}
}
static inline char *branch_mkdir(struct rvc *repo, struct branch *b) {
	char *path;
	path = malloc (r_str_len_utf8(repo->path) + r_str_len_utf8("/branches/") + r_str_len_utf8(b->name) + 1);
	if (!path) {
		return NULL;
	}
	if (!r_sys_mkdirp (path)) {
		free (path);
		return NULL;
	}
	return path;
}
R_API bool rvc_branch(const char *name, const struct branch *parent, struct rvc *repo) {
	struct branch *nb;
	struct branch **tmp;
	char *bpath;
	nb = malloc (sizeof (struct branch));
	if (!nb)
		return false;
	nb->head = NULL;
	nb->name = r_str_new (name);
	if (!nb->name) {
		free (nb);
		return false;
	}
	repo->branch_num++;
	tmp = realloc (repo->branches, repo->branch_num * sizeof (struct branch *));
	if (!tmp) {
		repo->branch_num--;
		free (nb->name);
		free (nb);
		free (bpath);
		return false;
	}
	repo->branches = tmp;
	repo->branches[repo->branch_num - 1] = nb;
	bpath = branch_mkdir (repo, nb);
	if (!bpath)
		return false;
	if (parent) {
		nb->head = parent->head;
		if (!copy_commits (bpath, parent->name, repo)) {
			free (nb->name);
			free (nb);
			repo->branch_num--;
			repo->branches = realloc (repo->branches, repo->branch_num * sizeof (struct branch *));
			free (bpath);
		}
	}
	return true;
}
R_API struct rvc *rvc_init(const char *path) {
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
