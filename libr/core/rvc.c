#include <rvc.h>
static bool copy_commits(const Rvc *repo, const char *dpath, const char *sname) {
	char *spath = r_str_newf ("%s" R_SYS_DIR "branches" R_SYS_DIR "%s"
			R_SYS_DIR "commits", repo->path, sname);
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
		path = r_str_newf ("%s" R_SYS_DIR "%s", spath, name);
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
	char *path = r_str_newf ("%s" R_SYS_DIR "branches" R_SYS_DIR "%s"
			R_SYS_DIR "commits" R_SYS_DIR,repo->path, b->name);
	r_return_val_if_fail (path, NULL);
	if (!r_sys_mkdirp (path)) {
		free (path);
		return NULL;
	}
	return path;
}

static inline char *hashtohex(const ut8 *data, size_t len) {
	char *tmp, *ret = r_str_new ("");
	int i = 0;
	for (i = 0; i < len; i++) {
		tmp = r_str_appendf (ret, "%02x", data[i]);
		if (!tmp) {
			if (!R_STR_ISEMPTY(ret)) {
				free (ret);
			}
			return NULL;
		}
	}
	return ret;
}

static char *find_sha256(const ut8 *block, int len) {
	char *ret;
	RHash *ctx = r_hash_new (true, R_HASH_SHA256);
	const ut8 *c = r_hash_do_sha256 (ctx, block, len);
	ret = hashtohex (c, R_HASH_SIZE_SHA256);
	r_hash_free (ctx);
	return ret;
}

static bool write_commit(Rvc *repo, RvcBranch *b, RvcCommit *c) {
	char *tmp, *commit = r_str_newf ("author:%s\ntimestamp:%ld\nprev:%s",
			c->author, c->timestamp, c->prev->hash);
	r_return_val_if_fail (commit, false);
	char *ppath, *cpath;
	FILE *pfile, *cfile;
	RListIter *iter;
	RvcBlob *blob;
	ls_foreach (c->blobs, iter, blob) {
		tmp = r_str_appendf (commit, "\n%s:%s",
				blob->fname, blob->hash);
		if (!tmp) {
			free (commit);
			return false;
		}
		commit = tmp;
	}
	c->hash = find_sha256 ((unsigned char *)commit,
			r_str_len_utf8 (commit) * sizeof (char));
	if (!c->hash) {
		free (commit);
		return false;
	}
	cpath = r_str_newf ("%s" R_SYS_DIR "branches" R_SYS_DIR "%s"
			R_SYS_DIR"%s", repo->path, b->name, c->prev->hash);
	cfile = fopen (ppath, "w");
	free (cpath);
	if (!cfile) {
		free (commit);
		return false;
	}
	fprintf (cfile, "%s", commit);
	fclose (cfile);
	if (c->prev) {
		ppath = r_str_newf ("%s" R_SYS_DIR "branches" R_SYS_DIR "%s"
				R_SYS_DIR "%s", repo->path, b->name, c->hash);
		pfile = fopen (ppath, "r+");
		free (ppath);
		if (!pfile) {
			free (commit);
			return false;
		}
		fseek (pfile, 0, SEEK_END);
		fprintf (pfile, "\nnext:%s", c->hash);
		fclose (pfile);
	}
	free (commit);
	return true;
}
R_API bool rvc_commit(Rvc *repo, RvcBranch *b, RList *blobs, char *auth) {
	RvcCommit *nc = R_NEW (RvcCommit);
	if (!nc) {
		eprintf ("Failed To Allocate New Commit\n");
		return false;
	}
	nc->author = r_str_new (auth);
	if (!nc->author) {
		free (nc);
		eprintf ("Failed To Allocate New Commit\n");
		return false;
	}
	nc->timestamp = time (NULL);
	nc->prev = b->head;
	nc->blobs = blobs;
	if (!write_commit (repo, b, nc)) {
		free (nc->author);
		free (nc);
		eprintf ("Failed To Create Commit File\n");
		return false;
	}
	free (nc->author);
	free (nc);
	return true;
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
	r_list_append (repo->branches, nb);
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
	Rvc *repo = R_NEW (Rvc);
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
