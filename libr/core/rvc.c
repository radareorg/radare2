#include <rvc.h>
#include <r_util.h>
static inline bool is_branch_name(char *name) {
	for (; *name; name++) {
		r_return_val_if_fail (IS_DIGIT (*name) || isalpha (*name), false);
	}
	return true;
}

static bool copy_commits(const Rvc *repo, const char *dpath, const char *spath) {
	char *name, *commit_path;
	RListIter *iter;
	RList *files;
	files = r_sys_dir (spath);
	bool ret = true;
	if (!files) {
		eprintf ("Can't Open Files\n");
		return false;
	}
	r_list_foreach (files, iter, name) {
		if (r_str_cmp (name, "..", 2) == 0 ||
				r_str_cmp (name, ".", 1) == 0) {
			printf ("%s", name);
			continue;
		}
		commit_path = r_str_newf ("%s" R_SYS_DIR "%s", spath, name);
		if (!commit_path) {
			ret = false;
			break;
		}
		ret = r_file_copy (commit_path, dpath);
		free (commit_path);
		if (!ret) {
			break;
		}
	}
	r_list_free (files);
	return ret;
}

static char *branch_mkdir(Rvc *repo, RvcBranch *b) {
	char *path = r_str_newf ("%s" R_SYS_DIR "branches" R_SYS_DIR "%s"
			R_SYS_DIR "commits" R_SYS_DIR, repo->path, b->name);
	r_return_val_if_fail (path, NULL);
	if (!r_sys_mkdirp (path)) {
		R_FREE (path);
	}
	return path;
}

static char *find_sha256(const ut8 *block, int len) {
	RHash *ctx = r_hash_new (true, R_HASH_SHA256);
	const ut8 *c = r_hash_do_sha256 (ctx, block, len);
	char *ret = r_hex_bin2strdup (c, R_HASH_SIZE_SHA256);
	r_hash_free (ctx);
	return ret;
}

static inline char *sha256_file(const char *fname) {
	char *content = r_file_slurp (fname, NULL);
	r_return_val_if_fail (content, NULL);
	return find_sha256 ((ut8 *)content, r_str_len_utf8 (content) * sizeof (char));
}

static bool write_commit(Rvc *repo, RvcBranch *b, RvcCommit *commit) {
	char *commit_path, *commit_string;
	char *prev_path;
	FILE *prev_file, *commit_file;
	RListIter *iter;
	RvcBlob *blob;
	commit_string = r_str_newf ("author:%s\nmessage:%s\nntimestamp:%ld\n----",
			commit->author, commit->message, commit->timestamp);
	r_return_val_if_fail (commit_string, false);
	r_list_foreach (commit->blobs, iter, blob) {
		char *tmp = r_str_appendf (commit_string, "\nblob:%s:%s",
				blob->fname, blob->hash);
		if (!tmp) {
			free (commit_string);
			return false;
		}
		commit_string = tmp;
	}
	commit->hash = find_sha256 ((ut8 *) commit,
			r_str_len_utf8 (commit_string) * sizeof (char));
	if (!commit->hash) {
		free (commit);
		return false;
	}
	commit_path = r_str_newf ("%s" R_SYS_DIR "branches" R_SYS_DIR
			"%s" R_SYS_DIR "commits" R_SYS_DIR "%s",
			repo->path, b->name, commit->hash);
	if (!commit_path) {
		free (commit);
		return false;
	}
	commit_file = fopen (commit_path, "w+");
	free (commit_path);
	if (!commit_file) {
		free (commit_string);
		return false;
	}
	fprintf (commit_file, "%s", commit_string);
	free (commit_string);
	if (!commit->prev) {
		fclose (commit_file);
		return true;
	}
	prev_path = r_str_newf ("%s" R_SYS_DIR "branches" R_SYS_DIR
			"%s" R_SYS_DIR "commits" R_SYS_DIR "%s",
			repo->path, b->name, commit->prev->hash);
	if (!prev_path) {
		fclose (commit_file);
		return false;
	}
	prev_file = fopen (prev_path, "r+");
	free (prev_path);
	if (!prev_file) {
		fclose (commit_file);
		return false;
	}
	fprintf (commit_file, "\nprev:%s", commit->prev->hash);
	fclose (commit_file);
	fseek (prev_file, 0, SEEK_END);
	fprintf (prev_file, "\nnext:%s", commit->hash);
	fclose (prev_file);
	return true;
}
R_API bool rvc_commit(Rvc *repo, RList *blobs, const char *auth, const char *message) {
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
	nc->message = r_str_new (message);
	if (!nc->message) {
		free (nc->author);
		free (nc);
		return false;
	}
	nc->timestamp = time (NULL);
	nc->prev = repo->current_branch->head;
	nc->blobs = blobs;
	if (!write_commit (repo, repo->current_branch, nc)) {
		free (nc->author);
		free (nc->message);
		free (nc);
		eprintf ("Failed To Create Commit File\n");
		return false;
	}
	repo->current_branch->head = nc;
	return true;
}
R_API bool rvc_branch(Rvc *repo, const char *name) {
	char *bpath, *ppath;
	RvcBranch *nb = R_NEW0 (RvcBranch);
	if (!is_branch_name (name)) {
		eprintf ("%s Is Not A Vaild Branch Name", name);
		return false;
	}
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
	if (repo->current_branch) {
		nb->head = repo->current_branch->head;
		ppath = r_str_newf ("%s" R_SYS_DIR "branches" R_SYS_DIR "%s"
				R_SYS_DIR "commits" R_SYS_DIR,
				repo->path, repo->current_branch->name);
		if (!copy_commits (repo, bpath, ppath)) {
			eprintf ("Failed To Copy Commits From Parent\n");
			free (nb->name);
			free (nb);
			free (bpath);
			return false;
		}
	}
	repo->current_branch = nb;
	free (bpath);
	return true;
}

R_API Rvc *rvc_new(const char *path) {
	Rvc *repo = R_NEW (Rvc);
	char *blob_path;
	if (!repo) {
		eprintf ("Failed To Allocate Repoistory Path\n");
		return false;
	}
	repo->current_branch = NULL;
	repo->path = r_str_newf ("%s" R_SYS_DIR ".rvc" R_SYS_DIR, path);
	if (r_file_exists (repo->path)) {
		eprintf ("RVC Repoistory Already exists in %s\n", repo->path);
		free (repo->path);
		free (repo);
		return false;
	}
	if (!repo->path) {
		eprintf ("Failed To Allocate Repoistory Path\n");
		free (repo);
		return NULL;
	}
	if (!r_sys_mkdir (repo->path)) {
		eprintf ("Failed To Create Repo Directory\n");
		free (repo->path);
		free (repo);
		return NULL;
	}
	repo->branches = r_list_new ();
	if (!repo->branches) {
		eprintf ("Failed To Allocate Branches List\n");
		free (repo);
		free (repo->path);
		return NULL;
	}
	if (!rvc_branch (repo, "master")) {
		eprintf ("Failed To Create The master Branch\n");
		free (repo->path);
		r_list_free (repo->branches);
		free (repo);
		return NULL;
	}
	blob_path = r_str_newf ("%s" R_SYS_DIR "blobs", repo->path);
	if (!blob_path) {
		r_list_free  (repo->branches);
		free (repo->path);
		return NULL;
	}
	if (!r_sys_mkdir (blob_path)) {
		r_list_free (repo->branches);
		free (blob_path);
		free (repo->path);
		free (repo);
		return NULL;
	};
	free (blob_path);
	return repo;
}
R_API RList *rvc_add(Rvc *repo, RList *files) {
	RListIter *iter;
	RList *blobs = r_list_new ();
	char *blob_path;
	if (!blobs) {
		eprintf ("Failed To Allocate Blobs");
		return NULL;
	}
	char *fname;
	const char *blobs_path = r_str_newf ("%s" R_SYS_DIR "blobs", repo->path);
	r_list_foreach (files, iter, fname) {
		RvcBlob *b = R_NEW (RvcBlob);
		if (!b) {
			r_list_free (blobs);
		}
		b->fname = r_str_new (fname);
		if (!b->fname) {
			free (b);
			r_list_free (blobs);
			return NULL;
		}
		b->hash = sha256_file (fname);
		if (!b->hash) {
			free (b->fname);
			free (b);
			r_list_free (blobs);
			return NULL;
		}
		blob_path = r_str_newf ("%s" R_SYS_DIR "%s", blobs_path, b->hash);
		if (!blob_path) {
			free (b->fname);
			free (b->hash);
			free (b);
			r_list_free (blobs);
			return NULL;
		}
		if (!r_file_copy (fname, blob_path)) {
			free (blob_path);
			free (b->fname);
			free (b->hash);
			free (b);
			r_list_free (blobs);
			return NULL;
		}
		free (blob_path);
		r_list_append (blobs, b);
		b = NULL;
	}
	return blobs;
}

static RvcBranch *branch_by_name(Rvc *repo, char *name) {
	RListIter *iter;
	RvcBranch *b;
	r_list_foreach (repo->branches, iter, b) {
		r_return_val_if_fail (r_str_cmp (name, b->name, r_str_len_utf8 (b->name) * sizeof (char)), b);
	}
	return NULL;
}

R_API int git_init (const char *path) {
	return r_sys_cmdf ("git init %s", path);
}

R_API int git_branch (const char *path, const char *name) {
	return r_sys_cmdf ("git -C %s checkout -b %s", path, name);
}

R_API int git_add (const char *path, const char *fname) {
	return r_sys_cmdf ("git -C %s branch %s", path, fname);
}

R_API int git_commit (const char *path, const char *message) {
	return r_sys_cmdf ("git -C %s commit -m %s", path, message);
}
