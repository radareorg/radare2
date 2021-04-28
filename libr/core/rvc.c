/* radare - LGPL - Copyright 2021-2023 - RHL120, pancake */

#include <rvc.h>

static inline bool is_branch_name(const char *name) {
	for (; *name; name++) {
		if (!IS_DIGIT (*name) && !isalpha (*name)) {
			return false;
		}
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
	return find_sha256 ((ut8 *)content, r_str_len_utf8 (content) * sizeof (ut8));
}

static char *read_until(const char *str, const char *find) {
	char *ret;
	char *f = strstr (str, find);
	if (!f) {
		return NULL;
	}
	ret = malloc (f - str + 1);
	if (!ret) {
		return NULL;
	}
	r_str_ncpy(ret, str, f - str + 1);
	return ret;
}

static char *p2rvcp(const Rvc *repo, const char *path) {
	char *ret;
	char *p;
	char *rp = read_until (repo->path, R_SYS_DIR ".rvc");
	if (!rp) {
		return NULL;
	}
	if (!r_file_is_abspath (path)) {
		p = r_file_abspath (path);
	} else {
		p = r_str_new (path);
	}
	if (!p) {
		free (rp);
		return NULL;
	}
	ret = r_str_new (p + r_str_len_utf8 (rp) + 1);
	free (p);
	free (rp);
	return ret;
}

static RvcBranch *branch_by_name(Rvc *repo, const char *name) {
	RListIter *iter;
	RvcBranch *b;
	r_list_foreach (repo->branches, iter, b) {
		if  (!r_str_cmp (name, b->name, r_str_len_utf8 (b->name) * sizeof (ut8))) {
			return b;
		}
	}

	return NULL;
}


static bool write_commit(Rvc *repo, RvcBranch *b, RvcCommit *commit) {
	char *commit_path, *commit_string;
	char *prev_path;
	FILE *prev_file, *commit_file;
	RListIter *iter;
	RvcBlob *blob;
	commit_string = r_str_newf ("author:%s\nmessage:%s\nntimestamp:%" PRId64"\n----",
			commit->author, commit->message, commit->timestamp);
	r_return_val_if_fail (commit_string, false);
	r_list_foreach (commit->blobs, iter, blob) {
		char *tmp = r_str_appendf (commit_string, "\nblob:%s:%s",
				blob->fname, blob->hash);
		if (!tmp) {
			return false;
		}
		commit_string = tmp;
	}
	commit->hash = find_sha256 ((ut8 *) commit_string,
			r_str_len_utf8 (commit_string) * sizeof (ut8));
	if (!commit->hash) {
		free (commit_string);
		return false;
	}
	commit_path = r_str_newf ("%s" R_SYS_DIR "branches" R_SYS_DIR
			"%s" R_SYS_DIR "commits" R_SYS_DIR "%s",
			repo->path, b->name, commit->hash);
	if (!commit_path) {
		free (commit_string);
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
R_API bool r_vc_commit(Rvc *repo, RList *blobs, const char *auth, const char *message) {
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
	if (nc->prev) {
		nc->prev->next = nc;
	}
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
R_API bool r_vc_branch(Rvc *repo, const char *name) {
	char *bpath, *ppath;
	RvcBranch *nb;
	if (!is_branch_name (name)) {
		eprintf ("%s Is Not A Vaild Branch Name\n", name);
		return false;
	}
	nb = R_NEW0 (RvcBranch);
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
			free (ppath);
			return false;
		}
		free (ppath);
	}
	repo->current_branch = nb;
	free (bpath);
	return true;
}

R_API Rvc *r_vc_new(const char *path) {
	Rvc *repo = R_NEW (Rvc);
	char *blob_path;
	char *rabsp;
	if (!repo) {
		eprintf ("Failed To Allocate Repoistory Path\n");
		return NULL;
	}
	repo->current_branch = NULL;
	rabsp = r_file_abspath (path);
	if (r_str_endswith (rabsp, "/")) {
		r_str_ncpy (rabsp, rabsp, r_str_len_utf8 (rabsp) - 1);
	}
	repo->path = r_str_newf ("%s" R_SYS_DIR ".rvc" R_SYS_DIR, rabsp);
	if (!repo->path) {
		eprintf ("Failed To Allocate Repoistory Path\n");
		free (repo);
		free (rabsp);
		return NULL;
	}
	if (r_file_exists (repo->path) || r_file_is_directory (repo->path)) {
		eprintf ("RVC Repoistory Already exists in %s\n", repo->path);
		free (repo->path);
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
	if (!r_vc_branch (repo, "master")) {
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
R_API RList *r_vc_add(Rvc *repo, RList *files) {
	RListIter *iter;
	char *fname;
	RList *blobs = r_list_new ();
	if (!blobs) {
		eprintf ("r_vc_add: memory failieur\n");
		return NULL;
	}
	r_list_foreach (files, iter, fname) {
		char *bpath;
		if (!r_file_exists (fname)) {
			r_list_free (blobs);
			eprintf ("r_vc_add: file: %s doesn't exist", fname);
			return NULL;
		}
		RvcBlob *blob = R_NEW (RvcBlob);
		if (!blob) {
			eprintf ("r_vc_add: Memory Faileur\n");
			r_list_free (blobs);
			return NULL;
		}
		blob->fname = p2rvcp (repo, fname);
		if (!blob->fname) {
			eprintf ("r_vc_add: Memory Faileur\n");
			r_list_free (blobs);
			free (blob);
			return NULL;
		}
		if (r_file_is_directory (fname)) {
			r_list_free (blobs);
			free (blob);
			free (blob->fname);
			eprintf ("r_vc_add: Can't Add Directories (Yet)");
			return NULL;
		}
		blob->hash = sha256_file (fname);
		if (!blob->hash) {
			eprintf ("r_vc_add: Memory Faileur\n");
			r_list_free (blobs);
			free (blob->fname);
			free (blob);
			return NULL;
		}
		bpath = r_str_newf ("%s" R_SYS_DIR "blobs" R_SYS_DIR "%s",
				repo->path, blob->hash);
		if (!bpath) {
			eprintf ("r_vc_add Memory Faileur\n");
			r_list_free (blobs);
			free (blob->fname);
			free (blob->hash);
			free (blob);
			return NULL;
		}
		if (r_sys_cmdf ("cp -f %s %s", fname, bpath)) {
			eprintf ("r_vc_add: can't copy blob\n");
			r_list_free (blobs);
			free (blob->fname);
			free (blob->hash);
			free (blob);
			return NULL;
		}
		free (bpath);
		if (!r_list_append (blobs, blob)) {
			eprintf ("r_vc_add: can't copy blob\n");
			r_list_free (blobs);
			free (blob->fname);
			free (blob->hash);
			free (blob);
			return NULL;
		}
	}
	return blobs;
}

R_API RvcBlob *r_vc_path_to_commit(Rvc *repo, const char *path) {
	RvcCommit *i;
	i = repo->current_branch->head;
	do {
		RListIter *iter;
		RvcBlob *blob;
		r_list_foreach(i->blobs, iter, blob) {
			char *hash;
			if (strcmp (blob->fname, path)) {
				continue;
			}
			hash = sha256_file (path);

			if (!hash) {
				return NULL;
			}
			if (!strcmp (hash, blob->hash)) {
				free (hash);
				return blob;
			}
			free (hash);
		}
	} while (i->prev);
	return NULL;
}

R_API RvcBlob *r_vc_last_blob(Rvc *repo, const char *path) {
	RvcCommit *i;
	i = repo->current_branch->head;
	do {
		RListIter *iter;
		RvcBlob *blob;
		r_list_foreach(i->blobs, iter, blob) {
			if (!strcmp (blob->fname, path)) {
				return blob;
			}
		}
	} while (i->prev);
	return NULL;
}

R_API RList *r_vc_uncomitted(Rvc *repo) {
	RListIter *iter, *tmp;
	char *path;
	char *rp = read_until (repo->path, R_SYS_DIR ".rvc/");
	printf ("%s\n", rp);
	if (!rp) {
		return NULL;
	}
	RList *files = r_file_lsrf (rp);
	if (!files) {
		free (rp);
		return NULL;
	}

	r_list_foreach_safe (files, iter, tmp, path) {
		path = p2rvcp (repo, path);
		if (!path) {
			r_list_free (files);
			files = NULL;
			break;
		}
		iter->data = path;
		if (!r_str_cmp (".rvc", path, 4)) {
			r_list_delete (files, iter);
			continue;
		}
		if (r_vc_path_to_commit (repo, path)) {
			r_list_delete (files, iter);
		}
	}
	free (rp);
	return files;
}

R_API bool r_vc_checkout(Rvc *repo, const char *name) {
	RListIter *iter;
	char *fpath;
	RvcBranch *branch = branch_by_name (repo, name);
	if (!branch) {
		return false;
	}
	RvcBranch *tmpb;
	RList *uncomitted = r_vc_uncomitted (repo);
	if (!uncomitted) {
		eprintf ("Memory failieur\n");
		return false;
	}
	if (!r_list_empty (uncomitted)) {
		eprintf ("Can Not Checkout Before You Commit The Following:\n");
		r_list_foreach (uncomitted, iter, fpath) {
			eprintf ("%s\n", fpath);
		}
		r_list_free (uncomitted);
		return false;
	}
	r_list_free (uncomitted);
	tmpb = repo->current_branch;
	repo->current_branch = branch;
	uncomitted = r_vc_uncomitted (repo);
	r_list_foreach (uncomitted, iter, fpath) {
		RvcBlob *blob;
		char *bpath;
		blob = r_vc_last_blob (repo, fpath);
		bpath = r_str_newf ("%s" R_SYS_DIR "blobs" R_SYS_DIR "%s",
				repo->path, blob->hash);
		if (!bpath) {
			r_file_rm (fpath);
			continue;
		}
		if (!r_file_copy (bpath, fpath)) {
			free (bpath);
			repo->current_branch = tmpb;
			return false;
		}
	}
	return true;
}

R_API int r_vc_git_init (const char *path) {
	return r_sys_cmdf ("git init %s", path);
}

R_API bool r_vc_git_branch (const char *path, const char *name) {
	return !r_sys_cmdf ("git -C %s branch %s", path, name);
}

R_API bool r_vc_git_checkout (const char *path, const char *name) {
	return !r_sys_cmdf ("git -C %s checkout %s", path, name);
}

R_API int r_vc_git_add (const char *path, const char *fname) {
	int ret;
	char *cwd = r_sys_getdir();
	if (!cwd) {
		return -1;
	}
	ret = r_sys_chdir (path);
	if (!ret) {
		free (cwd);
		return -2;
	}
	ret = r_sys_cmdf ("pwd; git add %s", fname);
	if (!r_sys_chdir (cwd)) {
		free (cwd);
		return -3;
	}
	free (cwd);
	return ret;
}

R_API int r_vc_git_commit (const char *path, const char *message) {
	return message ? r_sys_cmdf ("git -C %s commit -m %s", path, message) :
		r_sys_cmdf ("git -C %s commit", path);
}
