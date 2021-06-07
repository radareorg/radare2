/* radare - LGPL - Copyright 2021 - RHL120, pancake */

#include <rvc.h>
#define FIRST_BRANCH "master"

static bool is_valid_branch_name(const char *name) {
	if (r_str_len_utf8 (name) >= 16) {
		return false;
	}
	const char  *extention = r_str_endswith (name, ".zip") ?
		r_str_last (name, ".zip") : NULL;
	for (; *name && name != extention; name++) {
		if (IS_DIGIT (*name) || IS_LOWER (*name) || *name == '_') {
			continue;
		}
		return false;
	}
	return true;
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

static void free_blobs (RList *blobs) {
	RListIter *iter;
	RvcBlob *blob;
	r_list_foreach (blobs, iter, blob) {
		free (blob->fhash);
		free (blob->fname);
	}
	r_list_free (blobs);
}

static char *absp2rp(const char *rp, const char *absp) {
	char *ret;
	char *arp = r_file_abspath (rp);
	if (!arp) {
		return NULL;
	}
	if (r_str_len_utf8 (arp) < r_str_len_utf8 (rp)) {
		free (arp);
		return NULL;
	}
	ret = r_str_new (absp + r_str_len_utf8 (arp));
	free (arp);
	return ret;
}

static char *rp2absp(const char *rp, const char *path) {
	char *ret;
	char *arp = r_file_abspath (rp);
	if (!arp) {
		return NULL;
	}
	return r_str_appendf (arp, R_SYS_DIR "%s", path);
}

static RList *get_commits(Sdb *db, const size_t max_num) {
	char *i;
	RList *ret = r_list_new ();
	if (!ret) {
		return NULL;
	}
	i = sdb_get (db, sdb_const_get (db, "current_branch", 0), 0);
	while (true) {
		if (!r_list_prepend (ret, i)) {
			r_list_free (ret);
			break;
		}
		i = sdb_get (db, ret->tail->data, 0);
		if (!i || !*i) {
			r_list_free (ret);
			ret = NULL;
			break;
		}
		if ((max_num && ret->length >= max_num) || !*i) {
			ret = NULL;
			break;
		}
	}
	return ret;
}

bool delete_blob(RList *blobs, const char *hash) {
	RListIter *iter, *tmp;
	RvcBlob *current;
	r_list_foreach_safe (blobs, iter, tmp, current) {
		if (strcmp (current->fhash, hash)) {
			continue;
		}
		r_list_delete (blobs, iter);
		return true;
	}
	return false;
}

static bool update_blob(RList *blobs, RvcBlob *blob) {
	RListIter *iter;
	RvcBlob *current;
	bool found = false;
	r_list_foreach (blobs, iter, current) {
		if (strcmp (current->fname, blob->fname)) {
			continue;
		}
		free (iter->data);
		iter->data = blob;
		found = true;
	}
	return found ? true : !!(r_list_append (blobs, blob)); //!! is the only way I found that doesnt trigger a warnning;
}

static RList *get_current_tree (const char *rp) {
	Sdb *db = sdb_new0 ();
	if (!db) {
		return NULL;
	}
	char *dbp = r_str_newf ("%s" R_SYS_DIR ".rvc" "branches.sdb", rp);
	if (!dbp) {
		sdb_free (db);
		return NULL;
	}
	if (sdb_open (db, dbp) < 0) {
		free (dbp);
		sdb_free (db);
		return NULL;
	}
	free (dbp);
	RList *commits = get_commits (db, 0);
	if (!commits) {
		sdb_free (db);
		return NULL;
	}
	sdb_unlink (db);
	sdb_free (db);
	char *hash;
	RList *ret = r_list_new ();
	if (!ret) {
		return NULL;
	}
	RListIter *i;
	r_list_foreach (commits, i, hash) {
		char *cp = r_str_newf ("%s" R_SYS_DIR ".rvc" R_SYS_DIR
				"commits" R_SYS_DIR "%s", rp, hash);
		if (!cp) {
			break;
		}
		char *content = r_file_slurp (cp, 0);
		if (!content) {
			r_list_free (ret);
			ret = NULL;
		}
		RList *lines = r_str_split_duplist (content, "\n", false);
		free (content);
		if (!lines) {
			r_list_free (ret);
			break;
		}
		RListIter *j;
		char *ln;
		r_list_foreach (lines, j, ln) {
			if (r_str_cmp (ln, "blobs=", r_str_len_utf8 ("blobs="))) {
				continue;
			}
			RvcBlob *blob =  R_NEW (RvcBlob);
			if (!blob) {
				free_blobs (ret);
				break;
			}
			char *kv = strchr (ln, '=') + 1;
			blob->fhash = strchr(kv, '=') + 1;
			size_t klen = blob->fhash - kv;
			blob->fname = malloc ((klen + 1) * sizeof (char));
			blob->fhash = r_str_new (blob->fhash);
			if (!blob->fname || !blob->fhash) {
				free (blob->fname);
				free (blob->fhash);
				free (blob);
				free_blobs (ret);
			}
			strncpy (blob->fname, kv, klen);
			if (*blob->fname == '-') {
				delete_blob (ret, blob->fhash);
			}
			if (!update_blob (ret, blob)) {
				free (blob->fhash);
				free (blob->fname);
				free_blobs (ret);
				ret = NULL;
				break;
			}
			r_list_free (lines);
		}
	}
	return ret;
}

static bool bfadd(const char *rp, RList *dst, const char *path) {
	RvcBlob *blob;
	char *absp;
	char *blob_path;
	blob = R_NEW (RvcBlob);
	if (!blob) {
		return false;
	}
	absp = r_file_abspath (path);
	if (!absp) {
		free (blob);
		return false;
	}
	blob->fname = absp2rp (rp, path);
	if (!blob->fname) {
		free (absp);
		free (blob);
		return false;
	}
	blob->fhash = sha256_file (absp);
	if (!blob->fhash) {
		free (absp);
		free (blob->fname);
		free (blob);
		return false;
	}
	blob_path = r_str_newf ("%s" R_SYS_DIR ".rvc" R_SYS_DIR "blobs"
			R_SYS_DIR "%s", rp, blob->fhash);
	if (!blob_path) {
		free (absp);
		free (blob->fname);
		free (blob->fhash);
		free (blob);
		return false;
	}
	if (!r_list_append (dst, blob)) {
		free (absp);
		free (blob->fname);
		free (blob->fhash);
		free (blob);
		free (blob_path);
		return false;
	}
	if (!r_file_copy (absp, blob_path)) {
		free (absp);
		free (blob->fname);
		free (blob->fhash);
		free (blob);
		free (blob_path);
		r_list_pop (dst);
		return false;
	}
	free (absp);
	free (blob_path);
	return true;
}

static bool bdadd(const char *rp, const char *dir, RList *dst) {
	char *path;
	RListIter *iter;
	RList *files = r_file_lsrf (dir);
	if (!files) {
		return false;
	}
	r_list_foreach (files, iter, path) {
		if (r_file_is_directory (path)) {
			continue;
		}
		if (!bfadd (rp, dst, path)) {
			break;
		}
	}
	r_list_free (files);
	return false;
}

static RList *blobs_add(const char *rp, const RList *paths) {
	RList *ret;
	RListIter *iter;
	char *path;
	ret = r_list_new ();
	if (!ret) {
		return NULL;
	}
	r_list_foreach (paths, iter, path) {
		bool is_dir = r_file_is_directory (path);
		if (!is_dir && !r_file_exists (path)) {
			free_blobs (ret);
			ret = NULL;
			break;
		}
		if (is_dir) {
			if (!bdadd (rp, path, ret)) {
				free_blobs (ret);
				ret = NULL;
				break;
			}
			continue;
		}
		if (!bfadd (rp, ret, path)) {
			free_blobs (ret);
			ret = NULL;
			break;
		}
	}
	return ret;
}


static char *write_commit(const char *rp, const char *message, const char *author, RList *blobs) {
	RvcBlob *blob;
	RListIter *iter;
	char *commit_path, *commit_hash;
	char *content = r_str_newf ("message=%s\nauthor=%s\n----", message,
			author);
	FILE *commitf;
	if (!content) {
		return false;
	}
	r_list_foreach (blobs, iter, blob) {
		content = r_str_appendf (content, "\n%s=%s", blob->fname,
				blob->fhash);
		if (!content) {
			return false;
		}
	}
	commit_hash = find_sha256 ((unsigned char *)
			content, r_str_len_utf8 (content));
	if (!commit_hash) {
		free (content);
		return false;
	}
	commit_path = r_str_newf ("%s" R_SYS_DIR ".rvc" R_SYS_DIR "commits"
			R_SYS_DIR "%s", rp, commit_hash);
	if (!commit_path) {
		free (content);
		free (commit_hash);
		return false;
	}
	commitf = fopen (commit_path, "w+");
	free (commit_path);
	if (!commitf) {
		free (content);
		free (commit_hash);
		return false;
	}
	if (fprintf (commitf, "%s", content) != r_str_len_utf8 (content) * sizeof (char)) {
		free (content);
		free (commit_hash);
		fclose (commitf);
		return false;
	}
	fclose (commitf);
	free (content);
	return commit_hash;


}

R_API bool r_vc_commit(const char *rp, const char *message, const char *author, RList *files) {
	char *commit_hash;
	RList *blobs = blobs_add (rp, files);
	if (!blobs) {
		return false;
	}
	commit_hash = write_commit (rp, message, author, blobs);
	if (!commit_hash) {
		free_blobs (blobs);
		return false;
	}
	{
		char *dbf;
		const char *current_branch;
		Sdb *db = sdb_new0 ();
		if (!db) {
			free_blobs (blobs);
			free (commit_hash);
			return false;
		}
		dbf = r_str_newf ("%s" R_SYS_DIR ".rvc" R_SYS_DIR "branches.sdb",
				rp);
		if (!dbf) {
			sdb_unlink (db);
			sdb_free (db);
			free_blobs (blobs);
			free (commit_hash);
			return false;
		}
		if (sdb_open (db, dbf) < 0) {
			sdb_unlink (db);
			sdb_free (db);
			free_blobs (blobs);
			free (commit_hash);
			free (dbf);
			return false;
		}
		free (dbf);
		current_branch = sdb_const_get (db, "current_branch", 0);
		if (sdb_set (db, commit_hash, sdb_const_get (db, current_branch, 0), 0) < 0) {
			sdb_unlink (db);
			sdb_free (db);
			free_blobs (blobs);
			free (commit_hash);
			return false;
		}
		if (sdb_set(db, current_branch, commit_hash, 0) < 0) {
			sdb_unlink (db);
			sdb_free (db);
			free_blobs (blobs);
			free (commit_hash);
			return false;
		}
		sdb_sync (db);
		sdb_unlink (db);
		sdb_free (db);
	}
	free (commit_hash);
	free_blobs (blobs);
	return true;
}


R_API bool r_vc_branch(const char *rp, const char *bname) {
	const char *current_branch;
	const char *commits;
	char *dbp;
	Sdb *db;
	if (!is_valid_branch_name (bname)) {
		return false;
	}
	dbp = r_str_newf ("%s" R_SYS_DIR ".rvc" R_SYS_DIR "branches.sdb", rp);
	if (!dbp) {
		return false;
	}
	db = sdb_new0 ();
	if (!db) {
		free (dbp);
		return false;
	}
	if (!sdb_open (db, dbp)) {
		sdb_free (db);
		free (dbp);
		return false;
	}
	free (dbp);
	current_branch = sdb_const_get (db, "current_branch", 0);
	if (!current_branch) {
		sdb_free (db);
		return false;
	}
	commits = sdb_const_get (db, current_branch, 0);
	if (!commits) {
		sdb_free (db);
		return false;
	}
	sdb_set (db, bname, commits, 0);
	sdb_sync (db);
	sdb_unlink (db);
	sdb_free (db);
	return true;
}

R_API bool r_vc_new(const char *path) {
	Sdb *db;
	char *commitp, *blobsp;
	char *vcp = r_str_newf ("%s" R_SYS_DIR ".rvc", path);
	if (!vcp) {
		return false;
	}
	commitp = r_str_newf ("%s" R_SYS_DIR "commits", vcp);
	blobsp = r_str_newf ("%s" R_SYS_DIR "blobs", vcp);
	if (!commitp || !blobsp) {
		free (commitp);
		free (blobsp);
		return false;
	}
	if (!r_sys_mkdirp (commitp) || !r_sys_mkdir (blobsp)) {
		eprintf ("Can't create The RVC repo directory");
		free (commitp);
		free (blobsp);
		return false;
	}
	free (commitp);
	free (blobsp);
	db = sdb_new (vcp, "branches.sdb", 0);
	free (vcp);
	if (!db) {
		eprintf ("Can't create The RVC branches database");
		return false;
	}
	if (!sdb_set (db, FIRST_BRANCH, "", 0)) {
		sdb_unlink (db);
		sdb_free (db);
		return false;
	}
	if (!sdb_set (db, "current_branch", FIRST_BRANCH, 0)) {
		sdb_unlink (db);
		sdb_free (db);
		return false;
	}
	sdb_sync (db);
	sdb_unlink (db);
	sdb_free (db);
	return true;
}

// GIT commands as APIs

R_API int r_vc_git_init(const char *path) {
	return r_sys_cmdf ("git init %s", path);
}

R_API bool r_vc_git_branch(const char *path, const char *name) {
	return !r_sys_cmdf ("git -C %s branch %s", path, name);
}

R_API bool r_vc_git_checkout(const char *path, const char *name) {
	return !r_sys_cmdf ("git -C %s checkout %s", path, name);
}

R_API int r_vc_git_add(const char *path, const char *fname) {
	int ret;
	char *cwd = r_sys_getdir ();
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

R_API int r_vc_git_commit(const char *path, const char *message) {
	return message ? r_sys_cmdf ("git -C %s commit -m %s", path, message) :
		r_sys_cmdf ("git -C %s commit", path);
}
