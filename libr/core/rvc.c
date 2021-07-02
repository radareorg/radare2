/* radare - LGPL - Copyright 2021 - RHL120, pancake */

#include <rvc.h>
#define FIRST_BRANCH "branches.master"
#define NOT_SPECIAL(c) IS_DIGIT (c) || IS_LOWER (c) || c == '_'
#define COMMIT_BLOB_SEP "----"
#define DBNAME "branches.sdb"
#define CURRENTB "current_branch"
#define BPREFIX "branches."
#define NULLVAL "-"

static int repo_exists(const char *path) {
	char *rp = r_str_newf ("%s" R_SYS_DIR ".rvc", path);
	if (!rp) {
		return -1;
	}
	if (!r_file_is_directory (rp)) {
		free (rp);
		return 0;
	}
	int r = 1;
	char *files[3] = {r_str_newf ("%s" R_SYS_DIR DBNAME, rp),
		r_str_newf ("%s" R_SYS_DIR "commits", rp),
		r_str_newf ("%s" R_SYS_DIR "blobs", rp),
	};
	free (rp);
	for (size_t i = 0; i < 3; i++) {
		if (!files[i]) {
			r = -1;
			goto ret;
		}
		if (!r_file_is_directory (files[i]) && !r_file_exists (files[i])) {
			eprintf ("Error: Corrupt repo: %s doesn't exist\n",
					files[i]);
			r = -2;
			goto ret;
		}

	}
ret:
	free (files[0]);
	free (files[1]);
	free (files[2]);
	return r;
}

static bool is_valid_branch_name(const char *name) {
	if (r_str_len_utf8 (name) >= 16) {
		return false;
	}
	for (; *name; name++) {
		if (NOT_SPECIAL (*name)) {
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

char *rp2absp(const char *rp, const char *path) {
	char *arp = r_file_abspath (rp);
	if (!arp) {
		return NULL;
	}
	char *appended = r_str_newf ("%s" R_SYS_DIR "%s", arp, path);
	free (arp);
	if (!appended) {
		return NULL;
	}
	char *absp = r_file_abspath (appended);
	free (appended);
	return absp;
}

//TODO:Make the tree related functions abit cleaner & more efficient

static RList *get_commits(const char *rp, const size_t max_num) {
	char *i;
	RList *ret = r_list_new ();
	if (!ret) {
		return NULL;
	}
	Sdb *db = sdb_new0 ();
	if (!db) {
		r_list_free (ret);
		return NULL;
	}
	char *dbp = r_str_newf ("%s" R_SYS_DIR ".rvc" R_SYS_DIR DBNAME,
			rp);
	if (!dbp) {
		r_list_free (ret);
		sdb_free (db);
		return NULL;
	}
	if (sdb_open (db, dbp) < 0) {
		r_list_free (ret);
		sdb_free (db);
		free (dbp);
		return NULL;
	}
	free (dbp);
	i = sdb_get (db, sdb_const_get (db, CURRENTB, 0), 0);
	if (!strcmp (i, NULLVAL)) {
		sdb_unlink (db);
		sdb_free (db);
		return ret;
	}
	while (true) {
		if (!r_list_prepend (ret, i)) {
			r_list_free (ret);
			break;
		}
		i = sdb_get (db, i, 0);
		if (!i || !*i) {
			r_list_free (ret);
			ret = NULL;
			break;
		}
		if (!strcmp (i, NULLVAL) || (max_num && ret->length >= max_num)) {
			break;
		}
	}
	sdb_unlink (db);
	sdb_free (db);
	return ret;
}

static bool update_blobs(RList *blobs, const RList *nh) {
	RListIter *iter;
	RvcBlob *blob;
	r_list_foreach (blobs, iter, blob) {
		if (strcmp (nh->head->data, blob->fname)) {
			continue;
		}
		blob->fhash = r_str_new (nh->tail->data);
		return blob->fhash != NULL;
	}
	blob = R_NEW (RvcBlob);
	if (!blob) {
		return false;
	}
	blob->fhash = r_str_new (nh->tail->data);
	blob->fname = r_str_new (nh->head->data);
	if (!blob->fhash || !blob->fname) {
		free (blob->fhash);
		free (blob->fname);
		free (blob);
		return false;
	}
	if (!r_list_append (blobs, blob)) {
		free (blob->fhash);
		free (blob->fname);
		free (blob);
		return false;
	}
	return true;
}

static RList *get_blobs(const char *rp) {
	RList *commits = get_commits (rp, 0);
	if (!commits) {
		return NULL;
	}
	RList *ret = r_list_new ();
	if (!ret) {
		r_list_free (commits);
	}
	RListIter *i;
	char *hash;
	r_list_foreach (commits, i, hash) {
		char *commit_path = r_str_newf ("%s" R_SYS_DIR ".rvc" R_SYS_DIR
				"commits" R_SYS_DIR "%s", rp, hash);
		if (!commit_path) {
			free_blobs (ret);
			ret = NULL;
			break;
		}
		char *content = r_file_slurp (commit_path, 0);
		free (commit_path);
		if (!content) {
			free_blobs (ret);
			ret = NULL;
			break;
		}
		RList *lines = r_str_split_duplist (content, "\n", true);
		free (content);
		if (!lines) {
			free_blobs (ret);
			ret = NULL;
			break;
		}
		RListIter *j;
		char *ln;
		bool found = false;
		r_list_foreach (lines, j, ln) {
			if (!found) {
				found = !r_str_cmp (ln, COMMIT_BLOB_SEP, r_str_len_utf8 (COMMIT_BLOB_SEP));
				continue;
			}
			RvcBlob *blob = R_NEW (RvcBlob);
			if (!blob) {
				free_blobs (ret);
				ret = NULL;
				break;
			}
			RList *kv = r_str_split_list (ln, "=", 2);
			if (!kv) {
				free_blobs (ret);
				ret = NULL;
				break;
			}
			if (!update_blobs (ret, kv)) {
				free_blobs (ret);
				ret = NULL;
				free (kv);
				break;
			}
		}
		r_list_free (lines);
	}
	r_list_free (commits);
	return ret;
}

static RList *repo_files(const char *rp) {
	RList *files = r_file_lsrf (rp);
	if (!files) {
		return NULL;
	}
	char *repo_meta = r_str_newf ("%s" R_SYS_DIR ".rvc", rp);
	if (!repo_meta) {
		r_list_free (files);
		return NULL;
	}
	size_t repo_meta_len = r_str_len_utf8 (repo_meta);
	RListIter *iter;
	char *path;
	RList *ret = r_list_new ();
	r_list_foreach (files, iter, path) {
		if (!r_str_cmp (repo_meta, path, repo_meta_len)) {
			continue;
		}
		char *absp = r_file_abspath (path);
		if (!absp) {
			r_list_free (ret);
			ret = NULL;
			break;
		}
		if (!r_list_append (ret, absp)) {
			r_list_free (ret);
			ret = NULL;
			free (absp);
			break;
		}

	}
	free (repo_meta);
	r_list_free (files);
	return ret;

}

//shit function:
static RList *get_uncommitted(const char *rp) {
	RList *blobs = get_blobs (rp);
	if (!blobs) {
		return NULL;
	}
	RList *files = repo_files (rp);
	if (!files) {
		free_blobs (blobs);
		return NULL;
	}
	RList *ret = r_list_new ();
	if (!ret) {
		free_blobs (blobs);
		r_list_free (files);
		return NULL;
	}
	RListIter *iter;
	RvcBlob *blob;
	r_list_foreach (blobs, iter, blob) {
		char *blob_absp = rp2absp (rp, blob->fname);
		if (!blob_absp) {
			goto fail_ret;
		}
		char *file;
		RListIter *j, *tmp;
		bool found = false;
		r_list_foreach_safe (files, j, tmp, file) {
			if (strcmp (blob_absp, file)) {
				continue;
			}
			found = true;
			r_list_delete (files, j);
			char *file_hash = sha256_file (blob_absp);
			if (!file_hash) {
				free (blob_absp);
				goto fail_ret;
			}
			if (strcmp (file_hash, blob->fhash)) {
				free (file_hash);
				break;
			}
			free (file_hash);
			char *append = r_str_new (blob_absp);
			if (!append) {
				free (blob_absp);
				goto fail_ret;
			}
			if (!r_list_append (ret, blob_absp)) {
				free (blob_absp);
				goto fail_ret;
			}
		}
		if (!found) {
			char *fname = r_str_new (blob_absp) ;
			if (!fname) {
				free (blob_absp);
				goto fail_ret;
			}
			if (!r_list_append (ret, fname)) {
				free (blob_absp);
				free (fname);
				goto fail_ret;
			}
		}
		free (blob_absp);
	}
	char *file;
	free_blobs (blobs);
	blobs = NULL;
	r_list_foreach (files, iter, file) {
		char *append = r_str_new (file);
		if (!append) {
			goto fail_ret;
		}
		if (!r_list_append (ret, append)) {
			free (append);
			goto fail_ret;
		}
	}
	r_list_free (files);
	return ret;
fail_ret:
	r_list_free (files);
	r_list_free (ret);
	free_blobs (blobs);
	return NULL;
}

static char *find_blob_hash(const char *rp, const char *fname) {
	RList *blobs = get_blobs (rp);
	if (!blobs) {
		return NULL;
	}
	RListIter *i;
	RvcBlob *b;
	r_list_foreach_prev (blobs, i, b) {
		if (!strcmp (b->fname, fname)) {
			r_list_free (blobs);
			return r_str_new (b->fhash);
		}
	}
	r_list_free (blobs);
	return NULL;
}
static char *write_commit(const char *rp, const char *message, const char *author, RList *blobs) {
	RvcBlob *blob;
	RListIter *iter;
	char *commit_path, *commit_hash;
	FILE *commitf;
	char *content = r_str_newf ("message=%s\nauthor=%s\ntime=%ld\n"
			COMMIT_BLOB_SEP, message, author, time (NULL));
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

static RvcBlob *bfadd(const char *rp, const char *fname) {
	char *absp = r_file_abspath (fname);
	if (!absp) {
		return NULL;
	}
	RvcBlob *blob = R_NEW (RvcBlob);
	if (!blob) {
		free (absp);
		return NULL;
	}
	blob->fname = absp2rp (rp, absp);
	if (!blob->fname) {
		free (absp);
		free (blob);
		return NULL;
	}
	if (!r_file_exists (absp)) {
		char *hash = find_blob_hash (rp, blob->fname);
		if (!hash) {
			eprintf ("file %s doesn't exist", blob->fname);
			free (absp);
			free (blob->fname);
			free (blob);
			return NULL;
		}
		if (!strcmp (NULLVAL, hash)) {
			eprintf ("file %s doesn't exist", blob->fname);
			free (absp);
			free (blob->fname);
			free (blob);
			return NULL;
		}
		blob->fname = r_str_new (NULLVAL);
		if (!blob->fname) {
			free (absp);
			free (blob->fname);
			free (blob);
			return NULL;
		}
		return blob;
	}
	blob->fhash = sha256_file (absp);
	if (!blob->fhash) {
		goto fail_ret;
	}
	{
		char *hash = find_blob_hash (rp, blob->fname);
		if (hash) {
			if (!strcmp (blob->fhash, hash)) {
				eprintf ("%s is already committed.", fname);
				free (hash);
				goto fail_ret;
			}
			free (hash);
		}
	}
	{
		char *bpath = r_str_newf ("%s" R_SYS_DIR ".rvc" R_SYS_DIR
				"blobs" R_SYS_DIR "%s", rp, blob->fhash);
		if (!bpath) {
			goto fail_ret;
		}
		if (!r_file_copy (absp, bpath)) {
			free (bpath);
			goto fail_ret;

		}
		free (bpath);
		free (absp);
	}
	return blob;
fail_ret:
	free (blob->fhash);
	free (absp);
	free (blob->fname);
	free (blob);
	return NULL;
}

static RList *blobs_add (const char *rp, const RList *files) {
	RList *ret = r_list_new ();
	if (!ret) {
		return NULL;
	}
	RListIter *i;
	char *path;
	r_list_foreach (files, i, path) {
		if (r_file_is_directory (path)) {
			RList *subf = repo_files (path);
			if (!subf) {
				r_list_free (ret);
				return NULL;
			}
			RListIter *j;
			char *sf;
			r_list_foreach (subf, j, sf) {
				RvcBlob *b = bfadd (rp, sf);
				if (!b) {
					free_blobs (ret);
					r_list_free (subf);
					return NULL;

				}
				if (!r_list_append (ret, b)) {
					free (b->fhash);
					free (b->fname);
					free_blobs (ret);
					r_list_free (subf);
					return NULL;
				}
				continue;
			}
		}
		RvcBlob *b = bfadd (rp, path);
		if (!b) {
			free_blobs (ret);
			return NULL;
		}
		if (!r_list_append (ret, b)) {
			free (b->fhash);
			free (b->fname);
			free_blobs (ret);
			return NULL;
		}
	}
	return ret;
}

R_API bool r_vc_commit(const char *rp, const char *message, const char *author, const RList *files) {
	char *commit_hash;
	switch (repo_exists (rp)) {
	case 1:
		break;
	case 0:
		eprintf ("No repo in %s\nCan't commit\n", rp);
		return false;
	case -1:
		eprintf ("Can't commit\n");
		return false;
	case -2:
		eprintf ("Can't commit");
		return false;
	}
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
		dbf = r_str_newf ("%s" R_SYS_DIR ".rvc" R_SYS_DIR DBNAME,
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
		current_branch = sdb_const_get (db, CURRENTB, 0);
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
	switch (repo_exists (rp)) {
	case 1:
		break;
	case 0:
		eprintf ("No repo in %s\nCan't branch\n", rp);
		return false;
	case -1:
		eprintf ("Can't branch\n");
		return false;
	case -2:
		eprintf ("Can't branch");
		return false;
	}
	if (!is_valid_branch_name (bname)) {
		return false;
	}
	dbp = r_str_newf ("%s" R_SYS_DIR ".rvc" R_SYS_DIR DBNAME, rp);
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
	current_branch = sdb_const_get (db, CURRENTB, 0);
	if (!current_branch) {
		sdb_free (db);
		return false;
	}
	commits = sdb_const_get (db, current_branch, 0);
	commits = commits? commits : "";
	char *nbn = r_str_newf (BPREFIX "%s", bname);
	if (!nbn) {
		sdb_unlink (db);
		sdb_free (db);
		return false;
	}
	sdb_set (db, nbn, commits, 0);
	free (nbn);
	sdb_sync (db);
	sdb_unlink (db);
	sdb_free (db);
	return true;
}

R_API bool r_vc_new(const char *path) {
	Sdb *db;
	char *commitp, *blobsp;
	switch (repo_exists (path)) {
	case 0:
		break;
	case 1:
		eprintf ("Repo already exists at: %s", path);
		return false;
	case -1:
		eprintf ("Can't create repo\n");
		return false;
	case -2:
		eprintf ("Repository exists but is corrupt\n");
		return false;
	}
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
	db = sdb_new (vcp, DBNAME, 0);
	free (vcp);
	if (!db) {
		eprintf ("Can't create The RVC branches database");
		return false;
	}
	if (!sdb_set (db, FIRST_BRANCH, NULLVAL, 0)) {
		sdb_unlink (db);
		sdb_free (db);
		return false;
	}
	if (!sdb_set (db, CURRENTB, FIRST_BRANCH, 0)) {
		sdb_unlink (db);
		sdb_free (db);
		return false;
	}
	sdb_sync (db);
	sdb_unlink (db);
	sdb_free (db);
	return true;
}

R_API bool r_vc_checkout(const char *rp, const char *bname) {
	RList *uncommitted = get_uncommitted (rp);
	RListIter *i;
	char *f;
	switch (repo_exists (rp)) {
	case 1:
		break;
	case 0:
		eprintf ("No repo in %s\nCan't checkout\n", rp);
		return false;
	case -1:
		eprintf ("Can't checkout\n");
		return false;
	case -2:
		eprintf ("Can't checkout");
		return false;
	}
	bool ret = false;
	if (!uncommitted) {
		return false;
	}
	if (!r_list_empty (uncommitted)) {
		r_list_foreach (uncommitted, i, f) {
			printf ("%s\n", f);
		}
		puts ("Are uncommitted\n");
		r_list_free (uncommitted);
		return false;
	}
	r_list_free (uncommitted);
	Sdb *db = sdb_new0 ();
	if (!db) {
		return false;
	}
	char *dbp = r_str_newf ("%s" R_SYS_DIR ".rvc" R_SYS_DIR DBNAME, rp);
	if (!dbp) {
		sdb_free (db);
		return false;
	}
	if (sdb_open (db, dbp) < 0) {
		sdb_free (db);
		free (dbp);
		return false;
	}
	free (dbp);
	char *cb = sdb_get (db, CURRENTB, 0);
	if (!cb) {
		sdb_unlink (db);
		sdb_free (db);
		free (dbp);
	}
	char *fbname = r_str_newf (BPREFIX "%s", bname);
	//exist?
	if (!fbname) {
		sdb_unlink (db);
		sdb_free (db);
		free (dbp);
	}
	sdb_set (db, CURRENTB, fbname, 0);
	sdb_sync (db);
	uncommitted = get_uncommitted (rp);
	if (!uncommitted) {
		sdb_set (db, CURRENTB, fbname, 0);
		sdb_sync (db);
		sdb_free (db);
		free (fbname);
		return false;
	}
	r_list_foreach (uncommitted, i, f) {
		char *hash = find_blob_hash (rp, f);
		if (!hash) {
			sdb_set (db, CURRENTB, cb, 0);
			ret = false;
		}
		if (strcmp (hash, NULLVAL)) {
			free (hash);
			if (!r_file_rm (f)) {
				sdb_set (db, CURRENTB, cb, 0);
				free (hash);
				ret = false;
			}
			continue;
		}
		char *bp = r_str_newf ("%s" R_SYS_DIR ".rvc" R_SYS_DIR
				"blobs" R_SYS_DIR, hash);
		if (!bp) {
			free (hash);
		}
		if (!r_file_copy (bp, f)) {
			free (hash);
			free (bp);
			sdb_set (db, CURRENTB, cb, 0);
			ret = false;
		}
	}
	sdb_sync (db);
	sdb_unlink (db);
	sdb_free (db);
	return ret;
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
	ret = r_sys_cmdf ("git add %s", fname);
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

R_API int rvc_git_init(RCore *core, const char *rp) {
	if (strcmp (r_config_get (core->config, "prj.vc.type"), "git")) {
		return r_vc_git_init (rp);
	}
	return r_vc_git_init (rp);
}

R_API int rvc_git_commit(RCore *core, const char *rp, const char *message, const char *author, const RList *files) {
	if (!strcmp (r_config_get (core->config, "prj.vc.type"), "rvc")) {
		r_vc_commit (rp, message, author, files);
	}
	char *path;
	RListIter *iter;
	r_list_foreach (files, iter, path) {
		if (!r_vc_git_add (rp, path)) {
			return false;
		}
	}
	return r_vc_git_commit (rp, message);
}

R_API int rvc_git_branch(RCore *core, const char *rp, const char *bname) {
	if (!strcmp (r_config_get (core->config, "prj.vc.type"), "rvc")) {
		return r_vc_branch (rp, bname);
	}
	return r_vc_git_branch (rp, bname);
}

R_API int rvc_git_checkout(RCore *core, const char *rp, const char *bname) {
	if (!strcmp (r_config_get (core->config, "prj.vc.type"), "rvc")) {
		return r_vc_checkout (rp, bname);
	}
	return r_vc_git_checkout (rp, bname);
}
