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

static char *absp2rp(const char *absp, const char *rp) {
	char *arp = r_file_abspath (rp);
	if (!arp) {
		return NULL;
	}
	if (r_str_len_utf8 (arp) < r_str_len_utf8 (rp)) {
		free (arp);
		return NULL;
	}
	return r_str_new (absp + r_str_len_utf8 (arp));
}

static bool bfadd(RList *dst, const char *path, const char *rp) {
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
	blob->fname = absp2rp (path, rp);
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
		if (!bfadd (dst, path, rp)) {
			break;
		}
	}
	r_list_free (files);
	return false;
}

static RList *blobs_add(const RList *paths, const char *rp) {
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
		if (!bfadd (ret, path, rp)) {
			free_blobs (ret);
			ret = NULL;
			break;
		}
	}
	return ret;
}

/*This Function Is Probably Somehow Broken*/
static char *write_commit(const char *rp, const char *message, const char *auth, RList *blobs) {
	RvcBlob *blob;
	RListIter *iter;
	char *commit_path, *commit_hash;
	char *content = r_str_newf ("message=%s\nauthor=%s\n----", message,
			auth);
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

R_API bool r_vc_commit(const char *rp, const char *message, const char *auth, RList *files) {
	char *commit_hash;
	RList *blobs = blobs_add (files, rp);
	if (!blobs) {
		return false;
	}
	commit_hash = write_commit (rp, message, auth, blobs);
	if (!commit_hash) {
		free_blobs (blobs);
		return false;
	}
	{
		Sdb *db = sdb_new0 ();
		char *dbf;
		char *current_branch;
		if (!db) {
			free_blobs (blobs);
			free (commit_hash);
			return false;
		}
		dbf = r_str_newf ("%s" R_SYS_DIR ".rvc" R_SYS_DIR "branches.sdb",
				rp);
		if (!dbf) {
			free_blobs (blobs);
			free (commit_hash);
			return false;
		}
		if (sdb_open (db, dbf) < 0) {
			free_blobs (blobs);
			free (commit_hash);
			return false;
		}
		free (dbf);
		current_branch = sdb_get (db, "current_branch", 0);
		if (!current_branch) {
			free_blobs (blobs);
			free (commit_hash);
			sdb_free (db);
			return false;
		}
		if (!sdb_array_push (db, current_branch, commit_hash, 0)) {
			free_blobs (blobs);
			free (commit_hash);
			sdb_close (db);
			sdb_free (db);
			free (current_branch);
			return false;
		}
		free (current_branch);
		sdb_sync (db);
		sdb_unlink (db);
		sdb_free (db);
	}
	free (commit_hash);
	free_blobs (blobs);
	return true;
}


R_API bool r_vc_branch(const char *rp, const char *bname) {
	char *current_branch;
	char *commits;
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
	current_branch = sdb_get (db, "current_branch", 0);
	if (!current_branch) {
		sdb_free (db);
		return false;
	}
	commits = sdb_get (db, current_branch, 0);
	if (!commits) {
		sdb_free (db);
		free (current_branch);
		return false;
	}
	free (current_branch);
	sdb_set (db, bname, commits, 0);
	free (commits);
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
	if (!sdb_set (db, FIRST_BRANCH, "", 0)) { //Is this how you create an empty list?
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
