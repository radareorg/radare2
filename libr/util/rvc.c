/* radare - LGPL - Copyright 2021-2022 - RHL120, pancake */

#define R_LOG_ORIGIN "rvc"

#undef R_IPI
#define R_IPI R_HIDDEN static
#include "../crypto/hash/sha2.c"
#undef R_IPI
#define R_IPI

#include <r_util.h>
#include "r_config.h"
#include <rvc.h>
#include <sdb.h>
#define FIRST_BRANCH "branches.master"
#define NOT_SPECIAL(c) IS_DIGIT (c) || IS_LOWER (c) || c == '_'
#define COMMIT_BLOB_SEP "----"
#define DBNAME "branches.sdb"
#define CURRENTB "current_branch"
#define IGNORE_NAME ".rvc_ignore"
#define MAX_MESSAGE_LEN 80
#define NULLVAL "-"

//Access both git and rvc functionality from one set of functions
static inline void rvc_warn(void) {
	R_LOG_WARN ("rvc is still under development and can be unstable, be careful");
}

// copies src to dst and creates the parent dirs if they do not exist.
static bool file_copyp(const char *src, const char *dst) {
	if (r_file_is_directory (dst)) {
		return r_file_copy (src, dst);
	}
	const char *d = r_str_rchr (dst, dst + r_str_len_utf8 (dst) - 1, *R_SYS_DIR);
	if (!d) {
		return false;
	}
	char *dir = r_str_ndup (dst, d - dst);
	if (!dir) {
		return false;
	}
	if (!r_file_is_directory (dir)) {
		if (!r_sys_mkdirp (dir)) {
			free (dir);
			return false;
		}
	}
	bool res = r_file_copy (src, dst);
	free (dir);
	return res;
}

// should I move to file.c?
static bool file_copyrf(const char *src, const char *dst) {
	if (r_file_exists (src)) {
		return file_copyp (src, dst);
	}
	RList *fl = r_file_lsrf (src);
	if (!fl) {
		return false;
	}
	RListIter *iter;
	const char *path;
	bool ret = true;
	r_list_foreach (fl, iter, path) {
		//strlen(src) should always be less than strlen(path) so
		//I think this is ok??
		char *dstp = r_file_new (dst, path + strlen (src), NULL);
		if (dstp) {
			if (r_file_is_directory (path)) {
				r_sys_mkdirp (dstp);
			} else {
				if (!file_copyp (path, dstp)) {
					R_LOG_ERROR ("Failed to copy the file: %s to %s", path, dstp);
					ret = false;
					//continue copying files don't break
				}
			}
			free (dstp);
		} else {
			ret = false;
			R_LOG_ERROR ("Failed to copy the file: %s", path);
		}
	}
	return ret;
}

static char *strip_sys_dir(const char *path) {
	char *res = strdup (path);
	char *ptr = res;
	while (*ptr) {
		if (*ptr == *R_SYS_DIR) {
			if (ptr[1] == *R_SYS_DIR) {
				char *ptr2 = ptr + 1;
				while (*ptr2 == *R_SYS_DIR) {
					ptr2++;
				}
				memmove (ptr + 1, ptr2, strlen (ptr2) + 1);
			}
		}
		ptr++;
	}
	return res;
}

static Sdb *vcdb_open(const char *rp) {
	char *frp = r_file_new (rp, ".rvc", DBNAME, NULL);
	if (!frp) {
		return NULL;
	}
	Sdb *db = sdb_new0 ();
	if (!db) {
		free (frp);
		return NULL;
	}
	if (sdb_open (db, frp) < 0) {
		free (frp);
		sdb_free (db);
		return NULL;
	}
	free (frp);
	return db;
}

static bool repo_exists(const char *path) {
	char *rp = r_file_new (path, ".rvc", NULL);
	if (!rp) {
		return false;
	}
	if (!r_file_is_directory (rp)) {
		free (rp);
		return false;
	}
	bool r = true;
	char *files[3] = {
		r_file_new (rp, DBNAME, NULL),
		r_file_new (rp, "commits", NULL),
		r_file_new (rp, "blobs", NULL)
	};
	free (rp);
	size_t i;
	for (i = 0; i < 3; i++) {
		if (!files[i]) {
			r = false;
			break;
		}
		if (!r_file_is_directory (files[i]) && !r_file_exists (files[i])) {
			R_LOG_ERROR ("Corrupt repo: %s doesn't exist", files[i]);
			r = false;
			break;
		}

	}
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

static char *compute_hash(const ut8 *data, size_t len) {
	RSha256Context ctx;
	r_sha256_init (&ctx);
	r_sha256_update (&ctx, data, len);
	char textdigest[R_SHA256_DIGEST_STRING_LENGTH] = {0};
	r_sha256_end (&ctx, textdigest);
	return strdup (textdigest);
}

static inline char *sha256_file(const char *fname) {
	size_t content_length = 0;
	char *content = r_file_slurp (fname, &content_length);
	if (content) {
		char *res = compute_hash ((const ut8 *)content, content_length);
		free (content);
		return res;
	}
	return NULL;
}

static void free_blobs(RList *blobs) {
	if (blobs) {
		RListIter *iter;
		RvcBlob *blob;
		r_list_foreach (blobs, iter, blob) {
			free (blob->fhash);
			free (blob->fname);
			free (blob);
		}
		r_list_free (blobs);
	}
}

static char *absp2rp(Rvc *rvc, const char *absp) {
	char *arp = r_file_abspath (rvc->path);
	if (!arp) {
		return NULL;
	}
	if (r_str_len_utf8 (arp) < r_str_len_utf8 (rvc->path)) {
		free (arp);
		return NULL;
	}
	char *p = r_str_new (absp + r_str_len_utf8 (arp));
	free (arp);
	if (!p) {
		return NULL;
	}
	char *ret = strip_sys_dir (p);
	free (p);
	return ret;
}

char *rp2absp(Rvc *rvc, const char *path) {
	char *arp = r_file_abspath (rvc->path);
	if (!arp) {
		return NULL;
	}
	char *appended = r_file_new (arp, path, NULL);
	free (arp);
	if (!appended) {
		return NULL;
	}
	char *stripped = strip_sys_dir (appended);
	free (appended);
	return stripped;
}

//TODO:Make the tree related functions abit cleaner & more efficient

static RList *get_commits(Rvc *rvc, const size_t max_num) {
	RList *ret = r_list_new ();
	if (!ret) {
		return NULL;
	}
	char *i = sdb_get (rvc->db, sdb_const_get (rvc->db, CURRENTB, 0), 0);
	if (!i) {
		r_list_free (ret);
		ret = NULL;
		goto ret;
	}
	if (!strcmp (i, NULLVAL)) {
		goto ret;
	}
	while (true) {
		if (!r_list_prepend (ret, i)) {
			r_list_free (ret);
			ret = NULL;
			break;
		}
		i = sdb_get (rvc->db, i, 0);
		if (!i) {
			r_list_free (ret);
			ret = NULL;
			break;
		}
		if (!strcmp (i, NULLVAL) || (max_num && ret->length >= max_num)) {
			break;
		}
	}
ret:
	return ret;
}


// check if rpf is in the ignore file. if ignore is NULL it just returns false
static bool in_rvc_ignore(const RList *ignore, const char *rpf) {
	RListIter *iter;
	char *p;
	bool ret = false;
	r_list_foreach (ignore, iter, p) {
		char *stripped = strip_sys_dir (p);
		if (stripped) {
			if (!strcmp (stripped, rpf)) {
				free (stripped);
				ret = true;
				break;
			}
			free (stripped);
		}

	}
	return ret;
}

static bool update_blobs(const RList *ignore, RList *blobs, const RList *nh) {
	RListIter *iter;
	RvcBlob *blob;
	if (in_rvc_ignore (ignore, nh->head->data)) {
		return true;
	}
	r_list_foreach (blobs, iter, blob) {
		if (strcmp (nh->head->data, blob->fname)) {
			continue;
		}
		blob->fhash = r_str_new (nh->tail->data);
		return (bool) blob->fhash;
	}
	blob = R_NEW (RvcBlob);
	if (!blob) {
		return false;
	}
	blob->fhash = r_str_new (nh->tail->data);
	blob->fname = r_str_new (nh->head->data);
	if (!blob->fhash || !blob->fname) {
		goto fail_ret;
	}
	if (!r_list_append (blobs, blob)) {
		goto fail_ret;
	}
	return true;
fail_ret:
	free (blob->fhash);
	free (blob->fname);
	free (blob);
	return false;

}

static int branch_exists(Rvc *rvc, const char *bname) {
	RList *branches = r_vc_get_branches (rvc);
	if (!branches) {
		return -1;
	}
	RListIter *iter;
	char *branch;
	bool ret = 0;
	r_list_foreach (branches, iter, branch) {
		if (!strcmp (branch, bname)) {
			ret = 1;
			break;
		}
	}
	r_list_free (branches);
	return ret;
}

static RList *get_blobs(Rvc *rvc, RList *ignore) {
	RList *commits = get_commits (rvc, 0);
	if (!commits) {
		return NULL;
	}
	RList *ret = r_list_new ();
	if (!ret) {
		goto ret;
	}
	RListIter *i;
	char *hash;
	r_list_foreach (commits, i, hash) {
		char *commit_path = r_file_new (rvc->path, ".rvc", "commits",
				hash, NULL);
		if (!commit_path) {
			goto fail_ret;
		}
		char *content = r_file_slurp (commit_path, 0);
		free (commit_path);
		if (!content) {
			goto fail_ret;
		}
		RList *lines = r_str_split_duplist (content, "\n", true);
		free (content);
		if (!lines) {
			goto fail_ret;
		}
		RListIter *j;
		char *ln;
		bool found = false;
		r_list_foreach (lines, j, ln) {
			if (!found) {
				found = !r_str_cmp (ln, COMMIT_BLOB_SEP,
						r_str_len_utf8 (COMMIT_BLOB_SEP));
				continue;
			}
			RList *kv = r_str_split_list (ln, "=", 2);
			if (!kv) {
				free_blobs (ret);
				ret = NULL;
				break;
			}
			if (!update_blobs (ignore, ret, kv)) {
				free_blobs (ret);
				ret = NULL;
				free (kv);
				break;
			}
		}
		r_list_free (lines);
	}
ret:
	r_list_free (commits);
	return ret;
fail_ret:
	free_blobs(ret);
	return NULL;
}

static bool rm_empty_dir(Rvc *rvc) {
	char *path = r_file_new (rvc->path, ".rvc", NULL);
	if (!path) {
		return false;
	}
	RList *files = r_file_lsrf (rvc->path);
	RListIter *iter;
	const char *f;
	r_list_foreach (files, iter, f) {
		if (r_str_cmp (f, path, r_str_len_utf8 (path))) {
			rmdir (f);
		}
	}
	free (path);
	r_list_free (files);
	return true;
}

static bool traverse_files(RList *dst, const char *dir) {
	char *name;
	RListIter *iter;
	bool ret = true;
	RList *files = r_sys_dir (dir);
	if (!r_list_empty (dst)) {
		char *vcp = r_file_new (dir, ".rvc", NULL);
		if (!vcp) {
			r_list_free (files);
			return false;
		}
		if (r_file_is_directory (vcp)) {
			r_list_free (files);
			free (vcp);
			return true;
		}
		free (vcp);
	}
	if (!files) {
		r_list_free (files);
		return false;
	}
	r_list_foreach (files, iter, name) {
		char *path;
		if (!strcmp (name, "..") || !strcmp (name, ".")) {
			continue;
		}
		if (!strcmp (name, ".rvc")) {
			continue;
		}
		path = r_file_new (dir, name, NULL);
		if (!path) {
			ret = false;
			break;
		}
		if (r_file_is_directory (path)) {
			if (!traverse_files (dst, path)) {
				ret = false;
				break;
			}
			free (path);
			continue;
		}
		if (!r_list_append (dst, path)) {
			ret = false;
			free (path);
			break;
		}
	}
	r_list_free (files);
	return ret;
}

static RList *repo_files(const char *dir) {
	RList *ret = r_list_newf (free);
	if (ret) {
		if (!traverse_files (ret, dir)) {
			r_list_free (ret);
			ret = NULL;
		}
	}
	return ret;
}

static RList *load_rvc_ignore(Rvc *rvc) {
	RList *ignore = NULL;
	char *path = r_file_new (rvc->path, IGNORE_NAME, NULL);
	if (!path) {
		return false;
	}
	char *c = r_file_slurp (path, 0);
	// skip if contnet is not readable
	if (c) {
		ignore = r_str_split_duplist (c, "\n", true);
		free (c);
	}
	free (path);
	return ignore;
}

//shit function:
R_API RList *r_vc_get_uncommitted(Rvc *rvc) {
	RList *ignore = load_rvc_ignore (rvc);
	if (!repo_exists (rvc->path)) {
		R_LOG_ERROR ("No valid repo in %s", rvc->path);
		return false;
	}
	RList *blobs = get_blobs(rvc, ignore);
	if (!blobs) {
		return NULL;
	}
	RList *files = repo_files (rvc->path);
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
		char *blob_absp = rp2absp (rvc, blob->fname);
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
			if (!strcmp (file_hash, blob->fhash)) {
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
			if (!strcmp (NULLVAL, blob->fhash)) {
				free (blob_absp);
				continue;
			}
			if (!r_list_append (ret, blob_absp)) {
				free (blob_absp);
				goto fail_ret;
			}
		}
	}
	char *file;
	free_blobs (blobs);
	blobs = NULL;
	r_list_foreach (files, iter, file) {
		char *rfp = absp2rp (rvc, file);
		if (!rfp) {
			goto fail_ret;
		}
		if (in_rvc_ignore (ignore, rfp)) {
			free (rfp);
			continue;
		}
		free (rfp);
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

static char *find_blob_hash(Rvc *rvc, const char *fname) {
	RList *blobs = get_blobs (rvc, load_rvc_ignore(rvc));
	if (blobs) {
		RListIter *i;
		RvcBlob *b;
		r_list_foreach_prev (blobs, i, b) {
			if (!strcmp (b->fname, fname)) {
				char *bhash = r_str_new (b->fhash);
				free_blobs (blobs);
				return bhash;
			}
		}
	}
	return NULL;
}

static char *write_commit(Rvc *rvc, const char *message, const char *author, RList *blobs) {
	RvcBlob *blob;
	RListIter *iter;
	RStrBuf *sb = r_strbuf_newf ("message=%s\nauthor=%s\ntime=%" PFMT64d "\n" COMMIT_BLOB_SEP,
			message, author, (ut64) r_time_now ());
	r_list_foreach (blobs, iter, blob) {
		r_strbuf_appendf (sb, "\n%s=%s", blob->fname, blob->fhash);
	}
	size_t len = r_strbuf_length (sb);
	char *content = r_strbuf_drain (sb);
	char *commit_hash = compute_hash ((const ut8*)content, len);
	if (commit_hash) {
		char *commit_path = r_file_new (rvc->path, ".rvc", "commits", commit_hash, NULL);
		if (!commit_path || !r_file_dump (commit_path, (const ut8*)content, -1, false)) {
			return false;
		}
		return commit_hash;
	} else {
		R_LOG_ERROR ("Cannot compute hash");
	}
	free (content);
	free (commit_hash);
	return false;
}

static RvcBlob *bfadd(Rvc *rvc, const char *fname) {
	RvcBlob *ret = R_NEW (RvcBlob);
	if (!ret) {
		return NULL;
	}
	char *absp = r_file_abspath (fname);
	if (!absp) {
		free (ret);
		return NULL;
	}
	ret->fname = absp2rp (rvc, absp);
	if (!ret->fname) {
		free (ret);
		free (absp);
		return NULL;
	}
	if (!r_file_exists (absp)) {
		ret->fhash = r_str_new (NULLVAL);
		free (absp);
		if (!ret->fhash) {
			goto fail_ret;
		}
		return ret;
	}
	ret->fhash = sha256_file (absp);
	if (!ret->fhash) {
		free (absp);
		goto fail_ret;
	}
	char *bpath = r_file_new (rvc->path, ".rvc", "blobs", ret->fhash, NULL);
	if (!bpath) {
		goto fail_ret;
	}
	if (!r_file_copy (absp, bpath)) {
		free (ret->fhash);
		free (ret->fname);
		free (ret);
		ret = NULL;
	}
	free (absp);
	free (bpath);
	return ret;

fail_ret:
	free (ret->fhash);
	free (ret->fname);
	free (ret);
	return NULL;
}

static RList *blobs_add(Rvc *rvc, const RList *files) {
	RList *ret = r_list_new ();
	if (!ret) {
		return NULL;
	}
	RList *uncommitted = r_vc_get_uncommitted (rvc);
	if (!uncommitted) {
		free (ret);
		return NULL;
	}
	RListIter *i;
	char *path;
	r_list_foreach (files, i, path) {
		char *absp = r_file_abspath (path);
		if (!absp) {
			break;
		}
		RListIter *j;
		char *ucp;
		bool found = false;
		RListIter *tmp;
		//problamatic iterates even after finding the file but needed for directires.
		r_list_foreach_safe (uncommitted, j, tmp, ucp) {
			if (r_str_cmp (ucp, absp, r_str_len_utf8 (absp))) {
				continue;
			}
			found = true;
			RvcBlob *b = bfadd (rvc, ucp);
			if (!b) {
				free (absp);
				goto fail_ret;
			}
			if (!r_list_append (ret, b)) {
				free (absp);
				free (b->fhash);
				free (b->fname);
				free (b);
				goto fail_ret;
			}
			r_list_delete (uncommitted, j);
		}
		if (!found) {
			R_LOG_ERROR ("File %s is already committed", path);
		}
		free (absp);
	}
	return ret;
fail_ret:
	r_list_free (uncommitted);
	free (ret);
	return NULL;
}

R_API bool r_vc_commit(Rvc *rvc, const char *message, const char *author, const RList *files) {
	rvc_warn ();
	if (!repo_exists (rvc->path)) {
		R_LOG_ERROR ("No valid repo in %s", rvc->path);
		return false;
	}
#if 0
	/// XXX this should be handled by the caller
	if (R_STR_ISEMPTY (message)) {
		char *path = NULL;
		(void)r_file_mkstemp ("rvc", &path);
		if (path) {
			free (r_cons_editor (path, NULL));
			message = r_file_slurp (path, NULL);
			if (!message) {
				free (path);
				return false;
			}
		} else {
			return false;
		}
	}
#endif
	if (message && r_str_len_utf8 (message) > MAX_MESSAGE_LEN) {
		R_LOG_ERROR ("Commit message is too long");
		return false;
	}
	const char *m;
	for (m = message; *m; m++) {
		if (*m < ' ' && *m != '\n') {
			R_LOG_ERROR ("commit messages must not contain unprintable charecters %c",
					*m);
			return false;
		}
	}
	RList *blobs = blobs_add (rvc, files);
	if (!blobs) {
		return false;
	}
	if (r_list_empty (blobs)) {
		r_list_free (blobs);
		R_LOG_ERROR ("Nothing to commit");
		return false;
	}
	char *commit_hash = NULL;
	if (R_STR_ISEMPTY (author)) {
		char *au = r_sys_whoami ();
		commit_hash = write_commit (rvc, message, au, blobs);
		free (au);
	} else {
		commit_hash = write_commit (rvc, message, author, blobs);
	}
	if (!commit_hash) {
		free_blobs (blobs);
		return false;
	}
	{
		const char *current_branch;
		current_branch = sdb_const_get (rvc->db, CURRENTB, 0);
		if (sdb_set (rvc->db, commit_hash, sdb_const_get (rvc->db, current_branch, 0), 0) < 0) {
			free_blobs (blobs);
			free (commit_hash);
			return false;
		}
		if (sdb_set (rvc->db, current_branch, commit_hash, 0) < 0) {
			free_blobs (blobs);
			free (commit_hash);
			return false;
		}
	}
	free (commit_hash);
	free_blobs (blobs);
	return true;
}

R_API RList *r_vc_get_branches(Rvc *rvc) {
	if (!repo_exists (rvc->path)) {
		R_LOG_ERROR ("No valid repo in %s", rvc->path);
		return NULL;
	}
	RList *ret = r_list_new ();
	if (!ret) {
		return NULL;
	}
	SdbList *keys = sdb_foreach_list (rvc->db, false);
	if (!keys) {
		r_list_free (ret);
		return NULL;
	}
	SdbListIter *i;
	SdbKv *kv;
	ls_foreach (keys, i, kv) {
		size_t bplen = r_str_len_utf8 (BPREFIX);
		if (r_str_cmp ((char *)kv->base.key,
					BPREFIX, bplen)) {
			continue;
		}
		if (!r_list_append (ret, r_str_new ((char *)kv->base.key + bplen))
				&& !ret->head->data) {
			r_list_free (ret);
			ret = NULL;
			break;
		}
	}
	ls_free (keys);
	return ret;
}

R_API bool r_vc_branch(Rvc *rvc, const char *bname) {
	const char *current_branch;
	const char *commits;
	if (!repo_exists (rvc->path)) {
		R_LOG_ERROR ("No valid repo in %s", rvc->path);
		return false;
	}
	if (!is_valid_branch_name (bname)) {
		R_LOG_ERROR ("Invalid branch name %s", bname);
		return false;
	}
	{
		int ret = branch_exists (rvc, bname);
		if (ret < 0) {
			return false;
		} else if (ret) {
			R_LOG_ERROR ("The branch %s already exists", bname);
			return false;
		}
	}
	current_branch = sdb_const_get (rvc->db, CURRENTB, 0);
	if (!current_branch) {
		return false;
	}
	commits = sdb_const_get (rvc->db, current_branch, 0);
	char *nbn = r_str_newf (BPREFIX "%s", bname);
	if (!nbn) {
		return false;
	}
	sdb_set (rvc->db, nbn, commits, 0);
	free (nbn);
	return true;
}

R_API Rvc *r_vc_new(const char *path) {
	char *commitp, *blobsp;
	if (repo_exists (path)) {
		R_LOG_ERROR ("A repo already exists in %s", path);
		return NULL;
	}
	Rvc *rvc = R_NEW (Rvc);
	if (!rvc) {
		R_LOG_ERROR ("Failed to create repo");
		return NULL;
	}
	rvc->path = r_str_new (path);
	if (!rvc->path) {
		free (rvc);
		return NULL;
	}
	commitp = r_file_new (rvc->path, ".rvc", "commits", NULL);
	blobsp = r_file_new (rvc->path, ".rvc","blobs", NULL);
	if (!commitp || !blobsp) {
		free (commitp);
		free (blobsp);
		free (rvc->path);
		free (rvc);
		return false;
	}
	if (!r_sys_mkdirp (commitp) || !r_sys_mkdir (blobsp)) {
		R_LOG_ERROR ("Can't create The RVC repo directory");
		free (commitp);
		free (rvc->path);
		free (rvc);
		free (blobsp);
		return false;
	}
	free (commitp);
	free (blobsp);
	rvc->db = sdb_new (rvc->path, "/.rvc/" DBNAME, 0);
	if (!rvc->db) {
		R_LOG_ERROR ("Can't create The RVC branches database");
		free (rvc->path);
		free (rvc);
		return NULL;
	}
	if (!sdb_set (rvc->db, FIRST_BRANCH, NULLVAL, 0)) {
		sdb_unlink (rvc->db);
		sdb_free (rvc->db);
		free (rvc->path);
		free (rvc);
		return NULL;
	}
	if (!sdb_set (rvc->db, CURRENTB, FIRST_BRANCH, 0)) {
		sdb_unlink (rvc->db);
		sdb_free (rvc->db);
		free (rvc->path);
		free (rvc);
		return NULL;
	}
	if (!r_vc_use (rvc, RVC_TYPE_RVC)) {
		sdb_unlink (rvc->db);
		sdb_free (rvc->db);
		free (rvc->path);
		free (rvc);
		return NULL;
	}
	return r_vc_save (rvc)? rvc : NULL;
}

R_API bool r_vc_checkout(Rvc *rvc, const char *bname) {
	if (!repo_exists (rvc->path)) {
		R_LOG_ERROR ("No valid repo in %s", rvc->path);
		return false;
	}
	{
		int ret = branch_exists (rvc, bname);
		if (ret < 0) {
			return false;
		}
		if (ret == 0) {
			R_LOG_ERROR ("The branch %s doesn't exist", bname);
			return false;
		}
	}
	RList *uncommitted = r_vc_get_uncommitted (rvc);
	RListIter *i;
	char *file;
	if (!uncommitted) {
		return false;
	}
	if (!r_list_empty (uncommitted)) {
		eprintf ("The following files:\n");
		r_list_foreach (uncommitted, i, file) {
			eprintf ("%s\n", file);
		}
		eprintf ("Are uncommitted.\nCommit them before checkout\n");
		r_list_free (uncommitted);
		return false;
	}
	r_list_free (uncommitted);
	//Must set to NULL to avoid double r_list_free on fail_ret
	uncommitted = NULL;
	const char *oldb;
	{
		char *fbname = r_str_newf (BPREFIX "%s", bname);
		if (!fbname) {
			return false;
		}
		oldb = sdb_const_get (rvc->db, CURRENTB, 0);
		sdb_set (rvc->db, CURRENTB, fbname, 0);
		free (fbname);
		if (!sdb_sync (rvc->db)) {
			return false;
		}
	}
	if (!r_vc_reset (rvc)) {
		goto fail_ret;
	}
	if (!rm_empty_dir (rvc)) {
		goto fail_ret;
	}
	sdb_sync (rvc->db);
	return true;
fail_ret:
	r_list_free (uncommitted);
	sdb_set (rvc->db, CURRENTB, oldb, 0);
	sdb_sync (rvc->db);
	return false;
}

R_API bool r_vc_log(Rvc *rvc) {
	if (!repo_exists (rvc->path)) {
		R_LOG_ERROR ("No valid repo in %s", rvc->path);
		return false;
	}
	RList *commits = get_commits (rvc, 0);
	if (!commits) {
		return false;
	}
	bool ret = true;
	RListIter *iter;
	char *ch;
	r_list_foreach_prev (commits, iter, ch) {
		char *cp = r_file_new (rvc->path, ".rvc", "commits", ch, NULL);
		if (!cp) {
			ret = false;
			break;
		}
		char *contnet = r_file_slurp (cp, 0);
		free (cp);
		if (!contnet) {
			ret = false;
			break;
		}
		printf ("hash=%s", (char *) iter->data);
		if (!iter->data) {
			free (contnet);
			ret = false;
			break;
		}
		free (ch);
		printf ("\n%s\n****\n", contnet);
		free (contnet);
		if (!iter->data) {
			ret = false;
			break;
		}
	}
	r_list_free (commits);
	return ret;
}

R_API char *r_vc_current_branch(Rvc *rvc) {
	if (!repo_exists (rvc->path)) {
		R_LOG_ERROR ("No valid repo in %s", rvc->path);
		return false;
	}
	if (!rvc->db) {
		return NULL;
	}
	char *ret = r_str_new (sdb_const_get (rvc->db, CURRENTB, 0)
			+ r_str_len_utf8 (BPREFIX));
	return ret;
}

R_API bool r_vc_clone(const Rvc *rvc, const char *dst) {
	char *drp = r_file_new (dst, ".rvc", NULL);
	bool ret = false;
	if (drp) {
		char *srp = r_file_new (rvc->path, ".rvc", NULL);
		if (srp) {
			if (file_copyrf (srp, drp)) {
				Rvc *dst_repo = r_vc_open (dst, RVC_TYPE_RVC);
				if (dst_repo) {
					if (r_vc_reset (dst_repo)) {
						ret = true;
					} else {
						R_LOG_ERROR ("Failed to reset");
					}
					r_vc_free (dst_repo);
				}
			} else {
				R_LOG_ERROR ("Failed to copy files");
			}
			free (srp);
		}
		free (drp);
	}
	return ret;
}

// GIT commands as APIs

//TODO: unify the rvc and git apis

R_API Rvc *r_vc_git_open(const char *path) {
	char *git_path = r_file_new (path, ".git", NULL);
	if (!git_path || !r_file_is_directory (git_path)) {
		free (git_path);
		return NULL;
	}
	free (git_path);
	Rvc *vc = R_NEW (Rvc);
	if (!vc) {
		return NULL;
	}
	vc->path = r_str_new (path);
	if (!vc->path) {
		free (vc);
		return NULL;
	}
	vc->db = NULL;
	if (!r_vc_use (vc, RVC_TYPE_GIT)) {
		r_vc_free (vc);
		return NULL;
	}
	return vc;
}

R_API Rvc *r_vc_git_init(const char *path) {
	char *escpath = r_str_escape (path);
	int ret = r_sys_cmdf ("git init \"%s\"", escpath);
	free (escpath);
	return !ret? r_vc_git_open (path) : NULL;
}

R_API bool r_vc_git_branch(Rvc *vc, const char *name) {
	char *escpath = r_str_escape (vc->path);
	if (!escpath) {
		return false;
	}
	char *escname = r_str_escape (name);
	if (!escname) {
		free (escpath);
		return false;
	}
	int ret = r_sys_cmdf ("git -C \"%s\" branch \"%s\"", escpath, escname);
	free (escpath);
	free (escname);
	return !ret;
}

R_API bool r_vc_git_checkout(Rvc *vc, const char *name) {
	char *escpath = r_str_escape (vc->path);
	char *escname = r_str_escape (name);
	int ret = r_sys_cmdf ("git -C \"%s\" checkout \"%s\"", escpath, escname);
	free (escname);
	free (escpath);
	return !ret;
}

R_API bool r_vc_git_add(Rvc *vc, const RList *files) {
	RListIter *iter;
	const char *fname;
	char *cwd = r_sys_getdir ();
	if (!cwd) {
		return false;
	}
	if (!r_sys_chdir (vc->path)) {
		free (cwd);
		return false;
	}
	bool ret = true;
	r_list_foreach(files, iter, fname) {
		char *escfname = r_str_escape (fname);
		if (!escfname) {
			ret = false;
			break;
		}
		ret &= !r_sys_cmdf ("git add \"%s\"", escfname);
		free (escfname);
	}
	if (!r_sys_chdir (cwd)) {
		free (cwd);
		return false;
	}
	free (cwd);
	return ret;
}

R_API bool r_vc_git_commit(Rvc *vc, const char *_message, const char *author, const RList *files) {
	char *message = _message? strdup (_message): NULL;
	if (!r_vc_git_add (vc, files)) {
		return false;
	}
	char *escauth;
	if (!author) {
		char *user = r_sys_whoami ();
		escauth = r_str_escape (user);
		free (user);
	} else {
		escauth = r_str_escape (author);
	}
	if (!escauth) {
		return false;
	}
	if (R_STR_ISEMPTY (message)) {
		R_FREE (message);
		message = strdup ("default message");
	}
	if (R_STR_ISEMPTY (message)) {
		R_FREE (message);
		char *epath = r_str_escape (vc->path);
		if (epath) {
			// XXX ensure CWD in the same line?
			int res = r_sys_cmdf ("git -C \"%s\" commit --author \"%s <%s@localhost>\"", epath, escauth, escauth);
			free (escauth);
			free (epath);
			return res == 0;
		}
		return false;
	}
	char *epath = r_str_escape (vc->path);
	if (epath) {
		char *emsg = r_str_escape (message);
		if (emsg) {
			int res = r_sys_cmdf ("git -C %s commit -m %s --author \"%s <%s@localhost>\"",
					epath, emsg, escauth, escauth);
			free (escauth);
			free (message);
			free (epath);
			free (emsg);
			return res == 0;
		}
	}
	free (message);
	return false;
}

R_API bool r_vc_reset(Rvc *rvc) {
	r_return_val_if_fail (rvc, false);
	if (!repo_exists (rvc->path)) {
		return false;
	}
	bool ret = true;
	RList *uncommitted = r_vc_get_uncommitted (rvc);
	if (!uncommitted) {
		return false;
	}
	RListIter *iter;
	const char *fp;
	r_list_foreach (uncommitted, iter, fp) {
		char *blobp;
		{
			char *p = absp2rp (rvc, fp);
			if (!p) {
				ret = false;
				break;
			}
			char *b = find_blob_hash (rvc, p);
			if (!b || !strcmp (b, "-")) {
				free (p);
				if (!r_file_rm (fp)) {
					ret = false;
					break;
				}
				continue;

			}
			blobp = r_file_new (rvc->path, ".rvc", "blobs", b, NULL);
			free (b);
		}
		if (!blobp) {
			ret = false;
			break;
		}
		if (!file_copyp (blobp, fp)) {
			free (blobp);
			ret = false;
			break;
		}
	}
	r_list_free (uncommitted);
	return ret;
}

R_API RList *rvc_git_get_branches(Rvc *rvc) {
	r_return_val_if_fail (rvc, NULL);
	return rvc->p->get_branches (rvc);
}

R_API bool rvc_git_commit(Rvc *rvc, const char *message, const char *author, const RList *files) {
	r_return_val_if_fail (rvc && message && author && files, false);
	if (rvc->p->type == RVC_TYPE_RVC) {
#if 0
		author = author? author : r_config_get (core->config, "cfg.user");
#endif
		r_vc_commit (rvc, message, author, files);
		return r_vc_save (rvc);
	}
	return r_vc_git_commit (rvc, message, author, files);
}

R_API bool rvc_git_branch(Rvc *rvc, const char *bname) {
	r_return_val_if_fail (rvc && bname, false);
	if (rvc->p->type == RVC_TYPE_RVC) {
		rvc_warn ();
		r_vc_branch (rvc, bname);
		return r_vc_save(rvc);
	}
	return !r_vc_git_branch (rvc, bname);
}

R_API bool rvc_git_checkout(Rvc *rvc, const char *bname) {
#if 0
	return rvc->p->checkout (rvc, bname);
#endif
	if (rvc->p->type == RVC_TYPE_RVC) {
		rvc_warn ();
		r_vc_checkout (rvc, bname);
		return r_vc_save (rvc);
	}
	return r_vc_git_checkout (rvc, bname);
}

#if 0
R_API bool r_vc_git_repo_exists(const RCore *core, const char *path) {
	char *frp = !strcmp (r_config_get (core->config, "prj.vc.type"), "rvc")?
		r_file_new (path, ".rvc", NULL):
		r_file_new (path, ".git", NULL);
	if (frp) {
		bool ret = r_file_is_directory (frp);
		free (frp);
		return ret;
	}
	return false;
}
#endif

R_API Rvc *r_vc_open(const char *rp, RvcType type) {
	Rvc *repo = R_NEW (Rvc);
	if (repo) {
		repo->path = r_str_new (rp);
		if (repo->path) {
			repo->db = vcdb_open (rp) ;
			switch (type) {
			case RVC_TYPE_RVC:
			case RVC_TYPE_GIT:
				if (r_vc_use (repo, type)) {
					return repo;
				}
				break;
			case RVC_TYPE_ANY:
				{
					char *rvcdir = r_str_newf ("%s/.rvc/" DBNAME, rp);
					// check if .git exists and then .rvc or the other way
					if (r_file_exists (rvcdir)) {
						free (rvcdir);
						type = RVC_TYPE_RVC;
						if (r_vc_use (repo, type)) {
							return repo;
						}
					}
					free (rvcdir);
					char *gitdir = r_str_newf ("%s/.git/config", rp);
					if (r_file_exists (gitdir)) {
						free (gitdir);
						type = RVC_TYPE_GIT;
						if (r_vc_use (repo, type)) {
							return repo;
						}
					}
					free (gitdir);
				}
				break;
			default:
				// unknown vc type
				break;
			}
			sdb_free (repo->db);
			free (repo->path);
		}
		free (repo);
	}
	return NULL;
}

R_API bool r_vc_save(Rvc *vc) {
	r_return_val_if_fail (vc, false);
	if (vc->db) {
		sdb_sync (vc->db);
		return true;
	}
	return false;
}

R_API void r_vc_free(Rvc *vc) {
	if (vc) {
		// sdb_sync ()
		sdb_close (vc->db);
		free (vc->path);
		free (vc);
	}
}

R_API void r_vc_close(Rvc *vc, bool save) {
	r_return_if_fail (vc);
	if (save) {
		r_vc_save (vc);
	}
	r_vc_free (vc);
}

R_API RList *r_vc_git_get_branches(Rvc *rvc) {
	RList *ret = NULL;
	char *esc_path = r_str_escape (rvc->path);
	if (esc_path) {
		char *output = r_sys_cmd_strf ("git -C %s branch --color=never", esc_path);
		r_str_trim (output);
		free (esc_path);
		if (!R_STR_ISEMPTY (output)) {
			ret = r_str_split_duplist (output, "\n", true);
			RListIter *iter;
			char *name;
			r_list_foreach (ret, iter, name) {
				if (*(char *)iter->data == '*') {
					iter->data = r_str_new (name + 2);
					free (name);
				}

			}
		}
	}
	return ret;
}

R_API RList *r_vc_git_get_uncommitted(Rvc *rvc) {
	RList *ret = NULL;
	char *esc_path = r_str_escape (rvc->path);
	if (esc_path) {
		char *output = r_sys_cmd_strf ("git -C %s status --short",
				esc_path);
		free (esc_path);
		if (!R_STR_ISEMPTY (output)) {
			r_str_trim(output);
			ret = r_str_split_duplist (output, "\n", true);
			free (output);
			RListIter *iter;
			char *i;
			r_list_foreach (ret, iter, i) {
				//after we add one to the output, there maybe
				//a space so trim that
				char *ni = r_str_trim_dup (i + 2);
				if (!ni) {
					r_list_free (ret);
					ret = NULL;
					break;
				}
				free (i);
				iter->data = ni;
			}
		} else {
			ret = r_list_new ();
		}

	}
	return ret;
}

R_API bool r_vc_git_log(Rvc *rvc) {
	bool ret = true;
	char *esc_path = r_str_escape (rvc->path);
	if (esc_path) {
		ret = !r_sys_cmdf ("git -C %s log", esc_path);
		free (esc_path);
	}
	return ret;
}

R_API char *r_vc_git_current_branch(Rvc *rvc) {
	char *ret = NULL;
	char *esc_path = r_str_escape (rvc->path);
	if (esc_path) {
		char *branch = r_sys_cmd_strf ("git -C %s rev-parse --abbrev-ref HEAD", esc_path);
		if (!R_STR_ISEMPTY (branch)) {
			ret = r_str_ndup (branch, strlen (branch) - 1);
		}
		free (branch);
		free (esc_path);
	}
	return ret;
}

R_API bool r_vc_git_reset(Rvc *rvc) {
	char *esc_path = r_str_escape (rvc->path);
	if (esc_path) {
		bool ret = r_sys_cmdf ("git -C %s checkout .", esc_path);
		free (esc_path);
		return !ret;
	}
	return false;
}

R_API bool r_vc_git_clone(const Rvc *rvc, const char *dst) {
	char *esc_src = r_str_escape (rvc->path);
	char *esc_dst = r_str_escape (dst);
	bool ret = false;
	if (esc_src && esc_dst) {
		ret = !r_sys_cmdf ("git clone %s %s", esc_src, esc_dst);
	}
	free (esc_src);
	free (esc_dst);
	return ret;
}

R_API void r_vc_git_close(Rvc *vc, bool save) {
	if (vc) {
		free (vc->path);
		free (vc);
	}
}

R_API bool r_vc_git_save(Rvc *vc) {
	//do nothing, since git commands are automatically executed
	return true;
}

static const RvcPlugin vc_plugin_git = {
	.name = "git",
	.type = RVC_TYPE_GIT,
	.commit = r_vc_git_commit,
	.branch = r_vc_git_branch,
	.checkout = r_vc_git_checkout,
	.get_branches = r_vc_git_get_branches,
	.get_uncommitted = r_vc_git_get_uncommitted,
	.print_commits = r_vc_git_log,
	.current_branch = r_vc_git_current_branch,
	.reset = r_vc_git_reset,
	.clone = r_vc_git_clone,
	.close = r_vc_git_close,
	.save = r_vc_git_save,
};

static const RvcPlugin vc_plugin_rvc = {
	.name = "rvc",
	.type = RVC_TYPE_RVC,
	.commit = r_vc_commit,
	.branch = r_vc_branch,
	.checkout = r_vc_checkout,
	.get_branches = r_vc_get_branches,
	.get_uncommitted = r_vc_get_uncommitted,
	.print_commits = r_vc_log,
	.current_branch = r_vc_current_branch,
	.reset = r_vc_reset,
	.clone = r_vc_clone,
	.close = r_vc_close,
	.save = r_vc_save,
};

R_API bool r_vc_use(Rvc *vc, RvcType type) {
	switch (type) {
	case RVC_TYPE_GIT:
		vc->p = &vc_plugin_git;
		break;
	case RVC_TYPE_RVC:
		vc->p = &vc_plugin_rvc;
		break;
	default:
		r_return_val_if_reached (false);
	}
	return true;
}

R_API Rvc *rvc_git_open(const char *path) {
	r_return_val_if_fail (path, NULL);
	if (repo_exists (path)) {
		return r_vc_open (path, RVC_TYPE_ANY);
	}
	return r_vc_git_open (path);
}

R_API Rvc *rvc_init(const char *path, RvcType type) {
	r_return_val_if_fail (path, NULL);
	switch (type) {
	case RVC_TYPE_GIT:
		return r_vc_git_init (path);
		break;
	case RVC_TYPE_RVC:
		{
			rvc_warn ();
			Rvc *rvc = r_vc_new (path);
			if (!rvc || !r_vc_save (rvc)) {
				return NULL;
			}
			return rvc;
		}
		break;
	default:
		break;
	}
	R_LOG_ERROR ("Unknown version control");
	return NULL;
}

R_API void rvc_git_close(Rvc *vc, bool save) {
	r_return_if_fail (vc && vc->p);
	vc->p->close (vc, true);
}
