/* radare - LGPL - Copyright 2021-2023 - RHL120, pancake */

#define R_LOG_ORIGIN "rvc"

#include <rvc.h>
#define DBNAME "branches.sdb"

extern const RvcPlugin r_vc_plugin_git;
extern const RvcPlugin r_vc_plugin_rvc;

R_API void rvc_free(Rvc *vc) {
	if (vc) {
		// sdb_sync ()
		sdb_close (vc->db);
		free (vc->path);
		free (vc);
	}
}

R_API RvcType rvc_repo_type(const char *path) {
	const char *paths[] = {".git", ".rvc"};
	const RvcType types[] = {RVC_TYPE_GIT, RVC_TYPE_RVC};
	size_t i = 0;
	for (; i < sizeof (paths) / sizeof (char *)
			&& i < sizeof (types) / sizeof (RvcType); i++) {
		char *p = r_file_new (path, paths[i], NULL);
		if (r_file_is_directory (p)) {
			return types[i];
		}
		free (p);
	}
	return RVC_TYPE_INV;
}

R_API Rvc *rvc_open(const char *path, RvcType type) {
	r_return_val_if_fail (path, NULL);
	const int repotype = (type == RVC_TYPE_ANY)? rvc_repo_type (path): type;
	switch (repotype) {
	case RVC_TYPE_GIT:
		return r_vc_plugin_git.open (path);
	case RVC_TYPE_RVC:
		return r_vc_plugin_rvc.open (path);
	}
	return NULL;
}

R_API void rvc_close(Rvc *vc, bool save) {
	r_return_if_fail (vc);
	RvcPluginClose klose = R_UNWRAP3 (vc, p, close);
	if (klose) {
		klose (vc, save);
	}
}

R_API bool rvc_branch(Rvc *vc, const char *branch_name) {
	r_return_val_if_fail (vc && branch_name, false);
	RvcPluginBranch branch = R_UNWRAP3 (vc, p, branch);
	return branch? branch (vc, branch_name): false;
}

R_API RList *rvc_branches(Rvc *vc) {
	r_return_val_if_fail (vc, NULL);
	RvcPluginBranches branches = R_UNWRAP3 (vc, p, branches);
	return branches? branches (vc): NULL;
}

R_API bool rvc_checkout(Rvc *vc, const char *bname) {
	r_return_val_if_fail (vc && bname, false);
	RvcPluginCheckout co = R_UNWRAP3 (vc, p, checkout);
	return co? co (vc, bname): false;
}

R_API bool rvc_save(Rvc *vc) {
	r_return_val_if_fail (vc, false);
	RvcPluginSave s = R_UNWRAP3 (vc, p, save);
	return s? s (vc): false;
}

R_API bool rvc_commit(Rvc *vc, const char *message, const char *author, const RList *files) {
	r_return_val_if_fail (vc, false);
	RvcPluginCommit ci = R_UNWRAP3 (vc, p, commit);
	return ci? ci (vc, message, author, files): false;
}
