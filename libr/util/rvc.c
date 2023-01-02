/* radare - LGPL - Copyright 2021-2022 - RHL120, pancake */

#define R_LOG_ORIGIN "rvc"

#include <rvc.h>
#define DBNAME "branches.sdb"

extern RvcPlugin r_vc_plugin_git;
extern RvcPlugin r_vc_plugin_rvc;


R_API void rvc_free(Rvc *vc) {
	if (vc) {
		// sdb_sync ()
		sdb_close (vc->db);
		free (vc->path);
		free (vc);
	}
}

R_API bool rvc_use(Rvc *vc, RvcType type) {
	switch (type) {
	case RVC_TYPE_GIT:
		vc->p = &r_vc_plugin_git;
		break;
	case RVC_TYPE_RVC:
		vc->p = &r_vc_plugin_rvc;
		break;
	default:
		r_return_val_if_reached (false);
	}
	return true;
}

R_API RvcType rvc_repo_type(const char *path) {
	const char *paths[] = {".git", ".rvc"};
	const RvcType types[] = {RVC_TYPE_GIT, RVC_TYPE_RVC};
	size_t i = 0;
	for (; i < sizeof (paths) / sizeof (char *)
			&& i < sizeof (types) / sizeof (RvcType); i++) {
		char *p = r_file_new (path, paths[i], NULL);
		if (r_file_is_directory(p)) {
			return types[i];
		}
		free (p);
	}
	return RVC_TYPE_INV;
}

R_API Rvc *rvc_open(const char *path, RvcType type) {
	r_return_val_if_fail (path, NULL);
	Rvc *rvc = NULL;
	int repotype = (type == RVC_TYPE_ANY)? rvc_repo_type (path): type;
	switch (repotype) {
	case RVC_TYPE_GIT:
		rvc = r_vc_plugin_git.open (path);
		rvc->p = &r_vc_plugin_git;
		break;
	case RVC_TYPE_RVC:
		rvc = r_vc_plugin_rvc.open (path);
		rvc->p = &r_vc_plugin_rvc;
		break;
	}
	return rvc;
}

#if 0
// XXX this is conceptually wrong
R_API Rvc *rvc_init(const char *path, RvcType type) {
	r_return_val_if_fail (path, NULL);
#if 0
	RvcPluginBranch open = R_UNWRAP3 (vc, p, open);
	return open? open (vc, path, type): NULL;
#endif
#if 0
	r_return_val_if_fail (path, NULL);
	switch (type) {
	case RVC_TYPE_GIT:
		return r_vc_git_init (path);
		break;
	case RVC_TYPE_RVC:
		{
			Rvc *rvc = r_vc_new (path);
			if (!rvc || !rvc_save (rvc)) {
				return NULL;
			}
			return rvc;
		}
		break;
	default:
		break;
	}
	R_LOG_ERROR ("Unknown version control");
#endif
	return NULL;
}
#endif

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
