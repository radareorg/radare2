/* radare - LGPL - Copyright 2021-2023 - RHL120, pancake */
// GIT commands as APIs
#define R_LOG_ORIGIN "vc.git"
#include <rvc.h>

extern const RvcPlugin r_vc_plugin_git;

static Rvc *open_git(const char *path) {
	char *git_path = r_file_new (path, ".git", NULL);
	if (!git_path || !r_file_is_directory (git_path)) {
		char *escpath = r_str_escape (path);
		int ret = r_sys_cmdf ("git init \"%s\" > %s", escpath, R_SYS_DEVNULL);
		if (ret != 0) {
			R_LOG_WARN ("git init failed");
		}
		if (!r_file_is_directory (git_path)) {
			free (git_path);
			return NULL;
		}
	}
	free (git_path);
	Rvc *vc = R_NEW (Rvc);
	if (!vc) {
		return NULL;
	}
	vc->path = strdup (path);
	if (!vc->path) {
		free (vc);
		return NULL;
	}
	vc->db = NULL;
	vc->p = &r_vc_plugin_git;
	return vc;
}

static bool _git_branch(Rvc *vc, const char *name) {
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

static bool checkout_git(Rvc *vc, const char *name) {
	char *escpath = r_str_escape (vc->path);
	char *escname = r_str_escape (name);
	int ret = r_sys_cmdf ("git -C \"%s\" checkout \"%s\"", escpath, escname);
	free (escname);
	free (escpath);
	return !ret;
}

static bool add_git(Rvc *vc, const RList *files) {
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
	r_list_foreach (files, iter, fname) {
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

static bool commit_git(Rvc *vc, const char *_message, const char *author, const RList *files) {
	char *message = _message? strdup (_message): NULL;
	if (!add_git (vc, files)) {
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
			int res = r_sys_cmdf ("git -C \"%s\" commit -m \"%s\" --author \"%s <%s@localhost>\"",
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

#if 0
R_API RList *rvc_git_get_branches(Rvc *rvc) {
	R_RETURN_VAL_IF_FAIL (rvc, NULL);
	return rvc->p->get_branches (rvc);
}

static bool XXX_git_commit(Rvc *rvc, const char *message, const char *author, const RList *files) {
	R_RETURN_VAL_IF_FAIL (rvc && message && author && files, false);
	if (rvc->p->type == RVC_TYPE_RVC) {
#if 0
		author = author? author : r_config_get (core->config, "cfg.user");
#endif
		r_vc_commit (rvc, message, author, files);
		return rvc_save (rvc);
	}
	return r_vc_git_commit (rvc, message, author, files);
}
#endif

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

R_API RList *branches_git(Rvc *rvc) {
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
					iter->data = strdup (name + 2);
					free (name);
				}

			}
		}
	}
	return ret;
}

static RList *uncommited_git(Rvc *rvc) {
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

static bool log_git(Rvc *rvc) {
	bool ret = true;
	char *esc_path = r_str_escape (rvc->path);
	if (esc_path) {
		ret = !r_sys_cmdf ("git -C %s log", esc_path);
		free (esc_path);
	}
	return ret;
}

R_API char *curbranch_git(Rvc *rvc) {
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

static bool reset_git(Rvc *rvc) {
	char *esc_path = r_str_escape (rvc->path);
	if (esc_path) {
		bool ret = r_sys_cmdf ("git -C %s checkout .", esc_path);
		free (esc_path);
		return !ret;
	}
	return false;
}

static bool clone_git(const Rvc *rvc, const char *dst) {
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

static void close_git(Rvc *vc, bool save) {
	if (vc) {
		free (vc->path);
		free (vc);
	}
}

R_API bool save_git(Rvc *vc) {
	//do nothing, since git commands are automatically executed
	return true;
}

const RvcPlugin r_vc_plugin_git = {
	.name = "git",
	.type = RVC_TYPE_GIT,
	.commit = commit_git,
	.branch = _git_branch,
	.checkout = checkout_git,
	.branches = branches_git,
	.uncommited = uncommited_git,
	.log = log_git,
	.curbranch = curbranch_git,
	.reset = reset_git,
	.clone = clone_git,
	.close = close_git,
	.save = save_git,
	// .init = init_git,
	.open = open_git,
};
