/* radare - LGPL - Copyright 2021 - RHL120, pancake */

#ifndef R_RVC_H
#define R_RVC_H 1
#define BPREFIX "branches."

#ifdef __cplusplus
extern "C" {
#endif

#include <r_core.h>
#include <sdb.h>
typedef struct RvcBlob_t {
	char *fname;
	char *fhash;
} RvcBlob;

R_API bool r_vc_git_init(const char *path);
R_API bool r_vc_git_branch(const char *path, const char *name);
R_API bool r_vc_git_checkout(const char *path, const char *name);
R_API bool r_vc_git_add(const char *path, const char *fname);
R_API bool r_vc_git_commit(const char *path, const char *message);

R_API bool r_vc_commit(Rvc *rvc, const char *message, const char *author, const RList *files);
R_API bool r_vc_branch(Rvc *rvc, const char *bname);
R_API Rvc *r_vc_new(const char *path);
R_API bool r_vc_checkout(Rvc *rvc, const char *bname);
R_API RList *r_vc_get_branches(Rvc *rvc);
R_API RList *r_vc_get_uncommitted(Rvc *rvc);
R_API RList *r_vc_log(Rvc *rvc);
R_API char *r_vc_current_branch(Rvc *rvc);
R_API bool r_vc_reset(Rvc *rvc);
R_API bool r_vc_clone(const char *src, const char *dst);
R_API Rvc *r_vc_load(const char *rp);
R_API void r_vc_close(Rvc *vc, bool save);
R_API bool r_vc_save(Rvc *vc);

R_API bool rvc_git_init(const RCore *core, const char *path);
R_API bool rvc_git_commit(RCore *core, Rvc *rvc, const char *message, const char *author, const RList *files);
R_API bool rvc_git_branch(const RCore *core, Rvc *rvc, const char *bname);
R_API bool rvc_git_checkout(const RCore *core, Rvc *rvc, const char *bname);
R_API bool rvc_git_repo_exists(const RCore *core, const char *path);

#ifdef __cplusplus
}
#endif

#endif
