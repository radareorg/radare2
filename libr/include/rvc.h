/* radare - LGPL - Copyright 2021 - RHL120, pancake */

#ifndef R_RVC_H
#define R_RVC_H 1
#define BPREFIX "branches."

#ifdef __cplusplus
extern "C" {
#endif

#include <r_core.h>
#include <sdb.h>

typedef struct r_vc_blob_t {
	char *fname;
	char *fhash;
} RvcBlob;

typedef enum r_vc_type_t {
	RVC_TYPE_RVC,
	RVC_TYPE_GIT,
	RVC_TYPE_ANY,
	RVC_TYPE_INV
} RvcType;

typedef struct r_vc_t {
	char *path;
	Sdb *db;
	const struct rvc_plugin_t *p;
} Rvc;

typedef struct rvc_plugin_t {
	const char *name;
	const char *author;
	const char *desc;
	const char *license;
	RvcType type;
	bool (*commit)(struct r_vc_t *rvc, const char *message, const char *author, const RList *files);
	bool (*branch)(struct r_vc_t *rvc, const char *bname);
	bool (*checkout)(struct r_vc_t *rvc, const char *bname);
	RList *(*get_branches) (struct r_vc_t *rvc);
	RList *(*get_uncommitted) (struct r_vc_t *rvc);
	bool (*print_commits) (struct r_vc_t *rvc);
	char *(*current_branch)(struct r_vc_t *rvc);
	bool (*reset)(struct r_vc_t *rvc);
	bool (*clone)(const struct r_vc_t *rvc, const char *dst);
	void (*close)(struct r_vc_t *vc, bool save);
	bool (*save)(struct r_vc_t *vc);
} RvcPlugin;

R_API Rvc *rvc_init(const char *path, RvcType type);

R_API Rvc *r_vc_git_init(const char *path);
R_API bool r_vc_git_branch(Rvc *vc, const char *name);
R_API bool r_vc_git_checkout(Rvc *vc, const char *name);
R_API bool r_vc_git_add(Rvc *vc, const RList *files);
R_API bool r_vc_git_commit(Rvc *rvc, const char *message, const char *author, const RList *files);
R_API Rvc *r_vc_git_open(const char *path);

R_API bool r_vc_commit(Rvc *rvc, const char *message, const char *author, const RList *files);
R_API bool r_vc_branch(Rvc *rvc, const char *bname);
R_API Rvc *r_vc_new(const char *path);
R_API bool r_vc_checkout(Rvc *rvc, const char *bname);
R_API RList *r_vc_get_branches(Rvc *rvc);
R_API RList *r_vc_get_uncommitted(Rvc *rvc);
R_API bool r_vc_log(Rvc *rvc);
R_API char *r_vc_current_branch(Rvc *rvc);
R_API bool r_vc_reset(Rvc *rvc);
R_API bool r_vc_clone(const Rvc *rvc, const char *dst);
R_API Rvc *r_vc_open(const char *rp, RvcType type);
R_API void r_vc_close(Rvc *vc, bool save);
R_API bool r_vc_save(Rvc *vc);

R_API RList *r_vc_git_get_branches(Rvc *rvc);
R_API RList *r_vc_git_get_uncommitted(Rvc *rvc);
R_API bool r_vc_git_log(Rvc *rvc);
R_API char *r_vc_git_current_branch(Rvc *rvc);
R_API bool r_vc_git_reset(Rvc *rvc);
R_API bool r_vc_git_clone(const Rvc *rvc, const char *dst);
R_API void r_vc_git_close(Rvc *vc, bool save);
R_API bool rvc_git_checkout(Rvc *rvc, const char *bname);

R_API Rvc *rvc_git_init(const char *path);
R_API Rvc *rvc_git_open(const char *path);
R_API bool r_vc_use(Rvc *vc, RvcType);
R_API bool rvc_git_commit(Rvc *rvc, const char *message, const char *author, const RList *files);
R_API void rvc_git_close(struct r_vc_t *vc, bool save);
R_API RList *rvc_git_get_branches(Rvc *rvc);

#ifdef __cplusplus
}
#endif

#endif
