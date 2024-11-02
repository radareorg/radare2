/* radare - LGPL - Copyright 2021-2024 - RHL120, pancake */

#ifndef R_RVC_H
#define R_RVC_H 1
#define BPREFIX "branches."

#ifdef __cplusplus
extern "C" {
#endif

#include <r_util.h>
#include <sdb/sdb.h>

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

typedef bool (*RvcPluginBranch)(struct r_vc_t *rvc, const char *bname);
typedef bool (*RvcPluginCommit)(struct r_vc_t *rvc, const char *message, const char *author, const RList *files);
typedef bool (*RvcPluginCheckout)(struct r_vc_t *rvc, const char *bname);
typedef RList *(*RvcPluginBranches)(struct r_vc_t *rvc);
typedef void (*RvcPluginClose)(struct r_vc_t *vc, bool save);
typedef char *(*RvcPluginCurrentBranch)(struct r_vc_t *rvc);
typedef bool (*RvcPluginPrintCommits) (struct r_vc_t *rvc);
typedef RList *(*RvcPluginUncommited) (struct r_vc_t *rvc);
typedef bool (*RvcPluginReset)(struct r_vc_t *rvc);
typedef bool (*RvcPluginClone)(const struct r_vc_t *rvc, const char *dst);
typedef bool (*RvcPluginSave)(struct r_vc_t *vc);
typedef Rvc *(*RvcPluginOpen)(const char *path);

// R2_600 typedef char *(*RvcPluginHash)(const ut8 *data, size_t len);

typedef struct rvc_plugin_t {
	// TODO: R2_600 - Use RPluginMeta
	const char *const name;
	const char *const author;
	const char *const desc;
	const char *const license;
	RvcType type;
	RvcPluginCommit commit;
	RvcPluginCheckout checkout;
	RvcPluginBranch branch;
	RvcPluginBranches branches;
	RvcPluginCurrentBranch curbranch;
	RvcPluginUncommited uncommited;
	RvcPluginPrintCommits log;
	RvcPluginReset reset;
	RvcPluginClone clone;
	RvcPluginClose close;
	RvcPluginSave save;
	RvcPluginOpen open;
	// R2_600 RvcPluginHash hash;
} RvcPlugin;

R_API Rvc *rvc_open(const char *rp, RvcType type);
R_API void rvc_close(Rvc *vc, bool save);
R_API bool rvc_save(Rvc *vc);
R_API void rvc_free(Rvc *vc);

R_API RList *rvc_branches(Rvc *vc);

R_API bool rvc_commit(Rvc *rvc, const char *message, const char *author, const RList *files);
R_API bool rvc_branch(Rvc *rvc, const char *bname);
R_API Rvc *r_vc_new(const char *path);
R_API bool r_vc_checkout(Rvc *rvc, const char *bname);
R_API RList *r_vc_get_uncommitted(Rvc *rvc);
R_API bool r_vc_log(Rvc *rvc);
R_API char *r_vc_current_branch(Rvc *rvc);
R_API bool r_vc_reset(Rvc *rvc);
R_API bool r_vc_clone(const Rvc *rvc, const char *dst);

R_API Rvc *rvc_git_init(const char *path);
R_API Rvc *rvc_git_open(const char *path);
R_API bool rvc_checkout(Rvc *vc, const char *bname);
R_API bool rvc_git_commit(Rvc *rvc, const char *message, const char *author, const RList *files);
R_API void rvc_git_close(struct r_vc_t *vc, bool save);
R_API RList *rvc_git_get_branches(Rvc *rvc);

#ifdef __cplusplus
}
#endif

#endif
