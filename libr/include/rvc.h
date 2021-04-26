/* radare - LGPL - Copyright 2013-2020 - RHL120, pancake */

#include <r_core.h>
#include <r_util.h>

typedef struct blob {
	char *fname;
	char *hash;
} RvcBlob;

typedef struct commit {
	struct commit *prev;
	RList *blobs;
	char *author;
	int64_t timestamp;
	char *hash;
	size_t next_num;
	bool ishead;
	char *message;
	struct commit *next;
} RvcCommit;

typedef struct branch {
	char *name;
	RvcCommit *head;
} RvcBranch;

typedef struct RVc {
	char *path;
	RList *branches;
	RvcBranch *current_branch;
} Rvc;

R_API RvcBlob *r_vc_path_to_commit(Rvc *repo, const char *path);
R_API RList *r_vc_uncomitted(Rvc *repo);
R_API bool r_vc_checkout(Rvc *repo, const char *name);
R_API bool r_vc_commit(Rvc *repo, RList *blobs, const char *auth, const char *message);
R_API bool r_vc_branch(Rvc *repo, const char *name);
R_API RList *r_vc_add(Rvc *repo, RList *files);
R_API Rvc *r_vc_new(const char *path);
R_API int r_vc_git_init(const char *path);
R_API bool r_vc_git_branch(const char *path, const char *name);
R_API bool r_vc_git_checkout(const char *path, const char *name);
R_API int r_vc_git_add(const char *path, const char *fname);
R_API int r_vc_git_commit(const char *path, const char *message);
