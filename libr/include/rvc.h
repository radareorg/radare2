#include <r_core.h>
typedef struct blob {
	char *fname;
	char *hash;
} RvcBlob;

typedef struct commit {
	struct commit *prev;
	struct blob **blobs;
	char *author;
	int64_t *timestamp;
	char *hash;
	size_t next_num;
	RList *next; //next is an array so we can permit RVc revert
} RvcCommit;

typedef struct branch {
	char *name;
	RvcCommit *head;
} RvcBranch;

typedef struct RVc {
	char *path;
	RList *branches;
} Rvc;

static bool copy_commits(const Rvc *repo, const char *dpath, const char *sname);

static char *branch_mkdir(Rvc *repo, RvcBranch *b);

R_API bool rvc_branch(Rvc *repo, const char *name, const RvcBranch *parent);

R_API Rvc *rvc_new(const char *path);
