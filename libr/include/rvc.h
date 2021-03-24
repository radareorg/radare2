#include <r_core.h>
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



R_API bool rvc_commit(Rvc *repo, RvcBranch *b, RList *blobs, char *auth);

R_API bool rvc_branch(Rvc *repo, const char *name, const RvcBranch *parent);

R_API Rvc *rvc_new(const char *path);
