#ifndef regexp_h
#define regexp_h

#define regcompx js_regcompx
#define regfreex js_regfreex
#define regcomp js_regcomp
#define regexec js_regexec
#define regfree js_regfree

typedef struct Reprog Reprog;
typedef struct Resub Resub;

Reprog *regcompx(void *(*alloc)(void *ctx, void *p, int n), void *ctx,
	const char *pattern, int cflags, const char **errorp);
void regfreex(void *(*alloc)(void *ctx, void *p, int n), void *ctx,
	Reprog *prog);

Reprog *regcomp(const char *pattern, int cflags, const char **errorp);
int regexec(Reprog *prog, const char *string, Resub *sub, int eflags);
void regfree(Reprog *prog);

enum {
	/* regcomp flags */
	REG_ICASE = 1,
	REG_NEWLINE = 2,

	/* regexec flags */
	REG_NOTBOL = 4,
};

/* If you redefine REG_MAXSUB, you must make sure both the calling
 * code and the regexp.c compilation unit use the same value!
 */
#ifndef REG_MAXSUB
#define REG_MAXSUB 10
#endif

struct Resub {
	int nsub;
	struct {
		const char *sp;
		const char *ep;
	} sub[REG_MAXSUB];
};

#endif
