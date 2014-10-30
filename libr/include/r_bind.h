#ifndef R2_BIND_H
#define R2_BIND_H

// TODO: move riobind here too?

typedef int (*RCoreCmd)(void *core, const char *cmd);
typedef int (*RCoreDebugBpHit)(void *core, void *bp);
typedef char* (*RCoreCmdStr)(void *core, const char *cmd);
typedef void (*RCorePuts)(const char *cmd);

typedef struct r_core_bind_t {
	void *core;
	RCoreCmd cmd;
	RCoreCmdStr cmdstr;
	RCorePuts puts ;
	RCoreDebugBpHit bphit;
} RCoreBind;

#endif
