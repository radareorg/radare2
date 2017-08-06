/* radare2 - LGPL - Copyright 2015-2016 - pancake */
#ifndef R2_BIND_H
#define R2_BIND_H

// TODO: move riobind here too?
// TODO: move rprint here too

typedef int (*RCoreCmd)(void *core, const char *cmd);
typedef int (*RCoreCmdF)(void *user, const char *fmt, ...);
typedef int (*RCoreDebugBpHit)(void *core, void *bp);
typedef char* (*RCoreCmdStr)(void *core, const char *cmd);
typedef char* (*RCoreCmdStrF)(void *core, const char *cmd, ...);
typedef void (*RCorePuts)(const char *cmd);
typedef void (*RCoreSetArchBits)(void *core, const char *arch, int bits);
typedef char *(*RCoreGetName)(void *core, ut64 off);
typedef void (*RCoreSeekArchBits)(void *core, ut64 addr); 
typedef int (*RCoreConfigGetI)(void *core, const char *key);

typedef struct r_core_bind_t {
	void *core;
	RCoreCmd cmd;
	RCoreCmdF cmdf;
	RCoreCmdStr cmdstr;
	RCoreCmdStrF cmdstrf;
	RCorePuts puts;
	RCoreDebugBpHit bphit;
	RCoreSetArchBits setab;
	RCoreGetName getName;
	RCoreSeekArchBits archbits;
	RCoreConfigGetI cfggeti;
} RCoreBind;

#endif
