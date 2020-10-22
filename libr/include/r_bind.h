/* radare2 - LGPL - Copyright 2015-2020 - pancake */

#ifndef R2_BIND_H
#define R2_BIND_H

// TODO: move riobind here too?
// TODO: move rprint here too

typedef int (*RCoreCmd)(void *core, const char *cmd);
typedef int (*RCoreCmdF)(void *user, const char *fmt, ...);
typedef int (*RCoreDebugBpHit)(void *core, void *bp);
typedef void (*RCoreDebugSyscallHit)(void *core);
typedef char* (*RCoreCmdStr)(void *core, const char *cmd);
typedef char* (*RCoreCmdStrF)(void *core, const char *cmd, ...);
typedef void (*RCorePuts)(const char *cmd);
typedef void (*RCoreSetArchBits)(void *core, const char *arch, int bits);
typedef bool (*RCoreIsMapped)(void *core, ut64 addr, int perm);
typedef bool (*RCoreDebugMapsSync)(void *core);
typedef const char *(*RCoreGetName)(void *core, ut64 off);
typedef char *(*RCoreGetNameDelta)(void *core, ut64 off);
typedef void (*RCoreSeekArchBits)(void *core, ut64 addr); 
typedef int (*RCoreConfigGetI)(void *core, const char *key);
typedef const char *(*RCoreConfigGet)(void *core, const char *key);
typedef ut64 (*RCoreNumGet)(void *core, const char *str);
typedef void *(*RCorePJWithEncoding)(void *core);

typedef struct r_core_bind_t {
	void *core;
	RCoreCmd cmd;
	RCoreCmdF cmdf;
	RCoreCmdStr cmdstr;
	RCoreCmdStrF cmdstrf;
	RCorePuts puts;
	RCoreDebugBpHit bphit;
	RCoreDebugSyscallHit syshit;
	RCoreSetArchBits setab;
	RCoreGetName getName;
	RCoreGetNameDelta getNameDelta;
	RCoreSeekArchBits archbits;
	RCoreConfigGetI cfggeti;
	RCoreConfigGet cfgGet;
	RCoreNumGet numGet;
	RCoreIsMapped isMapped;
	RCoreDebugMapsSync syncDebugMaps;
	RCorePJWithEncoding pjWithEncoding;
} RCoreBind;

#endif
