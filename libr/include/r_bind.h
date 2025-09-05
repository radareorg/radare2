/* radare2 - LGPL - Copyright 2015-2024 - pancake */

#ifndef R2_BIND_H
#define R2_BIND_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef R2_CONS_H
typedef const char * const RCoreHelpMessage[];
#endif

typedef int (*RCoreCmd)(void *core, const char *cmd);
typedef int (*RCoreCmdF)(void *user, const char *fmt, ...);
typedef char *(*RCoreCallAt)(void *user, ut64 addr, const char *cmd);
typedef int (*RCoreDebugBpHit)(void *core, void *bp);
typedef void (*RCoreDebugSyscallHit)(void *core);
typedef char* (*RCoreCmdStr)(void *core, const char *cmd);
typedef char* (*RCoreBindHelp)(void *core, RCoreHelpMessage help);
typedef char* (*RCoreCmdStrF)(void *core, const char *cmd, ...);
typedef void (*RCorePuts)(const char *cmd);
typedef void (*RCoreSetArchBits)(void *core, const char *arch, int bits);
typedef bool (*RCoreIsMapped)(void *core, ut64 addr, int perm);
typedef bool (*RCoreDebugMapsSync)(void *core);
typedef const char *(*RCoreGetName)(void *core, ut64 off);
typedef char *(*RCoreGetNameDelta)(void *core, ut64 off);
typedef void (*RCoreSeekArchBits)(void *core, ut64 addr);
typedef bool (*RCoreConfigGetB)(void *core, const char *key);
typedef int (*RCoreConfigGetI)(void *core, const char *key);
typedef const char *(*RCoreConfigGet)(void *core, const char *key);
typedef ut64 (*RCoreNumGet)(void *core, const char *str);
typedef void *(*RCorePJWithEncoding)(void *core);

typedef struct r_core_bind_t {
	void *core;
	RCoreCmd cmd;
	RCoreCmdF cmdf;
	RCoreCallAt callAt;
	RCoreCmdStr cmdStr; // should be cmdStr if we care about snake
	RCoreCmdStrF cmdStrF;
	RCoreBindHelp help;
	RCorePuts puts;
	RCoreDebugBpHit bpHit;
	RCoreDebugSyscallHit sysHit;
	RCoreSetArchBits setArchBits;
	RCoreGetName getName;
	RCoreGetNameDelta getNameDelta;
	RCoreSeekArchBits archBits;
	RCoreConfigGetB cfgGetB;
	RCoreConfigGetI cfgGetI;
	RCoreConfigGet cfgGet;
	RCoreNumGet numGet;
	RCoreIsMapped isMapped;
	RCoreDebugMapsSync syncDebugMaps;
	RCorePJWithEncoding pjWithEncoding;
} RCoreBind;

#ifdef __cplusplus
}
#endif

#endif
