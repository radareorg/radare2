/* radare2 - LGPL - Copyright 2015-2024 - pancake */

#ifndef R2_BIND_H
#define R2_BIND_H

#include <r_types.h>

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
typedef ut64 (*RCoreConfigGetI)(void *core, const char *key);
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

/* Muta/Crypto bindings for hash and encryption */
typedef struct r_muta_t RMuta;
typedef struct r_muta_session_t RMutaSession;
typedef struct r_muta_bind_t RMutaBind;

typedef RMuta *(*RMutaNew)(void);
typedef void (*RMutaFree)(RMuta *cry);
typedef RMutaSession *(*RMutaUse)(RMuta *cry, const char *algo);
typedef bool (*RMutaSessionSetKey)(RMutaSession *cj, const ut8 *key, int keylen, int mode, int direction);
typedef bool (*RMutaSessionSetIV)(RMutaSession *cj, const ut8 *iv, int ivlen);
typedef int (*RMutaSessionEnd)(RMutaSession *cj, const ut8 *buf, int len);
typedef ut8 *(*RMutaSessionGetOutput)(RMutaSession *cj, int *size);
typedef void (*RMutaSessionFree)(RMutaSession *cj);
typedef ut8 *(*RMutaBindHashHmac)(RMutaBind *mb, const char *algo, const ut8 *buf, int buflen, const ut8 *key, int keylen, int *outlen);
typedef ut8 *(*RMutaBindHash)(RMutaBind *mb, const char *algo, const ut8 *buf, int buflen, int *outlen);
typedef bool (*RMutaBindTextOutput)(RMutaBind *mb, const char *algo);

typedef struct r_muta_bind_t {
	RMuta *muta;
	RMutaUse muta_use;
	RMutaSessionSetKey muta_session_set_key;
	RMutaSessionSetIV muta_session_set_iv;
	RMutaSessionEnd muta_session_end;
	RMutaSessionGetOutput muta_session_get_output;
	RMutaSessionFree muta_session_free;
	/* helper methods - parameterized hash helpers */
	RMutaBindHashHmac hash_hmac;
	RMutaBindHash hash;
	RMutaBindTextOutput text_output;
} RMutaBind;

#ifdef __cplusplus
}
#endif

#endif
