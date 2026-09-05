/* radare - LGPL - Copyright 2024-2026 - pancake */

#include "r_core.h"

#ifndef R2_CORE_PRIV_H
#define R2_CORE_PRIV_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_core_anal_artifact_store_t RCoreAnalArtifactStore;
typedef struct r_core_anal_artifact_comment_t RCoreAnalArtifactComment;
typedef struct r_core_anal_artifact_flag_t RCoreAnalArtifactFlag;

typedef struct r_core_anal_artifact_set_view_t {
	const char *provider_id;
	const char *domain_id;
	ut64 scope_id;
	size_t comment_count;
	size_t flag_count;
	size_t xref_count;
} RCoreAnalArtifactSetView;

typedef struct r_core_priv_t {
	// arch cache
	int old_bits;
	char *old_arch;
	// rtr
	RSocket *s;
	RThread *httpthread;
	RThread *rapthread;
	const char *listenport;
	char *errmsg_tmpfile;
	int errmsg_fd; // -1
	bool regnums;
	bool tags_loaded;
	bool autocomplete_loaded;
	RDebugSession *debug_replay_session;
	HtUP *debug_replay;
	RList *cmdqueue;
	RThreadLock *cmdqueue_lock;
	// disasm cache
	ut64 goaddr;
	char *section;
	RCoreAnalArtifactStore *anal_artifacts;
} RCorePriv;

R_IPI RCoreAnalArtifactStore *r_core_anal_artifact_store_new(void);
R_IPI void r_core_anal_artifact_store_free(RCoreAnalArtifactStore *store);
R_API bool r_core_anal_artifacts_reset(RCore *core);
R_IPI bool r_core_anal_artifacts_drop_scope(RCore *core, ut64 scope_id);
// Internal cross-library ABI. Caller holds core->lock while borrowing views.
R_API size_t r_core_anal_artifact_set_count(const RCore *core);
R_API bool r_core_anal_artifact_set_view(const RCore *core, size_t index, R_OUT RCoreAnalArtifactSetView *view);
R_API bool r_core_anal_artifact_comment_view(const RCore *core, size_t set_index, size_t index, R_OUT RCoreAnalArtifactComment *comment);
R_API bool r_core_anal_artifact_flag_view(const RCore *core, size_t set_index, size_t index, R_OUT RCoreAnalArtifactFlag *flag);
R_API bool r_core_anal_artifact_xref_view(const RCore *core, size_t set_index, size_t index, R_OUT RAnalRef *xref);

R_IPI bool isVisualDisasm(RCore *core);
R_IPI R_OWNED char * R_NULLABLE r_core_get_radare2rc(void);
R_IPI RCmdResult r_cmd_call_result(RCmd *cmd, RCmdContext *parent, const char *input, bool raw);
R_IPI int r_cmd_call_context(RCmd *cmd, RCmdContext *parent, const char *input, bool raw);

#ifdef __cplusplus
}
#endif

#endif
