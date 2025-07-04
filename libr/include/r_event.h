/* radare - LGPL - Copyright 2018-2025 - pancake */

#ifndef R_EVENT_H
#define R_EVENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sdb/ht_up.h>
#include <r_vec.h>

typedef enum {
	R_EVENT_ALL = 0,

	// stable // in-use

	R_EVENT_FUNCTION_ADDED,
	R_EVENT_FUNCTION_RENAMED,
	R_EVENT_FUNCTION_MODIFIED,
	R_EVENT_FUNCTION_DELETED,
	R_EVENT_FUNCTION_CALLED,
	R_EVENT_FUNCTION_RETURNED,

	R_EVENT_VARIABLE_ADDED,
	R_EVENT_VARIABLE_NAME_CHANGED,
	R_EVENT_VARIABLE_TYPE_CHANGED,
	R_EVENT_VARIABLE_DELETED,

	R_EVENT_META_SET,
	R_EVENT_META_DEL,
	R_EVENT_META_CLEAR,

	R_EVENT_IO_READ,
	R_EVENT_IO_WRITE,
	R_EVENT_IO_OPEN,
	R_EVENT_IO_CLOSE,

	R_EVENT_CLASS_ADDED,
	R_EVENT_CLASS_DELETED,
	R_EVENT_CLASS_RENAME,
	R_EVENT_CLASS_ATTR_SET,
	R_EVENT_CLASS_ATTR_DEL,
	R_EVENT_CLASS_ATTR_RENAME,

	R_EVENT_PLUGIN_LOAD,
	R_EVENT_PLUGIN_UNLOAD,
	// R_EVENT_PLUGIN_INITIALIZED,
	// R_EVENT_PLUGIN_FINALIZED,

	///////////////////////////////////
	///////////////////////////////////
	// unstable // subject-to-change //
	///////////////////////////////////
	///////////////////////////////////

	R_EVENT_ANALYSIS_START,
	R_EVENT_ANALYSIS_END,
	R_EVENT_ANALYSIS_BLOCK_ADDED,
	R_EVENT_ANALYSIS_BLOCK_DELETED,

	// analysis

	R_EVENT_ANALYSIS_RESTART,
	R_EVENT_ANALYSIS_ABORTED, // INTERRUPTED

	// other

	R_EVENT_SEARCH_START,
	R_EVENT_SEARCH_END,
	R_EVENT_SEARCH_HIT,

	R_EVENT_BINARY_START,
	R_EVENT_BINARY_LOADED,

	R_EVENT_FLAGS_ADDED,
	R_EVENT_FLAGS_REMOVED,

	// io-wip

	R_EVENT_MEMORY_READ,
	R_EVENT_MEMORY_WRITE,

	R_EVENT_MEMORY_ALLOCATED,
	R_EVENT_MEMORY_FREED,

	R_EVENT_FILE_OPEN,
	R_EVENT_FILE_CLOSE,

	R_EVENT_NETWORK_CONNECTION_OPEN,
	R_EVENT_NETWORK_CONNECTION_CLOSE,

	R_EVENT_NETWORK_DATA_RECEIVED,
	R_EVENT_NETWORK_DATA_SENT,

	R_EVENT_IO_MAP_ADDED,
	R_EVENT_IO_MAP_REMOVED,
	R_EVENT_MEMORY_ACCESS_VIOLATION,

	// binary

	R_EVENT_SYMBOL_ADDED,
	R_EVENT_SYMBOL_REMOVED,
	R_EVENT_BINARY_RELOCATED,

	// checksums

	R_EVENT_BINARY_HASH_COMPUTED,
	R_EVENT_SIGNATURE_MATCH_FOUND,
	R_EVENT_CRC_CHECKSUM_COMPUTED,
	R_EVENT_CODE_SIGNATURE_VERIFIED,
	R_EVENT_CODE_SIGNATURE_INVALID,
	R_EVENT_BINARY_CHECKSUM_VERIFIED,

	// binary

	R_EVENT_RELOCATIONS_PROCESSED,
	R_EVENT_SECTION_ADDED,

	R_EVENT_BINARY_DUMP_STARTED,
	R_EVENT_BINARY_DUMP_FINISHED,

	R_EVENT_STRING_DETECTED,
	R_EVENT_HEX_PATTERN_MATCHED,

	R_EVENT_DECOMPILATION_STARTED,
	R_EVENT_DECOMPILATION_ENDED,

	R_EVENT_INLINE_PATCH_ADDED,
	R_EVENT_INLINE_PATCH_REMOVED,

	R_EVENT_SYMBOL_RESOLVED,
	R_EVENT_SYMBOL_UNRESOLVED,

	R_EVENT_SECTION_MAPPED,
	R_EVENT_SECTION_UNMAPPED,

	R_EVENT_FILE_RELOCATED,

	// debugger events

	R_EVENT_DEBUG_PROCESS_FINISHED,
	R_EVENT_DEBUG_START,
	R_EVENT_DEBUG_STOP,
	R_EVENT_DEBUG_STEP,
	R_EVENT_DEBUG_BREAKPOINT_HIT,
	R_EVENT_DEBUG_EXCEPTION,

	R_EVENT_CHILD_SYSCALL,
	R_EVENT_CHILD_SIGNAL_RECEIVED,

	R_EVENT_TRACE_START,
	R_EVENT_TRACE_END,
	R_EVENT_TRACE_POINT_HIT,

	R_EVENT_BREAKPOINT_ADDED,
	R_EVENT_BREAKPOINT_REMOVED,

	R_EVENT_WATCHPOINT_ADDED,
	R_EVENT_WATCHPOINT_REMOVED,

	R_EVENT_STEP_OVER,
	R_EVENT_STEP_IN,
	R_EVENT_STEP_OUT,
	R_EVENT_EXECUTION_PAUSED,
	R_EVENT_EXECUTION_RESUMED,

	R_EVENT_PROCESS_START,
	R_EVENT_PROCESS_EXIT,

	R_EVENT_THREAD_START,
	R_EVENT_THREAD_STOP,

	R_EVENT_MODULE_LOADED,
	R_EVENT_MODULE_UNLOADED,

	R_EVENT_EXCEPTION_RAISED,
	R_EVENT_EXCEPTION_HANDLED,

	R_EVENT_HARDWARE_BREAKPOINT_SET,
	R_EVENT_HARDWARE_BREAKPOINT_REMOVED,

	R_EVENT_WATCHPOINT_HIT,
	R_EVENT_WATCHPOINT_IGNORED,
	R_EVENT_EMULATION_STARTED,
	R_EVENT_EMULATION_STOPPED,
	R_EVENT_CACHE_HIT,
	R_EVENT_CACHE_MISS,
	R_EVENT_INTERRUPT_RAISED,
	R_EVENT_INTERRUPT_HANDLED,

	R_EVENT_GADGET_FOUND,
	R_EVENT_GADGET_EXECUTED,

	R_EVENT_REGISTER_STATE_SAVED,
	R_EVENT_REGISTER_STATE_RESTORED,

	R_EVENT_CHILD_REGISTERS_UPDATED,
	R_EVENT_DEBUG_REGISTER_READ,
	R_EVENT_DEBUG_REGISTER_WRITE,

	R_EVENT_LAST,
} REventType;

typedef struct r_event_function_t {
	ut64 addr;
	void *fcn;
} REventFunction;

typedef struct r_event_variable_t {
	const char *name;
	const char *type;
	void *fcn;
	void *var;
} REventVariable;

typedef struct r_event_meta_t {
	int type;
	ut64 addr;
	const char *string;
} REventMeta;

typedef struct r_event_class_t {
	const char *name;
} REventClass;

typedef struct r_event_class_rename_t {
	const char *name_old;
	const char *name_new;
} REventClassRename;

typedef struct r_event_class_attr_t {
	const char *class_name;
	int attr_type; // RAnalClassAttrType
	const char *attr_id;
} REventClassAttr;

typedef struct r_event_class_attr_set_t {
	REventClassAttr attr;
	const char *content;
} REventClassAttrSet;

typedef struct r_event_class_attr_rename_t {
	REventClassAttr attr;
	const char *attr_id_new;
} REventClassAttrRename;

typedef struct r_event_debug_process_finished_t {
	int pid;
} REventDebugProcessFinished;

typedef struct r_event_plugin_t {
	const char *name;
	int type;
} REventPlugin;

typedef struct r_event_io_write_t {
	ut64 addr;
	const ut8 *buf;
	int len;
} REventIOWrite;

typedef struct r_event_msg_t {
	ut32 type;
	void *data;
	size_t data_len;
} REventMessage;

typedef struct r_event_t REvent;
typedef void (*REventCallback)(REvent *ev, int type, void *user, void *data);
typedef struct r_event_hook_t {
	ut32 event_type;
	REventCallback cb;
	void *user;
} REventHook;

// R_VEC_TYPE(RVecREventCallback, REventCallback);
R_VEC_TYPE(RVecREventHook, REventHook);

typedef struct r_event_t {
	void *user;
	RVecREventHook all_events;
	RVecREventHook known_events[R_EVENT_LAST];
	HtUP *other_events; // when event id > R_EVENT_LAST
	RThreadLock *lock;
} REvent;

typedef struct r_event_callback_handle_t {
	int handle;
	int type;
} REventCallbackHandle;

R_API REvent *r_event_new(void *user);
R_API void r_event_free(REvent *ev);
R_API bool r_event_hook(REvent *ev, ut32 type, REventCallback cb, void *data);
R_API bool r_event_unhook(REvent * R_NULLABLE ev, ut32 event_hook, REventCallback cb);
R_API void r_event_send(REvent *ev, ut32 type, void *data);

#ifdef __cplusplus
}
#endif

#endif
