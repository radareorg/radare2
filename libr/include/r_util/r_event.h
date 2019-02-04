/* radare - LGPL - Copyright 2018 - pancake */

#ifndef R_EVENT_H
#define R_EVENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sdb/ht_up.h>
#include <r_vector.h>

typedef struct r_event_t {
	void *user;
	bool incall;
	HtUP *callbacks;
	RVector *all_callbacks;
	int next_handle;
} REvent;

typedef struct r_event_callback_handle_t {
	int handle;
	int type;
} REventCallbackHandle;

typedef void (*REventCallback)(REvent *ev, int type, void *user, void *data);

typedef enum {
	R_EVENT_ALL = 0,
	R_EVENT_META_SET,
	R_EVENT_META_DEL,
	R_EVENT_META_CLEAR,
	R_EVENT_MAX,
} REventType;

typedef struct r_event_meta_t {
	int type;
	ut64 addr;
	const char *string;
} REventMeta;


R_API REvent *r_event_new(void *user);
R_API void r_event_free(REvent *ev);
R_API REventCallbackHandle r_event_hook(REvent *ev, int type, REventCallback cb, void *user);
R_API void r_event_unhook(REvent *ev, REventCallbackHandle handle);
R_API void r_event_send(REvent *ev, int type, void *data);

#ifdef __cplusplus
}
#endif

#endif
