/* radare - LGPL - Copyright 2018 - pancake */

#ifndef R_EVENT_H
#define R_EVENT_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_event_t {
	void *user;
	RList *callbacks;
} REvent;

typedef enum {
	R_EVENT_META_SET = 0,
} REventType;

typedef struct r_event_meta_t {
	int type;
	ut64 addr;
	const char *string;
} REventMeta;

typedef void (*REventCallback)(REvent *ev, REventType type, void *data);

R_API REvent *r_event_new(void *user);
R_API void r_event_free(REvent *ev);
R_API void r_event_hook(REvent *ev, REventCallback cb);
R_API void r_event_unhook(REvent *ev, REventCallback cb);
R_API void r_event_send(REvent *ev, int type, void *data);

#endif
