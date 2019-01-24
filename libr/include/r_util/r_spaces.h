#ifndef R_SPACES_H
#define R_SPACES_H

#define R_SPACES_MAX 512

#include "r_util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_space_t {
	char *name;
	RBNode rb;
} RSpace;

typedef enum {
	R_SPACE_EVENT_COUNT = 1,
	R_SPACE_EVENT_RENAME,
	R_SPACE_EVENT_UNSET,
} RSpaceEventType;

typedef struct r_space_event_t {
	union {
		struct {
			const RSpace *space;
		} count;
		struct {
			const RSpace *space;
		} unset;
		struct {
			const RSpace *space;
			const char *oldname;
			const char *newname;
		} rename;
	} data;
	int res;
} RSpaceEvent;

typedef struct r_spaces_t {
	const char *name;
	RSpace *current;
	RBTree spaces;
	RList *spacestack;
	REvent *event;
} RSpaces;

R_API RSpaces *r_spaces_new(const char *name);
R_API bool r_spaces_init(RSpaces *sp, const char *name);
R_API void r_spaces_fini(RSpaces *sp);
R_API void r_spaces_free(RSpaces *sp);
R_API RSpace *r_spaces_get(RSpaces *sp, const char *name);
R_API RSpace *r_spaces_add(RSpaces *sp, const char *name);
R_API RSpace *r_spaces_set(RSpaces *sp, const char *name);
R_API bool r_spaces_unset(RSpaces *sp, const char *name);
R_API bool r_spaces_rename(RSpaces *sp, const char *oname, const char *nname);
R_API int r_spaces_count(RSpaces *sp, const char *name);
R_API bool r_spaces_push(RSpaces *sp, const char *name);
R_API bool r_spaces_pop(RSpaces *sp);

static inline RSpace *r_spaces_current(RSpaces *sp) {
	return sp->current;
}

static inline const char *r_spaces_current_name(RSpaces *sp) {
	return sp->current? sp->current->name: "*";
}

#ifdef __cplusplus
}
#endif

#endif //  R_SPACES_H
