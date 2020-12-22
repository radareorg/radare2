#ifndef R_SPACES_H
#define R_SPACES_H

#define R_SPACES_MAX 512

#include "r_util.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * RSpaces represents a set of Spaces.
 * A Space is used to group similar objects and it can have a name. Name
 * "*"/""/NULL is reserved to indicate "all spaces".
 *
 * You can have groups of "meta" (e.g. bin meta, format meta, etc.), groups of
 * zign info, groups of flags, etc.
 *
 * It is possible to hook into the RSpaces functions by using REvent.
 * R_SPACE_EVENT_COUNT: called when you need to count how many elements there are in a given RSpace
 * R_SPACE_EVENT_RENAME: called when renaming a RSpace with an oldname to a newname
 * R_SPACE_EVENT_UNSET: called when deleting a RSpace with a given name
 */

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

// Create a new RSpaces with the given name
R_API RSpaces *r_spaces_new(const char *name);
// Initialize an existing RSpaces with the given name
R_API bool r_spaces_init(RSpaces *sp, const char *name);
// Finalize an existing RSpaces
R_API void r_spaces_fini(RSpaces *sp);
// Finalize and free an existing RSpaces
R_API void r_spaces_free(RSpaces *sp);
// Delete all spaces
R_API void r_spaces_purge(RSpaces *sp);
// Get the RSpace with the given name
R_API RSpace *r_spaces_get(RSpaces *sp, const char *name);
// Add a new RSpace if one does not already exist, otherwise return the existing one
R_API RSpace *r_spaces_add(RSpaces *sp, const char *name);
// Add and select a new RSpace if one does not already exist, otherwise return and select the existing one
R_API RSpace *r_spaces_set(RSpaces *sp, const char *name);
// Remove the RSpace with the given name or all of them if name is NULL
R_API bool r_spaces_unset(RSpaces *sp, const char *name);
// Change the name of RSpace with oname to nname
R_API bool r_spaces_rename(RSpaces *sp, const char *oname, const char *nname);
// Count the elements that belong to the RSpace with the given name
R_API int r_spaces_count(RSpaces *sp, const char *name);
// Add/Select the RSpace with the given name and save the current one in the history
R_API bool r_spaces_push(RSpaces *sp, const char *name);
// Select the RSpace that was set before the current one
R_API bool r_spaces_pop(RSpaces *sp);

static inline RSpace *r_spaces_current(RSpaces *sp) {
	return sp->current;
}

static inline const char *r_spaces_current_name(RSpaces *sp) {
	return sp->current? sp->current->name: "*";
}

static inline bool r_spaces_is_empty(RSpaces *sp) {
	RBIter it = r_rbtree_first (sp->spaces);
	return it.len == 0;
}

typedef RBIter RSpaceIter;
#define r_spaces_foreach(sp, it, s) \
	r_rbtree_foreach ((sp)->spaces, (it), (s), RSpace, rb)

#ifdef __cplusplus
}
#endif

#endif //  R_SPACES_H
