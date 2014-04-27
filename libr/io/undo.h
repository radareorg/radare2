#ifndef _INCLUDE_UNDO_H_
#define _INCLUDE_UNDO_H_

struct undow_t {
	int set;
	ut64 off;
	ut8 *o;   /* old data */
	ut8 *n;   /* new data */
	int len; /* length */
	struct list_head list;
};

enum { 
	UNDO_WRITE_UNSET = 0,
	UNDO_WRITE_SET   = 1
};

void undo_seek();
void undo_redo();
void undo_reset();
void undo_list();
void undo_push();

void undo_write_set_all(int set);
void undo_write_new(ut64 off, const ut8 *data, int len);
int undo_write_set(int n, int set);
void undo_write_list();
int undo_write_size();

#endif
