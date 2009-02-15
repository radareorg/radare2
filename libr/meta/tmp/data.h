#ifndef _INCLUDE_DATA_H_
#define _INCLUDE_DATA_H_

extern struct reflines_t *reflines;
//extern struct list_head data;
//extern struct list_head comments;
extern struct list_head traces;

struct data_t {
	u64 from;
	u64 to;
	int type;
	int times;
	u64 size;
	char arg[128];
	struct list_head list;
};

struct var_type_t {
	char name[128];
	char fmt[128];
	unsigned int size;
	struct list_head list;
};

struct comment_t {
	u64 offset;
	const char *comment;
	struct list_head list;
};

struct xrefs_t {
	u64 addr;  /* offset of the cross reference */
	u64 from;  /* where the code/data is referenced */
	int type;  /* 0 = code, 1 = data, -1 = unknown */
	struct list_head list;
};

struct reflines_t {
	u64 from;
	u64 to;
	int index;
	struct list_head list;
};

int data_set_len(u64 off, u64 len);
void data_info();
int data_set(u64 off, int type);
struct data_t *data_add_arg(u64 off, int type, const char *arg);
struct data_t *data_add(u64 off, int type);
u64 data_seek_to(u64 offset, int type, int idx);
struct data_t *data_get(u64 offset);
struct data_t *data_get_range(u64 offset);
struct data_t *data_get_between(u64 from, u64 to);
int data_type_range(u64 offset);
int data_type(u64 offset);
int data_end(u64 offset);
int data_size(u64 offset);
u64 data_prev(u64 off, int type);
int data_list();
int data_xrefs_print(u64 addr, int type);
int data_xrefs_add(u64 addr, u64 from, int type);
int data_xrefs_at(u64 addr);
void data_xrefs_del(u64 addr, u64 from, int data /* data or code */);
void data_comment_del(u64 offset, const char *str);
void data_comment_add(u64 offset, const char *str);
void data_comment_list();
void data_xrefs_here(u64 addr);
void data_xrefs_list();
char *data_comment_get(u64 offset, int lines);
void data_comment_init(int new);
void data_reflines_init();
int data_printd(int delta);
const char *data_var_type_format(const char *datatype);
void data_del(u64 addr, int type,int len/* data or code */);

#endif
