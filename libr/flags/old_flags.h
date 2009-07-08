#ifndef _INCLUDE_FLAGS_H_
#define _INCLUDE_FLAGS_H_

#include "main.h"
#include "radare.h"
#include "list.h"
#define FLAG_BSIZE 40

extern char **environ;

/* radare flag */
typedef struct {
	char name[FLAG_BSIZE];
	ut64 offset;
	ut64 length;
	print_fmt_t format;
	int space;
	const char *cmd;
	unsigned char data[FLAG_BSIZE]; // only take a minor part of the data
	struct list_head list;
} flag_t;

extern int flag_space_idx;
extern int flag_space_idx2;
#define flag_space_push() flag_space_idx2 = flag_space_idx;
#define flag_space_pop() flag_space_idx = flag_space_idx2;
void flag_init();
void flag_array_clear(const char *name);
void flag_clear(const char *name);
void flag_clear_by_addr(ut64 addr);
void flag_grep_np(const char *str, ut64 addr, int next);
ut64 flag_get_addr(const char *name);
flag_t *flag_by_offset(ut64 offset);
flag_t *flag_get(const char *name);
flag_t *flag_get_i(int id);
flag_t *flag_get_next();
flag_t *flag_get_reset();
int flags_between(ut64 from, ut64 to);
int flag_is_empty(flag_t *flag);
const char *flag_name_by_offset(ut64 offset);
int flag_set(const char *name, ut64 addr, int dup);
int flag_set_undef(const char *name, ut64 addr, int dup);
void print_flag_offset(ut64 seek);
void flags_setenv();
void flag_list(char *arg);
void flag_help();
int flag_rename_str(char *text);
int string_flag_offset(char *buf, ut64 seek, int idx);
int flag_interpolation(const char *from, const char *to);
struct list_head flags;
void flag_grep(const char *grep);
void flag_cmd(const char *text);
void flag_space_set(const char *name);
void flag_space_cleanup();
void flag_space(const char *name);
void flag_space_list();
void flag_space_init();
void flag_space_remove(const char *name);
int flag_filter_name(char *name);
void flag_from(const char *str);
void flag_space_move(const char *name); 
const char *flag_get_here_filter(ut64 at, const char *str);
const const char *flag_space_get(int idx);
ut64 flag_delta_between(ut64 from, ut64 to);

#endif
