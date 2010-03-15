#ifndef _INCLUDE_R_CORE_H_
#define _INCLUDE_R_CORE_H_

#include "r_types.h"
#include "r_io.h"
#include "r_lib.h"
#include "r_lang.h"
#include "r_asm.h"
#include "r_parse.h"
#include "r_anal.h"
#include "r_cmd.h"
#include "r_meta.h"
#include "r_cons.h"
#include "r_line.h"
#include "r_print.h"
#include "r_macro.h"
#include "r_search.h"
#include "r_debug.h"
#include "r_flags.h"
#include "r_config.h"
#include "r_bin.h"

#define R_CORE_CMD_EXIT -2
#define R_CORE_BLOCKSIZE 64
#define R_CORE_BLOCKSIZE_MAX 0x40000 /* 4 MB */

typedef struct r_core_file_t {
	char *uri;
	char *filename;
	ut64 seek;
	ut64 size;
	int rwx;
	int fd;
	int dbg;
	struct list_head list;
} RCoreFile;

typedef struct r_core_t {
	ut64 offset;
	ut32 blocksize;
	ut8 *block;
	ut8 *oobi; /* out of band input ; used to get input from file or multiline */
	int ffio;
	int oobi_len;
	ut8 *yank;
	int yank_len;
	ut64 yank_off;
	int interrupted; // XXX IS THIS DUPPED SOMEWHERE?
	/* files */
	struct r_io_t io;
	struct r_core_file_t *file;
	struct list_head files;
	struct r_num_t num;
	struct r_lib_t lib;
	struct r_cmd_t cmd;
	struct r_anal_t anal;
	RSyscall syscall;
	RAsm assembler;
	struct r_parse_t parser;
	struct r_print_t print;
	struct r_bin_t bin;
	struct r_meta_t meta;
	struct r_lang_t lang;
	struct r_debug_t dbg;
	struct r_flag_t flags;
	struct r_macro_t macro;
	struct r_config_t config;
	struct r_search_t *search;
} RCore;

#ifdef R_API
R_API int r_core_init(struct r_core_t *core);
R_API struct r_core_t *r_core_new();
R_API struct r_core_t *r_core_free(struct r_core_t *c);
R_API int r_core_config_init(struct r_core_t *core);
R_API int r_core_prompt(struct r_core_t *r);
R_API int r_core_cmd(struct r_core_t *r, const char *cmd, int log);
R_API int r_core_cmdf(void *user, const char *fmt, ...);
R_API int r_core_cmd0(void *user, const char *cmd);
R_API int r_core_cmd_init(struct r_core_t *core);
R_API char *r_core_cmd_str(struct r_core_t *core, const char *cmd);
R_API int r_core_cmd_file(struct r_core_t *core, const char *file);
R_API int r_core_cmd_command(struct r_core_t *core, const char *command);
R_API int r_core_seek(struct r_core_t *core, ut64 addr, int rb);
R_API int r_core_seek_align(struct r_core_t *core, ut64 align, int times);
R_API int r_core_block_read(struct r_core_t *core, int next);
R_API int r_core_block_size(struct r_core_t *core, ut32 bsize);
R_API int r_core_read_at(struct r_core_t *core, ut64 addr, ut8 *buf, int size);
R_API int r_core_cmd_init(struct r_core_t *core);
R_API int r_core_visual(struct r_core_t *core, const char *input);
R_API int r_core_visual_cmd(struct r_core_t *core, int ch);

R_API struct r_core_file_t *r_core_file_open(struct r_core_t *r, const char *file, int mode);
R_API struct r_core_file_t *r_core_file_get_fd(struct r_core_t *core, int fd);
R_API int r_core_file_close(struct r_core_t *r, struct r_core_file_t *fh);
R_API int r_core_file_list(struct r_core_t *core);
R_API int r_core_seek_delta(struct r_core_t *core, st64 addr);
R_API int r_core_write_at(struct r_core_t *core, ut64 addr, const ut8 *buf, int size);
R_API int r_core_write_op(struct r_core_t *core, const char *arg, char op);

R_API int r_core_yank(struct r_core_t *core, ut64 addr, int len);
R_API int r_core_yank_paste(struct r_core_t *core, ut64 addr, int len);

R_API int r_core_loadlibs(struct r_core_t *core);
R_API int r_core_cmd_buffer(void *user, const char *buf);
R_API int r_core_cmdf(void *user, const char *fmt, ...);
R_API int r_core_cmd0(void *user, const char *cmd);
R_API char *r_core_cmd_str(struct r_core_t *core, const char *cmd);
R_API int r_core_cmd_foreach(struct r_core_t *core, const char *cmd, char *each);

/* anal.c */
R_API int r_core_anal_bb(struct r_core_t *core, ut64 at, int depth);
R_API int r_core_anal_bb_clean(struct r_core_t *core, ut64 addr);
R_API int r_core_anal_bb_add(struct r_core_t *core, ut64 addr, ut64 size, ut64 jump, ut64 fail);
R_API int r_core_anal_bb_list(struct r_core_t *core, int rad);
R_API int r_core_anal_bb_seek(struct r_core_t *core, ut64 addr);
R_API int r_core_anal_fcn(struct r_core_t *core, ut64 at, ut64 from, int depth);
R_API int r_core_anal_fcn_add(struct r_core_t *core, ut64 addr, ut64 size, const char *name);
R_API int r_core_anal_fcn_list(struct r_core_t *core, int rad);
R_API int r_core_anal_fcn_clean(struct r_core_t *core, ut64 addr);
R_API int r_core_anal_graph(struct r_core_t *core, ut64 addr, int lines);
R_API int r_core_anal_graph_fcn(struct r_core_t *core, char *input, int lines);
#endif

#endif
