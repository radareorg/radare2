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
#include "r_search.h"
#include "r_sign.h"
#include "r_debug.h"
#include "r_flags.h"
#include "r_config.h"
#include "r_bin.h"

#define R_CORE_CMD_EXIT -2
#define R_CORE_BLOCKSIZE 64
#define R_CORE_BLOCKSIZE_MAX 0x40000 /* 4 MB */

#define R_CORE_ANAL_GRAPHLINES 0x1
#define R_CORE_ANAL_GRAPHBODY  0x2
#define R_CORE_ANAL_GRAPHDIFF  0x4

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
	RCons *cons;
	RIO *io;
	RCoreFile *file;
	struct list_head files;
	RNum *num;
	RLib *lib;
	RCmd *cmd;
	RAnal *anal;
	RSyscall *syscall;
	RAsm *assembler;
	RAnalRefline *reflines;
	RParse *parser;
	RPrint *print;
	RBin *bin;
	RMeta *meta;
	RLang *lang;
	RDebug *dbg;
	RFlag *flags;
	RConfig *config;
	RSearch *search;
	RSign *sign;
} RCore;

#ifdef R_API
#define r_core_cast(x) (RCore*)(size_t)(x)
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
R_API int r_core_seek_align(struct r_core_t *core, ut64 align, int count);
R_API int r_core_block_read(struct r_core_t *core, int next);
R_API int r_core_block_size(struct r_core_t *core, ut32 bsize);
R_API int r_core_read_at(struct r_core_t *core, ut64 addr, ut8 *buf, int size);
R_API int r_core_cmd_init(struct r_core_t *core); // MUST BE STATIC
R_API int r_core_visual(struct r_core_t *core, const char *input);
R_API int r_core_visual_cmd(struct r_core_t *core, int ch);

R_API struct r_core_file_t *r_core_file_open(struct r_core_t *r, const char *file, int mode);
R_API struct r_core_file_t *r_core_file_get_fd(struct r_core_t *core, int fd);
R_API int r_core_file_close(struct r_core_t *r, RCoreFile *fh);
R_API int r_core_file_close_fd(struct r_core_t *core, int fd);
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
R_API char *r_core_op_str(RCore *core, ut64 addr);
R_API RAnalOp *r_core_op_anal(RCore *core, ut64 addr);

/* anal.c */
R_API void r_core_anal_refs(RCore *core, ut64 addr, int gv);
R_API int r_core_anal_bb(RCore *core, ut64 at, int depth, int head);
R_API int r_core_anal_bb_list(struct r_core_t *core, int rad);
R_API int r_core_anal_bb_seek(struct r_core_t *core, ut64 addr);
R_API int r_core_anal_fcn(struct r_core_t *core, ut64 at, ut64 from, int depth);
R_API int r_core_anal_fcn_list(struct r_core_t *core, int rad);
R_API int r_core_anal_graph(struct r_core_t *core, ut64 addr, int opts);
R_API int r_core_anal_graph_fcn(struct r_core_t *core, char *input, int opts);

R_API int r_core_project_open(RCore *core, const char *file);
R_API int r_core_project_save(RCore *core, const char *file);
#endif

#endif
