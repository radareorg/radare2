#ifndef _INCLUDE_R_CORE_H_
#define _INCLUDE_R_CORE_H_

#include "r_types.h"
#include "r_io.h"
#include "r_fs.h"
#include "r_lib.h"
#include "r_lang.h"
#include "r_asm.h"
#include "r_parse.h"
#include "r_anal.h"
#include "r_cmd.h"
#include "r_cons.h"
#include "r_line.h"
#include "r_print.h"
#include "r_search.h"
#include "r_sign.h"
#include "r_debug.h"
#include "r_flags.h"
#include "r_config.h"
#include "r_bin.h"
#include "r_hash.h"
#include "r_socket.h"

#define R_CORE_CMD_EXIT -2
#define R_CORE_BLOCKSIZE 64
#define R_CORE_BLOCKSIZE_MAX 0x40000 /* 4 MB */

#define R_CORE_ANAL_GRAPHLINES 0x1
#define R_CORE_ANAL_GRAPHBODY  0x2
#define R_CORE_ANAL_GRAPHDIFF  0x4

/* rtr */
#define RTR_PROT_RAP 0
#define RTR_PROT_TCP 1
#define RTR_PROT_UDP 2

#define RTR_RAP_OPEN   0x01
#define RTR_RAP_CMD    0x07
#define RTR_RAP_REPLY  0x80

#define RTR_MAX_HOSTS 255

typedef struct r_core_rtr_host_t {
	int proto;
	char host[512];
	int port;
	char file[1024];
	RSocket *fd;
} RCoreRtrHost;
/* rtr */

typedef struct r_core_file_t {
	char *uri;
	char *filename;
	ut64 seek;
	ut64 size;
	RIOMap *map;
	int rwx;
	int dbg;
	RIODesc *fd;
	RBinObj *obj;
} RCoreFile;

#define R_CORE_ASMSTEPS 128
typedef struct r_core_asmsteps_t {
	ut64 offset;
	int cols;
} RCoreAsmsteps;

typedef struct r_core_t {
	ut64 offset;
	ut32 blocksize;
	ut8 *block;
	ut8 *oobi; /* out of band input ; used to get input from file or multiline */
	int ffio;
	int oobi_len;
	ut8 *yank;
	int yank_len;
	int tmpseek;
	boolt visual;
	ut64 yank_off;
	int interrupted; // XXX IS THIS DUPPED SOMEWHERE?
	/* files */
	RCons *cons;
	RIO *io;
	RCoreFile *file;
	RList *files;
	RNum *num;
	RLib *lib;
	RCmd *cmd;
	RAnal *anal;
	RAsm *assembler;
	RAnalRefline *reflines;
	RAnalRefline *reflines2;
	RParse *parser;
	RPrint *print;
	RBin *bin;
	RLang *lang;
	RDebug *dbg;
	RFlag *flags;
	RConfig *config;
	RSearch *search;
	RSign *sign;
	RFS *fs;
	char *cmdqueue;
	char *lastcmd;
	int cmdrepeat;
	ut64 inc;
	int rtr_n;
	RCoreRtrHost rtr_host[RTR_MAX_HOSTS];
	int curasmstep;
	RCoreAsmsteps asmsteps[R_CORE_ASMSTEPS];
	ut64 asmqjmps[10];
	// visual
	int printidx;
} RCore;

typedef int (*RCoreSearchCallback)(RCore *core, ut64 from, ut8 *buf, int len);

#ifdef R_API
#define r_core_cast(x) (RCore*)(size_t)(x)
R_API RAsmOp *r_core_disassemble (RCore *core, ut64 addr);
R_API int r_core_init(struct r_core_t *core);
R_API struct r_core_t *r_core_new();
R_API struct r_core_t *r_core_free(struct r_core_t *c);
R_API int r_core_config_init(struct r_core_t *core);
R_API int r_core_prompt(RCore *r, int sync);
R_API int r_core_prompt_exec(RCore *r);
R_API void r_core_prompt_loop(RCore *r);
R_API int r_core_cmd(struct r_core_t *r, const char *cmd, int log);
R_API void r_core_cmd_repeat(RCore *core, int next);
R_API char *r_core_editor (RCore *core, const char *str);
// XXX void*?? must be RCore !
R_API int r_core_cmdf(void *user, const char *fmt, ...);
R_API int r_core_cmd0(void *user, const char *cmd);
R_API void r_core_cmd_init(struct r_core_t *core);
R_API char *r_core_cmd_str(struct r_core_t *core, const char *cmd);
R_API int r_core_cmd_file(struct r_core_t *core, const char *file);
R_API int r_core_cmd_command(struct r_core_t *core, const char *command);
R_API boolt r_core_seek(struct r_core_t *core, ut64 addr, boolt rb);
R_API void r_core_seek_previous (RCore *core, const char *type);
R_API void r_core_seek_next (RCore *core, const char *type);
R_API int r_core_seek_align(struct r_core_t *core, ut64 align, int count);
R_API int r_core_block_read(struct r_core_t *core, int next);
R_API int r_core_block_size(struct r_core_t *core, ut32 bsize);
R_API int r_core_read_at(struct r_core_t *core, ut64 addr, ut8 *buf, int size);
R_API int r_core_visual(struct r_core_t *core, const char *input);
R_API int r_core_visual_cmd(struct r_core_t *core, int ch);

R_API int r_core_search_cb(RCore *core, ut64 from, ut64 to, RCoreSearchCallback cb);
R_API int r_core_serve(RCore *core, RIODesc *fd);
R_API void r_core_file_free(RCoreFile *cf);
R_API struct r_core_file_t *r_core_file_open(struct r_core_t *r, const char *file, int mode, ut64 loadaddr);
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
R_API char *r_core_disassemble_instr(RCore *core, ut64 addr, int l);
R_API char *r_core_disassemble_bytes(RCore *core, ut64 addr, int b);

/* anal.c */
R_API int r_core_anal_search(RCore *core, ut64 from, ut64 to, ut64 ref);
R_API void r_core_anal_refs(RCore *core, ut64 addr, int gv);
R_API int r_core_anal_bb(RCore *core, RAnalFcn *fcn, ut64 at, int head);
R_API int r_core_anal_bb_seek(struct r_core_t *core, ut64 addr);
R_API int r_core_anal_fcn(struct r_core_t *core, ut64 at, ut64 from, int reftype, int depth);
R_API int r_core_anal_fcn_list(RCore *core, const char *input, int rad);
R_API int r_core_anal_graph(struct r_core_t *core, ut64 addr, int opts);
R_API int r_core_anal_graph_fcn(struct r_core_t *core, char *input, int opts);
R_API int r_core_anal_ref_list(struct r_core_t *core, int rad);
R_API int r_core_anal_all(RCore *core);

/* asm.c */
typedef struct r_core_asm_hit {
	char *code;
	int len;
	ut64 addr;
} RCoreAsmHit;

R_API RCoreAsmHit *r_core_asm_hit_new();
R_API RList *r_core_asm_hit_list_new();
R_API void r_core_asm_hit_free(void *_hit);
R_API char* r_core_asm_search(RCore *core, const char *input, ut64 from, ut64 to);
R_API RList *r_core_asm_strsearch(RCore *core, const char *input, ut64 from, ut64 to);
R_API RList *r_core_asm_bwdisassemble (RCore *core, ut64 addr, int n, int len);
R_API int r_core_print_disasm(RPrint *p, RCore *core, ut64 addr, ut8 *buf, int len, int l);

R_API int r_core_bin_load(RCore *r, const char *file);
R_API int r_core_hash_load(RCore *r, const char *file);

/* gdiff.c */
R_API int r_core_gdiff(RCore *c, RCore *c2);

R_API int r_core_project_open(RCore *core, const char *file);
R_API int r_core_project_save(RCore *core, const char *file);
R_API char *r_core_project_info(RCore *core, const char *file);
R_API char *r_core_sysenv_begin(RCore *core, const char *cmd);
R_API void r_core_sysenv_end(RCore *core, const char *cmd);
R_API void r_core_sysenv_help();

/* rtr */
R_API void r_core_rtr_help(RCore *core);
R_API void r_core_rtr_pushout(RCore *core, const char *input);
R_API void r_core_rtr_list(RCore *core);
R_API void r_core_rtr_add(RCore *core, const char *input);
R_API void r_core_rtr_remove(RCore *core, const char *input);
R_API void r_core_rtr_session(RCore *core, const char *input);
R_API void r_core_rtr_cmd(RCore *core, const char *input);

R_API void r_core_visual_define (RCore *core);
R_API void r_core_visual_config (RCore *core);
R_API void r_core_visual_mounts (RCore *core);
R_API void r_core_visual_anal (RCore *core);
R_API void r_core_seek_next (RCore *core, const char *type);
R_API void r_core_seek_previous (RCore *core, const char *type);
R_API void r_core_visual_define (RCore *core);
R_API int r_core_visual_trackflags (RCore *core);
R_API void r_core_visual_prompt (RCore *core);
R_API int r_core_search_preludes(RCore *core);
R_API int r_core_search_prelude(RCore *core, ut64 from, ut64 to, const ut8 *buf, int blen, const ut8 *mask, int mlen);

#endif

#endif
