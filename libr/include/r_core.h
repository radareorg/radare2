/* radare - LGPL - Copyright 2009-2014 - pancake */

#ifndef R2_CORE_H
#define R2_CORE_H


#include "r_types.h"
#include "r_magic.h"
#include "r_io.h"
#include "r_fs.h"
#include "r_lib.h"
#include "r_diff.h"
#include "r_egg.h"
#include "r_lang.h"
#include "r_asm.h"
#include "r_parse.h"
#include "r_anal.h"
#include "r_cmd.h"
#include "r_cons.h"
#include "r_print.h"
#include "r_search.h"
#include "r_sign.h"
#include "r_debug.h"
#include "r_flags.h"
#include "r_config.h"
#include "r_bin.h"
#include "r_hash.h"
#include "r_socket.h"
#include "r_util.h"
#include "r_crypto.h"
#include "r_bind.h"

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_core);

#define R_CORE_CMD_EXIT -2
#define R_CORE_BLOCKSIZE 0x100
#define R_CORE_BLOCKSIZE_MAX 0x3200000 /* 32MB */

#define R_CORE_ANAL_GRAPHLINES 1
#define R_CORE_ANAL_GRAPHBODY  2
#define R_CORE_ANAL_GRAPHDIFF  4
#define R_CORE_ANAL_JSON       8
#define R_CORE_ANAL_KEYVALUE  16

/* rtr */
#define RTR_PROT_RAP 0
#define RTR_PROT_TCP 1
#define RTR_PROT_UDP 2
#define RTR_PROT_HTTP 3

#define RTR_RAP_OPEN   0x01
#define RTR_RAP_CMD    0x07
#define RTR_RAP_REPLY  0x80

#define RTR_MAX_HOSTS 255

#define R_CORE_CMD_DEPTH 10

typedef struct r_core_rtr_host_t {
	int proto;
	char host[512];
	int port;
	char file[1024];
	RSocket *fd;
} RCoreRtrHost;

typedef struct r_core_log_t {
	int first;
	int last;
	RStrpool *sp;
} RCoreLog;

typedef struct r_core_file_t {
	RIOMap *map;
	int dbg;
	RIODesc *desc;
	RBinBind binb;
	const struct r_core_t *core;
	ut8 alive;
} RCoreFile;

#define R_CORE_ASMSTEPS 128
typedef struct r_core_asmsteps_t {
	ut64 offset;
	int cols;
} RCoreAsmsteps;

typedef struct r_core_t {
	RBin *bin;
	RConfig *config;
	ut64 offset;
	ut32 blocksize;
	ut32 blocksize_max;
	ut8 *block;
	ut8 *oobi; /* out of band input ; used for multiline or file input */
	int oobi_len;
	RBuffer *yank_buf;
	int tmpseek;
	boolt vmode;
	int interrupted; // XXX IS THIS DUPPED SOMEWHERE?
	/* files */
	RCons *cons;
	RIO *io;
	RCoreFile *file;
	RList *files;
	RNum *num;
	RLib *lib;
	RCmd *rcmd;
	RAnal *anal;
	RAsm *assembler;
	RAnalRefline *reflines;
	RAnalRefline *reflines2;
	RParse *parser;
	RPrint *print;
	RLang *lang;
	RDebug *dbg;
	RFlag *flags;
	RSearch *search;
	RIOSection *section;
	RSign *sign;
	RFS *fs;
	REgg *egg;
	RCoreLog *log;
	char *cmdqueue;
	char *lastcmd;
	int cmdrepeat;
	ut64 inc;
	ut64 screen_bounds;
	int rtr_n;
	RCoreRtrHost rtr_host[RTR_MAX_HOSTS];
	int curasmstep;
	RCoreAsmsteps asmsteps[R_CORE_ASMSTEPS];
	ut64 asmqjmps[10];
	// visual
	int http_up;
	int printidx;
	int utf8;
	int vseek;
	int zerosep;
	int in_search;
	RList *watchers;
	RList *scriptstack;
	RList *tasks;
	int cmd_depth;
	ut8 switch_file_view;
	Sdb *sdb;
	int incomment;
} RCore;

R_API int r_core_bind(RCore *core, RCoreBind *bnd);

typedef struct r_core_cmpwatch_t {
	ut64 addr;
	int size;
	char cmd[32];
	ut8 *odata;
	ut8 *ndata;
} RCoreCmpWatcher;

typedef int (*RCoreSearchCallback)(RCore *core, ut64 from, ut8 *buf, int len);

#ifdef R_API
//#define r_core_ncast(x) (RCore*)(size_t)(x)
R_API RCons *r_core_get_cons (RCore *core);
R_API RBin *r_core_get_bin (RCore *core);
R_API RConfig *r_core_get_config (RCore *core);
R_API RAsmOp *r_core_disassemble (RCore *core, ut64 addr);
R_API int r_core_init(RCore *core);
R_API RCore *r_core_new();
R_API RCore *r_core_free(RCore *core);
R_API RCore *r_core_fini(RCore *c);
R_API RCore *r_core_ncast(ut64 p);
R_API RCore *r_core_cast(void *p);
R_API int r_core_config_init(RCore *core);
R_API int r_core_prompt(RCore *core, int sync);
R_API int r_core_prompt_exec(RCore *core);
R_API void r_core_prompt_loop(RCore *core);
R_API int r_core_cmd(RCore *core, const char *cmd, int log);
R_API void r_core_cmd_repeat(RCore *core, int next);
R_API char *r_core_editor (const RCore *core, const char *file, const char *str);
R_API int r_core_fgets(char *buf, int len);
// FIXME: change (void *user) to (RCore *core)
R_API int r_core_cmdf(void *user, const char *fmt, ...);
R_API int r_core_flush(void *user, const char *cmd);
R_API int r_core_cmd0(void *user, const char *cmd);
R_API void r_core_cmd_flush (RCore *core);
R_API void r_core_cmd_init(RCore *core);
R_API int r_core_cmd_pipe(RCore *core, char *radare_cmd, char *shell_cmd);
R_API char *r_core_cmd_str(RCore *core, const char *cmd);
R_API char *r_core_cmd_strf(RCore *core, const char *fmt, ...);
R_API char *r_core_cmd_str_pipe(RCore *core, const char *cmd);
R_API int r_core_cmd_file(RCore *core, const char *file);
R_API int r_core_cmd_lines(RCore *core, const char *lines);
R_API int r_core_cmd_command(RCore *core, const char *command);
R_API int r_core_run_script (RCore *core, const char *file);
R_API boolt r_core_seek(RCore *core, ut64 addr, boolt rb);
R_API int r_core_seek_base (RCore *core, const char *hex);
R_API void r_core_seek_previous (RCore *core, const char *type);
R_API void r_core_seek_next (RCore *core, const char *type);
R_API int r_core_seek_align(RCore *core, ut64 align, int count);
R_API int r_core_seek_archbits (RCore *core, ut64 addr);
R_API int r_core_block_read(RCore *core, int next);
R_API int r_core_block_size(RCore *core, int bsize);
R_API int r_core_read_at(RCore *core, ut64 addr, ut8 *buf, int size);
R_API int r_core_is_valid_offset (RCore *core, ut64 offset);
R_API int r_core_shift_block(RCore *core, ut64 addr, ut64 b_size, st64 dist);
R_API void r_core_visual_prompt_input (RCore *core);
R_API int r_core_visual(RCore *core, const char *input);
R_API int r_core_visual_graph(RCore *core, RAnalFunction *_fcn);
R_API int r_core_visual_cmd(RCore *core, int ch);
R_API void r_core_visual_seek_animation (RCore *core, ut64 addr);
R_API void r_core_visual_asm(RCore *core, ut64 addr);
R_API void r_core_visual_colors(RCore *core);
R_API int r_core_visual_xrefs_x (RCore *core);
R_API int r_core_visual_xrefs_X (RCore *core);

R_API int r_core_search_cb(RCore *core, ut64 from, ut64 to, RCoreSearchCallback cb);
R_API int r_core_serve(RCore *core, RIODesc *fd);
R_API int r_core_file_reopen(RCore *core, const char *args, int perm, int binload);
R_API RCoreFile * r_core_file_find_by_fd(RCore* core, ut64 fd);
R_API RCoreFile * r_core_file_find_by_name (RCore * core, const char * name);
R_API RCoreFile * r_core_file_cur (RCore *r);
R_API int r_core_file_set_by_fd(RCore *core, ut64 fd);
R_API int r_core_file_set_by_name(RCore *core, const char * name);
R_API int r_core_file_set_by_file (RCore * core, RCoreFile *cf);
R_API int r_core_setup_debugger (RCore *r, const char *debugbackend);

R_API int r_core_files_free(const RCore *core, RCoreFile *cf);
R_API void r_core_file_free(RCoreFile *cf);
R_API RCoreFile *r_core_file_open(RCore *core, const char *file, int flags, ut64 loadaddr);
R_API RCoreFile *r_core_file_open_many(RCore *r, const char *file, int flags, ut64 loadaddr);
R_API RCoreFile *r_core_file_get_by_fd(RCore *core, int fd);
R_API int r_core_file_close(RCore *core, RCoreFile *fh);
R_API int r_core_file_close_fd(RCore *core, int fd);
R_API int r_core_file_list(RCore *core, int mode);
R_API int r_core_file_binlist(RCore *core);
R_API int r_core_file_bin_raise(RCore *core, ut32 num);
R_API int r_core_seek_delta(RCore *core, st64 addr);
R_API int r_core_extend_at(RCore *core, ut64 addr, int size);
R_API int r_core_write_at(RCore *core, ut64 addr, const ut8 *buf, int size);
R_API int r_core_write_op(RCore *core, const char *arg, char op);
R_API int r_core_set_file_by_fd (RCore * core, ut64 bin_fd);
R_API int r_core_set_file_by_name (RBin * bin, const char * name);
R_API RBinFile * r_core_bin_cur (RCore *core);
R_API ut32 r_core_file_cur_fd (RCore *core);

#define R_CORE_FOREIGN_ADDR -1
R_API int r_core_yank(RCore *core, ut64 addr, int len);
R_API int r_core_yank_string(RCore *core, ut64 addr, int maxlen);
R_API int r_core_yank_paste(RCore *core, ut64 addr, int len);
R_API int r_core_yank_set (RCore *core, ut64 addr, const ut8 *buf, ut32 len);  // set yank buffer bytes
R_API int r_core_yank_set_str (RCore *core, ut64 addr, const char *buf, ut32 len); // Null terminate the bytes
R_API int r_core_yank_to(RCore *core, const char *arg);
R_API int r_core_yank_dump (RCore *core, ut64 pos);
R_API int r_core_yank_hexdump (RCore *core, ut64 pos);
R_API int r_core_yank_cat (RCore *core, ut64 pos);
R_API int r_core_yank_hud_file (RCore *core, const char *input);
R_API int r_core_yank_hud_path (RCore *core, const char *input, int dir);
R_API int r_core_yank_file_ex (RCore *core, const char *input);
R_API int r_core_yank_file_all (RCore *core, const char *input);

#define R_CORE_LOADLIBS_ENV 1
#define R_CORE_LOADLIBS_HOME 2
#define R_CORE_LOADLIBS_SYSTEM 4
#define R_CORE_LOADLIBS_CONFIG 8
#define R_CORE_LOADLIBS_ALL -1

R_API void r_core_loadlibs_init(RCore *core);
R_API int r_core_loadlibs(RCore *core, int where, const char *path);
// FIXME: change (void *user) -> (RCore *core)
R_API int r_core_cmd_buffer(void *user, const char *buf);
R_API int r_core_cmdf(void *user, const char *fmt, ...);
R_API int r_core_cmd0(void *user, const char *cmd);
R_API char *r_core_cmd_str(RCore *core, const char *cmd);
R_API int r_core_cmd_foreach(RCore *core, const char *cmd, char *each);
R_API char *r_core_op_str(RCore *core, ut64 addr);
R_API RAnalOp *r_core_op_anal(RCore *core, ut64 addr);
R_API char *r_core_disassemble_instr(RCore *core, ut64 addr, int l);
R_API char *r_core_disassemble_bytes(RCore *core, ut64 addr, int b);

/* anal.c */
R_API RAnalOp* r_core_anal_op(RCore *core, ut64 addr);
R_API void r_core_anal_fcn_merge (RCore *core, ut64 addr, ut64 addr2);
R_API const char *r_core_anal_optype_colorfor(RCore *core, ut64 addr);
R_API ut64 r_core_anal_address (RCore *core, ut64 addr);
R_API void r_core_anal_undefine (RCore *core, ut64 off);
R_API void r_core_anal_hint_list (RAnal *a, int mode);
R_API int r_core_anal_search(RCore *core, ut64 from, ut64 to, ut64 ref);
R_API int r_core_anal_data (RCore *core, ut64 addr, int count, int depth);
R_API void r_core_anal_refs(RCore *core, ut64 addr, int gv);
R_API int r_core_anal_bb(RCore *core, RAnalFunction *fcn, ut64 at, int head);
R_API int r_core_anal_bb_seek(RCore *core, ut64 addr);
R_API char *r_core_anal_fcn_autoname(RCore *core, ut64 addr);
R_API int r_core_anal_fcn(RCore *core, ut64 at, ut64 from, int reftype, int depth);
R_API int r_core_anal_fcn_list(RCore *core, const char *input, int rad);
R_API void r_core_anal_fcn_labels(RCore *core, RAnalFunction *fcn, int rad);
R_API int r_core_anal_graph(RCore *core, ut64 addr, int opts);
R_API int r_core_anal_graph_fcn(RCore *core, char *input, int opts);
R_API RList* r_core_anal_graph_to(RCore *core, ut64 addr, int n);
R_API int r_core_anal_ref_list(RCore *core, int rad);
R_API int r_core_anal_all(RCore *core);
R_API RList* r_core_anal_cycles (RCore *core, int ccl);

/* asm.c */
typedef struct r_core_asm_hit {
	char *code;
	int len;
	ut64 addr;
	ut8 valid;
} RCoreAsmHit;

R_API RBuffer *r_core_syscall (RCore *core, const char *name, const char *args);
R_API RBuffer *r_core_syscallf (RCore *core, const char *name, const char *fmt, ...);
R_API RCoreAsmHit *r_core_asm_hit_new();
R_API RList *r_core_asm_hit_list_new();
R_API void r_core_asm_hit_free(void *_hit);
R_API char* r_core_asm_search(RCore *core, const char *input, ut64 from, ut64 to);
R_API RList *r_core_asm_strsearch(RCore *core, const char *input, ut64 from, ut64 to, int maxhits);
R_API RList *r_core_asm_bwdisassemble (RCore *core, ut64 addr, int n, int len);
R_API RList *r_core_asm_back_disassemble_instr (RCore *core, ut64 addr, int len, ut32 hit_count, ut32 extra_padding);
R_API RList *r_core_asm_back_disassemble_byte (RCore *core, ut64 addr, int len, ut32 hit_count, ut32 extra_padding);
R_API ut32 r_core_asm_bwdis_len (RCore* core, int* len, ut64* start_addr, ut32 l);
R_API int r_core_print_disasm(RPrint *p, RCore *core, ut64 addr, ut8 *buf, int len, int lines, int invbreak, int nbytes);
R_API int r_core_print_disasm_json(RCore *core, ut64 addr, ut8 *buf, int len, int lines);
R_API int r_core_print_disasm_instructions (RCore *core, int len, int l);
R_API int r_core_print_fcn_disasm(RPrint *p, RCore *core, ut64 addr, int l, int invbreak, int cbytes);
R_API int r_core_file_bin_raise (RCore *core, ut32 binfile_idx);
//R_API int r_core_bin_bind(RCore *core, RBinFile *bf);
R_API int r_core_bin_set_env (RCore *r, RBinFile *binfile);
R_API int r_core_bin_set_by_fd (RCore *core, ut64 bin_fd);
R_API int r_core_bin_set_by_name (RCore *core, const char *name);
R_API int r_core_bin_reload(RCore *core, const char *file, ut64 baseaddr);
R_API int r_core_bin_load(RCore *core, const char *file, ut64 baseaddr);
R_API int r_core_hash_load(RCore *core, const char *file);
R_API int r_core_bin_list(RCore *core, int mode);
R_API int r_core_bin_raise (RCore *core, ut32 binfile_idx, ut32 obj_idx);
R_API int r_core_bin_delete (RCore *core, ut32 binfile_idx, ut32 binobj_idx);

// XXX - this is kinda hacky, maybe there should be a way to
// refresh the bin environment without specific calls?
R_API int r_core_bin_refresh_strings(RCore *core);

/* gdiff.c */
R_API int r_core_gdiff(RCore *core1, RCore *core2, int anal_all);
R_API int r_core_gdiff_fcn(RCore *c, ut64 addr, ut64 addr2);

R_API int r_core_project_open(RCore *core, const char *file);
R_API int r_core_project_save(RCore *core, const char *file);
R_API char *r_core_project_info(RCore *core, const char *file);
R_API char *r_core_sysenv_begin(RCore *core, const char *cmd);
R_API void r_core_sysenv_end(RCore *core, const char *cmd);
R_API void r_core_sysenv_help(const RCore* core);

/* bin.c */
#define R_CORE_BIN_PRINT	0x000
#define R_CORE_BIN_RADARE	0x001
#define R_CORE_BIN_SET		0x002
#define R_CORE_BIN_SIMPLE	0x004
#define R_CORE_BIN_JSON         0x008

#define R_CORE_BIN_ACC_STRINGS	0x001
#define R_CORE_BIN_ACC_INFO	0x002
#define R_CORE_BIN_ACC_MAIN	0x004
#define R_CORE_BIN_ACC_ENTRIES	0x008
#define R_CORE_BIN_ACC_RELOCS	0x010
#define R_CORE_BIN_ACC_IMPORTS	0x020
#define R_CORE_BIN_ACC_SYMBOLS	0x040
#define R_CORE_BIN_ACC_SECTIONS	0x080
#define R_CORE_BIN_ACC_FIELDS	0x100
#define R_CORE_BIN_ACC_LIBS	0x200
#define R_CORE_BIN_ACC_CLASSES	0x400
#define R_CORE_BIN_ACC_DWARF	0x800
#define R_CORE_BIN_ACC_PDB	0x2000
#define R_CORE_BIN_ACC_SIZE     0x1000
#define R_CORE_BIN_ACC_ALL	0xFFF

typedef struct r_core_bin_filter_t {
	ut64 offset;
	const char *name;
} RCoreBinFilter;

R_API int r_core_bin_info (RCore *core, int action, int mode, int va, RCoreBinFilter *filter, ut64 offset, const char *chksum);
R_API int r_core_bin_set_arch_bits (RCore *r, const char *name, const char * arch, ut16 bits);
R_API int r_core_bin_update_arch_bits (RCore *r);
/* rtr */
R_API int r_core_rtr_cmds (RCore *core, const char *port);
R_API char *r_core_rtr_cmds_query (RCore *core, const char *host, const char *port, const char *cmd);
R_API void r_core_rtr_help(RCore *core);
R_API void r_core_rtr_pushout(RCore *core, const char *input);
R_API void r_core_rtr_list(RCore *core);
R_API void r_core_rtr_add(RCore *core, const char *input);
R_API void r_core_rtr_remove(RCore *core, const char *input);
R_API void r_core_rtr_session(RCore *core, const char *input);
R_API void r_core_rtr_cmd(RCore *core, const char *input);
R_API int r_core_rtr_http(RCore *core, int launch, const char *path);
R_API int r_core_rtr_http_stop(RCore *u);

R_API void r_core_visual_define (RCore *core);
R_API void r_core_visual_config (RCore *core);
R_API void r_core_visual_mounts (RCore *core);
R_API void r_core_visual_anal (RCore *core);
R_API void r_core_seek_next (RCore *core, const char *type);
R_API void r_core_seek_previous (RCore *core, const char *type);
R_API void r_core_visual_define (RCore *core);
R_API int r_core_visual_trackflags (RCore *core);
R_API int r_core_visual_comments (RCore *core);
R_API int r_core_visual_prompt (RCore *core);
R_API int r_core_search_preludes(RCore *core);
R_API int r_core_search_prelude(RCore *core, ut64 from, ut64 to, const ut8 *buf, int blen, const ut8 *mask, int mlen);
R_API RList* /*<RIOMap*>*/ r_core_get_boundaries (RCore *core, const char *mode, ut64 *from, ut64 *to);

R_API int r_core_patch (RCore *core, const char *patch);

R_API void r_core_hack_help(RCore *core);
R_API int r_core_hack(RCore *core, const char *op);
R_API int r_core_dump(RCore *core, const char *file, ut64 addr, ut64 size);
R_API void r_core_diff_show(RCore *core, RCore *core2);


/* watchers */
R_API void r_core_cmpwatch_free (RCoreCmpWatcher *w);
R_API RCoreCmpWatcher *r_core_cmpwatch_get (RCore *core, ut64 addr);
R_API int r_core_cmpwatch_add (RCore *core, ut64 addr, int size, const char *cmd);
R_API int r_core_cmpwatch_del (RCore *core, ut64 addr);
R_API int r_core_cmpwatch_update (RCore *core, ut64 addr);
R_API int r_core_cmpwatch_show (RCore *core, ut64 addr, int mode);
R_API int r_core_cmpwatch_revert (RCore *core, ut64 addr);

/* logs */
R_API void r_core_log_free(RCoreLog *log);
R_API void r_core_log_init (RCoreLog *log);
R_API RCoreLog *r_core_log_new ();
R_API int r_core_log_list(RCore *core, int n, int count, char fmt);
R_API void r_core_log_add(RCore *core, const char *msg);
R_API void r_core_log_del(RCore *core, int n);

/* help */
R_API void r_core_cmd_help(const RCore *core, const char * help[]);

/* anal stats */

typedef struct {
	ut32 youarehere;
	ut32 flags;
	ut32 comments;
	ut32 functions;
	ut32 symbols;
	ut32 strings;
	ut32 imports;
} RCoreAnalStatsItem;
typedef struct {
	RCoreAnalStatsItem *block;
} RCoreAnalStats;

R_API RCoreAnalStats* r_core_anal_get_stats (RCore *a, ut64 from, ut64 to, ut64 step);
R_API void r_core_anal_stats_free (RCoreAnalStats *s);
R_API void r_core_syscmd_ls(const char *input);
R_API void r_core_syscmd_cat(const char *file);

/* tasks */

typedef void (*RCoreTaskCallback)(void *user, char *out);

typedef struct r_core_task_t {
	int id;
	char state;
	void *user;
	RCore *core;
	RThreadMsg *msg;
	RCoreTaskCallback cb;
} RCoreTask;

R_API RCoreTask *r_core_task_get (RCore *core, int id);
R_API void r_core_task_list (RCore *core, int mode);
R_API RCoreTask *r_core_task_new (RCore *core, const char *cmd, RCoreTaskCallback cb, void *user);
R_API void r_core_task_run(RCore *core, RCoreTask *_task);
R_API void r_core_task_run_bg(RCore *core, RCoreTask *_task);
R_API RCoreTask *r_core_task_add (RCore *core, RCoreTask *task);
R_API void r_core_task_add_bg (RCore *core, RCoreTask *task);
R_API int r_core_task_del (RCore *core, int id);
R_API void r_core_task_join (RCore *core, RCoreTask *task);

/* PLUGINS */
extern RCorePlugin r_core_plugin_java;
extern RCorePlugin r_core_plugin_anal;
extern RCorePlugin r_core_plugin_yara;

#endif

#ifdef __cplusplus
}
#endif

#endif
