/* radare - LGPL - Copyright 2009-2018 - pancake */

#ifndef R2_CORE_H
#define R2_CORE_H

#include "r_socket.h"
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
#include "r_flag.h"
#include "r_config.h"
#include "r_bin.h"
#include "r_hash.h"
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

#define R_CORE_ANAL_GRAPHLINES          1
#define R_CORE_ANAL_GRAPHBODY           2
#define R_CORE_ANAL_GRAPHDIFF           4
#define R_CORE_ANAL_JSON                8
#define R_CORE_ANAL_KEYVALUE            16
#define R_CORE_ANAL_JSON_FORMAT_DISASM  32

///
#define R_CONS_COLOR_DEF(x, def) ((core->cons && core->cons->pal.x)? core->cons->pal.x: def)
#define R_CONS_COLOR(x) R_CONS_COLOR_DEF (x, "")

/* rtr */
#define RTR_PROT_RAP 0
#define RTR_PROT_TCP 1
#define RTR_PROT_UDP 2
#define RTR_PROT_HTTP 3

#define RTR_RAP_OPEN   0x01
#define RTR_RAP_CMD    0x07
#define RTR_RAP_REPLY  0x80

#define RTR_MAX_HOSTS 255

#define R_CORE_CMD_DEPTH 100

/* visual mode */
#define NPF 9
#define PIDX (R_ABS (core->printidx % NPF))
#define R_CORE_VISUAL_MODE_PX    0
#define R_CORE_VISUAL_MODE_PD    1
#define R_CORE_VISUAL_MODE_PDDBG 2
#define R_CORE_VISUAL_MODE_PW    3
#define R_CORE_VISUAL_MODE_PC    4
#define R_CORE_VISUAL_MODE_PXA   5
#define R_CORE_VISUAL_MODE_PSS   6
#define R_CORE_VISUAL_MODE_PRC   7
#define R_CORE_VISUAL_MODE_PXa   8

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
	int dbg;
	int fd;
	RBinBind binb;
	const struct r_core_t *core;
	ut8 alive;
} RCoreFile;

typedef struct r_core_times_t {
	ut64 loadlibs_init_time;
	ut64 loadlibs_time;
	ut64 file_open_time;
} RCoreTimes;

#define R_CORE_ASMSTEPS 128
#define R_CORE_ASMQJMPS_NUM 10
#define R_CORE_ASMQJMPS_LETTERS 26
#define R_CORE_ASMQJMPS_MAX_LETTERS (26 * 26 * 26 * 26 * 26)
#define R_CORE_ASMQJMPS_LEN_LETTERS 5
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
	bool vmode;
	int interrupted; // XXX IS THIS DUPPED SOMEWHERE?
	/* files */
	RCons *cons;
	RIO *io;
	RCoreFile *file;
	RList *files;
	RNum *num;
	RNum *old_num;
	RLib *lib;
	RCmd *rcmd;
	RCmdDescriptor root_cmd_descriptor;
	RList/*<RCmdDescriptor>*/ *cmd_descriptors;
	RAnal *anal;
	RAsm *assembler;
	/* ^^ */
	RCoreTimes *times;
	RParse *parser;
	RPrint *print;
	RLang *lang;
	RDebug *dbg;
	RFlag *flags;
	RSearch *search;
	RIOSection *section;
	RFS *fs;
	REgg *egg;
	RCoreLog *log;
	RAGraph *graph;
	char *cmdqueue;
	char *lastcmd;
	char *cmdlog;
	bool cfglog;
	int cmdrepeat;
	ut64 inc;
	int rtr_n;
	RCoreRtrHost rtr_host[RTR_MAX_HOSTS];
	int curasmstep;
	RCoreAsmsteps asmsteps[R_CORE_ASMSTEPS];
	ut64 *asmqjmps;
	int asmqjmps_count;
	int asmqjmps_size;
	bool is_asmqjmps_letter;
	bool keep_asmqjmps;
	// visual
	int http_up;
	int gdbserver_up;
	int printidx;
	int vseek;
	bool in_search;
	RList *watchers;
	RList *scriptstack;
	RList *tasks;
	int cmd_depth;
	ut8 switch_file_view;
	Sdb *sdb;
	int incomment;
	int curtab; // current tab
	int seltab; // selected tab
	int cmdremote;
	char *lastsearch;
	bool fixedblock;
	char *cmdfilter;
	bool break_loop;
	RThreadLock *lock;
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
R_API RList *r_core_list_themes (RCore *core);
R_API RCons *r_core_get_cons (RCore *core);
R_API RBin *r_core_get_bin (RCore *core);
R_API RConfig *r_core_get_config (RCore *core);
R_API RAsmOp *r_core_disassemble (RCore *core, ut64 addr);
R_API bool r_core_init(RCore *core);
R_API RCore *r_core_new(void);
R_API RCore *r_core_free(RCore *core);
R_API RCore *r_core_fini(RCore *c);
R_API void r_core_wait(RCore *core);
R_API RCore *r_core_ncast(ut64 p);
R_API RCore *r_core_cast(void *p);
R_API int r_core_config_init(RCore *core);
R_API int r_core_prompt(RCore *core, int sync);
R_API int r_core_prompt_exec(RCore *core);
R_API int r_core_lines_initcache (RCore *core, ut64 start_addr, ut64 end_addr);
R_API int r_core_lines_currline (RCore *core);
R_API void r_core_prompt_loop(RCore *core);
R_API int r_core_cmd(RCore *core, const char *cmd, int log);
R_API void r_core_cmd_repeat(RCore *core, int next);
R_API char *r_core_editor (const RCore *core, const char *file, const char *str);
R_API int r_core_fgets(char *buf, int len);
// FIXME: change (void *user) to (RCore *core)
R_API int r_core_cmdf(void *user, const char *fmt, ...);
R_API int r_core_flush(void *user, const char *cmd);
R_API int r_core_cmd0(void *user, const char *cmd);
R_API void r_core_cmd_init(RCore *core);
R_API int r_core_cmd_pipe(RCore *core, char *radare_cmd, char *shell_cmd);
R_API char *r_core_cmd_str(RCore *core, const char *cmd);
R_API char *r_core_cmd_strf(RCore *core, const char *fmt, ...);
R_API char *r_core_cmd_str_pipe(RCore *core, const char *cmd);
R_API int r_core_cmd_file(RCore *core, const char *file);
R_API int r_core_cmd_lines(RCore *core, const char *lines);
R_API int r_core_cmd_command(RCore *core, const char *command);
R_API int r_core_run_script (RCore *core, const char *file);
R_API bool r_core_seek(RCore *core, ut64 addr, bool rb);
R_API int r_core_seek_base (RCore *core, const char *hex);
R_API void r_core_seek_previous (RCore *core, const char *type);
R_API void r_core_seek_next (RCore *core, const char *type);
R_API int r_core_seek_align(RCore *core, ut64 align, int count);
R_API void r_core_seek_archbits (RCore *core, ut64 addr);
R_API int r_core_block_read(RCore *core);
R_API int r_core_block_size(RCore *core, int bsize);
R_API int r_core_seek_size(RCore *core, ut64 addr, int bsize);
R_API bool r_core_read_at(RCore *core, ut64 addr, ut8 *buf, int size);
R_API int r_core_is_valid_offset (RCore *core, ut64 offset);
R_API int r_core_shift_block(RCore *core, ut64 addr, ut64 b_size, st64 dist);
R_API void r_core_visual_prompt_input (RCore *core);
R_API int r_core_visual_refs(RCore *core, bool xref);
R_API bool r_core_prevop_addr(RCore* core, ut64 start_addr, int numinstrs, ut64* prev_addr);
R_API ut64 r_core_prevop_addr_force(RCore *core, ut64 start_addr, int numinstrs);
R_API bool r_core_visual_hudstuff(RCore *core);
R_API int r_core_visual_classes(RCore *core);
R_API int r_core_visual_types(RCore *core);
R_API int r_core_visual(RCore *core, const char *input);
R_API int r_core_visual_graph(RCore *core, RAGraph *g, RAnalFunction *_fcn, int is_interactive);
R_API int r_core_fcn_graph(RCore *core, RAnalFunction *_fcn);
R_API int r_core_visual_panels(RCore *core);
R_API int r_core_visual_cmd(RCore *core, const char *arg);
R_API void r_core_visual_seek_animation (RCore *core, ut64 addr);
R_API void r_core_visual_asm(RCore *core, ut64 addr);
R_API void r_core_visual_colors(RCore *core);
R_API int r_core_visual_xrefs_x(RCore *core);
R_API int r_core_visual_xrefs_X(RCore *core);
R_API int r_core_visual_hud(RCore *core);
R_API ut64 r_core_get_asmqjmps(RCore *core, const char *str);
R_API void r_core_set_asmqjmps(RCore *core, char *str, size_t len, int i);
R_API char* r_core_add_asmqjmp(RCore *core, ut64 addr);

R_API void r_core_anal_type_init(RCore *core);
R_API void r_core_anal_cc_init(RCore *core);

R_API void r_core_list_io(RCore *core);
/* visual marks */
R_API void r_core_visual_mark_seek(RCore *core, ut8 ch);
R_API void r_core_visual_mark(RCore *core, ut8 ch);
R_API void r_core_visual_mark_set(RCore *core, ut8 ch, ut64 addr);
R_API void r_core_visual_mark_dump(RCore *core);
R_API void r_core_visual_mark_reset(RCore *core);

R_API int r_core_search_cb(RCore *core, ut64 from, ut64 to, RCoreSearchCallback cb);
R_API bool r_core_serve(RCore *core, RIODesc *fd);
R_API int r_core_file_reopen(RCore *core, const char *args, int perm, int binload);
R_API void r_core_file_reopen_debug(RCore *core, const char *args);
R_API RCoreFile * r_core_file_find_by_fd(RCore* core, ut64 fd);
R_API RCoreFile * r_core_file_find_by_name (RCore * core, const char * name);
R_API RCoreFile * r_core_file_cur (RCore *r);
R_API int r_core_file_set_by_fd(RCore *core, ut64 fd);
R_API int r_core_file_set_by_name(RCore *core, const char * name);
R_API int r_core_file_set_by_file (RCore * core, RCoreFile *cf);
R_API int r_core_setup_debugger (RCore *r, const char *debugbackend, bool attach);

R_API int r_core_files_free(const RCore *core, RCoreFile *cf);
R_API void r_core_file_free(RCoreFile *cf);
R_API RCoreFile *r_core_file_open(RCore *core, const char *file, int flags, ut64 loadaddr);
R_API RCoreFile *r_core_file_open_many(RCore *r, const char *file, int flags, ut64 loadaddr);
R_API RCoreFile *r_core_file_get_by_fd(RCore *core, int fd);
R_API int r_core_file_close(RCore *core, RCoreFile *fh);
R_API bool r_core_file_close_fd(RCore *core, int fd);
R_API bool r_core_file_close_all_but(RCore *core);
R_API int r_core_file_list(RCore *core, int mode);
R_API int r_core_file_binlist(RCore *core);
R_API int r_core_file_bin_raise(RCore *core, ut32 num);
R_API int r_core_seek_delta(RCore *core, st64 addr);
R_API int r_core_extend_at(RCore *core, ut64 addr, int size);
R_API bool r_core_write_at(RCore *core, ut64 addr, const ut8 *buf, int size);
R_API int r_core_write_op(RCore *core, const char *arg, char op);
R_API int r_core_set_file_by_fd (RCore * core, ut64 bin_fd);
R_API int r_core_set_file_by_name (RBin * bin, const char * name);
R_API RBinFile * r_core_bin_cur (RCore *core);
R_API ut32 r_core_file_cur_fd (RCore *core);

R_API void r_core_debug_rr (RCore *core, RReg *reg);

/* fortune */
R_API void r_core_fortune_list_types(void);
R_API void r_core_fortune_list(RCore *core);
R_API void r_core_fortune_print_random(RCore *core);

/* project */
R_API bool r_core_project_load(RCore *core, const char *prjfile, const char *rcfile);
R_API RThread *r_core_project_load_bg(RCore *core, const char *prjfile, const char *rcfile);
R_API void r_core_project_execute_cmds(RCore *core, const char *prjfile);

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
R_API int r_core_yank_cat_string (RCore *core, ut64 pos);
R_API int r_core_yank_hud_file (RCore *core, const char *input);
R_API int r_core_yank_hud_path (RCore *core, const char *input, int dir);
R_API bool r_core_yank_file_ex (RCore *core, const char *input);
R_API int r_core_yank_file_all (RCore *core, const char *input);

#define R_CORE_LOADLIBS_ENV 1
#define R_CORE_LOADLIBS_HOME 2
#define R_CORE_LOADLIBS_SYSTEM 4
#define R_CORE_LOADLIBS_CONFIG 8
#define R_CORE_LOADLIBS_ALL UT32_MAX

R_API void r_core_loadlibs_init(RCore *core);
R_API int r_core_loadlibs(RCore *core, int where, const char *path);
// FIXME: change (void *user) -> (RCore *core)
R_API int r_core_cmd_buffer(void *user, const char *buf);
R_API int r_core_cmdf(void *user, const char *fmt, ...);
R_API int r_core_cmd0(void *user, const char *cmd);
R_API char *r_core_cmd_str(RCore *core, const char *cmd);
R_API int r_core_cmd_foreach(RCore *core, const char *cmd, char *each);
R_API int r_core_cmd_foreach3(RCore *core, const char *cmd, char *each);
R_API char *r_core_op_str(RCore *core, ut64 addr);
R_API RAnalOp *r_core_op_anal(RCore *core, ut64 addr);
R_API char *r_core_disassemble_instr(RCore *core, ut64 addr, int l);
R_API char *r_core_disassemble_bytes(RCore *core, ut64 addr, int b);

R_API int r_core_process_input_pade(RCore *core, const char *input, char** hex, char **asm_arch, ut32 *bits);
R_API RList *r_core_get_func_args(RCore *core, const char *func_name);
R_API void r_core_print_func_args(RCore *core);

/* anal.c */
R_API RAnalOp* r_core_anal_op(RCore *core, ut64 addr);
R_API void r_core_anal_esil(RCore *core, const char *str, const char *addr);
R_API void r_core_anal_fcn_merge (RCore *core, ut64 addr, ut64 addr2);
R_API const char *r_core_anal_optype_colorfor(RCore *core, ut64 addr, bool verbose);
R_API ut64 r_core_anal_address (RCore *core, ut64 addr);
R_API void r_core_anal_undefine (RCore *core, ut64 off);
R_API void r_core_anal_hint_print (RAnal* a, ut64 addr, int mode);
R_API void r_core_anal_hint_list (RAnal *a, int mode);
R_API int r_core_anal_search(RCore *core, ut64 from, ut64 to, ut64 ref, int mode);
R_API int r_core_anal_search_xrefs(RCore *core, ut64 from, ut64 to, int rad);
R_API int r_core_anal_data (RCore *core, ut64 addr, int count, int depth, int wordsize);
R_API void r_core_anal_coderefs(RCore *core, ut64 addr, int gv);
R_API void r_core_anal_codexrefs(RCore *core, ut64 addr, int fmt);
R_API int r_core_anal_refs(RCore *core, const char *input);
R_API int r_core_esil_step(RCore *core, ut64 until_addr, const char *until_expr, ut64 *prev_addr);
R_API bool r_core_esil_cmd(RAnalEsil *esil, const char *cmd, ut64 a1, ut64 a2);
R_API int r_core_esil_step_back(RCore *core);
R_API int r_core_anal_bb(RCore *core, RAnalFunction *fcn, ut64 at, int head);
R_API ut64 r_core_anal_get_bbaddr(RCore *core, ut64 addr);
R_API int r_core_anal_bb_seek(RCore *core, ut64 addr);
R_API int r_core_anal_fcn(RCore *core, ut64 at, ut64 from, int reftype, int depth);
R_API char *r_core_anal_fcn_autoname(RCore *core, ut64 addr, int dump);
R_API void r_core_anal_autoname_all_fcns(RCore *core);
R_API int r_core_anal_fcn_list(RCore *core, const char *input, const char *rad);
R_API int r_core_anal_fcn_list_size(RCore *core);
R_API void r_core_anal_fcn_labels(RCore *core, RAnalFunction *fcn, int rad);
R_API int r_core_anal_fcn_clean(RCore *core, ut64 addr);
R_API int r_core_anal_graph(RCore *core, ut64 addr, int opts);
R_API int r_core_anal_graph_fcn(RCore *core, char *input, int opts);
R_API RList* r_core_anal_graph_to(RCore *core, ut64 addr, int n);
R_API int r_core_anal_ref_list(RCore *core, int rad);
R_API int r_core_anal_all(RCore *core);
R_API RList* r_core_anal_cycles (RCore *core, int ccl);

/*tp.c*/
R_API void r_core_anal_type_match(RCore *core, RAnalFunction *fcn);

/* asm.c */
typedef struct r_core_asm_hit {
	char *code;
	int len;
	ut64 addr;
	ut8 valid;
} RCoreAsmHit;

R_API RBuffer *r_core_syscall (RCore *core, const char *name, const char *args);
R_API RBuffer *r_core_syscallf (RCore *core, const char *name, const char *fmt, ...);
R_API RCoreAsmHit *r_core_asm_hit_new(void);
R_API RList *r_core_asm_hit_list_new(void);
R_API void r_core_asm_hit_free(void *_hit);
R_API void r_core_set_asm_configs(RCore *core, char *arch, ut32 bits, int segoff);
R_API char* r_core_asm_search(RCore *core, const char *input);
R_API RList *r_core_asm_strsearch(RCore *core, const char *input, ut64 from, ut64 to, int maxhits, int regexp, int everyByte, int mode);
R_API RList *r_core_asm_bwdisassemble (RCore *core, ut64 addr, int n, int len);
R_API RList *r_core_asm_back_disassemble_instr (RCore *core, ut64 addr, int len, ut32 hit_count, ut32 extra_padding);
R_API RList *r_core_asm_back_disassemble_byte (RCore *core, ut64 addr, int len, ut32 hit_count, ut32 extra_padding);
R_API ut32 r_core_asm_bwdis_len (RCore* core, int* len, ut64* start_addr, ut32 l);
R_API int r_core_print_disasm(RPrint *p, RCore *core, ut64 addr, ut8 *buf, int len, int lines, int invbreak, int nbytes, bool json);
R_API int r_core_print_disasm_json(RCore *core, ut64 addr, ut8 *buf, int len, int lines);
R_API int r_core_print_disasm_instructions (RCore *core, int len, int l);
R_API int r_core_print_disasm_all (RCore *core, ut64 addr, int l, int len, int mode);
R_API int r_core_disasm_pdi(RCore *core, int nb_opcodes, int nb_bytes, int fmt);
R_API int r_core_print_fcn_disasm(RPrint *p, RCore *core, ut64 addr, int l, int invbreak, int cbytes);
R_API int r_core_file_bin_raise (RCore *core, ut32 binfile_idx);
//R_API int r_core_bin_bind(RCore *core, RBinFile *bf);
R_API int r_core_bin_set_env (RCore *r, RBinFile *binfile);
R_API int r_core_bin_set_by_fd (RCore *core, ut64 bin_fd);
R_API int r_core_bin_set_by_name (RCore *core, const char *name);
R_API int r_core_bin_reload(RCore *core, const char *file, ut64 baseaddr);
R_API bool r_core_bin_load(RCore *core, const char *file, ut64 baseaddr);
R_API int r_core_bin_rebase(RCore *core, ut64 baddr);
R_API void r_core_bin_export_info_rad(RCore *core);
R_API int r_core_hash_load(RCore *core, const char *file);
R_API int r_core_bin_list(RCore *core, int mode);
R_API int r_core_bin_raise (RCore *core, ut32 binfile_idx, ut32 obj_idx);
R_API bool r_core_bin_delete (RCore *core, ut32 binfile_idx, ut32 binobj_idx);

// XXX - this is kinda hacky, maybe there should be a way to
// refresh the bin environment without specific calls?
R_API int r_core_bin_refresh_strings(RCore *core);
R_API int r_core_pseudo_code (RCore *core, const char *input);

/* gdiff.c */
R_API int r_core_gdiff(RCore *core1, RCore *core2);
R_API int r_core_gdiff_fcn(RCore *c, ut64 addr, ut64 addr2);

R_API bool r_core_project_open(RCore *core, const char *file, bool thready);
R_API int r_core_project_cat(RCore *core, const char *name);
R_API int r_core_project_delete(RCore *core, const char *prjfile);
R_API int r_core_project_list(RCore *core, int mode);
R_API bool r_core_project_save_rdb(RCore *core, const char *file, int opts);
R_API bool r_core_project_save(RCore *core, const char *file);
R_API char *r_core_project_info(RCore *core, const char *file);
R_API char *r_core_project_notes_file (RCore *core, const char *file);

R_API char *r_core_sysenv_begin(RCore *core, const char *cmd);
R_API void r_core_sysenv_end(RCore *core, const char *cmd);
R_API void r_core_sysenv_help(const RCore* core);

R_API void fcn_callconv (RCore *core, RAnalFunction *fcn);
/* bin.c */
#define R_CORE_BIN_PRINT	0x000 
#define R_CORE_BIN_RADARE	0x001
#define R_CORE_BIN_SET		0x002
#define R_CORE_BIN_SIMPLE	0x004
#define R_CORE_BIN_JSON		0x008
#define R_CORE_BIN_ARRAY	0x010
#define R_CORE_BIN_SIMPLEST	0x020
#define R_CORE_BIN_CLASSDUMP	0x040

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
#define R_CORE_BIN_ACC_SIZE     0x1000
#define R_CORE_BIN_ACC_PDB	0x2000
#define R_CORE_BIN_ACC_MEM	0x4000
#define R_CORE_BIN_ACC_EXPORTS  0x8000
#define R_CORE_BIN_ACC_VERSIONINFO 0x10000
#define R_CORE_BIN_ACC_SIGNATURE 0x20000
#define R_CORE_BIN_ACC_RAW_STRINGS	0x40000
#define R_CORE_BIN_ACC_HEADER 0x80000
#define R_CORE_BIN_ACC_RESOURCES 0x100000
#define R_CORE_BIN_ACC_INITFINI 0x200000
#define R_CORE_BIN_ACC_ALL	0x104FFF

#define R_CORE_PRJ_FLAGS	0x0001
#define R_CORE_PRJ_EVAL		0x0002
#define R_CORE_PRJ_IO_MAPS	0x0004
#define R_CORE_PRJ_SECTIONS	0x0008
#define R_CORE_PRJ_META		0x0010
#define R_CORE_PRJ_XREFS	0x0020
#define R_CORE_PRJ_FCNS		0x0040
#define R_CORE_PRJ_ANAL_HINTS	0x0080
#define R_CORE_PRJ_ANAL_TYPES	0x0100
#define R_CORE_PRJ_ANAL_MACROS	0x0200
#define R_CORE_PRJ_ANAL_SEEK	0x0400
#define R_CORE_PRJ_DBG_BREAK   0x0800
#define R_CORE_PRJ_ALL		0xFFFF

typedef struct r_core_bin_filter_t {
	ut64 offset;
	const char *name;
} RCoreBinFilter;

R_API int r_core_bin_info (RCore *core, int action, int mode, int va, RCoreBinFilter *filter, const char *chksum);
R_API int r_core_bin_set_arch_bits (RCore *r, const char *name, const char * arch, ut16 bits);
R_API int r_core_bin_update_arch_bits (RCore *r);
R_API char *r_core_bin_method_flags_str(ut64 flags, int mode);

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
R_API int r_core_rtr_gdb(RCore *core, int launch, const char *path);

R_API void r_core_visual_config (RCore *core);
R_API void r_core_visual_mounts (RCore *core);
R_API void r_core_visual_anal (RCore *core);
R_API void r_core_seek_next (RCore *core, const char *type);
R_API void r_core_seek_previous (RCore *core, const char *type);
R_API void r_core_visual_define (RCore *core, const char *arg);
R_API int r_core_visual_trackflags (RCore *core);
R_API int r_core_visual_comments (RCore *core);
R_API int r_core_visual_prompt (RCore *core);
R_API bool r_core_visual_esil (RCore *core);
R_API int r_core_search_preludes(RCore *core);
R_API int r_core_search_prelude(RCore *core, ut64 from, ut64 to, const ut8 *buf, int blen, const ut8 *mask, int mlen);
R_API RList* /*<RIOMap*>*/ r_core_get_boundaries_prot (RCore *core, int protection, const char *mode, const char *prefix);

R_API int r_core_patch (RCore *core, const char *patch);

R_API void r_core_hack_help(const RCore *core);
R_API int r_core_hack(RCore *core, const char *op);
R_API bool r_core_dump(RCore *core, const char *file, ut64 addr, ut64 size, int append);
R_API void r_core_diff_show(RCore *core, RCore *core2);
R_API void r_core_clippy(const char *msg);

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
R_API RCoreLog *r_core_log_new (void);
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
	ut32 rwx;
} RCoreAnalStatsItem;
typedef struct {
	RCoreAnalStatsItem *block;
} RCoreAnalStats;

R_API bool core_anal_bbs(RCore *core, const char* input);
R_API bool core_anal_bbs_range (RCore *core, const char* input);
R_API char *r_core_anal_hasrefs(RCore *core, ut64 value, bool verbose);
R_API char *r_core_anal_get_comments(RCore *core, ut64 addr);
R_API RCoreAnalStats* r_core_anal_get_stats (RCore *a, ut64 from, ut64 to, ut64 step);
R_API void r_core_anal_stats_free (RCoreAnalStats *s);
R_API void r_core_anal_list_vtables (void *core, bool printJson);
R_API void r_core_anal_print_rtti (void *core);

R_API void r_core_syscmd_ls(const char *input);
R_API void r_core_syscmd_cat(const char *file);
R_API void r_core_syscmd_mkdir(const char *dir);

// TODO : move into debug or syscall++
R_API char *cmd_syscall_dostr(RCore *core, int num);
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
typedef void (*inRangeCb) (RCore *core, ut64 from, ut64 to, int vsize,
			   bool asterisk, int count);
R_API int r_core_search_value_in_range (RCore *core, RInterval search_itv,
		ut64 vmin, ut64 vmax, int vsize, bool asterisk, inRangeCb cb);

/* PLUGINS */
extern RCorePlugin r_core_plugin_java;
extern RCorePlugin r_core_plugin_anal;

#endif

/*
	RTTI Parsing Information
	MSVC(Microsoft visual studio compiler) rtti structure
	information:
*/

typedef struct type_descriptor_t {
	ut64 pVFTable;//Always point to type_info's vftable
	int spare;
	char* className;
} type_descriptor;

typedef struct class_hierarchy_descriptor_t {
	int signature;//always 0

	//bit 0 --> Multiple inheritance
	//bit 1 --> Virtual inheritance
	int attributes;

	//total no of base classes
	// including itself
	int numBaseClasses;

	//Array of base class descriptor's
	RList* baseClassArray;
} class_hierarchy_descriptor;

typedef struct base_class_descriptor_t {
	//Type descriptor of current base class
	type_descriptor* typeDescriptor;

	//Number of direct bases
	//of this base class
	int numContainedBases;

	//vftable offset
	int mdisp;

	// vbtable offset
	int pdisp;

	//displacement of the base class
	//vftable pointer inside the vbtable
	int vdisp;

	//don't know what's this
	int attributes;

	//class hierarchy descriptor
	//of this base class
	class_hierarchy_descriptor* classDescriptor;
} base_class_descriptor;

typedef struct rtti_complete_object_locator_t {
	int signature;

	//within class offset
	int vftableOffset;

	//don't know what's this
	int cdOffset;

	//type descriptor for the current class
	type_descriptor* typeDescriptor;

	//hierarchy descriptor for current class
	class_hierarchy_descriptor* hierarchyDescriptor;
} rtti_complete_object_locator;

typedef struct run_time_type_information_t {
	ut64 vtable_start_addr;
	ut64 rtti_addr;
} rtti_struct;

#ifdef __cplusplus
}
#endif

#endif
