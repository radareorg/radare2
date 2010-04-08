/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_core.h>
#include "../config.h"

static ut64 num_callback(void *userptr, const char *str, int *ok) {
	RCore *core = userptr;
	struct r_flag_item_t *flag;
	struct r_anal_aop_t aop;
	
	if (str[0]=='$') {
		/* analyze opcode */
		switch (str[1]) {
		case '$': 
			return (str[2]=='$')? aop.length:core->offset;
		case 'e':
		case 'j':
		case 'f':
		case 'r':
			r_anal_aop (&core->anal, &aop, core->offset,
				core->block, core->blocksize);
			break;
		}
		
		/* return value */
		switch (str[1]) {
		case '{':
			{
				char *ptr, *bptr = strdup(str+2);
				ptr = strchr(bptr, '}');
				if (ptr != NULL) {
					ut64 ret;
					ptr[0]='\0';
					ret = r_config_get_i (&core->config, bptr);
					free (bptr);
					return ret;
				}
			}
			return 0;
		case 'e': return aop.eob;
		case 'j': return aop.jump;
		case 'f': return aop.fail;
		case 'r': return aop.ref;
		case 'b': return core->blocksize;
		case 's': return core->file->size;
		case '?': return core->num.value;
		}
	}

	flag = r_flag_get (&(core->flags), str);
	if (flag) *ok = R_TRUE;
	else *ok = R_FALSE;
	return (flag)?flag->offset:0LL;
}

R_API RCore *r_core_new() {
	RCore *c = R_NEW (struct r_core_t);
	r_core_init (c);
	return c;
}

/*-----------------------------------*/
#define CMDS 54
static const char *radare_argv[CMDS] ={
	"?", "!step", "!stepo", "!cont", "!signal", "!fd", "!maps", ".!maps*",
	"!bp", "!!", "#md5", "#sha1", "#crc32", "#entropy", "Visual", "ad", "ac",
	"ag", "emenu", "eval", "seek", "info", "help", "move", "quit", "flag",
	"Po", "Ps", "Pi", "H", "H no", "H nj", "H fj", "H lua", "x", "b",
	"y", "yy", "y?", "wx", "ww", "wf", "w?", "pD", "pG", "pb", "px",
	"pX", "po", "pm", "pz", "pr >", "p?", NULL
};

static int myfgets(char *buf, int len) {
	/* TODO: link against dietline if possible for autocompletion */
	char *ptr;
	RLine *rli = r_line_singleton (); 
	buf[0]='\0';
	rli->completion.argc = CMDS;
	rli->completion.argv = radare_argv;
	ptr = r_line_readline (); //CMDS, radare_argv);
	if (ptr == NULL)
		return -2;
	strncpy (buf, ptr, len);
	//free(ptr); // XXX leak
	return strlen (buf)+1;
}
/*-----------------------------------*/

#if 0
static int __dbg_read(void *user, int pid, ut64 addr, ut8 *buf, int len)
{
	RCore *core = (RCore *)user;
	// TODO: pid not used
	return r_core_read_at(core, addr, buf, len);
}

static int __dbg_write(void *user, int pid, ut64 addr, const ut8 *buf, int len)
{
	RCore *core = (RCore *)user;
	// TODO: pid not used
	return r_core_write_at(core, addr, buf, len);
}
#endif

R_API int r_core_init(RCore *core) {
	core->ffio = 0;
	core->oobi = NULL;
	core->oobi_len = 0;
	core->yank = NULL;
	core->yank_len = 0;
	core->yank_off = 0LL;
	core->num.callback = &num_callback;
	core->num.userptr = core;

	/* initialize libraries */
	r_syscall_init (&core->syscall);
	r_print_init (&core->print);
	core->print.printf = (void *)r_cons_printf;
	r_lang_init (&core->lang);
	r_lang_set_user_ptr (&core->lang, core);
	r_anal_init (&core->anal);
	r_anal_set_user_ptr (&core->anal, core);
	r_asm_init (&core->assembler);
	r_asm_set_user_ptr (&core->assembler, core);
	r_parse_init (&core->parser);
	r_parse_set_user_ptr (&core->parser, core);
	r_bin_init (&core->bin);
	r_bin_set_user_ptr (&core->bin, core);
	r_meta_init (&core->meta);
	r_cons_init ();
	r_line_init ();
	r_sign_init (&core->sign);
	r_cons_singleton()->user_fgets = (void *)myfgets;
	r_line_hist_load (".radare2_history");

	core->search = r_search_new(R_SEARCH_KEYWORD);
	r_io_init (&core->io);
	//r_cmd_macro_init (&core->macro);
	core->file = NULL;
	INIT_LIST_HEAD (&core->files);
	core->offset = 0LL;
	core->blocksize = R_CORE_BLOCKSIZE;
	core->block = (ut8*)malloc (R_CORE_BLOCKSIZE);
	if (core->block == NULL) {
		eprintf ("Cannot allocate %d bytes\n", R_CORE_BLOCKSIZE);
		/* XXX memory leak */
		return R_FALSE;
	}
	r_core_cmd_init (core);
	r_flag_init (&core->flags);
	r_debug_init (&core->dbg, R_TRUE);
	core->io.printf = r_cons_printf;
	core->dbg.printf = r_cons_printf;
	r_debug_io_bind (&core->dbg, &core->io);
	r_core_config_init (core);
	// XXX fix path here

	/* load plugins */
	r_core_loadlibs (core);

	// TODO: get arch from r_bin or from native arch
	r_asm_use (&core->assembler, R_SYS_ARCH);
	r_anal_use (&core->anal, R_SYS_ARCH);
	r_bp_use (core->dbg.bp, R_SYS_ARCH);
	if (R_SYS_BITS & R_SYS_BITS_64)
		r_config_set_i (&core->config, "asm.bits", 64);
	else
	if (R_SYS_BITS & R_SYS_BITS_32)
		r_config_set_i (&core->config, "asm.bits", 32);
	r_config_set (&core->config, "asm.arch", R_SYS_ARCH);
	return 0;
}

R_API RCore *r_core_free(RCore *c) {
	/* TODO: it leaks as shit */
	free (c);
	return NULL;
}

R_API int r_core_prompt(RCore *r) {
	static char *prevcmd = NULL;
	int ret;
	char *cmd;
	char line[1024];
	char prompt[32];
	const char *cmdprompt = r_config_get (&r->config, "cmd.prompt");

	if (cmdprompt && cmdprompt[0])
		ret = r_core_cmd (r, cmdprompt, 0);

	/* XXX : ultraslow */
	if (!r_config_get_i (&r->config, "scr.prompt"))
		*prompt = 0;
	else if (r_config_get_i (&r->config, "scr.color"))
		sprintf (prompt, Color_YELLOW"[0x%08llx]> "Color_RESET, r->offset);
	else sprintf (prompt, "[0x%08llx]> ", r->offset);
	r_line_singleton()->prompt = prompt;
	ret = r_cons_fgets (line, sizeof (line), 0, NULL);
	if (ret == -2)
		return R_CORE_CMD_EXIT;
	if (ret == -1)
		return 0;
	if (strcmp (line, ".")) {
		free (prevcmd);
		prevcmd = strdup (line);
		cmd = line;
	} else cmd = prevcmd;
	ret = r_core_cmd (r, cmd, R_TRUE);
	r_cons_flush ();
	return ret;
}

R_API int r_core_block_size(RCore *core, ut32 bsize) {
	int ret = R_FALSE;
	if (bsize<1)
		bsize = R_TRUE;
	else if (bsize> R_CORE_BLOCKSIZE_MAX)
		bsize = R_CORE_BLOCKSIZE_MAX;
	else ret = R_TRUE;
	core->block = realloc (core->block, bsize);
	core->blocksize = bsize;
	r_core_block_read (core, 0);
	return ret;
}

R_API int r_core_seek_align(RCore *core, ut64 align, int times) {
	int inc = (times>=0)?1:-1;
	int diff = core->offset%align;
	ut64 seek = core->offset;
	
	if (times == 0)
		diff = -diff;
	else if (diff) {
		if (inc>0) diff += align-diff;
		else diff = -diff;
		if (times) times -= inc;
	}
	while ((times*inc)>0) {
		times -= inc;
		diff += align*inc;
	}
	if (diff<0 && -diff>seek)
		seek = diff = 0;
	return r_core_seek (core, seek+diff, 1);
}

R_API int r_core_seek_delta(RCore *core, st64 addr) {
	ut64 tmp = core->offset;
	int ret;
	if (addr == 0)
		return R_TRUE;
	if (addr>0) {
		/* check end of file */
		if (0) addr = 0; // XXX tmp+addr>) {
		else addr += tmp;
	} else {
		/* check < 0 */
		if (-addr > tmp) addr = 0;
		else addr += tmp;
	}
	core->offset = addr;
	ret = r_core_block_read (core, 0);
	if (ret == -1)
		core->offset = tmp;
	return ret;
}
