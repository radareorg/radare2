/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_core.h>
#include "../config.h"

static u64 num_callback(void *userptr, const char *str, int *ok)
{
	struct r_core_t *core = userptr;
	struct r_flag_item_t *flag;
	struct r_anal_aop_t aop;
	
	if (str[0]=='$') {
		/* analyze opcode */
		switch(str[1]) {
		case '$': if (str[2]!='$') break;
		case 'e':
		case 'j':
		case 'f':
		case 'r':
			r_anal_set_pc(&core->anal, core->seek);
			r_anal_aop(&core->anal, &aop, core->block);
			break;
		}
		
		/* return value */
		switch(str[1]) {
		case '$':
			if (str[2]=='$')
				return aop.length;
			return core->seek;
		case '{':
			{
				char *ptr, *bptr = strdup(str+2);
				ptr = strchr(bptr, '}');
				if (ptr != NULL) {
					u64 ret;
					ptr[0]='\0';
					ret = r_config_get_i(&core->config, bptr);
					free(bptr);
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

	flag = r_flag_get(&(core->flags), str);
	if (flag != NULL) {
		*ok = 1;
		return flag->offset;
	}
	*ok = 0;
	return 0LL;
}

R_API struct r_core_t *r_core_new()
{
	struct r_core_t *c = MALLOC_STRUCT(struct r_core_t);
	r_core_init(c);
	return c;
}

/*-----------------------------------*/
#define CMDS 54
static const char *radare_argv[CMDS] ={
	NULL, // padding
	"? ", "!step ", "!stepo ", "!cont ", "!signal ", "!fd ", "!maps ", ".!maps*",
	"!bp ", "!!", "#md5", "#sha1", "#crc32", "#entropy", "Visual", "ad", "ac",
	"ag", "emenu ", "eval ", "seek ", "info ", "help ", "move ", "quit ", "flag ",
	"Po ", "Ps ", "Pi ", "H ", "H no ", "H nj ", "H fj ", "H lua ", "x ", "b ",
	"y ", "yy ", "y? ", "wx ", "ww ", "wf ", "w?", "pD ", "pG ", "pb ", "px ",
	"pX ", "po ", "pm ", "pz ", "pr > ", "p? "
};

static int myfgets(char *buf, int len)
{
	/* TODO: link against dietline if possible for autocompletion */
	char *ptr;
	buf[0]='\0';
	ptr = r_line_readline(CMDS, radare_argv);
	if (ptr == NULL)
		return -1;
	strncpy(buf, ptr, len);
	//free(ptr);
	return strlen(buf);
}
/*-----------------------------------*/

static int __dbg_read(void *user, int pid, u64 addr, u8 *buf, int len)
{
	struct r_core_t *core = (struct r_core_t *)user;
	// TODO: pid not used
	return r_core_read_at(core, addr, buf, len);
}

static int __dbg_write(void *user, int pid, u64 addr, const u8 *buf, int len)
{
	struct r_core_t *core = (struct r_core_t *)user;
	// TODO: pid not used
	return r_core_write_at(core, addr, buf, len);
}

R_API int r_core_init(struct r_core_t *core)
{
	core->oobi = NULL;
	core->oobi_len = 0;
	core->yank = NULL;
	core->yank_len = 0;
	core->yank_off = 0LL;
	core->num.callback = &num_callback;
	core->num.userptr = core;

	/* initialize libraries */
	r_print_init(&core->print);
	core->print.printf = r_cons_printf;
	r_lang_init(&core->lang);
	r_lang_set_user_ptr(&core->lang, core);
	r_anal_init(&core->anal);
	r_anal_set_user_ptr(&core->anal, core);
	r_asm_init(&core->assembler);
	r_asm_set_user_ptr(&core->assembler, core);
	r_parse_init(&core->parser);
	r_parse_set_user_ptr(&core->parser, core);
	r_bin_init(&core->bin);
	r_bininfo_init(&core->bininfo);
	r_bin_set_user_ptr(&core->bin, core);
	r_meta_init(&core->meta);
	r_line_init();
	r_cons_init();
	r_cons_user_fgets = myfgets;
	r_line_hist_load(".radare2_history");

	core->search = r_search_new(R_SEARCH_KEYWORD);
	r_io_init(&core->io);
	r_macro_init(&core->macro);
	core->macro.num = &core->num;
	core->macro.user = core;
	core->macro.cmd = r_core_cmd0;
	core->file = NULL;
	INIT_LIST_HEAD(&core->files);
	core->seek = 0LL;
	core->blocksize = R_CORE_BLOCKSIZE;
	core->block = (u8*)malloc(R_CORE_BLOCKSIZE);
	r_core_cmd_init(core);
	r_flag_init(&core->flags);
	r_debug_init(&core->dbg);
	r_debug_set_io(&core->dbg, &__dbg_read, &__dbg_write, core);
	r_core_config_init(core);
	// XXX fix path here

	/* load plugins */
	r_core_loadlibs(core);
	/* UH? */
	r_asm_set(&core->assembler, "asm_"DEFAULT_ARCH);
	r_anal_set(&core->anal, "anal_"DEFAULT_ARCH);
	r_bp_handle_set(&core->dbg.bp, "bp_"DEFAULT_ARCH);
	r_config_set(&core->config, "asm.arch", "x86");
	r_config_set_i(&core->config, "asm.bits", 32);

	return 0;
}

R_API struct r_core_t *r_core_free(struct r_core_t *c)
{
	free(c);
	return NULL;
}

R_API int r_core_prompt(struct r_core_t *r)
{
	char prompt[32];
	char line[1024];
	int ret;

	const char *cmdprompt = r_config_get(&r->config, "cmd.prompt");
	if (cmdprompt && cmdprompt[0])
		r_core_cmd(r, cmdprompt, 0);

	sprintf(prompt, "[0x%08llx]> ", r->seek);
	r_line_prompt = prompt;
	ret = r_cons_fgets(line, sizeof(line), 0 , NULL);
	if (ret<0)
		return -1;
	ret = r_core_cmd(r, line, R_TRUE);
	r_cons_flush();
	return ret;
}

R_API int r_core_block_size(struct r_core_t *core, u32 bsize)
{
	int ret = 0;
	if (bsize<1)
		bsize = 1;
	else if (bsize> R_CORE_BLOCKSIZE_MAX)
		bsize = R_CORE_BLOCKSIZE_MAX;
	else ret = 1;
	core->block = realloc(core->block, bsize);
	core->blocksize = bsize;
	r_core_block_read(core, 0);
	return ret;
}

R_API int r_core_seek_align(struct r_core_t *core, u64 align, int times)
{
	int inc = (times>=0)?1:-1;
	int diff = core->seek%align;
	u64 seek = core->seek;
	
	if (times == 0) diff = -diff;
	else if (diff) {
		if (inc>0) diff += align-diff;
		else diff = -diff;
		if (times) times -= inc;
	}
	while((times*inc)>0) {
		times -= inc;
		diff += align*inc;
	}
	return r_core_seek(core, seek+diff, 1);
}

R_API int r_core_seek_delta(struct r_core_t *core, s64 addr)
{
	u64 tmp = core->seek;
	int ret;
	if (addr == 0)
		return R_TRUE;
	if (addr>0) {
		/* check end of file */
		if (0) { // tmp+addr>) {
			addr = 0;
		} else addr += tmp;
	} else {
		/* check < 0 */
		if (tmp+addr<0) {
			addr = 0;
		} else addr += tmp;
	}
	core->seek = addr;
	ret = r_core_block_read(core, 0);
	if (ret == -1)
		core->seek = tmp;
	return ret;
}
