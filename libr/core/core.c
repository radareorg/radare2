/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include "r_core.h"

static u64 num_callback(void *userptr, const char *str, int *ok)
{
	struct r_core_t *core = userptr;
	struct r_flag_item_t *flag;
	
	if (str[0]=='$') {
		switch(str[1]) {
		case '$': return core->seek;
		case 'b': return core->blocksize;
		//case '?': return core->blocksize; // HELP
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
	r_asm_set(&core->assembler, "asm_x86"); // XXX should be done by r_asm on init?
	r_asm_set_user_ptr(&core->assembler, core);
	r_parse_init(&core->parser);
	r_parse_set_user_ptr(&core->parser, core);
	r_bin_init(&core->bin);
	r_bininfo_init(&core->bininfo);
	r_bin_set_user_ptr(&core->bin, core);
	r_meta_init(&core->meta);
	r_cons_init();

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
	r_core_config_init(core);
	// XXX fix path here

	/* load plugins */
	r_core_loadlibs(core);

	return 0;
}

R_API struct r_core_t *r_core_free(struct r_core_t *c)
{
	free(c);
	return NULL;
}

int r_core_prompt(struct r_core_t *r)
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

int r_core_block_size(struct r_core_t *core, u32 bsize)
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

int r_core_block_read(struct r_core_t *core, int next)
{
	if (core->file == NULL)
		return -1;
	r_io_lseek(&core->io, core->file->fd, core->seek+((next)?core->blocksize:0), R_IO_SEEK_SET);
	return r_io_read(&core->io, core->file->fd, core->block, core->blocksize);
}

int r_core_seek_align(struct r_core_t *core, u64 align, int times)
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
	return r_core_seek(core, seek+diff);
}

/* TODO: add a parameter to read or not the block? optimization? */
int r_core_seek(struct r_core_t *core, u64 addr)
{
	u64 tmp = core->seek;
	int ret;
	core->seek = addr;
	ret = r_core_block_read(core, 0);
	if (ret == -1)
		core->seek = tmp;
	return ret;
}

int r_core_seek_delta(struct r_core_t *core, s64 addr)
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
