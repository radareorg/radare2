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

struct r_core_t *r_core_new()
{
	struct r_core_t *c = MALLOC_STRUCT(struct r_core_t);
	r_core_init(c);
	return c;
}

/* TODO: move to a separated file */
/* io callback */
int __lib_io_cb(struct r_lib_plugin_t *pl, void *user, void *data)
{
	struct r_io_handle_t *hand = (struct r_io_handle_t *)data;
	struct r_core_t *core = (struct r_core_t *)user;
	//printf(" * Added IO handler\n");
	r_io_handle_add(&core->io, hand);
	return R_TRUE;
}

int __lib_io_dt(struct r_lib_plugin_t *pl, void *p, void *u) { return R_TRUE; }

/* debug callback */
int __lib_dbg_cb(struct r_lib_plugin_t *pl, void *user, void *data)
{
	struct r_debug_handle_t *hand = (struct r_debug_handle_t *)data;
	struct r_core_t *core = (struct r_core_t *)user;
	//printf(" * Added debugger handler\n");
	r_debug_handle_add(&core->dbg, hand);
	return R_TRUE;
}

int __lib_dbg_dt(struct r_lib_plugin_t *pl, void *p, void *u) { return R_TRUE; }

/* lang callback */
int __lib_lng_cb(struct r_lib_plugin_t *pl, void *user, void *data)
{
	struct r_lang_handle_t *hand = (struct r_lang_handle_t *)data;
	struct r_core_t *core = (struct r_core_t *)user;
	//printf(" * Added language handler\n");
	r_lang_add(&core->lang, hand);
	return R_TRUE;
}

int __lib_lng_dt(struct r_lib_plugin_t *pl, void *p, void *u) { return R_TRUE; }

/* anal callback */
int __lib_anl_cb(struct r_lib_plugin_t *pl, void *user, void *data)
{
	struct r_anal_handle_t *hand = (struct r_anal_handle_t *)data;
	struct r_core_t *core = (struct r_core_t *)user;
	//printf(" * Added analysis handler\n");
	r_anal_add(&core->anal, hand);
	return R_TRUE;
}

int __lib_anl_dt(struct r_lib_plugin_t *pl, void *p, void *u) { return R_TRUE; }

/* asm callback */
int __lib_asm_cb(struct r_lib_plugin_t *pl, void *user, void *data)
{
	struct r_asm_handle_t *hand = (struct r_asm_handle_t *)data;
	struct r_core_t *core = (struct r_core_t *)user;
	//printf(" * Added (dis)assembly handler\n");
	r_asm_add(&core->assembler, hand);
	return R_TRUE;
}

int __lib_asm_dt(struct r_lib_plugin_t *pl, void *p, void *u) { return R_TRUE; }

int r_core_init(struct r_core_t *core)
{
	core->oobi = NULL;
	core->oobi_len = 0;
	core->num.callback = &num_callback;
	core->num.userptr = core;
	r_lang_init(&core->lang);
	r_lang_set_user_ptr(&core->lang, core);
	r_anal_init(&core->anal);
	r_anal_set_user_ptr(&core->anal, core);
	r_asm_init(&core->assembler);
	r_asm_set_user_ptr(&core->assembler, core);
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
	r_core_config_init(core);
	r_flag_init(&core->flags);
	r_debug_init(&core->dbg);
	r_lib_init(&core->lib, "radare_plugin");
	r_lib_add_handler(&core->lib, R_LIB_TYPE_IO, "io plugins",
		&__lib_io_cb, &__lib_io_dt, core);
	r_lib_add_handler(&core->lib, R_LIB_TYPE_DBG, "debug plugins",
		&__lib_dbg_cb, &__lib_dbg_dt, core);
	r_lib_add_handler(&core->lib, R_LIB_TYPE_LANG, "language plugins",
		&__lib_lng_cb, &__lib_lng_dt, core);
	r_lib_add_handler(&core->lib, R_LIB_TYPE_ANAL, "analysis plugins",
		&__lib_anl_cb, &__lib_anl_dt, core);
	r_lib_add_handler(&core->lib, R_LIB_TYPE_ASM, "(dis)assembly plugins",
		&__lib_asm_cb, &__lib_asm_dt, core);
	r_lib_opendir(&core->lib, getenv("LIBR_PLUGINS"));
	{
		char *homeplugindir = r_str_home(".radare/plugins");
		r_lib_opendir(&core->lib, homeplugindir);
		free(homeplugindir);
	}
	// XXX fix path here
	return 0;
}

struct r_core_t *r_core_free(struct r_core_t *c)
{
	free(c);
	return NULL;
}

int r_core_prompt(struct r_core_t *r)
{
	char prompt[32];
	char line[1024];
	int ret;

	char *cmdprompt = r_config_get(&r->config, "cmd.prompt");
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
		} else addr+=tmp;
	} else {
		/* check < 0 */
		if (tmp+addr<0) {
			addr = 0;
		} else addr+=tmp;
	}
	core->seek = addr;
	ret = r_core_block_read(core, 0);
	if (ret == -1)
		core->seek = tmp;
	return ret;
}
