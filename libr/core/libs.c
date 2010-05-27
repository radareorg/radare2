/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include "r_core.h"

/* io callback */
static int __lib_io_cb(struct r_lib_plugin_t *pl, void *user, void *data) {
	struct r_io_plugin_t *hand = (struct r_io_plugin_t *)data;
	struct r_core_t *core = (struct r_core_t *)user;
	//printf(" * Added IO handler\n");
	r_io_plugin_add (core->io, hand);
	return R_TRUE;
}

static int __lib_io_dt(struct r_lib_plugin_t *pl, void *p, void *u) { return R_TRUE; }

/* cmd callback */
static int __lib_cmd_cb(struct r_lib_plugin_t *pl, void *user, void *data) {
	struct r_cmd_plugin_t *hand = (struct r_cmd_plugin_t *)data;
	struct r_core_t *core = (struct r_core_t *)user;
	//printf(" * Added CMD handler\n");
	r_cmd_plugin_add (core->cmd, hand);
	return R_TRUE;
}

static int __lib_cmd_dt(struct r_lib_plugin_t *pl, void *p, void *u) { return R_TRUE; }

/* debug callback */
static int __lib_dbg_cb(struct r_lib_plugin_t *pl, void *user, void *data) {
	struct r_debug_plugin_t *hand = (struct r_debug_plugin_t *)data;
	struct r_core_t *core = (struct r_core_t *)user;
	//printf(" * Added debugger handler\n");
	r_debug_plugin_add (core->dbg, hand);
	return R_TRUE;
}

static int __lib_dbg_dt(struct r_lib_plugin_t *pl, void *p, void *u) { return R_TRUE; }

/* breakpoint callback */
static int __lib_bp_cb(struct r_lib_plugin_t *pl, void *user, void *data)
{
	struct r_bp_plugin_t *hand = (struct r_bp_plugin_t *)data;
	struct r_core_t *core = (struct r_core_t *)user;
	//printf(" * Added bpger handler\n");
	r_bp_plugin_add (core->dbg->bp, hand);
	return R_TRUE;
}

static int __lib_bp_dt(struct r_lib_plugin_t *pl, void *p, void *u) { return R_TRUE; }

/* lang callback */
static int __lib_lng_cb(struct r_lib_plugin_t *pl, void *user, void *data) {
	struct r_lang_plugin_t *hand = (struct r_lang_plugin_t *)data;
	struct r_core_t *core = (struct r_core_t *)user;
	//printf(" * Added language handler\n");
	r_lang_add (core->lang, hand);
	return R_TRUE;
}

static int __lib_lng_dt(struct r_lib_plugin_t *pl, void *p, void *u) { return R_TRUE; }

/* anal callback */
static int __lib_anl_cb(struct r_lib_plugin_t *pl, void *user, void *data) {
	struct r_anal_plugin_t *hand = (struct r_anal_plugin_t *)data;
	struct r_core_t *core = (struct r_core_t *)user;
	//printf(" * Added analysis handler\n");
	r_anal_add (core->anal, hand);
	return R_TRUE;
}

static int __lib_anl_dt(struct r_lib_plugin_t *pl, void *p, void *u) { return R_TRUE; }

/* asm callback */
static int __lib_asm_cb(struct r_lib_plugin_t *pl, void *user, void *data) {
	struct r_asm_plugin_t *hand = (struct r_asm_plugin_t *)data;
	struct r_core_t *core = (struct r_core_t *)user;
	//printf(" * Added (dis)assembly handler\n");
	r_asm_add (core->assembler, hand);
	return R_TRUE;
}

static int __lib_asm_dt(struct r_lib_plugin_t *pl, void *p, void *u) { return R_TRUE; }

/* parse callback */
static int __lib_parse_cb(struct r_lib_plugin_t *pl, void *user, void *data) {
	struct r_parse_plugin_t *hand = (struct r_parse_plugin_t *)data;
	struct r_core_t *core = (struct r_core_t *)user;
	//printf(" * Added (dis)assembly handler\n");
	r_parse_add (core->parser, hand);
	return R_TRUE;
}

static int __lib_parse_dt(struct r_lib_plugin_t *pl, void *p, void *u) { return R_TRUE; }

/* bin callback */
static int __lib_bin_cb(struct r_lib_plugin_t *pl, void *user, void *data) {
	struct r_bin_plugin_t *hand = (struct r_bin_plugin_t *)data;
	struct r_core_t *core = (struct r_core_t *)user;
	//printf(" * Added (dis)assembly handler\n");
	r_bin_add (core->bin, hand);
	return R_TRUE;
}

static int __lib_bin_dt(struct r_lib_plugin_t *pl, void *p, void *u) { return R_TRUE; }

R_API int r_core_loadlibs_init(struct r_core_t *core) {
	/* initialize handlers */
	r_lib_add_handler (core->lib, R_LIB_TYPE_IO, "io plugins",
		&__lib_io_cb, &__lib_io_dt, core);
	r_lib_add_handler (core->lib, R_LIB_TYPE_CMD, "cmd plugins",
		&__lib_cmd_cb, &__lib_cmd_dt, core);
	r_lib_add_handler (core->lib, R_LIB_TYPE_DBG, "debug plugins",
		&__lib_dbg_cb, &__lib_dbg_dt, core);
	r_lib_add_handler (core->lib, R_LIB_TYPE_BP, "breakpoint plugins",
		&__lib_bp_cb, &__lib_bp_dt, core);
	r_lib_add_handler (core->lib, R_LIB_TYPE_LANG, "language plugins",
		&__lib_lng_cb, &__lib_lng_dt, core);
	r_lib_add_handler (core->lib, R_LIB_TYPE_ANAL, "analysis plugins",
		&__lib_anl_cb, &__lib_anl_dt, core);
	r_lib_add_handler (core->lib, R_LIB_TYPE_ASM, "(dis)assembly plugins",
		&__lib_asm_cb, &__lib_asm_dt, core);
	r_lib_add_handler (core->lib, R_LIB_TYPE_PARSE, "parsing plugins",
		&__lib_parse_cb, &__lib_parse_dt, core);
	r_lib_add_handler (core->lib, R_LIB_TYPE_BIN, "bin plugins",
		&__lib_bin_cb, &__lib_bin_dt, core);
	return R_TRUE;
}

R_API int r_core_loadlibs(struct r_core_t *core) {
	/* TODO: all those default plugin paths should be defined in r_lib */
	char *homeplugindir = r_str_home (".radare2/plugins");
	static int singleton = R_TRUE;
	core->lib = r_lib_new ("radare_plugin");
	if (singleton) {
		r_core_loadlibs_init (core);
		singleton = R_FALSE;
	}
	r_lib_opendir (core->lib, r_config_get (core->config, "dir.plugins"));
	r_lib_opendir (core->lib, getenv (R_LIB_ENV));
	r_lib_opendir (core->lib, ".");
	r_lib_opendir (core->lib, homeplugindir);
	r_lib_opendir (core->lib, LIBDIR"/radare2/");
	free (homeplugindir);
	return R_TRUE;
}
