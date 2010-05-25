/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */
/* ruby extension for libr (radare2) */

#include "r_lib.h"
#include "r_lang.h"
#include "ruby.h"

// XXX
//#define RUBYAPI  LIBDIR"/ruby1.8/radare.rb"
#define RUBYAPI  "/usr/lib/radare2/radare.rb"

#include "r_core.h"
static struct r_core_t *core = NULL;

static VALUE radare_ruby_cmd(VALUE self, VALUE string)
{
	const char *retstr;
	Check_Type(string, T_STRING);
	retstr = r_core_cmd_str(core, RSTRING(string)->ptr);
	if (retstr == NULL || retstr[0]=='\0')
		return rb_str_new2("");
	return rb_str_new2(retstr);
}

static int run(void *user, const char *code, int len)
{
	int err, ret = R_TRUE;
	rb_eval_string_protect(code, &err);
	if (err != 0) {
		printf("error %d handled\n", err);
		ret = R_FALSE;
	}
	return ret;
}

static int slurp_ruby(const char *file)
{
	if (r_file_exist(file)) {
		rb_load_file(file);
		ruby_exec();
		return R_TRUE;
	}
	eprintf("lang_ruby: Cannot open '%s'\n", file);
	return R_FALSE;
}

static int run_file(void *user, const char *file)
{
	return slurp_ruby(file);
}

static int init(void *user)
{
	VALUE rb_RadareCmd;

	ruby_init();
	ruby_init_loadpath();

	rb_eval_string_protect("require 'irb'", NULL);
	core = user;
	rb_RadareCmd = rb_define_class("RadareInternal", rb_cObject);
	rb_define_method(rb_RadareCmd, "cmd", radare_ruby_cmd, 1);
	rb_eval_string_protect("$r = RadareInternal.new()", NULL);

	if (!slurp_ruby(RUBYAPI)) {
		printf("[ruby] error loading ruby api\n");
		//return R_FALSE;
	}
	return R_TRUE;
}

static int prompt(void *user)
{
	int err;
	rb_eval_string_protect("IRB.start();", &err);
	if (err != 0)
		return R_FALSE;
	return R_TRUE;
}

static int fini(void *user)
{
	ruby_finalize();
	return R_TRUE;
}

static const char *help =
	"Ruby plugin usage:\n"
	" $r = RadareInternal.new()\n"
	" bytes = $r.cmd(\"p8 10\");\n";

static struct r_lang_plugin_t r_lang_plugin_ruby = {
	.name = "ruby",
	.desc = "Ruby language extension",
	.init = &init,
	.fini = &fini,
	.help = &help,
	.prompt = &prompt,
	.run = &run,
	.run_file = &run_file,
	.set_argv = NULL,
};

struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_LANG,
	.data = &r_lang_plugin_ruby,
};
