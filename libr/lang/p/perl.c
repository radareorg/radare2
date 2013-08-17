/* radare - LGPL - Copyright 2009-2011 */
/*   pancake<nopcode.org> */
/*   nibble.ds<gmail.com> */
/* perl extension for libr (radare2) */

#include "r_lib.h"
#include "r_lang.h"

#include <EXTERN.h>
#include <XSUB.h>
#undef PL_madskills
#undef PL_xmlfp
#include <perl.h>

#undef U32_MAX
#undef U32_MIN

#undef LIST_HEAD
#include "r_core.h"
static struct r_core_t *core = NULL;

static PerlInterpreter *my_perl = NULL;

static void perl_radare_cmd(pTHX_ CV* cv) {
	char *cmd;
	char *str;
	dXSARGS;
	cmd = sv_pv(ST(0));
	str = r_core_cmd_str(core, cmd);
	ST(0) = newSVpvn(str, strlen(str));
	free(str);
	XSRETURN(1);
	str = (char *)(size_t)items; /* dummy unreachable code */
}

static void xs_init(pTHX) {
	newXS ("r", perl_radare_cmd, __FILE__);
}

static int init(struct r_lang_t *lang) {
	char *perl_embed[] = { "", "-e", "0" };
	core = lang->user;
	my_perl = perl_alloc ();
	if (my_perl == NULL) {
		printf("Cannot init perl module\n");
		return R_FALSE;
	}
	perl_construct (my_perl);
	perl_parse (my_perl, xs_init, 3, perl_embed, (char **)NULL);

	return R_TRUE;
}

static int fini(void *user) {
	perl_destruct (my_perl);
	perl_free (my_perl);
	my_perl = NULL;

	return R_TRUE;
}

static int run(void *user, const char *code, int len) {
	/* TODO: catcth errors */
	eval_pv (code, TRUE);
	return R_TRUE;
}

static int setargv(void *user, int argc, char **argv) {
	perl_parse (my_perl, xs_init, argc, argv, (char **)NULL);
	return R_TRUE;
}

static int setup(RLang *lang) {
	RListIter *iter;
	RLangDef *def;
	char cmd[128];
	// Segfault if already initialized ?
	//PyRun_SimpleString ("require r2/r_core.pl");
#warning TODO: implement setup in lang/perl
	core = lang->user;
	r_list_foreach (lang->defs, iter, def) {
		if (!def->type || !def->name)
			continue;
		if (!strcmp (def->type, "int"))
			snprintf (cmd, sizeof (cmd), "%s=%d", def->name, (int)(size_t)def->value);
		else if (!strcmp (def->type, "string"))
			snprintf (cmd, sizeof (cmd), "%s=\"%s\"", def->name, (char *)def->value);
		else snprintf (cmd, sizeof (cmd), "%s=%s.cast(%p)",
			def->name, def->type, def->value);
	//	PyRun_SimpleString (cmd);
	}
	return R_TRUE;
}

static const char *help =
	"Perl plugin usage:\n"
	" print \"r(\"pd 10\")\\n\";\n";

static struct r_lang_plugin_t r_lang_plugin_perl = {
	.name = "perl",
	.ext = "pl",
	.desc = "Perl language extension",
	.init = &init,
	.setup = &setup,
	.fini = (void *)&fini,
	.help = (void *)&help,
	.prompt = NULL,
	.run = (void *)&run,
	.run_file = NULL,
	.set_argv = (void *)setargv,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_LANG,
	.data = &r_lang_plugin_perl,
};
#endif
