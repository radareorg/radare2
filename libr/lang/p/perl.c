/* radare - LGPL - Copyright 2009 */
/*   pancake<nopcode.org> */
/*   nibble.ds<gmail.com> */
/* perl extension for libr (radare2) */

#include "r_lib.h"
#include "r_lang.h"

#include <EXTERN.h>
#include <XSUB.h>
#include <perl.h>

#include "r_core.h"
static struct r_core_t *core = NULL;

extern PerlInterpreter *my_perl;
PerlInterpreter *my_perl = NULL;

extern void xs_init (pTHX);

void radare_perl(pTHX_ CV* cv)
{
	char *cmd;
	dXSARGS;

	char *str;
	cmd = sv_pv(ST(0));
	str = r_core_cmd_str(core, cmd);
	ST(0) = newSVpvn(str, strlen(str));
	free(str);
	XSRETURN(1);
#if 0
	if (!config.debug) {
		char *str;
		cmd = sv_pv(ST(0));
		str = pipe_command_to_string(cmd);
		ST(0) = newSVpvn(str, strlen(str));
		free(str);
		XSRETURN(1);
	} else {
		char str[4096];
		// XXX pipe_stdout_to_tmp_file is a br0ken idea
		str[0]='\0';
		cmd = sv_pv(ST(0));
		if (! pipe_stdout_to_tmp_file(file, cmd) ) {
			ST(0) = newSVpvn("", 0);
			return;
		}
		fd = fopen(file, "r");
		if (fd == NULL) {
			fprintf(stderr, "Cannot open tmpfile\n");
			unlink(file);
			ST(0) = newSVpvn("", 0);
			return;
		} else {
			while(!feof(fd)) {
				fgets(buf, 1023, fd);
				if (feof(fd)) break;
				if (strlen(buf)+strlen(str)> 4000) {
					fprintf(stderr, "Input line too large\n");
					break;
				}
				strcat(str, buf);
			}
			fclose(fd);
		}
		unlink(file);
	}
#endif
}

void xs_init(pTHX)
{
	newXS("r", radare_perl, __FILE__);
}

static int init(void *user)
{
	core = user;
	my_perl = perl_alloc();
	if (my_perl == NULL) {
		printf("Cannot init perl module\n");
		return R_FALSE;
	}
	perl_construct(my_perl);

	return R_TRUE;
}

static int fini(void *user)
{
	perl_destruct(my_perl);
	perl_free(my_perl);
	my_perl = NULL;

	return R_TRUE;
}

/* TODO: handle multi-line */
static int prompt(void *user)
{
	char str[1025];

	/* prepare array */
	{
		char *perl_embed[] = { "", "-e", "0" };
		perl_parse(my_perl, xs_init, 3, perl_embed, (char **)NULL);
	}
	while(1) {
		printf("perl> ");
		fflush(stdout);
		fgets(str, 1023, stdin);
		if (feof(stdin))
			break;
		str[strlen(str)-1]='\0';
	 	if (!strcmp(str, "q"))
			break;
		eval_pv(str, TRUE);
	}

	return R_TRUE;
}

static int run(void *user, const char *code, int len)
{
	return R_TRUE;
}

static int run_file(void *user, const char *file)
{
	return R_TRUE;
}

static const char *help =
	"Perl plugin usage:\n"
	" print \"r(pd 10)\\n\";\n";

static struct r_lang_handle_t r_lang_plugin_perl = {
	.name = "perl",
	.desc = "Perl language extension",
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
	.data = &r_lang_plugin_perl,
};
