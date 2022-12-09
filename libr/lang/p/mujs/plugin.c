/* lang.mujs plugin for r2 - 2022 - pancake */

#include <r_lib.h>
#include <r_core.h>
#include <r_lang.h>
#if USE_SYSMUJS
#include <mujs.h>
#else
#include "../../../shlr/mujs/one.c"
#endif
#include "jsapi.c"

typedef struct {
	js_State *J;
	RLangSession *s;
	RCore *core;
	// in case we need to store more data
} MujsContext;

static bool mujs_run(RLangSession *s, const char *code, int len) {
	MujsContext *ctx = s->plugin_data;
	js_State *J = ctx->J;
	const char *echo = strstr (code, "=")? "": "if (res != undefined) { console.log (res); }";
	char *nc = r_str_newf ("try { var res = (%s); %s } catch(e) { console.error(e); }", code, echo);
	js_dostring (J, nc);
	free (nc);
	return true;
}

static bool mujs_file(RLangSession *s, const char *file) {
	MujsContext *ctx = s->plugin_data;
	js_dofile (ctx->J, file);
	return true;
}

static void r2cmd(js_State *J) {
	MujsContext *ctx = J->uctx;
	const char *s = js_tostring (J, 1);
	if (s) {
		char *str = ctx->core->lang->cmd_str (ctx->core, s);
		// char *str = r_core_cmd_str (ctx->core, s);
		js_pushstring (J, str);
		free (str);
	} else {
		js_pushstring (J, "");
	}
}

static void r2call(js_State *J) {
	MujsContext *ctx = J->uctx;
	const char *s = js_tostring (J, 1);
	if (s) {
		ctx->core->lang->callf (ctx->core, "%s", s);
		js_pushundefined (J);
	} else {
		js_error(J, "string expected %s: %s", s, strerror (errno));
	}
}

static bool fini(RLangSession *s) {
	MujsContext *ctx = s->plugin_data;
	js_freestate (ctx->J);
	s->plugin_data = NULL;
	return NULL;
}

static void *init(RLangSession *s) {
	js_State *J = js_newstate (NULL, NULL, JS_STRICT);
	if (!J) {
		return NULL;
	}
	js_newcfunction (J, jsB_b64, "b64", 1);
	js_setglobal (J, "b64");
	js_newcfunction (J, r2cmd, "r2cmd", 1);
	js_setglobal (J, "r2cmd");
	js_newcfunction (J, r2call, "r2call", 1);
	js_setglobal (J, "r2call");

	js_newcfunction (J, jsB_read, "readFileSync", 1);
	js_setglobal (J, "readFileSync");
	js_newcfunction (J, jsB_write, "writeFileSync", 1);
	js_setglobal (J, "writeFileSync");
	js_dostring (J, fs_js);

	js_dostring (J, r2_js);
	js_dostring (J, require_js);
	js_dostring (J, stacktrace_js);
	js_dostring (J, "var global = {}; var G = global;");

	js_newcfunction (J, jsB_print, "print", 0);
	js_setglobal (J, "print");
	js_dostring (J, console_js);

	js_newcfunction(J, jsB_gc, "gc", 0);
	js_setglobal(J, "gc");

	MujsContext *ctx = R_NEW0 (MujsContext);
	if (ctx) {
		ctx->s = s;
		ctx->J = J;
		ctx->core = s->lang->user;
		J->uctx = ctx;
	}
	return ctx;
}

static RLangPlugin r_lang_plugin_mujs = {
	.name = "mujs",
	.ext = "mujs",
	.desc = "Ghostscripts mujs interpreter (ES5)",
	.license = "MIT",
	.run = mujs_run,
	.init = init,
	.fini = fini,
	.run_file = mujs_file,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_LANG,
	.data = &r_lang_plugin_mujs,
};
#endif
