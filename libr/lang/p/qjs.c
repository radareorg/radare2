/* radare - LGPL - Copyright 2020-2022 pancake */

#define CONFIG_BIGNUM 0

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <r_lib.h>
#include <r_core.h>
#include <r_config.h>
#include <r_lang.h>

#define countof(x) (sizeof (x) / sizeof ((x)[0]))

#include "quickjs.h"

typedef struct {
	JSContext *ctx;
	JSRuntime *r;
	RCore *core;
} QjsContext;

static bool eval(JSContext *ctx, const char *code);

static void js_dump_obj(JSContext *ctx, FILE *f, JSValueConst val) {
	const char *str = JS_ToCString (ctx, val);
	if (str) {
		fprintf (f, "%s\n", str);
		JS_FreeCString (ctx, str);
	} else {
		fprintf (f, "[exception]\n");
	}
}

static void js_std_dump_error1(JSContext *ctx, JSValueConst exception_val) {
	JSValue val;
	bool is_error;

	is_error = JS_IsError (ctx, exception_val);
	js_dump_obj (ctx, stderr, exception_val);
	if (is_error) {
		val = JS_GetPropertyStr (ctx, exception_val, "stack");
		if (!JS_IsUndefined (val)) {
			js_dump_obj (ctx, stderr, val);
		}
		JS_FreeValue (ctx, val);
	}
}

void js_std_dump_error(JSContext *ctx) {
	JSValue exception_val;
	exception_val = JS_GetException (ctx);
	js_std_dump_error1 (ctx, exception_val);
	JS_FreeValue (ctx, exception_val);
}

static JSValue r2log(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	size_t plen;
	const char *n = JS_ToCStringLen2 (ctx, &plen, argv[0], false);
	r_cons_printf ("%s\n", n);
	return JS_NewBool (ctx, true);
}

static JSValue r2error(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	size_t plen;
	const char *n = JS_ToCStringLen2 (ctx, &plen, argv[0], false);
	eprintf ("%s\n", n);
	return JS_NewBool (ctx, true);
}

static JSValue r2cmd(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	JSRuntime *rt = JS_GetRuntime (ctx);
	QjsContext *k = JS_GetRuntimeOpaque (rt);
	size_t plen;
	const char *n = JS_ToCStringLen2 (ctx, &plen, argv[0], false);
	char *ret = k->core->lang->cmd_str (k->core, n);
	return JS_NewString (ctx, r_str_get (ret));
}

static JSValue r2cmdj(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	JSRuntime *rt = JS_GetRuntime (ctx);
	QjsContext *k = JS_GetRuntimeOpaque (rt);
	size_t plen;
	const char *n = JS_ToCStringLen2 (ctx, &plen, argv[0], false);
	char *ret = k->core->lang->cmd_str (k->core, n);
	JSValue ns = JS_NewString (ctx, r_str_get (ret));
	return ns;
}

static const JSCFunctionListEntry js_r2_funcs[] = {
	JS_CFUNC_DEF ("cmd", 1, r2cmd),
	JS_CFUNC_DEF ("cmdj", 1, r2cmdj),
	JS_CFUNC_DEF ("log", 1, r2log),
	JS_CFUNC_DEF ("error", 1, r2error),
};

static int js_r2_init(JSContext *ctx, JSModuleDef *m) {
	return JS_SetModuleExportList (ctx, m, js_r2_funcs, countof (js_r2_funcs));
}

static JSContext *JS_NewCustomContext(JSRuntime *rt);

static JSValue js_print(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	int i;
	const char *str;
	size_t len;

	for (i = 0; i < argc; i++) {
		if (i != 0) {
			putchar (' ');
		}
		str = JS_ToCStringLen (ctx, &len, argv[i]);
		if (!str) {
			return JS_EXCEPTION;
		}
		fwrite (str, 1, len, stdout);
		JS_FreeCString (ctx, str);
	}
	putchar ('\n');
	return JS_UNDEFINED;
}

static void register_helpers(JSContext *ctx) {
#if 0
	JSRuntime *rt = JS_GetRuntime (ctx);
	js_std_set_worker_new_context_func (JS_NewCustomContext);
	js_std_init_handlers (rt);

	JS_SetModuleLoaderFunc (rt, NULL, js_module_loader, NULL);
#endif
	JSModuleDef *m = JS_NewCModule (ctx, "r2", js_r2_init);
	if (!m) {
		return;
	}
	js_r2_init (ctx, m);
	JS_AddModuleExportList (ctx, m, js_r2_funcs, countof (js_r2_funcs));
	JSValue global_obj = JS_GetGlobalObject (ctx);
	JS_SetPropertyStr (ctx, global_obj, "print",
		JS_NewCFunction (ctx, js_print, "print", 1));
	JS_SetPropertyStr (ctx, global_obj, "r2cmd",
		JS_NewCFunction (ctx, r2cmd, "r2cmd", 1));
	JS_SetPropertyStr (ctx, global_obj, "r2log",
		JS_NewCFunction (ctx, r2log, "r2log", 1));
	eval (ctx, "function dir(x) {"
		"console.log(JSON.stringify(x).replace(/,/g,',\\n '));"
		"for (var i in x) {console.log(i);}}");
	eval(ctx, "var console = { log:print, error:print, debug:print };");
	eval(ctx, "var r2 = { log:r2log, cmd:r2cmd, cmdj:(x)=>JSON.parse(r2cmd(x))};");
	eval(ctx, "var global = globalThis;");
}

static JSContext *JS_NewCustomContext(JSRuntime *rt) {
	JSContext *ctx = JS_NewContext (rt);
	// JSContext *ctx = JS_NewContextRaw (rt);
	if (!ctx) {
		return NULL;
	}
#if CONFIG_BIGNUM
	JS_AddIntrinsicBigFloat (ctx);
	JS_AddIntrinsicBigDecimal (ctx);
	JS_AddIntrinsicOperators (ctx);
	JS_EnableBignumExt (ctx, true);
#endif
	register_helpers (ctx);
	return ctx;
}

static void eval_jobs(JSContext *ctx) {
	JSRuntime *rt = JS_GetRuntime (ctx);
	JSContext * pctx = NULL;
	do {
		int res = JS_ExecutePendingJob (rt, &pctx);
		if (res == -1) {
			eprintf ("exception in job%c", 10);
		}
	} while (pctx);
}

static bool eval(JSContext *ctx, const char *code) {
	JSValue v = JS_Eval (ctx, code, strlen (code), "-", 0);
	if (JS_IsException (v)) {
		js_std_dump_error (ctx);
		JSValue e = JS_GetException (ctx);
		js_dump_obj (ctx, stderr, e);
	}
	eval_jobs (ctx);
	JS_FreeValue (ctx, v);
	return true;
}

static bool lang_quickjs_run(RLangSession *s, const char *code, int len) {
	r_return_val_if_fail (s && code, false);
	QjsContext *k = s->plugin_data;
	return eval (k->ctx, code);
}

static bool lang_quickjs_file(RLangSession *s, const char *file) {
	QjsContext *k = s->plugin_data;
	bool rc = false;
	char *code = r_file_slurp (file, NULL);
	if (code) {
		rc = eval (k->ctx, code) == 0;
		free (code);
	}
	return rc;
}

static void *init(RLangSession *s) {
	QjsContext *k = R_NEW0 (QjsContext);
	if (k) {
		JSRuntime *rt = JS_NewRuntime ();
		JS_SetRuntimeOpaque (rt, k);
		k->r = rt;
		k->ctx = JS_NewCustomContext (rt);
		register_helpers (k->ctx);
		k->core = s->lang->user;
	}
	s->plugin_data = k; // implicit
	return k;
}

static bool fini(RLangSession *s) {
	QjsContext *k = s->plugin_data;
	s->plugin_data = NULL;
	JS_FreeContext (k->ctx);
	k->ctx = NULL;
	// XXX this is segfaulting JS_FreeRuntime (k->r);
	k->r = NULL;
	free (k);
	return NULL;
}

static RLangPlugin r_lang_plugin_qjs = {
	.name = "qjs",
	.ext = "qjs",
	.license = "MIT",
	.desc = "JavaScript extension language using QuicKJS",
	.run = lang_quickjs_run,
	.run_file = lang_quickjs_file,
	.init = init,
	.fini = fini,
};

#if !CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_LANG,
	.data = &r_lang_plugin_qjs,
	.version = R2_VERSION
};
#endif
