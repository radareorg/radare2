/* radare - LGPL - Copyright 2020-2023 pancake */

#include <r_lib.h>
#include <r_core.h>

#define countof(x) (sizeof (x) / sizeof ((x)[0]))

#include "quickjs.h"
#include "../js_require.c"
#include "../js_r2papi.c"

typedef struct {
	RCore *core;
	char *name; // if name != NULL its a plugin reference
	JSRuntime *r;
	JSContext *ctx;
	JSValue func;
} QjsContext;

// XXX remove globals
static R_TH_LOCAL RList *Glist = NULL;
static R_TH_LOCAL int Gplug = 0;

static void qjsctx_free_item(QjsContext *c) {
	if (c) {
		free (c->name);
		free (c);
	}
}

static QjsContext *qjsctx_find(RCore *core, const char *name) {
	r_return_val_if_fail (core, NULL);
	QjsContext *qc;
	RListIter *iter;
	r_list_foreach (Glist, iter, qc) {
		if (name && core) {
			if (qc->core == core && qc->name && !strcmp (qc->name, name)) {
				return qc;
			}
		} else if (qc->core == core) {
			return qc;
		}
	}
	return NULL;
}

static QjsContext *qjsctx_add(RCore *core, const char *name, JSContext *ctx, JSValue func) {
	QjsContext *qc = R_NEW0 (QjsContext);
	if (qc) {
		qc->name = name? strdup (name): NULL;
		qc->core = core;
		qc->ctx = ctx;
		qc->func = func;
		if (!Glist) {
			Glist = r_list_newf ((RListFree)qjsctx_free_item);
		}
		r_list_append (Glist, qc);
	}
	return qc;
}

static bool qjsctx_del(RCore *core, const char *name) {
	r_return_val_if_fail (core && name, false);
	QjsContext *qc;
	RListIter *iter;
	r_list_foreach (Glist, iter, qc) {
		if (qc->core == core && name && qc->name && !strcmp (qc->name, name)) {
			r_list_delete (Glist, iter);
			return true;
		}
	}
	return false;
}

static void qjsctx_free(void) {
	r_list_free (Glist);
	Glist = NULL;
}

///////////////////////////////////////////////////////////

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

static JSValue b64(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	size_t plen;
	bool decode = false;
	if (argc > 1) {
		decode = true;
	}
	char *ret = NULL;
	if (argc > 0) {
		const char *n = JS_ToCStringLen2 (ctx, &plen, argv[0], false);
		if (R_STR_ISNOTEMPTY (n)) {
			if (decode) {
				int res = 0;
				ut8 *bret = sdb_decode (n, &res);
				ret = r_str_ndup ((const char *)bret, res);
				free (bret);
			} else {
				ret = sdb_encode ((const ut8*)n, -1);
			}
		}
	}
	JSValue v = JS_NewString (ctx, r_str_get (ret));
	free (ret);
	return v;
}

static int r2plugin_core_call2(QjsContext *qc, RCore *core, const char *input) {
	// ceprintf ("CALL2\n");
	if (!qc || !qc->ctx) {
		return 0;
	}
	JSValueConst args[1] = {
		JS_NewString (qc->ctx, input)
	};
	JSValue res = JS_Call (qc->ctx, qc->func, JS_UNDEFINED, countof (args), args);
	return JS_ToBool (qc->ctx, res) == 1;
}

// R2_590 - XXX this is a hack to not break the ABI
#define MAXPLUGS 5
static R_TH_LOCAL QjsContext *GcallsData[MAXPLUGS] = { NULL };
typedef int (*CallX)(void *, const char *);
static int call0(void *c, const char *i) { return r2plugin_core_call2 (GcallsData[0], c, i); }
static int call1(void *c, const char *i) { return r2plugin_core_call2 (GcallsData[1], c, i); }
static int call2(void *c, const char *i) { return r2plugin_core_call2 (GcallsData[2], c, i); }
static int call3(void *c, const char *i) { return r2plugin_core_call2 (GcallsData[3], c, i); }
static int call4(void *c, const char *i) { return r2plugin_core_call2 (GcallsData[4], c, i); }
static const CallX Gcalls[MAXPLUGS] = { &call0, &call1, &call2, &call3, &call4 };

#if 0
static int r2plugin_core_call(void *_core, const char *input) {
	return r2_plugin_core_call2 (NULL, _core, input);
#if 0
	QjsContext *qc = qjsctx_find (_core, "qjs-example");
	if (!qc) {
		R_LOG_WARN ("Internal error, cannot find the qjs context");
		return 0;
	}
	if (!qc->name) {
		return 0;
	}
	JSValueConst args[1] = {
		JS_NewString (qc->ctx, input)
	};
	JSValue res = JS_Call (qc->ctx, qc->func, JS_UNDEFINED, countof (args), args);
	return JS_ToBool (qc->ctx, res) == 1;
#endif
}
#endif

static JSValue r2plugin_core(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	JSRuntime *rt = JS_GetRuntime (ctx);
	QjsContext *k = JS_GetRuntimeOpaque (rt);
	RCore *core = k->core;

	if (argc != 2) {
		return JS_ThrowRangeError (ctx, "r2.plugin expects two arguments");
	}

	JSValueConst args[1] = {
		JS_NewString (ctx, ""),
	};
	JSValue res = JS_Call (ctx, argv[1], JS_UNDEFINED, countof (args), args);

	// check if res is an object
	if (!JS_IsObject (res)) {
		return JS_ThrowRangeError (ctx, "r2.plugin function must return an object");
	}

	RCorePlugin *ap = R_NEW0 (RCorePlugin);
	if (!ap) {
		return JS_ThrowRangeError (ctx, "heap stuff");
	}
	JSValue name = JS_GetPropertyStr (ctx, res, "name");
	size_t namelen;
	const char *nameptr = JS_ToCStringLen2 (ctx, &namelen, name, false);
	if (nameptr) {
		ap->name = strdup (nameptr);
	} else {
		R_LOG_WARN ("r2.plugin requires the function to return an object with the `name` field");
		return JS_NewBool (ctx, false);
	}
	JSValue desc = JS_GetPropertyStr (ctx, res, "desc");
	const char *descptr = JS_ToCStringLen2 (ctx, &namelen, desc, false);
	if (descptr) {
		ap->desc = strdup (descptr);
	}
	JSValue license = JS_GetPropertyStr (ctx, res, "license");
	const char *licenseptr = JS_ToCStringLen2 (ctx, &namelen, license, false);
	if (licenseptr) {
		ap->license = strdup (licenseptr);
	}
	JSValue func = JS_GetPropertyStr (ctx, res, "call");
	if (!JS_IsFunction (ctx, func)) {
		R_LOG_WARN ("r2.plugin requires the function to return an object with the `call` field to be a function");
		// return JS_ThrowRangeError (ctx, "r2.plugin requires the function to return an object with the `call` field to be a function");
		return JS_NewBool (ctx, false);
	}

	QjsContext *qc = qjsctx_find (core, ap->name);
	if (qc) {
		R_LOG_WARN ("r2.plugin with name %s is already registered", ap->name);
		free ((char*)ap->name);
		free (ap);
		// return JS_ThrowRangeError (ctx, "r2.plugin core already registered (only one exists)");
		return JS_NewBool (ctx, false);
	}
	if (Gplug >= MAXPLUGS) {
		R_LOG_WARN ("Maximum number of plugins loaded! this is a limitation induced by the");
		return JS_NewBool (ctx, false);
	}
	qc = qjsctx_add (core, nameptr, ctx, func);
	ap->call = Gcalls[Gplug];
	GcallsData[Gplug] = qc;
	Gplug++;

	int ret = -1;
	RLibStruct *lib = R_NEW0 (RLibStruct);
	if (lib) {
		lib->type = R_LIB_TYPE_CORE;
		lib->data = ap;
		lib->version = R2_VERSION;
		ret = r_lib_open_ptr (core->lib, nameptr, NULL, lib);
	}
	return JS_NewBool (ctx, ret == 0);
}

static JSValue r2plugin(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	size_t plen;
	const char *n = JS_ToCStringLen2 (ctx, &plen, argv[0], false);
	if (R_STR_ISNOTEMPTY (n)) {
		if (!strcmp (n, "core")) {
			// { name: string, call: function, license: string, desc: string }
			// JSValue val =
			return r2plugin_core (ctx, this_val, argc, argv);
		} else {
			// invalid throw exception here
			return JS_ThrowRangeError(ctx, "invalid r2plugin type");
		}
	}
	return JS_NewBool (ctx, false);
}

static JSValue r2plugin_unload(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	if (argc != 1 || !JS_IsString (argv[0])) {
		return JS_ThrowRangeError(ctx, "r2.unload takes only one string as argument");
	}
	JSRuntime *rt = JS_GetRuntime (ctx);
	QjsContext *k = JS_GetRuntimeOpaque (rt);
	size_t plen;
	const char *name = JS_ToCStringLen2 (ctx, &plen, argv[0], false);
	k->core->lang->cmdf (k->core, "L-%s", name);
	bool res = qjsctx_del (k->core, name);
	// invalid throw exception here
	// return JS_ThrowRangeError(ctx, "invalid r2plugin type");
	return JS_NewBool (ctx, res);
}

// WIP experimental
static JSValue r2cmd0(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	JSRuntime *rt = JS_GetRuntime (ctx);
	QjsContext *k = JS_GetRuntimeOpaque (rt);
	size_t plen;
	const char *n = JS_ToCStringLen2 (ctx, &plen, argv[0], false);
	int ret = 0;
	if (R_STR_ISNOTEMPTY (n)) {
		ret = k->core->lang->cmdf (k->core, "%s@e:scr.null=true", n);
	}
	// JS_FreeValue (ctx, argv[0]);
	return JS_NewInt32 (ctx, ret);
}

// WIP experimental
static JSValue r2call0(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	JSRuntime *rt = JS_GetRuntime (ctx);
	QjsContext *k = JS_GetRuntimeOpaque (rt);
	size_t plen;
	const char *n = JS_ToCStringLen2 (ctx, &plen, argv[0], false);
	int ret = 0;
	if (R_STR_ISNOTEMPTY (n)) {
		k->core->lang->cmdf (k->core, "\"\"e scr.null=true");
		ret = k->core->lang->cmdf (k->core, "\"\"%s", n);
		k->core->lang->cmdf (k->core, "\"\"e scr.null=false");
	}
	// JS_FreeValue (ctx, argv[0]);
	return JS_NewInt32 (ctx, ret);
}

static JSValue r2cmd(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	JSRuntime *rt = JS_GetRuntime (ctx);
	QjsContext *k = JS_GetRuntimeOpaque (rt);
	size_t plen;
	const char *n = JS_ToCStringLen2 (ctx, &plen, argv[0], false);
	char *ret = NULL;
	if (R_STR_ISNOTEMPTY (n)) {
		ret = k->core->lang->cmd_str (k->core, n);
	}
	// JS_FreeValue (ctx, argv[0]);
	return JS_NewString (ctx, r_str_get (ret));
}

static JSValue js_write(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
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
		if (len > 0) {
			fwrite (str, 1, len, stdout);
		}
		JS_FreeCString (ctx, str);
	}
	return JS_UNDEFINED;
}

static JSValue js_flush(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	r_cons_flush ();
	fflush (stdout);
	return JS_UNDEFINED;
}

static JSValue js_print(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	JSValue a = js_write (ctx, this_val, argc, argv);
	putchar ('\n');
	return a;
}

static JSValue js_os_read_write(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv, int magic) {
	int fd;
	uint64_t pos, len;
	size_t size;
	int ret;

	if (JS_ToInt32 (ctx, &fd, argv[0])) {
		return JS_EXCEPTION;
	}
	if (JS_ToIndex (ctx, &pos, argv[2])) {
		return JS_EXCEPTION;
	}
	if (JS_ToIndex(ctx, &len, argv[3])) {
		return JS_EXCEPTION;
	}
	uint8_t *buf = JS_GetArrayBuffer(ctx, &size, argv[1]);
	if (!buf) {
		return JS_EXCEPTION;
	}
	if (pos + len > size) {
		return JS_ThrowRangeError(ctx, "read/write array buffer overflow");
	}
	if (magic) {
		ret = write (fd, buf + pos, len);
	} else {
		ret = read (fd, buf + pos, len);
	}
	return JS_NewInt64 (ctx, ret);
}



static const JSCFunctionListEntry js_os_funcs[] = {
	JS_CFUNC_MAGIC_DEF ("read", 4, js_os_read_write, 0 ),
	JS_CFUNC_MAGIC_DEF ("write", 4, js_os_read_write, 1 ),
#if 0
	JS_CFUNC_MAGIC_DEF("setReadHandler", 2, js_os_setReadHandler, 0 ),
	JS_CFUNC_DEF("setTimeout", 2, js_os_setTimeout ),
	JS_CFUNC_DEF("clearTimeout", 1, js_os_clearTimeout ),
#endif
	// JS_CFUNC_DEF("open", 2, js_os_open ),
	// OS_FLAG(O_RDONLY),
};

static int js_os_init(JSContext *ctx, JSModuleDef *m) {
	return JS_SetModuleExportList(ctx, m, js_os_funcs,
			countof(js_os_funcs));
}

JSModuleDef *js_init_module_os(JSContext *ctx, const char *module_name) {
	JSModuleDef *m = JS_NewCModule (ctx, module_name, js_os_init);
	if (m) {
		JS_AddModuleExportList (ctx, m, js_os_funcs, countof(js_os_funcs));
	}
	return m;
}

static const JSCFunctionListEntry js_r2_funcs[] = {
	JS_CFUNC_DEF ("cmd", 1, r2cmd),
	JS_CFUNC_DEF ("plugin", 2, r2plugin),
	JS_CFUNC_DEF ("unload", 1, r2plugin_unload),
	// JS_CFUNC_DEF ("cmdj", 1, r2cmdj), // can be implemented in js
	JS_CFUNC_DEF ("log", 1, r2log),
	JS_CFUNC_DEF ("error", 1, r2error),
	JS_CFUNC_DEF ("cmd0", 1, r2cmd0),
	// implemented in js JS_CFUNC_DEF ("call", 1, r2call);
	JS_CFUNC_DEF ("call0", 1, r2call0),
};

static int js_r2_init(JSContext *ctx, JSModuleDef *m) {
	return JS_SetModuleExportList (ctx, m, js_r2_funcs, countof (js_r2_funcs));
}

JSModuleDef *js_init_module_r2(JSContext *ctx, const char *module_name) {
	JSModuleDef *m = JS_NewCModule (ctx, module_name, js_r2_init);
	if (m) {
		JSValue global_obj = JS_GetGlobalObject (ctx);
		JSValue name = JS_NewString(ctx, "r2");
		JSValue v = JS_NewObjectProtoClass(ctx, name, 0);
		JS_SetPropertyStr (ctx, global_obj, "r2", v);
		JS_SetPropertyFunctionList(ctx, v, js_r2_funcs, countof(js_r2_funcs));
		// JS_AddModuleExportList (ctx, m, js_r2_funcs, countof(js_r2_funcs));
	}
	return m;
}

static void register_helpers(JSContext *ctx) {
#if 0
	JSRuntime *rt = JS_GetRuntime (ctx);
	js_std_set_worker_new_context_func (JS_NewCustomContext);
	js_std_init_handlers (rt);

	JS_SetModuleLoaderFunc (rt, NULL, js_module_loader, NULL);
#endif
	/*
	JSModuleDef *m = JS_NewCModule (ctx, "r2", js_r2_init);
	if (!m) {
		return;
	}
	js_r2_init (ctx, m);
	*/
	js_init_module_os (ctx, "os");
	js_init_module_r2 (ctx, "r2");
	// JS_AddModuleExportList (ctx, m, js_r2_funcs, countof (js_r2_funcs));
	JSValue global_obj = JS_GetGlobalObject (ctx);
	// JS_SetPropertyStr (ctx, global_obj, "r2", global_obj); // JS_NewCFunction (ctx, b64, "b64", 1));
	JS_SetPropertyStr (ctx, global_obj, "b64", JS_NewCFunction (ctx, b64, "b64", 1));
	// r2cmd deprecate . we have r2.cmd already same for r2log
	JS_SetPropertyStr (ctx, global_obj, "r2cmd", JS_NewCFunction (ctx, r2cmd, "r2cmd", 1));
	JS_SetPropertyStr (ctx, global_obj, "r2log", JS_NewCFunction (ctx, r2log, "r2log", 1));
	JS_SetPropertyStr (ctx, global_obj, "write", JS_NewCFunction (ctx, js_write, "write", 1));
	JS_SetPropertyStr (ctx, global_obj, "flush", JS_NewCFunction (ctx, js_flush, "flush", 1));
	JS_SetPropertyStr (ctx, global_obj, "print", JS_NewCFunction (ctx, js_print, "print", 1));
	eval (ctx, "setTimeout = (x,y) => x();");
	eval (ctx, "function dump(x) {"
		"if (typeof x==='object' && Object.keys(x)[0] != '0') { for (let k of Object.keys(x)) { console.log(k);}} else "
		"if (typeof x==='number'&& x > 0x1000){console.log(R.hex(x));}else"
		"{console.log((typeof x==='string')?x:JSON.stringify(x, null, 2));}"
		"}");
	eval (ctx, "var console = { log:print, error:print, debug:print };");
	eval (ctx, "r2.cmdj = (x) => JSON.parse(r2.cmd(x));");
	eval (ctx, "r2.call = (x) => r2.cmd('\"\"' + x);");
	eval (ctx, "r2.callj = (x)=> JSON.parse(r2.call(x));");
	eval (ctx, "var global = globalThis; var G = globalThis;");
	eval (ctx, js_require_qjs);
	eval (ctx, "var exports = {};");
	eval (ctx, "G.R2Pipe=() => R.r2;");
	if (!r_sys_getenv_asbool ("R2_DEBUG_NOPAPI")) {
		eval (ctx, js_r2papi_qjs);
		eval (ctx, "R=G.R=new R2Papi(r2);");
	} else {
		eval (ctx, "R=r2;");
	}
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
	JSContext *pctx = NULL;
	do {
		int res = JS_ExecutePendingJob (rt, &pctx);
		if (res == -1) {
			eprintf ("exception in job\n");
		}
	} while (pctx);
}

static bool eval(JSContext *ctx, const char *code) {
	if (R_STR_ISEMPTY (code)) {
		return false;
	}
	bool wantRaw = strstr (code, "termInit(");
	if (wantRaw) {
		r_cons_set_raw (true);
	}
	JSValue v = JS_Eval (ctx, code, strlen (code), "-", 0);
	if (JS_IsException (v)) {
		js_std_dump_error (ctx);
		JSValue e = JS_GetException (ctx);
		js_dump_obj (ctx, stderr, e);
	}
	eval_jobs (ctx);
	if (wantRaw) {
		r_cons_set_raw (false);
	}
	// restore raw console
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
		rc = true;
	}
	return rc;
}

static void *init(RLangSession *ls) {
	RCore *core = (RCore *)ls->lang->user;
	JSRuntime *rt = JS_NewRuntime ();
	JSContext *ctx = JS_NewCustomContext (rt);
	JSValue jv = JS_NewBool (ctx, false); // fake function
	QjsContext *qc = qjsctx_add (core, NULL, ctx, jv);
	if (qc) {
		qc->r = rt;
		qc->core = ls->lang->user;
		JS_SetRuntimeOpaque (rt, qc);
		// XXX we still have a global list of plugins.. we can probably use this pointer to hold everything
		ls->plugin_data = qc; // implicit
	}
	return qc;
}

static bool fini(RLangSession *s) {
	QjsContext *k = s->plugin_data;
	s->plugin_data = NULL;
	JS_FreeContext (k->ctx);
	k->ctx = NULL;
	k->r = NULL;
	qjsctx_free ();
// 	free (k);
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
