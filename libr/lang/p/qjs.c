/* radare - LGPL - Copyright 2020-2024 pancake */

#include <r_lib.h>
#include <r_core.h>
#include <r_vec.h>

#define countof(x) (sizeof (x) / sizeof ((x)[0]))

#include "quickjs.h"
#include "../js_require.c"
#include "../js_r2papi.c"
#define QJS_STRING(x) JS_NewString(ctx, x)

typedef struct {
	R_BORROW JSContext *ctx;
	JSValue call_func;
} QjsContext;
#define QJS_CORE_MAGIC 0x07534617

typedef struct qjs_core_plugin {
	char *name;
	QjsContext qctx;
	// void *data;  // can be added later if needed
} QjsCorePlugin;

typedef struct qjs_arch_plugin_t {
	char *name;
	char *arch;
	R_BORROW JSContext *ctx;
	JSValue decode_func;
	// JSValue encode_func;
} QjsArchPlugin;

typedef struct qjs_io_plugin_t {
	char *name;
	RIOPlugin *iop;
	R_BORROW JSContext *ctx;
	JSValue fn_check_js;
	JSValue fn_open_js;
	JSValue fn_seek_js;
	JSValue fn_read_js;
	JSValue fn_close_js;
	JSValue fn_system_js;
	// JSValue encode_func;
} QjsIoPlugin;

static void core_plugin_fini(QjsCorePlugin *cp) {
	free (cp->name);
}

static void arch_plugin_fini(QjsArchPlugin *ap) {
	free (ap->name);
	free (ap->arch);
}

R_VEC_TYPE_WITH_FINI (RVecCorePlugin, QjsCorePlugin, core_plugin_fini);
R_VEC_TYPE_WITH_FINI (RVecArchPlugin, QjsArchPlugin, arch_plugin_fini);
R_VEC_TYPE (RVecIoPlugin, QjsIoPlugin); // R2_590 add finalizer function

typedef struct qjs_plugin_manager_t {
	ut32 magic;
	R_BORROW RCore *core;
	R_BORROW JSRuntime *rt;
	QjsContext default_ctx; // context for running normal JS code
	RVecCorePlugin core_plugins;
	RVecArchPlugin arch_plugins;
	RVecIoPlugin io_plugins;
} QjsPluginManager;

static QjsPluginManager *Gpm = NULL;
static bool plugin_manager_init(QjsPluginManager *pm, RCore *core, JSRuntime *rt) {
	pm->core = core;
	pm->rt = rt;
	RVecCorePlugin_init (&pm->core_plugins);
	RVecArchPlugin_init (&pm->arch_plugins);
	RVecIoPlugin_init (&pm->io_plugins);
	return true;
}

static void plugin_manager_add_core_plugin(QjsPluginManager *pm, const char *name, JSContext *ctx, JSValue func) {
	r_return_if_fail (pm);

	QjsCorePlugin *cp = RVecCorePlugin_emplace_back (&pm->core_plugins);
	if (cp) {
		cp->name = name? strdup (name): NULL;
		cp->qctx.ctx = ctx;
		cp->qctx.call_func = func;
	}
}

static QjsIoPlugin *plugin_manager_add_io_plugin(QjsPluginManager *pm, const char *name, JSContext *ctx, RIOPlugin *iop, JSValue func) {
	r_return_val_if_fail (pm, NULL);

	QjsIoPlugin *cp = RVecIoPlugin_emplace_back (&pm->io_plugins);
	if (cp) {
		cp->name = name? strdup (name): NULL;
		cp->ctx = ctx;
		cp->iop = iop;
		cp->fn_check_js = func;
		// cp->qctx.open_func = func;
		// cp->qctx.read_func = func;
	}
	return cp;
}

static inline int compare_core_plugin_name(const QjsCorePlugin *cp, const void *data) {
	const char *name = data;
	return strcmp (cp->name, name);
}

static inline int compare_io_plugin_name(const QjsIoPlugin *cp, const void *data) {
	const char *name = data;
	return strcmp (cp->name, name);
}

static QjsCorePlugin *plugin_manager_find_core_plugin(const QjsPluginManager *pm, const char *name) {
	r_return_val_if_fail (pm, NULL);

	return RVecCorePlugin_find (&pm->core_plugins, (void*) name, compare_core_plugin_name);
}

static QjsIoPlugin *plugin_manager_find_io_plugin(const QjsPluginManager *pm, const char *name) {
	r_return_val_if_fail (pm, NULL);

	return RVecIoPlugin_find (&pm->io_plugins, (void*) name, compare_io_plugin_name);
}

static bool plugin_manager_remove_core_plugin(QjsPluginManager *pm, const char *name) {
	r_return_val_if_fail (pm, false);

	ut64 index = RVecCorePlugin_find_index (&pm->core_plugins, (void*) name, compare_core_plugin_name);
	if (index != UT64_MAX) {
		pm->core->lang->cmdf (pm->core, "L-%s", name);
		RVecCorePlugin_remove (&pm->core_plugins, index);
		return true;
	}

	return false;
}

static void plugin_manager_add_arch_plugin(QjsPluginManager *pm, const char *name,
	const char *arch, JSContext *ctx, JSValue decode_func) {
	r_return_if_fail (pm);

	QjsArchPlugin *ap = RVecArchPlugin_emplace_back (&pm->arch_plugins);
	if (ap) {
		ap->name = strdup (name);
		ap->arch = strdup (arch);
		ap->ctx = ctx;
		ap->decode_func = decode_func;
	}
}

static inline int compare_arch_plugin_arch(const QjsArchPlugin *ap, const void *data) {
	// TODO also lookup plugin by endian-ness and bits (pass in data struct)
	const char *arch = data;
	return strcmp (ap->arch, arch);
}

static QjsArchPlugin *plugin_manager_find_arch_plugin(const QjsPluginManager *pm, const char *arch) {
	r_return_val_if_fail (pm, NULL);
	return RVecArchPlugin_find (&pm->arch_plugins, (void*) arch, compare_arch_plugin_arch);
}

static bool plugin_manager_remove_arch_plugin(QjsPluginManager *pm, const char *arch) {
	r_return_val_if_fail (pm, false);

	ut64 index = RVecArchPlugin_find_index (&pm->arch_plugins, (void*) arch, compare_arch_plugin_arch);
	if (index != UT64_MAX) {
		QjsArchPlugin *ap = RVecArchPlugin_at (&pm->arch_plugins, index);
		pm->core->lang->cmdf (pm->core, "L-%s", ap->name);
		RVecArchPlugin_remove (&pm->arch_plugins, index);
		return true;
	}

	return false;
}

static bool plugin_manager_remove_plugin(QjsPluginManager *pm, const char *type, const char *plugin_id) {
	r_return_val_if_fail (pm, false);

	if (R_STR_ISNOTEMPTY (type)) {
		if (!strcmp (type, "core")) {
			return plugin_manager_remove_core_plugin (pm, plugin_id);
		}

		if (!strcmp (type, "arch")) {
			return plugin_manager_remove_arch_plugin (pm, plugin_id);
		}
	}

	// TODO extend for bin / io / ... plugins
	// invalid throw exception here
	// return JS_ThrowRangeError(ctx, "invalid r2plugin type");
	return false;
}

static void plugin_manager_fini (QjsPluginManager *pm) {
	RVecCorePlugin_fini (&pm->core_plugins);
	RVecArchPlugin_fini (&pm->arch_plugins);
	RVecIoPlugin_fini (&pm->io_plugins);
	// XXX leaks, but calling it causes crash because not all JS objects are freed
	// JS_FreeRuntime (pm->rt);
	pm->rt = NULL;
}

#include "qjs/loader.c"
#include "qjs/arch.c"
#include "qjs/core.c"
#include "qjs/io.c"

///////////////////////////////////////////////////////////

static bool eval(JSContext *ctx, const char *code);

static void eval_jobs(JSContext *ctx) {
	JSRuntime *rt = JS_GetRuntime (ctx);
	JSContext *pctx = NULL;
	do {
		int res = JS_ExecutePendingJob (rt, &pctx);
		if (res == -1) {
			R_LOG_ERROR ("Exception in pending job");
		}
	} while (pctx);
}

static void r2qjs_dump_obj(JSContext *ctx, JSValueConst val) {
	const char *str = JS_ToCString (ctx, val);
	if (str) {
		R_LOG_ERROR ("%s", str);
		JS_FreeCString (ctx, str);
	} else {
		R_LOG_ERROR ("[exception]");
	}
}

static void js_std_dump_error1(JSContext *ctx, JSValueConst exception_val) {
	JSValue val;
	bool is_error;

	is_error = JS_IsError (ctx, exception_val);
	r2qjs_dump_obj (ctx, exception_val);
	if (is_error) {
		val = JS_GetPropertyStr (ctx, exception_val, "stack");
		if (!JS_IsUndefined (val)) {
			r2qjs_dump_obj (ctx, val);
		}
		JS_FreeValue (ctx, val);
	}
}

static void js_std_dump_error(JSContext *ctx) {
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

static JSValue r2plugin(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	size_t plen;
	const char *n = JS_ToCStringLen2 (ctx, &plen, argv[0], false);
	if (R_STR_ISNOTEMPTY (n)) {
		if (!strcmp (n, "core")) {
			return r2plugin_core_load (ctx, this_val, argc, argv);
		} else if (!strcmp (n, "arch")) {
			return r2plugin_arch_load (ctx, this_val, argc, argv);
		} else if (!strcmp (n, "io")) {
			return r2plugin_io (ctx, this_val, argc, argv);
#if 0
		} else if (!strcmp (n, "bin")) {
			return r2plugin_bin (ctx, this_val, argc, argv);
#endif
		} else {
			// invalid throw exception here
			return JS_ThrowRangeError(ctx, "invalid r2plugin type");
		}
	}
	return JS_NewBool (ctx, false);
}

static JSValue r2plugin_unload(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	if (argc != 2 || !JS_IsString (argv[0]) || !JS_IsString (argv[1])) {
		return JS_ThrowRangeError (ctx, "r2.unload takes only one string as argument");
	}
	JSRuntime *rt = JS_GetRuntime (ctx);
	QjsPluginManager *pm = JS_GetRuntimeOpaque (rt);

	size_t len;
	const char *type = JS_ToCStringLen2 (ctx, &len, argv[0], false);
	const char *name_or_arch = JS_ToCStringLen2 (ctx, &len, argv[1], false);
	const bool res = plugin_manager_remove_plugin (pm, type, name_or_arch);
	return JS_NewBool (ctx, res);
}

static JSValue r2syscmd(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	size_t plen;
	const char *n = JS_ToCStringLen2 (ctx, &plen, argv[0], false);
	int ret = 0;
	if (R_STR_ISNOTEMPTY (n)) {
		ret = r_sys_cmd (n);
	}
	// JS_FreeValue (ctx, argv[0]);
	return JS_NewInt32 (ctx, ret);
}

static JSValue r2syscmds(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	size_t plen;
	const char *n = JS_ToCStringLen2 (ctx, &plen, argv[0], false);
	char *ret = NULL;
	if (R_STR_ISNOTEMPTY (n)) {
		ret = r_sys_cmd_str (n, NULL, NULL);
	}
	JSValue v = JS_NewString (ctx, r_str_get (ret));
	free (ret);
	return v;
}

// WIP experimental
static JSValue r2cmd0(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	JSRuntime *rt = JS_GetRuntime (ctx);
	QjsPluginManager *pm = JS_GetRuntimeOpaque (rt);
	size_t plen;
	const char *n = JS_ToCStringLen2 (ctx, &plen, argv[0], false);
	int ret = 0;
	if (R_STR_ISNOTEMPTY (n)) {
		ret = pm->core->lang->cmdf (pm->core, "%s@e:scr.null=true", n);
	}
	// JS_FreeValue (ctx, argv[0]);
	return JS_NewInt32 (ctx, ret);
}

// WIP experimental
static JSValue r2call0(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	JSRuntime *rt = JS_GetRuntime (ctx);
	QjsPluginManager *pm = JS_GetRuntimeOpaque (rt);
	size_t plen;
	const char *n = JS_ToCStringLen2 (ctx, &plen, argv[0], false);
	int ret = 0;
	if (R_STR_ISNOTEMPTY (n)) {
		pm->core->lang->cmdf (pm->core, "'e scr.null=true");
		ret = pm->core->lang->cmdf (pm->core, "'%s", n);
		pm->core->lang->cmdf (pm->core, "'e scr.null=false");
	}
	// JS_FreeValue (ctx, argv[0]);
	return JS_NewInt32 (ctx, ret);
}

static JSValue r2cmd(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	JSRuntime *rt = JS_GetRuntime (ctx);
	QjsPluginManager *pm = JS_GetRuntimeOpaque (rt);
	size_t plen;
	const char *n = JS_ToCStringLen2 (ctx, &plen, argv[0], false);
	char *ret = NULL;
	if (R_STR_ISNOTEMPTY (n)) {
		ret = pm->core->lang->cmd_str (pm->core, n);
	}
	// JS_FreeValue (ctx, argv[0]);
	return JS_NewString (ctx, r_str_get (ret));
}

static JSValue r2callAt(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	if (argc != 2 || !JS_IsString (argv[0]) || (!JS_IsString (argv[1]) && !JS_IsNumber (argv[1]))) {
		return JS_ThrowRangeError (ctx, "r2.callAt takes two strings");
	}
	JSRuntime *rt = JS_GetRuntime (ctx);
	QjsPluginManager *pm = JS_GetRuntimeOpaque (rt);
	size_t plen;
	const char *c = JS_ToCStringLen2 (ctx, &plen, argv[0], false);
	const char *n = JS_ToCStringLen2 (ctx, &plen, argv[1], false);
	char *ret = NULL;
	if (R_STR_ISNOTEMPTY (n)) {
		ut64 at = r_num_math (pm->core->num, n);
		ret = pm->core->lang->call_at (pm->core, at, c);
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

static JSValue js_os_pending(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv, int magic) {
	eval_jobs (ctx);
	return JS_UNDEFINED;
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
	if (JS_ToIndex (ctx, &len, argv[3])) {
		return JS_EXCEPTION;
	}
	uint8_t *buf = JS_GetArrayBuffer (ctx, &size, argv[1]);
	if (!buf) {
		return JS_EXCEPTION;
	}
	if (pos + len > size) {
		return JS_ThrowRangeError (ctx, "read/write array buffer overflow");
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
	JS_CFUNC_MAGIC_DEF ("pending", 4, js_os_pending, 0 ),
#if 0
	JS_CFUNC_MAGIC_DEF("setReadHandler", 2, js_os_setReadHandler, 0 ),
	JS_CFUNC_DEF("setTimeout", 2, js_os_setTimeout ),
	JS_CFUNC_DEF("clearTimeout", 1, js_os_clearTimeout ),
#endif
	// JS_CFUNC_DEF("open", 2, js_os_open ),
	// OS_FLAG(O_RDONLY),
};

static int js_os_init(JSContext *ctx, JSModuleDef *m) {
	return JS_SetModuleExportList(ctx, m, js_os_funcs, countof (js_os_funcs));
}

static JSModuleDef *js_init_module_os(JSContext *ctx) {
	JSModuleDef *m = JS_NewCModule (ctx, "os", js_os_init);
	if (m) {
		JS_AddModuleExportList (ctx, m, js_os_funcs, countof (js_os_funcs));
	}
	return m;
}

static const JSCFunctionListEntry js_r2_funcs[] = {
	JS_CFUNC_DEF ("cmd", 1, r2cmd), // XXX deprecate, we have r2.cmd already
	JS_CFUNC_DEF ("plugin", 2, r2plugin),
	JS_CFUNC_DEF ("unload", 2, r2plugin_unload),
	// JS_CFUNC_DEF ("cmdj", 1, r2cmdj), // can be implemented in js
	JS_CFUNC_DEF ("log", 1, r2log),
	JS_CFUNC_DEF ("error", 1, r2error),
	JS_CFUNC_DEF ("cmd0", 1, r2cmd0),
	// implemented in js JS_CFUNC_DEF ("call", 1, r2call);
	JS_CFUNC_DEF ("call0", 1, r2call0),
	JS_CFUNC_DEF ("callAt", 2, r2callAt),
	JS_CFUNC_DEF ("syscmd", 1, r2syscmd),
	JS_CFUNC_DEF ("syscmds", 1, r2syscmds),
};

static int js_r2_init(JSContext *ctx, JSModuleDef *m) {
	return JS_SetModuleExportList (ctx, m, js_r2_funcs, countof (js_r2_funcs));
}

static JSModuleDef *js_init_module_r2(JSContext *ctx) {
	JSModuleDef *m = JS_NewCModule (ctx, "r2", js_r2_init);
	if (m) {
		JSValue global_obj = JS_GetGlobalObject (ctx);
		JSValue name = JS_NewString (ctx, "r2");
		JSValue v = JS_NewObjectProtoClass (ctx, name, 0);
		JS_SetPropertyStr (ctx, global_obj, "r2", v);
		JS_SetPropertyFunctionList (ctx, v, js_r2_funcs, countof (js_r2_funcs));
		// JS_AddModuleExportList (ctx, m, js_r2_funcs, countof(js_r2_funcs));
	}
	return m;
}

// r2pipe
static JSValue qjs_r2pipe_instance_cmd(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	if (argc != 1) {
		return JS_ThrowRangeError (ctx, "Only one argument permitted");
	}
	R2Pipe *r2p = JS_GetOpaque (this_val, 0);
	size_t plen;
	if (r2p) {
		const char *cmd = JS_ToCStringLen2 (ctx, &plen, argv[0], false);
		char *s = r2pipe_cmd (r2p, cmd);
		return QJS_STRING (s);
	}
	return JS_ThrowRangeError (ctx, "Only one argument permitted");
}

static JSValue qjs_r2pipe_instance_cmdj(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	JSValue arg0 = qjs_r2pipe_instance_cmd (ctx, this_val, argc, argv);
	const char jp[] = "JSON.parse";
	JSValue json_parse = JS_Eval (ctx, jp, strlen (jp), "-", JS_EVAL_TYPE_GLOBAL);
	JSValue args = JS_NewArray (ctx);
	JS_SetPropertyUint32 (ctx, args, 0, arg0);
	return JS_Call (ctx, json_parse, this_val, 1, &args);
}

static JSValue qjs_r2pipe_instance_quit(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	R2Pipe *r2p = JS_GetOpaque (this_val, 0);
	if (r2p) {
		r2pipe_close (r2p);
		JS_SetOpaque (this_val, NULL);
		return JS_NewBool (ctx, false);
	}
	return JS_NewBool (ctx, false);
}

static const JSCFunctionListEntry js_r2pipe_instance_funcs[] = {
	JS_CFUNC_DEF ("cmd", 2, qjs_r2pipe_instance_cmd),
	JS_CFUNC_DEF ("cmdj", 2, qjs_r2pipe_instance_cmdj),
	JS_CFUNC_DEF ("quit", 2, qjs_r2pipe_instance_quit)
};

static JSValue qjs_r2pipe_open(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	// JSRuntime *rt = JS_GetRuntime (ctx);
	// QjsPluginManager *pm = JS_GetRuntimeOpaque (rt);
	if (argc == 0) {
		// return the same current global instance of the r2
		return JS_Eval (ctx, "r2", 2, "-", JS_EVAL_TYPE_GLOBAL);
	}
	if (argc > 2) {
		return JS_ThrowRangeError (ctx, "Too many arguments");
	}
	char *args = strdup ("");
	if (argc == 2) {
		if (JS_IsArray (ctx, argv[1])) {
			int i;
			RStrBuf *sb = r_strbuf_new ("");
			JSValue array = argv[1];
			ut32 array_length;
			JSValue v = JS_GetPropertyStr (ctx, array, "length");
			JS_ToUint32 (ctx, &array_length, v);
			for (i = 0; i < array_length; i++) {
				v = JS_GetPropertyUint32 (ctx, array, i);
				size_t plen;
				const char *n = JS_ToCStringLen2 (ctx, &plen, v, false);
				r_strbuf_append (sb, n);
				r_strbuf_append (sb, " ");
			}
			r_strbuf_append (sb, " ");
			free (args);
			args = r_strbuf_drain (sb);
		} else {
			return JS_ThrowRangeError (ctx, "Second argument must be an array");
		}
	}
	size_t plen;
	const char *n = JS_ToCStringLen2 (ctx, &plen, argv[0], false);
	char *c = r_str_newf ("radare2 %s-q0 %s", args, n);
	R2Pipe *pipe = r2pipe_open (c);
	free (c);
	JSValue v = JS_NewObjectProtoClass (ctx, QJS_STRING ("r2pipeInstance"), 0);
	// char *r2p = r_str_newf ("%p", pipe);
	// JS_SetPropertyStr (ctx, v, "_r2p_", QJS_STRING (r2p));
	JS_SetOpaque (v, pipe);
	// free (r2p);
	JS_SetPropertyFunctionList (ctx, v, js_r2pipe_instance_funcs, countof (js_r2pipe_instance_funcs));
	return v;
}

static const JSCFunctionListEntry js_r2pipe_funcs[] = {
	JS_CFUNC_DEF ("open", 2, qjs_r2pipe_open)
	// JS_CFUNC_DEF ("openCore", 2, qjs_r2pipe_opencore) // r2pipe_open_corebind()
};

static int js_r2pipe_init(JSContext *ctx, JSModuleDef *m) {
	return JS_SetModuleExportList (ctx, m, js_r2pipe_funcs, countof (js_r2pipe_funcs));
}

static JSModuleDef *js_init_module_r2pipe(JSContext *ctx) {
	JSModuleDef *m = JS_NewCModule (ctx, "r2pipe", js_r2pipe_init);
	if (m) {
		JSValue global = JS_GetGlobalObject (ctx);
		JSValue v = JS_NewObjectProtoClass (ctx, QJS_STRING ("r2pipe"), 0);
		JS_SetPropertyStr (ctx, global, "r2pipe", v);
		JS_SetPropertyFunctionList (ctx, v, js_r2pipe_funcs, countof (js_r2pipe_funcs));
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
	js_init_module_os (ctx);
	js_init_module_r2 (ctx);
	js_init_module_r2pipe (ctx);
	r2qjs_modules (ctx);
	// JS_AddModuleExportList (ctx, m, js_r2_funcs, countof (js_r2_funcs));
	JSValue global_obj = JS_GetGlobalObject (ctx);
	// JS_SetPropertyStr (ctx, global_obj, "r2", global_obj); // JS_NewCFunction (ctx, b64, "b64", 1));
	JS_SetPropertyStr (ctx, global_obj, "b64", JS_NewCFunction (ctx, b64, "b64", 1));
	// r2cmd deprecate . we have r2.cmd already same for r2log
	JS_SetPropertyStr (ctx, global_obj, "r2cmd", JS_NewCFunction (ctx, r2cmd, "r2cmd", 1));
	JS_SetPropertyStr (ctx, global_obj, "r2call", JS_NewCFunction (ctx, r2callAt, "r2call", 1));
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
	eval (ctx, "r2.cmdAt = (x, a) => r2.cmd(x + ' @ ' + a);");
	eval (ctx, "r2.call = (x) => r2.cmd('\"\"' + x);");
	eval (ctx, "r2.callj = (x) => JSON.parse(r2.call(x));");
	eval (ctx, "var global = globalThis; var G = globalThis;");
	eval (ctx, js_require_qjs);
	eval (ctx, "require = function(x) { if (x == 'r2papi') { return new R2Papi(r2); } ; return requirejs(x); }");
	eval (ctx, "var exports = {};");
	// eval (ctx, "G.r2pipe = {open: function(){ return R.r2;}};");
	eval (ctx, "G.R2Pipe=() => R.r2;");
	if (r_sys_getenv_asbool ("R2_DEBUG_NOPAPI")) {
		eval (ctx, "R=r2;");
	} else {
		eval (ctx, js_r2papi_qjs);
		eval (ctx, "R=G.R=new R2Papi(r2);");
		eval (ctx, "G.Process = new ProcessClass(r2);");
		eval (ctx, "G.Module = new ModuleClass(r2);");
		eval (ctx, "G.Thread = new ThreadClass(r2);");
		eval (ctx, "function ptr(x) { return new NativePointer(x); }");
		eval (ctx, "G.NULL = ptr(0);");
	}
	eval (ctx, "G.Radare2 = { version: r2.cmd('?Vq').trim() };"); // calling r2.cmd requires a delayed initialization
}

static JSContext *JS_NewCustomContext(JSRuntime *rt) {
	JSContext *ctx = JS_NewContext (rt);
	if (!ctx) {
		return NULL;
	}
#if CONFIG_BIGNUM
	JS_AddIntrinsicBigFloat (ctx);
	JS_AddIntrinsicBigDecimal (ctx);
	JS_AddIntrinsicOperators (ctx);
	JS_EnableBignumExt (ctx, true);
#endif
	return ctx;
}

static bool eval(JSContext *ctx, const char *code) {
	if (R_STR_ISEMPTY (code)) {
		return false;
	}
	bool wantRaw = strstr (code, "termInit(");
	if (wantRaw) {
		r_cons_set_raw (true);
	}
	int flags = JS_EVAL_TYPE_GLOBAL; //  | JS_EVAL_TYPE_MODULE; //  | JS_EVAL_FLAG_STRICT;
	if (*code == '-') {
		flags = JS_EVAL_TYPE_GLOBAL | JS_EVAL_TYPE_MODULE; //  | JS_EVAL_FLAG_STRICT;
		code++;
	}
	JSValue v = JS_Eval (ctx, code, strlen (code), "-", flags);
	if (JS_IsException (v)) {
		js_std_dump_error (ctx);
		JSValue e = JS_GetException (ctx);
		r2qjs_dump_obj (ctx, e);
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
	r_return_val_if_fail (s && s->plugin_data && code, false);
	QjsPluginManager *pm = s->plugin_data;
	return eval (pm->default_ctx.ctx, code);
}

static bool lang_quickjs_file(RLangSession *s, const char *file) {
	r_return_val_if_fail (s && s->plugin_data && file, false);

	QjsPluginManager *pm = s->plugin_data;
	QjsContext *qctx = &pm->default_ctx;
	bool rc = false;
	char *code = r_file_slurp (file, NULL);
	if (code) {
		int loaded = r2qjs_loader (qctx->ctx, code);
		if (loaded == 1) {
			rc = true;
		} else if (loaded == -1) {
			// Error loading the file
			return false;
		} else {
			// not a package
			rc = eval (qctx->ctx, code) == 0;
			free (code);
			rc = true;
		}
	}
	return rc;
}

static bool init(RLangSession *ls) {
	if (ls == NULL) {
		// when ls is null means that we want to check if we can use it
		return true;
	}

	if (ls->plugin_data) {
		R_LOG_ERROR ("qjs lang plugin already loaded");
		return false;
	}

	JSRuntime *rt = JS_NewRuntime ();
	if (!rt) {
		return false;
	}
	JSContext *ctx = JS_NewCustomContext (rt);
	if (!ctx) {
		JS_FreeRuntime (rt);
		return false;
	}
	QjsPluginManager *pm = R_NEW0 (QjsPluginManager);
	if (!pm) {
		JS_FreeContext (ctx);
		JS_FreeRuntime (rt);
		return false;
	}
	Gpm = pm;
	pm->magic = QJS_CORE_MAGIC;
	RCore *core = ls->lang->user;
	plugin_manager_init (pm, core, rt);

	JSValue func = JS_NewBool (ctx, false); // fake function
	QjsContext *qc = &pm->default_ctx;
	qc->ctx = ctx;
	qc->call_func = func;
	r2qjs_modules (ctx);
	JS_SetRuntimeOpaque (rt, pm);  // expose pm to all qjs native functions in R2
	ls->plugin_data = pm;

	// requires pm to be set in the plugin_data
	register_helpers (ctx);
	return true;
}

static bool fini(RLangSession *s) {
	r_return_val_if_fail (s && s->plugin_data, false);

	QjsPluginManager *pm = s->plugin_data;

	QjsContext *qctx = &pm->default_ctx;
	JS_FreeContext (qctx->ctx);
	qctx->ctx = NULL;

	plugin_manager_fini (pm);

	free (pm);
	s->plugin_data = NULL;
	return true;
}

static RLangPlugin r_lang_plugin_qjs = {
	.meta = {
		.name = "qjs",
		.license = "MIT",
		.desc = "JavaScript extension language using QuickJS",
	},
	.ext = "qjs",
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
