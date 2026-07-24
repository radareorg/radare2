#if 0

# QuickJS core plugin example

```js

(function() {
	let { log } = console;

	function examplePlugin() {
		function coreCall(input) {
			if (input.startsWith("t1")) {
				log("This is a QJS test");
				return true;
			}
			return false;
		}
		return {
			name: "qjs-example",
			desc: "Example QJS plugin (type 't1') in the r2 shell",
			call: coreCall,
		};
	}

	function examplePlugin2() {
		function coreCall(input) {
			if (input.startsWith("t2")) {
				log("This is another QJS test");
				return true;
			}
			return false;
		}
		return {
			name: "qjs-example2",
			desc: "Example QJS plugin (type 't2') in the r2 shell",
			call: coreCall,
		};
	}

	log("Installing the `qjs-example` core plugin");
	log("Type 't1' or 't2' to confirm it works");
	console.log("load true", r2.plugin("core", examplePlugin));
	console.log("load true", r2.plugin("core", examplePlugin2));
	if (false) {
		console.log("load true", r2.plugin("core", examplePlugin));
		console.log("load true", r2.plugin("core", examplePlugin2));
		console.log("load false", r2.plugin("core", examplePlugin));
		console.log("unload false", r2.unload("core", "false"));
		console.log("unload true", r2.unload("core", "qjs-example"));
		console.log("unload false", r2.unload("core", "qjs-example"));
		log("Plugins:");
		log(r2.cmd("Lc"));
	}
})();

```

#endif

#define QJS_CORE_MAGIC 0x07534617

typedef struct {
	JSContext *ctx;
	JSValue func;
	R_TH_TID tid; // thread owning the JS runtime
} Hack;
Hack *hack = NULL;

static bool qjs_core_init(RCorePluginSession *cps) {
	RCore *core = cps->core;
	QjsPluginManager *pm = R_UNWRAP4 (core, lang, session, plugin_data);
	if (pm == NULL) {
		return false;
	}
	// QjsContext *qc = &plugin->ctx;
	cps->data = hack;
	return true;
}

static bool qjs_core_fini(RCorePluginSession *cps) {
	if (cps && cps->data) {
		Hack *hack = (Hack *)cps->data;
		free (hack);
		cps->data = NULL;
	}
	return true;
}

// defined here and also forward-declared in qjs.c so core_plugin_fini can use it
static void qjs_core_plugin_free(void *data) {
	RCorePlugin *ap = data;
	if (ap) {
		free ((char *)ap->meta.name);
		free ((char *)ap->meta.desc);
		free ((char *)ap->meta.license);
		free (ap);
	}
}

// TODO maybe add a function to call by plugin name? (is 1 extra arg)
static bool r_cmd_qjs_call(RCorePluginSession *cps, const char *input) {
	Hack *hack = cps->data;
	if (!hack) {
		return false;
	}
	if (!r_th_tid_equal (hack->tid, r_th_self ())) {
		// QuickJS runtimes must run on their owner thread.
		return false;
	}
	JSContext *ctx = hack->ctx;
	JSValue func = hack->func;
	JSValue args[1] = { JS_NewString (ctx, input) };
	JSValue res = JS_Call (ctx, func, JS_UNDEFINED, countof (args), args);
	bool ret = false;
	if (JS_IsException (res)) {
		// An erroring plugin must not claim the command as handled.
		JSValue e = JS_GetException (ctx);
		JS_FreeValue (ctx, e);
	} else if (JS_IsPromise (res)) {
		JSPromiseStateEnum state = qjs_await_promise (ctx, res);
		if (state == JS_PROMISE_FULFILLED) {
			JSValue e = JS_PromiseResult (ctx, res);
			ret = JS_ToBool (ctx, e) == 1;
			JS_FreeValue (ctx, e);
		}
	} else {
		ret = JS_ToBool (ctx, res) == 1;
	}
	JS_FreeValue (ctx, res);
	JS_FreeValue (ctx, args[0]);
	return ret;
}

typedef struct {
	JSContext *ctx;
	JSValue arg;
	JSValue res;
	JSValue name;
	JSValue func;
	JSValue desc;
	JSValue license;
	const char *nameptr;
	const char *descptr;
	const char *licenseptr;
	RCorePlugin *plugin;
} QjsCoreLoad;

static void qjs_core_load_fini(QjsCoreLoad *cl) {
	qjs_free_cstring (cl->ctx, &cl->licenseptr);
	qjs_free_cstring (cl->ctx, &cl->descptr);
	qjs_free_cstring (cl->ctx, &cl->nameptr);
	qjs_free_value (cl->ctx, &cl->license);
	qjs_free_value (cl->ctx, &cl->desc);
	qjs_free_value (cl->ctx, &cl->func);
	qjs_free_value (cl->ctx, &cl->name);
	qjs_free_value (cl->ctx, &cl->res);
	qjs_free_value (cl->ctx, &cl->arg);
	qjs_core_plugin_free (cl->plugin);
}

static JSValue r2plugin_core_load(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	JSRuntime *rt = JS_GetRuntime (ctx);
	QjsPluginManager *pm = JS_GetRuntimeOpaque (rt);
	if (argc != 2) {
		return JS_ThrowRangeError (ctx, "r2.plugin expects two arguments");
	}

	QjsCoreLoad cl = {
		.ctx = ctx,
		.arg = JS_NewString (ctx, ""),
		.res = JS_UNDEFINED,
		.name = JS_UNDEFINED,
		.func = JS_UNDEFINED,
		.desc = JS_UNDEFINED,
		.license = JS_UNDEFINED,
	};
	JSValue ret = JS_UNDEFINED;
	size_t namelen;

	cl.res = JS_Call (ctx, argv[1], JS_UNDEFINED, 1, &cl.arg);
	if (!JS_IsObject (cl.res)) {
		ret = JS_ThrowRangeError (ctx, "r2.plugin function must return an object");
		goto beach;
	}

	cl.name = JS_GetPropertyStr (ctx, cl.res, "name");
	cl.nameptr = JS_ToCStringLen2 (ctx, &namelen, cl.name, false);
	if (!cl.nameptr) {
		R_LOG_WARN ("r2.plugin requires the function to return an object with the `name` field");
		ret = JS_NewBool (ctx, false);
		goto beach;
	}

	cl.func = JS_GetPropertyStr (ctx, cl.res, "call");
	if (!JS_IsFunction (ctx, cl.func)) {
		R_LOG_WARN ("r2.plugin requires the function to return an object with the `call` field to be a function");
		ret = JS_NewBool (ctx, false);
		goto beach;
	}

	if (plugin_manager_find_core_plugin (pm, cl.nameptr)) {
		R_LOG_WARN ("r2.plugin with name %s is already registered", cl.nameptr);
		ret = JS_NewBool (ctx, false);
		goto beach;
	}

	cl.plugin = R_NEW0 (RCorePlugin);
	cl.desc = JS_GetPropertyStr (ctx, cl.res, "desc");
	cl.license = JS_GetPropertyStr (ctx, cl.res, "license");
	cl.descptr = JS_ToCStringLen2 (ctx, &namelen, cl.desc, false);
	cl.licenseptr = JS_ToCStringLen2 (ctx, &namelen, cl.license, false);

	cl.plugin->meta.name = strdup (cl.nameptr);
	if (cl.descptr) {
		cl.plugin->meta.desc = strdup (cl.descptr);
	}
	if (cl.licenseptr) {
		cl.plugin->meta.license = strdup (cl.licenseptr);
	}
	cl.plugin->init = qjs_core_init;
	cl.plugin->call = r_cmd_qjs_call;
	cl.plugin->fini = qjs_core_fini;

	const char *plugin_name = cl.plugin->meta.name;
	RCorePlugin *plugin = cl.plugin;
	JSValue func = cl.func;
	plugin_manager_add_core_plugin (pm, plugin_name, ctx, cl.func, plugin);
	cl.plugin = NULL;
	cl.func = JS_UNDEFINED;

	RLibStruct *lib = R_NEW0 (RLibStruct);
	lib->type = R_LIB_TYPE_CORE;
	lib->data = plugin;
	lib->version = R2_VERSION;
	hack = R_NEW0 (Hack);
	hack->ctx = ctx;
	hack->func = func;
	hack->tid = r_th_self ();
	int opened = r_lib_open_ptr (pm->core->lib, plugin_name, NULL, lib);
	free (lib);
	if (opened != 1) {
		free (hack);
		hack = NULL;
	}
	ret = JS_NewBool (ctx, opened == 1);

beach:
	qjs_core_load_fini (&cl);
	return ret;
}
