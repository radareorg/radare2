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
	log("Type 'test' to confirm it works");
	console.log("load true", r2.plugin("core", examplePlugin));
	console.log("load true", r2.plugin("core", examplePlugin2));
	if (false) {
		console.log("load true", r2.plugin("core", examplePlugin));
		console.log("load true", r2.plugin("core", examplePlugin2));
		console.log("load false", r2.plugin("core", examplePlugin));
		console.log("unload false", r2.unload("false"));
		console.log("unload true", r2.unload("qjs-example"));
		console.log("unload false", r2.unload("qjs-example"));
		log("Plugins:");
		log(r2cmd("Lc"));
	}
})();
```

#endif

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
static R_TH_LOCAL int Gplug = 0;
static R_TH_LOCAL QjsContext *GcallsData[MAXPLUGS] = { NULL };
typedef int (*CallX)(void *, const char *);
static int call0(void *c, const char *i) { return r2plugin_core_call2 (GcallsData[0], c, i); }
static int call1(void *c, const char *i) { return r2plugin_core_call2 (GcallsData[1], c, i); }
static int call2(void *c, const char *i) { return r2plugin_core_call2 (GcallsData[2], c, i); }
static int call3(void *c, const char *i) { return r2plugin_core_call2 (GcallsData[3], c, i); }
static int call4(void *c, const char *i) { return r2plugin_core_call2 (GcallsData[4], c, i); }
static const CallX Gcalls[MAXPLUGS] = { &call0, &call1, &call2, &call3, &call4 };


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
		ap->name = nameptr;
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

