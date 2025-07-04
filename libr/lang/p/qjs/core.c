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
		free(hack);
		cps->data = NULL;
	}
	return true;
}

// TODO maybe add a function to call by plugin name? (is 1 extra arg)
static bool r_cmd_qjs_call(RCorePluginSession *cps, const char *input) {
	Hack *hack = cps->data;
	JSContext *ctx = hack->ctx;
	JSValue func = hack->func;
	// RCore *core = cps->core;
	// QjsCorePlugin *plugin;
	// QjsContext *qc = cps->data;
	JSValueConst args[1] = { JS_NewString (ctx, input) };
	JSValue res = JS_Call (ctx, func, JS_UNDEFINED, countof (args), args);
	if (JS_ToBool (ctx, res)) {
		return true;
	}
	return false;
}

static JSValue r2plugin_core_load(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	JSRuntime *rt = JS_GetRuntime (ctx);
	QjsPluginManager *pm = JS_GetRuntimeOpaque (rt);

	if (argc != 2) {
		return JS_ThrowRangeError (ctx, "r2.plugin expects two arguments");
	}

	JSValueConst args[1] = { JS_NewString (ctx, ""), };

	// check if res is an object
	JSValue res = JS_Call (ctx, argv[1], JS_UNDEFINED, countof (args), args);
	if (!JS_IsObject (res)) {
		return JS_ThrowRangeError (ctx, "r2.plugin function must return an object");
	}

	JSValue name = JS_GetPropertyStr (ctx, res, "name");
	size_t namelen;
	const char *nameptr = JS_ToCStringLen2 (ctx, &namelen, name, false);
	if (!nameptr) {
		R_LOG_WARN ("r2.plugin requires the function to return an object with the `name` field");
		return JS_NewBool (ctx, false);
	}

	JSValue func = JS_GetPropertyStr (ctx, res, "call");
	if (!JS_IsFunction (ctx, func)) {
		R_LOG_WARN ("r2.plugin requires the function to return an object with the `call` field to be a function");
		// return JS_ThrowRangeError (ctx, "r2.plugin requires the function to return an object with the `call` field to be a function");
		return JS_NewBool (ctx, false);
	}

	QjsCorePlugin *cp = plugin_manager_find_core_plugin (pm, nameptr);
	if (cp) {
		R_LOG_WARN ("r2.plugin with name %s is already registered", nameptr);
		// return JS_ThrowRangeError (ctx, "r2.plugin core already registered (only one exists)");
		return JS_NewBool (ctx, false);
	}

	RCorePlugin *ap = R_NEW0 (RCorePlugin);
	JSValue desc = JS_GetPropertyStr (ctx, res, "desc");
	JSValue license = JS_GetPropertyStr (ctx, res, "license");
	const char *descptr = JS_ToCStringLen2 (ctx, &namelen, desc, false);
	const char *licenseptr = JS_ToCStringLen2 (ctx, &namelen, license, false);

	ap->meta.name = strdup (nameptr);
	if (descptr) {
		ap->meta.desc = strdup (descptr);
	}
	if (licenseptr) {
		ap->meta.license = strdup (licenseptr);
	}
	ap->init = qjs_core_init;
	ap->call = r_cmd_qjs_call;
	ap->fini = qjs_core_fini;

	plugin_manager_add_core_plugin (pm, nameptr, ctx, func);

	RLibStruct *lib = R_NEW0 (RLibStruct);
	lib->type = R_LIB_TYPE_CORE;
	lib->data = ap;
	lib->version = R2_VERSION;
	// void *ptr = pm->core->lib;
	hack = R_NEW0 (Hack);
	// hack->pm = pm;
	hack->ctx = ctx;
	hack->func = func;
	int ret = r_lib_open_ptr (pm->core->lib, ap->meta.name, NULL, lib);
	if (ret != 1) {
		free (hack);
		free (lib);
	} else {
		// JS_DupValue(ctx, func);
	}
	return JS_NewBool (ctx, ret == 1);
}
