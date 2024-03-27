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
// TODO maybe add a function to call by plugin name? (is 1 extra arg)
static int r_cmd_qjs_call(void *c, const char *input) {
	RCore *core = c;
	QjsPluginManager *pm = R_UNWRAP4 (core, lang, session, plugin_data);
	if (pm == NULL) {
		return false;
	}
	if (pm->magic != QJS_CORE_MAGIC) {
		pm = Gpm;
		R_LOG_DEBUG ("NOT the right lang session");
	}

	// Iterate over plugins until one returns "true" (meaning the plugin handled the input)
	QjsCorePlugin *plugin;
	R_VEC_FOREACH (&pm->core_plugins, plugin) {
		if (plugin == NULL) {
			continue;
		}
		// check if core plugin is a qjs one
		QjsContext *qc = &plugin->qctx;
		JSValueConst args[1] = { JS_NewString (qc->ctx, input) };
		JSValue res = JS_Call (qc->ctx, qc->call_func, JS_UNDEFINED, countof (args), args);
		if (JS_ToBool (qc->ctx, res)) {
			return true;
		}
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
	if (!ap) {
		return JS_ThrowRangeError (ctx, "could not allocate qjs core plugin");
	}

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

	ap->call = r_cmd_qjs_call;  // Technically this could all be handled by a single generic plugin

	plugin_manager_add_core_plugin (pm, nameptr, ctx, func);

	RLibStruct *lib = R_NEW0 (RLibStruct);
	if (!lib) {
		free (ap);
		return JS_NewBool (ctx, false);
	}

	lib->type = R_LIB_TYPE_CORE;
	lib->data = ap;
	lib->version = R2_VERSION;
	int ret = r_lib_open_ptr (pm->core->lib, ap->meta.name, NULL, lib);
	return JS_NewBool (ctx, ret == 1);
}
