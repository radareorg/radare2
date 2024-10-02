#if 0

# QuickJS RPares plugin example

```js

(function() {
	let { log } = console;

	function parseExample() {
		function parseCall(input) {
			return input.replace("sp, -0x60", "LOCALVAR");
		}
		return {
			name: "qjs",
			desc: "Example QJS RParse plugin (qjs://)",
			call: parseCall,
		};
	}

	r2.plugin("jsparse", parseExample);
	r2.cmd("-e asm.parser=qjs");
	r2.cmd("-e asm.pseudo=true");
	r2.cmd("pd 10");
})();

```

#endif

static int qjs_parse(RParse *p, const char *input, char *output) {
	RCore *core = p->user;
	QjsPluginManager *pm = R_UNWRAP4 (core, lang, session, plugin_data);

	// Iterate over plugins until one returns "true" (meaning the plugin handled the input)
	QjsParsePlugin *plugin;
	R_VEC_FOREACH (&pm->parse_plugins, plugin) {
		JSContext *ctx = plugin->ctx;
		JSValueConst args[1] = { JS_NewString (ctx, input) };
		JSValue res = JS_Call (ctx, plugin->fn_parse_js, JS_UNDEFINED, countof (args), args);
		if (JS_IsString (res)) {
			size_t namelen;
			const char *nameptr = JS_ToCStringLen2 (ctx, &namelen, res, false);
			if (!nameptr) {
				R_LOG_WARN ("r2.plugin requires the function to return an object with the `name` field");
				return false;
			}
			strcpy (output, nameptr);
			return true;
		}
	}

	return false;
}

static JSValue r2plugin_parse_load(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
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

	JSValue fn_parse_js = JS_GetPropertyStr (ctx, res, "parse");

	if (!JS_IsFunction (ctx, fn_parse_js)) {
		R_LOG_WARN ("r2.plugin('parse', X) expects X to be a function that returns an object with at least: parse");
		// return JS_ThrowRangeError (ctx, "r2.plugin requires the function to return an object with the `call` field to be a function");
		return JS_NewBool (ctx, false);
	}

	QjsParsePlugin *cp = plugin_manager_find_parse_plugin (pm, nameptr);
	if (cp) {
		R_LOG_WARN ("r2.plugin with name %s is already registered", nameptr);
		// return JS_ThrowRangeError (ctx, "r2.plugin core already registered (only one exists)");
		return JS_NewBool (ctx, false);
	}

	RParsePlugin *ap = R_NEW0 (RParsePlugin);
	if (!ap) {
		return JS_ThrowRangeError (ctx, "could not allocate qjs core plugin");
	}

	JSValue desc = JS_GetPropertyStr (ctx, res, "desc");
	const char *descptr = JS_ToCStringLen2 (ctx, &namelen, desc, false);

#if 0
	JSValue license = JS_GetPropertyStr (ctx, res, "license");
	const char *licenseptr = JS_ToCStringLen2 (ctx, &namelen, license, false);
	RPluginMeta meta = {
		.name = strdup (nameptr),
		.desc = descptr ? strdup (descptr) : NULL,
		.license = descptr ? strdup (licenseptr) : NULL,
	};
	memcpy ((void*)&ap->meta, &meta, sizeof (RPluginMeta));
#else
	ap->name = strdup (nameptr);
	ap->desc = descptr ? strdup (descptr) : NULL;
	// ap->license = strdup (licenseptr);
#endif

	ap->parse = qjs_parse;  // Technically this could all be handled by a single generic plugin

	QjsParsePlugin *pp = plugin_manager_add_parse_plugin (pm, nameptr, ctx, ap, fn_parse_js);
	pp->fn_parse_js = fn_parse_js;

	RLibStruct *lib = R_NEW0 (RLibStruct);
	if (!lib) {
		free (ap);
		return JS_NewBool (ctx, false);
	}

	lib->type = R_LIB_TYPE_PARSE;
	lib->data = ap;
	lib->version = R2_VERSION;
	int ret = r_lib_open_ptr (pm->core->lib, ap->name, NULL, lib);
	return JS_NewBool (ctx, ret == 1);
}
