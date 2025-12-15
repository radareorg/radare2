#if 0

# QuickJS arch plugin example

```js

(function() {
	function archPlugin() {
		return {
			name: "myarch qjs plugin",
			arch: "myarch",
			desc: "this is a test arch",
			license: "LGPL3",
			cpus: "mycpu",
			decode: function(op) {
				op.mnemonic = "nop";
				return true;
			}
		}
	}

	r2.plugin("arch", archPlugin);
	r2.unload("arch", archPlugin);
})()

```

#endif

typedef struct qjs_arch_plugin_data_t {
	R_UNOWNED RCore *core;
	R_UNOWNED JSContext *ctx;
	JSValue decode_func;
	// JSValue encode_func;
} QjsArchPluginData;

static inline void cleanup_arch_plugin(RArchPlugin *ap) {
	if (ap) {
		free (ap->meta.name);
		free (ap->meta.desc);
		free (ap->meta.author);
		free (ap->meta.license);
		free (ap->meta.version);
		free (ap->arch);
		free (ap->cpus);
		free (ap);
	}
}

static inline char *qjs_get_string(JSContext *ctx, JSValue obj, const char *key) {
	JSValue value = JS_GetPropertyStr (ctx, obj, key);
	if (JS_IsUndefined (value)) {
		return NULL;
	}

	size_t valuelen;
	const char *str = JS_ToCStringLen2 (ctx, &valuelen, value, false);
	return str && valuelen > 0 ? strdup (str) : NULL;
}

static inline ut32 qjs_get_ut32(JSContext *ctx, JSValue obj, const char *key) {
	JSValue size = JS_GetPropertyStr (ctx, obj, key);
	ut32 value = -1;
	return JS_ToUint32 (ctx, &value, size) ? -1 : value;
}

static bool r2qjs_arch_init(RArchSession *s) {
	R_RETURN_VAL_IF_FAIL (s, false);

	QjsArchPluginData *pd = R_NEW0 (QjsArchPluginData);
	if (!pd) {
		return false;
	}

	RCore *core = s->user;
	QjsPluginManager *pm = R_UNWRAP4 (core, lang, session, plugin_data);
	const char *arch = R_UNWRAP3 (s, plugin, arch);
	QjsArchPlugin *plugin = plugin_manager_find_arch_plugin (pm, arch);
	if (!plugin) {
		R_LOG_ERROR ("Could not find matching qjs arch plugin");
		free (pd);
		return false;
	}

	pd->core = core;
	pd->ctx = plugin->ctx;
	pd->decode_func = plugin->decode_func;
	s->data = pd;
	return true;
}

static bool r2qjs_arch_fini(RArchSession *s) {
	if (s == NULL) {
		return false;
	}

	RCore *core = s->user;
	QjsPluginManager *pm = R_UNWRAP4 (core, lang, session, plugin_data);
	const char *arch = R_UNWRAP3 (s, plugin, arch);
	bool success = plugin_manager_remove_arch_plugin (pm, arch);
	if (!success) {
		R_LOG_ERROR ("Failed to remove qjs arch plugin");
		return false;
	}

	R_FREE (s->data);
	return true;
}

static bool r2qjs_arch_decode(RArchSession *s, RAnalOp *op, RArchDecodeMask mask) {
	R_RETURN_VAL_IF_FAIL (s, false);

	QjsArchPluginData *pd = s->data;
	JSContext *ctx = pd->ctx;

	// build object with RAnalOp info
	JSValue obj = JS_NewObject(ctx);
	// JS_SetPropertyStr (ctx, obj, "mnemonic", val);
	// JS_SetPropertyStr (ctx, obj, "bytes", val); // tied with size!
	JSValue jsv_size = JS_NewUint32 (ctx, op->size);
	JS_SetPropertyStr (ctx, obj, "size", jsv_size);

	// call js function
	JSValue args[1] = { obj };
	JSValue res = JS_Call (ctx, pd->decode_func, obj, 1, args);
	if (JS_IsException (res)) {
		R_LOG_WARN ("exception in qjs decode");
		return false;
	}

	if (!JS_IsBool (res)) {
		R_LOG_WARN ("return is not bool");
		return false;
	}

	// deserialize the data
	free (op->mnemonic);
	op->mnemonic = qjs_get_string (ctx, obj, "mnemonic");
	op->size = qjs_get_ut32 (ctx, obj, "size");
	op->type = qjs_get_ut32 (ctx, obj, "type");

	// return decode result
	return JS_ToBool (ctx, res);
}

static JSValue r2plugin_arch_load(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	JSRuntime *rt = JS_GetRuntime (ctx);
	QjsPluginManager *pm = JS_GetRuntimeOpaque (rt);
 	RCore *core = pm->core;

	if (argc != 2) {
		return JS_ThrowRangeError (ctx, "r2.plugin expects two arguments");
	}

	JSValueConst args[1] = { JS_NewString (ctx, ""), };
	JSValue res = JS_Call (ctx, argv[1], JS_UNDEFINED, countof (args), args);

	// check if res is an object
	if (!JS_IsObject (res)) {
		return JS_ThrowRangeError (ctx, "r2.plugin function must return an object");
	}

	RArchPlugin *ap = R_NEW0 (RArchPlugin);
	if (!ap) {
		return JS_ThrowRangeError (ctx, "could not allocate arch plugin");
	}

	ap->meta.name = qjs_get_string (ctx, res, "name");
	if (!ap->meta.name) {
		cleanup_arch_plugin (ap);
		return JS_ThrowRangeError (ctx, "Missing name");
	}

	ap->arch = qjs_get_string (ctx, res, "arch");
	if (!ap->arch) {
		cleanup_arch_plugin (ap);
		return JS_ThrowRangeError (ctx, "Missing arch");
	}

	// TODO initialize bits, endian

	JSValue decode_func = JS_GetPropertyStr (ctx, res, "decode");
	if (!JS_IsFunction (ctx, decode_func)) {
		cleanup_arch_plugin (ap);
		return JS_ThrowRangeError (ctx, "r2.plugin requires the function to return an object with the `decode` field to be a function");
	}

	// TODO encode

	ap->cpus = qjs_get_string (ctx, res, "cpus");
	ap->meta.desc = qjs_get_string (ctx, res, "desc");
	ap->meta.author = qjs_get_string (ctx, res, "author");
	ap->meta.license = qjs_get_string (ctx, res, "license");
	ap->meta.version = qjs_get_string (ctx, res, "version");

	// removing const is valid here, because malloc itself doesn't return const qualified object
	*((RArchPluginDecodeCallback*)&ap->decode) = r2qjs_arch_decode;
	*((RArchPluginFiniCallback*)&ap->init) = r2qjs_arch_init;
	*((RArchPluginFiniCallback*)&ap->fini) = r2qjs_arch_fini;

	// TODO remove duplicate plugin check?
	QjsArchPlugin *plugin = plugin_manager_find_arch_plugin (pm, ap->arch);
	if (plugin) {
		R_LOG_WARN ("r2.plugin with name %s is already registered", ap->meta.name);
		cleanup_arch_plugin (ap);
		return JS_NewBool (ctx, false);
	}

	plugin_manager_add_arch_plugin (pm, ap->meta.name, ap->arch, ctx, decode_func);

	RLibStruct *lib = R_NEW0 (RLibStruct);
	if (!lib) {
		R_LOG_WARN ("r2.plugin with name %s is already registered", ap->meta.name);
		cleanup_arch_plugin (ap);
		return JS_NewBool (ctx, false);
	}

	lib->type = R_LIB_TYPE_ARCH;
	lib->data = ap;
	lib->version = R2_VERSION;
	int ret = r_lib_open_ptr (core->lib, ap->meta.name, NULL, lib);
	return JS_NewBool (ctx, ret == 1);
}
