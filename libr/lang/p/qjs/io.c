#if 0

# QuickJS IO plugin example

```js

(function() {
	let { log } = console;

	function ioExample() {
		function coreCall(input) {
			if (input.startsWith("t1")) {
				log("This is a QJS test");
				return true;
			}
			return false;
		}
		return {
			name: "qjs",
			desc: "Example QJS IO plugin (qjs://)",
			call: coreCall,
		};
	}

	r2.plugin("io", ioExample);
	r2.cmd("o my://");
	r2.cmd("x");
})();

```

#endif

static bool qjs_io_check(RIO *io, const char *name, bool perm) {
	RCore *core = io->coreb.core;
	QjsPluginManager *pm = R_UNWRAP4 (core, lang, session, plugin_data);

	// Iterate over plugins until one returns "true" (meaning the plugin handled the input)
	QjsIoPlugin *plugin;
	R_VEC_FOREACH (&pm->io_plugins, plugin) {
		JSContext *ctx = plugin->ctx;
		JSValueConst args[1] = { JS_NewString (ctx, name) };
		JSValue res = JS_Call (ctx, plugin->fn_check_js, JS_UNDEFINED, countof (args), args);
		if (JS_ToBool (ctx, res)) {
			return true;
		}
	}

	return false;
}

static int qjs_io_read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
#if 0
	buf[0] = 33;
	if (count > 5) {
		strcpy (buf, "hello");
	}
	// read stuff
	return count;
#endif
	RCore *core = io->coreb.core;
	QjsPluginManager *pm = R_UNWRAP4 (core, lang, session, plugin_data);

	// XXX this logic works for open or check, but not for seek, but its fine for 1 plugin for now
	ut64 addr = 0; // TODO: oops wheres the current seek
	QjsIoPlugin *plugin;
	R_VEC_FOREACH (&pm->io_plugins, plugin) {
		JSContext *ctx = plugin->ctx;
		JSValueConst args[2] = {
			JS_NewInt64 (ctx, addr),
			JS_NewInt32 (ctx, count),
		};
		JSValue res = JS_Call (ctx, plugin->fn_read_js, JS_UNDEFINED, countof (args), args);
		if (JS_IsArray (res)) {
			// JSObject *jo = JS_VALUE_GET_OBJ (res);
			int len = 10; //eS_ToArrayLengthFree (ctx, &le, res, true);
			// jint length = JS_GetProperty (ctx, res, JS_ATOM_Array);
			int i;
			JSValue jlen = JS_GetPropertyStr(ctx, res, "length");
			int64_t arrayLength = 10;
			JS_ToInt64 (ctx, &arrayLength, jlen);
			int length = R_MIN (arrayLength, count);
			for (i = 0; i < length; i++) {
				ut32 u;
				JSValue element = JS_GetPropertyUint32 (ctx, res, i);
				if (JS_IsException (element)) {
					R_LOG_WARN ("exception");
					break;
				}
				if (JS_ToUint32 (ctx, &u, element) != 0) {
					R_LOG_WARN ("exception2");
					break;
				}
				buf[i] = u;
			}
			return len;
		}
		R_LOG_WARN ("return is not array");
		return count;
	}
	// read stuff
	return count;
}

// static bool qjs_io_close(RIO *io, RIODesc *fd) {
static bool qjs_io_close(RIODesc *fd) {
	RIO *io = fd->io;
	RCore *core = io->coreb.core;
	QjsPluginManager *pm = R_UNWRAP4 (core, lang, session, plugin_data);

	// Iterate over plugins until one returns "true" (meaning the plugin handled the input)
	QjsIoPlugin *plugin;
	R_VEC_FOREACH (&pm->io_plugins, plugin) {
		JSContext *ctx = plugin->ctx;
		JSValueConst args[1] = { JS_NewInt32 (ctx, fd->fd) };
		JSValue res = JS_Call (ctx, plugin->fn_close_js, JS_UNDEFINED, countof (args), args);
		if (JS_ToBool (ctx, res)) {
			return true;
		}
	}
	return false;
}

static ut64 qjs_io_seek(RIO *io, RIODesc *fd, ut64 addr, int whence) {
	RCore *core = io->coreb.core;
	QjsPluginManager *pm = R_UNWRAP4 (core, lang, session, plugin_data);

	// XXX this logic works for open or check, but not for seek, but its fine for 1 plugin for now
	QjsIoPlugin *plugin;
	R_VEC_FOREACH (&pm->io_plugins, plugin) {
		JSContext *ctx = plugin->ctx;
		JSValueConst args[2] = {
			JS_NewInt64 (ctx, addr),
			JS_NewInt32 (ctx, whence),
		};
		JSValue res = JS_Call (ctx, plugin->fn_seek_js, JS_UNDEFINED, countof (args), args);
		int64_t radix = 10;
		JS_ToInt64 (ctx, &radix, res);
		return (ut64)radix;
	}
	return addr;
}

static RIODesc *qjs_io_open(RIO *io, const char *name, int perm, int mode) {
	RCore *core = io->coreb.core;
	QjsPluginManager *pm = R_UNWRAP4 (core, lang, session, plugin_data);

	// Iterate over plugins until one returns "true" (meaning the plugin handled the input)
	QjsIoPlugin *plugin;
	R_VEC_FOREACH (&pm->io_plugins, plugin) {
		JSContext *ctx = plugin->ctx;
		JSValueConst args[3] = {
			JS_NewString (ctx, name),
			JS_NewInt32 (ctx, perm),
			JS_NewInt32 (ctx, mode),
	       	};
		JSValue res = JS_Call (ctx, plugin->fn_open_js, JS_UNDEFINED, countof (args), args);
		if (JS_ToBool (ctx, res)) {
			RIOPlugin *iop = plugin->iop;
			return r_io_desc_new (io, iop, name, perm, mode, core);
		}
	}

	return NULL;
}

// TODO maybe add a function to call by plugin name? (is 1 extra arg)
static char *qjs_io_system(RIO *io, RIODesc *fd, const char *input) {
	RCore *core = io->coreb.core;
	QjsPluginManager *pm = R_UNWRAP4 (core, lang, session, plugin_data);

	// Iterate over plugins until one returns "true" (meaning the plugin handled the input)
	QjsIoPlugin *plugin;
	R_VEC_FOREACH (&pm->io_plugins, plugin) {
		JSContext *ctx = plugin->ctx;
		JSValueConst args[1] = { JS_NewString (ctx, input) };
		JSValue res = JS_Call (ctx, plugin->fn_system_js, JS_UNDEFINED, countof (args), args);
		if (JS_IsString (res)) {
			size_t namelen;
			const char *nameptr = JS_ToCStringLen2 (ctx, &namelen, res, false);
			if (!nameptr) {
				R_LOG_WARN ("r2.plugin requires the function to return an object with the `name` field");
				return NULL;
			}
			return strdup (nameptr);
		}
	}

	return NULL;
}

static JSValue r2plugin_io(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
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

	JSValue fn_check_js = JS_GetPropertyStr (ctx, res, "check");
	JSValue fn_open_js = JS_GetPropertyStr (ctx, res, "open");
	JSValue fn_read_js = JS_GetPropertyStr (ctx, res, "read");
	JSValue fn_seek_js = JS_GetPropertyStr (ctx, res, "seek");
	JSValue fn_close_js = JS_GetPropertyStr (ctx, res, "close");

	if (!JS_IsFunction (ctx, fn_check_js)
	 || !JS_IsFunction (ctx, fn_open_js)
	 || !JS_IsFunction (ctx, fn_read_js)
	 || !JS_IsFunction (ctx, fn_seek_js)
	 ) {
		R_LOG_WARN ("r2.plugin('io', X) expects X to be a function that returns an object with at least: check, open, read, seek");
		// return JS_ThrowRangeError (ctx, "r2.plugin requires the function to return an object with the `call` field to be a function");
		return JS_NewBool (ctx, false);
	}

	QjsIoPlugin *cp = plugin_manager_find_io_plugin (pm, nameptr);
	if (cp) {
		R_LOG_WARN ("r2.plugin with name %s is already registered", nameptr);
		// return JS_ThrowRangeError (ctx, "r2.plugin core already registered (only one exists)");
		return JS_NewBool (ctx, false);
	}

	RIOPlugin *ap = R_NEW0 (RIOPlugin);
	if (!ap) {
		return JS_ThrowRangeError (ctx, "could not allocate qjs core plugin");
	}

	JSValue desc = JS_GetPropertyStr (ctx, res, "desc");
	JSValue license = JS_GetPropertyStr (ctx, res, "license");
	const char *descptr = JS_ToCStringLen2 (ctx, &namelen, desc, false);
	const char *licenseptr = JS_ToCStringLen2 (ctx, &namelen, license, false);

	RPluginMeta meta = {
		.name = strdup (nameptr),
		.desc = descptr ? strdup (descptr) : NULL,
		.license = descptr ? strdup (licenseptr) : NULL,
	};
	memcpy ((void*)&ap->meta, &meta, sizeof (RPluginMeta));

	ap->check = qjs_io_check;
	ap->open = qjs_io_open;
	ap->read = qjs_io_read;
	ap->seek = qjs_io_seek;
	ap->close = qjs_io_close;
	ap->system = qjs_io_system;  // Technically this could all be handled by a single generic plugin

	QjsIoPlugin *iop = plugin_manager_add_io_plugin (pm, nameptr, ctx, ap, fn_check_js);
	iop->fn_check_js = fn_check_js;
	iop->fn_open_js = fn_open_js;
	iop->fn_seek_js = fn_seek_js;
	iop->fn_read_js = fn_read_js;
	iop->fn_close_js = fn_close_js;

	RLibStruct *lib = R_NEW0 (RLibStruct);
	if (!lib) {
		free (ap);
		return JS_NewBool (ctx, false);
	}

	lib->type = R_LIB_TYPE_IO;
	lib->data = ap;
	lib->version = R2_VERSION;
	int ret = r_lib_open_ptr (pm->core->lib, ap->meta.name, NULL, lib);
	return JS_NewBool (ctx, ret == 1);
}
