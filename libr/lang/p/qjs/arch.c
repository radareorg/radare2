#if 0

# QuickJS arch plugin example

```js

function archPlugin() {
	return {
		name: "myarch",
		description: "this is a test arch",
		decode: function(op) {
			op.mnemonic = "nop";
			return true;
		}
	}
}

r2.plugin("arch", archPlugin);

```

#endif

typedef struct {
	JSContext *ctx;
	RCore *core;
	JSValue decode; // decode function
} R2QJSArch;


static R_TH_LOCAL JSContext *Gctx = NULL; // XXX no globals
static R_TH_LOCAL JSValue Gres; //  = JS_UNDEFINED;

#define R2QJS_ASSERT(x, msg) if (!(x)) { return JS_ThrowRangeError (ctx, msg); }
#define R2QJS_GETNUMBER(dst, src, nam, msg) { \
	JSValue name = JS_GetPropertyStr (ctx, (src), (nam)); \
	ut32 v; \
	if (JS_ToUint32 (ctx, &v, name)) { \
		(dst) = -1; \
	} else {\
		(dst) = v; \
	} \
}
#define R2QJS_GETSTRING(dst, src, nam, msg) { \
	JSValue name = JS_GetPropertyStr (ctx, (src), (nam)); \
	size_t namelen; \
	const char *strp = JS_ToCStringLen2 (ctx, &namelen, name, false); \
	if (strp && namelen > 0) { \
		(dst) = strdup (strp); \
	} else { \
		if (msg) { \
			errmsg = (msg); \
			goto failure; \
		} else { \
			(dst) = NULL; \
		} \
	} \
}

#define R2QJS_REGISTER_PLUGIN(typ, nam, ap) { \
	int ret = -1; \
	RLibStruct *lib = R_NEW0 (RLibStruct); \
	if (lib) { \
		lib->type = (typ); \
		lib->data = (ap); \
		lib->version = R2_VERSION; \
		ret = r_lib_open_ptr (core->lib, (nam), NULL, lib); \
	} \
	return JS_NewBool (ctx, (ret == 1)); }
static bool r2qjs_arch_decode(RArchSession *s, struct r_anal_op_t *op, RArchDecodeMask mask) {
	const char *errmsg = NULL;
	R2QJSArch *rqa = (R2QJSArch *)s->data;
	JSContext *ctx = rqa->ctx;
	// build object with RAnalOp info
		JSValue obj = JS_NewObject(ctx);
		// JS_SetPropertyStr (ctx, obj, "mnemonic", val);
		// JS_SetPropertyStr (ctx, obj, "bytes", val); // tied with size!
		JSValue jsv_size = JS_NewUint32 (ctx, op->size);
		JS_SetPropertyStr (ctx, obj, "size", jsv_size);
	// call js function
		JSValue args[1] = { obj };
		JSValue res = JS_Call (ctx, rqa->decode, obj, 1, args);
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
		R2QJS_GETSTRING (op->mnemonic, obj, "mnemonic", NULL);
		R2QJS_GETNUMBER (op->size, obj, "size", NULL);
		if (op->mnemonic) {
			op->mnemonic = strdup (op->mnemonic);
		}
		R2QJS_GETNUMBER (op->type, obj, "type", NULL);
	// return value
	return JS_ToBool (ctx, res);
failure:
	if (errmsg) {
		R_LOG_ERROR ("%s", errmsg);
		return false;
	}
	return false;
}

static bool r2qjs_arch_init(RArchSession *s) {
	R2QJSArch *qa = R_NEW0 (R2QJSArch);
	if (qa && Gctx) {
		qa->ctx = Gctx;
		qa->core = s->user;
		JSValue func = JS_GetPropertyStr (qa->ctx, Gres, "decode");
		if (!JS_IsFunction (qa->ctx, func)) {
			R_LOG_WARN ("r2.plugin requires the function to return an object with the `call` field to be a function");
			free (qa);
			return false;
		}
		qa->decode = func;
		s->data = qa;
	}
	return true;
}

static JSValue r2plugin_arch(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	Gctx = ctx; // XXX no globals
	const char *errmsg = NULL;
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
	RArchPlugin *ap = R_NEW0 (RArchPlugin);
	R2QJS_ASSERT (ap, "heap failure");
	R2QJS_GETSTRING (ap->meta.name, res, "name", "Missing name");
	R2QJS_GETSTRING (ap->arch, res, "arch", "Missing arch");
	R2QJS_GETSTRING (ap->cpus, res, "cpus", NULL);
	R2QJS_GETSTRING (ap->meta.desc, res, "desc", NULL);
	R2QJS_GETSTRING (ap->meta.author, res, "author", NULL);
	R2QJS_GETSTRING (ap->meta.license, res, "license", NULL);
	R2QJS_GETSTRING (ap->meta.version, res, "version", NULL);

	Gres = res;
	ap->decode = r2qjs_arch_decode;
	ap->init = r2qjs_arch_init;
	// ap->fini = r2qjs_arch_fini;
	// TODO bits, endian
#if 0
	JSValue func = JS_GetPropertyStr (ctx, res, "decode");
	if (!JS_IsFunction (ctx, func)) {
		errmsg = "r2.plugin requires the function to return an object with the `call` field to be a function";
		goto failure;
	}
#if 0
	R2QJS_GETFUNCTION (ap->decode, res, "decode", NULL);
	R2QJS_GETFUNCTION (ap->encode, res, "encode", NULL);
#endif
#endif

	R2QJS_REGISTER_PLUGIN (R_LIB_TYPE_ARCH, ap->meta.name, ap);
failure:
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
	if (errmsg) {
		return JS_ThrowRangeError (ctx, "%s", errmsg);
	}
	return JS_NewBool (ctx, false);
}
