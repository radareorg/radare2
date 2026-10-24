/* radare - LGPL - Copyright 2026 - pancake */

#define QJS_BYTECODE_MAGIC "R2JSBC\r\n"
#define QJS_BYTECODE_HEADER 40
#define QJS_BYTECODE_LIMIT (64 * 1024 * 1024)
#define QJS_BYTECODE_LZ4 1
#define QJS_BYTECODE_RAW 2
#define QJS_LZ4_BLOCK 8192

typedef struct {
	JSContext *ctx;
	RBuffer *output;
	const char *entry;
	bool ok;
} QjsCompiler;

typedef struct {
	const ut8 *data;
	ut32 size;
} QjsBytecode;

static ut64 r2qjs_bytecode_version(void) {
	char *version = r_str_newf ("%s:%s:%d", JS_GetVersion (), R2_GITTIP, (int)sizeof (void *));
	ut64 hash = r_str_hash64 (version);
	free (version);
	return hash;
}

static int r2qjs_compile_module_init(JSContext *ctx, JSModuleDef *module) {
	return 0;
}

static JSModuleDef *r2qjs_compile_module(JSContext *ctx, const char *name, void *opaque) {
	// Compile each bundle member independently, without linking or executing it.
	return JS_NewCModule (ctx, name, r2qjs_compile_module_init);
}

static bool r2qjs_compile_record(QjsCompiler *compiler, const char *name, const char *source, int flags) {
	JSContext *ctx = compiler->ctx;
	JSValue value = JS_Eval (ctx, source, strlen (source), name, flags | JS_EVAL_FLAG_COMPILE_ONLY);
	if (JS_IsException (value)) {
		js_std_dump_error (ctx);
		return false;
	}
	size_t size;
	ut8 *bytes = JS_WriteObject (ctx, &size, value, JS_WRITE_OBJ_BYTECODE);
	JS_FreeValue (ctx, value);
	if (!bytes) {
		js_std_dump_error (ctx);
		return false;
	}
	size_t namesize = strlen (name);
	bool ok = size < QJS_BYTECODE_LIMIT && namesize < QJS_BYTECODE_LIMIT
		&& r_buf_size (compiler->output) + 8 + namesize + size <= QJS_BYTECODE_LIMIT;
	ut8 header[8];
	r_write_le32 (header, namesize);
	r_write_le32 (header + 4, size);
	ok = ok && r_buf_append_bytes (compiler->output, header, sizeof (header))
		&& r_buf_append_bytes (compiler->output, (const ut8 *)name, namesize)
		&& r_buf_append_bytes (compiler->output, bytes, size);
	js_free (ctx, bytes);
	return ok;
}

static bool r2qjs_compile_member(void *user, const void *key, const void *value) {
	QjsCompiler *compiler = user;
	if (strcmp (compiler->entry, key)) {
		compiler->ok = r2qjs_compile_record (compiler, key, value, JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_STRICT);
	}
	return compiler->ok;
}

static bool r2qjs_write_bytecode(const char *file, const ut8 *bytes, size_t size, ut32 flags, bool compress) {
	// LZ4 adds at most one extension per 255 literals and a small block header.
	size_t capacity = size + size / 255 + (size / QJS_LZ4_BLOCK + 1) * 20;
	ut8 *output = malloc (QJS_BYTECODE_HEADER + capacity);
	if (!output) {
		return false;
	}
	int stored = size;
	if (compress) {
		flags |= QJS_BYTECODE_LZ4;
		stored = r_lz4_compress (output + QJS_BYTECODE_HEADER, (ut8 *)bytes, size, 1024);
	} else {
		memcpy (output + QJS_BYTECODE_HEADER, bytes, size);
	}
	memcpy (output, QJS_BYTECODE_MAGIC, 8);
	r_write_le32 (output + 8, 1);
	r_write_le32 (output + 12, flags);
	r_write_le32 (output + 16, size);
	r_write_le32 (output + 20, stored);
	r_write_le64 (output + 24, r2qjs_bytecode_version ());
	r_write_le64 (output + 32, r_str_hash64_seed ((const char *)bytes, size, 0));
	char *name = r_str_newf ("%.*s.bin.r2.js", (int)strlen (file) - 6, file);
	bool ok = stored > 0 && r_file_dump (name, output, QJS_BYTECODE_HEADER + stored, false);
	free (name);
	free (output);
	return ok;
}

static bool r2qjs_compile_file(const char *file, bool compress) {
	if (!r_sandbox_check (R_SANDBOX_GRAIN_SCRIPT)) {
		R_LOG_ERROR ("Scripting is disabled in sandbox mode");
		return false;
	}
	if (!r_str_endswith (file, ".r2.js") || r_str_endswith (file, ".bin.r2.js")) {
		R_LOG_ERROR ("Expected a source .r2.js file");
		return false;
	}
	size_t source_size;
	char *source = r_file_slurp (file, &source_size);
	if (!source) {
		R_LOG_ERROR ("Cannot read %s", file);
		return false;
	}
	if (source_size > QJS_BYTECODE_LIMIT || memchr (source, 0, source_size)) {
		R_LOG_ERROR ("Invalid or oversized JavaScript source");
		free (source);
		return false;
	}
	bool ok = false;
	JSRuntime *rt = JS_NewRuntime ();
	JSContext *ctx = rt? JS_NewContext (rt): NULL;
	if (!ctx) {
		goto done;
	}
	JS_SetModuleLoaderFunc (rt, r2qjs_normalize_module_name, r2qjs_compile_module, NULL);
	QjsCompiler compiler = { ctx, r_buf_new (), NULL, true };
	ut32 flags = strstr (source, "termInit(")? QJS_BYTECODE_RAW: 0;
	if (r_str_startswith (source, package_marker)) {
		char *entry = NULL;
		HtPP *sources = r2qjs_parse_package (source, &entry);
		if (sources) {
			compiler.entry = entry;
			compiler.ok = r2qjs_compile_record (&compiler, entry, ht_pp_find (sources, entry, NULL),
				JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_STRICT);
			if (compiler.ok) {
				ht_pp_foreach (sources, r2qjs_compile_member, &compiler);
			}
		} else {
			compiler.ok = false;
			R_LOG_ERROR ("Invalid JavaScript package");
		}
		free (entry);
		ht_pp_free (sources);
	} else {
		const bool module = *source == '-';
		compiler.ok = r2qjs_compile_record (&compiler, "-", source + module,
			module? JS_EVAL_TYPE_MODULE: JS_EVAL_TYPE_GLOBAL);
	}
	if (compiler.ok) {
		ut64 size;
		ut8 *bytes = r_buf_drain (compiler.output, &size);
		compiler.output = NULL;
		if (bytes) {
			ok = r2qjs_write_bytecode (file, bytes, size, flags, compress);
			free (bytes);
		}
	}
	r_unref (compiler.output);
done:
	if (ctx) {
		JS_FreeContext (ctx);
	}
	if (rt) {
		JS_FreeRuntime (rt);
	}
	free (source);
	return ok;
}

static JSValue r2compile(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	if (argc < 1 || argc > 2) {
		return JS_ThrowTypeError (ctx, "compile(file.r2.js, compress?)");
	}
	const char *file = JS_ToCString (ctx, argv[0]);
	if (!file) {
		return JS_EXCEPTION;
	}
	bool ok = r2qjs_compile_file (file, argc == 2 && JS_ToBool (ctx, argv[1]));
	JS_FreeCString (ctx, file);
	return ok? JS_UNDEFINED: JS_ThrowInternalError (ctx, "Cannot compile JavaScript file");
}

static JSModuleDef *r2qjs_load_bytecode_module(JSContext *ctx, const char *name, void *opaque) {
	QjsBytecode *bytecode = ht_pp_find (opaque, name, NULL);
	if (!bytecode) {
		return r2qjs_load_module (ctx, name, NULL);
	}
	JSValue value = JS_ReadObject (ctx, bytecode->data, bytecode->size, JS_READ_OBJ_BYTECODE);
	if (JS_IsException (value)) {
		return NULL;
	}
	if (JS_VALUE_GET_TAG (value) != JS_TAG_MODULE) {
		JS_FreeValue (ctx, value);
		JS_ThrowTypeError (ctx, "Expected module bytecode");
		return NULL;
	}
	JSModuleDef *module = JS_VALUE_GET_PTR (value);
	JS_FreeValue (ctx, value);
	return module;
}

static ut8 *r2qjs_bytecode_payload(const ut8 *data, size_t size) {
	if (size < QJS_BYTECODE_HEADER || memcmp (data, QJS_BYTECODE_MAGIC, 8)
			|| r_read_le32 (data + 8) != 1 || (r_read_le32 (data + 12) & ~(QJS_BYTECODE_LZ4 | QJS_BYTECODE_RAW))
			|| r_read_le64 (data + 24) != r2qjs_bytecode_version ()) {
		R_LOG_ERROR ("Invalid or incompatible JavaScript bytecode header");
		return NULL;
	}
	ut32 rawsize = r_read_le32 (data + 16);
	ut32 stored = r_read_le32 (data + 20);
	ut32 flags = r_read_le32 (data + 12);
	ut64 checksum = r_read_le64 (data + 32);
	if (!rawsize || rawsize > QJS_BYTECODE_LIMIT || stored != size - QJS_BYTECODE_HEADER) {
		return NULL;
	}
	ut8 *output = malloc (rawsize);
	if (!output) {
		return NULL;
	}
	data += QJS_BYTECODE_HEADER;
	if (flags & QJS_BYTECODE_LZ4) {
		ut32 input_offset = 0, output_offset = 0;
		while (input_offset < stored) {
			if (stored - input_offset < 4 || output_offset >= rawsize) {
				goto invalid;
			}
			ut32 blocksize = r_read_le32 (data + input_offset);
			input_offset += 4;
			if (!blocksize || blocksize > QJS_LZ4_BLOCK + 48 || blocksize > stored - input_offset) {
				goto invalid;
			}
			int written = 0;
			if (r_lz4_decompress_block ((ut8 *)data + input_offset, blocksize, &written,
					output + output_offset, R_MIN (QJS_LZ4_BLOCK, rawsize - output_offset)) < 0 || !written) {
				goto invalid;
			}
			input_offset += blocksize;
			output_offset += written;
		}
		if (output_offset != rawsize) {
			goto invalid;
		}
	} else {
		if (stored != rawsize) {
			goto invalid;
		}
		memcpy (output, data, rawsize);
	}
	if (r_str_hash64_seed ((const char *)output, rawsize, 0) != checksum) {
		goto invalid;
	}
	return output;
invalid:
	free (output);
	return NULL;
}

static bool r2qjs_eval_bytecode(JSContext *ctx, const ut8 *data, size_t size) {
	ut8 *payload = r2qjs_bytecode_payload (data, size);
	if (!payload) {
		R_LOG_ERROR ("Cannot read JavaScript bytecode");
		return false;
	}
	ut32 rawsize = r_read_le32 (data + 16);
	HtPP *modules = ht_pp_new (NULL, free_kv_str, NULL);
	QjsBytecode *entry = NULL;
	ut32 offset = 0;
	bool ok = false;
	while (offset < rawsize) {
		if (rawsize - offset < 8) {
			goto done;
		}
		ut32 namesize = r_read_le32 (payload + offset);
		ut32 codesize = r_read_le32 (payload + offset + 4);
		offset += 8;
		if (!namesize || namesize > rawsize - offset || memchr (payload + offset, 0, namesize)) {
			goto done;
		}
		char *name = r_str_ndup ((const char *)payload + offset, namesize);
		offset += namesize;
		if (!codesize || codesize > rawsize - offset || ht_pp_find (modules, name, NULL)) {
			free (name);
			goto done;
		}
		QjsBytecode *bytecode = R_NEW0 (QjsBytecode);
		bytecode->data = payload + offset;
		bytecode->size = codesize;
		ht_pp_insert (modules, name, bytecode);
		free (name);
		if (!entry) {
			entry = bytecode;
		}
		offset += codesize;
	}
	JSRuntime *rt = JS_GetRuntime (ctx);
	QjsPluginManager *pm = JS_GetRuntimeOpaque (rt);
	RCons *cons = pm->core->cons;
	bool raw = r_read_le32 (data + 12) & QJS_BYTECODE_RAW;
	current_ctx = ctx;
	r_cons_context_break_push (cons, cons->context, qjs_break_handler, NULL, false);
	JS_SetInterruptHandler (rt, qjs_interrupt_handler, cons);
	JS_SetModuleLoaderFunc (rt, r2qjs_normalize_module_name, r2qjs_load_bytecode_module, modules);
	if (raw) {
		r_cons_set_raw (cons, true);
	}
	JSValue value = JS_ReadObject (ctx, entry->data, entry->size, JS_READ_OBJ_BYTECODE);
	if (!JS_IsException (value)) {
		if (JS_VALUE_GET_TAG (value) != JS_TAG_MODULE && JS_VALUE_GET_TAG (value) != JS_TAG_FUNCTION_BYTECODE) {
			JS_FreeValue (ctx, value);
			value = JS_ThrowTypeError (ctx, "Expected script bytecode");
		} else if (JS_ResolveModule (ctx, value) < 0) {
			JS_FreeValue (ctx, value);
			value = JS_EXCEPTION;
		} else {
			value = JS_EvalFunction (ctx, value);
		}
	}
	ok = !JS_IsException (value);
	if (!ok) {
		js_std_dump_error (ctx);
	}
	JS_FreeValue (ctx, value);
	eval_jobs (ctx);
	if (raw) {
		r_cons_set_raw (cons, false);
	}
	r2qjs_modules (ctx);
	r_cons_context_break_pop (cons, cons->context, false);
	JS_SetInterruptHandler (rt, NULL, NULL);
	current_ctx = NULL;
done:
	ht_pp_free (modules);
	free (payload);
	return ok;
}
