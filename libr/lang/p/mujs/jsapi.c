/* lang.mujs plugin for r2 - 2022 - pancake */

static const char *const r2_js =
	"var r2 = {cmd: r2cmd, call: r2call, cmdj: function(x) {\n"
	"  return JSON.parse(r2cmd(x));\n"
	" }\n"
	"};\n"
;
static const char *require_js =
// XXX inspect or dump !
	"function inspect(x) { try { var o = JSON.parse(x); } catch (e) { o = x; }\nreturn JSON.stringify(o,null, 2); }\n"
	"var dump = inspect;\n"
	"var exports = {}\n"
	"function require(name) {\n"
	"var cache = require.cache;\n"
	"if (name in cache) return cache[name];\n"
	"var exports = {};\n"
	"cache[name] = exports;\n"
	"Function('exports', readFileSync(name+'.js'))(exports);\n"
	"return exports;\n"
	"}\n"
	"require.cache = Object.create(null);\n"
;

static const char *const fs_js =
	"var fs = {}\n"
	"fs.readFileSync = readFileSync;\n"
	"fs.writeFileSync = writeFileSync;\n"
;

static const char *stacktrace_js =
	"Error.prototype.toString = function() {\n"
	"var s = this.name;\n"
	"if ('message' in this) s += ': ' + this.message;\n"
	"if ('stackTrace' in this) s += this.stackTrace;\n"
	"return s;\n"
	"};\n"
;
static const char *console_js =
	"var console = { log: print, debug: print, warn: print, error: print };"
;

static void jsB_write(js_State *J) {
	const char *filename = js_tostring(J, 1);
	const char *data = js_tostring(J, 2);
	bool append = false; // TODO fs.writeFileSync(path, data,{flag:'a+'});   //'a+' is append mode
	r_file_dump (filename, (const ut8*)data, strlen (data), append);
	js_pushundefined(J);
}

static void jsB_read(js_State *J) {
	const char *filename = js_tostring (J, 1);
	size_t sz = 0;
	char *data = r_file_slurp (filename, &sz);
	if (data) {
		js_pushstring (J, data);
		free (data);
	} else {
		js_error (J, "cannot read data from file '%s': %s", filename, strerror (errno));
	}
}

static void jsB_print(js_State *J) {
	int i, top = js_gettop(J);
	for (i = 1; i < top; i++) {
		const char *s = js_tostring(J, i);
	//	r_cons_printf ("%s\n", s);
	//	r_cons_flush ();
		if (i > 1) putchar(' ');
		fputs(s, stdout);
	}
	putchar('\n');
	js_pushundefined(J);
}

static void jsB_gc(js_State *J) {
	int report = js_toboolean(J, 1);
	js_gc(J, report);
	js_pushundefined(J);
}

static const char *const base64_js =
	"var Base64 = { encode : b64, decode: function(x) { return b64(x,1); }\n"
;

static void jsB_b64(js_State *J) {
	const char *input = js_tostring (J, 1);
	bool decode = js_toboolean (J, 2);
	if (decode) {
		int res = 0;
		ut8 *r = sdb_decode (input, &res);
		if (r) {
			js_pushstring (J, (const char *)r);
			free (r);
		} else {
			js_error (J, "Invalid base64 string");
		}
	} else {
		char *r = sdb_encode ((const ut8*) input, -1);
		js_pushstring (J, r);
		free (r);
	}
}
