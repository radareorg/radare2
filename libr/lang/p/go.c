/* radare - LGPL - Copyright 2021-2022 pancake */

#include <r_lang.h>

static const char *const r2go_sym = "entry";

static bool lang_go_file(RLangSession *lang, const char *file);

static const char *const r2go_head = \
	"package main\n"
	"\n"
	"// #cgo pkg-config: r_core\n"
	"// char *r_core_cmd_str(void *p, const char *cmd);\n"
	"import \"C\"\n";

static const char *const r2go_body = \
	"import \"unsafe\"\n"
	"\n"
	"func r2cmd(core unsafe.Pointer, c string) string {\n"
	"	return C.GoString(C.r_core_cmd_str(core, C.CString(c)))\n"
	"}\n"
	"\n"
	"func main() {}\n";

typedef struct GOParse {
	RStrBuf *head;
	RStrBuf *body;
} GOParse;

static void gocode_fini(GOParse *p) {
	if (p) {
		r_strbuf_free (p->head);
		r_strbuf_free (p->body);
	}
}

static GOParse gocode_parse(const char *code) {
	GOParse vp = {0};
	vp.head = r_strbuf_new ("");
	vp.body = r_strbuf_new ("");
	char *c = strdup (code);
	char *p = c;
	char *cp = c;
	for (; *cp; cp++) {
		if (*cp == '\n') {
			*cp = 0;
			if (r_str_startswith (p, "package")) {
				// ignore r_strbuf_appendf (vp.head, "%s\n", p);
			} else if (r_str_startswith (p, "import")) {
				if (strchr (p, '(')) {
					r_strbuf_append (vp.head, "\n");
				}
				char *end = strchr (p, ')');
				if (end) {
					*end = 0;
					cp = end + 1;
				}
				r_strbuf_appendf (vp.head, "%s\n", p);
			} else {
				r_strbuf_appendf (vp.body, "%s\n", p);
			}
			p = cp + 1;
		}
	}
	if (*p) {
		r_strbuf_appendf (vp.body, "%s\n", p);
	}
	free (c);
	return vp;
}

static void gorunlib(void *user, const char *lib) {
	void *vl = r_lib_dl_open (lib, false);
	if (vl) {
		void (*fcn)(RCore *, int argc, const char **argv);
		fcn = r_lib_dl_sym (vl, r2go_sym);
		if (fcn) {
			fcn (user, 0, NULL);
		} else {
			R_LOG_ERROR ("Cannot find '%s' symbol in library", r2go_sym);
		}
		// dlclosing causes a crash, this is a know issue by Golang
		// https://github.com/golang/go/issues/32497
		// https://github.com/golang/go/issues/11100
	// 	r_lib_dl_close (vl);
	} else {
		R_LOG_ERROR ("Cannot open '%s' library", lib);
	}
}

static bool __gorun(RLangSession *session, const char *code, int len) {
	RLang *lang = session->lang;
	// r_file_rm ("tmp.go");
	FILE *fd = r_sandbox_fopen ("tmp.go", "w");
	if (fd) {
		GOParse gocode = gocode_parse (code);
		fputs (r2go_head, fd);
		fputs (r_strbuf_get (gocode.head), fd);
		fputs (r2go_body, fd);
		const char *body = r_strbuf_get (gocode.body);
		bool has_entry = strstr (body, "func entry");
		if (!has_entry) {
			fputs ("//export entry\n", fd);
			fputs ("func entry(r2 unsafe.Pointer) {\n", fd);
		}
		fputs (body, fd);
		if (!has_entry) {
			fputs ("}\n", fd);
		}
		fclose (fd);
		// system ("cat tmp.go");
		lang_go_file (session, "tmp.go");
		gorunlib (lang->user, "tmp."R_LIB_EXT);
		r_file_rm ("tmp.go");
		r_file_rm ("tmp."R_LIB_EXT);
		gocode_fini (&gocode);
		return true;
	}
	R_LOG_ERROR ("Cannot open tmp.go");
	return false;
}

static bool lang_go_file(RLangSession *session, const char *file) {
	if (!session || R_STR_ISEMPTY (file)) {
		return false;
	}
	if (!r_str_endswith (file, ".go")) {
		return false;
	}
	if (strcmp (file, "tmp.go")) {
		char *code = r_file_slurp (file, NULL);
		bool r = __gorun (session, code, -1);
		free (code);
		return r;
	}
	if (!r_file_exists (file)) {
		eprintf ("file not found (%s)\n", file);
		return false;
	}
	r_sys_setenv ("PKG_CONFIG_PATH", R2_LIBDIR"/pkgconfig");
	char *lib = r_str_replace (strdup (file), ".go", "."R_LIB_EXT, 1);
	char *buf = r_str_newf ("go build -buildmode=c-shared -o %s %s", lib, file);
	if (r_sandbox_system (buf, 1) != 0) {
		free (buf);
		free (lib);
		return false;
	}
	free (buf);
	// gorunlib (lang->user, lib);
	// r_file_rm (lib);
	free (lib);
	return 0;
}

static bool lang_go_init(RLangSession *s) {
	char *go = r_file_path ("go");
	bool found = go != NULL;
	free (go);
	return found;
}

static bool lang_go_run(RLangSession *session, const char *code, int len) {
	return __gorun (session, code, len);
}

#define r_lang_go_example ""\
	"pub fn entry(r2 &R2) {\n" \
	"  println(r2.cmd('?E Hello World'))\n" \
	"}\n"

static RLangPlugin r_lang_plugin_go = {
	.meta = {
		.name = "go",
		.author = "pancake",
		.desc = "GO language extension",
		.license = "MIT",
	},
	.ext = "go",
	.example = r_lang_go_example,
	.init = lang_go_init,
	.run = lang_go_run,
	.run_file = (void*)lang_go_file,
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_LANG,
	.data = &r_lang_plugin_go,
};
#endif
