#include <r_util.h>
#include <sdb/sdb.h>

#if HAVE_GPERF
// #define COMPILE_GPERF 1
#define COMPILE_GPERF 0
#else
#define COMPILE_GPERF 0
#endif

static char *get_name(const char *name) {
	if (R_STR_ISEMPTY (name)) {
		return NULL;
	}
	const char *l = name + strlen(name) - 1;
	while (*l && l > name) {
		if (*l == '/') {
			name = l + 1;
			break;
		}
		l--;
	}
	char *n = strdup(name);
	char *v, *d = n;
	for (v = n; *v; v++) {
		if (*v == '.') {
			break;
		}
		*d++ = *v;
	}
	*d++ = 0;
	return n;
}

static char *get_cname(const char *name) {
	if (R_STR_ISEMPTY (name)) {
		return NULL;
	}
	const char *l = name + strlen(name) - 1;
	while (*l && l > name) {
		if (*l == '/') {
			name = l + 1;
			break;
		}
		l--;
	}
	char *n = strdup(name);
	char *v, *d = n;
	for (v = n; *v; v++) {
		if (*v == '/' || *v == '-') {
			*d++ = '_';
			continue;
		}
		if (*v == '.') {
			break;
		}
		*d++ = *v;
	}
	*d++ = 0;
	return n;
}

static char *escape(const char *b, int ch) {
	char *a = calloc((1 + strlen(b)), 4);
	if (!a) {
		return NULL;
	}
	char *c = a;
	while (*b) {
		if (*b == ch) {
			*c = '_';
		} else switch (*b) {
		case '"':
			*c++ = '\\';
			*c++ = '"';
			break;
		case '\\':
			*c++ = '\\';
			*c++ = '\\';
			break;
		case '\r':
			*c++ = '\\';
			*c++ = 'r';
			break;
		case '\n':
			*c++ = '\\';
			*c++ = 'n';
			break;
		case '\t':
			*c++ = '\\';
			*c++ = 't';
			break;
		default:
			*c = *b;
			break;
		}
		b++;
		c++;
	}
	return a;
}

static bool dothec(const char *file_txt, const char *file_gperf, const char *file_c, bool compile_gperf) {
	// Extract name and cname from file_txt
	char *name = get_name (file_txt);
	if (!name) {
		return false;
	}

	char *cname = get_cname (file_txt);
	if (!cname) {
		free (name);
		return false;
	}

	bool textmode = !compile_gperf;
	
	// Generate header string using the sdb API
	char *header = sdb_cgen_header (cname, textmode);
	if (!header) {
		R_LOG_ERROR ("Failed to generate header");
		free (name);
		free (cname);
		return false;
	}
	
	// Create a string buffer for the entire file content
	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		R_LOG_ERROR ("Failed to create string buffer");
		free (header);
		free (name);
		free (cname);
		return false;
	}
	
	// Add header to the buffer
	r_strbuf_append (sb, header);
	free (header);
	
	// Read key-value pairs from the SDB file
	Sdb *db = sdb_new (NULL, NULL, 0);
	if (!db) {
		R_LOG_ERROR ("Failed to create SDB instance");
		r_strbuf_free (sb);
		free (name);
		free (cname);
		return false;
	}

	if (!sdb_text_load (db, file_txt)) {
		R_LOG_ERROR ("Failed to load SDB text file %s", file_txt);
		sdb_free (db);
		r_strbuf_free (sb);
		free (name);
		free (cname);
		return false;
	}

	// Iterate and collect all key-value pairs in the string buffer
	SdbList *l = sdb_foreach_list (db, true);
	SdbKv *kv;
	SdbListIter *it;
	
	ls_foreach_cast (l, it, SdbKv*, kv) {
		const char *k = sdbkv_key (kv);
		const char *v = sdbkv_value (kv);

		// Escape special characters
		char *ek = escape (k, ',');
		char *ev = escape (v, 0);

		if (ek && ev) {
			r_strbuf_appendf (sb, "\t{\"%s\", \"%s\"},\n", ek, ev);
			free (ek);
			free (ev);
		}
	}
	ls_free (l);

	// Generate footer string using the sdb API
	char *footer = sdb_cgen_footer (name, cname, textmode);
	if (!footer) {
		R_LOG_ERROR ("Failed to generate footer");
		sdb_free (db);
		r_strbuf_free (sb);
		free (name);
		free (cname);
		return false;
	}
	
	// Add footer to the buffer
	r_strbuf_append (sb, footer);
	free (footer);

	// Get the complete file content and write it to the file
	char *content = r_strbuf_drain (sb);
	if (!content) {
		R_LOG_ERROR ("Failed to create file content");
		sdb_free (db);
		free (name);
		free (cname);
		return false;
	}

	// Write the complete content to file
	if (!r_file_dump (file_gperf, (const ut8 *)content, strlen (content), false)) {
		R_LOG_ERROR ("Failed to write to file %s", file_gperf);
		free (content);
		sdb_free (db);
		free (name);
		free (cname);
		return false;
	}
	free (content);

	R_LOG_INFO ("Generated GPERF file: %s", file_gperf);
	if (compile_gperf) {
		char *gperf_cmd = r_str_newf ("gperf -aclEDCIG --null-strings -H sdb_hash_c_%s"
				" -N sdb_get_c_%s -t %s > %s\n", cname, cname, file_gperf, file_c);
		R_LOG_INFO ("Generating C file from gperf: %s", file_c);
		eprintf ("system: %s\n", gperf_cmd);
		int rc = system (gperf_cmd);
		free (gperf_cmd);
		if (rc == 0) {
			R_LOG_INFO ("Done");
			unlink (file_gperf);
		} else {
			R_LOG_ERROR ("Cannot generate C file: %s", file_c);
		}
	}
	sdb_free (db);
	free (name);
	free (cname);
	return true;
}

static bool dothesdb(const char *file_txt, const char *file_sdb) {
	Sdb *db = sdb_new (NULL, file_sdb, 0);
	if (sdb_text_load (db, file_txt)) {
		eprintf ("maked %s\n", file_sdb);
		sdb_sync (db);
		sdb_free (db);
		return true;
	}
	R_LOG_ERROR ("Failed to parse %s", file_txt);
	sdb_free (db);
	return false;
}

static bool dothething(const char *basedir, const char *file_txt) {
	bool compile_gperf = COMPILE_GPERF;
	char *file_sdb = r_str_ndup (file_txt, strlen (file_txt) - 4);
	char *file_c = strdup (file_sdb);
	strcpy (file_c + strlen (file_c) - 3, "c");
	char *file_gperf = strdup (file_c); // r_str_newf ("%s.gperf", file_c);

	const char *file_ref = compile_gperf? file_c: file_gperf;
	if (!r_file_exists (file_ref) || r_file_is_newer (file_txt, file_ref)) {
		R_LOG_INFO ("newer %s", file_c);
		dothec (file_txt, file_gperf, file_c, compile_gperf);
	}
	if (!r_file_exists (file_sdb) || r_file_is_newer (file_txt, file_sdb)) {
		R_LOG_INFO ("newer %s", file_sdb);
		dothesdb (file_txt, file_sdb);
	}
	free (file_c);
	free (file_gperf);
	free (file_sdb);
	return true;
}

int main(int argc, char **argv) {
	if (argc < 2) {
		R_LOG_ERROR ("Usage: sdbtool [path]");
		return 1;
	}
	char *file;
	RListIter *iter;
	const char *basedir = argv[1];
	RList *files = r_sys_dir (basedir);
	if (!files) {
		R_LOG_ERROR ("Invalid directory: %s", basedir);
		return 1;
	}
	if (!r_sys_chdir (basedir)) {
		R_LOG_ERROR ("Cannot chdir to %s", basedir);
		return 1;
	}
	r_list_foreach (files, iter, file) {
		if (r_str_endswith (file, ".sdb.txt")) {
			dothething (basedir, file);
		}
	}
	// take path as argument
	return 0;
}
