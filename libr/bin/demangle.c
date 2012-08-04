/* radare - LGPL - Copyright 2011-2012 pancake<@nopcode.org> */

#include <r_bin.h>
#include <cxx/demangle.h>

// http://code.google.com/p/smali/wiki/TypesMethodsAndFields
R_API char *r_bin_demangle_java(const char *str) {
	RBuffer *buf;
	const char *w = NULL;
	int n = 0;
	const char *ptr;
	int is_array = 0;
	int is_ret = 0;
	int wlen = 0;

	ptr = strchr (str, '(');
	if (!ptr)
		return NULL;
	buf = r_buf_new ();
	if (!buf) return NULL;
	r_buf_append_bytes (buf, (const ut8*)str, (int)(size_t)(ptr-str));
	r_buf_append_bytes (buf, (const ut8*)" (", 2);
	while (*str) {
		switch (*str) {
		case ')':
			is_ret = 1;
			break;
		case '[':
			is_array = 1;
			break;
		case 'L':
			str++;
			ptr = strchr (str, ';');
			if (ptr) {
				w = str;
				wlen = (int)(size_t)(ptr-str);
			}
			str = ptr;
			break;
		case 'I': w = "int"; wlen = 3; break;
		case 'C': w = "char"; wlen = 4; break;
		case 'B': w = "byte"; wlen = 4; break;
		case 'V': w = "void"; wlen = 4; break;
		case 'J': w = "long"; wlen = 4; break;
		case 'F': w = "float"; wlen = 5; break;
		case 'S': w = "short"; wlen = 5; break;
		case 'D': w = "double"; wlen = 6; break;
		case 'Z': w = "boolean"; wlen = 7; break;
		}
		if (w) {
			if (is_ret) {
				r_buf_prepend_bytes (buf, (const ut8*)" ", 1);
				r_buf_prepend_bytes (buf, (const ut8*)w, wlen);
				r_buf_append_bytes (buf, (const ut8*)")", 1);
				break;
			} else {
				if (n++>0)
					r_buf_append_bytes (buf, (const ut8*)", ", 2);
				r_buf_append_bytes (buf, (const ut8*)w, wlen);
			}
			if (is_array) {
				r_buf_append_bytes (buf, (const ut8*)"[]", 2);
				is_array = 0;
			}
		}
		w = NULL;
		str++;
	}
	{
		char *ret = r_buf_to_string (buf);
		r_buf_free (buf);
		return ret;
	}
}

R_API char *r_bin_demangle_cxx(const char *str) {
	char *out;
	int flags = DMGL_PARAMS | DMGL_ANSI | DMGL_VERBOSE; // | DMGL_RET_POSTFIX | DMGL_TYPES;
	out = cplus_demangle_v3 (str, flags);
	return out;
}

R_API int r_bin_demangle_type (const char *str) {
	// XXX: add
	return R_BIN_NM_CXX;
}

R_API char *r_bin_demangle (RBin *bin, const char *str) {
	int type;
	if (bin && bin->cur.curplugin && bin->cur.curplugin->demangle_type)
		type = bin->cur.curplugin->demangle_type (str);
	else type = r_bin_demangle_type (str);
	switch (type) {
	case R_BIN_NM_JAVA: return r_bin_demangle_java (str);
	case R_BIN_NM_CXX: return r_bin_demangle_cxx (str);
	}
	return NULL;
}

#ifdef TEST
main() {
	char *out, str[128];
	strncpy (str, "_Z1hic", sizeof (str)-1);
	strncpy (str, "main(Ljava/lang/String;I)V", sizeof (str)-1);
	strncpy (str, "main([Ljava/lang/String;)V", sizeof (str)-1);
	strncpy (str, "foo([III)Ljava/lang/Integer;", sizeof (str)-1);
	//out = cplus_demangle_v3 (str, flags);
	out = r_bin_demangle_java (str); //, flags);
	printf ("INPUT (%s)\n", str);
	printf ("OUTPUT (%s)\n", out);
}
#endif
