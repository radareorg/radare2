/* work-in-progress reverse engineered swift-demangler in C
 * Copyright MIT 2015-2023 by pancake@nopcode.org */

#include <r_cons.h>
#include <r_lib.h>

// set this to true for debugging purposes
#define USE_THIS_CODE 1

static R_TH_LOCAL int have_swift_demangle = -1;
#if R2__UNIX__
static R_TH_LOCAL bool haveSwiftCore = false;
static R_TH_LOCAL char *(*swift_demangle)(const char *sym, int symlen, void *out, int *outlen, int flags, int unk) = NULL;
#endif

typedef struct {
	const char *code;
	const char *name;
} SwiftType;

/* basic types */
static const SwiftType types[] = {
	{ "Bi1", "Builtin.Int1" },
	{ "Bb", "Builtin.BridgeObject" },
	{ "BB", "Builtin.UnsafeValueBuffer" },
	{ "Bo", "Builtin.NativeObject" },
	{ "BO", "Builtin.UnknownObject" },
	{ "Bp", "Builtin.RawPointer" },
	{ "Bt", "Builtin.SILToken" },
	{ "Bw", "Builtin.Word" },
	{ "FS", "String" },
	{ "GV", "mutableAddressor" },
	{ "Sa", "Array" },
	{ "Sb", "Bool" },
	{ "SC", "Syntesized" },
	{ "Sc", "UnicodeScalar" },
	{ "Sd", "Swift.Double" },
	{ "Sf", "Swift.Float" },
	{ "Si", "Swift.Int" },
	{ "Sp", "UnsafeMutablePointer" },
	{ "SP", "UnsafePointer" },
	{ "SQ", "ImplicitlyUnwrappedOptional" },
	{ "Sq", "Optional" },
	{ "SR", "UnsafeBufferPointer" },
	{ "Sr", "UnsafeMutableBufferPointer" },
	// { "So", "Swift.Optional" },
	{ "Ss", "generic" },
	{ "SS", "Swift.String" },
	{ "Su", "UInt" },
	{ "Sv", "UnsafeMutableRawPointer" },
	{ "SV", "UnsafeRawPointer" },
	{ "S_", "Generic" },
	{ "TF", "GenericSpec" },
	{ "Ts", "String" },
	{ NULL, NULL }
};

/* attributes */
static const SwiftType metas [] = {
	{ "FC", "ClassFunc" },
	{ "S0_FT", "?" },
	{ "RxC", ".." },
	{ "S0", "self" },
	{ "U__FQ_T_", "<A>(A)" },
	{ "ToFC", "@objc class func" },
	{ "ToF", "@objc func" },
	{ NULL, NULL }
};

static const SwiftType flags [] = {
	//{ "f", "function" }, // this is not an accessor
	{ "s", "setter" },
	{ "g", "getter" },
	{ "m", "method" }, // field?
	{ "d", "destructor" },
	{ "D", "deallocator" },
	{ "c", "constructor" },
	{ "C", "allocator" },
	{ NULL, NULL}
};

static const char *getnum(const char* n, int *num) {
	if (num && *n) {
		*num = atoi (n);
	}
	while (*n && *n >= '0' && *n <='9') {
		n++;
	}
	return n;
	//return numpos (n);
}

static const char *numpos(const char* n) {
	while (*n && (*n < '0' || *n > '9')) {
		n++;
	}
	return n;
}

static const char *getstring(const char *s, int len) {
	static R_TH_LOCAL char buf[256] = {0};
	if (len < 0 || len > sizeof (buf) - 1) {
		return "";
	}
	r_str_ncpy (buf, s, len + 1);
	return buf;
}

static const char *resolve(const SwiftType *t, const char *foo, const char **bar) {
	if (R_STR_ISEMPTY (foo)) {
		return NULL;
	}
	for (; t[0].code; t++) {
		const int len = strlen (t[0].code);
		if (!strncmp (foo, t[0].code, len)) {
			if (bar) {
				*bar = t[0].name;
			}
			return foo + len;
		}
	}
	return NULL;
}

static char *swift_demangle_cmd(const char *s) {
	/* XXX: command injection issue here */
	static R_TH_LOCAL char *swift_demangle = NULL;
	if (have_swift_demangle == -1) {
		if (!swift_demangle) {
			have_swift_demangle = 0;
			swift_demangle = r_file_path ("swift-demangle");
			if (!swift_demangle) {
				char *xcrun = r_file_path ("xcrun");
				if (xcrun) {
					free (swift_demangle);
					swift_demangle = r_str_newf ("%s swift-demangle", xcrun);
					have_swift_demangle = 1;
				}
				free (xcrun);
			}
		}
	}
	if (swift_demangle) {
		if (strchr (s, '\'') || strchr (s, '\\')) {
			/* nice try */
			return NULL;
		}
		//char *res = r_sys_cmd_strf ("%s -compact -simplified '%s'",
		char *res = r_sys_cmd_strf ("%s -compact '%s'", swift_demangle, s);
		if (res && !*res) {
			free (res);
			res = NULL;
		}
		r_str_trim (res);
		return res;
	}
	return NULL;
}

static char *swift_demangle_lib(const char *s) {
#if R2__UNIX__
	if (!haveSwiftCore) {
		void *lib = r_lib_dl_open ("/usr/lib/swift/libswiftCore." R_LIB_EXT);
		if (!lib) {
			lib = r_lib_dl_open ("/usr/lib/libswiftCore." R_LIB_EXT);
			if (!lib) {
				lib = r_lib_dl_open ("libswiftCore");
				if (!lib) {
					lib = r_lib_dl_open ("/usr/lib/swift/libswiftDemangle." R_LIB_EXT);
					if (!lib) {
						lib = r_lib_dl_open ("libswiftDemangle");
					}
				}
			}
		}
		if (lib) {
			swift_demangle = r_lib_dl_sym (lib, "swift_demangle");
		}
		haveSwiftCore = true;
	}
	if (swift_demangle) {
		return swift_demangle (s, strlen (s), NULL, NULL, 0, 0);
	}
#endif
	return NULL;
}

static const char *str_seek(const char *s, int n) {
	int i;
	for (i = 0; i < n && *s; i++) {
		s++;
	}
	return s;
}

static inline const char *str_removeprefix(const char *s, const char *prefix) {
	const size_t prefix_len = strlen (prefix);
	if (r_str_startswith (s, prefix)) {
		s += prefix_len;
	}
	return s;
}

static bool looks_valid(char p) {
	if (IS_DIGIT (p)) {
		return true;
	}
	switch (p) {
	case 'F':
	case 'I':
	case 'M':
	case 'o':
	case 's':
	case 't':
	case 'T':
	case 'v':
	case 'V':
	case 'W':
		return true;
	}
	return false;
}

typedef struct {
	bool generic;
	bool first;
	bool last;
	bool retmode;
} SwiftCheck;

typedef struct {
	SwiftCheck is;
	RStrBuf *out;
	const char *tail;
} SwiftState;

static char *get_mangled_tail(const char **pp, RStrBuf *out) {
	const char *p = *pp;
	if (R_STR_ISEMPTY (p)) {
		return NULL;
	}
	switch (p[1]) {
	case 'T':
		r_strbuf_append (out, "Swift.");
		// type like 'SwiftObject'
		break;
	case 'W':
		switch (p[2]) {
		case 'a':
			return "..protocol";
		}
		break;
	case 'F':
		switch (p[2]) {
		case 'e':
			*pp += 2; // XXX evaluate if this is really needed
			return "..extension";
		}
		break;
	case 's':
		// nothing here
		break;
	case 'M':
		switch (p[2]) {
		case 'a':
			return "..accessor.metadata";
		case 'e':
			return "..override";
		case 'm':
			return "..metaclass";
		case 'L':
			return "..lazy.metadata";
		default:
			return "..metadata";
		}
		break;
	case 'I': // interfaces
		// TODO: Fix __TIFF demangling
		return "..interface";
	}
	return NULL;
}

static char *my_swift_demangler(const char *s) {
	// SwiftState ss = { 0 };
	SwiftCheck is = {0};
	is.first = true;

	int i, len;
	const char *attr = NULL;
	const char *attr2 = NULL;
	const char *q, *p = s;
	const char *q_end = p + strlen (p);
	const char *q_start = p;

	bool trick = r_str_startswith (p, "s");
	RStrBuf *out = r_strbuf_new (NULL);
	const char *tail = get_mangled_tail (&p, out);
	// workaround with tests, need proper testing when format is clarified
	if (trick) {
		if (!isdigit (p[1])) {
			return NULL;
		}
		if (p[1] && p[2]) {
			int len = atoi (p + 1);
			if (len > strlen (p + 2)) {
				return NULL;
			}
		}
		// do nothing
	} else {
		p = str_seek (p, tail? 1: (p[0] && p[1])? 2: 0);
	}
	q = getnum (p, NULL);

	// _TF or __TW
	if (looks_valid (*p)) {
		if (r_str_startswith (p + 1, "SS")) {
			r_strbuf_append (out, "String.init(");
			p += 3;
		}
		// TODO: move into get_tail()
		if (r_str_startswith (p, "vdv")) {
			tail = "..field";
			p += 3;
		}
		// TODO: move into get_tail()
		if (r_str_startswith (p, "oFC")) {
			tail = "..init.witnesstable";
			p = str_seek (p, 4); // XXX
		}
#if 0
		if (r_str_startswith (p+1, "C")) {
			strcat (out, "class ");
			p += 3;
		}
#endif
		q = getnum (q, &len);
		q = numpos (p);
		// printf ("(%s)\n", getstring (p, (q-p)));
		for (i = 0, len = 1; len && q < q_end; q += len, i++) {
			if (*q == 'P') {
		//		printf ("PUBLIC: ");
				q++;
			}
			q = getnum (q, &len);
			if (!len) {
				break;
			}
			const char *str = getstring (q, len);
			if (len == 2 && !strcmp (str, "ee")) {
				r_strbuf_append (out, "Swift");
			} else {
				if (i && r_strbuf_length (out) > 0) {
					r_strbuf_append (out, ".");
				}
				len = R_MIN (len, strlen (q));
				r_strbuf_append (out, getstring (q, len));
			}
		}
		if (q > q_end) {
			r_strbuf_free (out);
			return NULL;
		}
		p = resolve (flags, q, &attr);
#if 0
		if (attr && !strcmp (attr, "allocator")) {
			char *o = r_strbuf_drain (out);
			char *r = r_str_newf ("__C.%s", o);
			free (o);
			return r;
		}
#endif
		if (!p && ((*q == 'U') || (*q == 'R'))) {
			p = resolve (metas, q, &attr);
			if (attr && *q == 'R') {
				attr = NULL;
				q += 3;
//				//printf ("Template (%s)\n", attr);
			}
//			return 0;
		}
		/* parse accessors */
		if (attr) {
			int len = 0;
			const char *name;
			/* get field name and then type */
			resolve (types, q, &attr);

			//printf ("Accessor: %s\n", attr);
			q = getnum (q + 1, &len);
			name = getstring (q, len);
#if 0
			if (R_STR_ISNOTEMPTY (name)) {
				printf ("Field Name: %s\n", name);
			}
#endif
			const char *arg = (len < strlen (q))? q + len: q;
			resolve (types, arg, &attr2);
//			printf ("Field Type: %s\n", attr2);

			if (R_STR_ISNOTEMPTY (name)) {
				r_strbuf_appendf (out, ".%s", name);
			}
			if (R_STR_ISNOTEMPTY (attr)) {
				r_strbuf_appendf (out, ".%s", attr);
			}
			if (R_STR_ISNOTEMPTY (attr2)) {
				r_strbuf_appendf (out, "__%s", attr2);
			}
			if (*q == '_') {
				r_strbuf_append (out, " -> ()");
			}
		} else {
			/* parse function parameters here */
			// type len value/
			for (i = 0; q && q < q_end && q >= q_start; i++) {
				if (*q == 'f') {
					q++;
				}
				switch (*q) {
				case 's':
					{
						int n = 0;
						const char *Q = getnum (q + 1, &n);
						const char *res = getstring (Q, n);
						if (res) {
							r_strbuf_append (out, res);
						}
						q = Q + n + 1;
						continue;
					}
					break;
				case 'u':
					if (r_str_startswith (q, "uRxs")) {
						int n = 0;
						const char *Q = getnum (q + 4, &n);
						r_strbuf_appendf (out, "..%s", getstring (Q, n));
						q = Q + n + 1;
						continue;
					}
					break;
				case 'S': // "S0"
					if (q[1] == '1') {
						q++;
					}
					switch (q[1]) {
					case '0':
						r_strbuf_append (out, " (self) -> ()");
						if (attr) {
							r_strbuf_append (out, attr);
						}
						q = p = q + 1;
						attr = "";
						break;
					case 'S':
						// swift string
						r_strbuf_append (out, "__String");
						break;
					case '_':
						// swift string
						if (q[0] && q[1] && q[2]) {
							int n = 0;
							const char *Q = getnum (q + 2, &n);
							r_strbuf_appendf (out, "..%s", getstring (Q, n));
							q = Q + n + 1;
							continue;
						}
						break;
					}
					break;
				case 'B':
				case 'T':
				case 'I':
					p = resolve (types, q + 0, &attr); // type
					if (p && *p && IS_DIGIT (p[1])) {
						p--;
					}
					break;
				case 'F':
					r_strbuf_append (out, " ()");
					p = resolve (types, (strlen (q) > 2)? q + 3: "", &attr); // type
					break;
				case 'G':
					q = str_seek (q, 2);
					// printf ("GENERIC\n");
					if (r_str_startswith (q, "_V")) {
						q += 2;
					}
					p = resolve (types, q, &attr); // type
					break;
				case 'V':
					p = resolve (types, q + 1, &attr); // type
					break;
				case '_':
					// it's return value time!
					p = resolve (types, q + 1, &attr); // type
					// printf ("RETURN TYPE %s\n", attr);
					break;
				default:
					p = resolve (types, q, &attr); // type
					break;
				}
				if (p) {
					q = getnum (p, &len);
					if (attr && !strcmp (attr, "generic")) {
						is.generic = true;
					}
					//printf ("TYPE: %s LEN %d VALUE %s\n",
					//	attr, len, getstring (q, len));
					if (!len) {
						if (is.retmode) {
							if (q + 1 > q_end) {
								if (attr) {
									r_strbuf_appendf (out, " -> %s", attr);
								}
								break;
							}
							p = resolve (types, *q? q + 1: q, &attr);
							// printf ("RETURN TYPE %s\n", attr);
							// printf ("RET %s\n", attr);
							if (attr) {
								r_strbuf_appendf (out, " -> %s", attr);
							}
							break;
						}
						is.retmode = true;
						len++;
					}
					if (len < 0 || len > 256) {
						// invalid length
						break;
					}
					if (len <= (q_end - q) && q[len]) {
						const char *s = getstring (q, len);
						if (R_STR_ISNOTEMPTY (s)) {
							if (is.first) {
								r_strbuf_append (out, is.generic? "<": ": ");
								is.first = false;
							}
							is.last = strlen (q + len) < 5;
							if (attr) {
								r_strbuf_append (out, attr);
								if (!is.last) {
									r_strbuf_append (out, ", ");
								}
							}
								if (strcmp (s, "_")) {
									r_strbuf_appendf (out, "%s%s", s, is.generic? ">": "");
									is.first = (*s != '_');
									if (is.generic && !is.first) {
										break;
									}
								} else {
									r_strbuf_append (out, ")");
								}
						} else {
							if (attr) {
								r_strbuf_appendf (out, " -> %s", attr);
							}
						}
					} else {
						if (attr) {
							r_strbuf_appendf (out, " -> %s", attr);
						}
					}
					q += len;
					p = q;
				} else {
					if (R_STR_ISEMPTY (q)) {
						break;
					}
					q++;
					char *n = strstr (q, "__");
					if (n) {
						q = n + 1;
					} else {
						n = strchr (q, '_');
						if (!n) {
							break;
						}
						q = n + 1;
					}
				}
			}
		}
	} else {
		//printf ("Unsupported type: %c\n", *p);
	}
	// https://www.guardsquare.com/blog/swift-native-method-swizzling
	if (r_str_endswith (s, "FTX")) {
		r_strbuf_prepend (out, "dynamic variable ");
	} else if (r_str_endswith (s, "FTx")) {
		r_strbuf_prepend (out, "dynamic key ");
	} else if (r_str_endswith (s, "FTI"))  {
		r_strbuf_prepend (out, "dynamic thunk ");
	} else if (r_str_endswith (s, "ivs"))  {
		r_strbuf_prepend (out, "setter ");
	} else if (r_str_endswith (s, "ivg"))  {
		r_strbuf_prepend (out, "getter ");
	}

	if (r_strbuf_length (out) > 0) {
		if (tail) {
			r_strbuf_append (out, tail);
		}
#if 1
		char *p, *outstr = r_strbuf_drain (out);
		p = outstr;
		for (;;) {
			p = strstr (p, ")(");
			if (!p) {
				break;
			}
			p[0] = '_';
			p[1] = '_';
			p += 2;
		}
		return outstr;
#endif
	}
	r_strbuf_free (out);
	return NULL;
}

R_API char *r_bin_demangle_swift(const char *s, bool syscmd, bool trylib) {
#if 0
	if (strstr (s, "UITableViewHeaderFoote")) {
		eprintf ("==> (%s)\n", s);
	}
#endif
#if USE_THIS_CODE
	syscmd = trylib = false; // useful for debugging the embedded demangler on macos
#endif
	const char *space = strchr (s, ' ');
	if (space) {
		if (isdigit (space[1])) {
			char *ss = r_str_newf ("$s%s", space + 1);
			char *res = r_bin_demangle_swift (ss, syscmd, trylib);
			free (ss);
			return res;
		}
		if (space) {
			char *res = r_bin_demangle_swift (space + 1, syscmd, trylib);
			if (res) {
				if (strstr (s, "symbolic")) {
					char *ss = r_str_newf ("symbolic %s", res);
					free (res);
					return ss;
				}
				return res;
			}
		}
	}
	if (!syscmd && !trylib) {
		if (r_str_startswith (s, "$s")) {
			s += 2;
		}
		if (r_str_startswith (s, "So") && r_str_endswith (s, "C")) {
			int len = atoi (s + 2);
			s += 2;
			while (isdigit (*s)) {
				s++;
			}
			char *ns = r_str_ndup (s, len);
			char *fs = r_str_newf ("__C.%s", ns);
			free (ns);
			return fs;
		}
	}
#if 0
	if (syscmd || trylib) {
		if (r_str_startswith (s, "So") && isdigit (s[2])) {
			char *ss = r_str_newf ("$s%s", s);
			char *res = r_bin_demangle_swift (ss, syscmd, trylib);
			free (ss);
			return res;
		}
	} else {
#endif
//	}
	s = str_removeprefix (s, "imp.");
	s = str_removeprefix (s, "reloc.");
	// check if string doesnt start with __ then return
	s = str_removeprefix (s, "__"); // NOOO

	if (trylib) {
		char *res = swift_demangle_lib (s);
		if (res) {
			return res;
		}
	}

	if (*s != 's' && *s != 'T' && !r_str_startswith (s, "_T") && !r_str_startswith (s, "__T")) {
		// modern swift symbols not yet supported in this parser (only via trylib)
		if (!r_str_startswith (s, "$s")) {
			switch (*s) {
			case 'S':
			case 'B':
				{
					const char *attr = NULL;
					resolve (types, s, &attr); // type
					if (attr) {
						return strdup (attr);
					}
				}
				break;
			}
			return NULL;
		}
	} else {
		// TIFF ones found on COFF binaries, swift-unrelated, return early to avoid FP
		if (r_str_startswith (s, "TIFF")) {
			return NULL;
		}
	}

	if (strchr (s, '\'') || strchr (s, ' ')) {
		return NULL;
	}
	if (syscmd) {
		char *res = swift_demangle_cmd (s);
		if (res) {
			return res;
		}
	}
	return my_swift_demangler (s);
}
