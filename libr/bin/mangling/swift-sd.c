/* work-in-progress reverse engineered swift-demangler in C
 * Copyright MIT 2015-2023 by pancake@nopcode.org */

#include <r_cons.h>
#include <r_lib.h>

#define IFDBG if (0)

// $ echo "..." | xcrun swift-demangle

static R_TH_LOCAL int have_swift_demangle = -1;
#if R2__UNIX__
static R_TH_LOCAL bool haveSwiftCore = false;
static R_TH_LOCAL char *(*swift_demangle)(const char *sym, int symlen, void *out, int *outlen, int flags, int unk) = NULL;
#endif

struct Type {
	const char *code;
	const char *name;
};

static const struct Type types[] = {
	/* basic types */
	{ "Sb", "Bool" },
	{ "SS", "Swift.String" },
	{ "FS", "String" },
	{ "GV", "mutableAddressor" }, // C_ARGC
	{ "Ss", "generic" }, // C_ARGC
	{ "S_", "Generic" }, // C_ARGC
	{ "TF", "GenericSpec" }, // C_ARGC
	{ "Ts", "String" }, // C_ARGC
	{ "Sa", "Array" },
	{ "Si", "Swift.Int" },
	{ "Sf", "Float" },
	{ "Sb", "Bool" },
	{ "Su", "UInt" },
	{ "SQ", "ImplicitlyUnwrappedOptional" },
	{ "Sc", "UnicodeScalar" },
	{ "Sd", "Double" },
	/* builtin */
	{ "Bi1", "Builtin.Int1" },
	{ "Bp", "Builtin.RawPointer" },
	{ "Bw", "Builtin.Word" }, // isASCII ?
	/* eol */
	{ NULL, NULL }
};

static const struct Type metas [] = {
	/* attributes */
	{ "FC", "ClassFunc" },
	{ "S0_FT", "?" },
	{ "RxC", ".." },
	{ "S0", "self" },
	{ "U__FQ_T_", "<A>(A)" },
	{ "ToFC", "@objc class func" },
	{ "ToF", "@objc func" },
	/* eol */
	{ NULL, NULL }
};

static const struct Type flags [] = {
	//{ "f", "function" }, // this is not an accessor
	{ "s", "setter" },
	{ "g", "getter" },
	{ "m", "method" }, // field?
	{ "d", "destructor" },
	{ "D", "deallocator" },
	{ "c", "constructor" },
	{ "C", "allocator" },
	{ NULL , NULL}
};

static const char *getnum(const char* n, int *num) {
	if (num && *n) {
#if 1
		*num = atoi (n);
#else
		char *endptr;
		int _num = (int)strtoul (n, &endptr, 10);
		if (R_UNLIKELY (n == endptr || errno == ERANGE || _num < 0)) {
			*num = -0x40000000; // arbitrarily large number
		} else {
			*num = _num;
		}
		return endptr;
#endif
	}
	while (*n && *n >= '0' && *n <='9') {
		n++;
	}
	return n;
}

static const char *numpos(const char* n) {
	while (*n && (*n < '0' || *n > '9')) {
		n++;
	}
	return n;
}

static const char *getstring(const char *s, int len) {
	static R_TH_LOCAL char buf[256] = {0};
	if (len < 0 || len > sizeof (buf) - 2) {
		return "";
	}
	strncpy (buf, s, len);
	buf[len] = 0;
	return buf;
}

static const char *resolve(const struct Type *t, const char *foo, const char **bar) {
	if (!t || !foo || !*foo) {
		return NULL;
	}
	for (; t[0].code; t++) {
		int len = strlen (t[0].code);
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
		char *res = r_sys_cmd_strf ("%s -compact '%s'",
			swift_demangle, s);
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

R_API char *r_bin_demangle_swift(const char *s, bool syscmd, bool trylib) {
	int i, len, is_generic = 0;
	int is_first = 1;
	int is_last = 0;
	int retmode = 0;
	s = str_removeprefix (s, "imp.");
	s = str_removeprefix (s, "reloc.");
	s = str_removeprefix (s, "__");
	char *res = NULL;
	if (trylib) {
		res = swift_demangle_lib (s);
		if (res) {
			return res;
		}
	}
	if (*s != 'T' && !r_str_startswith (s, "_T") && !r_str_startswith (s, "__T")) {
		// modern swift symbols not yet supported in this parser (only via trylib)
		if (!r_str_startswith (s, "$s")) {
			return NULL;
		}
	}
	const char *attr = NULL;
	const char *attr2 = NULL;
	const char *q, *p = s;
	const char *q_end = p + strlen (p);
	const char *q_start = p;

	if (strchr (s, '\'') || strchr (s, ' ')) {
		return NULL;
	}
	if (syscmd) {
		res = swift_demangle_cmd (s);
		if (res) {
			return res;
		}
	}

	const char *tail = NULL;
	if (p[0]) {
		switch (p[1]) {
		case 'W':
			switch (p[2]) {
			case 'a':
				tail = "..protocol";
				break;
			}
			break;
		case 'F':
			switch (p[2]) {
			case 'e':
				tail = "..extension";
				p += 2;
				break;
			}
			break;
		case 'M':
			switch (p[2]) {
			case 'a':
				tail = "..accessor.metadata";
				break;
			case 'e':
				tail = "..override";
				break;
			case 'm':
				tail = "..metaclass";
				break;
			case 'L':
				tail = "..lazy.metadata";
				break;
			default:
				tail = "..metadata";
				break;
			}
			break;
		case 'I': // interfaces
			/* TODO */
			return NULL; // Fix __TIFF demangling
		}
	}
	if (tail) {
		p = str_seek (p, 1);
	} else {
		if (*p && p[1]) {
			p = str_seek (p, 2);
		}
	}

	// XXX
	q = getnum (p, NULL);

	RStrBuf *out = r_strbuf_new (NULL);
	// r_return_val_if_fail (r_strbuf_reserve (out, 1024), NULL);

	// _TF or __TW
	if (IS_DIGIT (*p) || *p == 'v' || *p == 'I' || *p == 'o' || *p == 'T' || *p == 'V' || *p == 'M' || *p == 'C' || *p == 'F' || *p == 'W') {
		if (r_str_startswith (p + 1, "SS")) {
			r_strbuf_append (out, "Swift.String.init(");
			p += 3;
		}
		if (r_str_startswith (p, "vdv")) {
			tail = "..field";
			p += 3;
		}
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
		//printf ("(%s)\n", getstring (p, (q-p)));
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
				// push string
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
		if (!p && ((*q == 'U') || (*q == 'R'))) {
			p = resolve (metas, q, &attr);
			if (attr && *q == 'R') {
				attr = NULL;
				q += 3;
				//q = p + 1;
//				//printf ("Template (%s)\n", attr);
			} else {
				//printf ("Findus (%s)\n", q);
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
			if (name && *name) {
				printf ("Field Name: %s\n", name);
			}
#endif
			if (len < strlen (q)) {
				resolve (types, q + len, &attr2);
			} else {
				resolve (types, q, &attr2);
			}
//			printf ("Field Type: %s\n", attr2);

			if (name && *name) {
				r_strbuf_appendf (out, ".%s", name);
			}
			if (attr && *attr) {
				r_strbuf_appendf (out, ".%s", attr);
			}
			if (attr2 && *attr2) {
				r_strbuf_appendf (out, "__%s", attr2);
			}
			if (*q == '_') {
				r_strbuf_append (out, " -> ()");
			}
		} else {
			/* parse function parameters here */
			// type len value/
			// r_return_val_if_fail (q_start <= q_end, NULL);
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
					//printf ("GENERIC\n");
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
					//printf ("RETURN TYPE %s\n", attr);
					break;
				default:
					p = resolve (types, q, &attr); // type
				}

				if (p) {
					q = getnum (p, &len);
					if (attr && !strcmp (attr, "generic")) {
						is_generic = 1;
					}
					//printf ("TYPE: %s LEN %d VALUE %s\n",
					//	attr, len, getstring (q, len));
					if (!len) {
						if (retmode) {
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
						retmode = 1;
						len++;
					}
					if (len < 0 || len > 256) {
						// invalid length
						break;
					}
					if (len <= (q_end - q) && q[len]) {
						const char *s = getstring (q, len);
						if (R_STR_ISNOTEMPTY (s)) {
							if (is_first) {
								r_strbuf_append (out, is_generic? "<": ": ");
								is_first = 0;
							}
							//printf ("ISLAST (%s)\n", q+len);
							is_last = strlen (q+len) < 5;
							if (attr) {
								r_strbuf_append (out, attr);
								if (!is_last) {
									r_strbuf_append (out, ", ");
								}
							}
								if (strcmp (s, "_")) {
									r_strbuf_appendf (out, "%s%s", s, is_generic? ">": "");
									is_first = (*s != '_');
									if (is_generic && !is_first) {
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
					if (q && *q) {
						q++;
					} else {
						break;
					}
					char *n = strstr (q, "__");
					if (n) {
						q = n + 1;
					} else {
						n = strchr (q, '_');
						if (n) {
							q = n + 1;
						} else {
							break;
						}
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
