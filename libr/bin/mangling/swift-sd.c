/* work-in-progress reverse engineered swift-demangler in C 
 * Copyright MIT 2015-2019
 * by pancake@nopcode.org */

#include <stdio.h>
#include <string.h>
#include <r_util.h>
#include <r_lib.h>
#include <stdlib.h>
#include <r_cons.h>

#define IFDBG if(0)

// $ echo "..." | xcrun swift-demangle

struct Type {
	const char *code;
	const char *name;
};

static struct Type types[] = {
	/* basic types */
	{ "Sb", "Bool" },
	{ "SS", "String" },
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
	{ "SS", "String" }, // Swift.String
	/* builtin */
	{ "Bi1", "Builtin.Int1" },
	{ "Bp", "Builtin.RawPointer" },
	{ "Bw", "Builtin.Word" }, // isASCII ?
	/* eol */
	{ NULL, NULL }
};

static struct Type metas [] = {
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

static struct Type flags [] = {
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
		*num = atoi (n);
	}
	while (*n && *n>='0' && *n <='9') {
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
	static char buf[256] = {0};
	if (len < 0 || len > sizeof (buf) - 2) {
		return "";
	}
	strncpy (buf, s, len);
	buf[len] = 0;
	return buf;
}

static const char *resolve(struct Type *t, const char *foo, const char **bar) {
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

static int have_swift_demangle = -1;

static char *swift_demangle_cmd(const char *s) {
	/* XXX: command injection issue here */
	static char *swift_demangle = NULL;
	if (have_swift_demangle == -1) {
		if (!swift_demangle) {
			have_swift_demangle = 0;
			swift_demangle = r_file_path ("swift-demangle");
			if (!swift_demangle || !strcmp (swift_demangle, "swift-demangle")) {
				char *xcrun = r_file_path ("xcrun");
				if (xcrun) {
					if (strcmp (xcrun, "xcrun")) {
						free (swift_demangle);
						swift_demangle = r_str_newf ("%s swift-demangle", xcrun);
						have_swift_demangle = 1;
					}
					free (xcrun);
				}
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
#if __UNIX__
	static bool haveSwiftCore = false;
	static char *(*swift_demangle)(const char *sym, int symlen, void *out, int *outlen, int flags) = NULL;
	if (!haveSwiftCore) {
		void *lib = r_lib_dl_open ("/usr/lib/swift/libswiftCore.dylib");
		if (lib) {
			swift_demangle = r_lib_dl_sym (lib, "swift_demangle");
		}
		haveSwiftCore = true;
	}
	if (swift_demangle) {
		return swift_demangle (s, strlen (s), NULL, NULL, 0);
	}
#endif
	return NULL;
}

R_API char *r_bin_demangle_swift(const char *s, bool syscmd) {
#define STRCAT_BOUNDS(x) if (((x) + 2 + strlen (out)) > sizeof (out)) break;
	char out[1024];
	int i, len, is_generic = 0;
	int is_first = 1;
	int is_last = 0;
	int retmode = 0;
	if (!strncmp (s, "imp.", 4)) {
		s = s + 4;
	}
	if (!strncmp (s, "reloc.", 6)) {
		s = s + 6;
	}

	if (*s != 'T' && strncmp (s, "_T", 2) && strncmp (s, "__T", 3)) {
		// modern swift symbols
		if (strncmp (s, "$s", 2)) {
			return NULL;
		}
	}

	if (!strncmp (s, "__", 2)) {
		s = s + 2;
	}
#if 0
	const char *element[] = {
		"module", "class", "method", NULL
	};
#endif
	char *res = swift_demangle_lib (s);
	if (res) {
		return res;
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

	out[0] = 0;

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
			break;
		}
	}
	if (tail) {
		if (*p) {
			p++;
		}
	} else {
		if (*p && p[1]) {
			p += 2;
		}
	}

	// XXX
	q = getnum (p, NULL);
	
	// _TF or __TW
	if (IS_DIGIT (*p) || *p == 'v' || *p == 'I' || *p == 'o' || *p == 'T' || *p == 'V' || *p == 'M' || *p == 'C' || *p == 'F' || *p == 'W') {
		if (!strncmp (p+1, "SS", 2)) {
			strcat (out, "Swift.String.init (");
			p += 3;
		}
		if (!strncmp (p, "vdv", 3)) {
			tail = "..field";
			p += 3;
		}
		if (!strncmp (p, "oFC", 3)) {
			tail = "..init.witnesstable";
			p += 4;
		}
#if 0
		if (!strncmp (p+1, "C", 2)) {
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
				strcat (out, "Swift");
			} else {
#if 0
				printf ("%s %d %s\n", element[i],
						len, getstring (q, len));
#endif
				// push string
				if (i && *out) {
					strcat (out, ".");
				}
				STRCAT_BOUNDS (len);
				len = R_MIN (len, strlen (q));
				strcat (out, getstring (q, len));
			}
		}
		if (q > q_end) {
			return 0;
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

			do {
				if (name && *name) {
					strcat (out, ".");
					STRCAT_BOUNDS (strlen (name));
					strcat (out, name);
				}
				if (attr && *attr) {
					strcat (out, ".");
					STRCAT_BOUNDS (strlen (attr));
					strcat (out, attr);
				}
				if (attr2 && *attr2) {
					strcat (out, "__");
					STRCAT_BOUNDS (strlen (attr2));
					strcat (out, attr2);
				}
			} while (0);
			if (*q == '_') {
				strcat (out, " -> ()");
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
							strcat (out, res);
						}
						q = Q + n + 1;
						continue;
					}
					break;
				case 'u':
					if (!strncmp (q, "uRxs", 4)) {
						strcat (out, "..");
						int n = 0 ;
						const char *Q = getnum (q + 4, &n);
						strcat (out, getstring (Q, n));
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
						strcat (out, " (self) -> ()");
						if (attr) {
							strcat (out, attr);
						}
						//p = q + 7;
						q = p = q + 1;
						attr = "";
						break;
					case 'S':
						// swift string
						strcat (out, "__String");
						break;
					case '_':
						// swift string
						if (q[0] && q[1] && q[2]) {
							strcat (out, "..");
							int n = 0;
							const char *Q = getnum (q + 2, &n);
							strcat (out, getstring (Q, n));
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
					strcat (out, " ()");
					p = resolve (types, (strlen (q) > 2)? q + 3: "", &attr); // type
					break;
				case 'G':
					q += 2;
					//printf ("GENERIC\n");
					if (!strncmp (q, "_V", 2)) {
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
									strcat (out, " -> ");
									STRCAT_BOUNDS (strlen (attr));
									strcat (out, attr);
								}
								break;
							}
							p = resolve (types, *q? q + 1: q, &attr); // type
							//printf ("RETURN TYPE %s\n", attr);
		//					printf ("RET %s\n", attr);
							if (attr) {
								strcat (out, " -> ");
								STRCAT_BOUNDS (strlen (attr));
								strcat (out, attr);
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
						if (s && *s) {
							if (is_first) {	
								strcat (out, is_generic?"<":"(");
								is_first = 0;
							}
							//printf ("ISLAST (%s)\n", q+len);
							is_last = q[len];
							if (attr) {
								STRCAT_BOUNDS (strlen (attr));
								strcat (out, attr);
								strcat (out, " ");
							}
							STRCAT_BOUNDS (strlen (s));
							strcat (out, s);
							if (is_last) {
								strcat (out, is_generic?">":")");
								is_first = (*s != '_');
								if (is_generic && !is_first) {
									break;
								}
							} else {
								strcat (out, ", ");
							}
						} else {
							if (attr) {
								strcat (out, " -> ");
								STRCAT_BOUNDS (strlen (attr));
								strcat (out, attr);
							}
						}
					} else {
						if (attr) {
							strcat (out, " -> ");
							STRCAT_BOUNDS (strlen (attr));
							strcat (out, attr);
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
	if (*out) {
		if (tail) {
			strcat (out, tail);
		}
#if 1
		char *p, *outstr = strdup (out);
		p = outstr;
		for (;;) {
			p = strstr (p, ")(");
			if (p) {
				p[0] = '_';
				p[1] = '_';
				p+=2;
			} else {
				break;
			}
		}
		return outstr;
#endif
	}
	return NULL;
}
