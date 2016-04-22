/* work-in-progress reverse engineered swift-demangler in C by pancake@nopcode.org */

#include <stdio.h>
#include <string.h>
#include <r_util.h>
#include <stdlib.h>

#define HAS_MAIN 0

// $ echo "..." | xcrun swift-demangle

struct Type {
	const char *code;
	const char *name;
};

static struct Type types[] = {
	/* basic types */
	{ "Sb", "Bool" },
	{ "SS", "String" },
	{ "GV", "mutableAddressor" }, // C_ARGC
	{ "Ss", "generic" }, // C_ARGC
	{ "S_", "Generic" }, // C_ARGC
	{ "Sa", "Array" },
	{ "Si", "Int" },
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

static struct Type metas [] = {
	/* attributes */
	{ "FC", "ClassFunc" },
	{ "S0_FT", "?" },
	{ "U__FQ_T_", "<A>(A)" },
	{ "ToFC", "@objc class func" },
	{ "ToF", "@objc func" },
	/* eol */
	{ NULL, NULL }
};

static struct Type flags [] = {
	{ "f", "function" },
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
	*num = atoi (n);
	while (*n>='0' && *n <='9') n++;
	return n;
}

static const char *numpos(const char* n) {
	while (*n<'0' || *n>'9') n++;
	return n;
}

static const char *getstring(const char *s, int len) {
	static char buf[256];
	if (len < 0 || len > sizeof (buf) - 2)
		return NULL;
	strncpy (buf, s, len);
	buf[len] = 0;
	return buf;
}

static const char *resolve (struct Type *t, const char *foo, const char **bar) {
	for (; t[0].code; t++) {
		int len = strlen (t[0].code);
		if (!strncmp (foo, t[0].code, len)) {
			*bar = t[0].name;
			return foo + len;
		}
	}
	return NULL;
}

char *r_bin_demangle_swift(const char *s) {
#define STRCAT_BOUNDS(x) if ((x+2+strlen (out))>sizeof (out)) break;
	static char *swift_demangle = NULL;
	char out[8192];
	int i, len, is_generic = 0;;
	int is_first = 1;
	int is_last = 0;
	int retmode = 0;
	if (!strncmp (s, "__", 2)) s = s + 2;
	if (!strncmp (s, "imp.", 4)) s = s + 4;
	if (!strncmp (s, "reloc.", 6)) s = s + 6;
#if 0
	const char *element[] = {
		"module", "class", "method", NULL
	};
#endif
	const char *attr = NULL;
	const char *attr2 = NULL;
	const char *q, *p = s;
	if (strncmp (s, "_T", 2)) {
		return NULL;
	}
	if (strchr (s, '\'') || strchr (s, ' '))
		return NULL;

	if (!swift_demangle) {
		swift_demangle = r_file_path ("swift-demangle");
		if (!swift_demangle || !strcmp (swift_demangle, "swift-demangle")) {
			char *xcrun = r_file_path ("xcrun");
			if (xcrun && strcmp (xcrun, "xcrun")) {
				free (swift_demangle);
				swift_demangle = r_str_newf ("%s swift-demangle", xcrun);
				free (xcrun);
			}
		}
	}
	if (swift_demangle) {
		char *res = r_sys_cmd_strf ("%s -compact -simplified '%s'",
			swift_demangle, s);
		if (res && !*res) {
			free (res);
			res = NULL;
		}
		return r_str_chop (res);
	}
	out[0] = 0;
	p += 2;
	if (*p == 'F' || *p == 'W') {
		q = numpos (p);
		//printf ("(%s)\n", getstring (p, (q-p)));
		for (i=0, len = 1; len; q += len, i++) {
			if (*q=='P') {
		//		printf ("PUBLIC: ");
				q++;
			}
			q = getnum (q, &len);
			if (!len)
				break;
#if 0
			printf ("%s %d %s\n", element[i],
				len, getstring (q, len));
#endif
			// push string
			if (*out)
				strcat (out, ".");
			STRCAT_BOUNDS (len);
			strcat (out, getstring (q, len));
		}
		p = resolve (flags, q, &attr);
		if (!p && *q=='U') {
			p = resolve (metas, q, &attr);
			if (attr) {
				//printf ("Template (%s)\n", attr);
			} else {
				//printf ("Findus (%s)\n", q);
			}
//			return 0;
		}
		if (attr) {
			int len;
			const char *name;
			/* get field name and then type */
			resolve (types, q, &attr);
			//printf ("Accessor: %s\n", attr);
			q = getnum (q+1, &len);
			name = getstring (q, len);
#if 0
			if (name && *name) {
				printf ("Field Name: %s\n", name);
			}
#endif
			resolve (types, q+len, &attr2);
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
		} else {
			/* parse function parameters here */
			// type len value
			for (i=0; q; i++) {
				switch (*q) {
				case 'B':
				case 'T':
				case 'I':
				case 'F':
					p = resolve (types, q+3, &attr); // type
					break;
				case 'G':
					q+=2;
					//printf ("GENERIC\n");
					if (!strncmp (q, "_V", 2)) {
						q+=2;
					}
					p = resolve (types, q, &attr); // type
					break;
				case 'V':
				//	printf ("VECTOR\n");
					p = resolve (types, q+1, &attr); // type
					break;
				case '_':

					// it's return value time!
					p = resolve (types, q+1, &attr); // type
					//printf ("RETURN TYPE %s\n", attr);
					break;
				default:
					p = resolve (types, q, &attr); // type
				}
				if (p) {
					q = p;
					q = getnum (p, &len);
					if (!strcmp (attr, "generic"))
						is_generic = 1;
					//printf ("TYPE: %s LEN %d VALUE %s\n",
					//	attr, len, getstring (q, len));
					if (!len) {
						if (retmode) {
							p = resolve (types, q+1, &attr); // type
							//printf ("RETURN TYPE %s\n", attr);
		//					printf ("RET %s\n", attr);
							strcat (out, " -> ");
							STRCAT_BOUNDS (strlen (attr));
							strcat (out, attr);
							break;
						}
						retmode = 1;
						len++;
					}
					if (q[len]) {
						const char *s = getstring (q, len);
						if (s && *s) {
							if (is_first) {	
								strcat (out, is_generic?"<":"(");
								is_first = 0;
							}
							//printf ("ISLAST (%s)\n", q+len);
							is_last = q[len];
							STRCAT_BOUNDS (strlen (attr));
							strcat (out, attr);
							strcat (out, " ");
							STRCAT_BOUNDS (strlen (s));
							strcat (out, s);
							if (is_last) {
								strcat (out, is_generic?">":")");
								is_first = 1;
							} else {
								strcat (out, ", ");
							}
						} else {
							strcat (out, " -> ");
							STRCAT_BOUNDS (strlen (attr));
							strcat (out, attr);

						}
					} else {
					}
					q += len;
				} else {
					//printf ("void\n");
					q++;
					break;
				}
			}
		}
	} else {
		//printf ("Unsupported type: %c\n", *p);
	}
	if (*out) {
		char *p, *outstr = strdup (out);
		p = outstr;
		for (;;) {
			p = strstr (p, ")(");
			if (p) {
				p[0] = '_';
				p[1] = '_';
				p+=2;
			} else break;
		}
		return outstr;
	}
	return NULL;
}
#define MAXMAIN

#if HAS_MAIN

const char *swift_tests[] = {
 "_TFC10swifthello5Hellog5WorldSS" // getter
,"_TFC10swifthello5Hellom5WorldSS" // method
,"_TFC10swifthello5Hellos5WorldSS" // setter
// Swift.String.init (Swift.String.Type)(_builtinStringLiteral : Builtin.RawPointer, byteSize : Builtin.Word, isASCII : Builtin.Int1) -> Swift.String
,"_TFSSCfMSSFT21_builtinStringLiteralBp8byteSizeBw7isASCIIBi1__SS"
// FlappyBird.GameScene.resetScene (FlappyBird.GameScene)() -> ()
,"_TFC10FlappyBird9GameScene10resetScenefS0_FT_T_"
// Swift.println <A>(A) -> ()
,"_TFSs7printlnU__FQ_T_"
// Swift.C_ARGV.mutableAddressor : Swift.UnsafeMutablePointer<Swift.UnsafeMutablePointer<Swift.Int8>>
,"_TFSsa6C_ARGVGVSs20UnsafeMutablePointerGS_VSs4Int8__"
// Swift.C_ARGC.mutableAddressor : Swift.Int32
,"_TFSsa6C_ARGCVSs5Int32"
//_swifthello.nor () -> Swift.Int
,"_TF10swifthello3norFT_Si"
,NULL
};

int main(int argc, char **argv) {
	char *ret;
	if (argc>1) {
		ret = r_bin_demangle_swift (argv[1]);
		if (ret) {
			printf ("%s\n", ret);
			free (ret);
		}
	} else {
		int i = 0;
		for (i=0; swift_tests[i]; i++) {
			printf ("\n-  %s\n", swift_tests[i]);
			ret = r_bin_demangle_swift (swift_tests[i]);
			if (ret) {
				printf ("+  %s\n", ret);
				free (ret);
			}
		}
	}
	return 0;
}
#endif
