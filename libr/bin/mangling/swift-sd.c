/* work-in-progress reverse engineered swift-demangler in C 
 * Copyright MIT 2015-2016
 * by pancake@nopcode.org */

#include <stdio.h>
#include <string.h>
#include <r_util.h>
#include <stdlib.h>
#include <r_cons.h>

#ifndef HAS_MAIN
#define HAS_MAIN 0
#endif

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
	{ "GV", "mutableAddressor" }, // C_ARGC
	{ "Ss", "generic" }, // C_ARGC
	{ "S_", "Generic" }, // C_ARGC
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

static const char *findnum(const char* n) {
	while (*n < '0' || *n >'9') n++;
	return n;
}

static const char *getnum(const char* n, int *num) {
	if (num) *num = atoi (n);
	while (*n>='0' && *n <='9') n++;
	return n;
}

static const char *numpos(const char* n) {
	while (*n && *n<'0' || *n>'9') n++;
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

static const char *resolve(struct Type *t, const char *foo, const char **bar) {
	if (!foo || !*foo) {
		return NULL;
	}
	for (; t[0].code; t++) {
		int len = strlen (t[0].code);
		if (!strncmp (foo, t[0].code, len)) {
			*bar = t[0].name;
			return foo + len;
		}
	}
	return NULL;
}

static int have_swift_demangle = -1;

static char *swift_demangle_cmd(const char *s) {
	static char *swift_demangle = NULL;
	if (have_swift_demangle == -1) {
		if (!swift_demangle) {
			have_swift_demangle = 0;
			swift_demangle = r_file_path ("swift-demangle");
			if (!swift_demangle || !strcmp (swift_demangle, "swift-demangle")) {
				char *xcrun = r_file_path ("xcrun");
				if (xcrun && strcmp (xcrun, "xcrun")) {
					free (swift_demangle);
					swift_demangle = r_str_newf ("%s swift-demangle", xcrun);
					have_swift_demangle = 1;
					free (xcrun);
				}
			}
		}
	}
	if (swift_demangle) {
		//char *res = r_sys_cmd_strf ("%s -compact -simplified '%s'",
		char *res = r_sys_cmd_strf ("%s -compact '%s'",
			swift_demangle, s);
		if (res && !*res) {
			free (res);
			res = NULL;
		}
		return r_str_chop (res);
	}
	return NULL;
}

char *r_bin_demangle_swift(const char *s, int syscmd) {
#define STRCAT_BOUNDS(x) if ((x + 2 + strlen (out)) > sizeof (out)) break;
	char out[1024];
	int i, len, is_generic = 0;
	int is_first = 1;
	int is_last = 0;
	int retmode = 0;
	if (!strncmp (s, "imp.", 4)) s = s + 4;
	if (!strncmp (s, "reloc.", 6)) s = s + 6;

	if (*s != 'T' && strncmp (s, "_T", 2) && strncmp (s, "__T", 3)) {
		return NULL;
	}

	if (!strncmp (s, "__", 2)) s = s + 2;
#if 0
	const char *element[] = {
		"module", "class", "method", NULL
	};
#endif
	const char *attr = NULL;
	const char *attr2 = NULL;
	const char *q, *p = s;

	if (strchr (s, '\'') || strchr (s, ' ')) {
		return NULL;
	}
	if (syscmd) {
		char *res = swift_demangle_cmd (s);
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
	p += (tail? 1: 2);

	// XXX
	q = getnum (p, NULL);
	
	if (IS_NUMBER (*p) || *p == 'v' || *p == 'o' || *p == 'V' || *p == 'M' || *p == 'C' || *p == 'F' || *p == 'W') { // _TF or __TW
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
		if (len > 0) {
			p = q;
		}

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
			if (i && *out) strcat (out, ".");
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
		/* parse accessors */
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
			if (q && *q == '_') {
				strcat (out, " -> ()");
			}
		} else {
			/* parse function parameters here */
			// type len value/
			for (i=0; q; i++) {
				if (*q == 'f') q++;
				switch (*q) {
				case 'S': // "S0"
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
						{
							strcat (out, "..");
							int n;
							char *Q = getnum (q + 2, &n);
							strcat (out, getstring (Q, n));
							q = Q;
						}
						break;
					}
					break;
				case 'B':
				case 'T':
				case 'I':
					p = resolve (types, q + 0, &attr); // type
					break;
				case 'F':
					strcat (out, " ()");
					p = resolve (types, q + 3, &attr); // type
					break;
				case 'G':
					q+=2;
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
					}
					q += len;
				} else {
						q++;
					break;
				}
			}
		}
	} else {
		//printf ("Unsupported type: %c\n", *p);
	}
	if (*out) {
		if (tail)
			strcat (out, tail);
#if 1
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
#endif
	}
	return NULL;
}
#define MAXMAIN

#if HAS_MAIN

typedef struct {
	const char *sym;
	const char *dem;
} Test;

Test swift_tests[] = {
{
	"_TFSSCfT21_builtinStringLiteralBp8byteSizeBw7isASCIIBi1__SS"
	,"Swift.String.init (_builtinStringLiteral(Builtin.RawPointer byteSize__Builtin.Word isASCII__Builtin.Int1 _) -> String"
	//, "Swift.String.init (Swift.String.Type) -> (_builtinStringLiteral : Builtin.RawPointer, byteSize : Builtin.Word, isASCII : Builtin.Int1) -> Swift.String
},{
	"_TFC10swifthello5Hellog5WorldSS" // getter
	,"swifthello.Hello.World.getter__String"
	// swifthello.Hello.World.getter : Swift.String
},{
	"_TFC10swifthello5Hellom5WorldSS" // getter
	,"swifthello.Hello.World.method__String"
},{
	"_TFC10swifthello5Hellos5WorldSS" // getter
	,"swifthello.Hello.World.setter__String"
},{
	"_TFSSCfMSSFT21_builtinStringLiteralBp8byteSizeBw7isASCIIBi1__SS"
	,"Swift.String.init (_builtinStringLiteral(Builtin.RawPointer byteSize__Builtin.Word isASCII__Builtin.Int1 _) -> String"
},{
	"_TF10swifthello3norFT_Si"
	,"swifthello.nor () -> Swift.Int"
},{
	"_TFSs7printlnU__FQ_T_"
	,"println.<A>(A) -> ()"
},{
	"_TFSsa6C_ARGVGVSs20UnsafeMutablePointerGS_VSs4Int8__"
	,"C_ARGV<generic UnsafeMutablePointer><generic Int8>"
},{
	"_TFC10FlappyBird9GameScene10resetScenefS0_FT_T_"
	,"FlappyBird.GameScene.resetScene (self) -> (__ _) ()" // XXX this is not correct
},{
	"__TFC4main8BarClass8sayHellofT_T_"
	,"main.BarClass.sayHello"
},{
	"__TFC4main4TostCfT_S0_"
	,"main.Tost.allocator"
},{
	"__TFC4main4TostD"
	,"main.Tost.deallocator"
},{
	"__TFC4main4TostcfT_S0_"
	,"main.Tost.constructor"
},{
	"__TF4main4moinFT_Si"
	,"main.moin () -> Swift.Int"
},{
	"__TFC4main4Tostg3msgSS"
	,"main.Tost.msg.getter__String"
},{
	"__TMC4main4Tost"
	,"main.Tost..metadata"
},{
	"__TMLC4main4Tost"
	,"main.Tost..lazy.metadata"

},{
	"__TMaC4main4Tost"
	,"main.Tost..accessor.metadata"
	//,"_lazy cache variable for type metadata for main.Tost"
},{
	"__TMmC4main4Tost"
	,"main.Tost..metaclass"
},{
	"__TFV4main7Balanceg5widthSd"
	,"main.Balance.width.getter__Double"
},{
	"__TWoFC4main4TostCfT_S0_"
	,"Tost.allocator..init.witnesstable"
},{
	"__TWvdvC4main4Tost3msgSS"
	,"main.Tost.msg__String..field"
},{
	"__TIFC10Moscapsule10MQTTClient11unsubscribeFTSS17requestCompletionGSqFTOS_10MosqResultSi_T___T_A0_"
	,"Moscapsule.MQTTClient.unsubscribe ()"
////imp._TIFC10Moscapsule10MQTTClient11unsubscribeFTSS17requestCompletionGSqFTOS_10MosqResultSi_T___T_A0_
},{
	"__TWaC4main8FooClassS_9FoodClassS_"
	,"main.FooClass..FoodClass..protocol"
},{
	// _direct field offset for main.Tost.msg : Swift.String
	NULL, NULL
}};

int main(int argc, char **argv) {
	char *ret;
	if (argc > 1) {
		ret = r_bin_demangle_swift (argv[1], 0);
		if (ret) {
			printf ("%s\n", ret);
			free (ret);
		}
	} else {
		int i = 0;
		for (i=0; swift_tests[i].sym; i++) {
			Test *test = &swift_tests[i];
			printf ("[>>] %s\n", test->sym);
			ret = r_bin_demangle_swift (test->sym, 0);
			if (ret) {
				if (!strcmp (ret, test->dem)) {
					printf (Color_GREEN"[OK]"Color_RESET"  %s\n", ret);
				} else {
					printf (Color_RED"[XX]"Color_RESET"  %s\n", ret);
					printf (Color_YELLOW"[MUSTBE]"Color_RESET"  %s\n", test->dem);
				}
				free (ret);
			} else {
				printf (Color_RED"[XX]"Color_RESET"  \"(null)\"\n");
				printf (Color_YELLOW"[MUSTBE]"Color_RESET"  %s\n", test->dem);
			}
		}
	}
	return 0;
}
#endif
