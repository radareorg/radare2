/* work-in-progress reverse engineered swift-demangler in C
 * Copyright MIT 2015-2026 by pancake@nopcode.org */

#include <r_cons.h>
#include <r_lib.h>
#include <r_bin.h>

// R2R db/formats/mangling/swift
// R2R db/tools/rabin2

// set this to true for debugging purposes
#define USE_THIS_CODE 0

static R_TH_LOCAL int have_swift_demangle = -1;
#if R2__UNIX__
static R_TH_LOCAL bool haveSwiftCore = false;
static R_TH_LOCAL char *(*swift_demangle)(const char *sym, int symlen, void *out, int *outlen, int flags, int unk) = NULL;
#endif

typedef struct {
	const char *code;
	const char *name;
} SwiftType;

/* basic types
 * See https://github.com/swiftlang/swift/blob/main/docs/ABI/Mangling.rst
 * for the full Swift ABI mangling specification */
static const SwiftType types[] = {
	/* Builtin types */
	{ "Bi1", "Builtin.Int1" },
	{ "Bb", "Builtin.BridgeObject" },
	{ "BB", "Builtin.UnsafeValueBuffer" },
	{ "Bo", "Builtin.NativeObject" },
	{ "aB", "'" },
	{ "BO", "Builtin.UnknownObject" },
	{ "Bp", "Builtin.RawPointer" },
	{ "Bt", "Builtin.SILToken" },
	{ "Bw", "Builtin.Word" },
	/* Standard library types (Sx abbreviations) */
	{ "Sa", "Array" },
	{ "Sb", "Bool" },
	{ "Sc", "UnicodeScalar" },
	{ "SD", "Dictionary" },
	{ "Sd", "Swift.Double" },
	{ "Sf", "Swift.Float" },
	{ "SH", "Set" },
	{ "Si", "Swift.Int" },
	{ "SJ", "Character" },
	{ "SN", "ClosedRange" },
	{ "Sn", "Range" },
	{ "Sp", "UnsafeMutablePointer" },
	{ "SP", "UnsafePointer" },
	{ "SQ", "ImplicitlyUnwrappedOptional" },
	{ "Sq", "Optional" },
	{ "SR", "UnsafeBufferPointer" },
	{ "Sr", "UnsafeMutableBufferPointer" },
	// { "So", "__C" },  // ObjC namespace
	{ "Ss", "Swift.String" },
	{ "SS", "Swift.String" },
	{ "Su", "UInt" },
	{ "Sv", "UnsafeMutableRawPointer" },
	{ "SV", "UnsafeRawPointer" },
	{ "S_", "Generic" },
	/* Other known prefixes */
	{ "FS", "String" },
	{ "GV", "mutableAddressor" },
	{ "Sg", "GenericAccessor" },
	{ "SC", "Synthesized" },
	{ "TF", "GenericSpec" },
	{ "Ts", "String" },
	{ NULL, NULL }
};

/* attributes */
static const SwiftType metas[] = {
	{ "FC", "ClassFunc" },
	{ "S0_FT", "?" },
	{ "RxC", ".." },
	{ "S0", "self" },
	{ "U__FQ_T_", "<A>(A)" },
	{ "ToFC", "@objc class func" },
	{ "ToF", "@objc func" },
	{ NULL, NULL }
};

static const SwiftType flags[] = {
	//{ "f", "function" }, // this is not an accessor
	{ "s", "setter" },
	{ "g", "getter" },
	{ "G", "globalGetter" },
	{ "m", "method" },
	{ "d", "destructor" },
	{ "D", "deallocator" },
	{ "c", "constructor" },
	{ "C", "allocator" },
	{ "w", "didSet" },
	{ "W", "willSet" },
	{ "r", "read" },
	{ "M", "modify" },
	{ "a", "addressor" },
	{ "l", "mutableAddressor" },
	{ "p", "subscript" },
	{ NULL, NULL }
};

static const char *getnum(const char *n, int *num) {
	if (num && *n) {
		int snum = atoi (n);
		if (snum > 0) {
			*num = snum;
		} else {
			*num = 0;
		}
	}
	return r_str_trim_head_digits (n);
}

static const char *numpos(const char *n) {
	while (*n && (*n < '0' || *n > '9')) {
		n++;
	}
	return n;
}

static const char *hasdigit(const char *n) {
	while (*n) {
		if (isdigit (*n)) {
			return n;
		}
		n++;
	}
	return NULL;
}

static inline void strbuf_append_n(RStrBuf *sb, const char *s, int len) {
	if (len > 0 && len <= 255 && s && r_str_nlen (s, len) == (size_t)len) {
		r_strbuf_append_n (sb, s, (size_t)len);
	}
}

static inline bool str_equals_n(const char *s, int len, const char *cmp) {
	return cmp && len == (int)strlen (cmp) && !strncmp (s, cmp, len);
}

static inline bool str_isnotempty_n(const char *s, int len) {
	return *s && len > 0;
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

static R_TH_LOCAL char *swift_demangle_cmd_str = NULL;

static char *swift_demangle_cmd(const char *s) {
	if (have_swift_demangle == -1) {
		have_swift_demangle = 0;
		char *sd = r_file_path ("swift-demangle");
		if (sd) {
			swift_demangle_cmd_str = r_str_newf ("%s -compact", sd);
			free (sd);
		} else {
			char *xcrun = r_file_path ("xcrun");
			if (xcrun) {
				swift_demangle_cmd_str = r_str_newf ("%s swift-demangle -compact", xcrun);
				free (xcrun);
			} else {
				char *sw = r_file_path ("swift");
				if (sw) {
					swift_demangle_cmd_str = r_str_newf ("%s demangle -compact", sw);
					free (sw);
				}
			}
		}
		if (swift_demangle_cmd_str) {
			have_swift_demangle = 1;
		}
	}
	if (!swift_demangle_cmd_str) {
		return NULL;
	}
	char *res = NULL;
	r_sys_cmd_str_full (swift_demangle_cmd_str, s, -1, &res, NULL, NULL);
	if (res && !*res) {
		free (res);
		return NULL;
	}
	r_str_trim (res);
	return res;
}

static char *swift_demangle_lib(const char *s) {
#if R2__UNIX__
	if (!haveSwiftCore) {
		void *lib = r_lib_dl_open ("/usr/lib/swift/libswiftCore." R_LIB_EXT, false);
		if (!lib) {
			lib = r_lib_dl_open ("/usr/lib/libswiftCore." R_LIB_EXT, false);
			if (!lib) {
				lib = r_lib_dl_open ("libswiftCore." R_LIB_EXT, false);
				if (!lib) {
					lib = r_lib_dl_open ("/usr/lib/swift/libswiftDemangle." R_LIB_EXT, false);
					if (!lib) {
						lib = r_lib_dl_open ("libswiftDemangle." R_LIB_EXT, false);
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

static const char *conformsto(char p) {
	switch (p) {
	case 'A':
		return "AnyObject";
	case 'B':
		return "BinaryFloatingPoint";
	case 'C':
		return "Collection";
	case 'D':
		return "Decodable";
	case 'E':
		return "Encodable";
	case 'F':
		return "FloatingPoint";
	case 'G':
		return "RandomNumberGenerator";
	case 'H':
		return "Hashable";
	case 'I':
		return "IteratorProtocol";
	case 'J':
		return "Numeric";
	case 'K':
		return "BidirectionalCollection";
	case 'L':
		return "Comparable";
	case 'M':
		return "MutableCollection";
	case 'N':
		return "RangeReplaceableCollection";
	case 'O':
		return "Error";
	case 'P':
		return "CaseIterable";
	case 'Q':
		return "Equatable";
	case 'R':
		return "RandomAccessCollection";
	case 'S':
		return "StringProtocol";
	case 'T':
		return "Sequence";
	case 'U':
		return "UnsignedInteger";
	case 'V':
		return "AdditiveArithmetic";
	case 'X':
		return "RangeExpression";
	case 'Y':
		return "RawRepresentable";
	case 'Z':
		return "SignedInteger";
	case 'e':
		return "Sendable";
	case 'j':
		return "Identifiable";
	}
	return NULL;
}

static bool looks_valid(char p) {
	if (isdigit (p)) {
		return true;
	}
	switch (p) {
	case 'A': // type alias
	case 'C': // class, enum case
	case 'E': // extension
	case 'F':
	case 'I':
	case 'M':
	case 'N': // ON
	case 'O': // enum
	case 'P': // protocol
	case 'S': // SHA SQAAMc
	case 'T':
	case 'V':
	case 'W':
	case 'f':
	case 'o':
	case 's':
	case 't':
	case 'v':
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

static const char *get_mangled_tail(const char **pp, RStrBuf *out) {
	const char *p = *pp;
	if (R_STR_ISEMPTY (p)) {
		return NULL;
	}
	if (p[1] == 'f') {
		p++;
	}
	switch (p[1]) {
	case 'T':
		switch (p[2]) {
		case 'W':
			return "..witness.thunk";
		case 'w':
			return "..protocol.witness";
		case 'o':
			return "..objc.thunk";
		}
		break;
	case 'W':
		switch (p[2]) {
		case 'a':
			return "..protocol";
		case 'C':
			return "..enum.case";
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
	case 'd':
		return "..deinit";
	case 'D':
		return "..deinit.deallocating";
	case 'N':
		return "..metadata.type";
	case 'M':
		switch (p[2]) {
		case 'e':
			return "..override";
		case 'm':
			return "..metaclass";
		case 'n':
			return "..nominal.type.descriptor";
		case 'o':
			return "..metadata.base";
		case 'V':
			return "..method.descriptor";
		case 'u':
			return "..method.lookup";
		case 'a':
			return "..metadata.accessor";
		case 'L':
			return "..metadata.lazy";
		default:
			return "..metadata";
		}
		break;
	case 'I': // interfaces
		// TODO: Fix __TIFF demangling
		return "..interface";
	case 'V':
		return "..property.descriptor";
	case 'v':
		switch (p[2]) {
		case 's':
			return "..setter";
		case 'g':
			return "..getter";
		case 'W':
			return "..willSet";
		case 'w':
			return "..didSet";
		case 'r':
			return "..read";
		case 'M':
			return "..modify";
		}
		return "..variable";
	case 'E':
		return "..extension";
	case 'e':
		return "..extension";
	case 'A':
		switch (p[2]) {
		case 'i':
			return "..default.arg";
		}
		return "..partial.apply";
	}
	return NULL;
}

static char *my_swift_demangler(const char *s) {
	// SwiftState ss = { 0 };
	SwiftCheck is = { 0 };
	is.first = true;
#if 0
	if (r_str_startswith (s, "$s")) {
		s += 2;
	}
#endif
	if (r_str_startswith (s, "So") && r_str_endswith (s, "C")) {
		int len = atoi (s + 2);
		s += 2;
		s = r_str_trim_head_digits (s);
		char *ns = r_str_ndup (s, len);
		char *fs = r_str_newf ("__C.%s", ns);
		free (ns);
		return fs;
	}

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
			r_strbuf_free (out);
			return NULL;
		}
		if (p[1] && p[2]) {
			int len = atoi (p + 1);
			if (len > strlen (p + 2)) {
				r_strbuf_free (out);
				return NULL;
			}
		}
		// do nothing
	} else {
		p = str_seek (p, tail? 1: (p[0] && p[1])? 2
							: 0);
	}
	q = getnum (p, NULL);

	// _TF or __TW
	if (looks_valid (*p)) {
		if (r_str_startswith (p + 1, "SS")) {
			r_strbuf_append (out, "Swift.String.init(");
			p += 3;
		}
		// TODO: move into get_tail ()
		if (r_str_startswith (p, "vdv")) {
			tail = "..field";
			p += 3;
		}
		// TODO: move into get_tail ()
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
				q++;
			}
			q = getnum (q, &len);
			if (!len) {
				break;
			}
			if (str_equals_n (q, len, "ee")) {
				r_strbuf_append (out, "Swift");
			} else {
				if (i && r_strbuf_length (out) > 0) {
					r_strbuf_append (out, ".");
				}
				len = R_MIN (len, strlen (q));
				strbuf_append_n (out, q, len);
			}
		}
		if (q > q_end) {
			eprintf ("END\n");
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
			if (r_str_startswith (q, "sE")) {
				q++;
			}
			int len = 0;
			/* get field name and then type */
			resolve (types, q, &attr);

			q = getnum (q + 1, &len);
			const char *arg = (len < strlen (q))? q + len: q;
			resolve (types, arg, &attr2);

			if (str_isnotempty_n (q, len)) {
				r_strbuf_append (out, ".");
				strbuf_append_n (out, q, len);
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
			if (arg) {
				q = arg;
				goto moreitems;
			}
		} else {
moreitems:
			/* parse function parameters here */
			// type len value/
			for (i = 0; q && q < q_end && q >= q_start; i++) {
				if (*q == 'f') {
					q++;
				}
				switch (*q) {
				case 'A': // skip 'AAC' cases

					if (!isdigit (q[1])) {
						q += 2;
						r_strbuf_append (out, ".");
						continue;
					}
					// ignored stuff here
					// break;
				case 'C': // "s16IOSSecuritySuiteAACMu"
				case 'O':
					if (!isdigit (q[1]) && looks_valid (q[1])) {
						if (q[1] == 'S') {
							const char *tail = conformsto (q[2]);
							if (tail) {
								r_strbuf_append (out, ".conformsto.");
								r_strbuf_append (out, tail);
							} else {
								R_LOG_DEBUG ("Unhandled s9Alamofire10HTTPMethodO8rawValueACSgSS_tcfC");
								r_strbuf_append (out, ".");
								r_strbuf_append (out, q);
								q = q_end;
								continue;
							}
						} else {
							const char *tail = get_mangled_tail (&q, out);
							if (tail) {
								r_strbuf_append (out, tail);
							} else {
								r_strbuf_append (out, ".");
							}
						}
						q++;
						continue;
					} else {
						r_strbuf_append (out, ".");
						// fallthorugh
					}
					if (isdigit (q[1])) {
						int n = 0;
						const char *Q = getnum (q + 1, &n);
						strbuf_append_n (out, Q, n);
						q = Q + n;
						if (q >= q_end) {
							continue;
						}
						if (isdigit (q[0])) {
							r_strbuf_append (out, ".");
							n = 0;
							const char *Q = getnum (q, &n);
							strbuf_append_n (out, Q, n);
							q = Q + n;
						}
						continue;
					}
				case 'b':
					r_strbuf_append (out, "bool");
					break;
				case 's':
					{
						int n = 0;
						const char *Q = getnum (q + 1, &n);
						strbuf_append_n (out, Q, n);
						q = Q + n + 1;
						continue;
					}
					break;
				case 'u':
					if (r_str_startswith (q, "uRxs")) {
						int n = 0;
						const char *Q = getnum (q + 4, &n);
						r_strbuf_append (out, "..");
						strbuf_append_n (out, Q, n);
						q = Q + n + 1;
						continue;
					}
					break;
				case 'S': // "S0"
					if (q[1] == '1') {
						q++;
					}
					if (*q == 'S') {
						//	r_strbuf_append (out, ".String");
					}
					switch (q[1]) {
					case 'g':
						r_strbuf_append (out, q);
						q = q_end;
						break;
					case 'v':
						if (q + 2 < q_end) {
							q += 2;
							const char *tail = get_mangled_tail (&q, out);
							if (tail) {
								r_strbuf_append (out, tail);
							} else {
								R_LOG_DEBUG ("Unhandled s9Alamofire10HTTPMethodO8rawValueACSgSS_tcfC");
								r_strbuf_append (out, ".");
								r_strbuf_append (out, q);
								q = q_end;
							}
						} else {
							R_LOG_DEBUG ("Unhandled s9Alamofire10HTTPMethodO8rawValueACSgSS_tcfC");
							r_strbuf_append (out, ".");
							r_strbuf_append (out, q);
							q = q_end;
						}
						break;
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
						q++;
						break;
					case '_':
						// swift string
						if (q[0] && q[1] && q[2]) {
							int n = 0;
							const char *Q = getnum (q + 2, &n);
							r_strbuf_append (out, "..");
							strbuf_append_n (out, Q, n);
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
					if (p && *p && isdigit (p[1])) {
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
					if (!p) {
						int n = 0;
					repeat:;
						const char *Q = getnum (q + 1, &n);
						if (str_isnotempty_n (Q, n)) {
							r_strbuf_append (out, ".");
							strbuf_append_n (out, Q, n);
						} else {
							if (q < q_end && *q) {
								r_strbuf_appendf (out, "...%s", q);
								q += strlen (q);
							}
						}
						if (n == 0) {
							continue;
						}
						q = Q + n;
						if (q >= q_end) {
							continue;
						}
						if (!isdigit (*q)) {
							if (!hasdigit (q) && *q == 'V') {
								r_strbuf_appendf (out, "...%s", q);
								q += strlen (q);
							} else {
								const char *dig = hasdigit (q);
								if (dig) {
									q = dig;
								} else {
									// eprintf ("NO DIGI\n");
								}
							}
						}
						if (isdigit (*q)) {
							q--;
							goto repeat;
#if 0
							int n = 0;
							const char *Q = getnum (q, &n);
							const char *res = getstring (Q, n);
							if (res) {
								r_strbuf_append (out, ".");
								r_strbuf_append (out, res);
							}
							q = Q + n;
#endif
						}
					}
					q++;
					break;
				case '_':
					// it's return value time!
					p = resolve (types, q + 1, &attr); // type
					if (!p) {
						int n = 0;
						const char *Q = getnum (q + 1, &n);
						if (str_isnotempty_n (Q, n)) {
							r_strbuf_append (out, ".");
							strbuf_append_n (out, Q, n);
						}
						q = Q + n;
						if (q >= q_end) {
							continue;
						}
						if (isdigit (*q)) {
							int n = 0;
							const char *Q = getnum (q, &n);
							if (str_isnotempty_n (Q, n)) {
								r_strbuf_append (out, ".");
								strbuf_append_n (out, Q, n);
							}
							q = Q + n;
						} else {
							if (*q) {
								r_strbuf_appendf (out, "...%s", q);
								q += strlen (q);
							}
						}
					}
					q++;
					break;
				default:
					p = resolve (types, q, &attr); // type
					break;
				}
				if (q >= q_end) {
					break;
				}
				if (p) {
					q = getnum (p, &len);
					if (attr && !strcmp (attr, "generic")) {
						is.generic = true;
					}
					// printf ("TYPE: %s LEN %d VALUE %s\n",
					//	attr, len, getstring (q, len));
					if (!len) {
						if (is.retmode) {
							if (q > q_end) {
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
						if (str_isnotempty_n (q, len)) {
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
							if (!str_equals_n (q, len, "_")) {
								strbuf_append_n (out, q, len);
								r_strbuf_append (out, is.generic? ">": "");
								is.first = (*q != '_');
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
					if (q >= q_end || R_STR_ISEMPTY (q)) {
						continue;
					}
					q++;
					char *n = strstr (q, "__");
					if (n) {
						q = n + 1;
					} else {
						n = strchr (q, '_');
						if (!n && *q) {
							if (isdigit (*q)) {
								q--;
								goto repeat;
							}
							r_strbuf_appendf (out, "(...%s)", q);
							break;
						}
						if (n) {
							q = n + 1;
						} else {
							q++;
						}
					}
				}
			}
		}
	} else {
		R_LOG_DEBUG ("Unsupported swift mangling type: %c", *p);
	}
	// https://www.guardsquare.com/blog/swift-native-method-swizzling
	if (r_str_endswith (s, "FTX")) {
		r_strbuf_prepend (out, "dynamic variable ");
	} else if (r_str_endswith (s, "FTx")) {
		r_strbuf_prepend (out, "dynamic key ");
	} else if (r_str_endswith (s, "FTI")) {
		r_strbuf_prepend (out, "dynamic thunk ");
	} else if (r_str_endswith (s, "ivs")) {
		r_strbuf_prepend (out, "setter ");
	} else if (r_str_endswith (s, "ivg")) {
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
#if USE_THIS_CODE
	syscmd = trylib = false; // useful for debugging the embedded demangler on macos
#endif
	// handle _TtCs<N><name> pattern: _Tt prefix + C (class) + s (Swift module) + length-prefixed name
	// see https://github.com/swiftlang/swift/blob/main/docs/ABI/Mangling.rst#declaration-contexts
	if (r_str_startswith (s, "_TtCs") && isdigit (s[5])) {
		int len = atoi (s + 5);
		const char *p = s + 5;
		p = r_str_trim_head_digits (p);
		if (len > 0 && len <= (int)strlen (p)) {
			char *name = r_str_ndup (p, len);
			char *result = r_str_newf ("Swift.%s", name);
			free (name);
			return result;
		}
	}
	if (trylib) {
		char *res = swift_demangle_lib (s);
		if (res) {
			return res;
		}
	}
	const char *os = s;
	bool hasdollar = *s == '$';

	// strip leading _$ (common in Mach-O symbols)
	if (r_str_startswith (s, "_$")) {
		hasdollar = true;
		s += 2;
	}

	// handle "symbolic ..." and space-separated prefixed symbols
	const char *space = strchr (s, ' ');
	if (space) {
		if (isdigit (space[1])) {
			char *ss = r_str_newf ("$s%s", space + 1);
			char *res = r_bin_demangle_swift (ss, syscmd, trylib);
			free (ss);
			return res;
		}
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

	// strip linker prefixes
	s = str_removeprefix (s, "imp.");
	s = str_removeprefix (s, "reloc.");
	s = str_removeprefix (s, "__");

	// determine if we have a $s or bare s prefix for Swift 5+ symbols
	const char *swift5_body = NULL;
	if (r_str_startswith (s, "$s")) {
		swift5_body = s + 2;
	} else if (s[0] == 's' && !r_str_startswith (s, "__T") && !r_str_startswith (s, "_T")) {
		swift5_body = s + 1;
	}

	// handle So<N><name>C pattern: ObjC class imports ($sSo8UIButtonC -> __C.UIButton)
	if (swift5_body && r_str_startswith (swift5_body, "So") && isdigit (swift5_body[2]) && r_str_endswith (s, "C")) {
		int len = atoi (swift5_body + 2);
		const char *p = swift5_body + 2;
		p = r_str_trim_head_digits (p);
		if (len > 0 && len <= (int)strlen (p) - 1) { // -1 for trailing 'C'
			char *name = r_str_ndup (p, len);
			char *result = r_str_newf ("__C.%s", name);
			free (name);
			return result;
		}
	}

	// handle bare standard type abbreviations: $sSi -> Swift.Int, $sSd -> Swift.Double, etc.
	if (swift5_body) {
		if (swift5_body[0] == 'S' && !swift5_body[1]) {
			return strdup ("Swift.String");
		}
		const char *attr = NULL;
		const char *rest = resolve (types, swift5_body, &attr);
		if (attr && rest && !*rest) {
			if (r_str_startswith (attr, "Swift.")) {
				return strdup (attr);
			}
			return r_str_newf ("Swift.%s", attr);
		}
	}

	// reject non-swift symbols early
	if (*s != 's' && *s != 'T' && !r_str_startswith (s, "_T") && !r_str_startswith (s, "__T")) {
		if (!r_str_startswith (s, "$s")) {
			switch (*s) {
			case 'S':
			case 'B':
				{
					const char *attr = NULL;
					resolve (types, s, &attr);
					if (attr) {
						return strdup (attr);
					}
				}
				break;
			}
			if (s > os) {
				s--;
			}
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
	char *res = my_swift_demangler (s);
	if (!res && hasdollar) {
		if (*s == '$' && s[1] && s[2]) {
			s += 2;
		}
		return r_str_newf ("...%s", s);
	}
	return res;
}

// -- minimal demangler for swift type manglings found in field descriptors --

#define TSTK 24
#define TS_LIST 1
#define TS_FIRST 2

typedef struct {
	char *s[TSTK];
	ut8 mark[TSTK];
	ut16 rep[TSTK];
	int n;
} TypeStack;

static void tpush(TypeStack *ts, char *s, ut8 mark) {
	if (s && ts->n < TSTK) {
		ts->s[ts->n] = s;
		ts->mark[ts->n] = mark;
		ts->rep[ts->n] = 0;
		ts->n++;
	} else {
		free (s);
	}
}

static char *tpop(TypeStack *ts) {
	if (ts->n < 1) {
		return NULL;
	}
	ts->n--;
	char *s = ts->s[ts->n];
	if (ts->mark[ts->n] & TS_LIST) {
		free (s);
		return strdup ("()");
	}
	return s;
}

static const char *swift_stdtype(char c) {
	switch (c) {
	case 'a': return "Swift.Array";
	case 'b': return "Swift.Bool";
	case 'c': return "Swift.UnicodeScalar";
	case 'D': return "Swift.Dictionary";
	case 'd': return "Swift.Double";
	case 'f': return "Swift.Float";
	case 'h': return "Swift.Set";
	case 'i': return "Swift.Int";
	case 'J': return "Swift.Character";
	case 'N': return "Swift.ClosedRange";
	case 'n': return "Swift.Range";
	case 'P': return "Swift.UnsafePointer";
	case 'p': return "Swift.UnsafeMutablePointer";
	case 'q': return "Swift.Optional";
	case 'R': return "Swift.UnsafeBufferPointer";
	case 'r': return "Swift.UnsafeMutableBufferPointer";
	case 'S': case 's': return "Swift.String";
	case 'u': return "Swift.UInt";
	case 'V': return "Swift.UnsafeRawPointer";
	case 'v': return "Swift.UnsafeMutableRawPointer";
	case 'w': return "Swift.UnsafeRawBufferPointer";
	case 'W': return "Swift.UnsafeMutableRawBufferPointer";
	}
	return NULL;
}

// build a tuple from the stack: pops until (and including) the TS_FIRST item,
// or until a TS_LIST marker (exclusive)
static char *swift_build_tuple(TypeStack *ts) {
	char *elem[TSTK];
	ut16 reps[TSTK];
	int i, n = 0;
	while (ts->n > 0 && n < TSTK) {
		if (ts->mark[ts->n - 1] & TS_LIST) {
			if (n == 0) {
				ts->n--;
				free (ts->s[ts->n]);
			}
			break;
		}
		const bool first = ts->mark[ts->n - 1] & TS_FIRST;
		ts->n--;
		elem[n] = ts->s[ts->n];
		reps[n] = ts->rep[ts->n];
		n++;
		if (first) {
			break;
		}
	}
	if (n == 0) {
		return strdup ("()");
	}
	if (n == 1 && reps[0] > 0) {
		char *res = r_str_newf ("(%d x %s)", reps[0] + 1, elem[0]);
		free (elem[0]);
		return res;
	}
	RStrBuf *sb = r_strbuf_new ("(");
	for (i = n - 1; i >= 0; i--) {
		r_strbuf_append (sb, elem[i]);
		if (i > 0) {
			r_strbuf_append (sb, ", ");
		}
		free (elem[i]);
	}
	r_strbuf_append (sb, ")");
	return r_strbuf_drain (sb);
}

static void swift_build_generic(TypeStack *ts) {
	char *args[TSTK];
	int i, n = 0;
	while (ts->n > 0 && n < TSTK && !(ts->mark[ts->n - 1] & TS_LIST)) {
		ts->n--;
		args[n++] = ts->s[ts->n];
	}
	if (ts->n > 0 && (ts->mark[ts->n - 1] & TS_LIST)) {
		ts->n--;
		free (ts->s[ts->n]);
	}
	char *base = tpop (ts);
	if (!base) {
		// no base: restore args joined as-is
		for (i = n - 1; i >= 0; i--) {
			tpush (ts, args[i], 0);
		}
		return;
	}
	char *res = NULL;
	if (n == 1 && !strcmp (base, "Swift.Optional")) {
		res = r_str_newf ("%s?", args[0]);
	} else if (n == 1 && !strcmp (base, "Swift.Array")) {
		res = r_str_newf ("[%s]", args[0]);
	} else if (n == 2 && !strcmp (base, "Swift.Dictionary")) {
		res = r_str_newf ("[%s: %s]", args[1], args[0]);
	} else {
		RStrBuf *sb = r_strbuf_new (base);
		r_strbuf_append (sb, "<");
		for (i = n - 1; i >= 0; i--) {
			r_strbuf_append (sb, args[i]);
			if (i > 0) {
				r_strbuf_append (sb, ", ");
			}
		}
		r_strbuf_append (sb, ">");
		res = r_strbuf_drain (sb);
	}
	for (i = 0; i < n; i++) {
		free (args[i]);
	}
	free (base);
	tpush (ts, res, 0);
}

static void swift_build_function(TypeStack *ts, const char *conv, bool athrows, bool aasync) {
	char *params = tpop (ts);
	char *result = tpop (ts);
	if (!params) {
		free (result);
		return;
	}
	const char *fmt = (*params == '(')? "%s%s%s%s -> %s": "%s(%s)%s%s -> %s";
	char *res = r_str_newf (fmt, conv, params,
		aasync? " async": "", athrows? " throws": "", result? result: "()");
	free (params);
	free (result);
	tpush (ts, res, 0);
}

// demangle a swift type mangling as found in reflection/field metadata.
// symbolic references (control bytes 0x01-0x1f) are resolved through the
// given callback, so this works for any container format (mach-o, elf, ...)
R_API char *r_bin_demangle_swift_typeref(const ut8 *p, int len, ut64 va, RBinSwiftResolver resolver, void *user) {
	TypeStack ts = { {0} };
	bool athrows = false, aasync = false;
	int i = 0;
	while (i < len) {
		const ut8 b = p[i];
		if (b < 0x20) {
			char *name = NULL;
			if (b >= 1 && b <= 0x17) {
				if (i + 5 > len) {
					break;
				}
				if (va && resolver && (b == 1 || b == 2)) {
					const st32 rel = (st32)r_read_le32 (p + i + 1);
					name = resolver (user, va + i + 1 + rel, b == 2);
				}
				i += 5;
			} else {
				i += 9; // 8-byte absolute references
			}
			tpush (&ts, name? name: strdup ("?"), 0);
			continue;
		}
		if (isdigit (b) || (b == 's' && i + 1 < len && isdigit (p[i + 1]))
				|| (b == 'S' && i + 2 < len && p[i + 1] == 'o' && isdigit (p[i + 2]))) {
			RStrBuf *nb = r_strbuf_new (NULL);
			if (b == 's') {
				r_strbuf_append (nb, "Swift");
				i++;
			} else if (b == 'S') {
				r_strbuf_append (nb, "__C");
				i += 2;
			}
			bool kindchar = !isdigit (b); // only bare identifiers can be tuple labels
			int segments = 0;
			while (i < len && isdigit (p[i])) {
				int n = atoi ((const char *)p + i);
				while (i < len && isdigit (p[i])) {
					i++;
				}
				// n comes from the mangled name, so `i + n` would wrap for a
				// large digit run and let the check pass. i <= len here, so
				// subtracting instead cannot overflow.
				if (n < 1 || n > len - i) {
					break;
				}
				if (r_strbuf_length (nb) > 0) {
					r_strbuf_append (nb, ".");
				}
				r_strbuf_append_n (nb, (const char *)p + i, n);
				i += n;
				segments++;
				if (i < len && strchr ("CVOP", p[i])) {
					i++; // nominal kind marker
					kindchar = true;
				}
			}
			if (!kindchar && segments == 1 && ts.n > 0 && !(ts.mark[ts.n - 1] & TS_LIST)
					&& i < len && (p[i] == '_' || p[i] == 't')) {
				// tuple element label: follows its element type
				char *t = tpop (&ts);
				char *label = r_strbuf_drain (nb);
				tpush (&ts, r_str_newf ("%s: %s", label, t), 0);
				free (label);
				free (t);
			} else {
				tpush (&ts, r_strbuf_drain (nb), 0);
			}
			continue;
		}
		switch (b) {
		case '$':
			i += (i + 1 < len && p[i + 1] == 's')? 2: 1;
			break;
		case 'S':
			if (i + 1 >= len) {
				i = len;
				break;
			}
			if (p[i + 1] == 'g') {
				char *t = tpop (&ts);
				// optional function types need wrapping parens
				tpush (&ts, t? r_str_newf (strstr (t, " -> ")? "(%s)?": "%s?", t): NULL, 0);
				free (t);
			} else {
				const char *st = swift_stdtype (p[i + 1]);
				tpush (&ts, strdup (st? st: "?"), 0);
			}
			i += 2;
			break;
		case 'y':
			tpush (&ts, strdup ("y"), TS_LIST);
			i++;
			break;
		case '_':
			if (ts.n > 0) {
				ts.mark[ts.n - 1] |= TS_FIRST;
			}
			i++;
			break;
		case 't':
			tpush (&ts, swift_build_tuple (&ts), 0);
			i++;
			break;
		case 'A':
			i++;
			if (i < len && isdigit (p[i]) && ts.n > 0) {
				ts.rep[ts.n - 1] = atoi ((const char *)p + i);
				while (i < len && isdigit (p[i])) {
					i++;
				}
			}
			break;
		case 'G':
			swift_build_generic (&ts);
			i++;
			break;
		case 'X':
			if (i + 1 < len && p[i + 1] == 'C') {
				swift_build_function (&ts, "@convention(c) ", athrows, aasync);
				athrows = aasync = false;
			}
			i += 2;
			break;
		case 'c':
			swift_build_function (&ts, "", athrows, aasync);
			athrows = aasync = false;
			i++;
			break;
		case 'K':
			athrows = true;
			i++;
			break;
		case 'Y':
			if (i + 1 < len && p[i + 1] == 'a') {
				aasync = true;
			}
			i += 2;
			break;
		case 'z':
			// inout marker applies to the following type; approximate by prefixing the next push
			i++;
			break;
		case 'm':
			{
				char *t = tpop (&ts);
				tpush (&ts, t? r_str_newf ("%s.Type", t): NULL, 0);
				free (t);
				i++;
			}
			break;
		case 'x':
			tpush (&ts, strdup ("A"), 0);
			i++;
			break;
		case 'q':
			if (i + 1 < len && p[i + 1] == '_') {
				tpush (&ts, strdup ("B"), 0);
				i += 2;
			} else if (i + 2 < len && isdigit (p[i + 1]) && p[i + 2] == '_') {
				char gp[2] = { (char)('C' + (p[i + 1] - '0')), 0 };
				tpush (&ts, strdup (gp), 0);
				i += 3;
			} else {
				i++;
			}
			break;
		default:
			// unknown mangling op: stop here and use what we have
			i = len;
			break;
		}
	}
	char *res = NULL;
	while (ts.n > 0) {
		char *t = tpop (&ts);
		if (!res && t && strcmp (t, "()")) {
			res = t;
		} else {
			free (t);
		}
	}
	return res;
}

// return the idx-th camelcase word of the identifiers in a mangled context,
// as used by the swift mangling word substitutions ("AA" and friends)
static char *swift_prefix_word(const char *prefix, int idx) {
	const char *p = prefix;
	while (p && *p) {
		if (!isdigit (*p)) {
			p++;
			continue;
		}
		const int n = atoi (p);
		p = r_str_trim_head_digits (p);
		if (n < 1 || n > (int)strlen (p)) {
			break;
		}
		int i = 0;
		while (i < n) {
			int j = i + 1;
			while (j < n && !isupper (p[j])) {
				j++;
			}
			if (j - i > 1) {
				if (idx == 0) {
					return r_str_ndup (p + i, j - i);
				}
				idx--;
			}
			i = j;
		}
		p += n;
	}
	return NULL;
}

// extract the member name and attributes from the tail of a mangled swift
// symbol after its nominal context ("3fooSivg" -> "foo" + GETTER); returns
// NULL for symbols that are not callable members (metadata, witnesses, ...)
R_API char *r_bin_demangle_swift_member(const char *context, const char *rest, ut64 *attr) {
	if (R_STR_ISEMPTY (rest)) {
		return NULL;
	}
	char *mname = NULL;
	if (isdigit (*rest)) {
		const int n = atoi (rest);
		const char *e = r_str_trim_head_digits (rest);
		if (n > 0 && n <= (int)strlen (e)) {
			mname = r_str_ndup (e, n);
		}
	} else if (rest[0] == 'A' && isupper (rest[1])) {
		// word-substituted member name referencing the context words
		mname = swift_prefix_word (context, rest[1] - 'A');
	}
	size_t rl = strlen (rest);
	if (rest[rl - 1] == 'Z') {
		*attr |= R_BIN_ATTR_STATIC;
		rl--;
	}
	if (rl < 2) {
		free (mname);
		return NULL;
	}
	const char *tail = rest + rl - 2;
	if (!strncmp (tail, "fC", 2) || !strncmp (tail, "fc", 2)) {
		*attr |= R_BIN_ATTR_CONSTRUCTOR;
		free (mname);
		return strdup ("init");
	}
	if (!strncmp (tail, "fD", 2) || !strncmp (tail, "fd", 2)) {
		free (mname);
		return strdup ("deinit");
	}
	if (!mname) {
		return NULL;
	}
	if (!strncmp (tail, "vg", 2)) {
		*attr |= R_BIN_ATTR_GETTER;
	} else if (!strncmp (tail, "vs", 2)) {
		*attr |= R_BIN_ATTR_SETTER;
	} else if (!strncmp (tail, "vM", 2) || !strncmp (tail, "vr", 2)) {
		// modify/read coroutine accessors
	} else if (tail[1] == 'F') {
		if ((rl >= 3 && !strncmp (rest + rl - 3, "YaF", 3))
				|| (rl >= 4 && !strncmp (rest + rl - 4, "YaKF", 4))) {
			*attr |= R_BIN_ATTR_ASYNC;
		}
	} else {
		free (mname);
		return NULL; // metadata, witness tables, thunks, ...
	}
	return mname;
}
