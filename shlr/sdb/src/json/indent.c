/* sdb - MIT - Copyright 2012-2015 - pancake */

static void doIndent(int idt, char** o, const char *tab) {
	int i;
	char *x;
	for (i = 0; i < idt; i++) {
		for (x = (char*) tab; *x; x++) {
			*(*o)++ = *x;
		}
	}
}

SDB_API char *sdb_json_indent(const char *s, const char* tab) {
	int indent = 0;
	int instr = 0;
	int osz;
	char *o, *O, *OE, *tmp;
	if (!s) return NULL;
	osz = (1+strlen (s)) * 20;
	if (osz<1) return NULL;
	O = malloc (osz);
	if (!O) return NULL;
	OE = O+osz;
	for (o=O; *s; s++) {
		if (o + indent + 10 > OE) {
			int delta = o-O;
			osz += 0x1000+indent;
			if (osz<1) {
				free (O);
				return NULL;
			}
			tmp = realloc (O, osz);
			if (!tmp) {
				free (O);
				return NULL;
			}
			O = tmp;
			OE = tmp + osz;
			o = O+delta;
		}
		if (instr) {
			if (s[0] == '"') instr = 0;
			else if (s[0] == '\\' && s[1] == '"')
				*o++ = *s;
			*o++ = *s;
			continue;
		} else {
			if (s[0] == '"')
				instr = 1;
		}
		if (*s == '\n'|| *s == '\r' || *s == '\t' || *s == ' ')
			continue;
		switch (*s) {
                case ':':
                        *o++ = *s;
                        *o++ = ' ';
                        break;
                case ',':
                        *o++ = *s;
                        *o++ = '\n';
			doIndent (indent, &o, tab);
                        break;
                case '{':
                case '[':
			*o++ = *s;
			*o++ = (indent!=-1)?'\n':' ';
			indent++;
			doIndent (indent, &o, tab);
                        break;
                case '}':
                case ']':
                        *o++ = '\n';
			indent--;
			doIndent (indent, &o, tab);
                        *o++ = *s;
                        break;
		default:
			*o++ = *s;
		}
	}
	*o++ = '\n';
	*o = 0;
	return O;
}

// TODO: move to utils?
SDB_API char *sdb_json_unindent(const char *s) {
	int instr = 0;
	int len = strlen (s);
	char *o, *O = malloc (len+1);
	if (!O) return NULL;
	memset (O, 0, len);
	for (o=O; *s; s++) {
		if (instr) {
			if (s[0] != '"') {
				if (s[0] == '\\' && s[1] == '"')
					*o++ = *s;
			} else instr = 0;
			*o++ = *s;
			continue;
		} else if (s[0] == '"') instr = 1;
		if (*s == '\n'|| *s == '\r' || *s == '\t' || *s == ' ')
			continue;
		*o++ = *s;
	}
	*o = 0;
	return O;
}
