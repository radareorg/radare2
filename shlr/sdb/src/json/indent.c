/* sdb - LGPLv3 - Copyright 2012-2014 - pancake */

SDB_API char *sdb_json_indent(const char *s) {
	int indent = 0;
	int i, instr = 0;
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
		#define INDENT(x) indent+=x; for (i=0;i<indent;i++) *o++ = '\t'
		switch (*s) {
                case ':':
                        *o++ = *s;
                        *o++ = ' ';
                        break;
                case ',':
                        *o++ = *s;
                        *o++ = '\n';
                        INDENT (0);
                        break;
                case '{':
                case '[':
			*o++ = *s;
			*o++ = (indent!=-1)?'\n':' ';
                        INDENT (1);
                        break;
                case '}':
                case ']':
                        *o++ = '\n';
                        INDENT (-1);
                        *o++ = *s;
                        break;
		default:
			*o++ = *s;
		}
	}
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
