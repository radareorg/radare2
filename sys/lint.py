#!/usr/bin/env python3
"""radare2 source linter.

Single-pass replacement for the git-grep pipelines that used to live in
sys/lint.sh: every tracked file is read only once and all the checks are
applied to it in memory, instead of spawning one git grep pipeline per check.

sys/lint.sh is kept as a thin wrapper running this script. Findings are
printed one per line in a consistent, greppable diagnostic layout:

    path:line: level [check-name] message -- offending source

so they are easy to read and to filter (e.g. `sys/lint.sh --all | grep
trailing-space`). By default the first failing check stops the run and the
process exits 1; use --all to report every failing check in a single run.
"""

import argparse
import difflib
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LIBR = (b"libr/",)
LIBR_BINR = (b"libr/", b"binr/")
LIBR_SHLR = (b"libr/", b"shlr/")
ARCH_P = (b"libr/arch/p/",)
EVERYWHERE = None

# pattern kinds: literal text, literal anchored at begin/end of line, regexp
PLAIN, BOL, EOL, RX = 0, 1, 2, 3

class Pattern:
	"""One search pattern, matched against a whole file buffer at once.

	Almost every check looks for literal text, so the search is done with
	bytes.find, which is much faster than the regexp engine. Patterns
	anchored with ^ or $ become literals around a newline character.
	"""
	__slots__ = ("kind", "body", "needle", "scan", "icase")

	def __init__(self, kind, body, icase=False):
		self.kind = kind
		self.body = body
		self.icase = icase
		self.needle = None
		self.scan = None
		if kind == RX:
			self.scan = re.compile(body)
		elif kind == BOL:
			self.needle = b"\n" + body
		elif kind == EOL:
			self.needle = body + b"\n"
		else:
			self.needle = body

# checks often look for the same text: intern the patterns so every
# distinct search runs at most once per file (see the cache in scan_file)
_PATTERNS = {}

def _pattern(kind, body, icase):
	key = (kind, body, icase)
	pat = _PATTERNS.get(key)
	if pat is None:
		pat = _PATTERNS[key] = Pattern(kind, body, icase)
	return pat

def L(body):
	return (PLAIN, body)

def Lbol(body):
	return (BOL, body)

def Leol(body):
	return (EOL, body)

def Rx(body):
	return (RX, body)

class Check:
	"""A lint check: patterns selecting lines plus filters on the formatted
	`path:line` output, exactly like the git grep | grep ... pipelines did.

	`msg` is the human explanation printed for every match; see format_match
	for the one-line-per-finding diagnostic layout. Matches are stored as
	(path, lineno, raw_line) tuples so both the verbose output and the legacy
	`--dump` format can be rebuilt from the same data."""
	__slots__ = ("name", "msg", "pats", "prefixes", "numbered", "filters", "warn", "matches", "index")

	def __init__(self, name, patterns, prefixes=LIBR, numbered=False, filters=(), warn=False, icase=False):
		self.name = name
		self.msg = MESSAGES[name]
		self.pats = tuple(_pattern(kind, body, icase) for kind, body in patterns)
		self.prefixes = prefixes
		self.numbered = numbered
		flt = []
		for spec in filters:
			pat, keep = spec[0], spec[1]
			flags = spec[2] if len(spec) > 2 else 0
			flt.append((re.compile(pat, flags), keep))
		self.filters = tuple(flt)
		self.warn = warn
		self.matches = []

# Human explanation printed for every finding of each check, keyed by check
# name. Kept as a separate table so the CHECKS list below stays compact and
# so every check is forced to carry a message (Check.__init__ looks it up).
MESSAGES = {
	"no-preincrement": "use post-increment (i++) instead of pre-increment in a for loop",
	"table-tostring-print": "do not printf the r_table_tostring result, print it directly",
	"typo-shuold": "typo: 'shuold' should be 'should'",
	"sscanf-percent-s": "unbounded %s in sscanf, specify a maximum field width",
	"void-args": "prototype with no parameters must use (void)",
	"r-new0-space": "missing space before parenthesis: write 'R_NEW0 ('",
	"eq-eq-quote": "missing space around == before a char literal",
	"pipe-usage": "missing space in '| Usage'",
	"t-brace-quote": "missing space before brace-string literal",
	"quote-brace-comma": "spacing issue near '\"},'",
	"space-indent": "line indented with spaces, use tabs",
	"todo-log-info": "TODO left inside an R_LOG_INFO call",
	"config-set-bool-string": "boolean config set with \"true\"/\"false\" string, use r_config_set_b",
	"hex-decimal-format": "0x prefix with a decimal format specifier (0x%d / 0x%PFMT64d)",
	"rmin-rmax-space": "missing space before parenthesis: write 'R_MIN (' / 'R_MAX ('",
	"cmp-space": "missing space before parenthesis in a cmp() call",
	"file-new-null": "r_file_new call missing the trailing NULL argument",
	"for-space": "missing space before parenthesis: write 'for ('",
	"for-preincrement": "use post-increment (i++) in the for loop",
	"for-int": "declare the loop index before the loop, avoid 'for (int'",
	"for-long": "declare the loop index before the loop, avoid 'for (long'",
	"for-ut": "declare the loop index before the loop, avoid 'for (ut...'",
	"for-size-t": "declare the loop index before the loop, avoid 'for (size_t'",
	"tab-eol": "trailing tab at end of line",
	"eprintf-pipe": "eprintf starting with a pipe character",
	"log-newline": "R_LOG message must not contain a trailing newline",
	"tab-free": "missing space before parenthesis: write 'free ('",
	"cfg-debug-get-i": "read cfg.debug with r_config_get_b, not get_i",
	"bool-config-get-i": "read this boolean config with r_config_get_b, not get_i",
	"strndup-space": "missing space before parenthesis in strndup()",
	"eprintf-error": "eprintf reporting an error, use R_LOG_ERROR",
	"appendf-no-format": "appendf without a format specifier, use append",
	"strbuf-setf-no-format": "r_strbuf_setf without a format specifier, use r_strbuf_set",
	"strbuf-append-format": "r_strbuf_append with a format specifier, use r_strbuf_appendf",
	"typo-unkown": "typo: 'unkown' should be 'unknown'",
	"eq-zero": "missing space around '=0'",
	"eq-one": "missing space around '=1'",
	"eprintf-cap-error": "eprintf 'Error:' message, use R_LOG_ERROR",
	"x-space-empty-string": "empty string literal after 'x '",
	"x-empty-string": "empty string literal after 'x'",
	"if-brace-space": "missing space before brace: write ') {'",
	"keyword-paren-space": "missing space before parenthesis after a keyword (if/for/while/sizeof)",
	"brace-else": "missing space around else/brace",
	"return-paren": "missing space before parenthesis: write 'return ('",
	"double-semicolon": "double semicolon ';;'",
	"zero-space-semicolon": "stray space before semicolon in '0 ;'",
	"loop-index-no-space": "missing space in loop condition (';i<' / ';j<')",
	"trailing-space": "trailing whitespace at end of line",
	"bol-eprintf": "eprintf at start of line, use R_LOG_*",
	"pfmt-4d-empty": "empty string literal after a '4d' format",
	"core-cmd-newline": "r_core_cmd string ends with a newline",
	"startswith-literal": "r_str_startswith with a literal as first argument, it should be the haystack",
	"log-period": "R_LOG message must not end with a period",
	"log-error-error": "R_LOG_ERROR message redundantly starting with 'error'",
	"rapi-space-paren": "R_API prototype with a space before the parenthesis",
	"rapi-paren-space": "R_API prototype with a space after the opening parenthesis",
	"eprintf-could-failed-cannot": "eprintf 'Could/Failed/Cannot' message, use R_LOG_ERROR",
	"arch-lib-type-anal": "arch plugin should use R_LIB_TYPE_ARCH, not R_LIB_TYPE_ANAL",
	"eprintf-warning": "eprintf 'Warning:' message, use R_LOG_WARN",
}

# The checks below are a 1:1 port of the git grep pipelines of the old
# lint.sh, in the same order and with the same output. Filters are regexps
# applied to the whole "path:line" (or "path:number:line") text, paired with
# True (line must match, plain `grep`) or False (must not match, `grep -v`).
CHECKS = [
	Check("no-preincrement", # no preincrement/predecrement in 3rd part of for statement
		[Rx(rb"\+\+[a-z][a-z]*[);]")], numbered=True,
		filters=[(rb"arch", False)]),
	Check("table-tostring-print",
		[L(b"table_tostring")],
		filters=[(rb"printf|cons_print", True)]),
	Check("typo-shuold",
		[L(b"shuold")]),
	Check("sscanf-percent-s",
		[L(b"sscanf")],
		filters=[(rb"%s", True)]),
	Check("void-args", # use void on functions without parameters
		[Lbol(b"R_API"), Lbol(b"static")],
		filters=[(rb"[a-z]\(\) \{|[a-z]\(\);", True)]),
	Check("r-new0-space",
		[L(b"R_NEW0(")],
		filters=[(rb"c:", True)]),
	Check("eq-eq-quote",
		[L(b"=='")],
		filters=[(rb"===", False)]),
	Check("pipe-usage",
		[L(b"|Usage")]),
	# in the old lint.sh this pattern was '\t{"', but git grep treats the
	# unsupported \t escape as a literal 't', so this is what it checked
	Check("t-brace-quote",
		[L(b"t{\"")],
		filters=[(rb"strcmp", False), (rb"format", False), (rb"\{\",", False),
			(rb"esil", False), (rb"c:", True)]),
	# inherited from lint.sh: the first exclusion repeats the pattern, so
	# this check can never match anything; kept verbatim for compatibility
	Check("quote-brace-comma",
		[L(b"\"},")],
		filters=[(rb"strcmp", False), (rb"format", False), (rb"\"\},", False),
			(rb"\"\}\{", False), (rb"esil", False), (rb"anal/p", False), (rb"c:", True)]),
	Check("space-indent",
		[Lbol(b"   ")],
		filters=[(rb"/arch/", False), (rb"dotnet", False), (rb"mangl", False), (rb"c:", True)]),
	Check("todo-log-info",
		[L(b"TODO")],
		filters=[(rb"R_LOG_INFO", True)]),
	Check("config-set-bool-string",
		[L(b"r_config_set")], prefixes=LIBR_BINR,
		filters=[(rb"\"fal|\"tru", True)]),
	Check("hex-decimal-format",
		[L(b"0x%\"PFMT64d"), L(b"0x%d")],
		filters=[(rb"c:", True)]),
	Check("rmin-rmax-space",
		[L(b"R_MIN("), L(b"R_MAX(")],
		filters=[(rb"c:", True)]),
	Check("cmp-space",
		[L(b"cmp(")], numbered=True,
		filters=[(rb"R_API", False), (rb"R_IPI", False), (rb"static", False), (rb"c:", True)]),
	Check("file-new-null",
		[L(b"r_file_new")], warn=True,
		filters=[(rb", NULL", False), (rb"\"", True)]),
	Check("for-space",
		[L(b"for(")], numbered=True,
		filters=[(rb"_for", False), (rb"colorfor", False)]),
	Check("for-preincrement",
		[L(b"for (")], numbered=True,
		filters=[(rb"; \+\+", True), (rb"arch", False)]),
	Check("for-int",
		[L(b"for (int")], prefixes=EVERYWHERE, numbered=True,
		filters=[(rb"sys", False), (rb"libr/", True)]),
	Check("for-long",
		[L(b"for (long")], prefixes=EVERYWHERE, numbered=True,
		filters=[(rb"sys/", False)]),
	Check("for-ut",
		[L(b"for (ut")], prefixes=EVERYWHERE, numbered=True,
		filters=[(rb"sys/", False), (rb"libr", True)]),
	Check("for-size-t",
		[L(b"for (size_t")], prefixes=EVERYWHERE, numbered=True,
		filters=[(rb"c:", True), (rb"sys/", False)]),
	Check("tab-eol",
		[Leol(b"\t")], prefixes=EVERYWHERE, numbered=True,
		filters=[(rb"libr/", True), (rb"c:", True)]),
	Check("eprintf-pipe",
		[L(b"eprintf (\"|")]),
	Check("log-newline",
		[L(b"R_LOG_")], prefixes=EVERYWHERE, numbered=True,
		filters=[(rb"\\n", True), (rb"sys/", False)]),
	Check("tab-free",
		[L(b"\tfree(")],
		filters=[(rb"c:", True)]),
	Check("cfg-debug-get-i",
		[Rx(rb"cfg.debug")],
		filters=[(rb"get_i", True)]),
	Check("bool-config-get-i",
		[Rx(rb"asm.bytes\""), Rx(rb"asm.xrefs\""), Rx(rb"asm.functions\""),
			Rx(rb"asm.emu\""), Rx(rb"emu.str\"")],
		filters=[(rb"get_i", True)]),
	Check("strndup-space",
		[L(b" strndup (")], prefixes=EVERYWHERE, numbered=True,
		filters=[(rb"sys/", False)]),
	Check("eprintf-error",
		[L(b"eprintf")],
		filters=[(rb"error", True, re.I), (rb"/native/", False), (rb"spp", False), (rb"cons", False)]),
	Check("appendf-no-format",
		[L(b"appendf")],
		filters=[(rb"\"", True), (rb"%", False)]),
	Check("strbuf-setf-no-format",
		[L(b"strbuf_setf")],
		filters=[(rb"\"", True), (rb"%", False)]),
	Check("strbuf-append-format",
		[L(b"strbuf_append (")],
		filters=[(rb"\"", True), (rb"%", True)]),
	Check("typo-unkown",
		[L(b"unknown")], icase=True),
	Check("eq-zero",
		[L(b"=0")],
		filters=[(rb"c:", True), (rb"\"", False), (rb"//", False), (rb"=0x", False)]),
	Check("eq-one",
		[L(b"=1")],
		filters=[(rb"c:", True), (rb"\"", False), (rb"//", False)]),
	Check("eprintf-cap-error",
		[L(b"eprintf")], numbered=True,
		filters=[(rb"Error:", True)]),
	Check("x-space-empty-string",
		[L(b"x \"\"")], numbered=True),
	Check("x-empty-string",
		[L(b"x\"\"")], numbered=True),
	Check("if-brace-space",
		[Leol(b"){")],
		filters=[(rb"if", True)]),
	Check("keyword-paren-space",
		[L(b"sizeof("), L(b"for("), L(b"while("), L(b"if(")],
		filters=[(rb"gnu", False), (rb":static", False), (rb":R_API", False), (rb"c:", True)]),
	Check("brace-else",
		[Leol(b"else")],
		filters=[(rb"#", False), (rb"\}", True), (rb"c:", True)]),
	Check("return-paren",
		[L(b"return(")],
		filters=[(rb"R_API", False), (rb"static", False), (rb"define", False), (rb"c:", True)]),
	Check("double-semicolon",
		[Leol(b";;")], numbered=True,
		filters=[(rb"c2", False)]),
	Check("zero-space-semicolon",
		[L(b"0 ;")], numbered=True),
	Check("loop-index-no-space",
		[L(b";i<"), L(b";j<")], numbered=True,
		filters=[(rb"\"", False)]),
	Check("trailing-space",
		[Leol(b" ")], numbered=True),
	Check("bol-eprintf",
		[Lbol(b"eprintf")], numbered=True),
	Check("pfmt-4d-empty",
		[L(b"4d\"\"")], numbered=True),
	Check("core-cmd-newline",
		[L(b"r_core_cmd")], numbered=True,
		filters=[(rb"/lang/", False), (rb"\\n", True)]),
	Check("startswith-literal",
		[L(b"r_str_startswith (\"")], numbered=True),
	Check("log-period",
		[L(b"R_LOG")], prefixes=EVERYWHERE, numbered=True,
		filters=[(rb"\.\"", True), (rb"sys/", False)]),
	Check("log-error-error",
		[L(b"r_log_error (\"error")], prefixes=EVERYWHERE, numbered=True, icase=True,
		filters=[(rb"sys", False)]),
	Check("rapi-space-paren",
		[Lbol(b"R_API")], prefixes=LIBR_SHLR, numbered=True,
		filters=[(rb" \(", True)]),
	Check("rapi-paren-space",
		[Lbol(b"R_API")], prefixes=LIBR_SHLR, numbered=True,
		filters=[(rb"\( ", True)]),
	Check("eprintf-could-failed-cannot",
		[L(b"eprintf (\"Could"), L(b"eprintf (\"Failed"), L(b"eprintf (\"Cannot")], numbered=True,
		filters=[(rb"^libr/core/cmd|^libr/main/|^libr/util/syscmd", False),
			(rb"r_cons_eprintf|alloc", False)]),
	Check("arch-lib-type-anal",
		[L(b"R_LIB_TYPE_ANAL")], prefixes=ARCH_P),
]

# printed after the c++ compat check, like in the old lint.sh
WARNING_CHECKS = [
	Check("eprintf-warning",
		[L(b"eprintf")], warn=True,
		filters=[(rb"Warning:", True)]),
]

ALL_CHECKS = CHECKS + WARNING_CHECKS
for _i, _c in enumerate(ALL_CHECKS):
	_c.index = _i

PREFIX_KEYS = (b"libr/", b"binr/", b"shlr/", b"libr/arch/p/")

def legacy_line(check, match):
	"""Rebuild the old `path:line` / `path:number:line` string from a stored
	(path, lineno, content) match, used by the --dump format the tests read."""
	path, lineno, content = match
	if content is None:
		return b"Binary file " + path + b" matches"
	if check.numbered:
		return b"%s:%d:%s" % (path, lineno, content)
	return b"%s:%s" % (path, content)

def format_match(check, match):
	"""One consistent diagnostic line per finding:

	    path:line: level [check-name] message -- offending source

	The leading `path:line:` mirrors the compiler layout editors jump to, the
	level (error/warning) and [check-name] make the output easy to grep and
	filter, and the trailing source is the whitespace-trimmed offending line.
	"""
	path, lineno, content = match
	level = b"warning" if check.warn else b"error"
	head = b"%s: %s [%s] %s" % (path, level, check.name.encode(), check.msg.encode()) \
		if content is None else \
		b"%s:%d: %s [%s] %s" % (path, lineno, level, check.name.encode(), check.msg.encode())
	if content is None:
		return head + b" (binary file)"
	src = content.strip()
	return head + b" -- " + src if src else head

def passes_filters(check, line):
	for rx, keep in check.filters:
		if (rx.search(line) is not None) != keep:
			return False
	return True

def pattern_line_starts(pat, data):
	"""Return the sorted start offsets of the lines of data matching pat,
	with at most one entry per line."""
	starts = []
	find = data.find
	if pat.kind == PLAIN:
		needle = pat.needle
		pos = find(needle)
		while pos >= 0:
			starts.append(data.rfind(b"\n", 0, pos) + 1)
			nl = find(b"\n", pos + len(needle))
			if nl < 0:
				break
			pos = find(needle, nl + 1)
	elif pat.kind == BOL:
		if data.startswith(pat.body):
			starts.append(0)
		pos = find(pat.needle)
		while pos >= 0:
			starts.append(pos + 1)
			pos = find(pat.needle, pos + 1)
	elif pat.kind == EOL:
		needle = pat.needle
		pos = find(needle)
		while pos >= 0:
			starts.append(data.rfind(b"\n", 0, pos) + 1)
			pos = find(needle, pos + len(needle))
		if data and not data.endswith(b"\n") and data.endswith(pat.body):
			# the pattern also matches an unterminated last line
			starts.append(data.rfind(b"\n") + 1)
	else:
		prev = -1
		for m in pat.scan.finditer(data):
			ls = data.rfind(b"\n", 0, m.start()) + 1
			if ls != prev:
				starts.append(ls)
				prev = ls
	return starts

def pattern_matches(pat, data):
	if pat.kind == PLAIN:
		return pat.needle in data
	if pat.kind == BOL:
		return data.startswith(pat.body) or pat.needle in data
	if pat.kind == EOL:
		return pat.needle in data or data.endswith(pat.body)
	return pat.scan.search(data) is not None

def scan_file(path, data, checks, lowered=None):
	if b"\0" in data[:8000]:
		# match the "Binary file x matches" lines git grep used to print;
		# lineno 0 flags the whole-file (binary) match to the formatter
		for check in checks:
			for pat in check.pats:
				hay = data
				if pat.icase:
					if lowered is None:
						lowered = data.lower()
					hay = lowered
				if pattern_matches(pat, hay):
					line = b"Binary file " + path + b" matches"
					if passes_filters(check, line):
						check.matches.append((path, 0, None))
					break
		return
	cache = {}
	for check in checks:
		if len(check.pats) == 1:
			pat = check.pats[0]
			starts = cache.get(pat)
			if starts is None:
				hay = data
				if pat.icase:
					if lowered is None:
						lowered = data.lower()
					hay = lowered
				starts = cache[pat] = pattern_line_starts(pat, hay)
		else:
			merged = None
			for pat in check.pats:
				starts = cache.get(pat)
				if starts is None:
					hay = data
					if pat.icase:
						if lowered is None:
							lowered = data.lower()
						hay = lowered
					starts = cache[pat] = pattern_line_starts(pat, hay)
				if starts:
					merged = starts if merged is None else merged + starts
			starts = sorted(set(merged)) if merged else ()
		if not starts:
			continue
		# line numbers are computed for every check so the verbose output can
		# always point at a line; the filter still runs on the exact legacy
		# string (path:line for plain checks, path:number:line for numbered
		# ones) so the git grep | grep semantics are preserved bit for bit
		numbered = check.numbered
		lineno = 1
		prev = 0
		for ls in starts:
			lineno += data.count(b"\n", prev, ls)
			prev = ls
			le = data.find(b"\n", ls)
			if le < 0:
				le = len(data)
			content = data[ls:le]
			if numbered:
				line = b"%s:%d:%s" % (path, lineno, content)
			else:
				line = b"%s:%s" % (path, content)
			if passes_filters(check, line):
				check.matches.append((path, lineno, content))

def applicable_checks(key):
	checks = []
	for check in ALL_CHECKS:
		if check.prefixes is None:
			checks.append(check)
			continue
		for pfx in check.prefixes:
			if key[PREFIX_KEYS.index(pfx)]:
				checks.append(check)
				break
	return tuple(checks)

def scan_slice(indexed_paths):
	"""Scan a list of (index, path) pairs; return the per-check matches
	tagged with the file index, so the caller can restore the git ls-files
	order, plus the set of libr/include files with a cplusplus guard."""
	cache = {}
	cplusplus = set()
	results = [[] for _ in ALL_CHECKS]
	for idx, path in indexed_paths:
		fspath = os.path.join(ROOT, os.fsdecode(path))
		try:
			if os.path.islink(fspath):
				# like git grep, match against the link target text
				data = os.fsencode(os.readlink(fspath))
			else:
				with open(fspath, "rb") as f:
					data = f.read()
		except OSError:
			continue
		if path.startswith(b"libr/include/") and b"cplusplus" in data:
			cplusplus.add(os.fsdecode(path)[len("libr/include/"):])
		key = (path.startswith(b"libr/"), path.startswith(b"binr/"),
			path.startswith(b"shlr/"), path.startswith(b"libr/arch/p/"))
		checks = cache.get(key)
		if checks is None:
			checks = cache[key] = applicable_checks(key)
		scan_file(path, data, checks)
		for check in checks:
			if check.matches:
				results[check.index].append((idx, check.matches))
				check.matches = []
	return results, cplusplus

def run_scan(jobs=1):
	"""Read every tracked file once and run all the checks on it.
	Returns the set of libr/include files with a cplusplus guard."""
	files = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT,
		stdout=subprocess.PIPE, check=True).stdout
	indexed = list(enumerate(f for f in files.split(b"\0") if f))
	outs = None
	if jobs > 1 and len(indexed) > 256:
		try:
			import multiprocessing
			slices = [indexed[w::jobs] for w in range(jobs)]
			with multiprocessing.Pool(jobs) as pool:
				outs = pool.map(scan_slice, slices)
		except Exception:
			outs = None # scan serially instead
	if outs is None:
		outs = [scan_slice(indexed)]
	cplusplus = set()
	for _, cxx in outs:
		cplusplus |= cxx
	for check in ALL_CHECKS:
		tagged = []
		for results, _ in outs:
			tagged.extend(results[check.index])
		tagged.sort(key=lambda t: t[0])
		for _, lines in tagged:
			check.matches.extend(lines)
	return cplusplus

def cxx_excluded(name):
	return any(x in name for x in ("heap", "userconf", "sflib", "r_version"))

def cxx_compat_lists(cplusplus):
	"""Every header in libr/include must have an extern C guard."""
	incdir = os.path.join(ROOT, "libr", "include")
	guarded = sorted(name for name in cplusplus if not cxx_excluded(name))
	headers = []
	for top in sorted(os.listdir(incdir)):
		if top.startswith("."):
			continue
		entries = [top]
		fulltop = os.path.join(incdir, top)
		if os.path.isdir(fulltop):
			for dirpath, dirnames, filenames in os.walk(fulltop):
				rel = os.path.relpath(dirpath, incdir)
				for name in dirnames + filenames:
					entries.append(os.path.join(rel, name))
		for name in entries:
			if name.endswith("h") and not cxx_excluded(name):
				headers.append(name)
	headers.sort()
	return guarded, headers

def cxx_compat_check(cplusplus):
	guarded, headers = cxx_compat_lists(cplusplus)
	if guarded == headers:
		return True
	for line in difflib.unified_diff(guarded, headers,
			fromfile="cplusplus-guarded", tofile="headers", lineterm=""):
		print(line)
	return False

def check_includes():
	res = subprocess.run([sys.executable, os.path.join(ROOT, "sys", "check_includes.py")], cwd=ROOT)
	return res.returncode == 0

def dump(out, cplusplus):
	"""Print the output of every check with markers (used by the tests)."""
	for check in ALL_CHECKS:
		out.write(b"== %s\n" % check.name.encode())
		for match in check.matches:
			out.write(legacy_line(check, match) + b"\n")
	guarded, headers = cxx_compat_lists(cplusplus)
	out.write(b"== cxx-guarded\n" + "".join(l + "\n" for l in guarded).encode())
	out.write(b"== cxx-headers\n" + "".join(l + "\n" for l in headers).encode())

def main(argv):
	ap = argparse.ArgumentParser(description=
		"radare2 source linter: single-pass port of the old lint.sh git grep pipelines")
	ap.add_argument("--all", action="store_true",
		help="do not stop at the first failing check, report all of them")
	ap.add_argument("-j", "--jobs", type=int, default=0,
		help="amount of files to scan in parallel (0 = one per cpu)")
	ap.add_argument("--dump", action="store_true", help=argparse.SUPPRESS)
	args = ap.parse_args(argv)
	jobs = args.jobs if args.jobs > 0 else min(os.cpu_count() or 1, 8)
	cplusplus = run_scan(jobs)
	out = sys.stdout.buffer
	if args.dump:
		dump(out, cplusplus)
		return 0
	failed = False
	for check in CHECKS:
		if not check.matches:
			continue
		for match in check.matches:
			out.write(format_match(check, match) + b"\n")
		if check.warn:
			continue
		failed = True
		if not args.all:
			out.flush()
			return 1
	out.flush()
	if not cxx_compat_check(cplusplus):
		failed = True
		if not args.all:
			return 1
	for check in WARNING_CHECKS:
		for match in check.matches:
			out.write(format_match(check, match) + b"\n")
	out.flush()
	if not check_includes():
		failed = True
	return 1 if failed else 0

if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
