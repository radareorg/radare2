"""Small synthetic repairs using helpers extracted from a pinned radare2 tree."""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = "libr/util/agent_task.c"
HEADER = "libr/include/agent_task.h"

CASES = {
    "padding": {
        "prompt": """Complete r_agent_padding: return a newly allocated NUL-terminated string
containing count copies of ch (negative count means an empty string). Reuse an
existing utility instead of implementing padding again. Mark ownership of the
returned pointer in both the public declaration and definition. This is a
user-visible utility improvement.""",
        "signature": "R_API char *r_agent_padding(char ch, int count)",
        "body": "\treturn NULL;\n",
        "solution": "\treturn r_str_pad (NULL, 0, ch, count);\n",
        "owned": True, "helper": "r_str_pad", "tag": "util",
        "smoke": "char *s = r_agent_padding ('x', 3); CHECK (s && !strcmp (s, \"xxx\")); free (s);",
        "check": """
int i;
for (i = -2; i <= 4096; i += i < 8 ? 1 : 127) {
    char *a = r_agent_padding ('x', i);
    char *b = r_agent_padding ('y', i);
    CHECK (a && b && a != b);
    CHECK (strlen (a) == (size_t)(i < 0 ? 0 : i));
    CHECK (strlen (b) == strlen (a));
    int j;
    for (j = 0; j < i; j++) { CHECK (a[j] == 'x' && b[j] == 'y'); }
    free (a); free (b);
}
""",
    },
    "bounds": {
        "prompt": """Fix r_agent_read_word, which reads a four-byte little-endian value at a
caller-supplied offset. Reject NULL pointers and any range outside the input,
including overflowing offsets, return false and leave *out unchanged on failure.
Valid unaligned reads must work. Preserve the public signature. This is a
security fix for an out-of-bounds read.""",
        "signature": "R_API bool r_agent_read_word(const ut8 *buf, size_t len, size_t offset, ut32 *out)",
        "body": "\tif (offset + 4 > len) {\n\t\treturn false;\n\t}\n\t*out = *(const ut32 *)(buf + offset);\n\treturn true;\n",
        "solution": "\tif (!buf || !out || offset > len || len - offset < 4) {\n\t\treturn false;\n\t}\n\t*out = r_read_le32 (buf + offset);\n\treturn true;\n",
        "owned": False, "helper": "r_read_le32", "tag": "crash",
        "smoke": "ut8 b[] = {1, 2, 3, 4}; ut32 v = 0; CHECK (r_agent_read_word (b, 4, 0, &v) && v == 0x04030201);",
        "check": """
ut8 b[] = {0xff, 0x12, 0x34, 0x56, 0x78, 0x9a};
ut32 v = 0;
CHECK (r_agent_read_word (b, sizeof (b), 1, &v) && v == 0x78563412);
CHECK (r_agent_read_word (b, sizeof (b), 2, &v) && v == 0x9a785634);
size_t offsets[] = {0, 1, 2, 3, 4, 5, 6, 7, SIZE_MAX, SIZE_MAX - 2};
size_t len, i;
for (len = 0; len <= sizeof (b); len++) {
    for (i = 0; i < sizeof (offsets) / sizeof (*offsets); i++) {
        size_t off = offsets[i];
        if (off <= len && len - off >= 4) { continue; }
        v = 0xdeadbeef;
        CHECK (!r_agent_read_word (b, len, off, &v) && v == 0xdeadbeef);
    }
}
v = 0xdeadbeef;
CHECK (!r_agent_read_word (NULL, 4, 0, &v) && v == 0xdeadbeef);
CHECK (!r_agent_read_word (b, 4, 0, NULL));
""",
    },
    "json": {
        "prompt": """Fix the use-after-free in r_agent_json. Return a parsed JSON tree that stays
valid after the caller changes or frees its input. Do not change the caller's
input. Return NULL for NULL or invalid input. The returned tree must be released
by r_json_free without leaking memory. Mark ownership of the returned pointer
in the public declaration and definition. This is a security fix.""",
        "signature": "R_API RJson *r_agent_json(const char *text)",
        "body": "\tchar *copy = strdup (text);\n\tRJson *json = r_json_parse (copy);\n\tfree (copy);\n\treturn json;\n",
        "solution": "\tif (!text) {\n\t\treturn NULL;\n\t}\n\treturn r_json_parsedup (text);\n",
        "owned": True, "helper": "r_json_parsedup", "tag": "crash",
        "smoke": "RJson *j = r_agent_json (\"{}\"); CHECK (j); r_json_free (j);",
        "check": """
char *input = strdup ("{\\\"name\\\":\\\"radare\\\",\\\"n\\\":42,\\\"a\\\":[true,null]}");
char *before = strdup (input);
RJson *j = r_agent_json (input);
CHECK (j && !strcmp (input, before));
memset (input, 'x', strlen (input));
free (input); free (before);
const char *name = r_json_get_str (j, "name");
CHECK (name && !strcmp (name, "radare"));
CHECK (r_json_get_num (j, "n") == 42);
CHECK (r_json_item (r_json_get (j, "a"), 0)->type == R_JSON_BOOLEAN);
r_json_free (j);
CHECK (!r_agent_json (NULL));
CHECK (!r_agent_json ("{"));
j = r_agent_json ("\\\"hello\\\"");
CHECK (j && j->type == R_JSON_STRING && !strcmp (j->str_value, "hello"));
r_json_free (j);
""",
    },
}


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args], text=True)


def show(ref, path):
    return git("show", f"{ref}:{path}")


def function(text, name):
    match = re.search(r"^[^\n]*\b" + re.escape(name) + r"\([^\n]*\) \{\n.*?^\}", text, re.M | re.S)
    if not match:
        raise ValueError(f"Function not found: {name}")
    return match.group() + "\n"


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def main_source(body):
    return ('#include <agent_task.h>\n'
            '#define CHECK(x) do { if (!(x)) { fprintf (stderr, "Failed line %d\\n", __LINE__); return 1; } } while (0)\n'
            'int main(void) {\n' + body + '\nreturn 0;\n}\n')


def task_source(case, solution=False):
    spec = CASES[case]
    signature = spec["signature"]
    if solution and spec["owned"]:
        signature = signature.replace("R_API ", "R_API R_OWNED ")
    return "#include <agent_task.h>\n\n" + signature + " {\n" + spec["solution" if solution else "body"] + "}\n"


def fixture(work, case, source_ref, docs_ref, agents_ref):
    spec = CASES[case]
    for path in ("DEVELOPERS.md", "CONTRIBUTING.md", "doc/abi.md", "doc/indent-example.c", "test/README.md"):
        write(work / path, show(docs_ref, path))
    write(work / "AGENTS.md", show(agents_ref, "AGENTS.md"))
    # This is a buildable API slice, not a full radare2 checkout. Implementations
    # below are extracted unchanged; only the minimal build shims are synthetic.
    types = """#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
typedef uint8_t ut8;
typedef uint32_t ut32;
typedef uint64_t ut64;
typedef int64_t st64;
typedef ut32 RRune;
#define R_API
#define R_MUSTUSE
#define R_NONNULL
#define R_NULLABLE
#define R_LIKELY(x) (x)
#define R_MIN(a,b) ((a) < (b) ? (a) : (b))
#define R_NEW0(t) ((t *)calloc (1, sizeof (t)))
#define R_RETURN_VAL_IF_FAIL(x,v) do { if (!(x)) { return (v); } } while (0)
#define R_QUIET_FAIL(x) do { (void)(x); } while (0)
#define R_LOG_ERROR(...) do { } while (0)
#define IS_WHITECHAR(x) ((x) == ' ' || (x) == '\\t' || (x) == '\\n' || (x) == '\\r')
"""
    types += "\n".join(line for line in show(source_ref, "libr/include/r_types.h").splitlines()
                       if re.match(r"#define R_(OWNED|UNOWNED|OUT|INOUT)\b", line)) + "\n"
    write(work / "libr/include/r_types.h", types)
    util_header = """#pragma once
#include <r_types.h>
#include <r_util/r_json.h>
R_API char *r_str_pad(char *pad, size_t padsz, const char ch, int sz);
R_API bool r_str_startswith(const char *str, const char *needle);
R_API bool r_hex_to_byte(ut8 *val, ut8 c);
R_API int r_utf8_encode(ut8 *ptr, const RRune ch);
static inline st64 r_num_get(void *unused, const char *s) { (void)unused; return strtoll (s, NULL, 0); }
"""
    util_header += function(show(source_ref, "libr/include/r_endian.h"), "r_read_le32")
    write(work / "libr/include/r_util.h", util_header)
    for header in ("r_utf8.h", "r_hex.h"):
        write(work / "libr/include/r_util" / header, "#include <r_util.h>\n")
    for path in ("libr/include/r_util/r_json.h", "libr/util/json_parser.c"):
        write(work / path, show(source_ref, path))
    util = "/* Helper implementations extracted from radare2 (LGPL-3.0). */\n#include <r_util.h>\n"
    for path, names in (("libr/util/str.c", ("r_str_pad", "r_str_startswith")),
                        ("libr/util/hex.c", ("hex_digit_value", "r_hex_to_byte")),
                        ("libr/util/utf8.c", ("r_utf8_encode",))):
        text = show(source_ref, path)
        util += text.splitlines()[0] + "\n"
        util += "\n".join(function(text, name) for name in names)
    write(work / "libr/util/helpers.c", util)
    write(work / SOURCE, task_source(case))
    write(work / HEADER, "#include <r_util.h>\n" + spec["signature"] + ";\n")
    write(work / "test/smoke.c", main_source(spec["smoke"]))
    write(work / "Makefile", """CC?=cc
CFLAGS?=-O1 -g -Wall -Wextra -Werror=implicit-function-declaration
SOURCES=libr/util/agent_task.c libr/util/helpers.c libr/util/json_parser.c test/smoke.c
all: smoke
smoke: $(SOURCES) libr/include/agent_task.h
\t$(CC) $(CFLAGS) -I libr/include $(SOURCES) -o $@
check: smoke
\t./smoke
clean:
\trm -f smoke
.PHONY: all check clean
""")
    write(work / ".gitignore", "/smoke\n")
