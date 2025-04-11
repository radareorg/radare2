import re, os, sys
import argparse
import subprocess
from typing import List

# Define lint checks using a class for modularity
class LintCheck:
    def __init__(self, id: str, description: str, enabled: bool = True,
                 pattern: re.Pattern = None,
                 filter_includes: List[str] = None, filter_excludes: List[str] = None,
                 file_include_patterns: List[str] = None, file_exclude_patterns: List[str] = None,
                 case_sensitive: bool = True):
        self.id = id
        self.description = description
        self.enabled = enabled
        self.pattern = pattern
        self.filter_includes = filter_includes or []
        self.filter_excludes = filter_excludes or []
        self.file_include_patterns = file_include_patterns or []
        self.file_exclude_patterns = file_exclude_patterns or []
        self.case_sensitive = case_sensitive

    def applies_to_file(self, file_path: str) -> bool:
        # Check if a file path should be scanned for this rule (based on include/exclude patterns)
        if self.file_include_patterns:
            if not any(inc in file_path for inc in self.file_include_patterns):
                return False
        if self.file_exclude_patterns:
            if any(exc in file_path for exc in self.file_exclude_patterns):
                return False
        return True

    def check_line(self, line: str) -> bool:
        # Determine if this line triggers the lint violation
        text = line if self.case_sensitive else line.lower()
        for inc in self.filter_includes:
            if (text if self.case_sensitive else text).find(inc if self.case_sensitive else inc.lower()) == -1:
                return False
        for exc in self.filter_excludes:
            if (text if self.case_sensitive else text).find(exc if self.case_sensitive else exc.lower()) != -1:
                return False
        if self.pattern:
            return bool(self.pattern.search(text if self.case_sensitive else text))
        return bool(self.filter_includes)  # if includes are satisfied and no pattern, it's a violation

def get_checks() -> List[LintCheck]:
    checks: List[LintCheck] = []
    # Re-implement all checks from lint.sh
    checks.append(LintCheck("no_preincrement_for", "No preincrement/predecrement in for-loop third clause",
                             pattern=re.compile(r'\+\+[a-z][a-z]*[);]'), file_include_patterns=["libr/"], file_exclude_patterns=["/arch/"]))
    checks.append(LintCheck("no_table_tostring_printf", "Avoid using table_tostring output with printf/cons_print",
                             pattern=re.compile(r'table_tostring.*(printf|cons_print)|(printf|cons_print).*table_tostring'), file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_typo_shuold", "Typo 'shuold' found (should be 'should')",
                             filter_includes=["shuold"], file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_sscanf_percent_s", "Use of 'sscanf' with '%s' (unsafe, use safer alternative)",
                             filter_includes=["sscanf", "%s"], file_include_patterns=["libr/"]))
    checks.append(LintCheck("use_void_for_no_params", "Function declared with empty '()' (should use 'void')",
                             pattern=re.compile(r'\b[a-zA-Z_][a-zA-Z_0-9]*\(\)\s*[\{;]'), file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_R_NEW0_in_c", "R_NEW0 macro used in .c file (discouraged)",
                             filter_includes=["R_NEW0("], file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_double_equal_char", "Comparison with char literal using == (suspect string compare)",
                             filter_includes=["=='"], filter_excludes=["==='"], file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_pipe_usage", "String '|Usage' found (misformatted usage message)",
                             filter_includes=["|Usage"], file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_tab_json_misformat", "Line starts with tab followed by '{\"' (possible JSON format issue)",
                             filter_includes=['\t{"'], filter_excludes=["strcmp", "format", '{",', "esil"], file_include_patterns=["libr/"]))
    checks.append(LintCheck("suspicious_json_brace", "Suspicious '\"},' sequence (possible missing brace or quote)",
                             filter_includes=['"},'], filter_excludes=["strcmp", "format", '"}{', 'esil', 'anal/p'], file_include_patterns=["libr/"]))
    checks.append(LintCheck("indent_with_tabs", "Line indented with spaces (should use tabs for code indent)",
                             pattern=re.compile(r'^[ ]{3,}'), file_include_patterns=["libr/"], file_exclude_patterns=["/arch/", "dotnet", "mangl"]))
    checks.append(LintCheck("no_TODO_in_logs", "TODO used in R_LOG_INFO call (remove before release)",
                             filter_includes=["TODO", "R_LOG_INFO"], file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_r_config_set_bool_strings", "r_config_set called with \"true\"/\"false\" strings (use booleans)",
                             pattern=re.compile(r'r_config_set.*"\s*(fal|tru)'), file_include_patterns=["libr/", "binr/"]))
    checks.append(LintCheck("no_hex_format_mismatch", "0x prefix used with %d format specifier (mismatch format)",
                             pattern=re.compile(r'0x%("PFMT64d"|%d)'), file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_R_MINMAX", "Use of R_MIN/R_MAX macros (deprecated)",
                             filter_includes=["R_MIN(", "R_MAX("], file_include_patterns=["libr/"]))
    checks.append(LintCheck("cmp_function_visibility", "Function 'cmp' not static or API (should be static or use R_API/R_IPI)",
                             filter_includes=["cmp("], filter_excludes=["R_API", "R_IPI", "static"], file_include_patterns=["libr/"]))
    checks.append(LintCheck("r_file_new_null", "r_file_new called without NULL as last argument",
                             filter_includes=["r_file_new"], filter_excludes=[", NULL"], file_include_patterns=["libr/"]))
    checks.append(LintCheck("for_no_space", "Missing space after 'for' keyword",
                             pattern=re.compile(r'\bfor\('), filter_excludes=["_for", "colorfor"], file_include_patterns=["libr/"]))
    checks.append(LintCheck("for_preincrement", "Pre-increment used in for-loop (use i++ instead of ++i)",
                             filter_includes=["; ++"], file_exclude_patterns=["/arch/"], file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_var_decl_in_for_int", "Variable of type int declared in for-loop (declare before loop)",
                             pattern=re.compile(r'\bfor\s*\(int\b'), file_exclude_patterns=["/sys/"]))
    checks.append(LintCheck("no_var_decl_in_for_long", "Variable of type long declared in for-loop (declare before loop)",
                             pattern=re.compile(r'\bfor\s*\(long\b'), file_exclude_patterns=["/sys/"]))
    checks.append(LintCheck("no_var_decl_in_for_ut", "Variable of type ut* declared in for-loop (declare before loop)",
                             pattern=re.compile(r'\bfor\s*\(ut'), file_exclude_patterns=["/sys/"]))
    checks.append(LintCheck("no_var_decl_in_for_size_t", "Variable of type size_t declared in for-loop (declare before loop)",
                             pattern=re.compile(r'\bfor\s*\(size_t'), file_exclude_patterns=["/sys/"]))
    checks.append(LintCheck("trailing_spaces", "Trailing whitespace at end of line",
                             pattern=re.compile(r'\s$'), file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_eprintf_usage", "Direct use of eprintf (use R_LOG API instead)",
                             pattern=re.compile(r'\beprintf\s*\('), file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_newline_in_R_LOG", "Newline '\\n' used inside R_LOG call",
                             filter_includes=["R_LOG_", "\\n"], file_exclude_patterns=["/sys/"]))
#    checks.append(LintCheck("no_direct_free", "Direct call to free() (use R_FREE macro)",
#                             pattern=re.compile(r'^\s*free\s*\('), file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_cfg_debug_geti", "cfg.debug accessed with get_i (use get_b for booleans)",
                             filter_includes=["cfg.debug", "get_i"], file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_asmcfg_geti", "Boolean asm/emu config accessed with get_i (use get_b)",
                             pattern=re.compile(r'asm\.bytes"|asm\.xrefs"|asm\.functions"|asm\.emu"|emu\.str"'), filter_includes=["get_i"], file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_strndup", "Use of strndup (use r_str_ndup or ensure proper free)",
                             pattern=re.compile(r'\bstrndup\s*\('), file_exclude_patterns=["/sys/"]))
    checks.append(LintCheck("no_eprintf_error", "eprintf used to print an error (use R_LOG_ERROR instead)",
                             filter_includes=["eprintf"], filter_excludes=["r_cons_eprintf"], pattern=re.compile(r'Error:'), file_include_patterns=["libr/"], file_exclude_patterns=["/native/", "spp", "/cons/"]))
    checks.append(LintCheck("no_appendf_static_string", "appendf used with static string (use append instead)",
                             filter_includes=["appendf", '"'], filter_excludes=["%"], file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_strbuf_setf_static_string", "strbuf_setf used with static string (use strbuf_set instead)",
                             filter_includes=["strbuf_setf", '"'], filter_excludes=["%"], file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_strbuf_append_format", "strbuf_append used with format specifier '%' (use strbuf_appendf)",
                             filter_includes=["strbuf_append (", '"', "%"], file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_typo_unknown", "Typo 'unkown' found (should be 'unknown')",
                             filter_includes=["unkown"], case_sensitive=False, file_include_patterns=["libr/"]))
    checks.append(LintCheck("use_NULL_not_0", "Literal 0 used (use NULL for pointers or false for booleans)",
                             filter_includes=["=0"], filter_excludes=['"', "=0x"], file_include_patterns=["libr/"]))
    checks.append(LintCheck("use_true_not_1", "Literal 1 used (use true for boolean values)",
                             filter_includes=["=1"], filter_excludes=['"', "//"], file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_eprintf_error_msg", "eprintf used with 'Error:' (use R_LOG_ERROR instead)",
                             filter_includes=["eprintf", "Error:"], file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_suspicious_x_string", "Suspicious usage of 'x \"\"' (possible string literal issue)",
                             filter_includes=['x ""'], file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_suspicious_x_string2", "Suspicious usage of 'x\"\"' (possible string literal issue)",
                             filter_includes=['x""'], file_include_patterns=["libr/"]))
    checks.append(LintCheck("if_brace_style", "Missing space between ')' and '{' in if statement",
                             pattern=re.compile(r'\){'), filter_includes=["if"], file_include_patterns=["libr/"]))
    checks.append(LintCheck("keyword_spacing", "No space after keyword (if/for/while/sizeof)",
                             pattern=re.compile(r'\b(if|for|while|sizeof)\('), file_include_patterns=["libr/"]))
    checks.append(LintCheck("else_newline_style", "'else' appears on new line without '}' on same line",
                             pattern=re.compile(r'\}\s*else\s*$'), filter_excludes=["#"], file_include_patterns=["libr/"]))
#    checks.append(LintCheck("no_return_paren", "Return statement with parentheses (use 'return x;' instead of 'return(x);')",
#                             pattern=re.compile(r'\breturn\s*\('), file_exclude_patterns=["#define"], file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_double_semicolon", "Double semicolon ';;' found",
                             pattern=re.compile(r';;\s*$'), filter_excludes=["c2"], file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_space_before_semicolon_zero", "Space before semicolon after 0 (should be '0;')",
                             filter_includes=["0 ;"], file_include_patterns=["libr/"]))
    checks.append(LintCheck("loop_index_spacing", "Missing space before '<' in loop comparison (e.g. 'if(i<j)')",
                             pattern=re.compile(r'\b[ijk]<'), filter_excludes=['"'], file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_eprintf_col0", "eprintf call starts at column 0 (should be indented or removed)",
                             pattern=re.compile(r'^eprintf'), file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_4d_doublequote", "Malformed format string '4d\"\"' (likely missing format specifier)",
                             filter_includes=['4d""'], file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_r_core_cmd_newline", "r_core_cmd used with embedded '\\n' in command string",
                             filter_includes=["r_core_cmd", "\\n"], file_exclude_patterns=["/lang/"], file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_r_str_startswith_literal", "r_str_startswith called with literal string as first arg (likely arguments swapped)",
                             filter_includes=['r_str_startswith ("'], file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_R_LOG_period_end", "Log message ends with a period before closing quote",
                             filter_includes=['."'], file_include_patterns=["libr/"]))
    checks.append(LintCheck("no_R_LOG_ERROR_caps", "R_LOG_ERROR message starts with 'ERROR:' (redundant in message)",
                             pattern=re.compile(r'R_LOG_ERROR\s*\(\s*"ERROR', re.IGNORECASE), file_exclude_patterns=["/sys/"]))
    # Checks requiring custom handling:
    checks.append(LintCheck("no_eprintf_could_fail_cannot", "eprintf with 'Could/Failed/Cannot' message"))
    checks.append(LintCheck("no_R_LIB_TYPE_ANAL", "Use of R_LIB_TYPE_ANAL in arch plugin (should be avoided)",
                             filter_includes=["R_LIB_TYPE_ANAL"], file_include_patterns=["libr/arch/p"]))
    checks.append(LintCheck("no_eprintf_warning", "eprintf with 'Warning:' message (use R_LOG_WARN)",
                             filter_includes=["eprintf", "Warning:"], file_include_patterns=["libr/"]))
    return checks

def check_cplusplus_guards() -> List[tuple]:
    """Custom check: ensure each header in libr/include has an __cplusplus guard."""
    issues = []
    include_dir = os.path.join("libr", "include")
    exclude_names = ["heap", "userconf", "sflib", "r_version"]
    headers = []
    try:
        # Use git ls-files to get headers in libr/include
        result = subprocess.run(
            ["git", "ls-files", f"{include_dir}/*.h"],
            capture_output=True,
            text=True,
            check=True
        )
        for path in result.stdout.splitlines():
            path = path.replace("\\", "/")
            if any(excl in path for excl in exclude_names):
                continue
            headers.append(path)
    except subprocess.CalledProcessError:
        return issues
    guarded_headers = []
    for header in headers:
        try:
            with open(header, 'r', encoding='utf-8', errors='ignore') as hf:
                content = hf.read()
                if "cplusplus" in content:
                    guarded_headers.append(header)
        except Exception:
            continue
    for header in headers:
        if header not in guarded_headers:
            issues.append((header, 0, "Header missing C++ guard (no '#ifdef __cplusplus')."))
    return issues

def run_lint_checks(checks: List[LintCheck], ignore_paths: List[str]) -> List[tuple]:
    issues = []
    exts = (".c", ".h", ".cpp", ".hpp", ".s", ".S")
    source_dirs = ["libr", "binr", "shlr"]
    files_to_check = []
    try:
        # Use git ls-files to get source files in specified directories
        result = subprocess.run(
            ["git", "ls-files"] + source_dirs,
            capture_output=True,
            text=True,
            check=True
        )
        for file_path in result.stdout.splitlines():
            file_path = file_path.replace("\\", "/")
            if file_path.endswith(exts) and any(file_path.startswith(d) for d in source_dirs):
                files_to_check.append(file_path)
    except subprocess.CalledProcessError:
        print("Error running git ls-files. Ensure git is installed and this is a git repository.")
        sys.exit(1)

    for file_path in files_to_check:
        if any(ig in file_path for ig in ignore_paths):
            continue
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception:
            continue
        for lineno, line in enumerate(lines, start=1):
            text = line.rstrip("\n")
            for check in checks:
                if not check.enabled:
                    continue
                # Skip custom checks here (handled after scanning lines)
                if check.id == "no_eprintf_could_fail_cannot":
                    continue
                if not check.applies_to_file(file_path):
                    continue
                # Additional content-specific guard conditions for certain checks
                if check.id == "r_file_new_null" and '"' not in text:
                    continue  # only flag r_file_new if there's a string literal (file name) present
                if check.id == "no_R_LOG_period_end" and "R_LOG" not in text:
                    continue
                if check.id == "if_brace_style" and "if" not in text:
                    continue
                if check.check_line(text):
                    issues.append((file_path, lineno, check.description))

    # Custom check: eprintf with "Could"/"Failed"/"Cannot"
    for file_path in files_to_check:
        if any(ig in file_path for ig in ignore_paths):
            continue
        if "libr/core/cmd" in file_path or "libr/main" in file_path or "libr/util/syscmd" in file_path:
            continue
        if not file_path.endswith(exts):
            continue
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception:
            continue
        for lineno, line in enumerate(lines, start=1):
            if "eprintf" in line and ("Could" in line or "Failed" in line or "Cannot" in line):
                if "r_cons_eprintf" in line or "alloc" in line:
                    continue  # skip allowed or unrelated usages
                issues.append((file_path, lineno, "eprintf with 'Could/Failed/Cannot' message"))

    # Custom check: C++ guards in headers
    cpp_guard_issues = check_cplusplus_guards()
    issues.extend(cpp_guard_issues)
    return issues

def main():
    parser = argparse.ArgumentParser(description="Run lint checks (Python replacement for lint.sh).")
    parser.add_argument("--ignore", "-i", action="append", default=[], help="Ignore files/directories containing this path substring")
    parser.add_argument("--disable-check", "-d", action="append", default=[], help="Disable a specific lint check by its ID")
    parser.add_argument("--list-checks", action="store_true", help="List all available lint check IDs and descriptions")
    args = parser.parse_args()

    checks = get_checks()
    if args.list_checks:
        for check in checks:
            status = "ENABLED" if check.enabled else "disabled"
            print(f"{check.id}: {check.description} ({status})")
        sys.exit(0)

    # Apply any requested check disables
    for check in checks:
        if check.id in args.disable_check:
            check.enabled = False

    ignore_paths = args.ignore or [
        "libr/debug/pp/mini-rv32ima/",
        "libr/config.h",
	"libr/anal/c",
        "libr/syscall/d/"
    ]
    issues = run_lint_checks(checks, ignore_paths)

    if not issues:
        print("All checks passed.")
        sys.exit(0)
    # Group and report issues by check description
    grouped = {}
    for file_path, lineno, desc in issues:
        grouped.setdefault(desc, []).append((file_path, lineno))
    for desc, occurrences in grouped.items():
        print(f"Check failed: {desc}")
        for file_path, lineno in occurrences:
            print(f"  {file_path}:{lineno}")
        print()
    sys.exit(1)

if __name__ == "__main__":
    main()
