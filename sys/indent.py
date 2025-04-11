import re
import sys
import subprocess


arg = sys.argv[1]
# Step 1: Format the file in-place using clang-format
subprocess.run(["clang-format", "-i", arg], check=True)

def is_function(s):
    return s and not s[0].isspace()

def is_control_structure(s):
    return s in {"if", "for", "while", "switch", "catch", "return"}

def fix_line(line):
    # Skip lines that are empty or only whitespace
    if not line.strip():
        return line

    # Match function calls like: foo(bar) => foo (bar)
    # Avoid if/for/while/catch/return and function *definitions*
    pattern = r'\b([a-zA-Z_]\w*)\('

    def replacer(match):
        name = match.group(1)
        if is_control_structure(name) or is_function(line):
            return match.group(0)  # No change
        return f'{name} ('

    return re.sub(pattern, replacer, line)

# Step 2: Read the file, transform it, and write it back
with open(arg, "r", encoding="utf-8") as f:
    lines = f.readlines()

with open(arg, "w", encoding="utf-8") as f:
    for line in lines:
        f.write(fix_line(line))
