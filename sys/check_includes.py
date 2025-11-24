#!/usr/bin/env python3

import glob
import os
import re
import sys

def extract_list(content, list_name):
    pattern = rf'{list_name} (\+?=) \[(.*?)\]'
    matches = re.findall(pattern, content, re.DOTALL)
    files = []
    for op, items in matches:
        # Split by comma, but handle multiline
        lines = items.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith("'") and (line.endswith("',") or line.endswith("'")):
                if line.endswith("',"):
                    files.append(line[1:-2])
                else:
                    files.append(line[1:-1])
            elif line.startswith('"') and (line.endswith('",') or line.endswith('"')):
                if line.endswith('",'):
                    files.append(line[1:-2])
                else:
                    files.append(line[1:-1])
            elif line.startswith('join_paths('):
                # Handle join_paths
                # For simplicity, assume it's join_paths('include', 'sflib', arch, file) or similar
                # But for common, it's join_paths('include/sflib/common/sftypes.h')
                # Actually, for sflib_common_files, it's join_paths('include/sflib/common/sftypes.h')
                # So, extract the string inside
                inner = line[11:-1]  # remove join_paths(
                if inner.endswith(')'):
                    inner = inner[:-1]
                # Assume it's a single string
                if inner.startswith("'") and inner.endswith("'"):
                    files.append(inner[1:-1])
    return files

def main():
    meson_file = 'libr/meson.build'
    if not os.path.exists(meson_file):
        print(f"Error: {meson_file} not found")
        sys.exit(1)

    with open(meson_file, 'r') as f:
        content = f.read()

    lists = [
        'include_files',
        'r_util_files',
        'r_muta_files',
        'r_anal_files',
        'r_esil_files',
        'sflib_common_files'
    ]

    all_files = []
    for lst in lists:
        all_files.extend(extract_list(content, lst))

    # Now, handle sflib_arch_files
    # First, get sflib_arch
    arch_match = re.search(r'sflib_arch = \[(.*?)\]', content, re.DOTALL)
    if arch_match:
        arch_items = arch_match.group(1)
        archs = []
        for line in arch_items.split('\n'):
            line = line.strip()
            if line.startswith("'") and line.endswith("',"):
                archs.append(line[1:-2])

        # sflib_arch_files
        arch_files_match = re.search(r'sflib_arch_files = \[(.*?)\]', content, re.DOTALL)
        if arch_files_match:
            arch_files_items = arch_files_match.group(1)
            arch_files = []
            for line in arch_files_items.split('\n'):
                line = line.strip()
                if line.startswith("'") and line.endswith("',"):
                    arch_files.append(line[1:-2])

            for arch in archs:
                for file in arch_files:
                    all_files.append(f'include/sflib/{arch}/{file}')

    # Get all actual header files
    all_headers = glob.glob('libr/include/**/*.h', recursive=True)
    actual = set()
    for h in all_headers:
        rel_path = h[len('libr/'):]
        if not rel_path.startswith('include/sdb/') and not rel_path.startswith('include/sflib/') and rel_path not in ('include/r_userconf.h', 'include/r_version.h'):
            actual.add(rel_path)

    listed = set(all_files)

    # Check for listed files that don't exist
    nonexistent = []
    for file in all_files:
        path = f'libr/{file}'
        if not os.path.exists(path):
            nonexistent.append(file)

    # Check for headers not listed
    missing = actual - listed

    # Check for extra listed headers
    extras = listed - actual

    if nonexistent:
        print("Listed include files that do not exist:")
        for m in sorted(nonexistent):
            print(f"  {m}")
        sys.exit(1)

    if missing:
        print("Headers in libr/include not listed in meson.build:")
        for m in sorted(missing):
            print(f"  {m}")
        sys.exit(1)

    if extras:
        print("Extra headers listed in meson.build:")
        for e in sorted(extras):
            print(f"  {e}")
        sys.exit(1)

    print("All include files are present and correctly listed.")

if __name__ == '__main__':
    main()