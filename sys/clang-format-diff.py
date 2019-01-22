#!/usr/bin/env python3
#
#===- clang-format-diff.py - ClangFormat Diff Reformatter ----*- python -*--===#
#
#                     The LLVM Compiler Infrastructure
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#

#
# Slightly modified to handle the definition of functions, which do not
# require a space before the parenthesis
#

r"""
ClangFormat Diff Reformatter
============================

This script reads input from a unified diff and reformats all the changed
lines. This is useful to reformat all the lines touched by a specific patch.
Example usage for git/svn users:

  git diff -U0 --no-color HEAD^ | clang-format-diff.py -p1 -i
  svn diff --diff-cmd=diff -x-U0 | clang-format-diff.py -i

"""

import argparse
import difflib
import re
import subprocess
import sys
import tempfile
import os
from functools import reduce
try:
  from StringIO import StringIO
except ImportError:
  from io import StringIO

def main():
  parser = argparse.ArgumentParser(description=
                                   'Reformat changed lines in diff. Without -i '
                                   'option just output the diff that would be '
                                   'introduced. Use something like: '
                                   'git diff master..my-branch | ./sys/clang-format-diff.py -p1 -i')
  parser.add_argument('-i', action='store_true', default=False,
                      help='apply edits to files instead of displaying a diff')
  parser.add_argument('-p', metavar='NUM', default=0,
                      help='strip the smallest prefix containing P slashes')
  parser.add_argument('-regex', metavar='PATTERN', default=None,
                      help='custom pattern selecting file paths to reformat '
                      '(case sensitive, overrides -iregex)')
  parser.add_argument('-iregex', metavar='PATTERN', default=
                      r'.*\.(cpp|cc|c\+\+|cxx|c|cl|h|hpp|m|mm|inc|js|ts|proto'
                      r'|protodevel|java)',
                      help='custom pattern selecting file paths to reformat '
                      '(case insensitive, overridden by -regex)')
  parser.add_argument('-sort-includes', action='store_true', default=False,
                      help='let clang-format sort include blocks')
  parser.add_argument('-v', '--verbose', action='store_true',
                      help='be more verbose, ineffective without -i')
  parser.add_argument('--debug', action='store_true',
                      help='debug mode')
  parser.add_argument('-style',
                      help='formatting style to apply (LLVM, Google, Chromium, '
                      'Mozilla, WebKit)')
  parser.add_argument('-binary', default='clang-format',
                      help='location of binary to use for clang-format')
  args = parser.parse_args()

  def debug(s):
    if args.debug:
      sys.stderr.write(str(s) + '\n')

  # Extract changed lines for each file.
  filename = None
  lines_by_file = {}
  input = sys.stdin.read().split('\n')
  for lineidx, line in enumerate(input):
    match = re.search('^\+\+\+\ (.*?/){%s}(\S*)' % args.p, line)
    if match:
      filename = match.group(2)
    if filename == None:
      continue

    if args.regex is not None:
      if not re.match('^%s$' % args.regex, filename):
        continue
    else:
      if not re.match('^%s$' % args.iregex, filename, re.IGNORECASE):
        continue

    match = re.search('^@@.*\+(\d+)(,(\d+))?', line)
    if match:
      start_line = int(match.group(1))
      line_count = 1
      if match.group(3):
        line_count = int(match.group(3))
      if line_count == 0:
        continue
      end_line = start_line + line_count - 1
      ranges = []
      range_start, range_end = None, None
      range_line = -1
      debug(line_count)
      i = 0
      while True:
        # stop iterating when finding the next diff
        if lineidx + i >= len(input) or input[lineidx + i].startswith('diff'):
          break

        debug('lineidx : ' + input[lineidx + i])
        # do not count lines that are removed
        if not input[lineidx + i].startswith('-'):
          range_line += 1

        if input[lineidx + i].startswith('+'):
          if range_start is None:
            range_start = start_line + range_line
            debug('set range_start: ' + str(start_line + range_line))
        elif range_start is not None and range_end is None:
            range_end = start_line + range_line
            debug('set range_end: ' + str(start_line + range_line))
            lines_by_file.setdefault(filename, []).append([range_start, range_end - 1])
            range_start, range_end = None, None

        i += 1

  # Reformat files containing changes in place.
  for filename, lines in lines_by_file.items():
    debug('%s: %s' % (filename,lines))
    command = [args.binary, filename]
    if args.sort_includes:
      command.append('-sort-includes')
    if lines:
        s = [('-lines', str(x[0]) + ':' + str(x[1])) for x in lines]
        s = reduce(lambda x, y: x + y, s)
        command.extend(s)
    if args.style:
      command.extend(['-style', args.style])
    p = subprocess.Popen(command,
                         stdout=subprocess.PIPE,
                         stderr=None,
                         stdin=subprocess.PIPE,
                         universal_newlines=True)
    stdout, stderr = p.communicate()
    if p.returncode != 0:
      sys.exit(p.returncode)

    with open(filename) as f:
      code = f.readlines()
    formatted_code = StringIO(stdout).readlines()
    modified_lines = dict()
    if lines:
        for x in lines:
            for i in range(x[0], x[1] + 1):
                modified_lines[i] = True

    delta = 10
    # handle functions definitions/declarations: do not use space before (
    for i, l in enumerate(formatted_code):
        if modified_lines and not any(map(lambda x: x in modified_lines, range(i + 1 - delta, i + 1 + delta))):
            continue

        debug('formatted_code: ' + formatted_code[i])
        if formatted_code[i].startswith('R_API ') or formatted_code[i].startswith('static ') or formatted_code[i].startswith('R_IPI '):
            formatted_code[i] = formatted_code[i].replace(' (', '(')

        formatted_code[i] = formatted_code[i].replace('Elf_ (', 'Elf_(')

        while ' ? ' in formatted_code[i] and ' : ' in formatted_code[i]:
            pos_q = formatted_code[i].index(' ? ')
            pos_c = formatted_code[i].index(' : ')
            if pos_q >= pos_c:
                break
            formatted_code[i] = formatted_code[i].replace(' ? ', '? ', 1)
            formatted_code[i] = formatted_code[i].replace(' : ', ': ', 1)

    diff = difflib.unified_diff(code, formatted_code,
                                filename, filename,
                                '(before formatting)', '(after formatting)')
    diff_string = ''.join(diff)
    if len(diff_string) > 0:
      if args.i:
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(diff_string.encode())
        f.close()
        os.system('git apply -p0 < "%s"' % (f.name))
        os.unlink(f.name)
      else:
        sys.stdout.write(diff_string)

if __name__ == '__main__':
  main()
