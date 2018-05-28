files = run_command(glob_cmd + ['*']).stdout().strip().split(';')

script = '''#script
import os
from sys import argv
for fname in argv[1:]:
    if any(ex in fname for ex in ('meson.build', 'Makefile')):
        continue
    with open(fname) as f:
        text = ' '.join(f.read().splitlines())
    print('ft %s %s' % (os.path.basename(fname), text))
'''

custom_target('tags.r2',
  input: files,
  output: 'tags.r2',
  command: [py3_exe, '-c', script, '@INPUT@'],
  capture: true,
  build_by_default: true,
  build_always: false,
  install: true,
  install_dir: r2_flags
)
