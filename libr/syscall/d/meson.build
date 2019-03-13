sdb_files = [
  'darwin-arm-32',
  'darwin-arm-64',
  'darwin-x86-32',
  'darwin-x86-64',
  'dos-x86-16',
  'freebsd-x86-32',
  'ios-arm-32',
  'ios-arm-64',
  'ios-x86-32',
  'linux-arm-32',
  'linux-arm-64',
  'linux-mips-32',
  'linux-sparc-32',
  'linux-x86-32',
  'linux-x86-64',
  'netbsd-x86-32',
  'openbsd-x86-32',
  'openbsd-x86-64',
  's110-arm-16',
  'windows-x86-32',
  'windows-x86-64',
]

sdb_pre_script = '''#script
import re
import sys
inf = open(sys.argv[1])
outf = open(sys.argv[2], 'w')
for line in inf:
    if not line.startswith('_') and '=' in line:
        arr = re.split('=|,', line)
        print('%s.%s=%s' % (arr[1], arr[2], arr[0]), file=outf)
    print(line, file=outf, end='')
inf.close()
outf.close()
'''

sdb_pre_cmd = [
  py3_exe,
  '-c',
  sdb_pre_script,
  '@INPUT@',
  '@OUTPUT@'
]

foreach file : sdb_files
  infile = '@0@.sdb.txt'.format(file)
  if host_machine.system() == 'windows'
    infile = run_command(sdb_readlink_cmd + [join_paths(meson.current_source_dir(), infile)]).stdout().strip()
  endif
  tmp_outfile = '@0@.sdb.txt.tmp'.format(file)
  pre_sdb_txt = custom_target(tmp_outfile,
    input: infile,
    output: tmp_outfile,
    command: sdb_pre_cmd,
    build_by_default: true,
    install: false
  )

  outfile = '@0@.sdb'.format(file)
  custom_target(outfile,
    input: pre_sdb_txt,
    output: outfile,
    command: sdb_gen_cmd,
    depends: sdb_exe,
    build_by_default: true,
    install: true,
    install_dir: join_paths(r2_sdb, 'syscall')
  )
endforeach
