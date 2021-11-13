sdb_files = [
  'aclui',
  'activeds',
  'atl',
  'borlndmm',
  'browseui',
  'cabinet',
  'comctl32',
  'csmfpapi',
  'csmtpapi',
  'csncdapi',
  'dsound'
]

r_bin_d_sources = []

if get_option('sdb_cgen')
foreach file : sdb_files
  outfile = '@0@.sdb'.format(file)
  target = custom_target(outfile,
    input: 'dll/@0@.sdb.txt'.format(file),
    output: outfile,
    command: sdb_gen_cmd,
    depends: sdb_exe,
    build_by_default: true,
    install: true,
    install_dir: join_paths(r2_sdb, 'format/dll')
  )
  r_bin_d_sources += target
endforeach
    
else

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
    infile = run_command(sdb_readlink_cmd + [join_paths(meson.current_source_dir(), 'd', infile)]).stdout().strip()
  endif
  tmp_outfile = '@0@.sdb.txt.tmp'.format(file)
  pre_sdb_txt = custom_target(tmp_outfile,
    input: infile,
    output: tmp_outfile,
    command: sdb_pre_cmd,
    build_by_default: true,
    install: false
  )
  if get_option('sdb_cgen')
    outfile = '@0@.c'.format(file)
    gen_cmd = sdb_gen_cmd_cgen
  else
    outfile = '@0@.sdb'.format(file)
    gen_cmd = sdb_gen_cmd
  endif

  custom_target(outfile,
    input: pre_sdb_txt,
    output: outfile,
    command: gen_cmd,
    depends: sdb_exe,
    build_by_default: true,
    install: true,
    install_dir: join_paths(r2_sdb, 'bin')
  )
endforeach
endif

format_files = [
  'elf32',
  'elf64',
  'elf_enums',
  'pe32',
  'trx',
  'mz',
  'zip'
]

install_data(format_files,
  install_dir: join_paths(r2_sdb, 'format')
)
