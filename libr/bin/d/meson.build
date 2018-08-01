sdb_files = [
  'ws2_32',
  'oleaut32',
  'wsock32',
  'msi',
  'csmfpapi',
  'csmtpapi',
  'csncdapi',
  'msvbvm60',
  'kernel32',
  'aclui',
  'activeds',
  'atl',
  'borlndmm',
  'browseui',
  'comctl32',
  'dsound',
  'mfc42',
  'mfc42u',
  'mstlsapi',
  'msvbvm50',
  'odbc32',
  'olecli32',
  'oledlg',
  'olepro32',
  'olesvr32',
  'shdocvw',
  'shell32',
  'shlwapi',
  'uxtheme',
  'vb40032',
  'vssapi',
  'winmm',
  'cabinet',
  'gsprop32',
  'spr32d70',
  'mfc90u',
  'wldap32',
  'iertutil',
  'urlmon',
  'wsnmp32',
  'mfc30',
  'mfc40',
  'mfc71',
  'mfc71u'
]

foreach file : sdb_files
  outfile = '@0@.sdb'.format(file)
  custom_target(outfile,
    input: 'dll/@0@.sdb.txt'.format(file),
    output: outfile,
    command: sdb_gen_cmd,
    depends: sdb_exe,
    build_by_default: true,
    install: true,
    install_dir: join_paths(r2_sdb, 'format/dll')
  )
endforeach

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
