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
  'dsound',
  'gsprop32',
  'iertutil',
  'kernel32',
  'mfc120',
  'mfc30',
  'mfc40',
  'mfc42',
  'mfc42u',
  'mfc71',
  'mfc71u',
  'mfc90u',
  'msi',
  'mstlsapi',
  'msvbvm50',
  'msvbvm60',
  'odbc32',
  'oleaut32',
  'olecli32',
  'oledlg',
  'olepro32',
  'olesvr32',
  'shdocvw',
  'shell32',
  'shlwapi',
  'spr32d70',
  'urlmon',
  'uxtheme',
  'vb40032',
  'vssapi',
  'winmm',
  'wldap32',
  'ws2_32',
  'wsnmp32',
  'wsock32',
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
