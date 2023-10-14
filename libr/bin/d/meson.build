sdb_dll_files = [
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
  'mfc100u',
  'mfc140u',
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
  'avicap',
  'avifile',
  'awdevl16',
  'cards',
  'cmc',
  'comm',
  'commctrl',
  'commdlg',
  'compobj',
  'cspman',
  'dciman',
  'ddeml',
  'deskcp16',
  'dibeng',
  'dispdib',
  'display',
  'dskmaint',
  'enable3',
  'faxcodec',
  'gdi',
  'inet16',
  'iosclass',
  'kernel',
  'keyboard',
  'lzexpand',
  'maincp16',
  'mapi',
  'mapiu',
  'mapix',
  'mciavi',
  'mcicda',
  'mcimidi',
  'mciole',
  'mciwave',
  'midimap',
  'ml3xec16',
  'mmci',
  'mmsystem',
  'modem',
  'modemui',
  'mouse',
  'msacm',
  'msacmmap',
  'msdos',
  'msdosd',
  'msjstick',
  'msmixmgr',
  'mspcic',
  'msprint',
  'mstcp',
  'msvideo',
  'netapi',
  'netcpl',
  'netdi',
  'netos',
  'netware',
  'nw16',
  'ole2',
  'ole2conv',
  'ole2disp',
  'ole2nls',
  'olecli',
  'olesvr',
  'pifmgr',
  'pkpd',
  'pmspl',
  'power',
  'rasapi16',
  'rnasetup',
  'rsrc16',
  'sb16snd',
  'sbfm',
  'setup4',
  'setupx',
  'shell',
  'sound',
  'spooler',
  'storage',
  'sysclass',
  'sysdetmg',
  'sysdm',
  'sysedit',
  'system',
  'systhunk',
  'tapi',
  'tapiaddr',
  'toolhelp',
  'typelib',
  'umdm16',
  'user',
  'ver',
  'whlp16t',
  'win32s16',
  'win87em',
  'winaspi',
  'winnet16',
  'winoldap',
  'winsock',
  'winspl16',
  'wpsapd',
  'wpsuni',
  'wpsunire',
  'wsasrv'
]

r_bin_d_sources = []

foreach file : sdb_dll_files
  if get_option('sdb_cgen')
    outfile = '@0@.c'.format(file)
    gen_cmd = sdb_gen_cmd_cgen
  else
    outfile = '@0@.sdb'.format(file)
    gen_cmd = sdb_gen_cmd
  endif
  target = custom_target(outfile,
    input: join_paths(meson.current_source_dir(), 'dll', '@0@.sdb.txt'.format(file)),
    output: outfile,
    command: gen_cmd,
    depends: sdb_exe,
    build_by_default: true,
    install: true,
    install_dir: join_paths(r2_sdb, join_paths('format', 'dll'))
  )
  if get_option('sdb_cgen')
    r_bin_d_sources += target
  endif
endforeach

# TODO: simplify this logic
sdb_files = [ 'symclass' ]

foreach file : sdb_files
  if get_option('sdb_cgen')
    outfile = '@0@.c'.format(file)
    gen_cmd = sdb_gen_cmd_cgen
  else
    outfile = '@0@.sdb'.format(file)
    gen_cmd = sdb_gen_cmd
  endif
  target = custom_target(outfile,
    input: join_paths(meson.current_source_dir(), '@0@.sdb.txt'.format(file)),
    output: outfile,
    command: gen_cmd,
    depends: sdb_exe,
    build_by_default: true,
    install: true,
    install_dir: join_paths(r2_sdb, join_paths('format'))
  )
  if get_option('sdb_cgen')
    r_bin_d_sources += target
  endif
endforeach

format_files = [
  'dex',
  'macho',
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
