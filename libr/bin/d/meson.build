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

# Build all DLL SDB files at once using 'sdb -r .'
dll_sdb_files = []
foreach file : sdb_dll_files
  dll_sdb_files += '@0@.sdb'.format(file)
  if get_option('sdb_cgen')
    dll_sdb_files += '@0@.c'.format(file)
  endif
endforeach

# Create environment with output directory set
sdb_env = environment()
sdb_env.set('SDB_OUTPUT_DIR', join_paths(meson.current_build_dir(), 'dll'))

r_bin_d_dll_sources = custom_target('dll-sdb',
  input: [],
  output: dll_sdb_files,
  command: [sdb_exe, '-r', join_paths(meson.current_source_dir(), 'dll')],
  env: sdb_env,
  depends: sdb_exe,
  build_by_default: true,
  install: true,
  install_dir: join_paths(r2_sdb, join_paths('format', 'dll'))
)

r_bin_d_sources = []
if get_option('sdb_cgen')
  r_bin_d_sources += r_bin_d_dll_sources
endif

# Build format SDB files
sdb_files = [ 'symclass' ]

# Build all format SDB files at once using 'sdb -r .'
format_sdb_files = []
foreach file : sdb_files
  format_sdb_files += '@0@.sdb'.format(file)
  if get_option('sdb_cgen')
    format_sdb_files += '@0@.c'.format(file)
  endif
endforeach

# Create environment with output directory set
format_sdb_env = environment()
format_sdb_env.set('SDB_OUTPUT_DIR', meson.current_build_dir())

r_bin_d_format_sources = custom_target('format-sdb',
  input: [],
  output: format_sdb_files,
  command: [sdb_exe, '-r', meson.current_source_dir()],
  env: format_sdb_env,
  depends: sdb_exe,
  build_by_default: true,
  install: true,
  install_dir: join_paths(r2_sdb, join_paths('format'))
)

if get_option('sdb_cgen')
  r_bin_d_sources += r_bin_d_format_sources
endif

format_files = [
  'cdex.h',
  'dex.h',
  'jni.h',
  'bios.r2',
  'dex.r2',
  'elf32.r2',
  'elf64.r2',
  'elf_enums.r2',
  'fatmacho.r2',
  'macho.r2',
  'mz.r2',
  'ntfs.r2',
  'pe32.r2',
  'trx.r2',
  'zip.r2',
]

install_data(format_files,
  install_dir: join_paths(r2_sdb, 'format')
)
