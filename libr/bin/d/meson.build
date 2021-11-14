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
  'AVICAP',
  'AVIFILE',
  'AWDEVL16',
  'CARDS',
  'CMC',
  'COMM',
  'COMMCTRL',
  'COMMDLG',
  'COMPOBJ',
  'CSPMAN',
  'DCIMAN',
  'DDEML',
  'DESKCP16',
  'DIBENG',
  'DISPDIB',
  'DISPLAY',
  'DSKMAINT',
  'ENABLE3',
  'FAXCODEC',
  'GDI',
  'INET16',
  'IOSCLASS',
  'KERNEL',
  'KEYBOARD',
  'LZEXPAND',
  'MAINCP16',
  'MAPI',
  'MAPIU',
  'MAPIX',
  'MCIAVI',
  'MCICDA',
  'MCIMIDI',
  'MCIOLE',
  'MCIWAVE',
  'MIDIMAP',
  'ML3XEC16',
  'MMCI',
  'MMSYSTEM',
  'MODEM',
  'MODEMUI',
  'MOUSE',
  'MSACM',
  'MSACMMAP',
  'MSDOS',
  'MSDOSD',
  'MSJSTICK',
  'MSMIXMGR',
  'MSPCIC',
  'MSPRINT',
  'MSTCP',
  'MSVIDEO',
  'NETAPI',
  'NETCPL',
  'NETDI',
  'NETOS',
  'NETWARE',
  'NW16',
  'OLE2',
  'OLE2CONV',
  'OLE2DISP',
  'OLE2NLS',
  'OLECLI',
  'OLESVR',
  'PIFMGR',
  'PKPD',
  'PMSPL',
  'POWER',
  'RASAPI16',
  'RNASETUP',
  'RSRC16',
  'SB16SND',
  'SBFM',
  'SETUP4',
  'SETUPX',
  'SHELL',
  'SOUND',
  'SPOOLER',
  'STORAGE',
  'SYSCLASS',
  'SYSDETMG',
  'SYSDM',
  'SYSEDIT',
  'SYSTEM',
  'SYSTHUNK',
  'TAPI',
  'TAPIADDR',
  'TOOLHELP',
  'TYPELIB',
  'UMDM16',
  'USER',
  'VER',
  'WHLP16T',
  'WIN32S16',
  'WIN87EM',
  'WINASPI',
  'WINNET16',
  'WINOLDAP',
  'WINSOCK',
  'WINSPL16',
  'WPSAPD',
  'WPSUNI',
  'WPSUNIRE',
  'WSASRV'
]

r_bin_d_sources = []

if get_option('sdb_cgen')

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
    #infile = run_command(sdb_readlink_cmd + [join_paths(meson.current_source_dir(), 'd', infile)]).stdout().strip()
    #infile = run_command(sdb_readlink_cmd + [join_paths(meson.current_source_dir(), 'd', infile)]).stdout().strip()
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
  gen_cmd = sdb_gen_cmd

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
    
else # sdb_cgen

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
