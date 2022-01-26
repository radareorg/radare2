# handle capstone dependency
capstone_dep = dependency('capstone', version: '>=3.0.4', required: false)
if not capstone_dep.found() or not get_option('use_sys_capstone')
  message('Use bundled capstone')

  if get_option('capstone_in_builddir')
    capstone_path = join_paths(meson.current_build_dir(), 'capstone')
  else
    capstone_path = 'capstone'
  endif

  capstone_version = get_option('use_capstone_version')

  res = run_command(py3_exe, '-c', '__import__("sys").exit(__import__("os").path.exists("@0@"))'.format(capstone_path))
  if res.returncode() == 0
    if not git_exe.found()
      error('Cannot load capstone library. Either provide capstone in ./shlr/capstone or install git, so it can be downloaded')
    endif

    patches_files = []
    # NOTE: when you update CS_TIP or CS_BRA, also update them in shlr/Makefile
    if capstone_version == 'v5'
      CS_TIP = '6656bcb63ab4e87dc6079bd6b6b12cc8dd9b2ad8'
      CS_BRA = 'next'
      patches_files = [
        'fix-x86-16.patch',
        'mmm.patch'
      ]
    elif capstone_version == 'v3'
      CS_TIP = '61bf71c771680033651f16cff832446e421847b1'
      CS_BRA = 'v3'
    elif capstone_version == 'v4'
      CS_TIP = 'a7cac8352f7397aa73bb2e2dcc1b6cdb2e1b8461'
      CS_BRA = 'v4'
      patches_files = [
        'capstone-calloc.patch',
        'fix-x86-16.patch',
        'sparc-crash.patch',
        'sstream-null.patch'
      ]
    else
      error('Wrong capstone version selected. Please use one of the supported versions.')
    endif

    capstone_git_user = 'capstone-engine'

    message('Cloning capstone ' + CS_BRA + ' branch, commit ' + CS_TIP + ', into ' + capstone_path)
    git_cmd = 'clone -b @0@ https://github.com/@1@/capstone.git @2@'.format(CS_BRA, capstone_git_user, capstone_path)
    clone_cmd = run_command(git_exe, git_cmd.split())
    if clone_cmd.returncode() != 0
      error('Cannot execute git clone command')
    endif

    reset_cmd_str = '-C @0@ reset --hard @1@'.format(capstone_path, CS_TIP)
    reset_cmd = run_command(git_exe, reset_cmd_str.split())
    if reset_cmd.returncode() != 0
      error('Cannot execute git reset command')
    endif

    message('Patching capstone with radare\'s patches')
    foreach file : patches_files
      patch_path = join_paths(meson.current_source_dir(), 'capstone-patches', capstone_version, file)
      patch_cmd_str = '-C @0@ apply -p1 @1@'.format(capstone_path, patch_path)
      patch_cmd = run_command(git_exe, patch_cmd_str.split())
      if patch_cmd.returncode() != 0
        warning('Cannot apply patch ' + file)
      endif
    endforeach
  endif

  rel_cs_files = [
    join_paths('arch','AArch64','AArch64BaseInfo.c'),
    join_paths('arch','AArch64','AArch64Disassembler.c'),
    join_paths('arch','AArch64','AArch64InstPrinter.c'),
    join_paths('arch','AArch64','AArch64Mapping.c'),
    join_paths('arch','AArch64','AArch64Module.c'),
    join_paths('arch','ARM','ARMDisassembler.c'),
    join_paths('arch','ARM','ARMInstPrinter.c'),
    join_paths('arch','ARM','ARMMapping.c'),
    join_paths('arch','ARM','ARMModule.c'),
    join_paths('arch','Mips','MipsDisassembler.c'),
    join_paths('arch','Mips','MipsInstPrinter.c'),
    join_paths('arch','Mips','MipsMapping.c'),
    join_paths('arch','Mips','MipsModule.c'),
    join_paths('arch','PowerPC','PPCDisassembler.c'),
    join_paths('arch','PowerPC','PPCInstPrinter.c'),
    join_paths('arch','PowerPC','PPCMapping.c'),
    join_paths('arch','PowerPC','PPCModule.c'),
    join_paths('arch','Sparc','SparcDisassembler.c'),
    join_paths('arch','Sparc','SparcInstPrinter.c'),
    join_paths('arch','Sparc','SparcMapping.c'),
    join_paths('arch','Sparc','SparcModule.c'),
    join_paths('arch','SystemZ','SystemZDisassembler.c'),
    join_paths('arch','SystemZ','SystemZInstPrinter.c'),
    join_paths('arch','SystemZ','SystemZMapping.c'),
    join_paths('arch','SystemZ','SystemZMCTargetDesc.c'),
    join_paths('arch','SystemZ','SystemZModule.c'),
    join_paths('arch','X86','X86ATTInstPrinter.c'),
    join_paths('arch','X86','X86Disassembler.c'),
    join_paths('arch','X86','X86DisassemblerDecoder.c'),
    join_paths('arch','X86','X86IntelInstPrinter.c'),
    join_paths('arch','X86','X86Mapping.c'),
    join_paths('arch','X86','X86Module.c'),
    join_paths('arch','XCore','XCoreDisassembler.c'),
    join_paths('arch','XCore','XCoreInstPrinter.c'),
    join_paths('arch','XCore','XCoreMapping.c'),
    join_paths('arch','XCore','XCoreModule.c'),
    'cs.c',
    'MCInst.c',
    'MCInstrDesc.c',
    'MCRegisterInfo.c',
    'SStream.c',
    'utils.c',
  ]
  rel_cs4_files = [
    join_paths('arch','M680X','M680XDisassembler.c'),
    join_paths('arch','M680X','M680XInstPrinter.c'),
    join_paths('arch','M680X','M680XModule.c'),
    join_paths('arch','M68K','M68KDisassembler.c'),
    join_paths('arch','M68K','M68KInstPrinter.c'),
    join_paths('arch','M68K','M68KModule.c'),
    join_paths('arch','TMS320C64x','TMS320C64xDisassembler.c'),
    join_paths('arch','TMS320C64x','TMS320C64xInstPrinter.c'),
    join_paths('arch','TMS320C64x','TMS320C64xMapping.c'),
    join_paths('arch','TMS320C64x','TMS320C64xModule.c'),
  ]
  rel_cs5_files = [
    join_paths('arch','X86','X86InstPrinterCommon.c'),
    # Add riscv files
    join_paths('arch','RISCV','RISCVMapping.c'),
    join_paths('arch','RISCV','RISCVModule.c'),
    join_paths('arch','RISCV','RISCVInstPrinter.c'),
    join_paths('arch','RISCV','RISCVDisassembler.c')
  ]

  user_plugins = get_option('plugins').split(',')
  no_user_plugins = get_option('plugins') == ''
  cs_c_args = [
    '-DCAPSTONE_USE_SYS_DYN_MEM',
    '-DCAPSTONE_DIET_NO',
  ]
  if user_plugins.contains('x86') or no_user_plugins
    cs_c_args += [
      '-DCAPSTONE_HAS_X86',
      '-DCAPSTONE_X86_ATT_DISABLE_NO',
      '-DCAPSTONE_X86_REDUCE_NO',
    ]
  endif
  if user_plugins.contains('arm') or no_user_plugins
    cs_c_args += [
      '-DCAPSTONE_HAS_ARM',
      '-DCAPSTONE_HAS_ARM64',
    ]
  endif
  if user_plugins.contains('sparc') or no_user_plugins
    cs_c_args += [
      '-DCAPSTONE_HAS_SPARC',
    ]
  endif
  if user_plugins.contains('mips') or no_user_plugins
    cs_c_args += [
      '-DCAPSTONE_HAS_MIPS',
    ]
  endif
  if no_user_plugins
    cs_c_args += [
      '-DCAPSTONE_HAS_M68K',
      '-DCAPSTONE_HAS_M680X',
      '-DCAPSTONE_HAS_POWERPC',
      '-DCAPSTONE_HAS_SPARC',
      '-DCAPSTONE_HAS_SYSZ',
      '-DCAPSTONE_HAS_XCORE',
      '-DCAPSTONE_HAS_TMS320C64X',
    ]
  endif

  cs_files = []
  foreach rel_cs_file : rel_cs_files
    cs_files += [join_paths(capstone_path, rel_cs_file)]
  endforeach
  if capstone_version == 'v4' or capstone_version == 'v5'
    foreach rel_cs_file : rel_cs4_files
      cs_files += [join_paths(capstone_path, rel_cs_file)]
    endforeach
  endif
  if capstone_version == 'v5'
    foreach rel_cs_file : rel_cs5_files
      cs_files += [join_paths(capstone_path, rel_cs_file)]
    endforeach
    cs_c_args += [ '-DCAPSTONE_HAS_RISCV' ]
  endif

  capstone_includes = [platform_inc, include_directories(join_paths('capstone','include'))]
  if capstone_version == 'v4' or capstone_version == 'v5'
    capstone_includes += [include_directories(join_paths('capstone','include','capstone'))]
  endif

  libr2capstone = static_library('r2capstone', cs_files,
    c_args: cs_c_args,
    include_directories: capstone_includes,
    implicit_include_directories: false
  )

  capstone_dep = declare_dependency(
    link_with: libr2capstone,
    include_directories: capstone_includes
  )
else
  message('Use system-provided capstone library')
endif

# handle bochs dependency
bochs_files = [
  join_paths('bochs','src','libbochs.c')
]

bochs_inc = [platform_inc, include_directories(join_paths('bochs','include'))]

libr2bochs = static_library('r2bochs', bochs_files,
  dependencies: [r_util_dep],
  include_directories: bochs_inc,
  implicit_include_directories: false
)

bochs_dep = declare_dependency(
  link_with: libr2bochs,
  include_directories: bochs_inc
)


# handle java dependency
java_files = [
  join_paths('java','class.c'),
  join_paths('java','code.c'),
  join_paths('java','dsojson.c'),
  join_paths('java','ops.c'),
  #'java/main.c',
]

java_inc = [platform_inc, include_directories('java')]

libr2java = static_library('r2java', java_files,
  dependencies: [r_util_dep],
  include_directories: java_inc,
  implicit_include_directories: false
)

java_dep = declare_dependency(
  link_with: libr2java,
  include_directories: java_inc
)


# handle qnx dependency
qnx_files = [
  join_paths('qnx','src','core.c'),
  join_paths('qnx','src','libqnxr.c'),
  join_paths('qnx','src','packet.c'),
  join_paths('qnx','src','sigutil.c'),
  join_paths('qnx','src','utils.c'),
]

qnx_inc = [platform_inc, include_directories(join_paths('qnx','include'))]

libr2qnx = static_library('r2qnx', qnx_files,
  dependencies: [r_socket_dep],
  include_directories: qnx_inc,
  implicit_include_directories: false
)

qnx_dep = declare_dependency(
  link_with: libr2qnx,
  include_directories: qnx_inc
)


# handle lz4 dependency (unused?)
lz4_dep = dependency('liblz4', required: false)
if not lz4_dep.found() or not get_option('use_sys_lz4')
  message('Use bundled lz4')
  lz4_files = [
    'lz4/lz4.c',
  ]

  lz4_inc = [platform_inc, include_directories('lz4')]

  libr2lz4 = static_library('r2lz4', lz4_files,
    include_directories: lz4_inc,
    implicit_include_directories: false
  )

  lz4_dep = declare_dependency(
    link_with: libr2lz4,
    include_directories: lz4_inc
  )
else
  message('Use system-provided lz4 library')
endif


# handle zip dependency
zip_dep = dependency('libzip', required: false)
if not zip_dep.found() or not get_option('use_sys_zip')
  message('Use bundled zip')

  zip_files = [
    join_paths('zip','zip','zip_add.c'),
    join_paths('zip','zip','zip_add_dir.c'),
    join_paths('zip','zip','zip_add_entry.c'),
    join_paths('zip','zip','zip_close.c'),
    join_paths('zip','zip','zip_delete.c'),
    join_paths('zip','zip','zip_dir_add.c'),
    join_paths('zip','zip','zip_dirent.c'),
    join_paths('zip','zip','zip_discard.c'),
    join_paths('zip','zip','zip_entry.c'),
    join_paths('zip','zip','zip_err_str.c'),
    join_paths('zip','zip','zip_error.c'),
    #join_paths('zip','zip','zip_error_clear.c'),
    join_paths('zip','zip','zip_error_get.c'),
    join_paths('zip','zip','zip_error_get_sys_type.c'),
    join_paths('zip','zip','zip_error_strerror.c'),
    join_paths('zip','zip','zip_error_to_str.c'),
    join_paths('zip','zip','zip_extra_field.c'),
    join_paths('zip','zip','zip_extra_field_api.c'),
    join_paths('zip','zip','zip_fclose.c'),
    join_paths('zip','zip','zip_fdopen.c'),
    join_paths('zip','zip','zip_file_add.c'),
    #join_paths('zip','zip','zip_file_error_clear.c'),
    join_paths('zip','zip','zip_file_error_get.c'),
    join_paths('zip','zip','zip_file_get_comment.c'),
    join_paths('zip','zip','zip_file_get_offset.c'),
    join_paths('zip','zip','zip_file_rename.c'),
    join_paths('zip','zip','zip_file_replace.c'),
    join_paths('zip','zip','zip_file_set_comment.c'),
    join_paths('zip','zip','zip_file_strerror.c'),
    join_paths('zip','zip','zip_filerange_crc.c'),
    join_paths('zip','zip','zip_fopen.c'),
    join_paths('zip','zip','zip_fopen_encrypted.c'),
    join_paths('zip','zip','zip_fopen_index.c'),
    join_paths('zip','zip','zip_fopen_index_encrypted.c'),
    join_paths('zip','zip','zip_fread.c'),
    join_paths('zip','zip','zip_get_archive_comment.c'),
    join_paths('zip','zip','zip_get_archive_flag.c'),
    join_paths('zip','zip','zip_get_compression_implementation.c'),
    join_paths('zip','zip','zip_get_encryption_implementation.c'),
    join_paths('zip','zip','zip_get_file_comment.c'),
    join_paths('zip','zip','zip_get_name.c'),
    join_paths('zip','zip','zip_get_num_entries.c'),
    join_paths('zip','zip','zip_get_num_files.c'),
    join_paths('zip','zip','zip_name_locate.c'),
    join_paths('zip','zip','zip_new.c'),
    join_paths('zip','zip','zip_open.c'),
    join_paths('zip','zip','zip_rename.c'),
    join_paths('zip','zip','zip_replace.c'),
    join_paths('zip','zip','zip_set_archive_comment.c'),
    join_paths('zip','zip','zip_set_archive_flag.c'),
    join_paths('zip','zip','zip_set_default_password.c'),
    join_paths('zip','zip','zip_set_file_comment.c'),
    join_paths('zip','zip','zip_set_file_compression.c'),
    join_paths('zip','zip','zip_set_name.c'),
    join_paths('zip','zip','zip_source_buffer.c'),
    join_paths('zip','zip','zip_source_close.c'),
    join_paths('zip','zip','zip_source_crc.c'),
    join_paths('zip','zip','zip_source_deflate.c'),
    join_paths('zip','zip','zip_source_error.c'),
    join_paths('zip','zip','zip_source_file.c'),
    join_paths('zip','zip','zip_source_filep.c'),
    join_paths('zip','zip','zip_source_free.c'),
    join_paths('zip','zip','zip_source_function.c'),
    join_paths('zip','zip','zip_source_layered.c'),
    join_paths('zip','zip','zip_source_open.c'),
    join_paths('zip','zip','zip_source_pkware.c'),
    join_paths('zip','zip','zip_source_pop.c'),
    join_paths('zip','zip','zip_source_read.c'),
    join_paths('zip','zip','zip_source_stat.c'),
    join_paths('zip','zip','zip_source_window.c'),
    join_paths('zip','zip','zip_source_zip.c'),
    join_paths('zip','zip','zip_source_zip_new.c'),
    join_paths('zip','zip','zip_stat.c'),
    join_paths('zip','zip','zip_stat_index.c'),
    join_paths('zip','zip','zip_stat_init.c'),
    join_paths('zip','zip','zip_strerror.c'),
    join_paths('zip','zip','zip_string.c'),
    join_paths('zip','zip','zip_unchange.c'),
    join_paths('zip','zip','zip_unchange_all.c'),
    join_paths('zip','zip','zip_unchange_archive.c'),
    join_paths('zip','zip','zip_unchange_data.c'),
    join_paths('zip','zip','zip_utf-8.c')
  ]

  zip_inc = [platform_inc, include_directories('zip/include')]

  libr2zip = static_library('r2zip', zip_files,
    include_directories: zip_inc,
    implicit_include_directories: false,
    dependencies: zlib_dep
  )

  zip_dep = declare_dependency(
    link_with: libr2zip,
    include_directories: zip_inc
  )
else
  message('Use system-provided zip library')
endif


# handle grub dependency
grub_files = [
  #'grub/fs/affs.c',
  #'grub/fs/afs.c',
  #'grub/fs/afs_be.c',
  #'grub/fs/befs.c',
  #'grub/fs/befs_be.c',
  #'grub/fs/btrfs.c',
  join_paths('grub','fs','cpio.c'),
  join_paths('grub','fs','ext2.c'),
  join_paths('grub','fs','fat.c'),
  join_paths('grub','fs','fb.c'),
  join_paths('grub','fs','fshelp.c'),
  join_paths('grub','fs','hfs.c'),
  join_paths('grub','fs','hfsplus.c'),
  join_paths('grub','fs','iso9660.c'),
  join_paths('grub','fs','jfs.c'),
  join_paths('grub','fs','minix.c'),
  #join_paths('grub','fs','minix2.c'),
  #join_paths('grub','fs','nilfs2.c'),
  join_paths('grub','fs','ntfs.c'),
  join_paths('grub','fs','ntfscomp.c'),
  join_paths('grub','fs','reiserfs.c'),
  join_paths('grub','fs','sfs.c'),
  join_paths('grub','fs','tar.c'),
  join_paths('grub','fs','udf.c'),
  join_paths('grub','fs','ufs.c'),
  join_paths('grub','fs','ufs2.c'),
  join_paths('grub','fs','xfs.c'),
  join_paths('grub','grubfs.c'),
  join_paths('grub','kern','device.c'),
  join_paths('grub','kern','disk.c'),
  join_paths('grub','kern','env.c'),
  join_paths('grub','kern','err.c'),
  join_paths('grub','kern','file.c'),
  join_paths('grub','kern','fs.c'),
  join_paths('grub','kern','list.c'),
  join_paths('grub','kern','misc.c'),
  join_paths('grub','kern','mm.c'),
  join_paths('grub','kern','partition.c'),
  join_paths('grub','kern','term.c'),
  join_paths('grub','kern','time.c'),
  #join_paths('grub','main.c'),
  #join_paths('grub','partmap','acorn.c'),
  join_paths('grub','partmap','amiga.c'),
  join_paths('grub','partmap','apple.c'),
  join_paths('grub','partmap','bsdlabel.c'),
  join_paths('grub','partmap','gpt.c'),
  join_paths('grub','partmap','msdos.c'),
  join_paths('grub','partmap','sun.c'),
  join_paths('grub','partmap','sunpc.c'),
]

grub_inc = [platform_inc, include_directories('grub', join_paths('grub','include'))]

libr2grub = static_library('r2grub', grub_files,
  dependencies: [r_util_dep],
  include_directories: grub_inc,
  implicit_include_directories: false
)

grub_dep = declare_dependency(
  link_with: libr2grub,
  include_directories: grub_inc
)

# handle winkd dependency
winkd_files = [
  join_paths('winkd','iob_pipe.c'),
  join_paths('winkd','iob_net.c'),
  join_paths('winkd','kd.c'),
  join_paths('winkd','transport.c'),
  join_paths('winkd','winkd.c'),
]

winkd_inc = [platform_inc, include_directories('winkd')]

libr2winkd = static_library('r2winkd', winkd_files,
  dependencies: [r_hash_dep, r_crypto_dep, r_socket_dep, r_util_dep],
  include_directories: winkd_inc,
  implicit_include_directories: false
)

winkd_dep = declare_dependency(
  link_with: libr2winkd,
  include_directories: winkd_inc
)


# handle ar dependency
ar_files = [
  'ar/ar.c'
]

ar_inc = [platform_inc, include_directories(['ar'])]

libr2ar = static_library('r2ar', ar_files,
  dependencies: [r_util_dep],
  include_directories: ar_inc,
  implicit_include_directories: false
)

ar_dep = declare_dependency(
  link_with: libr2ar,
  include_directories: ar_inc
)

# handle mpc dependency
mpc_files = [
  join_paths('mpc','mpc.c')
]

mpc_inc = [platform_inc, include_directories(['mpc'])]

libmpc = static_library('r2mpc', mpc_files,
  include_directories: mpc_inc,
  implicit_include_directories: false
)

mpc_dep = declare_dependency(
  link_with: libmpc,
  include_directories: mpc_inc
)

# handle yxml dependency
yxml_files = [
  join_paths('yxml','yxml.c')
]

yxml_inc = [platform_inc, include_directories(['yxml'])]

libyxml = static_library('r2yxml', yxml_files,
  include_directories: yxml_inc,
  implicit_include_directories: false
)

yxml_dep = declare_dependency(
  link_with: libyxml,
  include_directories: yxml_inc
)
