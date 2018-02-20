bochs_files = [
  'bochs/src/libbochs.c'
]

libr2bochs = static_library('libr2bochs', bochs_files,
  include_directories: [
    platform_inc,
    include_directories([
      'bochs/include'
    ])
  ],
  implicit_include_directories: false
)

gdb_files = [
  'gdb/src/arch.c',
  'gdb/src/common.c',
  'gdb/src/packet.c',
  'gdb/src/utils.c',
  'gdb/src/libgdbr.c',

  'gdb/src/gdbclient/core.c',
  'gdb/src/gdbclient/responses.c',
  'gdb/src/gdbclient/xml.c',

  'gdb/src/gdbserver/core.c',
]

libr2gdb = static_library('libr2gdb', gdb_files,
  include_directories: [
    platform_inc,
    include_directories([
      './gdb/include',
      './gdb/include/gdbclient',
      './gdb/include/gdbserver'
    ])
  ],
  implicit_include_directories: false
)

java_files = [
  'java/class.c',
  'java/code.c',
  'java/dsojson.c',
  'java/ops.c',
  #'java/main.c',
]

libr2java = static_library('libr2java', java_files,
  include_directories: [
    platform_inc,
    include_directories([
      'java'
    ])
  ],
  implicit_include_directories: false
)

qnx_files = [
  'qnx/src/core.c',
  'qnx/src/libqnxr.c',
  'qnx/src/packet.c',
  'qnx/src/sigutil.c',
  'qnx/src/utils.c',
]

libr2qnx = static_library('libr2qnx', qnx_files,
  include_directories: [
    platform_inc,
    include_directories([
      'qnx/include'
    ])
  ],
  implicit_include_directories: false
)

tcc_files = [
  'tcc/libtcc.c',
  'tcc/tccgen.c',
  'tcc/tccpp.c'
]

libr2tcc = static_library('libr2tcc', tcc_files,
  include_directories: [
    platform_inc,
    include_directories([
      'tcc'
    ])
  ],
  implicit_include_directories: false
)

spp_files = [
  'spp/spp.c'
]

libr2spp = static_library('libr2spp', spp_files,
  include_directories: [
    platform_inc,
    include_directories([
      'spp/'
    ])
  ],
  c_args: ['-DHAVE_R_UTIL'],
  implicit_include_directories: false
)

sdb_files = [
  'sdb/src/array.c',
  'sdb/src/base64.c',
  'sdb/src/buffer.c',
  'sdb/src/cdb.c',
  'sdb/src/cdb_make.c',
  'sdb/src/disk.c',
  'sdb/src/fmt.c',
  'sdb/src/ht.c',
  'sdb/src/journal.c',
  'sdb/src/json.c',
  'sdb/src/lock.c',
  'sdb/src/ls.c',
  # 'sdb/src/main.c',
  'sdb/src/match.c',
  'sdb/src/ns.c',
  'sdb/src/num.c',
  'sdb/src/query.c',
  'sdb/src/sdb.c',
  'sdb/src/sdbht.c',
  'sdb/src/util.c'
]

libr2sdb = static_library('libr2sdb', sdb_files,
  include_directories: [
    platform_inc,
    include_directories([
      'sdb/src',
      '../libr/include/sdb'
    ])
  ],
  implicit_include_directories: false
)

lz4_files = [
  'lz4/lz4.c',
]

libr2lz4 = static_library('libr2lz4', lz4_files,
  include_directories: [
    platform_inc,
    include_directories([
      'lz4'
    ])
  ],
  implicit_include_directories: false
)

zlib_files = [
  'zip/zip/zip_add.c',
  'zip/zip/zip_add_dir.c',
  'zip/zip/zip_add_entry.c',
  'zip/zip/zip_close.c',
  'zip/zip/zip_delete.c',
  'zip/zip/zip_dir_add.c',
  'zip/zip/zip_dirent.c',
  'zip/zip/zip_discard.c',
  'zip/zip/zip_entry.c',
  'zip/zip/zip_err_str.c',
  'zip/zip/zip_error.c',
  #'zip/zip/zip_error_clear.c',
  'zip/zip/zip_error_get.c',
  'zip/zip/zip_error_get_sys_type.c',
  'zip/zip/zip_error_strerror.c',
  'zip/zip/zip_error_to_str.c',
  'zip/zip/zip_extra_field.c',
  'zip/zip/zip_extra_field_api.c',
  'zip/zip/zip_fclose.c',
  'zip/zip/zip_fdopen.c',
  'zip/zip/zip_file_add.c',
  #'zip/zip/zip_file_error_clear.c',
  'zip/zip/zip_file_error_get.c',
  'zip/zip/zip_file_get_comment.c',
  'zip/zip/zip_file_get_offset.c',
  'zip/zip/zip_file_rename.c',
  'zip/zip/zip_file_replace.c',
  'zip/zip/zip_file_set_comment.c',
  'zip/zip/zip_file_strerror.c',
  'zip/zip/zip_filerange_crc.c',
  'zip/zip/zip_fopen.c',
  'zip/zip/zip_fopen_encrypted.c',
  'zip/zip/zip_fopen_index.c',
  'zip/zip/zip_fopen_index_encrypted.c',
  'zip/zip/zip_fread.c',
  'zip/zip/zip_get_archive_comment.c',
  'zip/zip/zip_get_archive_flag.c',
  'zip/zip/zip_get_compression_implementation.c',
  'zip/zip/zip_get_encryption_implementation.c',
  'zip/zip/zip_get_file_comment.c',
  'zip/zip/zip_get_name.c',
  'zip/zip/zip_get_num_entries.c',
  'zip/zip/zip_get_num_files.c',
  'zip/zip/zip_name_locate.c',
  'zip/zip/zip_new.c',
  'zip/zip/zip_open.c',
  'zip/zip/zip_rename.c',
  'zip/zip/zip_replace.c',
  'zip/zip/zip_set_archive_comment.c',
  'zip/zip/zip_set_archive_flag.c',
  'zip/zip/zip_set_default_password.c',
  'zip/zip/zip_set_file_comment.c',
  'zip/zip/zip_set_file_compression.c',
  'zip/zip/zip_set_name.c',
  'zip/zip/zip_source_buffer.c',
  'zip/zip/zip_source_close.c',
  'zip/zip/zip_source_crc.c',
  'zip/zip/zip_source_deflate.c',
  'zip/zip/zip_source_error.c',
  'zip/zip/zip_source_file.c',
  'zip/zip/zip_source_filep.c',
  'zip/zip/zip_source_free.c',
  'zip/zip/zip_source_function.c',
  'zip/zip/zip_source_layered.c',
  'zip/zip/zip_source_open.c',
  'zip/zip/zip_source_pkware.c',
  'zip/zip/zip_source_pop.c',
  'zip/zip/zip_source_read.c',
  'zip/zip/zip_source_stat.c',
  'zip/zip/zip_source_window.c',
  'zip/zip/zip_source_zip.c',
  'zip/zip/zip_source_zip_new.c',
  'zip/zip/zip_stat.c',
  'zip/zip/zip_stat_index.c',
  'zip/zip/zip_stat_init.c',
  'zip/zip/zip_strerror.c',
  'zip/zip/zip_string.c',
  'zip/zip/zip_unchange.c',
  'zip/zip/zip_unchange_all.c',
  'zip/zip/zip_unchange_archive.c',
  'zip/zip/zip_unchange_data.c',
  'zip/zip/zip_utf-8.c',
  'zip/zlib/adler32.c',
  'zip/zlib/compress.c',
  'zip/zlib/crc32.c',
  'zip/zlib/deflate.c',
  'zip/zlib/gzclose.c',
  'zip/zlib/gzlib.c',
  'zip/zlib/gzread.c',
  'zip/zlib/gzwrite.c',
  'zip/zlib/infback.c',
  'zip/zlib/inffast.c',
  'zip/zlib/inflate.c',
  'zip/zlib/inftrees.c',
  'zip/zlib/trees.c',
  'zip/zlib/uncompr.c',
  'zip/zlib/zutil.c'
]

libr2zip = static_library('libr2zip', zlib_files,
  include_directories: [
    platform_inc,
    include_directories([
      'zip/include'
    ])
  ],
  implicit_include_directories: false
)

cs_files = [
  'capstone/arch/AArch64/AArch64BaseInfo.c',
  'capstone/arch/AArch64/AArch64Disassembler.c',
  'capstone/arch/AArch64/AArch64InstPrinter.c',
  'capstone/arch/AArch64/AArch64Mapping.c',
  'capstone/arch/AArch64/AArch64Module.c',
  'capstone/arch/ARM/ARMDisassembler.c',
  'capstone/arch/ARM/ARMInstPrinter.c',
  'capstone/arch/ARM/ARMMapping.c',
  'capstone/arch/ARM/ARMModule.c',
  'capstone/arch/M68K/M68KDisassembler.c',
  'capstone/arch/M68K/M68KInstPrinter.c',
  'capstone/arch/M68K/M68KModule.c',
  'capstone/arch/Mips/MipsDisassembler.c',
  'capstone/arch/Mips/MipsInstPrinter.c',
  'capstone/arch/Mips/MipsMapping.c',
  'capstone/arch/Mips/MipsModule.c',
  'capstone/arch/PowerPC/PPCDisassembler.c',
  'capstone/arch/PowerPC/PPCInstPrinter.c',
  'capstone/arch/PowerPC/PPCMapping.c',
  'capstone/arch/PowerPC/PPCModule.c',
  'capstone/arch/Sparc/SparcDisassembler.c',
  'capstone/arch/Sparc/SparcInstPrinter.c',
  'capstone/arch/Sparc/SparcMapping.c',
  'capstone/arch/Sparc/SparcModule.c',
  'capstone/arch/SystemZ/SystemZDisassembler.c',
  'capstone/arch/SystemZ/SystemZInstPrinter.c',
  'capstone/arch/SystemZ/SystemZMapping.c',
  'capstone/arch/SystemZ/SystemZMCTargetDesc.c',
  'capstone/arch/SystemZ/SystemZModule.c',
  'capstone/arch/TMS320C64x/TMS320C64xDisassembler.c',
  'capstone/arch/TMS320C64x/TMS320C64xInstPrinter.c',
  'capstone/arch/TMS320C64x/TMS320C64xMapping.c',
  'capstone/arch/TMS320C64x/TMS320C64xModule.c',
  'capstone/arch/X86/X86ATTInstPrinter.c',
  'capstone/arch/X86/X86Disassembler.c',
  'capstone/arch/X86/X86DisassemblerDecoder.c',
  'capstone/arch/X86/X86IntelInstPrinter.c',
  'capstone/arch/X86/X86Mapping.c',
  'capstone/arch/X86/X86Module.c',
  'capstone/arch/XCore/XCoreDisassembler.c',
  'capstone/arch/XCore/XCoreInstPrinter.c',
  'capstone/arch/XCore/XCoreMapping.c',
  'capstone/arch/XCore/XCoreModule.c',
  'capstone/cs.c',
  'capstone/MCInst.c',
  'capstone/MCInstrDesc.c',
  'capstone/MCRegisterInfo.c',
  'capstone/SStream.c',
  'capstone/utils.c',
]

libr2capstone = static_library('libr2capstone', cs_files,
  c_args: [
    '-DCAPSTONE_X86_ATT_DISABLE_NO',
    '-DCAPSTONE_X86_REDUCE_NO',
    '-DCAPSTONE_USE_SYS_DYN_MEM',
    '-DCAPSTONE_DIET_NO',
    '-DCAPSTONE_HAS_ARM',
    '-DCAPSTONE_HAS_ARM64',
    '-DCAPSTONE_HAS_M68K',
    '-DCAPSTONE_HAS_MIPS',
    '-DCAPSTONE_HAS_POWERPC',
    '-DCAPSTONE_HAS_SPARC',
    '-DCAPSTONE_HAS_SYSZ',
    '-DCAPSTONE_HAS_X86',
    '-DCAPSTONE_HAS_XCORE',
    '-DCAPSTONE_HAS_TMS320C64X',
  ],
  include_directories: [
    include_directories([
      'capstone/include'
    ])
  ],
  implicit_include_directories: false
)

grub_files = [
  'grub/fs/affs.c',
  #'grub/fs/afs.c',
  #'grub/fs/afs_be.c',
  #'grub/fs/befs.c',
  #'grub/fs/befs_be.c',
  'grub/fs/btrfs.c',
  #'grub/fs/cpio.c',
  'grub/fs/ext2.c',
  'grub/fs/fat.c',
  'grub/fs/fb.c',
  'grub/fs/fshelp.c',
  'grub/fs/hfs.c',
  'grub/fs/hfsplus.c',
  'grub/fs/iso9660.c',
  'grub/fs/jfs.c',
  'grub/fs/minix.c',
  'grub/fs/minix2.c',
  'grub/fs/nilfs2.c',
  'grub/fs/ntfs.c',
  'grub/fs/ntfscomp.c',
  'grub/fs/reiserfs.c',
  'grub/fs/sfs.c',
  'grub/fs/tar.c',
  'grub/fs/udf.c',
  'grub/fs/ufs.c',
  'grub/fs/ufs2.c',
  'grub/fs/xfs.c',
  'grub/grubfs.c',
  'grub/kern/device.c',
  'grub/kern/disk.c',
  #'grub/kern/dl.c',
  'grub/kern/env.c',
  'grub/kern/err.c',
  'grub/kern/file.c',
  'grub/kern/fs.c',
  'grub/kern/list.c',
  'grub/kern/misc.c',
  'grub/kern/mm.c',
  'grub/kern/partition.c',
  'grub/kern/term.c',
  'grub/kern/time.c',
  #'grub/main.c',
  #'grub/partmap/acorn.c',
  'grub/partmap/amiga.c',
  'grub/partmap/apple.c',
  'grub/partmap/bsdlabel.c',
  'grub/partmap/gpt.c',
  'grub/partmap/msdos.c',
  'grub/partmap/sun.c',
  'grub/partmap/sunpc.c',
]

libr2grub = static_library('libr2grub', grub_files,
  include_directories: [
    platform_inc,
    include_directories([
      'grub',
      'grub/include'
    ])
  ],
  implicit_include_directories: false
)

windbg_files = [
  'windbg/iob_pipe.c',
  'windbg/kd.c',
  'windbg/transport.c',
  'windbg/windbg.c',
]

libr2windbg = static_library('libr2windbg', windbg_files,
  include_directories: [
    platform_inc,
    include_directories([
      'windbg'
    ])
  ],
  implicit_include_directories: false
)

udis86_files = [
  'udis86/decode.c',
  'udis86/itab.c',
  'udis86/syn.c',
  'udis86/syn-att.c',
  'udis86/syn-intel.c',
  'udis86/udis86.c',
]

libr2udis86 = static_library('libr2udis86', udis86_files,
  include_directories: [
    platform_inc,
    include_directories([
      'udis86'
    ])
  ],
  implicit_include_directories: false
)

ar_files = [
  'ar/ar.c'
]

libr2ar = static_library('libr2ar', ar_files,
  include_directories: [
    platform_inc,
    include_directories([
      'ar'
    ])
  ],
  implicit_include_directories: false
)

libr_shlr = [
  libr2ar, libr2bochs, libr2capstone, libr2gdb, libr2grub, libr2java, libr2lz4,
  libr2qnx, libr2sdb, libr2spp, libr2spp, libr2tcc, libr2udis86, libr2windbg,
  libr2zip
]
