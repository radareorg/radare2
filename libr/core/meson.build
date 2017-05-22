files=[
'anal_tp.c',
#'anal_vt.c',
'asm.c',
'p/core_anal.c',
'blaze.c',
'canal.c',
'cbin.c',
'cconfig.c',
'cio.c',
'cmd.c',
#'cmd_anal.c',
'cmd_api.c',
#'cmd_cmp.c',
#'cmd_debug.c',
#'cmd_egg.c',
#'cmd_eval.c',
#'cmd_flag.c',
#'cmd_hash.c',
#'cmd_help.c',
#'cmd_info.c',
#'cmd_log.c',
'cmd_macro.c',
'cmd_magic.c',
#'cmd_meta.c',
#'cmd_mount.c',
#'cmd_open.c',
#'cmd_print.c',
#'cmd_project.c',
#'cmd_quit.c',
#'cmd_search.c',
#'cmd_search_rop.c',
#'cmd_section.c',
#'cmd_seek.c',
#'cmd_type.c',
#'cmd_write.c',
#'cmd_zign.c',
'core.c',
'disasm.c',
'file.c',
'gdiff.c',
'graph.c',
'hack.c',
'help.c',
'libs.c',
#'linux_heap_glibc.c',
'log.c',
'panels.c',
'patch.c',
'plugin.c',
'project.c',
'pseudo.c',
'rtr.c',
'task.c',
'vasm.c',
'visual.c',
'vmarks.c',
'vmenus.c',
'yank.c'
]

gdbr_files=[
  '../../shlr/gdb/src/arch.c',
  '../../shlr/gdb/src/common.c',
  '../../shlr/gdb/src/libgdbr.c',
  '../../shlr/gdb/src/packet.c',
  '../../shlr/gdb/src/utils.c',
  '../../shlr/gdb/src/gdbclient/core.c',
  '../../shlr/gdb/src/gdbclient/responses.c',
  '../../shlr/gdb/src/gdbserver/core.c'
]

gdbr = static_library('gdbr', gdbr_files,
  include_directories: include_directories([
  '../../shlr/gdb/include',
  '../../libr/include',
  platform_librinc
  ]))

r_core = shared_library('r_core', files,
  include_directories: include_directories([
  '../include','../../shlr',
  platform_librinc
  ]),
  c_args: ['-DCORELIB'],
  link_with: [r_util, r_reg, r_syscall, r_search, r_cons, r_anal, r_socket, r_io, r_fs, r_lang, r_hash, r_flag, r_parse, r_egg, r_debug, r_magic, r_crypto, r_config, r_bin],
  objects: [
    r_sdb.extract_all_objects(),
	spp.extract_all_objects(),
	gdbr.extract_all_objects()
  ],
  install: true
)
