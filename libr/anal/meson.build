subdir('d')

r_anal_sources = [
  'c2/kv.c',
  'anal.c',
  'anplugs.c',
  'bb.c',
  'block.c',
  'function.c',
  'jmptbl.c',
  'btrace.c',
  'cc.c',
  'class.c',
  'tid.c',
  'cond.c',
  'cparse.c',
  'codemeta.c',
  'cycles.c',
  'data.c',
  'diff.c',
  'esil_cfg.c',
  'esil_dfg.c',
  'fcn.c',
  'flirt.c',
  'global.c',
  'hint.c',
  'labels.c',
  'meta.c',
  'op.c',
  'pin.c',
  'reflines.c',
  'rtti.c',
  'rtti_msvc.c',
  'rtti_itanium.c',
  'sign.c',
  'switch.c',
  'type.c',
  'type_pdb.c',
  'dwarf_process.c',
  'value.c',
  'var.c',
  'vtable.c',
  'xrefs.c',
  'p/anal_null.c',
  'p/anal_sbpf.c',
  'p/anal_tcc.c',
  'p/anal_tp.c',
  'p/anal_a2f.c',
  'p/anal_blaze.c',
  'p/anal_path.c',
]

r_anal_sources += r_anal_d_sources

# tcc_sources are not used, because p/anal_tcc.c directly includes these .c files
tcc_sources = [
  'c/libtcc.c',
  'c/tccgen.c',
  'c/tccpp.c'
]

r_anal_inc = [ platform_inc ]

r_anal = library('r_anal', r_anal_sources,
  include_directories: r_anal_inc,
  c_args: library_cflags,
  dependencies: [
    r_util_dep,
    r_reg_dep,
    r_asm_dep,
    r_arch_dep,
    r_esil_dep,
    r_muta_dep,
    r_search_dep,
    r_cons_dep,
    r_syscall_dep,
    r_flag_dep,
    capstone_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_anal_dep = declare_dependency(link_with: r_anal,
  include_directories: r_anal_inc)

if get_option('blob')
r_anal_static = static_library('r_anal_static', r_anal_sources,
  include_directories: r_anal_inc,
  c_args: library_cflags,
  dependencies: [
    capstone_dep,
    java_static_dep,
    r_arch_static_dep,
    r_asm_static_dep,
    r_cons_static_dep,
    r_muta_static_dep,
    r_esil_static_dep,
    r_flag_static_dep,
    r_reg_static_dep,
    r_search_static_dep,
    r_syscall_static_dep,
    r_util_static_dep,
  ],
  install: true,
  implicit_include_directories: false,
)

r_anal_static_dep = declare_dependency(link_with: r_anal_static,
  include_directories: r_anal_inc)
endif

pkgconfig_mod.generate(r_anal,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_anal',
  filebase: 'r_anal',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'r_util',
    'r_reg',
    'r_asm',
    'r_muta',
    'r_syscall',
    'r_arch',
    'r_search',
    'r_cons',
    'r_flag'
  ],
  description: 'radare foundation libraries'
)
