subdir('p')

files = [
  'anal.c',
  'anal_ex.c',
  'bb.c',
  'cc.c',
  'cond.c',
  'cycles.c',
  'data.c',
  'diff.c',
  'esil.c',
  'esil2reil.c',
  'esil_stats.c',
  'esil_trace.c',
  'fcn.c',
  'flirt.c',
  'hint.c',
  'labels.c',
  'meta.c',
  'op.c',
  'pin.c',
  'reflines.c',
  'rtti.c',
  'rtti_msvc.c',
  'rtti_itanium.c',
  'session.c',
  'sign.c',
  'state.c',
  'switch.c',
  'types.c',
  'value.c',
  'var.c',
  'vtable.c',
  'xrefs.c',
]

r_anal = library('r_anal', files,
  include_directories: [
    platform_inc,
    include_directories(
      'arch',
      '../asm/arch/include',
      '../../shlr'
    )
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    r_util,
    r_reg,
    r_asm,
    r_syscall,
    r_search,
    r_cons,
    r_flag,
    r_anal_plugins,
    libr_shlr
  ],
  install: true,
  implicit_include_directories: false,
  soversion: r2_libversion
)

pkgconfig_mod.generate(
  libraries: [r_anal],
  subdirs: 'libr',
  version: r2_version,
  name: 'r_anal',
  filebase: 'r_anal',
  requires: [
    'r_util',
    'r_reg',
    'r_asm',
    'r_syscall',
    'r_search',
    'r_cons',
    'r_flag'
  ],
  description: 'radare foundation libraries'
)
