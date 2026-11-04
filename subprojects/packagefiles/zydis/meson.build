project('zydis', 'c', version: '4.1.0', meson_version: '>=0.55.0')

cc = meson.get_compiler('c')

if cc.has_argument('--std=gnu99')
  add_project_arguments('--std=gnu99', language: ['c'])
elif cc.has_argument('--std=c99')
  add_project_arguments('--std=c99', language: ['c'])
endif

if cc.get_argument_syntax() == 'msvc'
  if get_option('b_lto')
    add_project_arguments(
      '/GL', # Compiler optimisation for MSVC
      language: 'c',
    )
    add_project_link_arguments(
      '/LTCG', # Used for Linking when compiling with /GL
      language: 'c',
    )
  endif
endif

zydis_c_args = []
zydis_dep_c_args = []

if get_option('default_library') == 'static'
  zydis_c_args += ['-DZYDIS_STATIC_BUILD']
else
  zydis_c_args += ['-DZYDIS_SHOULD_EXPORT']
endif
zydis_dep_c_args += ['-DUSE_SYS_ZYDIS=0', '-DZYDIS_STATIC_BUILD']

zydis_sources = [
  'amalgamated-dist/Zydis.c'
]

zydis_includes = include_directories('amalgamated-dist')

zydis_override_options = []
zydis_warn_args = []
if cc.get_argument_syntax() == 'msvc'
  # Disable warnings for this vendored source without overriding /W2 with
  # /W0 on the command line, which would warn D9025.
  zydis_override_options += ['warning_level=0']
elif cc.has_argument('-w')
  zydis_warn_args += ['-w']
endif

libzydis = library('zydis', zydis_sources,
  c_args: zydis_c_args + zydis_warn_args,
  override_options: zydis_override_options,
  include_directories: zydis_includes,
  install: false,
)

zydis_dep = declare_dependency(
  link_with: libzydis,
  include_directories: zydis_includes,
  compile_args: zydis_dep_c_args,
)
