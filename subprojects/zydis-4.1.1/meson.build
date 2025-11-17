project(
  'Zydis',
  'c',
  version: '4.1.1',
  license: 'MIT',
  license_files: 'LICENSE',
  meson_version: '>=1.3',
  default_options: [
    'c_std=c11',
    'warning_level=3',
  ],
)

datadir = get_option('datadir')

root = not meson.is_subproject()

minimal = get_option('minimal')
decoder = get_option('decoder')
formatter = get_option('formatter')
avx512 = get_option('avx512')
knc = get_option('knc')
segment = get_option('segment')
encoder = get_option('encoder')

examples = get_option('examples')
tools = get_option('tools')
man = get_option('man')
doc = get_option('doc')
tests = get_option('tests')

nolibc = get_option('nolibc')

# Auto feature set
encoder = encoder.enable_auto_if(
  minimal.disabled()
  and decoder.allowed()
  and avx512.allowed()
  and knc.allowed(),
)
decoder = decoder.enable_auto_if(encoder.enabled())

avx512 = avx512.enable_auto_if(encoder.enabled())
knc = knc.enable_auto_if(encoder.enabled())
segment = segment.enable_auto_if(decoder.enabled())

formatter = formatter.enable_auto_if(
  decoder.enabled(),
)

# Feature guards
minimal = minimal.disable_if(encoder.enabled())
decoder = decoder.enable_if(encoder.enabled() or formatter.enabled())
avx512 = avx512.enable_if(encoder.enabled())
knc = knc.enable_if(encoder.enabled())

# Extra targets
examples = examples.disable_if(nolibc)
tools = tools.disable_if(nolibc)
tests = tests.disable_if(nolibc)

examples = examples.disable_auto_if(not root).enable_auto_if(root)
tools = tools.disable_auto_if(not root).enable_auto_if(root)
tests = tests.disable_auto_if(not root)
man = man.disable_auto_if(not root)
doc = doc.disable_auto_if(not root)

cc = meson.get_compiler('c')

if cc.get_argument_syntax() == 'msvc'
  if get_option('b_lto')
    add_project_arguments(
      '/GL', # -flto
      language: 'c',
    )
    add_project_link_arguments(
      '/LTCG',
      language: 'c',
    )
  endif
elif nolibc
  add_project_arguments(
    '-fno-stack-protector',
    language: 'c',
  )
  add_project_link_arguments(
    '-nostdlib',
    '-nodefaultlibs',
    language: 'c',
  )
endif

if cc.get_linker_id() == 'ld.wasm'
  emflags = ['-sEXPORT_NAME="Zydis"', '-sMODULARIZE=1']
  add_project_link_arguments(
    emflags,
    language: 'c',
  )
endif

zycore_dep = dependency(
  'zycore',
  version: '>=1.5.0',
)

predef = []

if minimal.enabled()
  predef += 'ZYDIS_MINIMAL_MODE'
endif
if decoder.disabled()
  predef += 'ZYDIS_DISABLE_DECODER'
endif
if encoder.disabled()
  predef += 'ZYDIS_DISABLE_ENCODER'
endif
if formatter.disabled()
  predef += 'ZYDIS_DISABLE_FORMATTER'
endif
if avx512.disabled()
  predef += 'ZYDIS_DISABLE_AVX512'
endif
if knc.disabled()
  predef += 'ZYDIS_DISABLE_KNC'
endif
if segment.disabled()
  predef += 'ZYDIS_DISABLE_SEGMENT'
endif

foreach def : predef
  add_project_arguments(f'-D@def@', language: 'c')
endforeach

inc = include_directories('include')
inc_private = include_directories('src')

hdrs_common = files(
  'include/Zydis/Defines.h',
  'include/Zydis/MetaInfo.h',
  'include/Zydis/Mnemonic.h',
  'include/Zydis/Register.h',
  'include/Zydis/SharedTypes.h',
  'include/Zydis/ShortString.h',
  'include/Zydis/Status.h',
  'include/Zydis/Utils.h',
  'include/Zydis/Zydis.h',
)

hdrs_internal = files(
  'include/Zydis/Internal/SharedData.h',
  'include/Zydis/Internal/String.h',
)

src = files(
  'src/MetaInfo.c',
  'src/Mnemonic.c',
  'src/Register.c',
  'src/SharedData.c',
  'src/String.c',
  'src/Utils.c',
  'src/Zydis.c',
)

if decoder.enabled()
  hdrs_common += files(
    'include/Zydis/Decoder.h',
    'include/Zydis/DecoderTypes.h',
  )
  hdrs_internal += files(
    'include/Zydis/Internal/DecoderData.h',
  )
  src += files(
    'src/Decoder.c',
    'src/DecoderData.c',
  )
endif

if encoder.enabled()
  hdrs_common += files(
    'include/Zydis/Encoder.h',
  )
  hdrs_internal += files(
    'include/Zydis/Internal/EncoderData.h',
  )
  src += files(
    'src/Encoder.c',
    'src/EncoderData.c',
  )
endif

if formatter.enabled()
  hdrs_common += files(
    'include/Zydis/Disassembler.h',
    'include/Zydis/Formatter.h',
    'include/Zydis/FormatterBuffer.h',
  )
  hdrs_internal += files(
    'include/Zydis/Internal/FormatterATT.h',
    'include/Zydis/Internal/FormatterBase.h',
    'include/Zydis/Internal/FormatterIntel.h',
  )
  src += files(
    'src/Disassembler.c',
    'src/Formatter.c',
    'src/FormatterATT.c',
    'src/FormatterBase.c',
    'src/FormatterBuffer.c',
    'src/FormatterIntel.c',
  )
endif

if segment.enabled()
  hdrs_common += files(
    'include/Zydis/Segment.h',
  )
  src += files(
    'src/Segment.c',
  )
endif

hdrs = hdrs_common + hdrs_internal

if host_machine.system() == 'windows'
  windows = import('windows')
  src += windows.compile_resources('resources/VersionInfo.rc')
endif

zydis_lib = library(
  'Zydis',
  src + hdrs,
  c_static_args: ['-DZYDIS_STATIC_BUILD'],
  c_shared_args: ['-DZYDIS_SHOULD_EXPORT'],
  include_directories: [inc, inc_private],
  implicit_include_directories: false,
  dependencies: [zycore_dep],
  version: meson.project_version(),
  install: true,
)

install_headers(hdrs_common, subdir: 'Zydis')
install_headers(hdrs_internal, subdir: 'Zydis/Internal')

# Note: on MSVC, define ZYDIS_STATIC_BUILD and ZYCORE_STATIC_BUILD accordingly
# in the user project.
zydis_dep = declare_dependency(
  include_directories: inc,
  link_with: zydis_lib,
  dependencies: [zycore_dep],
)

pkg = import('pkgconfig')
pkg.generate(
  zydis_lib,
  name: 'zydis',
  description: 'Zyan Disassembler Library',
  url: 'https://github.com/zyantific/zydis',
)

meson.override_dependency('zydis', zydis_dep)

subdir('examples')
subdir('tools')
subdir('tests')

doxygen_exe = find_program('doxygen', required: doc)
doc_req = doxygen_exe.found()
if doc_req
  cdata = configuration_data()
  cdata.set('VERSION', meson.project_version())
  cdata.set('TOP_SRCDIR', meson.project_source_root())
  cdata.set('TOP_BUILDDIR', meson.project_build_root())

  dot_exe = find_program('dot', required: false)
  if dot_exe.found()
    cdata.set('HAVE_DOT', 'YES')
    cdata.set('DOT_PATH', dot_exe.full_path())
    cdata.set(
      'HAVE_DOT_1_8_10',
      dot_exe.version().version_compare('>=1.8.10') ? 'YES' : 'NO',
    )
  else
    cdata.set('HAVE_DOT', 'NO')
  endif

  if find_program('pdf2svg', required: false).found() or find_program('inkscape', required: false).found()
    cdata.set('HTML_FORMULA_FORMAT', 'svg')
  else
    cdata.set('HTML_FORMULA_FORMAT', 'png')
  endif

  cdata.set('PREDEFINED', ' '.join(predef))
  cdata.set(
    'ZYCORE_INCLUDE_PATH',
    # We don't care if the directory exists or not
    meson.project_source_root() / 'subprojects/zycore/include',
  )

  doxyfile = configure_file(
    input: 'Doxyfile.meson.in',
    output: 'Doxyfile',
    configuration: cdata,
    install: false,
  )

  custom_target(
    'ZydisDoc',
    input: doxyfile,
    output: 'doc',
    command: [doxygen_exe, doxyfile],
    depend_files: [hdrs, files('Doxyfile')],
    install: true,
    install_dir: datadir / 'doc' / 'Zydis',
  )

  summary(
    {
      'dot': cdata.get('HAVE_DOT') == 'YES',
      'formula format': cdata.get('HTML_FORMULA_FORMAT'),
    },
    section: 'Doxygen',
  )
endif

subdir('man')

summary(
  {
    'doc': doc_req,
    'nolibc': nolibc,
    'minimal': minimal,
    'decoder': decoder,
    'formatter': formatter,
    'avx512': avx512,
    'knc': knc,
    'segment': segment,
    'encoder': encoder,
  },
  section: 'Features',
)
