project('radare2', 'c', meson_version: '>=0.46.0')

py3_exe = import('python3').find_python()
git_exe = find_program('git', required: false)
pkgconfig_mod = import('pkgconfig')
glob_cmd = [py3_exe, '-c', 'from sys import argv; print(";".join(__import__("glob").glob(argv[1])))']

# Get r2 version
r2_version = run_command(py3_exe, 'sys/version.py')
if r2_version.returncode() != 0
  r2_version = 'unknown-error'
else
  r2_version = r2_version.stdout().strip()
endif

repo = '.'
if meson.is_subproject()
  repo = meson.current_source_dir()
  if host_machine.system() == 'windows'
    py_cmd = 'print(__import__("os").readlink(r"@0@"))'.format(repo)
    py_cmd = run_command(py3_exe, '-c', py_cmd)
    if py_cmd.returncode() == 0
      repo = py_cmd.stdout().strip()
      message('r2 real path: ' + repo)
    endif
  endif
endif

version_commit = ''
gittap = ''
gittip = 'unknown'

if git_exe.found()
  # Get version_commit
  git_rev_list = run_command(git_exe, '-C', repo, 'rev-list', '--all', '--count')
  if git_rev_list.returncode() == 0
    version_commit = git_rev_list.stdout().strip()
  endif

  # Get gittap
  git_describe = run_command(git_exe, '-C', repo, 'describe', '--tags', '--match', '[0-9]*')
  if git_describe.returncode() == 0
    gittap = git_describe.stdout().strip()
  endif

  # Get gittip
  git_rev_parse = run_command(git_exe, '-C', repo, 'rev-parse', 'HEAD')
  if git_rev_parse.returncode() == 0
    gittip = git_rev_parse.stdout().strip()
  endif
endif

if get_option('r2_version_commit') != ''
  version_commit = get_option('r2_version_commit')
endif

if get_option('r2_gittap') != ''
  gittap = get_option('r2_gittap')
endif

if get_option('r2_gittip') != ''
  gittip = get_option('r2_gittip')
endif

# Get current date
if host_machine.system() == 'windows'
  r2birth = run_command('cmd', '/c', 'echo %date%__%time%')
else
  r2birth = run_command('date', '+%Y-%m-%d__%H:%M:%S')
endif
if r2birth.returncode() != 0
  r2birth = ''
else
  r2birth = r2birth.stdout().strip()
endif

r2_libversion = host_machine.system() == 'windows' ? '' : r2_version

# system dependencies
cc = meson.get_compiler('c')
# required for linux
ldl = cc.find_library('dl', required: false)
pth = cc.find_library('pthread', required: false)
utl = cc.find_library('util', required: false)
mth = cc.find_library('m', required: false)

platform_deps = []
platform_inc = ['.', 'libr/include']
if host_machine.system() == 'windows'
  platform_deps = [cc.find_library('ws2_32')]
  platform_inc += ['libr/include/msvc']
endif
platform_inc = include_directories(platform_inc)

if get_option('static_runtime')
  if cc.get_id() == 'msvc'
    add_project_arguments('/MT', language: 'c')
  endif
endif

if host_machine.system() == 'windows'
  r2_prefix = '.'
  r2_libdir = 'lib'
  r2_incdir = 'include'
  r2_datdir = 'share'

  opts1 = [
    'r2_libdir',
    'r2_incdir',
    'r2_datdir'
  ]
  foreach opt : opts1
    val = get_option(opt)
    if val != ''
      set_variable(opt, val)
    endif
  endforeach

  r2_wwwroot = join_paths(r2_datdir, 'www')
  r2_sdb = join_paths(r2_datdir)
  r2_zigns = join_paths(r2_datdir, 'zigns')
  r2_themes = join_paths(r2_datdir, 'cons')
  r2_fortunes = join_paths(r2_datdir, 'doc')
  r2_flags = join_paths(r2_datdir, 'flag')
  r2_hud = join_paths(r2_datdir, 'hud')

  opts2 = [
    'r2_wwwroot',
    'r2_sdb',
    'r2_zigns',
    'r2_themes',
    'r2_fortunes',
    'r2_flags',
    'r2_hud'
  ]
  foreach opt : opts2
    val = get_option(opt)
    if val != ''
      set_variable(opt, val)
    endif
  endforeach

  opts3 = [
    'r2_plugins',
    'r2_extras',
    'r2_bindings'
  ]
  r2_plugins = join_paths(r2_libdir, 'plugins')
  r2_extras = join_paths(r2_libdir, 'extras')
  r2_bindings = join_paths(r2_libdir, 'bindings')

  foreach opt : opts1 + opts2 + opts3
    val = get_variable(opt)
    val = '\\\\'.join(val.split('/'))
    set_variable(opt, val)
  endforeach
else
  r2_prefix = get_option('prefix')
  r2_libdir = join_paths(r2_prefix, get_option('libdir'))
  r2_incdir = join_paths(r2_prefix, get_option('includedir'), 'libr')
  r2_datdir = join_paths(r2_prefix, get_option('datadir'))
  r2_wwwroot = join_paths(r2_datdir, 'radare2', r2_version, 'www')
  r2_sdb = join_paths(get_option('datadir'), 'radare2', r2_version)
  r2_zigns = join_paths(get_option('datadir'), 'radare2', r2_version, 'zigns')
  r2_themes = join_paths(get_option('datadir'), 'radare2', r2_version, 'cons')
  r2_fortunes = join_paths(get_option('datadir'), 'doc/radare2')
  r2_flags = join_paths(get_option('datadir'), 'radare2', r2_version, 'flag')
  r2_hud = join_paths(get_option('datadir'), 'radare2', r2_version, 'hud')
  r2_plugins = join_paths(get_option('libdir'), 'radare2', r2_version)
  r2_extras = join_paths(get_option('libdir'), 'radare2-extras', r2_version)
  r2_bindings = join_paths(get_option('libdir'), 'radare2-bindings', r2_version)
endif

# load plugin configuration
subdir('libr')

conf_data = configuration_data()
conf_data.set('plugins_core', '&r_core_plugin_' + ', &r_core_plugin_'.join(core_plugins) + ', 0')
conf_data.set('plugins_anal', '&r_anal_plugin_' + ', &r_anal_plugin_'.join(anal_plugins) + ', 0')
conf_data.set('plugins_asm', '&r_asm_plugin_' + ', &r_asm_plugin_'.join(asm_plugins) + ', 0')
conf_data.set('plugins_bp', '&r_bp_plugin_' + ', &r_bp_plugin_'.join(bp_plugins) + ', 0')
conf_data.set('plugins_bin', '&r_bin_plugin_' + ', &r_bin_plugin_'.join(bin_plugins) + ', 0')
conf_data.set('plugins_bin_ldr', '&r_bin_ldr_plugin_' + ', &r_bin_ldr_plugin_'.join(bin_ldr_plugins) + ', 0')
conf_data.set('plugins_bin_xtr', '&r_bin_xtr_plugin_' + ', &r_bin_xtr_plugin_'.join(bin_xtr_plugins) + ', 0')
conf_data.set('plugins_crypto', '&r_crypto_plugin_' + ', &r_crypto_plugin_'.join(crypto_plugins) + ', 0')
conf_data.set('plugins_io', '&r_io_plugin_' + ', &r_io_plugin_'.join(io_plugins) + ', 0')
conf_data.set('plugins_fs', '&r_fs_plugin_' + ', &r_fs_plugin_'.join(fs_plugins) + ', 0')
conf_data.set('plugins_debug', '&r_debug_plugin_' + ', &r_debug_plugin_'.join(debug_plugins) + ', 0')
conf_data.set('plugins_egg', '&r_egg_plugin_' + ', &r_egg_plugin_'.join(egg_plugins) + ', 0')
conf_data.set('plugins_lang', '&r_lang_plugin_' + ', &r_lang_plugin_'.join(lang_plugins) + ', 0')
conf_data.set('plugins_parse', '&r_parse_plugin_' + ', &r_parse_plugin_'.join(parse_plugins) + ', 0')
config_h = configure_file(
  input: 'libr/config.h.in',
  output: 'config.h',
  configuration: conf_data
)

userconf = configuration_data()
userconf.set('DEBUGGER', 1)
userconf.set('PREFIX', r2_prefix)
userconf.set('LIBDIR', r2_libdir)
userconf.set('INCLUDEDIR', r2_incdir)
userconf.set('DATADIR', r2_datdir)
userconf.set('WWWROOT', r2_wwwroot)
userconf.set('SDB', r2_sdb)
userconf.set('ZIGNS', r2_zigns)
userconf.set('THEMES', r2_themes)
userconf.set('FORTUNES', r2_fortunes)
userconf.set('FLAGS', r2_flags)
userconf.set('HUD', r2_hud)
userconf.set('PLUGINS', r2_plugins)
userconf.set('EXTRAS', r2_extras)
userconf.set('BINDINGS', r2_bindings)
userconf.set('HAVE_LIB_MAGIC', 0)
userconf.set('USE_LIB_MAGIC', 0)
userconf.set('HAVE_OPENSSL', 0)
userconf.set('HAVE_FORK', 1)
userconf.set('WITH_GPL', 1)
if host_machine.system() == 'windows'
  userconf.set('HAVE_JEMALLOC', 0)
else
  userconf.set('HAVE_JEMALLOC', 1)
endif
if cc.has_header_symbol('sys/personality.h', 'ADDR_NO_RANDOMIZE')
  userconf.set('HAVE_DECL_ADDR_NO_RANDOMIZE', 1)
else
  userconf.set('HAVE_DECL_ADDR_NO_RANDOMIZE', 0)
endif
r_userconf_h = configure_file(
  input: 'libr/include/r_userconf.h.in',
  output: 'r_userconf.h',
  configuration: userconf,
  install_dir: join_paths(get_option('includedir'), 'libr')
)

versionconf = configuration_data()
versionconf.set('VERSIONCOMMIT', version_commit)
versionconf.set('R2_VERSION', r2_version)
versionconf.set('R2_GITTAP', gittap)
versionconf.set('R2_GITTIP', gittip)
versionconf.set('R2_BIRTH', r2birth)
r_version_h = configure_file(
  input: 'libr/include/r_version.h.in',
  output: 'r_version.h',
  configuration: versionconf,
  install_dir: join_paths(get_option('includedir'), 'libr')
)

# Copy missing header
run_command(py3_exe, '-c', '__import__("shutil").copyfile("shlr/spp/config.def.h", "shlr/spp/config.h")')

pcconf = configuration_data()
pcconf.set('PREFIX', get_option('prefix'))
pcconf.set('LIBDIR', join_paths(get_option('prefix'), get_option('libdir')))
pcconf.set('VERSION', r2_version)
libr_pc = configure_file(
  input: 'libr/libr.pc.acr',
  output: 'libr.pc',
  configuration: userconf,
  install_dir: join_paths(get_option('libdir'), 'pkgconfig')
)

subdir('shlr')

subdir('libr/util')
subdir('libr/hash')
subdir('libr/crypto')
subdir('libr/socket')
subdir('libr/io')
subdir('libr/bp')
subdir('libr/syscall')
subdir('libr/cons')
subdir('libr/search')
subdir('libr/magic')
subdir('libr/flag')
subdir('libr/reg')
subdir('libr/bin')
subdir('libr/config')
subdir('libr/parse')
subdir('libr/lang')
subdir('libr/asm')
subdir('libr/anal')
subdir('libr/egg')
subdir('libr/fs')
subdir('libr/debug')
subdir('libr/core')

subdir('shlr/sdb')

subdir('libr/anal/d')
subdir('libr/asm/d')
subdir('libr/bin/d')
subdir('libr/syscall/d')
subdir('libr/cons/d')
subdir('libr/magic/d')
subdir('libr/flag/d')

if not meson.is_subproject()
  subdir('binr/rahash2')
  subdir('binr/rarun2')
  subdir('binr/rasm2')
  subdir('binr/rabin2')
  subdir('binr/radare2')
  subdir('binr/ragg2')
  subdir('binr/r2agent')
  subdir('binr/radiff2')
  subdir('binr/rafind2')
  subdir('binr/rax2')
else
  libr2_dep = declare_dependency(
    link_with: [
      r_anal,
      r_asm,
      r_bin,
      r_bp,
      r_config,
      r_cons,
      r_core,
      r_crypto,
      r_egg,
      r_flag,
      r_fs,
      r_hash,
      r_io,
      r_lang,
      r_magic,
      r_parse,
      r_reg,
      r_search,
      r_socket,
      r_syscall,
      r_util
    ],
    include_directories: include_directories('.', 'libr/include'),
    version: r2_version
  )
endif

install_subdir('shlr/www',
  install_dir: r2_wwwroot,
  strip_directory: true
)

fortunes_files = run_command(glob_cmd + ['doc/fortunes.*']).stdout().strip().split(';')
install_data(fortunes_files,
  install_dir: r2_fortunes
)

man1_files = run_command(glob_cmd + ['man/*.1']).stdout().strip().split(';')
install_data(man1_files,
  install_dir: join_paths(get_option('mandir'), 'man1')
)

man7_files = run_command(glob_cmd + ['man/*.7']).stdout().strip().split(';')
install_data(man7_files,
  install_dir: join_paths(get_option('mandir'), 'man7')
)

install_data('doc/hud',
  install_dir: r2_hud,
  rename: 'main'
)
