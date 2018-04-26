project('radare2', 'c', meson_version: '>=0.46.0')

py3_exe = import('python3').find_python()
git_exe = find_program('git')
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

# Get version_commit
version_commit = run_command(git_exe, '-C', repo, 'rev-list', '--all', '--count')
if version_commit.returncode() != 0
  version_commit = 0
else
  version_commit = version_commit.stdout().strip()
endif

# Get gittap
gittap  = run_command(git_exe, '-C', repo, 'describe', '--tags', '--match', '[0-9]*')
if gittap.returncode() != 0
  gittap = ''
else
  gittap = gittap.stdout().strip()
endif

# Get gittip
gittip  = run_command(git_exe, '-C', repo, 'rev-parse', 'HEAD')
if gittip.returncode() != 0
  gittip = 'unknown'
else
  gittip = gittip.stdout().strip()
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
  r2_libdir = get_option('r2_libdir')
  if r2_libdir == ''
    r2_libdir = 'lib'
  endif
  r2_incdir = get_option('r2_incdir')
  if r2_incdir == ''
    r2_incdir = 'include/libr'
  endif
  r2_datdir = get_option('r2_datdir')
  if r2_datdir == ''
    r2_datdir = 'share'
  endif
  r2_wwwroot = get_option('r2_wwwroot')
  if r2_wwwroot == ''
    r2_wwwroot = join_paths(r2_datdir, 'radare2', r2_version, 'www')
  endif
  r2_sdbdir = get_option('r2_sdbdir')
  if r2_sdbdir == ''
    r2_sdbdir = join_paths(r2_datdir, 'radare2', r2_version)
  endif
  r2_zignsdir = get_option('r2_zignsdir')
  if r2_zignsdir == ''
    r2_zignsdir = join_paths(r2_datdir, 'radare2', r2_version, 'zigns')
  endif
  r2_themesdir = get_option('r2_themesdir')
  if r2_themesdir == ''
    r2_themesdir = join_paths(r2_datdir, 'radare2', r2_version, 'cons')
  endif
  r2_fortunesdir = get_option('r2_fortunesdir')
  if r2_fortunesdir == ''
    r2_fortunesdir = join_paths(r2_datdir, 'doc/radare2')
  endif
  r2_huddir = get_option('r2_huddir')
  if r2_huddir == ''
    r2_huddir = join_paths(r2_datdir, 'radare2', r2_version, 'hud')
  endif
else
  r2_prefix = get_option('prefix')
  r2_libdir = join_paths(r2_prefix, get_option('libdir'))
  r2_incdir = join_paths(r2_prefix, get_option('includedir'), 'libr')
  r2_datdir = join_paths(r2_prefix, get_option('datadir'))
  r2_wwwroot = join_paths(r2_datdir, 'radare2', r2_version, 'www')
  r2_sdbdir = join_paths(get_option('datadir'), 'radare2', r2_version)
  r2_zignsdir = join_paths(get_option('datadir'), 'radare2', r2_version, 'zigns')
  r2_themesdir = join_paths(get_option('datadir'), 'radare2', r2_version, 'cons')
  r2_fortunesdir = join_paths(get_option('datadir'), 'doc/radare2')
  r2_huddir = join_paths(get_option('datadir'), 'radare2', r2_version, 'hud')
endif

# load plugin configuration
subdir('libr')

conf_data = configuration_data()
conf_data.set('plugins_core', '&r_core_plugin_' + ',&r_core_plugin_'.join(core) + ', 0')
conf_data.set('plugins_anal', '&r_anal_plugin_' + ',&r_anal_plugin_'.join(anal) + ', 0')
conf_data.set('plugins_asm', '&r_asm_plugin_' + ',&r_asm_plugin_'.join(asm) + ', 0')
conf_data.set('plugins_bp', '&r_bp_plugin_' + ',&r_bp_plugin_'.join(bp) + ', 0')
conf_data.set('plugins_bin', '&r_bin_plugin_' + ',&r_bin_plugin_'.join(bin) + ', 0')
conf_data.set('plugins_crypto', '&r_crypto_plugin_' + ',&r_crypto_plugin_'.join(crypto) + ', 0')
conf_data.set('plugins_io', '&r_io_plugin_' + ',&r_io_plugin_'.join(io) + ', 0')
conf_data.set('plugins_fs', '&r_fs_plugin_' + ',&r_fs_plugin_'.join(fs) + ', 0')
conf_data.set('plugins_debug', '&r_debug_plugin_' + ',&r_debug_plugin_'.join(debug) + ', 0')
conf_data.set('plugins_egg', '&r_egg_plugin_' + ',&r_egg_plugin_'.join(egg) + ', 0')
conf_data.set('plugins_lang', '&r_lang_plugin_' + ',&r_lang_plugin_'.join(lang) + ', 0')
conf_data.set('plugins_parse', '&r_parse_plugin_' + ',&r_parse_plugin_'.join(parse) + ', 0')
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
userconf.set('SDBDIR', r2_sdbdir)
userconf.set('ZIGNSDIR', r2_zignsdir)
userconf.set('THEMESDIR', r2_themesdir)
userconf.set('FORTUNESDIR', r2_fortunesdir)
userconf.set('HUDDIR', r2_huddir)
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
  libr2_lib = [
    r_anal, r_asm, r_bin, r_bp, r_config, r_cons, r_core, r_crypto, r_egg,
    r_flag, r_fs, r_hash, r_io, r_lang, r_magic, r_parse, r_reg, r_search,
    r_socket, r_syscall, r_util
  ]
  libr2_inc = include_directories(['.', 'libr/include'])
  libr2_dep = declare_dependency(
    link_with: libr2_lib,
    include_directories: libr2_inc,
    version: r2_version
  )
endif

install_subdir('shlr/www',
  install_dir: join_paths(get_option('prefix'), get_option('datadir'), 'radare2', r2_version)
)

fortunes_files = run_command(glob_cmd + ['doc/fortunes.*']).stdout().strip().split(';')
install_data(fortunes_files,
  install_dir: join_paths(get_option('datadir'), 'doc/radare2')
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
  install_dir: join_paths(get_option('datadir'), 'radare2', r2_version, 'hud'),
  rename: 'main'
)
