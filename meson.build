project('radare2', 'c', license : 'LGPL3', meson_version : '>=0.50', version : '5.9.9')

# Global Arguments First

# system dependencies
cc = meson.get_compiler('c')

if get_option('wasan')
  add_global_arguments('/DEBUG', language: 'c')
  add_global_arguments('/MD', language: 'c')
  add_global_arguments('/fsanitize=address', language: 'c')
  # add_global_arguments('/Zi', language: 'c') # generate .pdb iirc
  # add_global_arguments('/Z7', language: 'c') # generate .symbols instead of .pdb
  # add_global_arguments('/guard:cf', language: 'c')
endif

if cc.get_id() == 'msvc'
  # add_project_arguments('/Zc:preprocessor', language: 'c')
  if get_option('static_runtime')
    add_global_arguments('/MT', language: 'c')
  endif
endif

if cc.get_id() == 'clang-cl'
  add_global_arguments('-D__STDC__=1', language: 'c')
  add_global_arguments('-D_CRT_DECLARE_NONSTDC_NAMES ', language: 'c')
  add_global_arguments('-D_CRT_SECURE_NO_WARNINGS', language: 'c')
  add_global_arguments('-D_CRT_NONSTDC_NO_DEPRECATE', language: 'c')
endif

if get_option('default_library') == 'shared'
  if host_machine.system() != 'windows' or cc.get_id() != 'msvc' and cc.get_id() != 'clang-cl'
    add_global_arguments('-fvisibility=hidden', language: 'c')
  endif
endif

py3_exe = import('python').find_installation('python3')
gen_py = '@0@/libr/syscall/d/gen.py'.format(meson.current_source_dir())
git_exe = find_program('git', required: false)
pkgconfig_mod = import('pkgconfig')

# Get r2 version
r2_version = meson.project_version()
vers = r2_version.split('.')
r2_version_major = vers[0].to_int()
r2_version_minor = vers[1].to_int()
r2_version_patch = vers[2].split('-')[0].to_int()
r2_version_number = (r2_version_major * 10000) + (r2_version_minor * 100) + (r2_version_patch)

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

# by default, not version commit is used
version_commit = '0'

gittap = ''
gittip = 'unknown'

if git_exe.found()
  # Get version_commit
  git_rev_list = run_command(git_exe, '-C', repo, 'rev-list', '--all', '--count')
  if git_rev_list.returncode() == 0
    version_commit = git_rev_list.stdout().strip()
  endif
  if version_commit == ''
    version_commit = '0'
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
# gittap is used for the version of each r_ library
# in case it has not been set (e.g. a release tarball) set it
if gittap == ''
  gittap = r2_version
endif

if get_option('r2_gittip') != ''
  gittip = get_option('r2_gittip')
endif

if gittip == ''
  gittip = r2_version
endif

# Get current date
if host_machine.system() == 'windows'
  r2birth = run_command('cmd', '/c', 'echo %date%__%time%')
else
  r2birth = run_command('sh', '-c', '''
      SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-`date +%s`}";
      FORMAT="+%Y-%m-%d__%H:%M:%S";
      date -u -d @"$SOURCE_DATE_EPOCH" "$FORMAT" 2>/dev/null ||
      date -u -r  "$SOURCE_DATE_EPOCH" "$FORMAT" 2>/dev/null ||
      date -u "$FORMAT"''')
endif
if r2birth.returncode() != 0
  r2birth = ''
else
  r2birth = r2birth.stdout().strip()
endif

r2_libversion = host_machine.system() == 'windows' ? '' : r2_version
message('r2 lib version: ' + r2_libversion)

# required for linux
ldl = cc.find_library('dl', required: false)
pth = dependency('threads', required: false)
utl = cc.find_library('util', required: false)
if host_machine.system() == 'sunos'
  # workaround for Solaris until https://github.com/mesonbuild/meson/issues/4328 is fixed
  mth = declare_dependency(link_args: '-lm')
else
  mth = cc.find_library('m', required: false)
endif

platform_deps = []
platform_inc = ['.', 'libr/include']
if host_machine.system() == 'windows'
  platform_deps = [cc.find_library('ws2_32'), cc.find_library('wininet'), cc.find_library('psapi')]
endif
platform_inc = include_directories(platform_inc)


if get_option('threadsafety')
  r2_critical_enabled = 1
else
  r2_critical_enabled = 0
endif

library_cflags = ['-DR2_PLUGIN_INCORE=1']

if host_machine.system() == 'windows'
  r2_prefix = '.'
  r2_libdir = 'lib'
  r2_incdir = 'include/libr'
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
  r2_scripts = join_paths(r2_datdir, 'scripts')
  r2_themes = join_paths(r2_datdir, 'cons')
  r2_panels = join_paths(r2_datdir, 'panels')
  r2_platform = join_paths(r2_datdir, 'platform')
  r2_fortunes = join_paths(r2_datdir, 'doc')
  r2_flags = join_paths(r2_datdir, 'flag')
  r2_hud = join_paths(r2_datdir, 'hud')

  opts2 = [
    'r2_wwwroot',
    'r2_sdb',
    'r2_platform',
    'r2_zigns',
    'r2_themes',
    'r2_panels',
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
  r2_libdir = get_option('libdir')
  r2_incdir = join_paths(get_option('includedir'), 'libr')
  r2_datdir = get_option('datadir')
  r2_datdir_r2 = join_paths(r2_datdir, 'radare2')
  r2_wwwroot = join_paths(r2_datdir_r2, r2_version, 'www')
  r2_sdb = join_paths(r2_datdir_r2, r2_version)
  r2_scripts = join_paths(r2_datdir_r2, r2_version, 'scripts')
  r2_zigns = join_paths(r2_datdir_r2, r2_version, 'zigns')
  r2_platform = join_paths(r2_datdir_r2, r2_version, 'platform')
  r2_themes = join_paths(r2_datdir_r2, r2_version, 'cons')
  r2_panels = join_paths(r2_datdir_r2, r2_version, 'panels')
  r2_fortunes = join_paths(r2_datdir, 'doc', 'radare2')
  r2_flags = join_paths(r2_datdir_r2, r2_version, 'flag')
  r2_hud = join_paths(r2_datdir_r2, r2_version, 'hud')
  r2_plugins = join_paths(r2_libdir, 'radare2', r2_version)
  r2_extras = join_paths(r2_libdir, 'radare2-extras', r2_version)
  r2_bindings = join_paths(r2_libdir, 'radare2-bindings', r2_version)
endif

if host_machine.system() == 'aix'
  library_cflags += ['-D_LINUX_SOURCE_COMPAT']
endif

r2_zsh_compdir = join_paths(r2_datdir, 'zsh', 'site-functions')

# load plugin configuration
subdir('libr')

conf_data = configuration_data()
conf_data.set('plugins_core', '&r_core_plugin_' + ', &r_core_plugin_'.join(core_plugins) + ', 0')
conf_data.set('plugins_esil', '&r_esil_plugin_' + ', &r_esil_plugin_'.join(esil_plugins) + ', 0')
conf_data.set('plugins_anal', '&r_anal_plugin_' + ', &r_anal_plugin_'.join(anal_plugins) + ', 0')
conf_data.set('plugins_arch', '&r_arch_plugin_' + ', &r_arch_plugin_'.join(arch_plugins) + ', 0')
conf_data.set('plugins_asm', '&r_asm_plugin_' + ', &r_asm_plugin_'.join(asm_plugins) + ', 0')
conf_data.set('plugins_bp', '&r_bp_plugin_' + ', &r_bp_plugin_'.join(bp_plugins) + ', 0')
conf_data.set('plugins_bin', '&r_bin_plugin_' + ', &r_bin_plugin_'.join(bin_plugins) + ', 0')
conf_data.set('plugins_bin_ldr', '&r_bin_ldr_plugin_' + ', &r_bin_ldr_plugin_'.join(bin_ldr_plugins) + ', 0')
conf_data.set('plugins_bin_xtr', '&r_bin_xtr_plugin_' + ', &r_bin_xtr_plugin_'.join(bin_xtr_plugins) + ', 0')
conf_data.set('plugins_muta', '&r_muta_plugin_' + ', &r_muta_plugin_'.join(muta_plugins) + ', 0')
conf_data.set('plugins_io', '&r_io_plugin_' + ', &r_io_plugin_'.join(io_plugins) + ', 0')
conf_data.set('plugins_fs', '&r_fs_plugin_' + ', &r_fs_plugin_'.join(fs_plugins) + ', 0')
conf_data.set('plugins_debug', '&r_debug_plugin_' + ', &r_debug_plugin_'.join(debug_plugins) + ', 0')
conf_data.set('plugins_egg', '&r_egg_plugin_' + ', &r_egg_plugin_'.join(egg_plugins) + ', 0')
conf_data.set('plugins_lang', '&r_lang_plugin_' + ', &r_lang_plugin_'.join(lang_plugins) + ', 0')
conf_data.set('WANT_THREADS', get_option('want_threads')? '1': '0')
conf_data.set('WANT_QJS', get_option('want_qjs')? '1': '0')
conf_data.set('WANT_V35', get_option('use_v35')? '1': '0')

config_h = configure_file(
  input: 'libr/config.h.in',
  output: 'config.h',
  configuration: conf_data
)

# handle magic library
sys_magic = cc.find_library('magic', required: false)
use_syslib_magic = false

if sys_magic.found() and get_option('use_sys_magic')
  use_syslib_magic = true
endif

# handle xxhash library
sys_xxhash = dependency('libxxhash', required: false)
use_sys_xxhash = false
if not sys_xxhash.found()
  sys_xxhash = dependency('xxhash', required: false)
endif
if not sys_xxhash.found()
  sys_xxhash = cc.find_library('xxhash', required: false)
endif

if sys_xxhash.found() and get_option('use_sys_xxhash')
  message('Using system xxhash library')
  use_sys_xxhash = true
else
  message('Using bundled xxhash library')
endif

# handle openssl library
use_ssl_crypto = get_option('use_ssl_crypto')
if get_option('use_ssl')
  static_sys_openssl = get_option('static_sys_openssl')
  sys_openssl = dependency('openssl', required: false, static: static_sys_openssl)
  use_sys_openssl = false
  if sys_openssl.found() and get_option('use_sys_openssl')
    message('Using system openssl library')
    use_sys_openssl = true
  else
    message('Using bundled openssl code')
    use_ssl_crypto = false
  endif
else
  sys_openssl = false
  use_sys_openssl = false
  use_ssl_crypto = false
endif

use_fork = get_option('use_fork')
use_dylink = get_option('use_dylink')

# handle libuv library
if get_option('use_libuv')
  libuv_dep = dependency('libuv', version: '>=1.0.0', required: false)
  use_libuv = libuv_dep.found()
  if not libuv_dep.found()
    warning('use_libuv option was set to true, but libuv was not found.')
  endif
else
  use_libuv = false
endif

if use_libuv
  message('Using libuv')
else
  message('Not using libuv, thus using fallback server implementations')
endif

use_libsqsh = false
if get_option('use_libsqsh')
  libsqsh_dep = dependency('libsqsh', version: '>=1.4.0', required: false)
  use_libsqsh = libsqsh_dep.found()
  if not libsqsh_dep.found()
    use_libsqsh = false
    warning('use_libsqsh option was set to true, but libsqsh was not found.')
  endif
else
  use_libsqsh = false
endif

has_debugger = get_option('debugger')
have_ptrace = not ['haiku', 'windows', 'cygwin', 'sunos', 'aix'].contains(host_machine.system())
can_ptrace_wrap = ['linux'].contains(host_machine.system())

have_ptrace = have_ptrace and has_debugger
use_ptrace_wrap = can_ptrace_wrap and has_debugger

message('HAVE_PTRACE: @0@'.format(have_ptrace))
message('USE_PTRACE_WRAP: @0@'.format(use_ptrace_wrap))

checks_level = get_option('checks_level')
if checks_level == 9999
  if get_option('buildtype') == 'release'
    checks_level = 1
  else
    checks_level = 2
  endif
endif

message('R2_CHECKS_LEVEL: @0@'.format(checks_level))

userconf = configuration_data()
userconf.set('R_CHECKS_LEVEL', checks_level)
userconf.set10('HAVE_LIB_MAGIC', sys_magic.found())
userconf.set10('USE_LIB_MAGIC', use_syslib_magic)
userconf.set10('HAVE_LIB_XXHASH', sys_xxhash.found())
userconf.set10('USE_LIB_XXHASH', use_sys_xxhash)
userconf.set10('HAVE_LINUX_CAN_H', false)
userconf.set10('DEBUGGER', has_debugger)
userconf.set('ETCDIR', join_paths(r2_prefix, 'etc'))
userconf.set('PREFIX', r2_prefix)
userconf.set('BINDIR', join_paths(r2_prefix, 'bin'))
if host_machine.system() == 'windows'
  userconf.set('LIBDIR', r2_libdir)
  userconf.set('INCLUDEDIR', r2_incdir)
  userconf.set('DATADIR_R2', r2_datdir)
  userconf.set10('HAVE_JEMALLOC', false)
else
  userconf.set('LIBDIR', join_paths(r2_prefix, r2_libdir))
  userconf.set('INCLUDEDIR', join_paths(r2_prefix, r2_incdir))
  userconf.set('DATADIR_R2', r2_datdir_r2)
  userconf.set10('HAVE_JEMALLOC', true)
endif
userconf.set('WITH_STATIC_THEMES', get_option('static_themes'))

userconf.set('DATADIR', join_paths(r2_prefix, r2_datdir))
userconf.set('WWWROOT', join_paths(r2_prefix, r2_wwwroot))
userconf.set('SDB', r2_sdb)
userconf.set('PLATFORM', r2_platform)
userconf.set('ZIGNS', r2_zigns)
userconf.set('THEMES', r2_themes)
userconf.set('PANELS', r2_panels)
userconf.set('FORTUNES', r2_fortunes)
userconf.set('FLAGS', r2_flags)
userconf.set('HUD', r2_hud)
userconf.set('PLUGINS', r2_plugins)
userconf.set('EXTRAS', r2_extras)
userconf.set('BINDINGS', r2_bindings)
userconf.set('R2_BUILDSYSTEM', 'meson')
userconf.set10('USE_SQSH', use_libsqsh)
capstone_version = get_option('use_capstone_version')
userconf.set10('USE_CS4', capstone_version == 'v4')
userconf.set10('USE_CSNEXT', capstone_version == 'v6')
userconf.set10('HAVE_OPENSSL', use_sys_openssl)
userconf.set10('WANT_SSL_CRYPTO', use_ssl_crypto)
userconf.set10('HAVE_LIBUV', use_libuv)
userconf.set10('HAVE_FORK', use_fork)
userconf.set10('HAVE_GPERF', get_option('sdb_cgen'))
userconf.set10('WANT_DYLINK', use_dylink)
userconf.set10('WANT_QJS', get_option('want_qjs'))
userconf.set10('WANT_V35', get_option('use_v35'))
userconf.set10('WANT_THREADS', get_option('want_threads'))
userconf.set10('WANT_CAPSTONE', get_option('want_capstone'))
userconf.set10('USE_NEW_ABI', get_option('use_new_abi'))
userconf.set10('HAVE_PTRACE', have_ptrace)
userconf.set10('WANT_DEBUGSTUFF', get_option('debugstuff'))
userconf.set('R_CRITICAL_ENABLED', r2_critical_enabled)
userconf.set10('USE_PTRACE_WRAP', use_ptrace_wrap)
userconf.set10('WITH_GPL', not get_option('nogpl'))
ok = cc.has_header_symbol('sys/personality.h', 'ADDR_NO_RANDOMIZE')
userconf.set10('HAVE_DECL_ADDR_NO_RANDOMIZE', ok)

lrt = []
if not cc.has_function('clock_gettime', prefix: '#include <time.h>') and cc.has_header_symbol('features.h', '__GLIBC__')
  lrt = cc.find_library('rt', required: true)
endif

foreach item : [
    ['arc4random_uniform', '#include <stdlib.h>', []],
    ['explicit_bzero', '#include <string.h>', []],
    ['explicit_memset', '#include <string.h>', []],
    ['clock_nanosleep', '#include <time.h>', []],
    ['clock_gettime', '#include <time.h>', [lrt]],
    ['sigaction', '#include <signal.h>', []]
  ]
  func = item[0]
  ok = cc.has_function(func, prefix: item[1], dependencies: item[2])
  userconf.set10('HAVE_@0@'.format(func.to_upper()), ok)
endforeach

r_userconf_h = configure_file(
  input: 'libr/include/r_userconf.h.acr',
  output: 'r_userconf.h',
  configuration: userconf,
  install_dir: r2_incdir
)

versionconf = configuration_data()
versionconf.set('MESON_VERSION', meson.version())
versionconf.set('VERSIONCOMMIT', version_commit)
versionconf.set('R2_VERSION_MAJOR', r2_version_major)
versionconf.set('R2_VERSION_MINOR', r2_version_minor)
versionconf.set('R2_VERSION_PATCH', r2_version_patch)
versionconf.set('R2_VERSION_NUMBER', r2_version_number)
versionconf.set('R2_VERSION', r2_version)
versionconf.set('R2_GITTAP', gittap)
versionconf.set('R2_GITTIP', gittip)
versionconf.set('R2_BIRTH', r2birth)
r_version_h = configure_file(
  input: 'libr/include/r_version.h.in',
  output: 'r_version.h',
  configuration: versionconf,
  install_dir: r2_incdir
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
  configuration: pcconf,
  install_dir: join_paths(get_option('libdir'), 'pkgconfig')
)

subdir('shlr/zip')

script_files = [
  'scripts/il2cpp.r2.js',
  'scripts/ipsw-kernel-symbolicate.r2.js',
  'scripts/licenses.r2.js',
  'scripts/parseplug.r2.js',
  'scripts/r2sptrace.py',
  'scripts/tags.r2.js',
  'scripts/symbols.r2.js',
  'scripts/unzip.r2.js',
  'scripts/vsmap.r2.js',
]
install_data(script_files, install_dir: r2_scripts)

libsdb_sp = subproject('sdb')
libsdb_static = libsdb_sp.get_variable('libsdb_static')
libsdb_dynamic = libsdb_sp.get_variable('libsdb').get_shared_lib()
libsdb_includes = libsdb_sp.get_variable('sdb_inc')
libsdb_version = libsdb_sp.get_variable('sdb_version')

sdb_dep = declare_dependency(
  link_whole: libsdb_static,
  include_directories: libsdb_includes
)

sdb_exe = libsdb_sp.get_variable('sdb_exe')

if host_machine.system() == 'windows'
copyinout = [
	'powershell', '-Command',
	'Copy-Item', '@INPUT@', '@OUTPUT@'
]
else
copyinout = ['cp', '-f', '@INPUT@', '@OUTPUT@']
endif

sdb_install = custom_target('r2sdb',
  input : sdb_exe,
  output : 'r2sdb',
  command : copyinout,
  install : true,
  install_dir : get_option('bindir'))

os_name = host_machine.system()
lib_extension = '.so.' + libsdb_version  # Default for Linux

if os_name == 'darwin'
    lib_extension = '.dylib'
elif os_name == 'windows'
    lib_extension = '.dll'
endif

libsdb_install = custom_target('libr2sdb',
  input : libsdb_dynamic,
  output : 'libsdb' + lib_extension,
  command : copyinout,
  install : true,
  install_dir : get_option('libdir'))

sdb_gen_cmd_cgen = [ sdb_exe, '-t', '-C', '-o', '@OUTPUT@', '@INPUT@' ]
sdb_gen_cmd = [ sdb_exe, '@OUTPUT@', '==', '@INPUT@' ]

py_cmd = '__import__("os").readlink(r"@0@"))'.format(repo)
syscall_sdb_gen_cmd = [ py3_exe, gen_py, sdb_exe, '@INPUT@', '@OUTPUT@', ]

# handle spp dependency
spp_files = [
  'shlr/spp/spp.c'
]

spp_inc = [platform_inc, include_directories(join_paths('shlr','spp'))]

libr2spp = static_library('r2spp', spp_files,
  link_with: [ libsdb_static ], # libsdb_static,
  include_directories: [ libsdb_includes, spp_inc ],
  c_args: ['-DHAVE_R_UTIL', '-DUSE_R2=1'],
  implicit_include_directories: false
)

spp_dep = declare_dependency(
  link_with: libr2spp,
  include_directories: spp_inc
)

pkgcfg_sanitize_libs = ''
if get_option('b_sanitize').contains('address')
  pkgcfg_sanitize_libs += ' -lasan'
endif
if get_option('b_sanitize').contains('undefined')
  pkgcfg_sanitize_libs += ' -lubsan'
endif
if get_option('b_sanitize').contains('thread')
  pkgcfg_sanitize_libs += ' -fsanitize=thread'
endif

rpath_exe = ''
rpath_lib = ''
if get_option('local') and get_option('default_library') == 'shared'
  rpath_exe = '$ORIGIN/../' + get_option('libdir')
  rpath_lib = '$ORIGIN'
endif

subdir('libr/util')
subdir('libr/socket')
subdir('libr/muta')
subdir('shlr')
subdir('libr/cons')
subdir('shlr/gdb')
subdir('libr/io')
subdir('libr/bp')
subdir('libr/syscall')
subdir('libr/search')
subdir('libr/magic')
subdir('libr/flag')
subdir('libr/reg')
subdir('libr/esil')
subdir('libr/arch')
subdir('libr/fs')
subdir('libr/bin')
subdir('libr/config')
subdir('libr/asm')
subdir('libr/lang')
subdir('libr/anal')
subdir('libr/egg')
subdir('libr/debug')
subdir('libr/core')
subdir('libr/cons/d')
subdir('libr/magic/d')
subdir('libr/flag/d')
subdir('libr/main')
subdir('shlr/panels')


subdir('binr')
if meson.is_subproject()
  libr2_dep = declare_dependency(
    dependencies: [
      r_anal_dep,
      r_asm_dep,
      r_bp_dep,
      r_config_dep,
      r_cons_dep,
      r_core_dep,
      r_main_dep,
      r_muta_dep,
      r_debug_dep,
      r_egg_dep,
      r_flag_dep,
      r_fs_dep,
      r_bin_dep,
      r_io_dep,
      r_lang_dep,
      r_magic_dep,
      r_reg_dep,
      r_search_dep,
      r_socket_dep,
      r_syscall_dep,
      r_util_dep
    ],
    include_directories: include_directories('.', 'libr/include'),
    version: r2_version
  )
endif

if get_option('use_webui')
  install_subdir('shlr/www',
    install_dir: r2_wwwroot,
    strip_directory: true
  )
endif

subdir('test/unit')
subdir('test/fuzz')

install_data(
  'doc/fortunes.fun',
  'doc/fortunes.tips',
  install_dir: r2_fortunes
)

install_data(
  'libr/arch/d/nes-init.r2',
  'libr/arch/d/nes-fini.r2',
  install_dir: r2_platform
)

if cli_enabled
  install_man(
    'man/r2agent.1',
    'man/r2pm.1',
    'man/rabin2.1',
    'man/radare2.1',
    'man/radiff2.1',
    'man/rafind2.1',
    'man/ragg2.1',
    'man/rahash2.1',
    'man/rarun2.1',
    'man/rasign2.1',
    'man/rasm2.1',
    'man/rax2.1',
    'man/ravc2.1',
    'man/esil.7'
  )

  install_data('doc/hud',
    install_dir: r2_hud,
    rename: 'main'
  )

  install_data(
    'doc/zsh/_r2',
    'doc/zsh/_rabin2',
    'doc/zsh/_radiff2',
    'doc/zsh/_rafind2',
    'doc/zsh/_ragg2',
    'doc/zsh/_rahash2',
    'doc/zsh/_rasm2',
    'doc/zsh/_rax2',
    install_dir: r2_zsh_compdir
  )

  if host_machine.system() == 'windows'
    meson.add_install_script('sys/create_r2.bat')
  else
    meson.add_install_script('sys/create_r2.sh')
  endif
endif
