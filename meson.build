project('radare2', 'c')

# Get r2 version
r2version = run_command('python', 'sys/version.py')
if r2version.returncode() != 0
  r2version = 'unknown-error'
else
  r2version = r2version.stdout().strip()
endif

repo = '.'
if meson.is_subproject()
  repo = meson.current_source_dir()
  if host_machine.system() == 'windows'
    py_cmd = 'print(__import__("os").readlink(r"@0@"))'.format(repo)
    py_cmd = run_command('python', '-c', py_cmd)
    if py_cmd.returncode() == 0
      repo = py_cmd.stdout().strip()
      message('r2 realpath: ' + repo)
    endif
  endif
endif

# Get version_commit
version_commit = run_command('git', '-C', repo, 'rev-list', '--all', '--count')
if version_commit.returncode() != 0
  version_commit = 0
else
  version_commit = version_commit.stdout().strip()
endif

# Get gittap
gittap  = run_command('git', '-C', repo, 'describe', '--tags', '--match', '[0-9]*')
if gittap.returncode() != 0
  gittap = ''
else
  gittap = gittap.stdout().strip()
endif

# Get gittip
gittip  = run_command('git', '-C', repo, 'rev-parse', 'HEAD')
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

prefix = '/usr/local'

# system dependencies
cc = meson.get_compiler('c')
# required for linux
ldl = cc.find_library('dl', required: false)
pth = cc.find_library('pthread', required: false)
utl = cc.find_library('util', required: false)
mth = cc.find_library('m', required: false)

# detect OS
if cc.get_define('__linux__') == '1'
  host_os = 'linux'
else
  host_os = 'darwin'
endif

platform_deps = []
platform_inc = include_directories(['.', 'libr/include'])
if host_machine.system() == 'windows'
  platform_deps = [cc.find_library('ws2_32')]
  platform_inc = include_directories(['.', 'libr/include', 'libr/include/msvc'])
  host_os = 'windows'
  if get_option('default_library') == 'static'
    if get_option('buildtype') == 'release' and not meson.is_subproject()
      add_project_arguments('/MT', language: 'c')
    endif
    message(' ------ WINDOWS VERSION: BUILD STATIC ------')
  else
    message(' ------ WINDOWS VERSION: BUILD SHARED ------')
  endif
elif host_machine.system() == 'linux'
  if get_option('default_library') == 'static'
    message(' ------ LINUX VERSION: BUILD STATIC ------')
  else
    message(' ------ LINUX VERSION: BUILD SHARED ------')
  endif
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
configure_file(input: 'libr/config.h.in',
               output: 'config.h',
               configuration: conf_data)

userconf = configuration_data()
userconf.set('DEBUGGER', 1)
userconf.set('PREFIX', prefix)
userconf.set('LIBDIR', prefix + '/lib')
userconf.set('INCLUDEDIR', prefix + '/include')
userconf.set('DATADIR', prefix + '/share')
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
configure_file(input: 'libr/include/r_userconf.h.in',
               output: 'r_userconf.h',
               configuration: userconf)

versionconf = configuration_data()
versionconf.set('VERSIONCOMMIT', version_commit)
versionconf.set('R2_VERSION', r2version)
versionconf.set('R2_GITTAP', gittap)
versionconf.set('R2_GITTIP', gittip)
versionconf.set('R2_BIRTH', r2birth)
configure_file(input: 'libr/include/r_version.h.in',
               output: 'r_version.h',
               configuration: versionconf)

# Copy missing header
run_command('python', '-c', '__import__("shutil").copyfile("shlr/spp/config.def.h", "shlr/spp/config.h")')

subdir('shlr/')
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

if meson.is_subproject()
  libr2_lib = [
    r_anal, r_asm, r_bin, r_bp, r_config, r_cons, r_core, r_crypto, r_egg,
    r_flag, r_fs, r_hash, r_io, r_lang, r_magic, r_parse, r_reg, r_search,
    r_socket, r_syscall, r_util
  ]
  libr2_inc = include_directories(['.', 'libr/include'])
  libr2_dep = declare_dependency(
    link_with: libr2_lib,
    include_directories: libr2_inc,
    version: r2version
  )
else
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
endif
