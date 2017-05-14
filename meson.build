project('radare2', 'c')

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

if host_machine.system() == 'windows'
  platform_deps = [cc.find_library('ws2_32')] # ,cc.find_library('capstone',dirs :'d:/2017/radare/myradare2/shlr/capstone/msvc/Release')]
  platform_librinc  = ['../include/msvc']
  platform_binrinc  = ['../../libr/include/msvc']
  host_os = 'windows'
else
  platform_librinc = []
  platform_binrinc = []
endif
subdir('libr/util')
subdir('binr/rax2')

subdir('libr/hash')
subdir('libr/crypto')
subdir('libr/socket')
subdir('libr/io')
subdir('binr/rahash2')
subdir('binr/rarun2')

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
subdir('binr/rasm2')
subdir('libr/egg')

subdir('libr/fs')

subdir('libr/debug')

subdir('libr/core')

subdir('binr/rabin2')
subdir('binr/radare2')
subdir('binr/ragg2')
