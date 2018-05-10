anal = [
  '6502',
  '8051',
  'arc',
  'arm_cs',
  'arm_gnu',
  'avr',
  'bf',
  'chip8',
  'cr16',
  'cris',
  'dalvik',
  'ebc',
  'gb',
  'h8300',
  'hexagon',
  'i4004',
  'i8080',
  'java',
  'm68k_cs',
  'malbolge',
  'mips_cs',
  'mips_gnu',
  'msp430',
  'nios2',
  'null',
  'pic',
  'ppc_cs',
  'ppc_gnu',
  'propeller',
  'riscv',
  'rsp',
  'sh',
  'snes',
  'sparc_cs',
  'sparc_gnu',
  'sysz',
  'tms320',
  #'tms320c64x',
  'v810',
  'v850',
  'vax',
  'wasm',
  'ws',
  'x86_cs',
  'xap',
  'xcore_cs',
  'xtensa',
  'z80',
]

anal_plugins = []
foreach p : anal
  anal_plugins += ['&r_anal_plugin_' + p]
endforeach
anal_plugins = ', '.join(anal_plugins)

asm = [
  '6502',
  '8051',
  'arc',
  'arm_as',
  'arm_cs',
  'arm_gnu',
  'arm_winedbg',
  'avr',
  'bf',
  'chip8',
  'cr16',
  'cris_gnu',
  'dalvik',
  'dcpu16',
  'ebc',
  'gb',
  'h8300',
  'hexagon',
  #'hexagon_gnu',
  'hppa_gnu',
  'i4004',
  'i8080',
  'java',
  'lanai_gnu',
  'lh5801',
  'lm32',
  'm68k_cs',
  'malbolge',
  'mcs96',
  'mips_cs',
  'mips_gnu',
  'msp430',
  'nios2',
  'pic',
  'ppc_cs',
  'ppc_gnu',
  'propeller',
  'riscv',
  'rsp',
  'sh',
  'snes',
  'sparc_cs',
  'sparc_gnu',
  'spc700',
  'sysz',
  'tms320',
  'tricore',
  'v810',
  'v850',
  'vax',
  'wasm',
  'ws',
  'x86_as',
  'x86_cs',
  #'x86_gas',
  'x86_nasm',
  'x86_nz',
  'xap',
  'xcore_cs',
  'xtensa',
  'z80',
]

asm_plugins = []
foreach p : asm
  asm_plugins += ['&r_asm_plugin_' + p]
endforeach
asm_plugins = ', '.join(asm_plugins)

bin = [
  'any',
  'art',
  'bf',
  'bflt',
  'bios',
  'bootimg',
  'cgc',
  'coff',
  'dex',
  'dol',
  'dyldcache',
  'elf',
  'elf64',
  'fs',
  'java',
  'mach0',
  'mach064',
  'mbn',
  'mdmp',
  'menuet',
  'mz',
  'nes',
  'nin3ds',
  'ninds',
  'ningb',
  'ningba',
  'nro',
  'nso',
  'omf',
  'p9',
  'pe',
  'pe64',
  'pebble',
  'psxexe',
  'sfc',
  'smd',
  'sms',
  'spc700',
  'te',
  'vsf',
  'wasm',
  'xbe',
  'z64',
  'zimg',
]

bin_plugins = []
foreach p : bin
  bin_plugins += ['&r_bin_plugin_' + p]
endforeach
bin_plugins = ', '.join(bin_plugins)

bin_ldr = [
  'ldr_linux',
]

bin_ldr_plugins = []
foreach p : bin_ldr
  bin_ldr_plugins += ['&r_bin_ldr_plugin_' + p]
endforeach
bin_ldr_plugins = ', '.join(bin_ldr_plugins)

bin_xtr = [
  'xtr_dyldcache',
  'xtr_fatmach0',
]

bin_xtr_plugins = []
foreach p : bin_xtr
  bin_xtr_plugins += ['&r_bin_xtr_plugin_' + p]
endforeach
bin_xtr_plugins = ', '.join(bin_xtr_plugins)

bp = [
  'arm',
  'bf',
  'mips',
  'ppc',
  'sh',
  'x86'
]

bp_plugins = []
foreach p : bp
  bp_plugins += ['&r_bp_plugin_' + p]
endforeach
bp_plugins = ', '.join(bp_plugins)

core = [
  'anal',
  'java'
]

core_plugins = []
foreach p : core
  core_plugins += ['&r_core_plugin_' + p]
endforeach
core_plugins = ', '.join(core_plugins)

crypto = [
  'aes',
  'aes_cbc',
  'base64',
  'base91',
  'blowfish',
  'cps2',
  'des',
  'punycode',
  'rc2',
  'rc4',
  'rc6',
  'rol',
  'ror',
  'rot',
  'serpent',
  'xor',
]

crypto_plugins = []
foreach p : crypto
  crypto_plugins += ['&r_crypto_plugin_' + p]
endforeach
crypto_plugins = ', '.join(crypto_plugins)

debug = [
  'bf',
  'bochs',
  'esil',
  'gdb',
  'io',
  'native',
  'null',
  'qnx',
  'rap',
  'windbg'
]

debug_plugins = []
foreach p : debug
  debug_plugins += ['&r_debug_plugin_' + p]
endforeach
debug_plugins = ', '.join(debug_plugins)

egg = [
  'exec',
  'xor'
]

egg_plugins = []
foreach p : egg
  egg_plugins += ['&r_egg_plugin_' + p]
endforeach
egg_plugins = ', '.join(egg_plugins)

fs = [
  'cpio',
  'ext2',
  'fat',
  'fb',
  'hfs',
  'hfsplus',
  'io',
  'iso9660',
  'jfs',
  'minix',
  'ntfs',
  'posix',
  'r2',
  'reiserfs',
  'sfs',
  'tar',
  'udf',
  'ufs',
  'ufs2',
  'xfs'
]

fs_plugins = []
foreach p : fs
  fs_plugins += ['&r_fs_plugin_' + p]
endforeach
fs_plugins = ', '.join(fs_plugins)

io = [
  'ar',
  'bfdbg',
  'bochs',
  'debug',
  'default',
  'gdb',
  'gprobe',
  'gzip',
  'http',
  'ihex',
  'mach',
  'malloc',
  'mmap',
  'null',
  'procpid',
  'ptrace',
  'qnx',
  'r2k',
  'r2pipe',
  'r2web',
  'rap',
  'rbuf',
  'self',
  'shm',
  'sparse',
  'tcp',
  'windbg',
  'winedbg',
  'zip'
]

if host_machine.system() == 'windows'
  io += [
    'w32dbg',
    'w32',
  ]
endif

io_plugins = []
foreach p : io
  io_plugins += ['&r_io_plugin_' + p]
endforeach
io_plugins = ', '.join(io_plugins)

lang = [
  'vala'
]

lang_plugins = []
foreach p : lang
  lang_plugins += ['&r_lang_plugin_' + p]
endforeach
lang_plugins = ', '.join(lang_plugins)

parse = [
  '6502_pseudo',
  'arm_pseudo',
  'att2intel',
  'avr_pseudo',
  'dalvik_pseudo',
  'm68k_pseudo',
  'mips_pseudo',
  'mreplace',
  'ppc_pseudo',
  'sh_pseudo',
  'x86_pseudo',
  'z80_pseudo'
]

parse_plugins = []
foreach p : parse
  parse_plugins += ['&r_parse_plugin_' + p]
endforeach
parse_plugins = ', '.join(parse_plugins)

include_files = run_command(glob_cmd + ['include/*.h']).stdout().strip().split(';')
install_headers(include_files, subdir: 'libr')

r_util_files = run_command(glob_cmd + ['include/r_util/*.h']).stdout().strip().split(';')
install_headers(r_util_files, subdir: 'libr/r_util')

sdb_files = run_command(glob_cmd + ['include/sdb/*.h']).stdout().strip().split(';')
install_headers(sdb_files, subdir: 'libr/sdb')

sflib_common_files = [
  'include/sflib/common/sftypes.h',
  'include/sflib/common/sfsocketcall.h'
]

sflib_arch = [
  'linux-x86-64',
  'linux-x86-32',
  'linux-arm-64',
  'linux-arm-32',
  'darwin-x86-64',
  'darwin-x86-32',
  'darwin-arm-64'
]

sflib_arch_files = [
  'sflib.h',
  'sfsyscall.h',
  'sfsysnr.h'
]

install_headers(sflib_common_files, subdir: 'libr/sflib/common')
foreach arch : sflib_arch
  foreach file : sflib_arch_files
    install_headers(join_paths('include/sflib', arch, file), subdir: join_paths('libr/sflib', arch))
  endforeach
endforeach
