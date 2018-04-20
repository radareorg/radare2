anal = [
  '6502',
  '8051',
  'arc',
  'avr',
  'arm_cs',
  'arm_gnu',
  'bf',
  'cr16',
  'cris',
  'dalvik',
  'ebc',
  'i4004',
  'i8080',
  'java',
  'gb',
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
  'sh',
  'snes',
  'sparc_cs',
  'sparc_gnu',
  'sysz',
  'tms320',
  'vax',
  'v810',
  'v850',
  'ws',
  'x86_cs',
  'xap',
  'xcore_cs',
  'xtensa',
  'z80',
]

asm = [
  '6502',
  '8051',
  'arc',
  'avr',
  'arm_as',
  'arm_cs',
  'arm_gnu',
  'arm_winedbg',
  'bf',
  'cr16',
  'cris_gnu',
  'dalvik',
  'dcpu16',
  'gb',
  'ebc',
  'h8300',
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
  'x86_nasm',
  'x86_nz',
  'xap',
  'xcore_cs',
  'xtensa',
  'z80',
]

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
  'zimg',
  'z64',
]

bin_xtr = [
  'fatmach0',
  'xtr_dyldcache'
]

bp = [
  'arm',
  'bf',
  'mips',
  'ppc',
  'x86'
]

core = [
  'anal'
]

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
  'xor',
  'serpent'
]

debug = [
  'bf',
  'esil',
  'io',
  'native',
  'rap',
  'gdb',
  'windbg'
]

egg = [
  'exec',
  'xor'
]

fs = [
  'ext2',
  'fat',
  'fb',
  'hfs',
  'hfsplus',
  'iso9660',
  'jfs',
  'minix',
  'ntfs',
  'posix',
  'reiserfs',
  'sfs',
  'tar',
  'udf',
  'ufs',
  'xfs'
]

io = [
  'ar',
  'bfdbg',
  'debug',
  'default',
  'gdb',
  'gzip',
  'http',
  'ihex',
  'mach',
  'malloc',
  'mmap',
  'null',
  'procpid',
  'ptrace',
  'r2k',
  'r2pipe',
  'r2web',
  'rap',
  'self',
  'shm',
  'sparse',
  'tcp',
  'windbg',
  'winedbg'
]

if host_machine.system() == 'windows'
  io += [
    'w32dbg',
    'w32',
  ]
endif

lang = [
  'vala'
]

parse = [
  '6502_pseudo',
  'arm_pseudo',
  'att2intel',
  'dalvik_pseudo',
  'm68k_pseudo',
  'mips_pseudo',
  'mreplace',
  'ppc_pseudo',
  'sh_pseudo',
  'avr_pseudo',
  'x86_pseudo',
]

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
