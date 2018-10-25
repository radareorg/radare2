anal_plugins = [
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
  'mcore',
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

asm_plugins = [
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
  'tms320c64x',
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

bin_plugins = [
  'any',
  'art',
  'avr',
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

bin_ldr_plugins = [
  'ldr_linux',
]

bin_xtr_plugins = [
  'xtr_dyldcache',
  'xtr_fatmach0',
]

bp_plugins = [
  'arm',
  'bf',
  'mips',
  'ppc',
  'sh',
  'x86'
]

core_plugins = [
  'a2f',
  'java'
]

crypto_plugins = [
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

debug_plugins = [
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

egg_plugins = [
  'exec',
  #'shya',
  'xor'
]

fs_plugins = [
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

io_plugins = [
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
  io_plugins += [
    'w32dbg',
    'w32',
  ]
endif

lang_plugins = [
  'c',
  'cpipe',
  'lib',
  'pipe',
  'rust',
  'vala'
]

parse_plugins = [
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

sdb_readlink_script = '''#script
import os
import sys
infile = sys.argv[1]
if os.name == 'nt' and os.path.getsize(infile) <= 64:
    with open(infile) as sdb_txt:
        fname = sdb_txt.readline()
    if fname.endswith('.sdb.txt'):
        infile = fname
else:
    infile = os.path.basename(infile)
print(infile)
'''

sdb_readlink_cmd = [
  py3_exe,
  '-c',
  sdb_readlink_script
]
