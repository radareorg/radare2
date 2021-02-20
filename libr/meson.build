user_plugins = get_option('plugins').split(',')
no_user_plugins = get_option('plugins') == ''

esil_plugins = [ 'dummy' ]
asm_plugins = [ 'bf' ]
anal_plugins = [ 'null' ]
bin_plugins = [ 'any' ]
bin_ldr_plugins = [ 'ldr_linux' ]
bin_xtr_plugins = [ 'xtr_sep64' ]
io_plugins = [ 'malloc', 'fd', 'default', 'null', 'rbuf', 'r2pipe' , 'r2pipe']
fs_plugins = [ 'r2', 'posix', 'io' ]
bp_plugins = [ 'bf' ]
crypto_plugins = [ 'xor', 'punycode' ]
core_plugins = [ 'a2f' ]
egg_plugins = [ 'xor' ]
debug_plugins = [ 'null', 'io' ]
lang_plugins = [ 'lib', 'pipe' ]
parse_plugins = [ 'att2intel' ]

# This must be splitted in meson.builds for each module
# meson split is results in 1 empty element when splitting an empty string :facepalm:
if not no_user_plugins
  if user_plugins.contains('apple') or user_plugins.contains('macos') or user_plugins.contains('ios')
    io_plugins += [
      'mach',
    ]
    bin_plugins += [
      'mach0', 'mach064',
      'dyldcache',
      'xnu_kernelcache',
    ]
    bin_xtr_plugins += [
      'xtr_dyldcache',
      'xtr_fatmach0',
      'xtr_sep64'
    ]
  endif
  if user_plugins.contains('android')
    bin_plugins += [
      'elf', 'elf64',
      'art', 'nso', 'nro'
    ]
    bin_ldr_plugins += [
      'ldr_linux'
    ]
  endif
  if user_plugins.contains('x86')
    asm_plugins += [ 'x86_cs', 'x86_nz' ]
    anal_plugins += [ 'x86_cs' ]
    bp_plugins += [ 'x86' ]
    parse_plugins += [ 'x86_pseudo' ]
  endif
  if user_plugins.contains('web')
    io_plugins += [ 'http' ]
    io_plugins += [ 'r2web' ]
  endif
  if user_plugins.contains('arm')
    asm_plugins += [ 'arm_cs' ]
    anal_plugins += [ 'x86_cs' ]
    bp_plugins += [ 'arm' ]
    parse_plugins += [ 'arm_pseudo' ]
  endif
  if user_plugins.contains('v850')
    asm_plugins += [ 'v850', 'v810', 'v850_gnu' ]
    anal_plugins += [ 'v850', 'v810' ]
    parse_plugins += [ 'v850_pseudo' ]
  endif
  if user_plugins.contains('wasm')
    asm_plugins += [ 'wasm' ]
    anal_plugins += [ 'wasm' ]
    parse_plugins += [ 'wasm_pseudo' ]
  endif
  if user_plugins.contains('sparc')
    asm_plugins += [ 'sparc_cs', 'sparc_gnu' ]
    anal_plugins += [ 'sparc_cs', 'sparc_gnu' ]
    bp_plugins += [ 'sparc' ]
    # missing parse_plugins += [ 'sparc_pseudo' ]
  endif
  if user_plugins.contains('mips')
    asm_plugins += [ 'mips_cs', 'mips_gnu' ]
    anal_plugins += [ 'mips_cs', 'mips_gnu' ]
    bp_plugins += [ 'mips' ]
    parse_plugins += [ 'mips_pseudo' ]
  endif
  if user_plugins.contains('dalvik')
    bin_plugins += [ 'dex' ]
    asm_plugins += [ 'dalvik' ]
    anal_plugins += [ 'dalvik' ]
    parse_plugins += [ 'dalvik_pseudo' ]
  endif
  if user_plugins.contains('riscv')
    asm_plugins += [ 'riscv' ]
    anal_plugins += [ 'riscv' ]
    parse_plugins += [ 'riscv_pseudo' ]
  endif
  if user_plugins.contains('elf')
    bin_plugins += [ 'elf', 'elf64' ]
  endif
  if user_plugins.contains('pe')
    bin_plugins += [ 'pe', 'pe64', 'coff', 'mz', 'ne' ]
  endif
  if user_plugins.contains('grub')
    fs_plugins += [ 'cpio', 'ext2', 'fat', 'fb', 'hfs',
      'hfsplus', 'iso9660', 'jfs', 'minix', 'ntfs', 'reiserfs',
      'sfs', 'tar', 'udf', 'ufs', 'ufs2', 'xfs' ]
  endif
endif
# else
if no_user_plugins
anal_plugins += [
  '6502',
  '8051',
  'amd29k',
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
  'm680x_cs',
  'malbolge',
  'mcore',
  'mips_cs',
  'mips_gnu',
  'msp430',
  'nios2',
  'or1k',
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
  'tricore',
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

asm_plugins += [
  '6502',
  '8051',
  'amd29k',
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
  'm680x_cs',
  'malbolge',
  'mcore',
  'mcs96',
  'mips_cs',
  'mips_gnu',
  'msp430',
  'nios2',
  'or1k',
  'pic',
  'ppc_as',
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
  'tms320c64x',
  'tricore',
  'v810',
  'v850',
  'v850_gnu',
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

bin_plugins += [
  'art',
  'avr',
  'bf',
  'bflt',
  'bios',
  'bootimg',
  'cgc',
  'coff',
  'dex',
  'dmp64',
  'dol',
  'dyldcache',
  'elf',
  'elf64',
  'fs',
  'java',
  'le',
  'mach0',
  'mach064',
  'mbn',
  'mdmp',
  'menuet',
  'mz',
  'ne',
  'nes',
  'nin3ds',
  'ninds',
  'ningb',
  'ningba',
  'nro',
  'nso',
  'omf',
  'qnx',
  'p9',
  'pe',
  'pe64',
  'pebble',
  'prg',
  'psxexe',
  'sfc',
  'smd',
  'sms',
  'symbols',
  'te',
  'vsf',
  'wasm',
  'xbe',
  'xnu_kernelcache',
  'z64',
  'zimg'
]

bin_ldr_plugins += [
  'ldr_linux'
]

bin_xtr_plugins += [
  'xtr_dyldcache',
  'xtr_fatmach0',
  'xtr_sep64',
]

bp_plugins += [
  'arm',
  'bf',
  'mips',
  'ppc',
  'sh',
  'x86'
]

core_plugins += [
  'a2f',
  'java'
]

crypto_plugins += [
  'aes',
  'aes_cbc',
  'base64',
  'base91',
  'blowfish',
  'cps2',
  'des',
  'rc2',
  'rc4',
  'rc6',
  'rol',
  'ror',
  'rot',
  'serpent',
]

debug_plugins += [
  'bf',
  'bochs',
  'esil',
  'gdb',
  'io',
  'native',
  'null',
  'qnx',
  'rap',
  'winkd'
]

egg_plugins += [
  'exec',
  #'shya',
]

fs_plugins += [
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

io_plugins += [
  'ar',
  'fd',
  'bfdbg',
  'bochs',
  'debug',
  'gdb',
  'gprobe',
  'gzip',
  'http',
  'ihex',
  'mach',
  'mmap',
  'procpid',
  'ptrace',
  'qnx',
  'r2k',
  'rap',
  'rbuf',
  'self',
  'shm',
  'sparse',
  'tcp',
  'winkd',
  'winedbg',
  'zip'
]

if host_machine.system() == 'windows'
  io_plugins += [
    'windbg',
    'w32dbg',
    'w32',
  ]
  debug_plugins += 'windbg'
endif

lang_plugins += [
  'rust',
  'vala'
]

if host_machine.system() != 'windows'
  lang_plugins += [
    'c',
    'cpipe'
  ]
endif

parse_plugins += [
  '6502_pseudo',
  'arm_pseudo',
  'avr_pseudo',
  'chip8_pseudo',
  'tms320_pseudo',
  'dalvik_pseudo',
  'm68k_pseudo',
  'mips_pseudo',
  'ppc_pseudo',
  'sh_pseudo',
  'riscv_pseudo',
  'v850_pseudo',
  'wasm_pseudo',
  'x86_pseudo',
  'z80_pseudo'
]

endif

include_files = [
  'include/r2naked.h',
  'include/r_agraph.h',
  'include/r_anal.h',
  'include/r_asm.h',
  'include/r_bind.h',
  'include/r_getopt.h',
  'include/r_bin_dwarf.h',
  'include/r_bin.h',
  'include/r_binheap.h',
  'include/r_bp.h',
  'include/r_cmd.h',
  'include/r_config.h',
  'include/r_cons.h',
  'include/r_core.h',
  'include/r_crypto.h',
  'include/r_debug.h',
  'include/r_diff.h',
  'include/r_egg.h',
  'include/r_main.h',
  'include/r_endian.h',
  'include/r_flag.h',
  'include/r_flist.h',
  'include/r_fs.h',
  'include/r_hash.h',
  'include/r_heap_glibc.h',
  'include/r_heap_jemalloc.h',
  'include/r_io.h',
  'include/r_lang.h',
  'include/r_lib.h',
  'include/r_list.h',
  'include/r_magic.h',
  'include/r_parse.h',
  'include/r_pdb.h',
  'include/r_qrcode.h',
  'include/r_regex.h',
  'include/r_reg.h',
  'include/r_search.h',
  'include/r_sign.h',
  'include/r_skiplist.h',
  'include/r_socket.h',
  'include/r_syscall.h',
  'include/r_th.h',
  'include/r_types_overflow.h',
  'include/r_types_base.h',
  'include/r_types.h',
  'include/r_util.h',
  'include/r_vector.h',
  'include/r_skyline.h',
]
install_headers(include_files, install_dir: r2_incdir)

r_util_files = [
  'include/r_util/pj.h',
  'include/r_util/r_ascii_table.h',
  'include/r_util/r_asn1.h',
  'include/r_util/r_assert.h',
  'include/r_util/r_protobuf.h',
  'include/r_util/r_base64.h',
  'include/r_util/r_base91.h',
  'include/r_util/r_big.h',
  'include/r_util/r_bitmap.h',
  'include/r_util/r_buf.h',
  'include/r_util/r_cache.h',
  'include/r_util/r_ctypes.h',
  'include/r_util/r_debruijn.h',
  'include/r_util/r_event.h',
  'include/r_util/r_file.h',
  'include/r_util/r_graph.h',
  'include/r_util/r_graph_drawable.h',
  'include/r_util/r_hex.h',
  'include/r_util/r_idpool.h',
  'include/r_util/r_itv.h',
  'include/r_util/r_json.h',
  'include/r_util/r_log.h',
  'include/r_util/r_mem.h',
  'include/r_util/r_name.h',
  'include/r_util/r_num.h',
  'include/r_util/r_panels.h',
  'include/r_util/r_table.h',
  'include/r_util/r_pkcs7.h',
  'include/r_util/r_pool.h',
  'include/r_util/r_print.h',
  'include/r_util/r_punycode.h',
  'include/r_util/r_queue.h',
  'include/r_util/r_range.h',
  'include/r_util/r_rbtree.h',
  'include/r_util/r_intervaltree.h',
  'include/r_util/r_sandbox.h',
  'include/r_util/r_signal.h',
  'include/r_util/r_spaces.h',
  'include/r_util/r_stack.h',
  'include/r_util/r_strbuf.h',
  'include/r_util/r_str.h',
  'include/r_util/r_strpool.h',
  'include/r_util/r_str_constpool.h',
  'include/r_util/r_str_util.h',
  'include/r_util/r_sys.h',
  'include/r_util/r_alloc.h',
  'include/r_util/r_time.h',
  'include/r_util/r_tree.h',
  'include/r_util/r_uleb128.h',
  'include/r_util/r_utf16.h',
  'include/r_util/r_utf32.h',
  'include/r_util/r_utf8.h',
  'include/r_util/r_x509.h',
  'include/r_util/r_annotated_code.h'
]
install_headers(r_util_files, install_dir: join_paths(r2_incdir, 'r_util'))

r_crypto_files = [
  'include/r_crypto/r_des.h'
]
install_headers(r_crypto_files, install_dir: join_paths(r2_incdir, 'r_crypto'))

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

install_headers(sflib_common_files, install_dir: join_paths(r2_incdir, 'sflib/common'))
foreach arch : sflib_arch
  foreach file : sflib_arch_files
    install_headers(join_paths('include/sflib', arch, file), install_dir: join_paths(r2_incdir, 'sflib', arch))
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
