use_gpl = not get_option('nogpl')
user_plugins = get_option('plugins').split(',')
no_user_plugins = get_option('plugins') == ''

esil_plugins = [ 'dummy' ]
asm_plugins = [ 'null' ]
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

if get_option('nogpl')
  user_plugins += ['nogrub']
endif


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
      'xtr_xalz',
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
    anal_plugins += [ 'arm_cs' ]
    bp_plugins += [ 'arm' ]
    parse_plugins += [ 'arm_pseudo' ]
  endif
  if user_plugins.contains('v850')
    anal_plugins += [ 'v850', 'v850_np', 'v810' ]
    parse_plugins += [ 'v850_pseudo' ]
  endif
  if user_plugins.contains('wasm')
    anal_plugins += [ 'wasm' ]
    parse_plugins += [ 'wasm_pseudo' ]
  endif
  if user_plugins.contains('sparc')
    anal_plugins += [ 'sparc_cs' ]
    if use_gpl
      asm_plugins += [ 'sparc_gnu' ]
      anal_plugins += [ 'sparc_gnu' ]
    endif
    bp_plugins += [ 'sparc' ]
    # missing parse_plugins += [ 'sparc_pseudo' ]
  endif
  if user_plugins.contains('mips')
    asm_plugins += [ 'mips_cs' ]
    anal_plugins += [ 'mips_cs' ]
    if use_gpl
      asm_plugins += [ 'mips_gnu' ]
      anal_plugins += [ 'mips_gnu' ]
    endif
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
  if user_plugins.contains('loongarch')
    anal_plugins += [ 'loongarch_gnu' ]
  endif
  if user_plugins.contains('elf')
    bin_plugins += [ 'elf', 'elf64' ]
  endif
  if user_plugins.contains('pe')
    bin_plugins += [ 'pe', 'pe64', 'coff', 'mz', 'ne' ]
    bin_xtr_plugins += [ 'xtr_pemixed' ]
  endif
  if not user_plugins.contains('nogrub')
    fs_plugins += [ 'cpio', 'ext2', 'fat', 'fb', 'hfs',
      'hfsplus', 'iso9660', 'jfs', 'minix', 'ntfs', 'reiserfs',
      'sfs', 'tar', 'udf', 'ufs', 'ufs2', 'xfs' ]
  endif
endif

# else
if no_user_plugins

asm_plugins += [
  'arm_as',
  'arm_cs',
  'arm_winedbg',
  'dalvik',
  'dcpu16',
  'gb',
  'java',
  'm680x_cs',
  'mcs96',
  'mips_cs',
  'or1k',
  'ppc_as',
  'ppc_cs',
  'propeller',
  'riscv',
  'rsp',
  'sh',
  'tms320',
  'x86_as',
  'x86_cs',
  'x86_nasm',
  'x86_nz',
]

# TODO: add the pyc plugin for meson builds too
anal_plugins += [
  '6502',
  '6502_cs',
  '8051',
  'alpha',
  'amd29k',
  #'arc',
  'arm_cs',
  'avr',
  'bf',
  'bpf',
  'bpf_cs',
  'chip8',
  'cr16',
  'bpf',
  'cris',
  'dalvik',
  'ebc',
  'evm_cs',
  'gb',
  'h8300',
  'i4004',
  'i8080',
  'java',
  'kvx',
  'lh5801',
  'lm32',
  'loongarch_gnu',
  'm68k_cs',
  'm680x_cs',
  'malbolge',
  'mcore',
  'mips_cs',
  'msp430',
  'nios2',
  'or1k',
  'pic',
  'ppc_cs',
  'propeller',
  'riscv',
  'riscv_cs',
  'rsp',
  'sh',
  'snes',
  'sparc_cs',
  's390_cs',
  'tms320',
  'tricore',
  'v810',
  'v850',
  'v850_np',
  'vax',
  'wasm',
  'ws',
  'x86_cs',
  'xap',
  'xcore_cs',
  'xtensa',
]

if no_user_plugins
  if use_gpl
    asm_plugins += [
      # 'z80',
      'arm_gnu',
      'cris_gnu',
  #    'hppa_gnu',
      'm68k_gnu',
      'lanai_gnu',
      'mips_gnu',
      'sparc_gnu'
    ]
    anal_plugins += [
      'z80',
      'arm_gnu',
      'bpf',
      'mips_gnu',
      'loongarch_gnu',
      's390_gnu',
      'pdp11_gnu',
      'ppc_gnu',
      'sparc_gnu',
    ]
  endif
endif

if get_option('use_v35')
  anal_plugins += ['arm_v35']
endif

bin_plugins += [
  'art',
  'avr',
  'bf',
  's390',
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
  'xtr_xalz',
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
  'aes_wrap',
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
  'socket',
  'tcpslurp',
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
  'v',
  'lib',
  'spp',
  'rust',
  'go',
  'zig',
  'c',
  'vala'
]

if host_machine.system() != 'windows'
  lang_plugins += [
    'pipe',
    'cpipe'
  ]
endif

parse_plugins += [
  '6502_pseudo',
  'arm_pseudo',
  'avr_pseudo',
  'chip8_pseudo',
  'dalvik_pseudo',
  'm68k_pseudo',
  'mips_pseudo',
  'ppc_pseudo',
  'riscv_pseudo',
  'sh_pseudo',
  'tms320_pseudo',
  'v850_pseudo',
  'wasm_pseudo',
  'x86_pseudo',
  'z80_pseudo'
]

endif

include_files = [
  join_paths('include/r2naked.h'),
  join_paths('include/r_agraph.h'),
  join_paths('include/r_anal.h'),
  join_paths('include/r_arch.h'),
  join_paths('include/r_asm.h'),
  join_paths('include/r_bin.h'),
  join_paths('include/r_bin_dwarf.h'),
  join_paths('include/r_bind.h'),
  join_paths('include/r_bp.h'),
  join_paths('include/r_cmd.h'),
  join_paths('include/r_codemeta.h'),
  join_paths('include/r_config.h'),
  join_paths('include/r_cons.h'),
  join_paths('include/r_core.h'),
  join_paths('include/r_crypto.h'),
  join_paths('include/r_debug.h'),
  join_paths('include/r_egg.h'),
  join_paths('include/r_endian.h'),
  join_paths('include/r_flag.h'),
  join_paths('include/r_flist.h'),
  join_paths('include/r_fs.h'),
  join_paths('include/r_getopt.h'),
  join_paths('include/r_hash.h'),
  join_paths('include/r_heap_glibc.h'),
  join_paths('include/r_heap_jemalloc.h'),
  join_paths('include/r_io.h'),
  join_paths('include/r_lang.h'),
  join_paths('include/r_lib.h'),
  join_paths('include/r_list.h'),
  join_paths('include/r_magic.h'),
  join_paths('include/r_main.h'),
  join_paths('include/r_parse.h'),
  join_paths('include/r_pdb.h'),
  join_paths('include/r_qrcode.h'),
  join_paths('include/r_reg.h'),
  join_paths('include/r_regex.h'),
  join_paths('include/r_search.h'),
  join_paths('include/r_sign.h'),
  join_paths('include/r_skiplist.h'),
  join_paths('include/r_skyline.h'),
  join_paths('include/r_socket.h'),
  join_paths('include/r_syscall.h'),
  join_paths('include/r_th.h'),
  join_paths('include/r_types.h'),
  join_paths('include/r_types_base.h'),
  join_paths('include/r_types_overflow.h'),
  join_paths('include/r_util.h'),
  join_paths('include/r_vector.h'),
]
install_headers(include_files, install_dir: r2_incdir)

r_util_files = [
  join_paths('include/r_util/bplist.h'),
  join_paths('include/r_util/pj.h'),
  join_paths('include/r_util/r_alloc.h'),
  join_paths('include/r_util/r_ascii_table.h'),
  join_paths('include/r_util/r_asn1.h'),
  join_paths('include/r_util/r_assert.h'),
  join_paths('include/r_util/r_axml.h'),
  join_paths('include/r_util/r_base64.h'),
  join_paths('include/r_util/r_base91.h'),
  join_paths('include/r_util/r_big.h'),
  join_paths('include/r_util/r_bitmap.h'),
  join_paths('include/r_util/r_buf.h'),
  join_paths('include/r_util/r_cache.h'),
  join_paths('include/r_util/r_ctypes.h'),
  join_paths('include/r_util/r_debruijn.h'),
  join_paths('include/r_util/r_diff.h'),
  join_paths('include/r_util/r_event.h'),
  join_paths('include/r_util/r_file.h'),
  join_paths('include/r_util/r_graph.h'),
  join_paths('include/r_util/r_graph_drawable.h'),
  join_paths('include/r_util/r_hex.h'),
  join_paths('include/r_util/r_idpool.h'),
  join_paths('include/r_util/r_intervaltree.h'),
  join_paths('include/r_util/r_itv.h'),
  join_paths('include/r_util/r_json.h'),
  join_paths('include/r_util/r_log.h'),
  join_paths('include/r_util/r_mem.h'),
  join_paths('include/r_util/r_name.h'),
  join_paths('include/r_util/r_new_rbtree.h'),
  join_paths('include/r_util/r_num.h'),
  join_paths('include/r_util/r_panels.h'),
  join_paths('include/r_util/r_pkcs7.h'),
  join_paths('include/r_util/r_pool.h'),
  join_paths('include/r_util/r_print.h'),
  join_paths('include/r_util/r_protobuf.h'),
  join_paths('include/r_util/r_punycode.h'),
  join_paths('include/r_util/r_queue.h'),
  join_paths('include/r_util/r_range.h'),
  join_paths('include/r_util/r_rbtree.h'),
  join_paths('include/r_util/r_sandbox.h'),
  join_paths('include/r_util/r_signal.h'),
  join_paths('include/r_util/r_spaces.h'),
  join_paths('include/r_util/r_stack.h'),
  join_paths('include/r_util/r_str.h'),
  join_paths('include/r_util/r_str_constpool.h'),
  join_paths('include/r_util/r_str_util.h'),
  join_paths('include/r_util/r_strbuf.h'),
  join_paths('include/r_util/r_strpool.h'),
  join_paths('include/r_util/r_sys.h'),
  join_paths('include/r_util/r_table.h'),
  join_paths('include/r_util/r_time.h'),
  join_paths('include/r_util/r_token.h'),
  join_paths('include/r_util/r_tree.h'),
  join_paths('include/r_util/r_uleb128.h'),
  join_paths('include/r_util/r_utf16.h'),
  join_paths('include/r_util/r_utf32.h'),
  join_paths('include/r_util/r_utf8.h'),
  join_paths('include/r_util/r_w32.h'),
  join_paths('include/r_util/r_w32dw.h'),
  join_paths('include/r_util/r_x509.h')
]
install_headers(r_util_files, install_dir: join_paths(r2_incdir, 'r_util'))

r_crypto_files = [
  'include/r_crypto/r_des.h'
]
install_headers(r_crypto_files, install_dir: join_paths(r2_incdir, 'r_crypto'))

sflib_common_files = [
  join_paths('include/sflib/common/sftypes.h'),
  join_paths('include/sflib/common/sfsocketcall.h')
]

sflib_arch = [
  'darwin-arm-64',
  'darwin-x86-32',
  'darwin-x86-64',
  'freebsd-x86-32',
  'linux-arm-32',
  'linux-arm-64',
  'linux-x86-32',
  'linux-x86-64',
]

sflib_arch_files = [
  'sflib.h',
  'sfsyscall.h',
  'sfsysnr.h'
]

install_headers(sflib_common_files, install_dir: join_paths(r2_incdir, 'sflib', 'common'))
foreach arch : sflib_arch
  foreach file : sflib_arch_files
    dst = join_paths('include', 'sflib', arch, file)
    install_headers(dst, install_dir: join_paths(r2_incdir, 'sflib', arch))
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
