subdir('d')

r_util_sources = [
  'alloc.c',
  'asn1_str.c',
  'asn1.c',
  'assert.c',
  'axml.c',
  'base32.c',
  'base36.c',
  'base85.c',
  'base91.c',
  'bdiff.c',
  'bitmap.c',
  'bloom.c',
  'bplist.c',
  'bscanf.c',
  'buf.c',
  'charset.c',
  'chartable.c',
  'chmod.c',
  'debruijn.c',
  'donut.c',
  'event.c',
  'file.c',
  'format.c',
  'format2.c',
  'getopt.c',
  'graph_drawable.c',
  'graph.c',
  'hex.c',
  'idpool.c',
  'intervaltree.c',
  'json_indent.c',
  'json_parser.c',
  'lib.c',
  'list.c',
  'log.c',
  'math.c',
  'mmap.c',
  'mem.c',
  'name.c',
  'new_rbtree.c',
  'pie.c',
  'pj.c',
  'pkcs7.c',
  'print_code.c',
  'print.c',
  'prof.c',
  'protobuf.c',
  'punycode.c',
  'qrcode.c',
  'queue.c',
  'randomart.c',
  'range.c',
  'rbtree.c',
  'regex/regcomp.c',
  'regex/regerror.c',
  'regex/regexec.c',
  'rlz4.c',
  'rprintf.c',
  'rstr.c',
  'rvc_git.c',
  'rvc_rvc.c',
  'rvc.c',
  'rxml.c',
  'rxmldom.c',
  'sandbox.c',
  'seven.c',
  'signal.c',
  'skiplist.c',
  'spaces.c',
  'sstext.c',
  'stack.c',
  'str_constpool.c',
  'str_pseudo.c',
  'str_pseudo.c',
  'str_strip.c',
  'str_trim.c',
  'str.c',
  'strbuf.c',
  'strpool.c',
  'sys_sh.c',
  'sys_w32.c',
  'sys.c',
  'syscmd.c',
  'table.c',
  'thread_chan.c',
  'thread_cond.c',
  'thread_lock.c',
  'thread_pipe.c',
  'thread_sem.c',
  'thread.c',
  'time.c',
  'token.c',
  'tree.c',
  'treemap.c',
  'ubase64.c',
  'udiff.c',
  'uleb128.c',
  'unum.c',
  'utf16.c',
  'utf32.c',
  'utf8.c',
  'utype.c',
  'vector.c',
  'w32.c',
  'w32dw.c',
  'x509.c',
  'xdg.c',
  'zip.c',
]

if get_option('sdb_cgen')
  r_util_sources += r_util_d_sources
endif

lz4_dep = dependency('liblz4', required: false)
if not get_option('use_sys_lz4')
  library_cflags += ['-DUSE_RLZ4']
endif

r_util_deps = [ldl, mth, spp_dep, pth, utl, sdb_dep, lz4_dep, zlib_dep, platform_deps]

if host_machine.system().startswith('freebsd') or host_machine.system().startswith('netbsd') or host_machine.system().startswith('haiku')
  # backtrace_symbols_fd requires -lexecinfo
  r_util_deps += [cc.find_library('execinfo')]
endif

if use_sys_openssl
  r_util_deps += [sys_openssl]
  r_util_sources += ['big_ssl.c']
else
  r_util_sources += ['big.c']
endif


r_util = library('r_util', r_util_sources,
  include_directories: platform_inc,
  c_args: library_cflags,
  dependencies: r_util_deps,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_util_dep = declare_dependency(link_with: r_util,
  include_directories: platform_inc,
  dependencies: r_util_deps)

if get_option('blob')
  r_util_static = static_library('r_util_static', r_util_sources,
    include_directories: platform_inc,
    c_args: library_cflags,
    dependencies: r_util_deps,
    install: true,
    implicit_include_directories: false,
    install_rpath: rpath_lib,
  )
  r_util_static_dep = declare_dependency(link_with: r_util_static,
    include_directories: platform_inc,
    dependencies: r_util_deps)
endif

pkgconfig_mod.generate(r_util,
  subdirs: ['libr', 'libr/sdb'],
  version: r2_version,
  libraries: pkgcfg_sanitize_libs,
  name: 'r_util',
  filebase: 'r_util',
  description: 'radare foundation libraries'
)
