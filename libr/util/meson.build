subdir('d')

r_util_sources = [
  'chartable.c',
  'assert.c',
  'bloom.c',
  'w32.c',
  'rlz4.c',
  'w32dw.c',
  'alloc.c',
  'rxml.c',
  'rvc.c',
  'rvc_git.c',
  'rvc_rvc.c',
  'charset.c',
  'donut.c',
  'token.c',
  'table.c',
  'bplist.c',
  'rstr.c',
  'sstext.c',
  'getopt.c',
  'print_code.c',
  'base32.c',
  'base36.c',
  'base85.c',
  'base91.c',
  'bdiff.c',
  'bitmap.c',
  'xdg.c',
  'buf.c',
  'chmod.c',
  'debruijn.c',
  'udiff.c',
  'event.c',
  'file.c',
  'graph.c',
  'graph_drawable.c',
  'hex.c',
  'idpool.c',
  'json_parser.c',
  'json_indent.c',
  'lib.c',
  'list.c',
  'log.c',
  'bscanf.c',
  'rprintf.c',
  'mem.c',
  'name.c',
  'new_rbtree.c',
  'format.c',
  'format2.c',
  'pie.c',
  'seven.c',
  'print.c',
  'prof.c',
  'punycode.c',
  'qrcode.c',
  'queue.c',
  'asn1.c',
  'asn1_str.c',
  'axml.c',
  'pkcs7.c',
  'x509.c',
  'utype.c',
  'randomart.c',
  'range.c',
  'rbtree.c',
  'intervaltree.c',
  'sandbox.c',
  'signal.c',
  'skiplist.c',
  'spaces.c',
  'stack.c',
  'str.c',
  'str_constpool.c',
  'str_trim.c',
  'strbuf.c',
  'strpool.c',
  'ustrpool.c',
  'sys.c',
  'sys_sh.c',
  'syscmd.c',
  'thread.c',
  'thread_sem.c',
  'thread_lock.c',
  'thread_cond.c',
  'thread_chan.c',
  'thread_pipe.c',
  'time.c',
  'tree.c',
  'pj.c',
  'ubase64.c',
  'uleb128.c',
  'unum.c',
  'math.c',
  'utf8.c',
  'utf16.c',
  'utf32.c',
  'vector.c',
  'sys_w32.c',
  'zip.c',
  'protobuf.c',
  'regex/regcomp.c',
  'regex/regexec.c',
  'regex/regerror.c'
]

if get_option('sdb_cgen')
  r_util_sources += r_util_d_sources
endif

if not get_option('use_sys_lz4')
  library_cflags += ['-DUSE_SMALLZ4']
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
