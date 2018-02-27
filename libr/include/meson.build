
include_files = [
  'r_anal_ex.h',
  'r_socket.h',
  'r_list.h',
  'r_vector.h',
  'r_heap_glibc.h',
  'r_reg.h',
  'r_debug.h',
  'r_types_base.h',
  'r_core.h',
  'r_parse.h',
  'r_slist.h',
  'r_regex.h',
  'r_egg.h',
  'r_endian.h',
  'r_qrcode.h',
  'r_magic.h',
  'r_heap_jemalloc.h',
  'r_crypto.h',
  'r_bp.h',
  'r_th.h',
  'r_diff.h',
  'r_flist.h',
  'r_skiplist.h',
  'r_fs.h',
  'btree.h',
  'r_bin.h',
  'r_util.h',
  'r_io.h',
  'r_asm.h',
  'r_flag.h',
  'r_lib.h',
  'r_types.h',
  'r_lang.h',
  'r_binheap.h',
  'r_bind.h',
  'sdb.h',
  'r_print.h',
  'r_search.h',
  'r_syscall.h',
  'r_pdb.h',
  'r_hash.h',
  'r_config.h',
  'r2naked.h',
  'r_sign.h',
  'r_bin_dwarf.h',
  'r_cons.h',
  'r_anal.h',
  'r_cmd.h'
]

r_util_files = [
  'r_util/r_json.h',
  'r_util/r_big.h',
  'r_util/r_base64.h',
  'r_util/r_mem.h',
  'r_util/r_name.h',
  'r_util/r_sandbox.h',
  'r_util/r_x509.h',
  'r_util/r_asn1.h',
  'r_util/r_buf.h',
  'r_util/r_rbtree.h',
  'r_util/r_file.h',
  'r_util/r_id_storage.h',
  'r_util/r_spaces.h',
  'r_util/r_tree.h',
  'r_util/r_str.h',
  'r_util/r_base91.h',
  'r_util/r_signal.h',
  'r_util/r_cache.h',
  'r_util/r_itv.h',
  'r_util/r_strbuf.h',
  'r_util/r_uleb128.h',
  'r_util/r_constr.h',
  'r_util/r_des.h',
  'r_util/r_queue.h',
  'r_util/r_pkcs7.h',
  'r_util/r_graph.h',
  'r_util/r_strpool.h',
  'r_util/r_str_util.h',
  'r_util/r_log.h',
  'r_util/r_hex.h',
  'r_util/r_sys.h',
  'r_util/r_utf8.h',
  'r_util/r_debruijn.h',
  'r_util/r_mixed.h',
  'r_util/r_pool.h',
  'r_util/r_num.h',
  'r_util/r_stack.h',
  'r_util/r_bitmap.h',
  'r_util/r_range.h',
  'r_util/r_utf32.h',
  'r_util/r_utf16.h',
  'r_util/r_punycode.h'
]

sdb_files = [
  'sdb/sdb_version.h',
  'sdb/config.h',
  'sdb/ht.h',
  'sdb/cdb_make.h',
  'sdb/ls.h',
  'sdb/dict.h',
  'sdb/cdb.h',
  'sdb/types.h',
  'sdb/sdbht.h',
  'sdb/sdb.h',
  'sdb/buffer.h'
]

install_headers(include_files, subdir: 'libr')
install_headers(r_util_files, subdir: 'libr/r_util')
install_headers(sdb_files, subdir: 'libr/sdb')

sflib__common_files = [
  'sflib/common/sftypes.h',
  'sflib/common/sfsocketcall.h'
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

install_headers(sflib__common_files, subdir: 'libr/sflib/common')
foreach arch : sflib_arch
  foreach file : sflib_arch_files
    install_headers(join_paths('sflib', arch, file), subdir: join_paths('libr/sflib', arch))
  endforeach
endforeach
