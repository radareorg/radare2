/* radare - LGPL - Copyright 2008-2023 - pancake */

#ifndef R2_UTIL_H
#define R2_UTIL_H

#include <r_types.h>
#include <r_regex.h>
#include <r_getopt.h>
#include <r_list.h> // radare linked list
#include <r_skiplist.h> // skiplist
#include <r_th.h>
#if !R2__WINDOWS__
#include <dirent.h>
#include <signal.h>
#endif
#ifdef HAVE_LIB_GMP
#include <gmp.h>
#endif
#if HAVE_LIB_SSL
#include <openssl/bn.h>
#endif
#if APPLE_SDK_IPHONEOS
extern int ptrace(int _request, pid_t _pid, caddr_t _addr, int _data);
#endif
#ifdef _MSC_VER
#include <windows.h>
int gettimeofday (struct timeval* p, void* tz);
#endif
#include "r_util/r_event.h"
#include "r_util/r_assert.h"
#include "r_util/r_itv.h"
#include "r_util/r_signal.h"
#include "r_util/r_alloc.h"
#include "r_util/r_rbtree.h"
#include "r_util/r_xml.h"
#include "r_util/r_new_rbtree.h"
#include "r_util/r_intervaltree.h"
#include "r_util/r_big.h"
#include "r_util/r_base36.h"
#include "r_util/r_base64.h"
#include "r_util/r_base91.h"
#include "r_util/r_buf.h"
#include "r_util/r_bitmap.h"
#include "r_util/r_time.h"
#include "r_util/r_debruijn.h"
#include "r_util/r_ctypes.h"
#include "r_util/r_file.h"
#include "r_util/r_hex.h"
#include "r_util/r_log.h"
#include "r_util/r_mem.h"
#include "r_util/r_name.h"
#include "r_util/r_num.h"
#include "r_util/r_table.h"
#include "r_util/r_graph.h"
#include "r_util/r_panels.h"
#include "r_util/r_pool.h"
#include "r_util/r_diff.h"
#include "r_util/r_punycode.h"
#include "r_util/r_queue.h"
#include "r_util/r_range.h"
#include "r_util/r_sandbox.h"
#include "r_util/r_signal.h"
#include "r_util/r_spaces.h"
#include "r_util/r_stack.h"
#include "r_util/r_str.h"
#include "r_util/r_strbuf.h"
#include "r_util/r_strpool.h"
#include "r_util/r_str_constpool.h"
#include "r_util/r_sys.h"
#include "r_util/r_tree.h"
#include "r_util/r_uleb128.h"
#include "r_util/r_utf8.h"
#include "r_util/r_utf16.h"
#include "r_util/r_utf32.h"
#include "r_util/r_idpool.h"
#include "r_util/r_asn1.h"
#include "r_util/pj.h"
#include "r_util/r_graph_drawable.h"
#include "r_util/bplist.h"
#include "r_util/r_x509.h"
#include "r_util/r_pkcs7.h"
#include "r_util/r_protobuf.h"
#include "r_util/r_big.h"
#include "r_util/r_ref.h"
#include "r_util/r_w32.h"
#include "r_util/r_token.h"
#include "r_util/r_axml.h"
// requires io, core, ... #include "r_util/r_print.h"

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER (r_util);

#ifdef __cplusplus
}
#endif

#endif
