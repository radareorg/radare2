%module r_util
%{
#define bool int
#include <r_types.h>
#include <list.h>
#include <r_util.h>
%}
%include <r_types.h>
%include <list.h>
%include <r_util.h>

extern int r_hex_str2bin (const char* input, unsigned char* buf);
extern char * r_hex_bin2strdup (unsigned char* buf, int len);
extern unsigned char * r_mem_mem (unsigned char* a, int al, unsigned char* b, int bl);
extern void r_mem_copyendian (unsigned char* dest, unsigned char* orig, int size, int endian);
extern void r_mem_copyloop (unsigned char* dest, unsigned char* orig, int dsize, int osize);
extern void r_mem_cmp_mask (unsigned char* dest, unsigned char* orig, unsigned char* mask, int len);
extern unsigned long long r_num_get (void* num, const char* str);

%extend rUtil {
  int hex_str2bin (const char* input, unsigned char* buf) {
    return r_hex_str2bin (input, buf);
  }
  char * hex_bin2strdup (unsigned char* buf, int len) {
    return r_hex_bin2strdup (buf, len);
  }
  unsigned char * mem_mem (unsigned char* a, int al, unsigned char* b, int bl) {
    return r_mem_mem (a, al, b, bl);
  }
  void mem_copyendian (unsigned char* dest, unsigned char* orig, int size, int endian) {
     r_mem_copyendian (dest, orig, size, endian);
  }
  void mem_copyloop (unsigned char* dest, unsigned char* orig, int dsize, int osize) {
     r_mem_copyloop (dest, orig, dsize, osize);
  }
  void mem_cmp_mask (unsigned char* dest, unsigned char* orig, unsigned char* mask, int len) {
     r_mem_cmp_mask (dest, orig, mask, len);
  }
  unsigned long long num_get (void* num, const char* str) {
    return r_num_get (num, str);
  }
};
%extend rStr {
  rStr () {
    return r_strnew ();
  }
  int hash (const char* str) {
    return r_strhash (self, str);
  }
};
%extend rLog {
  bool msg (const char* str) {
    return r_logmsg (self, str);
  }
  bool err (const char* str) {
    return r_logerr (self, str);
  }
};
%extend rBuffer {
  rBuffer () {
    return r_buf_new ();
  }
  int read_at (unsigned long long addr, unsigned char* buf, int len) {
    return r_buf_read_at (self, addr, buf, len);
  }
  int write_at (unsigned long long addr, unsigned char* buf, int len) {
    return r_buf_write_at (self, addr, buf, len);
  }
  bool set_bytes (unsigned char* buf, int len) {
    return r_buf_set_bytes (self, buf, len);
  }
  bool memcpy (unsigned long long addr, unsigned char* dst, unsigned char* src, int len) {
    return r_buf_memcpy (self, addr, dst, src, len);
  }
};
%extend rIter {
  rIter (int size) {
    return r_iter_new (size);
  }
  G get () {
    return r_iter_get (self);
  }
  rIter<G>* next () {
    return r_iter_next (self);
  }
  rIter<G>* next_n (int idx) {
    return r_iter_next_n (self, idx);
  }
  G prev () {
    return r_iter_prev (self);
  }
  void delete () {
     r_iter_delete (self);
  }
  G first () {
    return r_iter_first (self);
  }
  bool last () {
    return r_iter_last (self);
  }
  G free () {
    return r_iter_free (self);
  }
  void set (int idx, gpointer data) {
     r_iter_set (self, idx, data);
  }
};
%extend rList {
  bool next () {
    return ralist_next (self);
  }
  G free (gconstpointer arg) {
    return  (self, arg);
  }
  G get (int type) {
    return ralist_get (self, type);
  }
  rList<weak G>* iterator () {
    return ralist_iterator (self);
  }
};
%extend rArray {
  bool next (int type) {
    return rarray_next (self, type);
  }
  G free (gconstpointer arg) {
    return  (self, arg);
  }
  G get (int type) {
    return rarray_get (self, type);
  }
  rArray<G>* iterator () {
    return rarray_iterator (self);
  }
};

