%module r_util
%{
#include <r_util.h>
%}

%include <r_util.h>

extern int r_hex_str2bin (rUtil*, const char* input, unsigned char* buf);
extern string r_hex_bin2strdup (rUtil*, unsigned char* buf, int len);
extern uint8* r_mem_mem (rUtil*, unsigned char* a, int al, unsigned char* b, int bl);
extern void r_mem_copyendian (rUtil*, unsigned char* dest, unsigned char* orig, int size, int endian);
extern void r_mem_copyloop (rUtil*, unsigned char* dest, unsigned char* orig, int dsize, int osize);
extern void r_mem_cmp_mask (rUtil*, unsigned char* dest, unsigned char* orig, unsigned char* mask, int len);
extern uint64 r_num_get (rUtil*, void* num, const char* str);
extern rStr* r_strnew ();
extern int r_strhash (rStr*, const char* str);
extern int r_logmsg (rLog*, const char* str);
extern int r_logerr (rLog*, const char* str);
extern rBuffer* r_buf_new ();
extern int r_buf_read_at (rBuffer*, unsigned long long addr, unsigned char* buf, int len);
extern int r_buf_write_at (rBuffer*, unsigned long long addr, unsigned char* buf, int len);
extern int r_buf_set_bytes (rBuffer*, unsigned char* buf, int len);
extern int r_buf_memcpy (rBuffer*, unsigned long long addr, unsigned char* dst, unsigned char* src, int len);
extern rIter* r_iter_new (int size);
extern G r_iter_get (rIter*, );
extern rIter<G>* r_iter_next (rIter*, );
extern rIter<G>* r_iter_next_n (rIter*, int idx);
extern G r_iter_prev (rIter*, );
extern void r_iter_delete (rIter*, );
extern G r_iter_first (rIter*, );
extern int r_iter_last (rIter*, );
extern G r_iter_free (rIter*, );
extern void r_iter_set (rIter*, int idx, gpointer data);
extern int ralist_next (rList*, );
extern G  (rList*, gconstpointer arg);
extern G ralist_get (rList*, );
extern rList<weak G>* ralist_iterator (rList*, );
extern int rarray_next (rArray*, );
extern G  (rArray*, gconstpointer arg);
extern G rarray_get (rArray*, );
extern rArray<G>* rarray_iterator (rArray*, );

%extend rUtil {
  int hex_str2bin (const char* input, unsigned char* buf) {
    return r_hex_str2bin (self, input, buf);
  }
  string hex_bin2strdup (unsigned char* buf, int len) {
    return r_hex_bin2strdup (self, buf, len);
  }
  uint8* mem_mem (unsigned char* a, int al, unsigned char* b, int bl) {
    return r_mem_mem (self, a, al, b, bl);
  }
  void mem_copyendian (unsigned char* dest, unsigned char* orig, int size, int endian) {
     r_mem_copyendian (self, dest, orig, size, endian);
  }
  void mem_copyloop (unsigned char* dest, unsigned char* orig, int dsize, int osize) {
     r_mem_copyloop (self, dest, orig, dsize, osize);
  }
  void mem_cmp_mask (unsigned char* dest, unsigned char* orig, unsigned char* mask, int len) {
     r_mem_cmp_mask (self, dest, orig, mask, len);
  }
  uint64 num_get (void* num, const char* str) {
    return r_num_get (self, num, str);
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
  int msg (const char* str) {
    return r_logmsg (self, str);
  }
  int err (const char* str) {
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
  int set_bytes (unsigned char* buf, int len) {
    return r_buf_set_bytes (self, buf, len);
  }
  int memcpy (unsigned long long addr, unsigned char* dst, unsigned char* src, int len) {
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
  int last () {
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
  int next () {
    return ralist_next (self);
  }
  G free (gconstpointer arg) {
    return  (self, arg);
  }
  G get () {
    return ralist_get (self);
  }
  rList<weak G>* iterator () {
    return ralist_iterator (self);
  }
};
%extend rArray {
  int next () {
    return rarray_next (self);
  }
  G free (gconstpointer arg) {
    return  (self, arg);
  }
  G get () {
    return rarray_get (self);
  }
  rArray<G>* iterator () {
    return rarray_iterator (self);
  }
};

