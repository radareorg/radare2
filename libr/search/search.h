// To keep update function out of public r_search API
int search_kw_update(RSearch *s, ut64 from, const ut8 *buf, int len);
int search_aes_update(RSearch *s, ut64 from, const ut8 *buf, int len);
int search_privkey_update(RSearch *s, ut64 from, const ut8 *buf, int len);
int search_deltakey_update(RSearch *s, ut64 from, const ut8 *buf, int len);
int search_strings_update(RSearch *s, ut64 from, const ut8 *buf, int len);
int search_regexp_update(RSearch *s, ut64 from, const ut8 *buf, int len);
