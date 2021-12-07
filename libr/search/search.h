// To keep update function out of public r_search API
int r_search_mybinparse_update(RSearch *s, ut64 from, const ut8 *buf, int len);
int r_search_aes_update(RSearch *s, ut64 from, const ut8 *buf, int len);
int r_search_privkey_update(RSearch *s, ut64 from, const ut8 *buf, int len);
int r_search_deltakey_update(RSearch *s, ut64 from, const ut8 *buf, int len);
int r_search_strings_update(RSearch *s, ut64 from, const ut8 *buf, int len);
int r_search_regexp_update(RSearch *s, ut64 from, const ut8 *buf, int len);
