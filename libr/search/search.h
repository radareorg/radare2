// To keep update function out of public r_search API
R_IPI int search_kw_update(RSearch *s, ut64 from, const ut8 *buf, int len);
R_IPI int search_aes_update(RSearch *s, ut64 from, const ut8 *buf, int len);
R_IPI int search_sm4_update(RSearch *s, ut64 from, const ut8 *buf, int len);
R_IPI int search_asn1_privkey_update(RSearch *s, ut64 from, const ut8 *buf, int len);
R_IPI int search_raw_privkey_update(RSearch *s, ut64 from, const ut8 *buf, int len);
R_IPI int search_deltakey_update(RSearch *s, ut64 from, const ut8 *buf, int len);
R_IPI int search_strings_update(RSearch *s, ut64 from, const ut8 *buf, int len);
R_IPI int search_regexp_update(RSearch *s, ut64 from, const ut8 *buf, int len);

// update read API's use RSearch.iob instead of provided buf
R_IPI bool search_pattern(RSearch *s, ut64 from, ut64 to);
R_IPI int search_regex_read(RSearch *s, ut64 from, ut64 to);
R_IPI int search_rk(RSearch *s, ut64 from, ut64 to);
R_IPI int search_tire(RSearch *srch, ut64 from, ut64 to);

R_IPI int r_search_hit_sz(RSearch *s, RSearchKeyword *kw, ut64 addr, ut32 sz);
