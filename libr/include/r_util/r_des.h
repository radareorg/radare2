#ifndef R_DES_H
#define R_DES_H

R_API ut64 r_des_pc2(ut64 k);
R_API ut64 r_des_pc1(ut64 k);
R_API ut64 r_des_get_roundkey(ut64 key, int round, int enc);
R_API ut64 r_des_round(ut64 plaintext, ut64 roundkey);
R_API ut64 r_des_f(ut32 half, ut64 round_key);
R_API ut32 r_des_sbox(ut8 in, const ut32* box);
R_API ut64 r_des_ip(ut64 state, int inv);
R_API ut64 r_des_expansion(ut32 half);
R_API ut32 r_des_p(ut32 half);
#endif //  R_DES_H