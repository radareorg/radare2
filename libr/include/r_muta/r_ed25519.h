#ifndef R_ED25519_H
#define R_ED25519_H

#ifdef __cplusplus
extern "C" {
#endif

#define ED25519_SIG_LEN        64
#define ED25519_SEED_LENGTH    32
#define ED25519_PUBKEY_LENGTH  32
#define ED25519_PRIVKEY_LENGTH 64

R_API void r_muta_ed25519_keypair(const ut8 *seed, ut8 *privkey, ut8 *pubkey);

#ifdef __cplusplus
}
#endif

#endif //  R_ED25519_H
