#ifndef CRYPTO_SERPENT_ALGO_H
#define CRYPTO_SERPENT_ALGO_H

#include <r_crypto.h>
#define DW_BY_BLOCK 4
#define DW_BY_USERKEY 8
#define NB_ROUNDS 32
#define NB_SUBKEYS 33
#define NIBBLES_BY_SUBKEY 32

struct serpent_state {
    ut32 key[8];
    int key_size;
};

/*
 * st: A pointer to a serpent_state structure containing the key and the key size.
 * in: A block of data to be encrypted.
 * out: When the function returns, the block of data encrypted by serpent
 *      with the key contained in st.
 */
void serpent_encrypt(struct serpent_state *st, ut32 in[DW_BY_BLOCK], ut32 out[DW_BY_BLOCK]);

/*
 * st: A pointer to a serpent_state structure containing the key and the key size.
 * in: A block of data to be decrypted.
 * out: When the function returns, the block of data decrypted by serpent
 *      with the key contained in st.
 */
void serpent_decrypt(struct serpent_state *st, ut32 in[DW_BY_BLOCK], ut32 out[DW_BY_BLOCK]);

/*
 * st: A serpent_state structure containing the key and the key size.
 * subkeys: When the function returns, an array of double words containings
 *          all the subkeys needed for the encryptio/dcryption with serpent.
 */
void serpent_keyschedule(struct serpent_state st,
        ut32 subkeys[NB_SUBKEYS * DW_BY_BLOCK]);

#endif
