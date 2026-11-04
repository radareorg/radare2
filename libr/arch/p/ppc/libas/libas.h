#ifndef LIBAS_H
#define LIBAS_H
#include <r_types.h>

/* PowerPC-AS (iSeries tagged-memory extensions) instruction decoder.
 *
 * These are IBM private instructions used by the IBM i LIC; they are NOT
 * part of the public Power ISA and are decoded as `invalid` by Capstone.
 * Decoding mirrors the patched QEMU target/ppc/translate.c AS hooks so the
 * mnemonics/fields match the execution model.
 *
 * libas_decode() takes the instruction word in the session's native byte
 * order (already big-endian-swapped by the caller, matching decompile_ps)
 * and, on a match, writes the textual mnemonic into `out` and returns true.
 * Returns false for non-AS words so the caller can fall back to Capstone.
 */
bool libas_decode (ut32 word, char *out, int outsz);

#endif
