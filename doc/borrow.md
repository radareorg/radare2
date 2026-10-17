# Pointer ownership and lifetime

Empty macros from `libr/include/r_types.h` describe who owns a pointer and how
long it stays valid. They generate no code; they document the API contract for
readers, reviewers and analysis tools.

| Macro | Return value | Parameter |
| --- | --- | --- |
| `R_OWNED` | Caller owns it and must free it | Callee takes it (consumes or frees it) |
| `R_UNOWNED` | Borrowed, never free it | Callee borrows it, caller keeps ownership |
| `R_TRANSIENT` | Borrowed and only valid until the next call that mutates its owner | - |
| `R_NOALIAS` | - | Must not point into storage modified by the call |
| `R_OUT`, `R_INOUT` | - | Written, or read and written, by the callee |
| `R_NULLABLE`, `R_NONNULL` | May or must not be NULL | Same |

Unannotated `const char *` parameters are borrowed for the duration of the call.

## Rules

- Do not keep an `R_TRANSIENT` pointer across a call that may write, flush, filter or free its owner. Read it right away, or re-read it after the call.
- Copy only to keep data across such a call. Prefer taking ownership (`r_cons_drain`, `r_strbuf_drain`) over `strdup` followed by freeing the original.
- A function that appends from a caller pointer into a growable buffer must either handle a source inside that buffer (alias-safe) or mark the parameter `R_NOALIAS`.
- `R_WEAK` is a linker attribute, not a lifetime hint.

## RCons buffer

`RConsContext.buffer` is owned by its context. `buffer_len` counts used bytes and
`buffer_sz` the allocated capacity including the trailing NUL. `buffer_sz` must
never exceed the real allocation.

Pointers from `r_cons_get_buffer` and `r_cons_lastline` are `R_TRANSIENT`. They
become invalid when:

- a write grows the buffer (`r_cons_print`, `r_cons_printf`, `r_cons_memset`, ...)
- `r_cons_flush` hands a large buffer over to `lastOutput`
- `r_cons_filter`, `r_cons_grepbuf` or `r_cons_highlight` replace it
- `r_cons_drain` takes it, or `r_cons_pop` frees the pushed context

`r_cons_printf` arguments are `R_NOALIAS`: they are formatted in place.

Example: `?e [[[["A"]]]]~{}..` passed the cons buffer to `r_cons_less_str`,
which printed it into itself; the buffer was reallocated before the copy and
the output contained freed memory (ANT-2026-1C3D8D53).
