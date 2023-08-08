#ifndef MSCVER_STDATOMIC_H_
#define MSCVER_STDATOMIC_H_

#if !defined(__cplusplus) && defined(_MSC_VER)

#pragma warning(push)
#pragma warning(disable:4067)    /* newline for __has_include_next */

#if defined(__clang__) && __has_include_next(<stdatomic.h>)
   /* use the clang stdatomic.h with clang-cl*/
#  include_next <stdatomic.h>
#else /* ! stdatomic.h */

#include <windows.h>

typedef volatile LONG  atomic_int;
typedef volatile ULONG atomic_uint;

typedef enum {
    memory_order_relaxed,
    memory_order_acquire
} msvc_atomic_memory_order;

#define atomic_init(p_a, v)           do { *(p_a) = (v); } while(0)
#define atomic_store(p_a, v)          InterlockedExchange((LONG*)p_a, v)
#define atomic_load(p_a)              InterlockedCompareExchange((LONG*)p_a, 0, 0)
#define atomic_exchange(p_a, v)       InterlockedExchange(p_a, v)
#define atomic_load_explicit(p_a, mo) atomic_load(p_a)

static inline int atomic_compare_exchange_strong_int(LONG *obj, LONG *expected,
                                                     LONG desired)
{
    LONG orig = *expected;
    *expected = InterlockedCompareExchange(obj, desired, orig);
    return *expected == orig;
}
#define atomic_compare_exchange_strong(p_a, expected, desired) atomic_compare_exchange_strong_int((LONG *)p_a, (LONG *)expected, (LONG)desired)

/*
 * TODO use a special call to increment/decrement
 * using InterlockedIncrement/InterlockedDecrement
 */
#define atomic_fetch_add(p_a, inc)    InterlockedExchangeAdd(p_a, inc)
#define atomic_fetch_sub(p_a, dec)    InterlockedExchangeAdd(p_a, -(dec))
#define atomic_fetch_or(p_a, v)       InterlockedOr(p_a, v)
#define atomic_fetch_add_explicit(p_a, inc, mo) atomic_fetch_add(p_a, inc)

#endif /* ! stdatomic.h */

#pragma warning(pop)

#endif /* !defined(__cplusplus) && defined(_MSC_VER) */

#endif /* MSCVER_STDATOMIC_H_ */
