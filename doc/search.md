# Ordered keyword streams

`r_search_new()` and `r_search_set_mode()` accept keyword mode flags without
changing the `RSearch` layout or adding exported functions:

- `R_SEARCH_KEYWORD`: existing keyword-major callbacks and behavior.
- `R_SEARCH_KEYWORD | R_SEARCH_ORDERED`: forward callbacks in increasing start
  address order; ties follow keyword registration order.
- Add `R_SEARCH_UNIQUE` to report only the first accepted keyword at each address.
  Later keywords at that address are not evaluated or counted. This flag requires
  `R_SEARCH_ORDERED`.

Register keywords before feeding data. Adding keywords after an ordered stream
has started fails without taking ownership of the new keyword. Keyword bytes,
lengths, masks and search options must remain unchanged during a stream. Callbacks
must not reset or mutate the active search; nested searches need their own
`RSearch` instance.

Feed forward, non-overlapping blocks through `r_search_update()`. Within a
contiguous stream, callbacks run when the longest-keyword lookahead at that start address
is available, or when the stream is flushed. At most `longest_keyword_length - 1` trailing bytes are deferred;
this prevents a short keyword near a block end from being reported before an
earlier, longer keyword crossing that boundary. No hit collection or sorting is
performed. Masks, case folding, distance, inverse matching, overlap, alignment,
contiguous-hit policy and callback stop/max-hit limits still apply.

Flush at each range end, including after the last block:

```c
RSearch *s = r_search_new (R_SEARCH_KEYWORD | R_SEARCH_ORDERED | R_SEARCH_UNIQUE);
r_search_kw_add (s, r_search_keyword_new_hexstr ("554889e5", NULL));
r_search_begin (s);
r_search_set_callback (s, on_hit, user);
r_search_update (s, base, buf, len);
r_search_update (s, base + len, NULL, 0);
r_search_free (s);
```

A gap flushes the previous tail before starting the next range; bytes across a
gap never form a match. Backward or overlapping input updates are rejected.
`r_search_begin()` discards pending bytes and resets keyword positions; use it
when starting another independent range, after flushing the previous one.
`r_search_reset()` resets the total hit count. Return values retain the existing
API convention: hits emitted during the call, or `-1` on error/callback failure.
A callback returning more than one stops the current update; the caller should
stop feeding that stream. `maxhits` also prevents subsequent updates and flushes
from emitting more hits.
