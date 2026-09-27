# Panel caching

Press `&` in panels mode to toggle caching for the current panel. This works for
custom commands as well as built-in panels. The toggle discards the previous
output; `F` also discards it while clearing panel filters. Scrolling and resizing
reuse cached output, including empty results. Saved layouts retain each panel's
`Cache` boolean; layouts without it use the panel defaults.

New entries in `modal_entries_db` can specify `PANEL_CACHE_ON` or
`PANEL_CACHE_OFF` as their fourth field. Omit it, or use `PANEL_CACHE_AUTO`, to
inherit the command-prefix whitelist and the existing list-panel defaults.
Explicit defaults apply to the matching built-in title and command, before the
whitelist is considered. Defaults are resolved only when creating or replacing
a panel; cursor setup and opening or cancelling the panel chooser do not change
the user's choice.

Cache expensive, stable output such as symbols, imports, headers and file hashes.
Keep live debugger views uncached. Graphs and disassembly summaries invalidate
their cached output when the current function changes and auto update is enabled.
A cache hit reuses the stored output without executing the command or copying the
entire string.
