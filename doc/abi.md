# API/ABI/CMD Stability in R2

Since r2-6.0.0 the `ABI_VERSION` define avoid plugins built with different ABI
to be loaded to avoid segfaults.

ABI 165 removes `REsilCallbacks` and the `cb`/`ocb`/`ocb_set` fields of `REsil`
in favor of the explicit `REsilRegInterface`, `REsilMemInterface` and
`REsilUtilInterface` plus voyeurs for read-only observation. The trap-record
fields of `REsil` keep their offsets. Consumers of the old `cb` hooks must
layer their own interfaces or register voyeurs; rebuild external plugins
against these headers.

ABI 164 adds ESIL's full-width fault address and validity fields, the `REsilTrap`
snapshot type, and `r_esil_set_trap`/`r_esil_set_fault`/`r_esil_get_trap`/
`r_esil_restore_trap`. This explicitly versioned ABI extension changes `REsil`
and its embedding structures' sizes; rebuild external plugins against these
headers. Existing field offsets within `REsil` remain unchanged. See
[ESIL trap records](esil.md#trap-records-and-fault-addresses-abi-164).

ABI 163 guarantees `RAnalFunction.is_inline` and the
`r_anal_function_is_inline`/`r_anal_function_set_inline` accessors. External
decompilers such as r2ghidra can guard their future inline support with
`#if R2_ABIVERSION >= 163`.

## Introduction

Since r2-5.6.0 the development model has changed in order to provide a reliable
way to push updates without the need to recompile the plugins, tools and api
bindings.

In order to achieve this, the contributions need to follow some new rules in
order to be merged, so we ensure that binaries keep stable.

As it's said, odd version numbers are development versions that are only available
in `git` form. The releases are always an even number (0, 2, 4, 6, 8).

When `X.Y.9` is reached, it's time to merge all the pull requests tagged for
the next big release, the .9 versions are always the most unstable as they focus
on quick development in order to make all the breaking changes needed to
introduce new features or simplify the usage of some apis.

## Development rules

What you **CANNOT** do between X.Y.0 and X.Y.8:

* Add, Remove or rename public functions, structs or enums
* Change function signature (adding or removing arguments)
* Add, remove or reorder fields in structs
* Remove or change r2 commands (must be documented in release)

What you **CAN** do between X.Y.0 and X.Y.8:

* Remove global symbols (they shouldn't be accessed directly anyway)
* Change internal structs or functions (static)
* Refactor the programs (those are not libraries and dont expose apis)
* If you really need to add a new public function use `R2_XY0 static inline`
  * This way the function is inlined and no new symbols are exposed.
* Add new r2 commands
* Add, rename or remove plugins
* Extend r2 commands with new arguments, not breaking previous behaviour)
* Fix memleaks, race conditions, bugs, improve performance, usability, documentation, etc
* Add breaking code under `#if R2_XY0` to be removed when .9 arrives
* Use `R_DEPRECATE` to tag everything that will be removed when .9 is reached

What you **MUST** do in X.Y.9:

* Remove everything marked as `R_DEPRECATE` or `R2_XY0`. Use `git grep` to find them out
* Anything that was forbidden 

## CI

All this is checked in the CI with the `abidiff` utility.

[.github/workflows/build.yml#L607](../../94a31e97b868ead86d27031280ead2f5c64fecbd/.github/workflows/build.yml#L607)
