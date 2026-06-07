// SPDX-FileCopyrightText: 2026 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT
//
// cxx2: small, clean, dependency-light demanglers meant to replace the GNU
// libiberty demangler.
//
// Design goals:
//  - no mutable global state (everything lives in a parser context)
//  - bounded recursion (hard depth cap, no infinite-recursion footguns)
//  - one bulk allocation lifetime (node arena freed in a single pass)
//  - much smaller than the GNU/LLVM implementations
//
// The engines return a malloc'd C string on success, or NULL when the input is
// not a (recognized) mangled name, so callers can fall back gracefully.

#ifndef R2_CXX2_H
#define R2_CXX2_H

#ifdef __cplusplus
extern "C" {
#endif

// Core engines. Each takes the raw symbol (leading underscores optional) and
// returns a newly allocated demangled string, or NULL on failure.
char *r_demangle_arm(const char *mangled);      // __ct__1cFi (pre-Itanium ARM/cfront ABI)

#ifdef __cplusplus
}
#endif

#endif
