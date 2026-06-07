// SPDX-FileCopyrightText: 2026 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT
//
// cxx2: a small, clean, dependency-light demangler for the Itanium C++ ABI,
// legacy IBM XL C++, Rust (legacy + v0) and D, meant to replace the GNU
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
char *r_demangle_itanium(const char *mangled);  // _Z...   (C++ Itanium ABI)
char *r_demangle_ibmxl(const char *mangled);    // foo__Fv (legacy IBM XL C++)
char *r_demangle_rust(const char *mangled);     // _R... (v0) or _ZN..E (legacy)
char *r_demangle_rust_v0(const char *mangled);  // _R...   (Rust v0 only)
char *r_demangle_dlang(const char *mangled);    // _D...   (D language)
char *r_demangle_gnu_v2(const char *mangled);   // foo__1Ai (pre-Itanium g++ ABI)
char *r_demangle_arm(const char *mangled);      // __ct__1cFi (pre-Itanium ARM/cfront ABI)

// Convenience dispatcher: sniffs the mangling scheme and routes accordingly.
char *r_demangle_cxx2(const char *mangled);

#ifdef __cplusplus
}
#endif

#endif
