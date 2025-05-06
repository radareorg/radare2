#ifndef R_TYPES_NULL_H
#define R_TYPES_NULL_H

// TODO: use this new syntax instead: #define R_NONNULL(type) type * _Nonnull

// -Wno-nullability-completeness

#ifdef __clang__
#pragma clang diagnostic ignored "-Wnullability-completeness"
#endif

#if defined(__clang__)
  // Clang supports _Nonnull / _Nullable with -fnullability
  #if __has_feature(nullability)
    #define R_NONNULL _Nonnull
    #define R_NULLABLE _Nullable
// -Wnullability-completeness
  #else
    // Fallback for Clang without nullability feature
    #define R_NONNULL
    #define R_NULLABLE
  #endif

#elif defined(__GNUC__)
  // GCC does not support _Nonnull / _Nullable, fallback to nothing
  #define R_NONNULL
  #define R_NULLABLE

#else
  // Other compilers (MSVC, Intel, etc.)
  #define R_NONNULL
  #define R_NULLABLE
#endif

#if defined(__clang__) || defined(__GNUC__)
  // Attribute to mark whole functions as nonnull
  #define ATTR_NONNULL(...) __attribute__((nonnull(__VA_ARGS__)))
#else
  #define ATTR_NONNULL(...)
#endif

#endif // NULLABILITY_H
