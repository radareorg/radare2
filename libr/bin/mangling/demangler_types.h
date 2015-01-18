#ifndef DEMANGLER_TYPES_H
#define DEMANGLER_TYPES_H

/// Enum of possible errors while demangler working
typedef enum EDemanglerErr {
	eDemanglerErrOK = 0, ///< if all is OK
	eDemanglerErrMemoryAllocation, ///< some memory allocation problem
	eDemanglerErrUnsupportedMangling, ///< unsupported mangling scheme yet
	eDemanglerErrUnkown, ///< unknown mangling scheme
	eDemanglerErrUncorrectMangledSymbol, ///< uncorrect mangled symbol
	eDemanglerErrMax
} EDemanglerErr;

struct SDemangler;
typedef EDemanglerErr (*demangle_func)(struct SDemangler *, char **res);

/// Demangler object
typedef struct SDemangler {
	char *symbol; ///< symbol that need to be demangled
	demangle_func demangle; ///< function that will use for demangling
} SDemangler;

#endif // DEMANGLER_TYPES_H
