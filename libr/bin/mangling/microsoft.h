#ifndef DEMANGLER_H
#define DEMANGLER_H
#include <r_types.h>
#include <r_list.h>

/// Enum of possible errors while demangler working
typedef enum EDemanglerErr {
	eDemanglerErrOK = 0, ///< if all is OK
	eDemanglerErrMemoryAllocation, ///< some memory allocation problem
	eDemanglerErrUnsupportedMangling, ///< unsupported mangling scheme yet
	eDemanglerErrUnknown, ///< unknown mangling scheme
	eDemanglerErrUncorrectMangledSymbol, ///< uncorrect mangled symbol
	eDemanglerErrMax
} EDemanglerErr;

struct SDemangler;
typedef EDemanglerErr (*demangle_func)(struct SDemangler *, char **res);
/// Demangler object
typedef struct SDemangler {
	char *symbol; ///< symbol that need to be demangled
	demangle_func demangle; ///< function that will use for demangling
	RList *abbr_types;
	RList *abbr_names;
} SDemangler;

///////////////////////////////////////////////////////////////////////////////
/// \brief Do demangle for microsoft mangling scheme. Demangled name need to be
///			free by user
/// \param demangler 'this' object of demangler
/// \param demangled_name Demangled name of symbol of demangler object
/// \return Returns OK if initialization has been finish with success, else one
///			of next errors: eDemanglerErrUnsupportedMangling, ...
///////////////////////////////////////////////////////////////////////////////
EDemanglerErr microsoft_demangle(SDemangler *demangler, char **demangled_name);

///////////////////////////////////////////////////////////////////////////////
// Usage of SDemangler:
// SDemangler *mangler = 0;
// char *demangled_name = 0;
// create_demangler(&mangler); // can be checked == eDemanlerErrMemoryAlloc...
// if (init_demangler(mangler, str) == eDemanglerErrOK) {
//	mangler->demangle(mangler, &demangled_name);
// }
// free_demangler(mangler);
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
/// \brief Create object of demangler.
/// \param demangler Object that will be created
/// \return Returns eDemangleErrOK if creating of object has been finish with
///			success, else - eDemanglerErrMemoryAllocation
///////////////////////////////////////////////////////////////////////////////
EDemanglerErr create_demangler(SDemangler **demangler);

///////////////////////////////////////////////////////////////////////////////
/// \brief Initialize object of demangler
/// \param demangler Object of demangler that will be initialized
/// \param sym Symbol that need to be demangled
/// \return Returns eDemangleErrOK if creating of object has been finish with
///			success, else one of next errors: eManglingUnsupported,
///			eDemanglerErrMemoryAllocation, eDemanglerErrUnsupportedMangling,
///			eDemanglerErrUnknown
///////////////////////////////////////////////////////////////////////////////
EDemanglerErr init_demangler(SDemangler *demangler, char *sym);

///////////////////////////////////////////////////////////////////////////////
/// \brief Deallocate demangler object
/// \param demangler Demangler object that will be deallocated
/// \return Returns void
///////////////////////////////////////////////////////////////////////////////
void free_demangler(SDemangler *demangler);

#endif // DEMANGLER_H
