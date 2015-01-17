#ifndef DEMANGLER_H
#define DEMANGLER_H

#include "demangler_types.h"

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
///			eDemanglerErrUnkown
///////////////////////////////////////////////////////////////////////////////
EDemanglerErr init_demangler(SDemangler *demangler, char *sym);

///////////////////////////////////////////////////////////////////////////////
/// \brief Deallocate demangler object
/// \param demangler Demangler object that will be deallocated
/// \return Returns void
///////////////////////////////////////////////////////////////////////////////
void free_demangler(SDemangler *demangler);

#endif // DEMANGLER_H
