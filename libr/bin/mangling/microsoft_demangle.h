#ifndef MICROSOFT_DEMANGLE_H
#define MICROSOFT_DEMANGLE_H

#include "demangler_types.h"

///////////////////////////////////////////////////////////////////////////////
/// \brief Do demangle for microsoft mangling scheme. Demangled name need to be
///			free by user
/// \param demangler 'this' object of demangler
/// \param demangled_name Demangled name of symbol of demangler object
/// \return Returns OK if initialization has been finish with success, else one
///			of next errors: eDemanglerErrUnsupportedMangling, ...
///////////////////////////////////////////////////////////////////////////////
EDemanglerErr microsoft_demangle(SDemangler *demangler, char **demangled_name);

#endif // MICROSOFT_DEMANGLE_H
