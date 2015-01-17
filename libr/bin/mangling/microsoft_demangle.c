#include "microsoft_demangle.h"
#include <r_cons.h>

///////////////////////////////////////////////////////////////////////////////
EDemanglerErr microsoft_demangle(SDemangler *demangler, char **demangled_name)
{
	r_cons_printf("microsoft demangle\n");

	return eDemanglerErrUnsupportedMangling;
}
