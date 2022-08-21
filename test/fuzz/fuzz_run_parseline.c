#include <stdlib.h>
#include <string.h>
#include <r_types.h>
#include <r_socket.h>
#include <r_util/r_log.h>
#include <r_util/r_sys.h>
#include <r_util/r_sandbox.h>

int LLVMFuzzerInitialize(int *argc, char ***argv) {
	r_sys_clearenv ();
	r_sandbox_enable (true);
	r_sandbox_grain (R_SANDBOX_GRAIN_NONE);
	r_log_set_quiet (true);
	return 0;
}

int LLVMFuzzerTestOneInput(const ut8 *data, size_t len) {
	char *str = malloc (len + 1);
	memcpy (str, data, len);
	str[len] = 0;

	RRunProfile *p = r_run_new (NULL);
	r_run_parseline (p, str);
	free (str);
	r_run_free (p);
	r_sys_clearenv ();

	return 0;
}
