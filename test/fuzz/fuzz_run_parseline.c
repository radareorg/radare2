#include <stdlib.h>
#include <string.h>
#include <r_types.h>
#include <r_socket.h>
#include <r_util/r_log.h>
#include <r_util/r_sys.h>
#include <r_util/r_sandbox.h>

#include "fuzz_common.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
	r_sys_clearenv ();
	r_sandbox_enable (true);
	r_sandbox_grain (R_SANDBOX_GRAIN_NONE);
	r_log_set_quiet (true);
	return 0;
}

int LLVMFuzzerTestOneInput(const ut8 *data, size_t len) {
	char *profile_text = rfuzz_strndup (data, len);
	char *line_text = rfuzz_strndup (data, len);
	if (!profile_text || !line_text) {
		free (profile_text);
		free (line_text);
		return 0;
	}
	rfuzz_normalize_text (profile_text, len, '\n');
	rfuzz_normalize_text (line_text, len, '\n');

	RRunProfile *p = r_run_new (NULL);
	if (p) {
		r_run_parse (p, profile_text);
		char *cur = line_text;
		while (cur) {
			char *next = strchr (cur, '\n');
			if (next) {
				*next++ = 0;
			}
			if (*cur) {
				r_run_parseline (p, cur);
			}
			cur = next;
		}
		r_run_free (p);
	}
	free (profile_text);
	free (line_text);
	r_sys_clearenv ();

	return 0;
}
