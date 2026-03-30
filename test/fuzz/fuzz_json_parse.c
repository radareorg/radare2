#include <r_types.h>
#include <r_util/r_json.h>
#include <r_util/r_log.h>

#include "fuzz_common.h"

int LLVMFuzzerInitialize(int *lf_argc, char ***lf_argv) {
	r_log_set_quiet (true);
	return 0;
}

int LLVMFuzzerTestOneInput(const ut8 *data, size_t len) {
	if (!len) {
		return 0;
	}
	char *text = rfuzz_strndup (data, len);
	if (!text) {
		return 0;
	}
	rfuzz_normalize_text (text, len, ' ');

	RJson *json = r_json_parseown (text);
	if (json) {
		if (json->type == R_JSON_OBJECT && json->children.first && json->children.first->key) {
			(void)r_json_get (json, json->children.first->key);
			(void)r_json_get_num (json, json->children.first->key);
			(void)r_json_get_str (json, json->children.first->key);
		}
		r_json_free (json);
	}
	free (text);
	return 0;
}
