#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <r_util/r_json.h>

int main() {
	// Create a JSON string
	char *json_str = strdup("{\"name\": \"test\", \"value\": 42}");

	printf("Original JSON string: %s\n", json_str);

	// Parse the JSON - parser now owns the string
	RJson *json = r_json_parse(json_str);

	if (!json) {
		printf("Failed to parse JSON\n");
		free(json_str);
		return 1;
	}

	// Now we can safely free the original string since parser owns it
	free(json_str);
	printf("Original string freed successfully\n");

	// Verify we can still access the parsed data
	const char *name = r_json_get_str(json, "name");
	st64 value = r_json_get_num(json, "value");

	printf("Parsed name: %s\n", name ? name : "NULL");
	printf("Parsed value: %lld\n", value);

	// Free the JSON structure (which should also free the owned string)
	r_json_free(json);
	printf("JSON structure freed successfully\n");

	return 0;
}