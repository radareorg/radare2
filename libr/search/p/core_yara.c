/* radare - GPLv2 - Copyright 2014 jvoisin <julien.voisin@dustri.org> */

#include <r_core.h>

#include "yara.h"

#undef R_API
#define R_API static
#undef R_IPI
#define R_IPI static

static int show_offset = 0;
static int fast_scan = 0;
static int timeout = 0;

static int r_cmd_yara_call(void *user, const char *input);
static int r_cmd_yara_process(const RCore* core, const char* input);
static int callback(int message, YR_RULE* rule, void* data);

static int callback (int message, YR_RULE* rule, void* data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        eprintf ("%s\n", rule->identifier);
        if (show_offset) {
            const YR_STRING* string = rule->strings;
            while (!STRING_IS_NULL(string)) {
                if (STRING_FOUND (string)) {
                    YR_MATCH* match = STRING_MATCHES(string).head;
                    while (match != NULL) {
                        eprintf("\t0x%llx\n", match->offset);
                        match = match->next;
                    }
                }
                string++;
            }
            eprintf ("\n");
        }
    }
    return CALLBACK_CONTINUE;
}

static int r_cmd_yara_process(const RCore* core, const char* input) {
    YR_RULES* rules;
    YR_COMPILER* compiler;
    FILE* rules_file;
    void* buffer;
    int result;
    const unsigned int buffer_size = r_io_size (core->io);
    const char *rules_path = r_config_get (core->config, "yara.rules");

    if (buffer_size < 1) {
        eprintf ("Invalid file size\n");
        return 1;
    }

    if (!rules_path){
        eprintf ("Please set `yara.rules` in your radare2rc\n");
        return 1;
    }

    rules_file = fopen (rules_path, "r");
    if (!rules_file) {
        eprintf ("Unable to open the rules file\n");
        return 1;
    }

    yr_initialize ();

    if (yr_compiler_create (&compiler) != ERROR_SUCCESS) {
        eprintf ("Unable to create the yara compiler\n");
        yr_finalize ();
        return 1;
    }

    yr_compiler_push_file_name (compiler, rules_path);
    result = yr_compiler_add_file (compiler, rules_file, NULL);
    fclose (rules_file);
    if (result > 0) {
        yr_compiler_destroy (compiler);
        yr_finalize ();
        eprintf ("Something went wrong during the compilation of %s\n", rules_path);
        return result;
    }

    result = yr_compiler_get_rules (compiler, &rules);
    yr_compiler_destroy (compiler);
    if (result > 0) {
        yr_finalize ();
        eprintf ("Something went wrong during the import of %s\n", rules_path);
        return result;
    }

    buffer = malloc (buffer_size);
    if (!buffer) {
        eprintf ("Something went wrong during memory allocation\n");
        return 1;
    }
    result = r_io_read_at (core->io, 0L, buffer, buffer_size);
    if (!result) {
        eprintf ("Something went wrong during r_io_read_at\n");
        return result;
    }

    fast_scan = r_config_get_i (core->config, "yara.fast_scan");
    timeout = r_config_get_i (core->config, "yara.timeout");
    show_offset = r_config_get_i (core->config, "yara.offset");
    
    yr_rules_scan_mem (rules, buffer, buffer_size, callback, NULL, fast_scan, timeout);

    free (buffer);

    return 0;
}

static int r_cmd_yara_call(void *user, const char *input) {
    const RCore* core = (RCore*) user;
    if (!strncmp (input, "yara", 4)) {
        const char *args = input+4;
        if (*args) args++;
        r_cmd_yara_process (core, args);
        return R_TRUE;
    }
    return R_FALSE;
}

RCorePlugin r_core_plugin_yara = {
    .name = "yara",
    .desc = "YARA integration",
    .license = "LGPL",
    .call = r_cmd_yara_call,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_CORE,
    .data = &r_core_plugin_yara
};
#endif
