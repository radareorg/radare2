static int run_statement (ServerState *ss, char *stmt, RCore *core) {
r_str_trim (stmt);
if (R_STR_ISEMPTY (stmt)) {
}
