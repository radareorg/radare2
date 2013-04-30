/* Copyleft 2012 - sdb (aka SimpleDB) - pancake<nopcode.org> */

int test_parse_json_path() {
	Rangstr rs = rangstr_new ("ping.board[\"pop\"][1][2][\"caca\"].panda");
	json_path_first (&rs);
	do {
		printf (" - ");
		rangstr_print (&rs);
		printf (" Int (%d)", rangstr_int (&rs));
		printf ("\n");
	} while (json_path_next (&rs));
	printf ("--\n");
}
