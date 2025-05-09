/* radare2 - LGPL - Copyright 2008-2022 - pancake */

#include <r_cons.h>

typedef struct game_state_t {
	ut8 twok_buf[4][4];
	int score;
	int moves;
} GameState;


static void twok_init(GameState *state) {
	memset (state, 0, sizeof (GameState));
}

static void twok_add(GameState *state) {
	int i, j;
	while (true) {
		i = r_num_rand (4);
		j = r_num_rand (4);
		if (!state->twok_buf[i][j]) {
			state->twok_buf[i][j] = 1 + (r_num_rand (10) == 1);
			break;
		}
	}
}

static bool twok_fin(GameState *state) {
	int i, j;
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			if (!state->twok_buf[i][j]) {
				return true;
			}
		}
	}
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 3; j++) {
			if (state->twok_buf[i][j] == state->twok_buf[i][j + 1]) {
				return true;
			}
		}
	}
	for (i = 0; i < 3; i++) {
		for (j = 0; j < 4; j++) {
			if (state->twok_buf[i][j] == state->twok_buf[i + 1][j]) {
				return true;
			}
		}
	}
	return false;
}

static void twok_move(GameState *state, int u, int v) {
	int i, j, k;
	int nKI = 0, nKJ = 0, nIK = 0, nJK = 0;
	int moved = 0;
	for (k = 0; k < 4; k++) {
		for (i = 0; i < 4; i++) {
			for (j = i + 1; j < 4 && !state->twok_buf[nKJ = u ? k : v ? j : 3 - j][nJK = !u ? k : v ? j : 3 - j]; j++) {
				;
			}
			if (j == 4) {
				continue;
			}
			nKI = u? k: v? i: 3 - i;
			nIK = !u? k: v? i: 3 - i;
			if (!state->twok_buf[nKI][nIK]) {
				state->twok_buf[nKI][nIK] = state->twok_buf[nKJ][nJK];
				state->twok_buf[nKJ][nJK] = 0;
				--i;
				moved = 1;
			} else if (state->twok_buf[nKI][nIK] == state->twok_buf[nKJ][nJK]) {
				state->score += 1 << ++state->twok_buf[nKI][nIK];
				state->twok_buf[nKJ][nJK] = 0;
				moved = 1;
			}
		}
	}
	if (moved) {
		twok_add (state);
		state->moves++;
	}
}

static void getval(GameState *state, bool color, char *val0, int i, int x) {
	const char * colorarray[] = {
		Color_WHITE,
		Color_RED,
		Color_GREEN,
		Color_MAGENTA,
		Color_YELLOW,
		Color_CYAN,
		Color_BLUE,
		Color_GRAY
	};
	if (state->twok_buf[i][x]) {
		if (color) {
			snprintf (val0, 31, "%s%4d"Color_RESET, colorarray [state->twok_buf [i][x] % 8 ], 1 << state->twok_buf[i][x]);
		} else {
			snprintf (val0, 31, "%4d", 1 << state->twok_buf[i][x]);
		}
	} else {
		strcpy (val0, "    ");
	}
}

static void twok_print(GameState *state, bool color) {
	char val0[32];
	char val1[32];
	char val2[32];
	char val3[32];
	int i;
	if (color) {
		printf (Color_BBLUE"  +------+------+------+------+\n");
	} else {
		printf ("  +------+------+------+------+\n");
	}
	for (i = 0; i < 4; i++) {
		getval (state, color, val0, i, 0);
		getval (state, color, val1, i, 1);
		getval (state, color, val2, i, 2);
		getval (state, color, val3, i, 3);
		if (color) {
			printf (Color_BBLUE"  |      |      |      |      |\n");
			printf ("  |"Color_RESET" %s "Color_BBLUE"|"Color_RESET" %s "
				Color_BBLUE"|"Color_RESET" %s "Color_BBLUE"|"Color_RESET" %s "Color_BBLUE"|\n",
				val0, val1, val2, val3);
			printf ("  |      |      |      |      |\n");
			printf ("  +------+------+------+------+\n"Color_RESET);
		} else {
			printf ("  |      |      |      |      |\n");
			printf ("  | %s | %s | %s | %s |\n",
				val0, val1, val2, val3);
			printf ("  |      |      |      |      |\n");
			printf ("  +------+------+------+------+\n");
		}
	}
	printf ("Hexboard:     'hjkl' and 'q'uit\n");
	for (i = 0; i < 4; i++) {
		printf ("  %02x %02x %02x %02x\n",
			state->twok_buf[i][0], state->twok_buf[i][1],
			state->twok_buf[i][2], state->twok_buf[i][3]);
	}
}

R_API void r_cons_2048(bool color) {
	RCons *cons = r_cons_singleton ();
	GameState state;
	int ch;
	r_kons_set_raw (cons, 1);
	twok_init (&state);
	twok_add (&state);
	twok_add (&state);
	while (twok_fin (&state)) {
		r_cons_clear00 ();
		if (color) {
			r_cons_printf (Color_GREEN"[r2048]"Color_BYELLOW" score: %d   moves: %d\n"Color_RESET, state.score, state.moves);
		} else {
			r_cons_printf ("[r2048] score: %d   moves: %d\n", state.score, state.moves);
		}
		r_cons_flush ();
		twok_print (&state, color);
		ch = r_cons_readchar (cons);
		ch = r_cons_arrow_to_hjkl (ch);
		switch (ch) {
		case 'h':
			twok_move (&state, 1, 1);
			break;
		case 'j':
			twok_move (&state, 0, 0);
			break;
		case 'k':
			twok_move (&state, 0, 1);
			break;
		case 'l':
			twok_move (&state, 1, 0);
			break;
		}
		if (ch < 1 || ch == 'q') {
			break;
		}
	}
	r_cons_clear00 ();
	r_cons_printf ("[r2048] score: %d\n", state.score);
	r_cons_flush ();
	twok_print (&state, color);

	r_cons_printf ("\n  [r2048.score] %d\n", state.score);
	do {
		ch = r_cons_any_key ("Press 'q' to quit.");
	} while (ch != 'q' && ch >= 1);
	r_cons_set_raw (0);
}
