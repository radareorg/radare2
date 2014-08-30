#include <r_cons.h>
// TWOK is a C implemnetation of 2048 game

#define ut8 unsigned char
static ut8 twok_buf[4][4];
static int score =0;
static int moves =0;
#define INTERNAL static

INTERNAL void twok_init() {
	int i, j;
	score = 0;
	for (i=0;i<4;i++)
		for (j=0;j<4;j++)
			twok_buf[i][j] = 0;
}

INTERNAL void twok_add() {
	int i, j;

	while (R_TRUE) {
		i = r_num_rand (4);
		j = r_num_rand (4);
		if (!twok_buf[i][j]) {
			twok_buf[i][j] = 1 + (r_num_rand (10) == 1);
			break;
		}
	}
}

INTERNAL int twok_fin() {
	int i,j;
	for (i=0;i<4;i++)
		for (j=0;j<4;j++)
			if (!twok_buf[i][j])
				return 1;
	for (i=0;i<4;i++)
		for (j=0;j<3;j++)
			if (twok_buf[i][j] == twok_buf[i][j+1])
				return 1;
	for (i=0;i<3;i++)
		for (j=0;j<4;j++)
			if (twok_buf[i][j] == twok_buf[i+1][j])
				return 1;
	return 0;
}

INTERNAL void twok_move(int u, int v) {
	int i, j, k;
	int nKI, nKJ, nIK, nJK;
	int moved = 0;
	for(k = 0; k < 4; ++k) {
		for(i = 0; i < 4; ++i) {
			for(j = i + 1; j < 4 && !twok_buf[nKJ = u?k:v?j:3-j][nJK = !u?k:v?j:3-j]; ++j) ;
			if(j == 4) continue;
			nKI= u?k:v?i:3-i;
			nIK= !u?k:v?i:3-i;
			if(!twok_buf[nKI][nIK]){
				twok_buf[nKI][nIK] = twok_buf[nKJ][nJK];
				twok_buf[nKJ][nJK] = 0;
				--i;
				moved = 1;
			}
			else if(twok_buf[nKI][nIK] == twok_buf[nKJ][nJK]) {
				score += 1 << ++twok_buf[nKI][nIK];
				twok_buf[nKJ][nJK] = 0;
				moved = 1;
			}
		}
	}
	if(moved) {
		twok_add ();
		moves++;
	}
}

INTERNAL void twok_print() {
	char val0[32];
	char val1[32];
	char val2[32];
	char val3[32];
	int i;
#define VAL(x) if (twok_buf[i][x]){\
	sprintf(val##x,"%4d",1<<twok_buf[i][x]); \
	} else strcpy(val##x, "    ");
	printf ("  +------+------+------+------+\n");
	for (i = 0; i<4; i++)  {
		VAL(0); VAL(1);
		VAL(2); VAL(3);
		printf ("  |      |      |      |      |\n");
		printf ("  | %s | %s | %s | %s |\n",
			val0,val1,val2,val3);
		printf ("  |      |      |      |      |\n");
		printf ("  +------+------+------+------+\n");
	}
	printf ("Hexboard:     'hjkl' and 'q'uit\n");
	for (i = 0; i<4; i++)
		printf ("  %02x %02x %02x %02x\n",
			twok_buf[i][0], twok_buf[i][1],
			twok_buf[i][2], twok_buf[i][3]);
}

R_API void r_cons_2048() {
	int ch;
	r_cons_set_raw (1);
	twok_init ();
	twok_add ();
	twok_add ();
	while (twok_fin()) {
		r_cons_clear00();
		r_cons_printf ("[r2048] score: %d   moves: %d\n",
			score, moves);
		r_cons_flush ();
		twok_print();
		ch = r_cons_readchar ();
		ch = r_cons_arrow_to_hjkl (ch);
		switch(ch){
		case 'h':
			twok_move(1,1);
			break;
		case 'j':
			twok_move(0,0);
			break;
		case 'k':
			twok_move(0,1);
			break;
		case 'l':
			twok_move(1,0);
			break;
		}
		if (ch<1||ch =='q') break;
	}
	r_cons_clear00();
	r_cons_printf ("[r2048] score: %d\n", score );
	r_cons_flush ();
	twok_print();
	r_cons_printf ("\n  [r2048.score] %d\n", score );
	r_cons_any_key ();
	r_cons_set_raw (0);
}
