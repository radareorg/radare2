/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2011
 * Phillip Lougher <phillip@lougher.demon.co.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * action.h
 */

/*
 * Lexical analyser definitions
 */
#define TOK_WHITE_SPACE		0
#define TOK_OPEN_BRACKET	1
#define TOK_CLOSE_BRACKET	2
#define TOK_AND			3
#define TOK_OR			4
#define TOK_NOT			5
#define TOK_COMMA		6
#define TOK_AT			7
#define TOK_STRING		8
#define TOK_EOF			9

#define TOK_TO_STR(OP, S) ({ \
	char *s; \
	switch(OP) { \
	case TOK_EOF: \
		s = "EOF"; \
		break; \
	case TOK_STRING: \
		s = S; \
		break; \
	default: \
		s = token_table[OP].string; \
		break; \
	} \
	s; \
})


struct token_entry {
	char *string;
	int token;
	int size;
};

/*
 * Expression parser definitions
 */
#define OP_TYPE			0
#define ATOM_TYPE		1
#define UNARY_TYPE		2

#define SYNTAX_ERROR(S, ARGS...) { \
	char *src = strdup(source); \
	src[cur_ptr - source] = '\0'; \
	printf("Failed to parse action \"%s\"\n", source); \
	printf("Syntax error: "S, ##ARGS); \
	printf("Got here \"%s\"\n", src); \
}

struct expr;

struct expr_op {
	struct expr *lhs;
	struct expr *rhs;
	int op;
};


struct atom {
	struct test_entry *test;
	char **argv;
	void *data;
};


struct unary_op {
	struct expr *expr;
	int op;
};


struct expr {
	int type;
	union {
		struct atom atom;
		struct expr_op expr_op;
		struct unary_op unary_op;
	};
};

/*
 * Test operation definitions
 */
#define NUM_EQ		1
#define NUM_LESS	2
#define NUM_GREATER	3

struct test_number_arg {
	long long size;
	int range;
};

struct test_range_args {
	long long start;
	long long end;
};

struct action;
struct action_data;

struct test_entry {
	char *name;
	int args;
	int (*fn)(struct atom *, struct action_data *);
	int (*parse_args)(struct test_entry *, struct atom *);
};


/*
 * Type test specific definitions
 */
struct type_entry {
	int value;
	char type;
};


/*
 * Action definitions
 */
#define FRAGMENT_ACTION 0
#define EXCLUDE_ACTION 1
#define FRAGMENTS_ACTION 2
#define NO_FRAGMENTS_ACTION 3
#define ALWAYS_FRAGS_ACTION 4
#define NO_ALWAYS_FRAGS_ACTION 5
#define COMPRESSED_ACTION 6
#define UNCOMPRESSED_ACTION 7
#define UID_ACTION 8
#define GID_ACTION 9
#define GUID_ACTION 10
#define MODE_ACTION 11
#define EMPTY_ACTION 12

/*
 * Define what file types each action operates over
 */
#define ACTION_DIR S_IFDIR
#define ACTION_REG S_IFREG
#define ACTION_ALL_LNK (S_IFDIR | S_IFREG | S_IFBLK | S_IFCHR | S_IFSOCK | \
			S_IFIFO | S_IFLNK)
#define ACTION_ALL (S_IFDIR | S_IFREG | S_IFBLK | S_IFCHR | S_IFSOCK | S_IFIFO)

struct action_entry {
	char *name;
	int type;
	int args;
	int file_types;
	int (*parse_args)(struct action_entry *, int, char **, void **);
	void (*run_action)(struct action *, struct dir_ent *);
};


struct action_data {
	int depth;
	char *name;
	char *pathname;
	struct stat *buf;
};


struct action {
	int type;
	struct action_entry *action;
	int args;
	char **argv;
	struct expr *expr;
	void *data;
};


/*
 * Uid/gid action specific definitions
 */
struct uid_info {
	uid_t uid;
};

struct gid_info {
	gid_t gid;
};

struct guid_info {
	uid_t uid;
	gid_t gid;
};


/*
 * Mode action specific definitions
 */
#define ACTION_MODE_SET 0
#define ACTION_MODE_ADD 1
#define ACTION_MODE_REM 2
#define ACTION_MODE_OCT 3

struct mode_data {
	struct mode_data *next;
	int operation;
	int mode;
	unsigned int mask;
	char X;
};


/*
 * Empty action specific definitions
 */
#define EMPTY_ALL 0
#define EMPTY_SOURCE 1
#define EMPTY_EXCLUDED 2

struct empty_data {
	int val;
};


/*
 * External function definitions
 */
extern int parse_action(char *);
extern void dump_actions(void);
extern void *eval_frag_actions(struct dir_ent *);
extern void *get_frag_action(void *);
extern int eval_exclude_actions(char *, char *, struct stat *, int);
extern void eval_actions(struct dir_ent *);
extern int eval_empty_actions(char *, char *, struct stat *, int,
							struct dir_info *);
