/* radare - LGPL3 - Copyright 2016 - Matthieu (c0riolis) Tardy */

#ifndef MARSHAL_H
#define MARSHAL_H

#include <r_util.h>
#include <r_types.h>

typedef enum {
	TYPE_ASCII = 'a',
	TYPE_ASCII_INTERNED = 'A',
	TYPE_BINARY_COMPLEX = 'y',
	TYPE_BINARY_FLOAT = 'g',
	TYPE_CODE_v0 = 'C',
	TYPE_CODE_v1 = 'c',
	TYPE_COMPLEX = 'x',
	TYPE_DICT = '{',
	TYPE_ELLIPSIS = '.',
	TYPE_FALSE = 'F',
	TYPE_FLOAT = 'f',
	TYPE_FROZENSET = '>',
	TYPE_INT64 = 'I',
	TYPE_INTERNED = 't',
	TYPE_INT = 'i',
	TYPE_LIST = '[',
	TYPE_LONG = 'l',
	TYPE_NONE = 'N',
	TYPE_NULL = '0',
	TYPE_REF = 'r',
	TYPE_SET = '<',
	TYPE_SHORT_ASCII_INTERNED = 'Z',
	TYPE_SHORT_ASCII = 'z',
	TYPE_SMALL_TUPLE = ')',
	TYPE_STOPITER = 'S',
	TYPE_STRINGREF = 'R',
	TYPE_STRING = 's',
	TYPE_TRUE = 'T',
	TYPE_TUPLE = '(',
	TYPE_UNICODE = 'u',
	TYPE_UNKNOWN = '?',
} pyc_marshal_type;

typedef enum {
	FLAG_REF = '\x80',
} pyc_marshal_flag;

typedef struct {
	pyc_marshal_type type;
	void *data;
} pyc_object;

typedef struct {
	ut32 argcount;
	ut32 posonlyargcount;
	ut32 kwonlyargcount;
	ut32 nlocals;
	ut32 stacksize;
	ut32 flags;
	pyc_object *code;
	pyc_object *consts;
	pyc_object *names;
	pyc_object *varnames;
	pyc_object *freevars;
	pyc_object *cellvars;
	pyc_object *filename;
	pyc_object *name;
	ut32 firstlineno;
	pyc_object *lnotab;
	st64 start_offset;
	st64 end_offset;
} pyc_code_object;

// Per-parse context to avoid global variables.
// Created fresh for each parse operation (sections/symbols extraction).
typedef struct {
	ut32 magic;            // .pyc magic number
	ut32 scount;           // symbol ordinal counter
	RList *refs;           // ref table for FLAG_REF objects (internal to parse)
	RList *interned_table; // shared interned strings table
} PycUnmarshalCtx;

bool get_sections_symbols_from_code_objects(PycUnmarshalCtx *ctx, RBuffer *buffer, RList *sections, RList *symbols, RList *objs);
ut64 get_code_object_addr(RBuffer *buffer, ut32 magic);

#endif
