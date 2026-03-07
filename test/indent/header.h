enum Foo {
	This,
	One,
	Comba,
	Rula
};

struct Bar {
	int x;
	char y;
};

typedef struct {
	ut32 a;
	ut64 b;
} Vector;

typedef struct Point {
	int x;
	int y;
} Point;

typedef enum {
	STATE_IDLE,
	STATE_RUNNING,
	STATE_STOPPED
} StateEnum;

typedef struct nested_struct_t {
	int count;
	char *name;
	union {
		ut32 value32;
		ut64 value64;
	} u;
	struct {
		int width;
		int height;
	} dimensions;
} NestedStruct;

union DataUnion {
	int i;
	float f;
	char c[4];
};

enum {
	VALUE_A = 1,
	VALUE_B = 2,
	VALUE_C = 3
};

R_PACKED(struct packed_struct_t) {
	ut8 a;
	ut16 b;
	ut32 c;
};

// Function declarations with various styles
void simple_function(void);
int function_with_args(int a, char *b, ut64 c);
char *function_with_return(int x, int y);
void function_with_long_params(int a, int b, int c, int d, int e, int f, int g);

// Function pointer declarations
typedef int(*callback_t)(int a, int b);
typedef void(*handler_t)(void *data, ut32 size);

// Macros with various constructs
#define SIMPLE_MACRO 42
#define MACRO_WITH_PARAMS(x) ((x) * 2)
#define MACRO_WITH_MULTILINE(x, y) \
	do { \
		int z = (x) + (y); \
		printf ("%d\n", z); \
	} while (0)
#define R_PACKED(x) __attribute__((packed)) x

// Ternary operators
int value = cond? a: b;
int complex = x > y? (a < b? c: d): (e > f? g: h);

// Switch case with R2 style (case labels at same indent as switch)
switch(type) {
case TYPE_A:
	do_something_a ();
	break;
case TYPE_B:
	do_something_b ();
	break;
default:
	do_default ();
	break;
}

// Switch case with braces
switch(value) {
case 0:
	{
		int local = 0;
		process (local);
		break;
	}
case 1:
	{
		int local = 1;
		process (local);
		break;
	}
case 2:
	process (3);
	break;
default:
	break;
}

void function() {
	// If statements with braces
	if (condition) {
		do_thing ();
	}

	if (a && b) {
		do_thing ();
	}

	if (a || b) {
		do_thing ();
	}

	// For loops
	for (i = 0; i < count; i++) {
		process (i);
	}

	// While loops
	while (condition) {
		do_thing ();
	}

	// Do-while
	do {
		iteration++;
	} while (iteration < max);

	// Goto labels
	goto cleanup;

cleanup:
	free (ptr);
	return result;
}

void another_function() {
	// Struct member access
	ptr->member = value;
	struct_var.member = value;
	array[i].field = value;

	// Complex expressions
	result = (a + b) *(c - d) / e;
	result = func (a, b, c) + func2 (d, e);
	result = !cond? x: y;
	result = (ptr != NULL)? ptr->value: 0;

	// String concatenation
	const char *str =
		"This is a very long string"
		" that continues on the next line"
		" with proper indentation.";

	// Multi-dimensional array access
	matrix[i][j] = value;
	data[row * cols + col] = value;

	// Bitwise operations
	flags |= FLAG_A;
	flags &= ~FLAG_B;
	flags ^= FLAG_C;
	mask = (1 << n) - 1;
}

// Comments
// Single line comment
int x = 0; /* inline comment */

/* Multi-line comment
 * spanning multiple lines
 * with proper indentation
 */

// Preprocessor directives
#ifdef FEATURE_X
int feature_x = 1;
#else
int feature_x = 0;
#endif

#if defined(OS_LINUX) && defined(ARCH_X86)
void platform_specific(void);
#elif defined(OS_MACOS)
void platform_specific_macos(void);
#else
void platform_generic(void);
#endif

// Complex macro definitions
#define MIN(a, b) ((a) < (b)? (a): (b))
#define MAX(a, b) ((a) > (b)? (a): (b))
#define CLAMP(x, low, high) (MIN (MAX (x, low), high))

// Function-like macros with statements
#define SAFE_FREE(p) \
	do { \
		if (p) { \
			free (p); \
			p = NULL; \
		} \
	} while (0)

#define R_NEW0(type) (type *)calloc (1, sizeof (type))

// Enums with explicit values
enum named_enum_t {
	VALUE_FIRST = 0,
	VALUE_SECOND = 10,
	VALUE_THIRD = 20,
	VALUE_LAST = 100
};

// Bitfield enums
enum flags_t {
	FLAG_READ = 1 << 0,
	FLAG_WRITE = 1 << 1,
	FLAG_EXEC = 1 << 2,
	FLAG_ALL = (FLAG_READ | FLAG_WRITE | FLAG_EXEC)
};

// Anonymous enums/structs in typedefs
typedef enum {
	OPTION_A = 'a',
	OPTION_B = 'b',
	OPTION_C = 'c'
} Options;

// Nested function calls
result = func(func2(func3(a, b), c), d);

// Array initialization
int counts[] = { 1, 2, 3, 4, 5 };
char *names[] = { "foo", "bar", "baz" };

// Struct initialization
struct Point p = {
	.x = 10,
	.y = 20
};

// Pointer arithmetic
value = *ptr++;
value = *++ptr;
value = ptr[0] + ptr[1];

// Complex declarations
int(*func_ptr_array[10])(int a, int b);
int **matrix_ptr;
char ***triple_ptr;

// Volatile and const
volatile int counter;
const char *const_str;
char *const const_ptr = buf;
const volatile ut32 *const hw_reg;

// R2R test comment reference
// R2R test/db/cmd/cmd_je

// Inline assembly markers
#if defined(__x86_64__)
__asm__ volatile ("nop");
#endif

// Deep nested structs (triple nesting)
typedef struct triple_nested_t {
	ut32 id;
	union {
		struct {
			union {
				ut8 level3;
			} inner;
		} middle;
		ut64 alternative;
	} outer;
} TripleNested;

// Struct with trailing array
typedef struct {
	ut32 count;
	ut32 data[];
} FlexibleArray;

// Multiple function pointers in struct
typedef struct callback_table_t {
	int (*init) (void *ctx);
	void (*process) (void *ctx, ut8 *data, ut32 len);
	void (*fini) (void *ctx);
	int (*validate) (const ut8 *buf, ut32 size);
} CallbackTable;

// Struct with bitfields
typedef struct bitfield_struct_t {
	ut32 enabled : 1;
	ut32 mode : 3;
	ut32 flags : 4;
	ut32 reserved : 24;
} BitfieldStruct;

// Enum with trailing comma
typedef enum {
	ALPHA,
	BETA,
	GAMMA,
} TrailingCommaEnum;

// Complex nested anonymous union in struct
typedef struct {
	ut32 type;
	union {
		struct {
			ut32 x;
			ut32 y;
			ut32 w;
			ut32 h;
		};
		ut64 packed;
	};
} BoundingBox;

// Struct with flexible array and nested members
typedef struct {
	ut32 magic;
	ut32 version;
	union {
		struct {
			ut16 major;
			ut16 minor;
		} ver;
		ut32 raw;
	};
	ut32 count;
	ut8 buffer[];
} HeaderStruct;

// Function with complex return type and attributes
__attribute__((malloc)) void *R_ALLOCATED alloc_buffer (ut32 size) __attribute__((warn_unused_result));

// Macro with variadic arguments
#define LOG_DEBUG(fmt, ...) \
	r_log ("%s:%d " fmt, __FILE__, __LINE__, ## __VA_ARGS__)

// Macro with stringification
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

// Macro with token pasting
#define CONCAT(a, b) a ## b
#define CONCAT3(a, b, c) a ## b ## c

// Do-while macro with multiple statements
#define SWAP(a, b) \
	do { \
		typeof (a) _tmp = (a); \
		(a) = (b); \
		(b) = _tmp; \
	} while (0)

// Complex ternary in macro
#define ABS(x) ((x) < 0? - (x): (x))
#define SIGN(x) ((x) < 0? -1: ((x) > 0? 1: 0))

// Multiple levels of indirection
void triple_pointer(int ***matrix);
void quad_pointer(char ****grid);

// Static inline function
static inline ut32 get_u32_le(const ut8 *buf) {
	return buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
}

// Function with sentinel parameter
void variadic_with_sentinel(const char *fmt, ...) __attribute__((sentinel));

// Const correctness examples
const char *get_const_string(void);
char *get_mutable_string(void);
const char *const get_const_ptr_const_string(void);

// Restrict pointer
void copy_buffer(const char *restrict src, char *restrict dst, ut32 len);

// Alignas and alignment attributes
typedef struct {
	ut8 data[16];
} R_ALIGNED (16) AlignedData;

// Nested struct with same name as outer (shadowing test)
struct Outer {
	int value;
	struct Inner {
		int value;
		int other;
	} inner;
};

// Anonymous struct in union
typedef union {
	struct {
		ut8 r;
		ut8 g;
		ut8 b;
		ut8 a;
	};
	ut32 rgba;
} Color;

// Struct initialization with nested braces
struct {
	int a;
	struct {
		int x;
		int y;
	} point;
} compound = { 1, { 2, 3 } };

// Designated initialization with arrays
int array_init[] = {
	[0] = 1,
	[5] = 10,
	[10] = 100,
};

// Complex preprocessor nesting
#ifdef FEATURE_A
#ifdef SUBFEATURE_A1
#define MODE 1
#else
#define MODE 2
#endif
#else
#define MODE 0
#endif

// Line continuation in macro
#define LONG_MACRO(a, b, c, d, e, f) \
	((a) + (b) + \
		(c) + (d) + \
		(e) + (f))

// Empty initializer
typedef struct {
	ut32 count;
	ut8 data[1];
} EmptyInit;

EmptyInit empty = { 0 };

// Compound literal
void use_compound(void) {
	int *ptr = (int[]){ 1, 2, 3, 4, 5 };
	(void)ptr;
}

// GNU statement expression
#define MAX_SAFE(a, b) ({ \
	typeof (a) _a = (a); \
	typeof (b) _b = (b); \
	(_a > _b)? _a: _b; \
})

// Attribute packed with explicit packing
typedef struct {
	ut8 a;
	ut16 b;
	ut32 c;
} R_PACKED (PackedExplicit);

// Deprecated attribute
__attribute__((deprecated)) void old_function (void);

// Format attribute
void log_message(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

// NoReturn attribute
void fatal_error(const char *msg) __attribute__((noreturn));

// Weak symbol
__attribute__((weak)) void weak_function (void);

// Pure and const functions
__attribute__((pure))
ut32
compute_hash(const void *data, ut32 len);

__attribute__((const))
ut32
square(ut32 x);

// Unused variable marker
void use_params(int argc, char **argv) {
	(void)argc;
	(void)argv;
}

// Fallthrough attribute
switch(value) {
case 0:
case 1:
	__attribute__((fallthrough));
case 2:
	do_thing ();
	break;
}

// Complex array declarators
int(*array_of_func_ptrs[10])(int, int);
int(*(*variable))[10];

// Thread local storage
_Thread_local int thread_var;

// Static assertions
_Static_assert (sizeof (ut32) == 4, "ut32 must be 4 bytes");
_Static_assert (sizeof (ut64) == 8, "ut64 must be 8 bytes");

// Complex pointer to array
int(*ptr_to_array)[10];

// Restrict with const
void process_data(const ut8 *restrict data, ut32 size);

// Inline assembly with clobbers
static inline void memory_barrier(void) {
	__asm__ volatile ("" ::: "memory");
}
