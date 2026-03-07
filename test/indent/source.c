#include "header.h"
#include <r_types.h>
#include <stdio.h>
#include <stdlib.h>

// Simple function implementation
void simple_function(void) {
	printf ("Hello, World!\n");
}

int function_with_args(int a, char *b, ut64 c) {
	if (a < 0) {
		return -1;
	}
	if (b != NULL) {
		printf ("%s\n", b);
	}
	return (int) (c & 0xFFFFFFFF);
}

char *function_with_return(int x, int y) {
	if (x > y) {
		return "x is greater";
	} else if (x < y) {
		return "y is greater";
	}
	return "equal";
}

void function_with_long_params(int a, int b, int c, int d, int e, int f, int g) {
	int sum = a + b + c + d + e + f + g;
	printf ("Sum: %d\n", sum);
}

// Callback implementations
int callback_handler(int a, int b) {
	return a + b;
}

void data_handler(void *data, ut32 size) {
	if (data == NULL) {
		return;
	}
	ut8 *buf = (ut8 *)data;
	for (ut32 i = 0; i < size; i++) {
		printf ("%02x", buf[i]);
	}
	printf ("\n");
}

// Switch statement implementation
typedef enum {
	TYPE_A,
	TYPE_B,
	TYPE_C
} TypeEnum;

void process_type(TypeEnum type) {
	switch (type) {
	case TYPE_A:
		printf ("Type A\n");
		break;
	case TYPE_B:
		printf ("Type B\n");
		break;
	case TYPE_C:
		printf ("Type C\n");
		break;
	default:
		printf ("Unknown type\n");
		break;
	}
}

// Complex ternary usage
int clamp_value(int val, int min, int max) {
	return val < min? min: (val > max? max: val);
}

int sign_value(int x) {
	return x < 0? -1: (x > 0? 1: 0);
}

// Nested struct operations
void process_nested(NestedStruct *ns) {
	if (ns == NULL) {
		return;
	}
	printf ("Count: %d, Name: %s\n", ns->count, ns->name);
	if (ns->u.value32 > 0) {
		printf ("Value32: %u\n", ns->u.value32);
	} else {
		printf ("Value64: %" PFMT64u "\n", ns->u.value64);
	}
}

// Vector operations
Vector vector_add(Vector a, Vector b) {
	Vector result;
	result.a = a.a + b.a;
	result.b = a.b + b.b;
	return result;
}

// Point operations
Point point_create(int x, int y) {
	Point p;
	p.x = x;
	p.y = y;
	return p;
}

int point_distance(Point *a, Point *b) {
	if (a == NULL || b == NULL) {
		return 0;
	}
	int dx = a->x - b->x;
	int dy = a->y - b->y;
	return dx * dx + dy * dy;
}

// State machine
void run_state_machine(StateEnum state) {
	switch (state) {
	case STATE_IDLE:
		printf ("Idle\n");
		break;
	case STATE_RUNNING:
		printf ("Running\n");
		break;
	case STATE_STOPPED:
		printf ("Stopped\n");
		break;
	}
}

// Main function with test cases
int main(int argc, char **argv) {
	(void)argc;
	(void)argv;

	// Test simple function
	simple_function ();

	// Test function with args
	int result = function_with_args (42, "test", 0x12345678);
	printf ("Result: %d\n", result);

	// Test ternary
	int clamped = clamp_value (15, 0, 10);
	printf ("Clamped: %d\n", clamped);

	// Test struct
	Point p = point_create (10, 20);
	printf ("Point: (%d, %d)\n", p.x, p.y);

	// Test vector
	Vector v1 = { 1, 2 };
	Vector v2 = { 3, 4 };
	Vector v3 = vector_add (v1, v2);
	printf ("Vector sum: (%u, %" PFMT64u ")\n", v3.a, v3.b);

	// Test state machine
	run_state_machine (STATE_RUNNING);

	// Test switch
	process_type (TYPE_B);

	return 0;
}
