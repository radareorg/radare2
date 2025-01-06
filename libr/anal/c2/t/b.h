/// @pack(4)

/// @pack(2) @align(4)
struct Foo {
	int a;
	char name[20];
	/// @author(pancake)
	float var;
};

/// @noreturn
int foo(double age, char *name);

struct Bar {
	ut64 name;
	void *ptr;
};

/// @type(ut64)
enum Enum {
	FOO = 1,
	BAR,
	COW,
	LOW=-1
};
