enum Bar {
	COW=123
};
enum Cow {
	LOW=123
};
struct foo { char gap;int bar __attribute__((__aligned__(4))); };
enum Row {
	ROW=123
};
// struct foo3 {char gap3[3];int ubar __attribute__((__aligned__(4)));};
