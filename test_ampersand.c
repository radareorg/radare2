int main() {
	int a = &((1 << 7) >> 1);
	int b = a & (b >> 1);
	return 0;
}