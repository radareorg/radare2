#include "../big.c"
 /*
#include "../big-ssl.c"
#include "../big-gmp.c"
 */

void main() {
	long long a, b, size;
	char *str;
	RNumBig *n1 = r_big_new();
	RNumBig *n2 = r_big_new();
	RNumBig *n3 = r_big_new();
	RNumBig *zero = r_big_new();

	r_big_from_int (n2, -2);
	r_big_from_hexstr (n3, "-0x3", 4);
printf ("n3->sign = %d\n", n3->sign);
printf ("%d %d\n", n3->array[0], n3->array[1]);
	r_big_mul (n2, n2, n3);
	str = r_big_to_hexstr (n2, &size);
printf ("n2 * n3 = %s(%d)\n", str, size);
	free(str);
printf("--\n");

	r_big_from_int (n1, 2);
	r_big_from_int (n2, 3);
	r_big_mul(n1, n1, n2);
	str = r_big_to_hexstr (n1, &size);
printf ("%s (%d)\n", str, size);
	free(str);

	r_big_from_int (n3, 923459999);
	r_big_mul (n1, n2, n3);
	r_big_mul (n2, n1, n3);
	r_big_mul (n1, n2, n3);
	str = r_big_to_hexstr (n1, &size);
printf ("%s (%d)\n", str, size);
	free(str);

	r_big_from_int (n2, 9999923459999999);
	r_big_from_int (n3, 9999992345999999);
	r_big_mul (n1, n2, n3);
	r_big_mul (n2, n1, n3);
	r_big_mul (n1, n2, n3);
	str = r_big_to_hexstr (n1, &size);
printf ("%s (%d)\n", str, size);
	free(str);

	while (scanf ("%ld %ld\n",&a,&b) != EOF) {
		printf("a = %ld    b = %ld\n",a,b);
		r_big_from_int (n1, a);
		r_big_from_int (n2, b);

		r_big_add (n3, n1, n2);
		str = r_big_to_hexstr (n3, &size);
		printf ("add %s (%d)\n", str, size);
		free(str);

		printf ("r_big_cmp a ? b = %d\n",r_big_cmp(n1, n2));

		r_big_sub (n3,n1,n2);
		str = r_big_to_hexstr (n3, &size);
		printf ("sub %s (%d)\n", str, size);
		free(str);

        r_big_mul (n3,n1,n2);
		str = r_big_to_hexstr (n3, &size);
		printf ("mul %s (%d)\n", str, size);
		free(str);

		r_big_from_int (zero, 0);
		if (r_big_cmp(zero, n2) == 0)
			printf("division -- NaN \n");
                else {
			r_big_div (n3,n1,n2);
		str = r_big_to_hexstr (n3, &size);
		printf ("div %s (%d)\n", str, size);
		free(str);
		}
		printf("--------------------------\n");
	}
}
