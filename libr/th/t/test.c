#include <r_th.h>


int looper(struct r_th_t *th)
{
	int i;
	int *ctr = th->user;
	for(i=0;i<9999;i++) {
		if (th->breaked)
			break;
		(*ctr)++;
		printf("loop %d\r", *ctr);
		fflush(stdout);
	}
	return 0; // do not loop
}

int test1()
{
	int ctr = 0;
	struct r_th_t *th;

	th = r_th_new (&looper, &ctr, 0);

	//r_th_start(th, R_TRUE);
	//sleep(1);
	while(r_th_wait_async(th)) {
		printf("\nwaiting...\n");
		fflush(stdout);
		usleep(400);
		//	r_th_break(th);
	}
	printf("\nfinished\n");
#if 0
	r_th_start(th, R_TRUE);
	sleep(1);
#endif
	/* wait and free */
	r_th_wait(th);
	r_th_free(th);

	printf("\nresult %d\n", ctr);
	return 0;
}

int main()
{
	return test1();
}
