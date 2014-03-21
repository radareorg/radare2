#define R_API
#define R_ALLOC_USE_MMAP 1
#define USE_MALLOC 0

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>

#if USE_MALLOC
R_API void r_initmem(char *p, size_t s) { }
R_API void* r_malloc(size_t s) { return malloc (s); }
R_API void r_free(void *p) { free (s); }
#else

typedef
struct
{
	int is_available;
	int size;
} MCB, *MCB_P;


static char *mem_start_p;
static int max_mem;
static int allocated_mem; /* this is the memory in use. */
static int mcb_count;
static char *heap_end;

enum {NEW_MCB=0,NO_MCB,REUSE_MCB};
enum {FREE,IN_USE};

void InitMem(char *ptr, int size_in_bytes) {
	/* store the ptr and size_in_bytes in global variable */
	max_mem = size_in_bytes;
	mem_start_p = ptr;
	mcb_count = 0;
	allocated_mem = 0;
	heap_end = mem_start_p + size_in_bytes;
	memset (mem_start_p, 0x00, max_mem);
	/* This function is complete :-) */
}


R_API void *r_malloc(int elem_size) {
	/* check whether any chunk (allocated before) is free first */
	MCB_P p_mcb;
	int flag = NO_MCB;
	int sz;

	p_mcb = (MCB_P)mem_start_p;
	sz = sizeof(MCB);

	if ( (elem_size + sz) > (max_mem - (allocated_mem + mcb_count * sz ) ) )
		return NULL;
	while ( heap_end > ( (char *)p_mcb + elem_size + sz) ) {
		if (p_mcb->is_available == 0) {
			if (p_mcb->size == 0) {
				flag = NEW_MCB;
				break;
			}
			if (p_mcb->size >= (elem_size + sz) ) {
				flag = REUSE_MCB;
				break;
			}
		}
		p_mcb = (MCB_P) ( (char *)p_mcb + p_mcb->size);
	}

	if (flag != NO_MCB) {
		p_mcb->is_available = 1;

		if( flag == NEW_MCB) {
			p_mcb->size = elem_size + sizeof(MCB);
		} else if( flag == REUSE_MCB) {
			elem_size = p_mcb->size - sizeof(MCB);
		}
		mcb_count++;
		allocated_mem += elem_size;
		return ( (char *) p_mcb + sz);
	}
	return NULL;
}

void r_free(void *p) {
	/* Mark in MCB that this chunk is free */
	MCB_P ptr = (MCB_P)p;
	ptr--;

	if (ptr->is_available != FREE) {
		mcb_count--;
		ptr->is_available = FREE;
		allocated_mem -= (ptr->size - sizeof(MCB));
	 }
}
#endif


#if __MAIN__
int main() {
#define MB 7
#define R_MALLOC_MAX 1024*1024*MB

#if R_ALLOC_USE_STACK
	char B[R_MALLOC_MAX];
#endif
#if R_ALLOC_USE_MMAP
	int fd = open (".mem", O_CREAT|O_RDWR, 0600);
	ftruncate (fd, R_MALLOC_MAX);
	char *B = mmap (NULL, R_MALLOC_MAX, PROT_WRITE|PROT_READ,
		MAP_FILE|MAP_PRIVATE, fd, 0);
	unlink (".mem");
	close (fd);
#endif

//char *B = sbrk (1024*1024*MB);
	InitMem (B, R_MALLOC_MAX);

	char *a = r_malloc (1024);
	if (!a) {
		printf ("cant malloc\n");
		return 1;
	}
	strcpy (a, "hello");
	char *b = r_malloc (1024);
	strcpy (b, "world");
	printf ("%s %s\n", a, b);
	r_free (b);
	r_free (a);
	return 0;
}
#endif
