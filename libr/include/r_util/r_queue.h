#ifndef R_QUEUE_H
#define R_QUEUE_H

typedef struct r_queue_t {
	void **elems;
	unsigned int capacity;
	unsigned int front;
	int rear;
	unsigned int size;
} RQueue;

R_API RQueue *r_queue_new(int n);
R_API void r_queue_free(RQueue *q);
R_API int r_queue_enqueue(RQueue *q, void *el);
R_API void *r_queue_dequeue(RQueue *q);
R_API int r_queue_is_empty(RQueue *q);
#endif //  R_QUEUE_H
