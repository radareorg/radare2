/* radare - LGPL - Copyright 2007-2015 - ret2libc */

#include <r_util.h>

R_API RQueue *r_queue_new (int n) {
	if (n <= 0) {
		return NULL;
	}
	RQueue *q = R_NEW0 (RQueue);
	if (!q) {
		return NULL;
	}
	q->elems = R_NEWS0 (void *, n);
	if (!q->elems){
		free (q);
		return NULL;
	}
	q->front = 0;
	q->rear = -1;
	q->size = 0;
	q->capacity = n;
	return q;
}

R_API void r_queue_free(RQueue *q) {
	free (q->elems);
	free (q);
}

static int is_full(RQueue *q) {
	 return q->size == q->capacity;
}

static int increase_capacity(RQueue *q) {
	unsigned int new_capacity = q->capacity * 2;
	void **newelems;
	int i, tmp_front;

	newelems = R_NEWS0(void *, new_capacity);
	if (!newelems) {
		return false;
	}

	i = -1;
	tmp_front = q->front;
	while (i + 1 < q->size) {
		i++;
		newelems[i] = q->elems[tmp_front];
		tmp_front = (tmp_front + 1) % q->capacity;
	}

	free (q->elems);
	q->elems = newelems;
	q->front = 0;
	q->rear = i;
	q->capacity = new_capacity;
	return true;
}

R_API int r_queue_enqueue(RQueue *q, void *el) {
	if (is_full(q)) {
		int res = increase_capacity (q);
		if (!res) {
			return false;
		}
	}

	q->rear = (q->rear + 1) % q->capacity;
	q->elems[q->rear] = el;
	q->size++;
	return true;
}

R_API void *r_queue_dequeue(RQueue *q) {
	void *res;

	if (r_queue_is_empty (q)) {
		return NULL;
	}
	res = q->elems[q->front];
	q->front = (q->front + 1) % q->capacity;
	q->size--;
	return res;
}

R_API int r_queue_is_empty(RQueue *q) {
	return q->size == 0;
}
