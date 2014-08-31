#ifndef _TRANSPORT_H_
#define _TRANSPORT_H_

#include "r_types.h"

enum {
    E_OK = 0,
    E_TIMEOUT = -1,
    E_ERROR = -2,
    E_NOIF = -3,
};

typedef struct io_backend_t {
    const char *name;
    int (* init)(void);
    int (* deinit)(void);
    void *(* open)(const char *path);
    int (* close)(void *);
    int (* config)(void *, void *);
    int (* read)(void *, ut8 *buf, const ut64 count, const int timeout);
    int (* write)(void *, ut8 *buf, const ut64 count, const int timeout);
} io_backend_t;

int iob_select (const char *name);

void *iob_open (const char *path);
int iob_close (void *);
int iob_config (void *, void *);
int iob_write (void *fp, ut8 *buf, const ut32 buf_len);
int iob_read (void *fp, ut8 *buf, const ut32 buf_len);

#endif
