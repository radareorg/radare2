#ifndef _TRANSPORT_H_
#define _TRANSPORT_H_

#include <stdint.h>

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
    int (* read)(void *, uint8_t *buf, const uint64_t count, const int timeout);
    int (* write)(void *, const uint8_t *buf, const uint64_t count, const int timeout);
} io_backend_t;

int iob_select (const char *name);

void *iob_open (const char *path);
int iob_close (void *);
int iob_config (void *, void *);
int iob_write (void *fp, const uint8_t *buf, const uint32_t buf_len);
int iob_read (void *fp, uint8_t *buf, const uint32_t buf_len);

#endif
