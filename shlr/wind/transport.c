#include <r_util.h>
#include "transport.h"

extern io_backend_t iob_pipe;

static io_backend_t *io_backends[] = {
    &iob_pipe,
    NULL,
};

static io_backend_t *sel_backend = NULL;

int iob_select (const char *name) {
    io_backend_t *iob;

    iob = io_backends[0];
    
    if (!iob)
        return R_FALSE;

    if (sel_backend && sel_backend->deinit)
        sel_backend->deinit();

    sel_backend = iob;

    if (sel_backend->init)
        sel_backend->init();

    return R_TRUE;
}

void *iob_open (const char *path) {
    if (!sel_backend)
        return NULL;
    return sel_backend->open(path);
}

int iob_close (void *fp) {
    if (!sel_backend)
        return E_NOIF;
    return sel_backend->close(fp);
}

int iob_config (void *fp, void *cfg) {
    if (!sel_backend)
        return E_NOIF;
    return sel_backend->config(fp, cfg);
}

int iob_write (void *fp, ut8 *buf, const ut32 buf_len) {
    ut32 done;

    if (!sel_backend)
        return E_NOIF;

    for (done = 0; done < buf_len;)
        done += sel_backend->write(fp, buf + done, buf_len - done, 100);

    return done;
}

int iob_read (void *fp, ut8 *buf, const ut32 buf_len) {
    ut32 done;

    if (!sel_backend)
        return E_NOIF;

    for (done = 0; done < buf_len;)
        done += sel_backend->read(fp, buf + done, buf_len - done, 100);

    return done;
}
