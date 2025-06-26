/* radare2 - LGPL - Copyright 2025 - pancake */

#include <r_cons.h>
#include "private.h"

R_API void r_kons_print(RCons *cons, const char *str) {
	R_RETURN_IF_FAIL (str);
	if (cons->null) {
		return;
	}
	size_t len = strlen (str);
	if (len > 0) {
		r_cons_write (cons, str, len);
	}
}

R_API int r_cons_printf(RCons *cons, const char *format, ...) {
	va_list ap;
	if (R_STR_ISEMPTY (format)) {
		return -1;
	}
	va_start (ap, format);
	r_cons_printf_list (cons, format, ap);
	va_end (ap);
	return 0;
}

typedef struct {
	bool breaked;
	RConsEvent event_interrupt;
	void *event_interrupt_data;
} RConsBreakStack;

static void break_stack_free(void *ptr) {
	RConsBreakStack *b = (RConsBreakStack*)ptr;
	free (b);
}

static void grep_word_free(RConsGrepWord *gw) {
	if (gw) {
		free (gw->str);
		free (gw);
	}
}

static void cons_grep_reset(RConsGrep *grep) {
	if (grep) {
		free (grep->str);
		grep->str = NULL;
		if (grep->strings) {
			r_list_free (grep->strings);
			grep->strings = r_list_newf ((RListFree)grep_word_free);
		}
		ZERO_FILL (*grep);
		grep->line = -1;
		grep->sort = -1;
		grep->sort_invert = false;
	}
}

#if 0
typedef struct {
	char *buf;
	int buf_len;
	int buf_size;
	RConsGrep *grep;
} RConsStack;

static void cons_stack_free(void *ptr) {
	RConsStack *s = (RConsStack *)ptr;
	R_FREE (s->buf);
	cons_grep_reset (s->grep);
	R_FREE (s->grep);
	free (s);
#if 0
	// XXX
	C->grep.str = NULL;
	cons_grep_reset (&C->grep);
#endif
}
static RConsStack *cons_stack_dump(RCons *cons, bool recreate) {
	RConsContext *ctx = cons->context;
	RConsStack *data = R_NEW0 (RConsStack);
	if (ctx->buffer) {
		data->buf = ctx->buffer;
		data->buf_len = ctx->buffer_len;
		data->buf_size = ctx->buffer_sz;
	}
	data->grep = r_mem_dup (&ctx->grep, sizeof (RConsGrep));
	if (ctx->grep.str) {
		data->grep->str = strdup (ctx->grep.str);
	}
	if (recreate && ctx->buffer_sz > 0) {
		ctx->buffer = malloc (ctx->buffer_sz);
		if (R_UNLIKELY (!ctx->buffer)) {
			ctx->buffer = data->buf;
			free (data);
			return NULL;
		}
	} else {
		ctx->buffer = NULL;
	}
	return data;
}

static void cons_stack_load(RConsContext *C, RConsStack *data, bool free_current) {
	return;
	R_RETURN_IF_FAIL (data);
	if (free_current) {
		// double free
		free (C->buffer);
	}
	C->buffer = data->buf;
	data->buf = NULL;
	C->buffer_len = data->buf_len;
	C->buffer_sz = data->buf_size;
	if (data->grep) {
		free (C->grep.str);
		memcpy (&C->grep, data->grep, sizeof (RConsGrep));
	}
}

static void cons_context_deinit(RConsContext *ctx) {
	return;
	// r_stack_free (ctx->cons_stack);
	r_list_free (ctx->marks);
	ctx->cons_stack = NULL;
	r_stack_free (ctx->break_stack);
	ctx->break_stack = NULL;
	r_cons_pal_free (ctx);
}
#endif

static void mark_free(RConsMark *m) {
	free (m->name);
	free (m);
}

static void init_cons_context(RCons *cons, RConsContext * R_NULLABLE parent) {
	RConsContext *ctx = cons->context;
	ctx->marks = r_list_newf ((RListFree)mark_free);
	ctx->breaked = false;
	// ctx->cmd_depth = R_CONS_CMD_DEPTH + 1;
	ctx->buffer_sz = 0;
	ctx->lastEnabled = true;
	ctx->buffer_len = 0;
	ctx->is_interactive = false;
	// ctx->cons_stack = r_stack_newf (6, cons_stack_free);
	ctx->break_stack = r_stack_newf (6, break_stack_free);
	ctx->event_interrupt = NULL;
	ctx->event_interrupt_data = NULL;
	ctx->pageable = true;
	ctx->log_callback = NULL;
	ctx->cmd_str_depth = 0;
	ctx->noflush = false;

	if (parent) {
		ctx->color_mode = parent->color_mode;
		r_cons_pal_copy (cons, parent);
	} else {
		ctx->color_mode = COLOR_MODE_DISABLED;
		r_cons_pal_init (cons);
	}
	cons_grep_reset (&ctx->grep);
}
#if R2__WINDOWS__
static HANDLE h;
static BOOL __w32_control(DWORD type) {
	if (type == CTRL_C_EVENT) {
		__break_signal (2); // SIGINT
		eprintf ("{ctrl+c} pressed.\n");
		return true;
	}
	return false;
}
#elif R2__UNIX__ && !__wasi__
volatile sig_atomic_t sigwinchFlag;
static void resize(int sig) {
	sigwinchFlag = 1;
}
#endif

static inline void init_cons_input(InputState *state) {
	state->readbuffer = NULL;
	state->readbuffer_length = 0;
	state->bufactive = true;
}

R_API RCons *r_kons_new(void) {
	RCons *cons = R_NEW0 (RCons);
#if 0
	if (cons->refcnt != 1) {
		return cons;
	}
	if (cons->lock) {
		r_th_lock_wait (cons->lock);
	} else {
		cons->lock = r_th_lock_new (false);
	}
	R_CRITICAL_ENTER (I);
#endif
	// r_cons_context_reset (cons->context);
	cons->context = R_NEW0 (RConsContext);
	cons->ctx_stack = r_list_newf ((RListFree)r_cons_context_free);
	init_cons_context (cons, NULL);
	// eprintf ("CTX %p %p\n", cons, cons->context);
	init_cons_input (&cons->input_state);
	cons->lock = r_th_lock_new (false);
	cons->use_utf8 = r_cons_is_utf8 ();
	cons->rgbstr = r_cons_rgb_str_off; // XXX maybe we can kill that
	cons->enable_highlight = true;
	cons->highlight = NULL;
	cons->is_wine = -1;
	cons->fps = 0;
	cons->blankline = true;
	cons->teefile = NULL;
	cons->fix_columns = 0;
	cons->fix_rows = 0;
	RVecFdPairs_init (&cons->fds);
	cons->mouse_event = 0;
	cons->force_rows = 0;
	cons->force_columns = 0;
	cons->event_resize = NULL;
	cons->event_data = NULL;
	cons->linesleep = 0;
	cons->fdin = stdin;
	cons->fdout = 1;
	cons->break_lines = false;
	cons->lines = 0;
	cons->maxpage = 102400;

	r_cons_get_size (cons, &cons->pagesize);
	cons->num = NULL;
	cons->null = 0;
#if R2__WINDOWS__
	cons->old_cp = GetConsoleOutputCP ();
	cons->vtmode = win_is_vtcompat ();
#else
	cons->vtmode = 2;
#endif
#if EMSCRIPTEN || __wasi__
	/* do nothing here :? */
#elif R2__UNIX__
	tcgetattr (0, &cons->term_buf);
	memcpy (&cons->term_raw, &cons->term_buf, sizeof (cons->term_raw));
	cons->term_raw.c_iflag &= ~(BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
	cons->term_raw.c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
	cons->term_raw.c_cflag &= ~(CSIZE|PARENB);
	cons->term_raw.c_cflag |= CS8;
	cons->term_raw.c_cc[VMIN] = 1; // Solaris stuff hehe
	r_sys_signal (SIGWINCH, resize);
#elif R2__WINDOWS__
	h = GetStdHandle (STD_INPUT_HANDLE);
	GetConsoleMode (h, &cons->term_buf);
	cons->term_raw = 0;
	if (!SetConsoleCtrlHandler ((PHANDLER_ROUTINE)__w32_control, TRUE)) {
		R_LOG_ERROR ("Cannot set control console handler");
	}
#endif
	cons->pager = NULL; /* no pager by default */
	cons->mouse = 0;
	cons->show_vals = false;
	r_cons_reset (cons);
	cons->line = r_line_new (cons);
	return cons;
}

R_API void r_kons_free(RCons * R_NULLABLE cons) {
	if (!cons) {
		return;
	}
#if R2__WINDOWS__
	r_cons_enable_mouse (cons, false);
	if (cons->old_cp) {
		(void)SetConsoleOutputCP (cons->old_cp);
		// chcp doesn't pick up the code page switch for some reason
		(void)r_sys_cmdf ("chcp %u > NUL", cons->old_cp);
	}
#endif
	if (cons->line) {
		r_line_free (cons->line);
		cons->line = NULL;
	}
	while (!r_list_empty (cons->ctx_stack)) {
		r_cons_pop (cons);
	}
	r_cons_context_free (cons->context);
#if 0
	RConsContext *ctx = cons->context;
	R_FREE (ctx->buffer);
	R_FREE (cons->break_word);
	cons_context_deinit (ctx);
	R_FREE (ctx->lastOutput);
	ctx->lastLength = 0;
#endif
	R_FREE (cons->pager);
	RVecFdPairs_fini (&cons->fds);
}
