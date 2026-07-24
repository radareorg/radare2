typedef struct qjs_timer_t {
	int id;
	ut64 when;
	ut64 interval;
	bool active;
	R_UNOWNED JSContext *ctx;
	JSValue func;
	int argc;
	JSValue *argv;
} QjsTimer;

static void qjs_timer_free(void *ptr) {
	QjsTimer *timer = ptr;
	if (!timer) {
		return;
	}
	JS_FreeValue (timer->ctx, timer->func);
	int i;
	for (i = 0; i < timer->argc; i++) {
		JS_FreeValue (timer->ctx, timer->argv[i]);
	}
	free (timer->argv);
	free (timer);
}

static ut64 qjs_next_timer_delay(JSContext *ctx) {
	JSRuntime *rt = JS_GetRuntime (ctx);
	QjsPluginManager *pm = JS_GetRuntimeOpaque (rt);
	if (!pm || !pm->timers) {
		return UT64_MAX;
	}
	QjsTimer *timer;
	RListIter *iter;
	ut64 best = UT64_MAX;
	const ut64 now = r_time_now_mono ();
	r_list_foreach (pm->timers, iter, timer) {
		if (!timer->active || timer->ctx != ctx) {
			continue;
		}
		if (timer->when <= now) {
			return 0;
		}
		const ut64 delta = timer->when - now;
		if (delta < best) {
			best = delta;
		}
	}
	return best;
}

static bool qjs_run_due_timers(JSContext *ctx);

static bool qjs_drain_jobs(JSContext *ctx, bool wait) {
	JSRuntime *rt = JS_GetRuntime (ctx);
	QjsPluginManager *pm = JS_GetRuntimeOpaque (rt);
	bool did = false;
	for (;;) {
		bool progressed = false;
		for (;;) {
			JSContext *pctx = NULL;
			int res = JS_ExecutePendingJob (rt, &pctx);
			if (res <= 0) {
				if (res == -1) {
					R_LOG_ERROR ("Exception in pending job");
				}
				break;
			}
			progressed = true;
			did = true;
		}
		if (qjs_run_due_timers (ctx)) {
			progressed = true;
			did = true;
			continue;
		}
		if (progressed || !wait) {
			if (progressed) {
				continue;
			}
			break;
		}
		if (pm && pm->core && pm->core->cons && pm->core->cons->context && pm->core->cons->context->breaked) {
			break;
		}
		ut64 delay = qjs_next_timer_delay (ctx);
		if (delay == UT64_MAX) {
			break;
		}
		if (delay > 0) {
			r_sys_usleep ((int)R_MIN (delay, 10000));
		}
	}
	return did;
}

static void eval_jobs(JSContext *ctx) {
	qjs_drain_jobs (ctx, false);
}

static JSPromiseStateEnum qjs_await_promise(JSContext *ctx, JSValueConst promise) {
	for (;;) {
		JSPromiseStateEnum state = JS_PromiseState (ctx, promise);
		if (state != JS_PROMISE_PENDING) {
			return state;
		}
		if (!qjs_drain_jobs (ctx, true)) {
			return JS_PROMISE_PENDING;
		}
	}
}

static JSValue qjs_set_timeout(JSContext *ctx, int argc, JSValueConst *argv, bool interval) {
	if (argc < 1 || !JS_IsFunction (ctx, argv[0])) {
		return JS_ThrowTypeError (ctx, "setTimeout expects a function");
	}
	JSRuntime *rt = JS_GetRuntime (ctx);
	QjsPluginManager *pm = JS_GetRuntimeOpaque (rt);
	if (!pm || !pm->timers) {
		return JS_ThrowPlainError (ctx, "timer queue is unavailable");
	}
	double delay = 0;
	if (argc > 1 && JS_ToFloat64 (ctx, &delay, argv[1])) {
		return JS_EXCEPTION;
	}
	if (!(delay > 0)) {
		delay = 0;
	}
	if (interval && delay < 1) {
		delay = 1;
	}
	const ut64 delay_us = (ut64)(delay * R_USEC_PER_MSEC);
	QjsTimer *timer = R_NEW0 (QjsTimer);
	timer->id = pm->next_timer_id++;
	if (pm->next_timer_id <= 0) {
		pm->next_timer_id = 1;
	}
	timer->ctx = ctx;
	timer->active = true;
	timer->interval = interval? delay_us: 0;
	timer->when = r_time_now_mono () + delay_us;
	timer->func = JS_DupValue (ctx, argv[0]);
	timer->argc = argc > 2? argc - 2: 0;
	if (timer->argc > 0) {
		timer->argv = calloc (timer->argc, sizeof (JSValue));
		if (!timer->argv) {
			qjs_timer_free (timer);
			return JS_ThrowOutOfMemory (ctx);
		}
		int i;
		for (i = 0; i < timer->argc; i++) {
			timer->argv[i] = JS_DupValue (ctx, argv[i + 2]);
		}
	}
	r_list_append (pm->timers, timer);
	return JS_NewInt32 (ctx, timer->id);
}

static JSValue qjs_clear_timer(JSContext *ctx, int argc, JSValueConst *argv) {
	int32_t id = 0;
	if (argc > 0 && JS_ToInt32 (ctx, &id, argv[0])) {
		return JS_EXCEPTION;
	}
	JSRuntime *rt = JS_GetRuntime (ctx);
	QjsPluginManager *pm = JS_GetRuntimeOpaque (rt);
	if (!pm || !pm->timers) {
		return JS_UNDEFINED;
	}
	QjsTimer *timer;
	RListIter *iter;
	r_list_foreach (pm->timers, iter, timer) {
		if (timer->ctx == ctx && timer->id == id) {
			timer->active = false;
			break;
		}
	}
	return JS_UNDEFINED;
}

static JSValue js_os_setTimeout(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	return qjs_set_timeout (ctx, argc, argv, false);
}

static JSValue js_os_setInterval(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	return qjs_set_timeout (ctx, argc, argv, true);
}

static JSValue js_os_clear_timer(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	return qjs_clear_timer (ctx, argc, argv);
}

static bool qjs_run_due_timers(JSContext *ctx) {
	JSRuntime *rt = JS_GetRuntime (ctx);
	QjsPluginManager *pm = JS_GetRuntimeOpaque (rt);
	if (!pm || !pm->timers) {
		return false;
	}
	QjsTimer *timer;
	RListIter *iter, *tmp;
	bool did = false;
	const ut64 now = r_time_now_mono ();
	r_list_foreach_safe (pm->timers, iter, tmp, timer) {
		if (!timer->active) {
			r_list_delete (pm->timers, iter);
			did = true;
			continue;
		}
		if (timer->ctx != ctx || timer->when > now) {
			continue;
		}
		JSValue ret = JS_Call (ctx, timer->func, JS_UNDEFINED, timer->argc, (JSValueConst *)timer->argv);
		if (JS_IsException (ret)) {
			js_std_dump_error (ctx);
		} else {
			JS_FreeValue (ctx, ret);
		}
		if (timer->active && timer->interval) {
			timer->when = now + timer->interval;
		} else {
			r_list_delete (pm->timers, iter);
		}
		did = true;
	}
	return did;
}
