
static PR_(TYPE_NAME) *PMFN_(passrunner_new)(PASS_(TYPE_NAME) *p) {
	PR_(TYPE_NAME) *pr = R_NEW0 (PR_(TYPE_NAME));
	if (!pr) {
		return NULL;
	}
	pr->p = p;

	//FIXME create better tuned hash table
	HtPPOptions opt = { 0 };
	pr->passResults = ht_pp_new_opt (&opt);
	return pr;
}

static bool PMFN_(invalidatecb) (TYPE *object, const char *passname, const PR_(TYPE_NAME) *pr) {
	void *x = NULL;

	if (!pr || !pr->p) {
		return false;
	}

	x = pr->p->invalidate (pr->parent, pr->p, object);
	if (x) {
		ht_pp_insert (pr->passResults, object, x);
	} else {
		ht_pp_delete (pr->passResults, object);
	}
	return true;
}

static bool PMFN_(passcache1_free) (PASS_(TYPE_NAME) *p, const TYPE *object, void *result) {
	if (p) {
		p->free_result (result);
	}
	free (result);
	return true;
}

static bool PMFN_(passcache2_free) (PASS_(TYPE_NAME) *p, const TYPE *object, void *result) {
	free (result);
	return true;
}

static bool PMFN_(passrunner_free)(void *user, const char *passname, PR_(TYPE_NAME) *pr) {
	if (pr && pr->p && pr->p->free_result) {
		ht_pp_foreach (pr->passResults, (HtPPForeachCallback)PMFN_(passcache1_free), pr->p);
	} else {
		ht_pp_foreach (pr->passResults, (HtPPForeachCallback)PMFN_(passcache2_free), pr->p);
	}
	if (pr && pr->p && pr->p->free_pass) {
		pr->p->free_pass (pr->p);
	}
	ht_pp_free (pr->passResults);
	free (pr);
	return true;
}

static bool PMFN_(running_free) (void *user, TYPE *object, HtPP *objects_running_passes) {
	ht_pp_free (objects_running_passes);
	return true;
}

R_API PM_(TYPE_NAME) *PMFN_(new) () {
	PM_(TYPE_NAME) *pm = R_NEW0 (PM_(TYPE_NAME));
	if (!pm) {
		return NULL;
	}
	pm->passes = ht_pp_new0 ();
	//FIXME create better tuned hash table
	HtPPOptions opt = { 0 };
	pm->running = ht_pp_new_opt (&opt);
	return pm;
}

R_API void PMFN_(set_anal)(PM_(TYPE_NAME) *pm, RAnal *anal) {
	if (!pm)
		return;
	pm->parent = anal;
}

R_API RAnal *PMFN_(get_anal)(PM_(TYPE_NAME) *pm) {
	if (!pm)
		return NULL;
	return pm->parent;
}

R_API void PMFN_(free)(PM_(TYPE_NAME) *pm) {
	ht_pp_foreach (pm->passes, (HtPPForeachCallback)PMFN_(passrunner_free), NULL);
	ht_pp_free (pm->passes);
	ht_pp_foreach (pm->running, (HtPPForeachCallback)PMFN_(running_free), NULL);
	ht_pp_free (pm->running);
	free (pm);
}

R_API bool PMFN_(register_pass)(PM_(TYPE_NAME) *pm, PASS_(TYPE_NAME) *pass) {
	bool pass_exist;
	if (!pass || !pm) {
		return false;
	}
	if (!pass->run || !pass->invalidate) {
		return false;
	}
	ht_pp_find (pm->passes, pass->name, &pass_exist);
	if (pass_exist) {
		return true;
	}
	PR_(TYPE_NAME) *pr = PMFN_(passrunner_new) (pass);
	pr->parent = pm;
	//Must be done in this order, First register the current pass,
	//then register its depencencies, do it the other way round
	//and you may end up with unresolved circular dependencies
	ht_pp_insert (pm->passes, pass->name, pr);
	if (pass->registerDependencies) {
		pass->registerDependencies (pm);
	}
	return true;
}

/*
 * running is of type <TYPE *object, HtPP<char *passName, NULL>>
 */
static bool PMFN_(is_running)(HtPP *running, char *passName, TYPE *object) {
	bool found;
	HtPP *objects_running_passes = ht_pp_find (running, object, &found);
	if (!found) {
		return false;
	}
	ht_pp_find (objects_running_passes, passName, &found);
	return found;
}

/*
 * running is of type : <TYPE *object, HtPP<void *passName, NULL>>
 */

static void PMFN_(add_running)(HtPP *running, char *passName, TYPE *object) {
	bool found;
	HtPP *objects_running_passes = ht_pp_find (running, object, &found);
	if (!found) {
		objects_running_passes = ht_pp_new0 ();
		ht_pp_insert (running, object, objects_running_passes);
	}
	ht_pp_insert (objects_running_passes, passName, NULL);
}

/* running is of type: <void *object, HtPP<void *pass, NULL>>
 *
 *  We don't do sanity checks, since I only delete after insertion, I
 *  make sure that everything is in the right place*
 */
static void PMFN_(del_running)(HtPP *running, char *passName, TYPE *object) {
	HtPP *objects_running_passes = ht_pp_find (running, object, NULL);
	ht_pp_delete (objects_running_passes, passName);
}

R_API void *PMFN_(get_result)(PM_(TYPE_NAME) *pm, char *passName, TYPE *object) {
	void *result = PMFN_(get_cached_result) (pm, passName, object);
	if (result) {
		return result;
	}

	PR_(TYPE_NAME) *pr = ht_pp_find (pm->passes, passName, NULL);
	r_return_val_if_fail (pr != NULL, NULL);
	r_return_val_if_fail (!PMFN_(is_running) (pm->running, pr->p->name, object), NULL);
	PMFN_(add_running) (pm->running, pr->p->name, object);
	result = pr->p->run (pm, pr->p, object);
	ht_pp_insert (pr->passResults, object, result);
	PMFN_(del_running) (pm->running, pr->p->name, object);
	return result;
}

R_API void *PMFN_(get_cached_result)(PM_(TYPE_NAME) *pm, char *passName, TYPE *object) {
	PR_(TYPE_NAME) *pr = ht_pp_find (pm->passes, passName, NULL);
	if (!pr) {
		return NULL;
	}
	void *result = ht_pp_find (pr->passResults, object, NULL);
	return result;
}

R_API void PMFN_(invalidate)(PM_(TYPE_NAME) *pm, TYPE *object) {
	ht_pp_foreach (pm->passes, (HtPPForeachCallback)PMFN_(invalidatecb), object);
}
