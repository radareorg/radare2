#define PASSMANAGER_IMPLEMENTATION_FOR_INTERNAL_USE_ONLY

#include <passmanager.h>

//This #define implements basically the whole file so there is basically no need to indent everything

#define IMPLEMENT_PASSMANAGER(TYPE, TYPE_NAME, FUNC_NAME)\
	static TYPE_NAME##PassRunner *new_##FUNC_NAME##_passrunner (TYPE_NAME##Pass *p) {\
		TYPE_NAME##PassRunner *pr = calloc (sizeof (TYPE_NAME##PassRunner), 1);\
		if (!pr) {\
			return NULL;\
		}\
		pr->p = p;\
		/*XXX create better tuned hash table*/\
		HtPPOptions opt = { 0 };\
		pr->passResults = ht_pp_new_opt (&opt);\
		return pr;\
	}\
\
	static bool FUNC_NAME##_invalidatecb (TYPE *object, const char *passname, const TYPE_NAME##PassRunner *pr) {\
		void *x = pr->p->invalidate (pr->parent, pr->p, object);\
		if (x) {\
			ht_pp_insert (pr->passResults, object, x);\
		} else {\
			ht_pp_delete (pr->passResults, object);\
		}\
		return true;\
	}\
\
	static bool free_##FUNC_NAME##_PassCache1 (TYPE_NAME##Pass *p, const TYPE *object, void *result) {\
		p->free_result (result);\
		free (result);\
		return true;\
	}\
\
	static bool free_##FUNC_NAME##_PassCache2 (TYPE_NAME##Pass *p, const TYPE *object, void *result) {\
		free (result);\
		return true;\
	}\
\
	static bool free_##FUNC_NAME##_PassRunner (void *NOT_USED, const char *passname, TYPE_NAME##PassRunner *pr) {\
		if (pr->p->free_result) {\
			ht_pp_foreach (pr->passResults, (HtPPForeachCallback)free_##FUNC_NAME##_PassCache1, pr->p);\
		} else {\
			ht_pp_foreach (pr->passResults, (HtPPForeachCallback)free_##FUNC_NAME##_PassCache2, pr->p);\
		}\
		if (pr->p->free_pass) {\
			pr->p->free_pass (pr->p);\
		}\
		ht_pp_free (pr->passResults);\
		free (pr);\
		return true;\
	}\
\
	static bool free_##FUNC_NAME##_running (void *NOT_USED, TYPE *object, HtPP *objects_running_passes) {\
		ht_pp_free (objects_running_passes);\
		return true;\
	}\
\
	R_API TYPE_NAME##PassManager *FUNC_NAME##_new () {\
		TYPE_NAME##PassManager *pm = calloc (sizeof (TYPE_NAME##PassManager), 1);\
		if (!pm) {\
			return NULL;\
		}\
		pm->passes = ht_pp_new0 ();\
		/*XXX create better tuned hash table*/\
		HtPPOptions opt = { 0 };\
		pm->running = ht_pp_new_opt (&opt);\
		return pm;\
	}\
\
	R_API void FUNC_NAME##_set_anal (TYPE_NAME##PassManager *pm, RAnal *anal) {\
		pm->parent = anal;\
	}\
\
	R_API RAnal *FUNC_NAME##_get_anal (TYPE_NAME##PassManager *pm) {\
		return pm->parent;\
	}\
\
	R_API void FUNC_NAME##_free (TYPE_NAME##PassManager *pm) {\
		ht_pp_foreach (pm->passes, (HtPPForeachCallback)free_##FUNC_NAME##_PassRunner, NULL);\
		ht_pp_free (pm->passes);\
		ht_pp_foreach (pm->running, (HtPPForeachCallback)free_##FUNC_NAME##_running, NULL);\
		ht_pp_free (pm->running);\
		free (pm);\
	}\
\
	R_API bool FUNC_NAME##_register_pass (TYPE_NAME##PassManager *pm, TYPE_NAME##Pass *pass) {\
		bool pass_exist;\
		if (!pass) {\
			return false;\
		}\
		if (!pass->run || !pass->invalidate) {\
			return false;\
		}\
		ht_pp_find (pm->passes, pass->name, &pass_exist);\
		if (pass_exist) {\
			return true;\
		}\
		TYPE_NAME##PassRunner *pr = new_##FUNC_NAME##_passrunner (pass);\
		pr->parent = pm;\
		/*Must be done in this order, First register the current pass, then*/\
		/*register its depencencies, do it the other way round and you may end*/\
		/*up with unresolved circular dependencies*/\
		ht_pp_insert (pm->passes, pass->name, pr);\
		if (pass->registerDependencies) {\
			pass->registerDependencies (pm);\
		}\
		return true;\
	}\
\
	static bool FUNC_NAME##_is_running (HtPP /*<void *object, HtPP<void *pass, NULL>>*/ *running, char *passName, TYPE *object) {\
		bool found;\
		HtPP *objects_running_passes = ht_pp_find (running, object, &found);\
		if (!found) {\
			return false;\
		}\
		ht_pp_find (objects_running_passes, passName, &found);\
		return found;\
	}\
\
	static void FUNC_NAME##_add_running (HtPP /*<void *object, HtPP<void *pass, NULL>>*/ *running, char *passName, TYPE *object) {\
		bool found;\
		HtPP *objects_running_passes = ht_pp_find (running, object, &found);\
		if (!found) {\
			objects_running_passes = ht_pp_new0 ();\
			ht_pp_insert (running, object, objects_running_passes);\
		}\
		ht_pp_insert (objects_running_passes, passName, NULL);\
	}\
\
	static void FUNC_NAME##_del_running (HtPP /*<void *object, HtPP<void *pass, NULL>>*/ *running, char *passName, TYPE *object) {\
		/*We don't do sanity checks, since I only delete after insertion, I make sure that everything is in the right place*/\
		HtPP *objects_running_passes = ht_pp_find (running, object, NULL);\
		ht_pp_delete (objects_running_passes, passName);\
	}\
\
	R_API void *FUNC_NAME##_get_result (TYPE_NAME##PassManager *pm, char *passName, TYPE *object) {\
		void *result = FUNC_NAME##_get_cached_result (pm, passName, object);\
		if (result) {\
			return result;\
		}\
\
		TYPE_NAME##PassRunner *pr = ht_pp_find (pm->passes, passName, NULL);\
		r_return_val_if_fail (pr != NULL, NULL);\
		r_return_val_if_fail (!FUNC_NAME##_is_running (pm->running, pr->p->name, object), NULL);\
		FUNC_NAME##_add_running (pm->running, pr->p->name, object);\
		result = pr->p->run (pm, pr->p, object);\
		ht_pp_insert (pr->passResults, object, result);\
		FUNC_NAME##_del_running (pm->running, pr->p->name, object);\
		return result;\
	}\
\
	R_API void *FUNC_NAME##_get_cached_result (TYPE_NAME##PassManager *pm, char *passName, TYPE *object) {\
		TYPE_NAME##PassRunner *pr = ht_pp_find (pm->passes, passName, NULL);\
		if (!pr) {\
			return NULL;\
		}\
		void *result = ht_pp_find (pr->passResults, object, NULL);\
		return result;\
	}\
\
	R_API void FUNC_NAME##_invalidate (TYPE_NAME##PassManager *pm, TYPE *object) {\
		ht_pp_foreach (pm->passes, (HtPPForeachCallback)FUNC_NAME##_invalidatecb, object);\
	}
