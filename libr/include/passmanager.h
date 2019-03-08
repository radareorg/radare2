/* radare2 - LGPL - Copyright 2019 - oddcoder*/

#ifndef R2_PASSMANAGER_H
#define R2_PASSMANAGER_H

#include <r_util.h>
#include <r_anal.h>

/************************************************TEMPLATE STUFF************************************/
/*
 * Always add elements to this structure at the bottom not at the begining,
 * so it is always backward compatiable
 */

#define PASS(TYPE, TYPE_NAME)\
	typedef struct _##TYPE_NAME##_pass TYPE_NAME##Pass;\
	typedef struct _##TYPE_NAME##_pass {\
		char *name; /*must be unique for every pass*/\
		/*This function is used to register the dependency passes for this pass*/\
		void (*registerDependencies) (TYPE_NAME##PassManager *);\
		void *(*run) (TYPE_NAME##PassManager *, TYPE_NAME##Pass *p, TYPE *object);\
		void *(*invalidate) (TYPE_NAME##PassManager *, TYPE_NAME##Pass *p, TYPE *object);\
		/*This callback gets called when this pass is about to be destroyed*/\
		void (*free_pass) (TYPE_NAME##Pass * p);\
		/*This callback gets calld when the invalidate cb returns new pointer than the one strored*/\
		void (*free_result) (void *);\
		/*Arbitrary data stored for the pass*/\
		void *customDataStructure;\
		/*TODO  passes can come with their own set of commands*/\
	} TYPE_NAME##Pass;

/*
 * They are all defined the same, but, different PassManager
 * types accepts different PassRunners types which in turn wraps
 * different passes, these different passes finally operates on one of bunch of types as
 * Function, Module, basicBlock...etc
 */
#define DEFINE_PASSMANAGER(TYPE, TYPE_NAME)\
	typedef struct _##TYPE_NAME##_pm {\
		HtPP *passes; /*<char *Pass->name, PassRunner>*/\
		/*This can be used to detect circular dependencies*/\
		HtPP *running; /*<TYPE *object,HtPP<char *passName, NULL>>*/\
		RAnal *parent;\
	} TYPE_NAME##PassManager

#define DECLARE_PASSMANAGER(TYPE, TYPE_NAME)\
	typedef struct _##TYPE_NAME##_pm TYPE_NAME##PassManager

#define PASSRUNNER(TYPE, TYPE_NAME)\
	typedef struct {\
		TYPE_NAME##Pass *p;\
		HtPP *passResults; /*<void *object, void *result>*/\
		TYPE_NAME##PassManager *parent;\
	} TYPE_NAME##PassRunner

#define PASS_MANAGER_API(TYPE, TYPE_NAME, FUNC_NAME)\
	R_API TYPE_NAME##PassManager *FUNC_NAME##_new ();\
	R_API RAnal *FUNC_NAME##_get_anal (TYPE_NAME##PassManager *pm);\
	R_API void FUNC_NAME##_invalidate (TYPE_NAME##PassManager *pm, TYPE *object);\
	R_API void FUNC_NAME##_set_anal (TYPE_NAME##PassManager *pm, RAnal *anal);\
	R_API void FUNC_NAME##_free (TYPE_NAME##PassManager *pm);\
	R_API bool FUNC_NAME##_register_pass (TYPE_NAME##PassManager *pm, TYPE_NAME##Pass *p);\
	R_API void *FUNC_NAME##_get_result (TYPE_NAME##PassManager *pm, char *passName, TYPE *object);\
	R_API void *FUNC_NAME##_get_cached_result (TYPE_NAME##PassManager *pm, char *passName, TYPE *object)

/************************************TEMPLATE ENDS HERE********************************************/

/*
 * Don't define this unless:-
 * A) You are testing **only** the internals of the passmanager.
 * B) You are extending the functionality of the passmanager.
 */
DECLARE_PASSMANAGER (RAnalFunction, Function);
DECLARE_PASSMANAGER (RAnalBlock, BasicBlock);
DECLARE_PASSMANAGER (RBin, Bin);

PASS (RAnalFunction, Function);
PASS (RAnalBlock, BasicBlock);
PASS (RBin, Bin);

PASS_MANAGER_API (RAnalFunction, Function, fpm);
PASS_MANAGER_API (RAnalBlock, BasicBlock, bbpm);
PASS_MANAGER_API (RBin, Bin, bpm);

//TODO Flow sensitive path sensive walker inter-procedural pass as well

#ifdef PASSMANAGER_IMPLEMENTATION_FOR_INTERNAL_USE_ONLY
PASSRUNNER (RAnalFunction, Function);
PASSRUNNER (RAnalBlock, BasicBlock);
PASSRUNNER (RBin, Bin);

DEFINE_PASSMANAGER (RAnalFunction, Function);
DEFINE_PASSMANAGER (RAnalBlock, BasicBlock);
DEFINE_PASSMANAGER (RBin, Bin);

#endif

#endif
