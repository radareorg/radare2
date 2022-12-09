#ifndef js_run_h
#define js_run_h

js_Environment *jsR_newenvironment(js_State *J, js_Object *variables, js_Environment *outer);

struct js_Environment
{
	js_Environment *outer;
	js_Object *variables;

	js_Environment *gcnext;
	int gcmark;
};

#endif
