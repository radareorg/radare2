/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */
/* python extension for libr (radare2) */

#include "r_lib.h"
#include "r_lang.h"
#undef _GNU_SOURCE
#include <Python.h>
#include <structmember.h>

#include "r_core.h"
static struct r_core_t *core = NULL;

static int run(void *user, const char *code, int len)
{
	PyRun_SimpleString(code);
	return R_TRUE;
}

static int slurp_python(const char *file)
{
	FILE *fd = fopen(file, "r");
	if (fd == NULL)
		return R_FALSE;
	PyRun_SimpleFile(fd, file);
	fclose(fd);
	return R_TRUE;
}

static int run_file(void *user, const char *file)
{
	return slurp_python(file);
}

/* init */
static char *py_nullstr = "";
typedef struct {
	PyObject_HEAD
		PyObject *first; /* first name */
	PyObject *last;  /* last name */
	int number;
} Radare;

static void Radare_dealloc(Radare* self)
{
	Py_XDECREF(self->first);
	Py_XDECREF(self->last);
	self->ob_type->tp_free((PyObject*)self);
}

static PyObject * Radare_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	Radare *self;

	self = (Radare *)type->tp_alloc(type, 0);
	if (self != NULL) {
		self->first = PyString_FromString("");
		if (self->first == NULL) {
			Py_DECREF(self);
			return NULL;
		}

		self->last = PyString_FromString("");
		if (self->last == NULL) {
			Py_DECREF(self);
			return NULL;
		}

		self->number = 0;
	}

	return (PyObject *)self;
}

static PyObject * Radare_cmd(Radare* self, PyObject *args)
{
	PyObject *result;
	char *str, *cmd = NULL;

	if (!PyArg_ParseTuple(args, "s", &cmd))
		return NULL;

	str = r_core_cmd_str(core, cmd);
	if (str == NULL)
		str = py_nullstr;

	result = PyString_FromString(str);

	return result;
}

static int Radare_init(Radare *self, PyObject *args, PyObject *kwds)
{
	PyObject *first=NULL, *last=NULL, *tmp;

	static char *kwlist[] = {"first", "last", "number", NULL};

	if (! PyArg_ParseTupleAndKeywords(args, kwds, "|OOi",
		kwlist, &first, &last, &self->number))
		return -1;

	if (first) {
		tmp = self->first;
		Py_INCREF(first);
		self->first = first;
		Py_XDECREF(tmp);
	}

	if (last) {
		tmp = self->last;
		Py_INCREF(last);
		self->last = last;
		Py_XDECREF(tmp);
	}

	return 0;
}

static PyMemberDef Radare_members[] = {
	{"first", T_OBJECT_EX, offsetof(Radare, first), 0,
		"first name"},
	{"last", T_OBJECT_EX, offsetof(Radare, last), 0,
		"last name"},
	{"number", T_INT, offsetof(Radare, number), 0,
		"noddy number"},
	{NULL}  /* Sentinel */
};

static PyMethodDef Radare_methods[] = {
	{"cmd", (PyCFunction)Radare_cmd, METH_VARARGS,
		"Executes a radare command and returns a string"
	},
	{NULL}  /* Sentinel */
};

static PyTypeObject RadareType = {
	PyObject_HEAD_INIT(NULL)
	0,                         /*ob_size*/
	"radare.RadareInternal",   /*tp_name*/
	sizeof(Radare),            /*tp_basicsize*/
	0,                         /*tp_itemsize*/
	(destructor)Radare_dealloc,/*tp_dealloc*/
	0,                         /*tp_print*/
	0,                         /*tp_getattr*/
	0,                         /*tp_setattr*/
	0,                         /*tp_compare*/
	0,                         /*tp_repr*/
	0,                         /*tp_as_number*/
	0,                         /*tp_as_sequence*/
	0,                         /*tp_as_mapping*/
	0,                         /*tp_hash */
	0,                         /*tp_call*/
	0,                         /*tp_str*/
	0,                         /*tp_getattro*/
	0,                         /*tp_setattro*/
	0,                         /*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
	"Radare objects",          /* tp_doc */
	0,                         /* tp_traverse */
	0,                         /* tp_clear */
	0,                         /* tp_richcompare */
	0,                         /* tp_weaklistoffset */
	0,                         /* tp_iter */
	0,                         /* tp_iternext */
	Radare_methods,            /* tp_methods */
	Radare_members,            /* tp_members */
	0,                         /* tp_getset */
	0,                         /* tp_base */
	0,                         /* tp_dict */
	0,                         /* tp_descr_get */
	0,                         /* tp_descr_set */
	0,                         /* tp_dictoffset */
	(initproc)Radare_init,     /* tp_init */
	0,                         /* tp_alloc */
	Radare_new,                /* tp_new */
};

static void init_radare_module(void)
{
	PyObject* m;
	if (PyType_Ready(&RadareType) < 0)
		return;
	m = Py_InitModule3("r", Radare_methods, //module_methods,
			"Example module that creates an extension type.");
}
/* -init- */

static int prompt(void *user)
{
	int err = 1;
	// PyRun_SimpleString("import IPython");
	if (err != 0)
		return R_FALSE;
	return R_TRUE;
}

static int init(void *user)
{
	core = user;
	Py_Initialize();
	init_radare_module();
	//Py_InitModule3("radare", Radare_methods, NULL);
	PyRun_SimpleString("import r");
//	PyRun_SimpleString("import radare");
//	PyRun_SimpleString("from radare import *");
	return R_TRUE;
}

static int fini(void *user)
{
	return R_TRUE;
}

static const char *help =
	"Python plugin usage:\n"
	//" r = new RadareInternal()\n"
	" bytes = r.cmd(\"p8 10\");\n";

static struct r_lang_handle_t r_lang_plugin_python = {
	.name = "python",
	.desc = "Python language extension",
	.init = &init,
	.fini = &fini,
	.help = &help,
	.prompt = &prompt,
	.run = &run,
	.run_file = &run_file,
	.set_argv = NULL,
};

struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_LANG,
	.data = &r_lang_plugin_python,
};
