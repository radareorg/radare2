/* radare - LGPL - Copyright 2009-2012 - pancake */
/* python extension for libr (radare2) */

#include <r_lib.h>
#include <r_lang.h>
#include <r_core.h>
#undef _GNU_SOURCE
#undef _XOPEN_SOURCE
#undef _POSIX_C_SOURCE
#undef PREFIX
#include <Python.h>
#include <structmember.h>
#if PY_MAJOR_VERSION>=3
#define PyString_FromString PyUnicode_FromString
#endif

static RCore *core = NULL;

static int run(RLang *lang, const char *code, int len) {
	PyRun_SimpleString (code);
	return R_TRUE;
}

static int slurp_python(const char *file) {
	FILE *fd = r_sandbox_fopen (file, "r");
	if (fd == NULL)
		return R_FALSE;
	PyRun_SimpleFile (fd, file);
	fclose (fd);
	return R_TRUE;
}

static int run_file(struct r_lang_t *lang, const char *file) {
	return slurp_python (file);
}

/* init */
typedef struct {
	PyObject_HEAD
	PyObject *first; /* first name */
	PyObject *last;  /* last name */
	int number;
} Radare;

#if PY_MAJOR_VERSION<3
static char *py_nullstr = "";

static void Radare_dealloc(Radare* self) {
	Py_XDECREF (self->first);
	Py_XDECREF (self->last);
	//self->ob_type->tp_free((PyObject*)self);
}

static PyObject * Radare_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
	Radare *self = (Radare *)type->tp_alloc (type, 0);
	if (self != NULL) {
		self->first = PyString_FromString ("");
		if (self->first == NULL) {
			Py_DECREF (self);
			return NULL;
		}

		self->last = PyString_FromString ("");
		if (self->last == NULL) {
			Py_DECREF (self);
			return NULL;
		}
		self->number = 0;
	}

	return (PyObject *)self;
}

static PyObject *Radare_cmd(Radare* self, PyObject *args) {
	char *str, *cmd = NULL;

	if (!PyArg_ParseTuple (args, "s", &cmd))
		return NULL;
	str = r_core_cmd_str (core, cmd);
	return PyString_FromString (str? str: py_nullstr);
}

static int Radare_init(Radare *self, PyObject *args, PyObject *kwds) {
	PyObject *first=NULL, *last=NULL, *tmp;

	static char *kwlist[] = {"first", "last", "number", NULL};

	if (!PyArg_ParseTupleAndKeywords (args, kwds, "|OOi",
		kwlist, &first, &last, &self->number))
		return -1;

	if (first) {
		tmp = self->first;
		Py_INCREF (first);
		self->first = first;
		Py_XDECREF (tmp);
	}

	if (last) {
		tmp = self->last;
		Py_INCREF (last);
		self->last = last;
		Py_XDECREF (tmp);
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
	PyObject_HEAD_INIT (NULL)
	0,                         /*ob_size*/
	"radare.RadareInternal",   /*tp_name*/
	sizeof (Radare),           /*tp_basicsize*/
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

static void init_radare_module(void) {
	if (PyType_Ready (&RadareType) < 0)
		return;
	Py_InitModule3 ("r", Radare_methods, "radare python extension");
}
#else

/*
SEE 
static PyMethodDef EmbMethods[] = {
    {"numargs", emb_numargs, METH_VARARGS,
     "Return the number of arguments received by the process."},
    {NULL, NULL, 0, NULL}
};
*/

static PyModuleDef EmbModule = {
    PyModuleDef_HEAD_INIT, "radare", NULL, -1, NULL, //EmbMethods,
    NULL, NULL, NULL, NULL
};

static int init_radare_module(void) {
	// TODO import r2-swig api
	//eprintf ("TODO: python>3.x instantiate 'r' object\n");
	PyObject *m = PyModule_Create (&EmbModule);
	if (m == NULL) {
		eprintf ("Cannot create python3 r2 module\n");
		return R_FALSE;
	}
	return R_TRUE;
}
#endif
/* -init- */

static int prompt(void *user) {
	int err = 1;
	// PyRun_SimpleString("import IPython");
	if (err != 0)
		return R_FALSE;
	return R_TRUE;
}

static int setup(RLang *lang) {
	RListIter *iter;
	RLangDef *def;
	char cmd[128];
	// Segfault if already initialized ?
	PyRun_SimpleString ("from r2.r_core import RCore");
	core = lang->user;
	r_list_foreach (lang->defs, iter, def) {
		if (!def->type || !def->name)
			continue;
		if (!strcmp (def->type, "int"))
			snprintf (cmd, sizeof (cmd), "%s=%d", def->name, (int)(size_t)def->value);
		else if (!strcmp (def->type, "string"))
			snprintf (cmd, sizeof (cmd), "%s=\"%s\"", def->name, (char *)def->value);
		else snprintf (cmd, sizeof (cmd), "%s=%s.cast(%p)",
			def->name, def->type, def->value);
		PyRun_SimpleString (cmd);
	}
	return R_TRUE;
}

static int init(RLang *lang) {
	core = lang->user;
	// DO NOT INITIALIZE MODULE IF ALREADY INITIALIZED
	if (Py_IsInitialized ()) {
		return 0;
	}
	Py_Initialize ();
	init_radare_module ();
	return R_TRUE;
}

static int fini(void *user) {
	return R_TRUE;
}

static const char *help =
	//" r = new RadareInternal()\n"
	"  print r.cmd(\"p8 10\");\n";

struct r_lang_plugin_t r_lang_plugin_python = {
	.name = "python",
	.desc = "Python language extension",
	.init = &init,
	.setup = &setup,
	.fini = (void *)&fini,
	.help = &help,
	.prompt = (void *)&prompt,
	.run = &run,
	.run_file = &run_file,
	.set_argv = NULL,
};

#if !CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_LANG,
	.data = &r_lang_plugin_python,
};
#endif
