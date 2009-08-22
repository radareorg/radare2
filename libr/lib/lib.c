/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

#include "r_types.h"
#include "r_lib.h"
#include <stdio.h>
#include <dirent.h>

/* TODO: support for nested plugins ?? here */

#if __UNIX__
#include <dlfcn.h>
  #define DLOPEN(x)  dlopen(x, RTLD_GLOBAL | RTLD_NOW)
  #define DLSYM(x,y) dlsym(x,y)
  #define DLCLOSE(x) dlclose(x)
#elif __WINDOWS__ && !__CYGWIN__
#include <windows.h>
  #define DLOPEN(x)  LoadLibrary(x)
  #define DLSYM(x,y) GetProcAddress(x,y)
  #define DLCLOSE(x) CloseLibrary(x)
#else
  #define DLOPEN(x)  NULL
  #define DLSYM(x,y) NULL
  #define DLCLOSE(x) NULL
#endif

const char *r_lib_types[] = {
	"io", "dbg", "lang", "asm", "anal", "parse", "bin", "bininfo", 
	"bp", "syscall", "fastcall", NULL
};

const char *r_lib_types_get(int idx)
{
	if (idx<0||idx>R_LIB_TYPE_LAST)
		return "unk";
	return r_lib_types[idx];
}

void *r_lib_dl_open(const char *libname)
{
	void *ret;
	IFRTDBG fprintf(stderr, "Opening '%s'\n", libname);
	ret = DLOPEN(libname);
	if (ret == NULL)
		IFDBG fprintf(stderr, "dlerror: %s\n", dlerror());
	return ret;
}

void *r_lib_dl_sym(void *handle, const char *name)
{
	return DLSYM(handle, name);
}

int r_lib_dl_close(void *handle)
{
	return DLCLOSE(handle);
}

/* ---- */

int r_lib_init(struct r_lib_t *lib, const char *symname)
{
	INIT_LIST_HEAD(&lib->handlers);
	INIT_LIST_HEAD(&lib->plugins);
	strncpy(lib->symname, symname, sizeof(lib->symname)-1);
	return 0;
}

struct r_lib_t *r_lib_new(const char *symname)
{
	struct r_lib_t *lib = MALLOC_STRUCT(struct r_lib_t);
	r_lib_init(lib, symname);
	return lib;
}

int r_lib_free(struct r_lib_t *lib)
{
	/* TODO: iterate over libraries and free them all */
	/* TODO: iterate over handlers and free them all */
	r_lib_close(lib, NULL);
	free (lib);
	return 0;
}

/* THIS IS WRONG */
int r_lib_dl_check_filename(const char *file)
{
	/* skip hidden files */
	if (file[0]=='.')
		return R_FALSE;
	else
	/* per SO dylib filename extensions */
	if (strstr(file, ".so"))
		return R_TRUE;
	if (strstr(file, ".dll"))
		return R_TRUE;
	if (strstr(file, ".dylib"))
		return R_TRUE;
	return R_FALSE;
}

/* high level api */

int r_lib_run_handler(struct r_lib_t *lib, struct r_lib_plugin_t *plugin, struct r_lib_struct_t *symbol)
{
	struct r_lib_handler_t *h = plugin->handler;
	if (h && h->constructor != NULL)
		return h->constructor(plugin, h->user, symbol->data);
	return -1;
}

struct r_lib_handler_t *r_lib_get_handler(struct r_lib_t *lib, int type)
{
	struct list_head *pos;
	list_for_each_prev(pos, &lib->handlers) {
		struct r_lib_handler_t *h = list_entry(pos, struct r_lib_handler_t, list);
		if (h->type == type) {
			return h;
		}
	}
	return 0;
}

R_API int r_lib_close(struct r_lib_t *lib, const char *file)
{
	struct list_head *pos;
	list_for_each_prev(pos, &lib->plugins) {
		struct r_lib_plugin_t *h = list_entry(pos, struct r_lib_plugin_t, list);
		if ((file==NULL || (!strcmp(file, h->file))) && h->handler->destructor != NULL) {
			int ret = h->handler->destructor(h, h->handler->user, h->data);
			free(h->file);
			list_del(&h->list);
			free(h);
			return ret;
		}
	}
	return -1;
}

// XXX ugly hack ?
static int samefile(const char *a, const char *b)
{
	char *sa = strdup(a);
	char *sb = strdup(b);
	char *ptr;
	int ret;

	if (sa != NULL && sb != NULL) {
		do {
			ptr = strstr(sa, "//");
			if (ptr) strcpy(ptr, ptr+1);	
		} while(ptr);

		do {
			ptr = strstr(sb, "//");
			if (ptr) strcpy(ptr, ptr+1);	
		} while(ptr);
		ret = strcmp(sa,sb)?R_FALSE:R_TRUE;
	}

	free(sa);
	free(sb);
	return ret;
}

R_API int r_lib_open(struct r_lib_t *lib, const char *file)
{
	struct r_lib_struct_t *stru;
	void * handler;
	int ret;

//printf("OPENLIB(%s)\n", file);
	/* ignored by filename */
	if (!r_lib_dl_check_filename(file)) {
		IFDBG fprintf(stderr, "Invalid library extension: %s\n", file);
		return -1;
	}

	handler = r_lib_dl_open(file);
	if (handler == NULL) {
		IFDBG fprintf(stderr, "Cannot open library: '%s'\n", file);
		return -1;
	}
	
	stru = (struct r_lib_struct_t *) r_lib_dl_sym(handler, lib->symname);
	if (stru == NULL) {
		IFDBG fprintf(stderr, "No root symbol '%s' found in library '%s'\n", lib->symname, file);
		return -1;
	}
{
	struct list_head *pos;
	list_for_each_prev(pos, &lib->plugins) {
		struct r_lib_plugin_t *p = list_entry(pos, struct r_lib_plugin_t, list);
		if (samefile(file, p->file)) {
//printf("SKIP---------------(%s)\n", file);
			r_lib_dl_close(handler);
			return 0;
		}
	}
}
	struct r_lib_plugin_t *p = MALLOC_STRUCT(struct r_lib_plugin_t);
	p->type = stru->type;
	p->data = stru->data;
	p->file = strdup(file);
	p->dl_handler = handler;
	p->handler = r_lib_get_handler(lib, p->type);
	
//printf("ADD---------------(%s)\n", file);
	ret = r_lib_run_handler(lib, p, stru);
	if (ret == -1) {
		IFDBG fprintf(stderr, "Library handler returned -1 for '%s'\n", file);
		free(p->file);
		free(p);
		r_lib_dl_close(handler);
	} else {
		/* append plugin */
		list_add(&p->list, &lib->plugins);
	}
	return ret;
}

int r_lib_opendir(struct r_lib_t *lib, const char *path)
{
	char file[1024];
	struct dirent *de;
	DIR *dh;

#ifdef LIBR_PLUGINS
	if (path == NULL)
		path = LIBR_PLUGINS;
#endif
	if (path == NULL)
		return R_FALSE;

//printf("OPENPATH(%s)\n", path);
	dh = opendir(path);
	if (dh == NULL) {
		IFDBG fprintf(stderr, "Cannot open directory '%s'\n", path);
		return R_FALSE;
	}
	while((de = (struct dirent *)readdir(dh))) {
		snprintf(file, 1023, "%s/%s", path, de->d_name);
		r_lib_open(lib, file);
	}
	closedir(dh);
	return R_TRUE;
}

int r_lib_list(struct r_lib_t *lib)
{
	struct list_head *pos;
#if 0
	printf("Plugin Handlers:\n");
	list_for_each_prev(pos, &lib->handlers) {
		struct r_lib_handler_t *h = list_entry(pos, struct r_lib_handler_t, list);
		printf(" - %d: %s\n", h->type, h->desc);
	}
#endif
	//printf("Loaded plugins:\n");
	list_for_each_prev(pos, &lib->plugins) {
		struct r_lib_plugin_t *p = list_entry(pos, struct r_lib_plugin_t, list);
		printf(" %5s %p %s \n", r_lib_types_get(p->type), p->handler->destructor, p->file);
	}
	return 0;
}

int r_lib_add_handler(struct r_lib_t *lib,
	int type, const char *desc,
	int (*cb)(struct r_lib_plugin_t *, void *, void *),  /* constructor */
	int (*dt)(struct r_lib_plugin_t *, void *, void *),  /* destructor */
	void *user)
{
	struct list_head *pos;
	struct r_lib_handler_t *handler = NULL;

	list_for_each_prev(pos, &lib->handlers) {
		struct r_lib_handler_t *h = list_entry(pos, struct r_lib_handler_t, list);
		if (type == h->type) {
			IFDBG fprintf(stderr, "Redefining library handler constructor for %d\n", type);
			handler = h;
			break;
		}
	}
	if (handler == NULL) {
		handler = MALLOC_STRUCT(struct r_lib_handler_t);
		handler->type = type;
		list_add(&handler->list, &lib->handlers);
	}
	strncpy(handler->desc, desc, sizeof(handler->desc));
	handler->user = user;
	handler->constructor = cb;
	handler->destructor = dt;

//printf("constructor: %p\n", dt);
//printf("destructor : %p\n", dt);
	return 0;
}

#if 0
// TODO

int r_lib_del_handler(struct r_lib_t *lib)
{
	return 0;
}


#endif
