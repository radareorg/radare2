#include <r_anal.h>
#include <r_util.h>
#include <r_lib.h>

R_API void r_anal_esil_sources_init (RAnalEsil *esil) {
	if (esil && !esil->sources) {
		esil->sources =r_id_storage_new (1, 0xffffffff);	//0 is reserved for stuff from plugins
	}
}

R_API ut32 r_anal_esil_load_source(RAnalEsil *esil, const char *path) {
	RAnalEsilSource *src;

	if (!esil) {
		eprintf ("no esil?\n");
		return 0;
	}
	
	src = R_NEW0 (RAnalEsilSource);
	src->content = r_lib_dl_open(path);
	if (!src->content) {
		eprintf ("no content\n");
		free (src);
		return 0;
	}

	r_anal_esil_sources_init (esil);
	if (!r_id_storage_add(esil->sources, src, &src->id)) {
		eprintf ("cannot add to storage\n");
		r_lib_dl_close (src->content);
		free (src);
		return 0;
	}

	return src->id;
}

static RAnalEsilSource *_get_source(RAnalEsil *esil, ut32 src_id) {
	if (!esil || !esil->sources) {
		return NULL;
	}
	return (RAnalEsilSource *)r_id_storage_get (esil->sources, src_id);
}

R_API void *r_anal_esil_get_source(RAnalEsil *esil, ut32 src_id) {
	RAnalEsilSource *src = _get_source(esil, src_id);

	return src ? src->content : NULL;
}

R_API bool r_anal_esil_claim_source(RAnalEsil *esil, ut32 src_id) {
	RAnalEsilSource *src = _get_source(esil, src_id);

	if (src) {
		src->claimed++;
		return true;
	}
	return false;
}

R_API void r_anal_esil_release_source(RAnalEsil *esil, ut32 src_id) {
	RAnalEsilSource *src = _get_source(esil, src_id);

	if (!src) {
		return;
	}
	if (src->claimed <= 1) {
		r_id_storage_delete (esil->sources, src_id);
		r_lib_dl_close (src->content);
		free (src);
	} else {
		src->claimed--;
	}
}

static bool _free_source_cb(void *user, void *data, ut32 id) {
	RAnalEsilSource *src = (RAnalEsilSource *)data;

	if (src) {
		r_lib_dl_close (src->content);
	}
	free (src);
	return true;
}

R_API void r_anal_esil_sources_fini(RAnalEsil *esil) {
	if (esil) {
		r_id_storage_foreach(esil->sources, _free_source_cb, NULL);
		r_id_storage_free(esil->sources);
	}
}
