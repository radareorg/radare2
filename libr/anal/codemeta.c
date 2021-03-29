/* radare2 - LGPL - Copyright 2020-2021 - nimmumanoj, pancake */

#include <r_util/r_codemeta.h>
#include <r_core.h>
#include <r_util.h>

R_API RCodeMeta *r_codemeta_new(const char *code) {
	RCodeMeta *r = R_NEW0 (RCodeMeta);
	if (!r) {
		return NULL;
	}
	r->code = strdup (code);
	r_vector_init (&r->annotations, sizeof (RCodeMetaItem), r_codemeta_item_free, NULL);
	return r;
}

R_API void r_codemeta_item_free(RCodeMetaItem *m, void *user) {
	(void)user;
	if (mi->type == R_CODE_ANNOTATION_TYPE_FUNCTION_NAME) {
		free (mi->reference.name);
	} else if (mi->type == R_CODE_ANNOTATION_TYPE_LOCAL_VARIABLE || annotation->type == R_CODE_ANNOTATION_TYPE_FUNCTION_PARAMETER) {
		free (mi->variable.name);
	}
}

R_API bool r_codemeta_item_is_reference(RCodeMetaItem *mi) {
	r_return_val_if_fail (mi, false);
	return (mi->type == R_CODE_ANNOTATION_TYPE_GLOBAL_VARIABLE || mi->type == R_CODE_ANNOTATION_TYPE_CONSTANT_VARIABLE || mi->type == R_CODE_ANNOTATION_TYPE_FUNCTION_NAME);
}

R_API bool r_codemeta_item_is_variable(RCodeMetaItem *mi) {
	r_return_val_if_fail (mi, false);
	return (mi->type == R_CODE_ANNOTATION_TYPE_LOCAL_VARIABLE || mi->type == R_CODE_ANNOTATION_TYPE_FUNCTION_PARAMETER);
}

R_API void r_codemeta_free(RCodeMeta *code) {
	if (!code) {
		return;
	}
	r_vector_clear (&code->annotations);
	r_free (code->code);
	r_free (code);
}

R_API void r_codemeta_add_annotation(RCodeMeta *code, RCodeMetaItem *annotation) {
	r_return_if_fail (code && annotation);
	r_vector_push (&code->annotations, annotation);
}

R_API RPVector *r_codemeta_annotations_in(RCodeMeta *code, ut64 offset) {
	r_return_val_if_fail (code, NULL);
	RPVector *r = r_pvector_new (NULL);
	if (!r) {
		return NULL;
	}
	RCodeMetaItem *annotation;
	r_vector_foreach (&code->annotations, annotation) {
		if (offset >= annotation->start && offset < annotation->end) {
			r_pvector_push (r, annotation);
		}
	}
	return r;
}

R_API RPVector *r_codemeta_range(RCodeMeta *code, ut64 start, ut64 end) {
	r_return_val_if_fail (code, NULL);
	RPVector *r = r_pvector_new (NULL);
	if (!r) {
		return NULL;
	}
	RCodeMetaItem *annotation;
	r_vector_foreach (&code->annotations, annotation) {
		if (start >= annotation->end || end < annotation->start) {
			continue;
		}
		r_pvector_push (r, annotation);
	}
	return r;
}

R_API RVector *r_codemeta_line_offsets(RCodeMeta *code) {
	r_return_val_if_fail (code, NULL);
	RVector *r = r_vector_new (sizeof (ut64), NULL, NULL);
	if (!r) {
		return NULL;
	}
	size_t cur = 0;
	size_t len = strlen (code->code);
	do {
		char *next = strchr (code->code + cur, '\n');
		size_t next_i = next? (next - code->code) + 1: len;
		RPVector *annotations = r_codemeta_range (code, cur, next_i);
		ut64 offset = UT64_MAX;
		void **it;
		r_pvector_foreach (annotations, it) {
			RCodeMetaItem *annotation = *it;
			if (annotation->type != R_CODE_ANNOTATION_TYPE_OFFSET) {
				continue;
			}
			offset = annotation->offset.offset;
			break;
		}
		r_vector_push (r, &offset);
		cur = next_i;
		r_pvector_free (annotations);
	} while (cur < len);
	return r;
}
