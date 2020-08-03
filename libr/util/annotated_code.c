
#include <r_util/r_annotated_code.h>
#include <r_core.h>
#include <r_util.h>

R_API RAnnotatedCode *r_annotated_code_new(char *code) {
	RAnnotatedCode *r = R_NEW0 (RAnnotatedCode);
	if (!r) {
		return NULL;
	}
	r->code = code;
	r_vector_init (&r->annotations, sizeof (RCodeAnnotation), r_annotation_free, NULL);
	return r;
}

R_API void r_annotation_free(void *e, void *user) {
	(void)user;
	RCodeAnnotation *annotation = e;
	if (annotation->type == R_CODE_ANNOTATION_TYPE_FUNCTION_NAME) {
		free (annotation->reference.name);
	} else if (annotation->type == R_CODE_ANNOTATION_TYPE_LOCAL_VARIABLE || annotation->type == R_CODE_ANNOTATION_TYPE_FUNCTION_PARAMETER) {
		free (annotation->variable.name);
	}
}

R_API bool r_annotation_is_reference(RCodeAnnotation *annotation) {
	return (annotation->type == R_CODE_ANNOTATION_TYPE_GLOBAL_VARIABLE || annotation->type == R_CODE_ANNOTATION_TYPE_CONSTANT_VARIABLE || annotation->type == R_CODE_ANNOTATION_TYPE_FUNCTION_NAME);
}

R_API bool r_annotation_is_variable(RCodeAnnotation *annotation) {
	return (annotation->type == R_CODE_ANNOTATION_TYPE_LOCAL_VARIABLE || annotation->type == R_CODE_ANNOTATION_TYPE_FUNCTION_PARAMETER);
}

R_API void r_annotated_code_free(RAnnotatedCode *code) {
	if (!code) {
		return;
	}
	r_vector_clear (&code->annotations);
	r_free (code->code);
	r_free (code);
}

R_API void r_annotated_code_add_annotation(RAnnotatedCode *code, RCodeAnnotation *annotation) {
	r_vector_push (&code->annotations, annotation);
}

R_API RPVector *r_annotated_code_annotations_in(RAnnotatedCode *code, size_t offset) {
	RPVector *r = r_pvector_new (NULL);
	if (!r) {
		return NULL;
	}
	RCodeAnnotation *annotation;
	r_vector_foreach (&code->annotations, annotation) {
		if (offset >= annotation->start && offset < annotation->end) {
			r_pvector_push (r, annotation);
		}
	}
	return r;
}

R_API RPVector *r_annotated_code_annotations_range(RAnnotatedCode *code, size_t start, size_t end) {
	RPVector *r = r_pvector_new (NULL);
	if (!r) {
		return NULL;
	}
	RCodeAnnotation *annotation;
	r_vector_foreach (&code->annotations, annotation) {
		if (start >= annotation->end || end < annotation->start) {
			continue;
		}
		r_pvector_push (r, annotation);
	}
	return r;
}

R_API RVector *r_annotated_code_line_offsets(RAnnotatedCode *code) {
	RVector *r = r_vector_new (sizeof (ut64), NULL, NULL);
	if (!r) {
		return NULL;
	}
	size_t cur = 0;
	size_t len = strlen (code->code);
	do {
		char *next = strchr (code->code + cur, '\n');
		size_t next_i = next? (next - code->code) + 1: len;
		RPVector *annotations = r_annotated_code_annotations_range (code, cur, next_i);
		ut64 offset = UT64_MAX;
		void **it;
		r_pvector_foreach (annotations, it) {
			RCodeAnnotation *annotation = *it;
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
