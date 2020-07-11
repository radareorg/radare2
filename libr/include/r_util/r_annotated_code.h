
#ifndef R_ANNOTATEDCODE_H
#define R_ANNOTATEDCODE_H

// #include <r_core.h>
#include <r_types.h>
#include <r_vector.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum r_syntax_highlight_type_t {
	R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD,
	R_SYNTAX_HIGHLIGHT_TYPE_COMMENT,
	R_SYNTAX_HIGHLIGHT_TYPE_DATATYPE,
	R_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_NAME,
	R_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_PARAMETER,
	R_SYNTAX_HIGHLIGHT_TYPE_LOCAL_VARIABLE,
	R_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE,
	R_SYNTAX_HIGHLIGHT_TYPE_GLOBAL_VARIABLE,
} RSyntaxHighlightType;

/**
 * enum r_code_annotation_type_t - typedefed as RCodeAnnotationType and this gives types of annotation
 *
 * There are two kinds of RCodeAnnotation. One for offset, which of the type 
 * R_CODE_ANNOTATION_TYPE_OFFSET and other one is for syntax highlight, which is
 * of the type R_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT.
 * R_CODE_ANNOTATION_TYPE_OFFSET is for representing annotations that gives an offset for 
 * a range while R_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT is for representing the
 * kind of data the range represents. Here, range refers to the range of annotation.
 */

typedef enum r_code_annotation_type_t {
	R_CODE_ANNOTATION_TYPE_OFFSET,
	R_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT,
	// ...
} RCodeAnnotationType;

typedef struct r_code_annotation_t {
	size_t start;
	size_t end;
	RCodeAnnotationType type;
	union {
		struct {
			ut64 offset;
		} offset;

		struct {
			RSyntaxHighlightType type;
		} syntax_highlight;
	};
} RCodeAnnotation;

typedef struct r_annotated_code_t {
	char *code; // owned
	RVector /*<RCodeAnnotation>*/ annotations;
} RAnnotatedCode;

/**
 * r_annotated_code_new() - Creates a new RAnnotatedCode structure and returns its pointer.
 * @code: Literal code for which the RAnnotatedCode structure will be created .
 *
 * This functions creates a new RAnnotatedCode structure.
 * RAnnotatedCode.code will be initialized as the character array passed.
 * Here, code must be a string that can deallocated.
 * This will initialize RVector<RCodeAnnotation> annotations as well.
 * 
 * Return: Pointer to the new RAnnotatedCode structure created.
 */
R_API RAnnotatedCode *r_annotated_code_new(char *code);
/**
 * r_annotated_code_free() - Deallocates *code.
 * @code: Pointer to a RAnnotatedCode.
 *
 * This functions deallocates memory allocated for *code.
 * 
 * Return: Nothing.
 */
R_API void r_annotated_code_free(RAnnotatedCode *code);
/**
 * r_annotated_code_add_annotation() - Inserts *annotation in *code.
 * @code: Pointer to a RAnnotatedCode.
 * @annotation: Pointer to a annotation.
 *
 * This functions inserts the annotation represented by the pointer 'annotation' to the vector
 * of annotations in the RAnnotatedCode represented by 'code'. To be more precise,
 * annotation will be added to code->annotations, which is a RVector<RCodeAnnotation> annotations.
 * 
 * Return: Nothing.
 */
R_API void r_annotated_code_add_annotation(RAnnotatedCode *code, RCodeAnnotation *annotation);
/**
 * r_annotated_code_annotations_in() - Returns all annotations with range that contains the given offset.
 * @code: Pointer to a RAnnotatedCode.
 * @offset: Offset.
 *
 * Creates an RPVector and inserts the pointers to all annotations in which 
 * annotation->start <= offset < annotation->end.
 * 
 * Return: Pointer to the RPVecrtor created.
 */
R_API RPVector *r_annotated_code_annotations_in(RAnnotatedCode *code, size_t offset);
/**
 * r_annotated_code_annotations_range() - Returns all annotations with range that overlap with the given range.
 * @code: Pointer to a RAnnotatedCode.
 * @start: Start of the range(inclusive).
 * @end: End of the range(exclusive).
 *
 * Creates an RPVector and inserts the pointers to all annotations whose 
 * range overlap with range [start, end-1] (both inclusive).
 * 
 * Return: Pointer to the RPVecrtor created.
 */
R_API RPVector *r_annotated_code_annotations_range(RAnnotatedCode *code, size_t start, size_t end);
/**
 * r_annotated_code_line_offsets() - Returns the offset for every line of decompiled code in RAnnotatedCode *code.
 * @code: Pointer to a RAnnotatedCode.
 *
 * Creates an RVector and inserts the offsets for every seperate line of decompiled code in
 * code->code (code->code is a character array).
 * If a line of decompiled code doesn't have a unique offset, UT64_MAX is inserted as its offset.
 * 	
 * Return: Pointer to the RVector created.
 */
R_API RVector *r_annotated_code_line_offsets(RAnnotatedCode *code);

#ifdef __cplusplus
}
#endif

#endif //R_ANNOTATEDCODE_H
