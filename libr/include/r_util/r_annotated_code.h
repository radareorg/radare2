
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

/** Represents the type of annnotation. */
typedef enum r_code_annotation_type_t {
	R_CODE_ANNOTATION_TYPE_OFFSET, /*!< Gives the offset of the specified range in annotation. */
	R_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT, /*!< Represents the kind of data the specified range represents for highlighting purposes. */
	R_CODE_ANNOTATION_TYPE_FUNCTION_NAME, /*!< Specified range in annotation represents a function name. */
	R_CODE_ANNOTATION_TYPE_GLOBAL_VARIABLE, /*!< Specified range in annotation represents a global variable. */
	R_CODE_ANNOTATION_TYPE_CONSTANT_VARIABLE, /*!< Specified range in annotation represents a constant variable with an address. */
	R_CODE_ANNOTATION_TYPE_LOCAL_VARIABLE, /*!< Specified range in annotation represents a local variable. */
	R_CODE_ANNOTATION_TYPE_FUNCTION_PARAMETER, /*!< Specified range in annotation represents a function parameter. */
	// ...
} RCodeAnnotationType;

/**
 * \brief Annotations for the decompiled code are represented using this structure.
 */
typedef struct r_code_annotation_t {
	size_t start; /**< Start of the range in the annotation(inclusive). */
	size_t end; /**< End of the range in the annotation(exclusive). */
	RCodeAnnotationType type;
	union {
		/** If the annotation is of type R_CODE_ANNOTATION_TYPE_OFFSET,
		 * offset should be stored in the struct named offset in this union.
		 */
		struct {
			ut64 offset;
		} offset;
		/** If the annotation is of type R_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT,
		 * type of the syntax highlight will be stored in the struct named syntax_highlight
		 * in this union.
		 */
		struct {
			RSyntaxHighlightType type;
		} syntax_highlight;

		/** Information in annotations of type R_CODE_ANNOTATION_TYPE_FUNCTION_NAME,
		 * R_CODE_ANNOTATION_TYPE_GLOBAL_VARIABLE, and R_CODE_ANNOTATION_TYPE_CONSTANT_VARIABLE
		 * will be stored in the struct named reference in this union.
		 */
		struct {
			char *name;
			ut64 offset;
		} reference;

		/** Information in annotations of type R_CODE_ANNOTATION_TYPE_LOCAL_VARIABLE
		 * and R_CODE_ANNOTATION_TYPE_FUNCTION_PARAMETER will be stored in the 
		 * struct named variable in this union.
		 */
		struct {
			char *name;
		} variable;
	};
} RCodeAnnotation;
/**
 * \brief This structure contains the decompiled code and all the annotations for the decompiled code.
 */
typedef struct r_annotated_code_t {
	char *code; /**< Decompiled code. RAnnotatedCode owns this string and it must free it. */
	RVector annotations; /**< @ref RVector <RCodeAnnotation> contains the list of annotations for the decompiled code. */
} RAnnotatedCode;

/**
 * @brief Create and initialize a RAnnotatedCode structure and returns its pointer.
 * 
 * This function creates and initializes a new RAnnotatedCode
 * structure with the specified decompiled code that's passed
 * as an argument. Here, the argument code must be a string that can be deallocated.
 * This will initialize @ref RVector <RCodeAnnotation> annotations as well.
 * 
 * @param code A deallocatable character array.
 * @return Pointer to the new RAnnotatedCode structure created.
 */
R_API RAnnotatedCode *r_annotated_code_new(char *code);
/**
 * @brief Deallocates the dynamically allocated memory for the specified RAnnotatedCode.
 * 
 * @param code Pointer to a RAnnotatedCode.
 */
R_API void r_annotated_code_free(RAnnotatedCode *code);
/**
 * @brief Deallocates dynamically allocated memory for the specified annotation.
 * 
 * This function recognizes the type of the specified annotation and
 * frees memory that is dynamically allocated for it.
 * 
 * @param e Pointer to the annotation.
 * @param user Always NULL for this function. Present here for this function to be of the type @ref RVectorFree.
 */
R_API void r_annotation_free(void *e, void *user);
/**
 * @brief Checks if the specified annotation is a reference.
 * 
 * This function recognizes the type of the specified annotation and returns true if its
 * type is any of the following three: R_CODE_ANNOTATION_TYPE_GLOBAL_VARIABLE,
 * R_CODE_ANNOTATION_TYPE_CONSTANT_VARIABLE, R_CODE_ANNOTATION_TYPE_FUNCTION_NAME
 * 
 * @param annotation Pointer to an annotation.
 * @return Returns true if the specified annotation is a reference.
 */
R_API bool r_annotation_is_reference(RCodeAnnotation *annotation);
/**
 * @brief Checks if the specified annotation is a function variable.
 * 
 * This function recognizes the type of the specified annotation and returns true if its
 * type is any of the following two: R_CODE_ANNOTATION_TYPE_LOCAL_VARIABLE,
 * R_CODE_ANNOTATION_TYPE_FUNCTION_PARAMETER
 * 
 * @param annotation Pointer to an annotation.
 * @return Returns true if the specified annotation is a function variable.
 */
R_API bool r_annotation_is_variable(RCodeAnnotation *annotation);
/**
 * @brief Inserts the specified annotation into the list of annotations in the specified RAnnotatedCode.
 * 
 * @param code Pointer to a RAnnotatedCode.
 * @param annotation Pointer to an annotation.
 */
R_API void r_annotated_code_add_annotation(RAnnotatedCode *code, RCodeAnnotation *annotation);
/**
 * @brief Returns all annotations with range that contains the given offset.
 * 
 * Creates a @ref RPVector <RCodeAnnotation> and inserts the pointers to all annotations in which 
 * annotation->start <= offset < annotation->end.
 * 
 * @param code Pointer to a RAnnotatedCode.
 * @param offset Offset.
 * @return Pointer to the @ref RPVector created.
 */
R_API RPVector *r_annotated_code_annotations_in(RAnnotatedCode *code, size_t offset);
/**
 * @brief Returns all annotations with range that overlap with the specified range.
 * 
 * Creates an @ref RPVector <RCodeAnnotation> and inserts the pointers to all annotations whose 
 * range overlap with range specified.
 * 
 * @param code Pointer to a RAnnotatedCode.
 * @param start Start of the range(inclusive).
 * @param end End of the range(exclusive).
 * @return Pointer to the @ref RPVector created.
 */
R_API RPVector *r_annotated_code_annotations_range(RAnnotatedCode *code, size_t start, size_t end);
/**
 * @brief Returns the offset for every line of decompiled code in the specified RAnnotatedCode.
 * 
 * Creates an @ref RVector <ut64> and inserts the offsets for every seperate line of decompiled code in
 * the specified RAnnotatedCode.
 * If a line of decompiled code doesn't have a unique offset, UT64_MAX is inserted as its offset.
 * 
 * @param code Pointer to a RAnnotatedCode.
 * @return Pointer to the @ref RVector created.
 */
R_API RVector *r_annotated_code_line_offsets(RAnnotatedCode *code);

#ifdef __cplusplus
}
#endif

#endif //R_ANNOTATEDCODE_H
