
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
	R_CODEMETA_TYPE_OFFSET, /*!< Gives the offset of the specified range in annotation. */
	R_CODEMETA_TYPE_SYNTAX_HIGHLIGHT, /*!< Represents the kind of data the specified range represents for highlighting purposes. */
	R_CODEMETA_TYPE_FUNCTION_NAME, /*!< Specified range in annotation represents a function name. */
	R_CODEMETA_TYPE_GLOBAL_VARIABLE, /*!< Specified range in annotation represents a global variable. */
	R_CODEMETA_TYPE_CONSTANT_VARIABLE, /*!< Specified range in annotation represents a constant variable with an address. */
	R_CODEMETA_TYPE_LOCAL_VARIABLE, /*!< Specified range in annotation represents a local variable. */
	R_CODEMETA_TYPE_FUNCTION_PARAMETER, /*!< Specified range in annotation represents a function parameter. */
	// ...
} RCodeMetaItemType;

/**
 * \brief Annotations for the decompiled code are represented using this structure.
 */
typedef struct r_codemeta_item_t {
	size_t start;
	size_t end;
	RCodeMetaItemType type;
	union {
		struct {
			ut64 offset;
		} offset;
		struct {
			RSyntaxHighlightType type;
		} syntax_highlight;

		struct {
			char *name;
			ut64 offset;
		} reference;

		struct {
			char *name;
		} variable;
	};
} RCodeMetaItem;

typedef struct r_codemeta_t {
	char *code; /**< Decompiled code. RCodeMeta owns this string and it must free it. */
	RVector annotations; /**< @ref RVector <RCodeMetaItem> contains the list of annotations for the decompiled code. */
} RCodeMeta;

R_API RCodeMeta *r_codemeta_new(const char *code);
R_API void r_codemeta_free(RCodeMeta *code);
R_API RCodeMetaItem *r_codemeta_item_new(void);
R_API void r_codemeta_item_free(RCodeMetaItem *e, void *user);
R_API bool r_codemeta_item_is_reference(RCodeMetaItem *annotation);
R_API bool r_codemeta_item_is_variable(RCodeMetaItem *annotation);
R_API void r_codemeta_add_annotation(RCodeMeta *code, RCodeMetaItem *annotation);
R_API RPVector *r_codemeta_at(RCodeMeta *code, size_t offset);
R_API RPVector *r_codemeta_in(RCodeMeta *code, size_t start, size_t end);
R_API RVector *r_codemeta_line_offsets(RCodeMeta *code);

#ifdef __cplusplus
}
#endif

#endif //R_ANNOTATEDCODE_H
