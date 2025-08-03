/* Copyright (c) 2013-2014 Yoran Heling
// Copyright (c) 2023-2025 - pancake

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be included
  in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
  CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
  TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
  SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef R_XML_H
#define R_XML_H

#include <r_types.h>
#include <r_util/r_assert.h>

/* Full API documentation for this library can be found in the "r_xml.md" file
 * in the r_xml git repository, or online at http://dev.yorhel.nl/r_xml/man */

typedef enum {
	R_XML_EEOF        = -5, /* Unexpected EOF                             */
	R_XML_EREF        = -4, /* Invalid character or entity reference (&whatever;) */
	R_XML_ECLOSE      = -3, /* Close tag does not match open tag (<Tag> .. </OtherTag>) */
	R_XML_ESTACK      = -2, /* Stack overflow (too deeply nested tags or too long element/attribute name) */
	R_XML_ESYN        = -1, /* Syntax error (unexpected byte)             */
	R_XML_OK          =  0, /* Character consumed, no new token present   */
	R_XML_ELEMSTART   =  1, /* Start of an element:   '<Tag ..'           */
	R_XML_CONTENT     =  2, /* Element content                            */
	R_XML_ELEMEND     =  3, /* End of an element:     '.. />' or '</Tag>' */
	R_XML_ATTRSTART   =  4, /* Attribute:             'Name=..'           */
	R_XML_ATTRVAL     =  5, /* Attribute value                            */
	R_XML_ATTREND     =  6, /* End of attribute       '.."'               */
	R_XML_PISTART     =  7, /* Start of a processing instruction          */
	R_XML_PICONTENT   =  8, /* Content of a PI                            */
	R_XML_PIEND       =  9  /* End of a processing instruction            */
} RXmlRet;

/* When, exactly, are tokens returned?
 *
 * <TagName
 *   '>' ELEMSTART
 *   '/' ELEMSTART, '>' ELEMEND
 *   ' ' ELEMSTART
 *     '>'
 *     '/', '>' ELEMEND
 *     Attr
 *       '=' ATTRSTART
 *         "X ATTRVAL
 *           'Y'  ATTRVAL
 *             'Z'  ATTRVAL
 *               '"' ATTREND
 *                 '>'
 *                 '/', '>' ELEMEND
 *
 * </TagName
 *   '>' ELEMEND
 */

typedef enum r_xml_state_t {
	R_XML_STATE_STRING,
	R_XML_STATE_ATTR0,
	R_XML_STATE_ATTR1,
	R_XML_STATE_ATTR2,
	R_XML_STATE_ATTR3,
	R_XML_STATE_ATTR4,
	R_XML_STATE_CD0,
	R_XML_STATE_CD1,
	R_XML_STATE_CD2,
	R_XML_STATE_COMMENT0,
	R_XML_STATE_COMMENT1,
	R_XML_STATE_COMMENT2,
	R_XML_STATE_COMMENT3,
	R_XML_STATE_COMMENT4,
	R_XML_STATE_DT0,
	R_XML_STATE_DT1,
	R_XML_STATE_DT2,
	R_XML_STATE_DT3,
	R_XML_STATE_DT4,
	R_XML_STATE_ELEM0,
	R_XML_STATE_ELEM1,
	R_XML_STATE_ELEM2,
	R_XML_STATE_ELEM3,
	R_XML_STATE_ENC0,
	R_XML_STATE_ENC1,
	R_XML_STATE_ENC2,
	R_XML_STATE_ENC3,
	R_XML_STATE_ETAG0,
	R_XML_STATE_ETAG1,
	R_XML_STATE_ETAG2,
	R_XML_STATE_INIT,
	R_XML_STATE_le0,
	R_XML_STATE_le1,
	R_XML_STATE_le2,
	R_XML_STATE_le3,
	R_XML_STATE_LEE1,
	R_XML_STATE_LEE2,
	R_XML_STATE_LEQ0,
	R_XML_STATE_MISC0,
	R_XML_STATE_MISC1,
	R_XML_STATE_MISC2,
	R_XML_STATE_MISC2a,
	R_XML_STATE_MISC3,
	R_XML_STATE_PI0,
	R_XML_STATE_PI1,
	R_XML_STATE_PI2,
	R_XML_STATE_PI3,
	R_XML_STATE_PI4,
	R_XML_STATE_STD0,
	R_XML_STATE_STD1,
	R_XML_STATE_STD2,
	R_XML_STATE_STD3,
	R_XML_STATE_VER0,
	R_XML_STATE_VER1,
	R_XML_STATE_VER2,
	R_XML_STATE_VER3,
	R_XML_STATE_XMLDECL0,
	R_XML_STATE_XMLDECL1,
	R_XML_STATE_XMLDECL2,
	R_XML_STATE_XMLDECL3,
	R_XML_STATE_XMLDECL4,
	R_XML_STATE_XMLDECL5,
	R_XML_STATE_XMLDECL6,
	R_XML_STATE_XMLDECL7,
	R_XML_STATE_XMLDECL8,
	R_XML_STATE_XMLDECL9
} RXmlState;


typedef struct r_xml_t {
	/* PUBLIC (read-only) */

	/* Name of the current element, zero-length if not in any element. Changed
	 * after R_XML_ELEMSTART. The pointer will remain valid up to and including
	 * the next non-R_XML_ATTR* token, the pointed-to buffer will remain valid
	 * up to and including the R_XML_ELEMEND for the corresponding element. */
	char *elem;

	/* The last read character(s) of an attribute value (R_XML_ATTRVAL), element
	 * data (R_XML_CONTENT), or processing instruction (R_XML_PICONTENT). Changed
	 * after one of the respective R_XML_ values is returned, and only valid
	 * until the next r_xml_parse() call. Usually, this string only consists of
	 * a single byte, but multiple bytes are returned in the following cases:
	 * - "<?SomePI ?x ?>": The two characters "?x"
	 * - "<![CDATA[ ]x ]]>": The two characters "]x"
	 * - "<![CDATA[ ]]x ]]>": The three characters "]]x"
	 * - "&#N;" and "&#xN;", where dec(n) > 127. The referenced Unicode
	 *   character is then encoded in multiple UTF-8 bytes.
	 */
	char data[8];

	/* Name of the current attribute. Changed after R_XML_ATTRSTART, valid up to
	 * and including the next R_XML_ATTREND. */
	char *attr;

	/* Name/target of the current processing instruction, zero-length if not in
	 * a PI. Changed after R_XML_PISTART, valid up to (but excluding)
	 * the next R_XML_PIEND. */
	char *pi;

	/* Line number, byte offset within that line, and total bytes read. These
	 * values refer to the position _after_ the last byte given to
	 * r_xml_parse(). These are useful for debugging and error reporting. */
	ut64 byte;
	ut64 total;
	uint32_t line;

	/* PRIVATE */
	RXmlState state;
	ut8 *stack; /* Stack of element names + attribute/PI name, separated by \0. Also starts with a \0. */
	size_t stacksize, stacklen;
	unsigned int reflen;
	unsigned int quote;
	int nextstate; /* Used for '@' state remembering and for the "string" consuming state */
	unsigned int ignore;
	ut8 *string;
} RXml;


#ifdef __cplusplus
extern "C" {
#endif

R_API void r_xml_init(RXml *, void *, size_t);
R_API RXmlRet r_xml_parse(RXml *, int);

R_API RXml *r_xml_new(int stacksize);
R_API void r_xml_free(RXml *);
R_API char *r_xml_indent(const char *s);

/* May be called after the last character has been given to r_xml_parse().
 * Returns R_XML_OK if the XML document is valid, R_XML_EEOF otherwise.  Using
 * this function isn't really necessary, but can be used to detect documents
 * that don't end correctly. In particular, an error is returned when the XML
 * document did not contain a (complete) root element, or when the document
 * ended while in a comment or processing instruction. */
R_API RXmlRet r_xml_eof(RXml *);

/* Returns the length of the element name (x->elem), attribute name (x->attr),
 * or PI name (x->pi). This function should ONLY be used directly after the
 * R_XML_ELEMSTART, R_XML_ATTRSTART or R_XML_PISTART (respectively) tokens have
 * been returned by r_xml_parse(), calling this at any other time may not give
 * the correct results. This function should also NOT be used on strings other
 * than x->elem, x->attr or x->pi. */
static inline size_t r_xml_symlen(RXml *x, const char *s) {
	return (x->stack + x->stacklen) - (const ut8 *)s;
}

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	RXML_NODE_TYPE_ELEMENT,
	RXML_NODE_TYPE_TEXT
} RXmlNodeType;

typedef struct RXmlAttr {
	char *key;
	char *value;
	struct RXmlAttr *next;
} RXmlAttr;

typedef struct RXmlNode {
	RXmlNodeType type;
	char *name;
	char *text;
	RXmlAttr *attributes;
	struct RXmlNode *children;
	struct RXmlNode *next;
	struct RXmlNode *parent;
} RXmlNode;

// Parsing
RXmlNode* rxml_dom_parse(const char *xml_string);
void rxml_dom_free(RXmlNode *node);

// Node introspection
const char *rxml_dom_get_attribute(const RXmlNode *node, const char *key);
const char *rxml_dom_child_value(const RXmlNode *node);
const char *rxml_dom_name(const RXmlNode *node);
int rxml_dom_is_element(const RXmlNode *node);
int rxml_dom_is_text(const RXmlNode *node);

// Navigation
RXmlNode *rxml_dom_first_child(const RXmlNode *node);
RXmlNode *rxml_dom_next_sibling(const RXmlNode *node);
RXmlNode *rxml_dom_parent(const RXmlNode *node);

#ifdef __cplusplus
}
#endif

#endif // USE_RXML

#ifdef __cplusplus
}
#endif
