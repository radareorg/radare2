/* radare2 - LGPL - Copyright 2025 - pancake */
/* r_xmldom its a DOM api written on top of rxml.c */

#include <r_util.h>
#include <r_util/r_xml.h>

static bool flush_text(RStrBuf *sb, RXmlNode *parent, RXmlNode ***tail) {
	const char *text = r_strbuf_get (sb);
	if (!*text) {
		return true;
	}
	RXmlNode *node = R_NEW0 (RXmlNode);
	node->type = RXML_NODE_TYPE_TEXT;
	node->parent = parent;
	node->text = strdup (text);
	**tail = node;
	*tail = &node->next;
	r_strbuf_set (sb, "");
	return node->text != NULL;
}

R_API RXmlNode *rxml_dom_parse(const char *xml_string) {
	R_RETURN_VAL_IF_FAIL (xml_string, NULL);
	RXml *rx = r_xml_new (1024);
	if (!rx) {
		return NULL;
	}
	RXmlNode *root = R_NEW0 (RXmlNode);
	root->type = RXML_NODE_TYPE_ELEMENT;
	RXmlNode *current = root;
	RXmlNode **child_tail = &root->children;
	RXmlAttr **attr_tail = &root->attributes;

	RStrBuf attribute, text;
	r_strbuf_init (&attribute);
	r_strbuf_init (&text);
	bool ok = true;
	const char *p = xml_string;
	while (*p && ok) {
		RXmlRet ret = r_xml_parse (rx, *p++);
		switch (ret) {
		case R_XML_ELEMSTART: {
			ok = flush_text (&text, current, &child_tail);
			RXmlNode *node = R_NEW0 (RXmlNode);
			node->type = RXML_NODE_TYPE_ELEMENT;
			node->name = strdup (rx->elem);
			node->parent = current;
			*child_tail = node;
			current = node;
			child_tail = &node->children;
			attr_tail = &node->attributes;
			ok = ok && node->name;
			break;
		}
		case R_XML_ELEMEND:
			ok = flush_text (&text, current, &child_tail);
			child_tail = &current->next;
			current = current->parent;
			break;
		case R_XML_ATTRSTART:
			r_strbuf_set (&attribute, "");
			break;
		case R_XML_ATTRVAL:
			ok = r_strbuf_append (&attribute, rx->data);
			break;
		case R_XML_ATTREND: {
			RXmlAttr *attr = R_NEW0 (RXmlAttr);
			attr->key = strdup (rx->attr);
			attr->value = strdup (r_strbuf_get (&attribute));
			*attr_tail = attr;
			attr_tail = &attr->next;
			ok = attr->key && attr->value;
			break;
		}
		case R_XML_CONTENT:
			ok = r_strbuf_append (&text, rx->data);
			break;
		default:
			ok = ret >= 0;
			break;
		}
	}
	ok = ok && r_xml_eof (rx) == R_XML_OK;
	r_strbuf_fini (&attribute);
	r_strbuf_fini (&text);
	r_xml_free (rx);
	if (!ok) {
		rxml_dom_free (root);
		return NULL;
	}
	return root;
}

R_API void rxml_dom_free(RXmlNode *node) {
	if (!node) {
		return;
	}
	RXmlNode *child = node->children;
	while (child) {
		RXmlNode *next = child->next;
		rxml_dom_free (child);
		child = next;
	}
	RXmlAttr *attr = node->attributes;
	while (attr) {
		RXmlAttr *next = attr->next;
		free (attr->key);
		free (attr->value);
		free (attr);
		attr = next;
	}
	free (node->name);
	free (node->text);
	free (node);
}

R_API const char *rxml_dom_get_attribute(const RXmlNode *node, const char *key) {
	RXmlAttr *attr = node ? node->attributes : NULL;
	while (attr) {
		if (!strcmp (attr->key, key)) {
			return attr->value;
		}
		attr = attr->next;
	}
	return NULL;
}

R_API ut64 rxml_dom_attr_ullong(const RXmlNode *node, const char *key, ut64 def) {
	const char *v = rxml_dom_get_attribute (node, key);
	return v ? strtoull (v, NULL, 0) : def;
}

R_API int rxml_dom_attr_int(const RXmlNode *node, const char *key, int def) {
	const char *v = rxml_dom_get_attribute (node, key);
	return v ? (int) strtol (v, NULL, 0) : def;
}

R_API ut32 rxml_dom_attr_uint(const RXmlNode *node, const char *key, ut32 def) {
	const char *v = rxml_dom_get_attribute (node, key);
	return v ? (ut32) strtoul (v, NULL, 0) : def;
}

R_API const char *rxml_dom_child_value(const RXmlNode *node) {
	R_RETURN_VAL_IF_FAIL (node, NULL);
	RXmlNode *child = node->children;
	while (child) {
		if (child->type == RXML_NODE_TYPE_TEXT) {
			return child->text;
		}
		child = child->next;
	}
	return NULL;
}

R_API const char *rxml_dom_text(const RXmlNode *node) {
	return (node && node->type == RXML_NODE_TYPE_TEXT) ? node->text : NULL;
}

R_API RXmlNode *rxml_dom_first_child(const RXmlNode *node) {
	return node ? node->children : NULL;
}

R_API RXmlNode *rxml_dom_child(const RXmlNode *node, const char *name) {
	if (!node || !name) {
		return NULL;
	}
	RXmlNode *child = node->children;
	while (child) {
		if (child->type == RXML_NODE_TYPE_ELEMENT && child->name && !strcmp (child->name, name)) {
			return child;
		}
		child = child->next;
	}
	return NULL;
}

R_API RXmlNode *rxml_dom_next_sibling(const RXmlNode *node) {
	return node ? node->next : NULL;
}

R_API RXmlNode *rxml_dom_parent(const RXmlNode *node) {
	return node ? node->parent : NULL;
}

R_API const char *rxml_dom_name(const RXmlNode *node) {
	return node ? node->name : NULL;
}

R_API bool rxml_dom_is_element(const RXmlNode *node) {
	return node && node->type == RXML_NODE_TYPE_ELEMENT;
}

R_API bool rxml_dom_is_text(const RXmlNode *node) {
	return node && node->type == RXML_NODE_TYPE_TEXT;
}
