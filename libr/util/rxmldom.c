/* radare2 - LGPL - Copyright 2025 - pancake */
/* r_xmldom its a DOM api written on top of rxml.c */

#include <r_util.h>
#include <r_util/r_xml.h>

static RXmlAttr* rxml_add_attribute(RXmlNode *node, const char *key, const char *value) {
	RXmlAttr *attr = R_NEW (RXmlAttr);
	attr->key = strdup (key);
	attr->value = strdup (value);
	attr->next = node->attributes;
	node->attributes = attr;
	return attr;
}

static RXmlNode* rxml_add_child(RXmlNode *parent, RXmlNode *child) {
	R_RETURN_VAL_IF_FAIL (parent && child, NULL);
	child->next = parent->children;
	parent->children = child;
	return child;
}

R_API RXmlNode* rxml_dom_parse(const char *xml_string) {
	RXml *rx = r_xml_new (1024);
	RXmlNode *root = R_NEW0 (RXmlNode);
	root->type = RXML_NODE_TYPE_ELEMENT;
	RXmlNode *current_node = root;

	const char *p = xml_string;
	while (*p) {
		RXmlRet ret = r_xml_parse (rx, *p++);
		if (ret < 0) {
			break;
		}
		switch (ret) {
		case R_XML_ELEMSTART: {
			RXmlNode *node = R_NEW0 (RXmlNode);
			node->type = RXML_NODE_TYPE_ELEMENT;
			node->name = strdup (rx->elem);
			node->parent = current_node;
			rxml_add_child (current_node, node);
			current_node = node;
			break;
		}
		case R_XML_ELEMEND:
			if (current_node->parent) {
				current_node = current_node->parent;
			}
			break;
		case R_XML_ATTRSTART:
			break;
		case R_XML_ATTRVAL:
			if (rx->attr && rx->data[0]) {
				rxml_add_attribute (current_node, rx->attr, rx->data);
			}
			break;
		case R_XML_CONTENT:
			{
				RXmlNode *node = R_NEW0 (RXmlNode);
				node->type = RXML_NODE_TYPE_TEXT;
				node->text = strdup (rx->data);
				node->parent = current_node;
				rxml_add_child (current_node, node);
			}
			break;
		default:
			break;
		}
	}

	r_xml_free (rx);
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

R_API RXmlNode *rxml_dom_first_child(const RXmlNode *node) {
	return node ? node->children : NULL;
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

R_API int rxml_dom_is_element(const RXmlNode *node) {
	return node && node->type == RXML_NODE_TYPE_ELEMENT;
}

R_API int rxml_dom_is_text(const RXmlNode *node) {
	return node && node->type == RXML_NODE_TYPE_TEXT;
}
