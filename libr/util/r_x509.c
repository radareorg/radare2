/* radare2 - LGPL - Copyright 2017 - wargio */

#include <r_util.h>
#include <stdlib.h>
#include <string.h>
#include <r_types.h>

#include "r_x509_internal.h"

bool r_x509_parse_validity (RX509Validity *validity, RASN1Object *object) {
	RASN1Object *o;
	if (!validity || !object || object->list.length != 2) {
		return false;
	}
	if (object->klass == CLASS_UNIVERSAL &&
			object->tag == TAG_SEQUENCE &&
			object->form == FORM_CONSTRUCTED) {
		o = object->list.objects[0];
		if (o->klass == CLASS_UNIVERSAL && o->form == FORM_PRIMITIVE) {
			if (o->tag == TAG_UTCTIME) {
				validity->notBefore = r_asn1_stringify_utctime (o->sector, o->length);
			} else if (o->tag == TAG_GENERALIZEDTIME) {
				validity->notBefore = r_asn1_stringify_time (o->sector, o->length);
			}
		}
		o = object->list.objects[1];
		if (o->klass == CLASS_UNIVERSAL && o->form == FORM_PRIMITIVE) {
			if (o->tag == TAG_UTCTIME) {
				validity->notAfter = r_asn1_stringify_utctime (o->sector, o->length);
			} else if (o->tag == TAG_GENERALIZEDTIME) {
				validity->notAfter = r_asn1_stringify_time (o->sector, o->length);
			}
		}
	}
	return true;
}

bool r_x509_parse_algorithmidentifier (RX509AlgorithmIdentifier *ai, RASN1Object * object) {
	if (!ai || !object || object->list.length < 1 || !object->list.objects) {
		return false;
	}
	if (object->list.objects[0] && object->list.objects[0]->klass == CLASS_UNIVERSAL && object->list.objects[0]->tag == TAG_OID) {
		ai->algorithm = r_asn1_stringify_oid (object->list.objects[0]->sector, object->list.objects[0]->length);
	}
	ai->parameters = NULL; // TODO
	//ai->parameters = asn1_stringify_sector (object->list.objects[1]);
	return true;
}

bool r_x509_parse_subjectpublickeyinfo (RX509SubjectPublicKeyInfo * spki, RASN1Object *object) {
	RASN1Object *o;
	if (!spki || !object || object->list.length != 2) {
		return false;
	}
	r_x509_parse_algorithmidentifier (&spki->algorithm, object->list.objects[0]);
	if (object->list.objects[1]) {
		o = object->list.objects[1];
		spki->subjectPublicKey = r_asn1_create_binary (o->sector, o->length);
		if (o->list.length == 1 && o->list.objects[0] && o->list.objects[0]->list.length == 2) {
			o = o->list.objects[0];
			if (o->list.objects[0]) {
				spki->subjectPublicKeyExponent = r_asn1_create_binary (o->list.objects[0]->sector, o->list.objects[0]->length);
			}
			if (o->list.objects[1]) {
				spki->subjectPublicKeyModule = r_asn1_create_binary (o->list.objects[1]->sector, o->list.objects[1]->length);
			}
		}
	}
	return true;
}

bool r_x509_parse_name (RX509Name *name, RASN1Object * object) {
	ut32 i;
	if (!name || !object || !object->list.length) {
		return false;
	}
	if (object->klass == CLASS_UNIVERSAL && object->tag == TAG_SEQUENCE) {
		name->length = object->list.length;
		name->names = (RASN1String**) calloc (name->length, sizeof (RASN1String*));
		if (!name->names) {
			name->length = 0;
			return false;
		}
		name->oids = (RASN1String**) calloc (name->length, sizeof (RASN1String*));
		if (!name->oids) {
			name->length = 0;
			free (name->names);
			name->names = NULL;
			return false;
		}
		for (i = 0; i < object->list.length; ++i) {
			RASN1Object *o = object->list.objects[i];
			if (o && o->klass == CLASS_UNIVERSAL &&
					o->tag == TAG_SET &&
					o->form == FORM_CONSTRUCTED &&
					o->list.length == 1) {
				o = o->list.objects[0];
				if (o && o->list.length > 1 &&
						o->klass == CLASS_UNIVERSAL &&
						o->tag == TAG_SEQUENCE) {
					if (o->list.objects[0]->klass == CLASS_UNIVERSAL &&
							o->list.objects[0]->tag == TAG_OID) {
						name->oids[i] = r_asn1_stringify_oid (o->list.objects[0]->sector, o->list.objects[0]->length);
					}
					RASN1Object *obj1 = o->list.objects[1];
					if (obj1 && obj1->klass == CLASS_UNIVERSAL) {
						name->names[i] = r_asn1_stringify_string (obj1->sector, obj1->length);
					}
				}
			}
		}
	}
	return true;
}

bool r_x509_parse_extension (RX509Extension *ext, RASN1Object *object) {
	RASN1Object *o;
	if (!ext || !object || object->list.length < 2) {
		return false;
	}
	o = object->list.objects[0];
	if (o && o->tag == TAG_OID) {
		ext->extnID = r_asn1_stringify_oid (o->sector, o->length);
		o = object->list.objects[1];
		if (o->tag == TAG_BOOLEAN) {
			//This field is optional (so len must be 3)
			ext->critical = o->sector[0] != 0;
			o = object->list.objects[2];
		}
		if (o->tag == TAG_OCTETSTRING) {
			ext->extnValue = r_asn1_create_binary (o->sector, o->length);
		}
	}
	return true;
}

bool r_x509_parse_extensions (RX509Extensions *ext, RASN1Object * object) {
	ut32 i;
	if (!ext || !object || object->list.length != 1 || !object->list.objects[0]->length) {
		return false;
	}
	object = object->list.objects[0];
	ext->extensions = (RX509Extension**) calloc (object->list.length, sizeof (RX509Extension*));
	if (!ext->extensions) {
		return false;
	}
	ext->length = object->list.length;
	for (i = 0; i < object->list.length; ++i) {
		ext->extensions[i] = R_NEW0 (RX509Extension);
		if (!r_x509_parse_extension (ext->extensions[i], object->list.objects[i])) {
			r_x509_free_extension (ext->extensions[i]);
			ext->extensions[i] = NULL;
		}
	}
	return true;
}

bool r_x509_parse_tbscertificate (RX509TBSCertificate *tbsc, RASN1Object * object) {
	RASN1Object **elems;
	ut32 i;
	ut32 shift = 0;
	if (!tbsc || !object || object->list.length < 6) {
		return false;
	}
	elems = object->list.objects;
	//Following RFC
	if (elems[0]->list.length == 1 &&
			elems[0]->klass == CLASS_CONTEXT &&
			elems[0]->form == FORM_CONSTRUCTED &&
			elems[0]->list.objects[0]->tag == TAG_INTEGER &&
			elems[0]->list.objects[0]->length == 1) {
		//Integer inside a CLASS_CONTEXT
		tbsc->version = (ut32) elems[0]->list.objects[0]->sector[0];
		shift = 1;
	} else {
		tbsc->version = 0;
	}
	if (shift < object->list.length && elems[shift]->klass == CLASS_UNIVERSAL && elems[shift]->tag == TAG_INTEGER) {
		tbsc->serialNumber = r_asn1_stringify_integer (elems[shift]->sector, elems[shift]->length);
	}
	r_x509_parse_algorithmidentifier (&tbsc->signature, elems[shift + 1]);
	r_x509_parse_name (&tbsc->issuer, elems[shift + 2]);
	r_x509_parse_validity (&tbsc->validity, elems[shift + 3]);
	r_x509_parse_name (&tbsc->subject, elems[shift + 4]);
	r_x509_parse_subjectpublickeyinfo (&tbsc->subjectPublicKeyInfo, elems[shift + 5]);
	if (tbsc->version > 0) {
		for (i = shift + 6; i < object->list.length; i++) {
			if (!elems[i] || elems[i]->klass != CLASS_CONTEXT) {
				continue;
			}
			if (elems[i]->tag == 1) {
				tbsc->issuerUniqueID = r_asn1_create_binary (object->list.objects[i]->sector, object->list.objects[i]->length);
			}
			if (!elems[i]) {
				continue;
			}
			if (elems[i]->tag == 2) {
				tbsc->subjectUniqueID = r_asn1_create_binary (object->list.objects[i]->sector, object->list.objects[i]->length);
			}
			if (!elems[i]) {
				continue;
			}
			if (tbsc->version == 2 && elems[i]->tag == 3 && elems[i]->form == FORM_CONSTRUCTED) {
				r_x509_parse_extensions (&tbsc->extensions, elems[i]);
			}
		}
	}
	return true;
}

RX509Certificate * r_x509_parse_certificate (RASN1Object *object) {
	RX509Certificate *certificate;
	RASN1Object *tmp;
	if (!object) {
		return NULL;
	}
	certificate = (RX509Certificate*) malloc (sizeof (RX509Certificate));
	if (!certificate) {
		r_asn1_free_object (object);
		return NULL;
	}
	memset (certificate, 0, sizeof (RX509Certificate));

	if (object->klass != CLASS_UNIVERSAL || object->form != FORM_CONSTRUCTED || object->list.length != 3) {
		// Malformed certificate
		// It needs to have tbsCertificate, algorithmIdentifier and a signature
		r_asn1_free_object (object);
		free (certificate);
		return NULL;
	}
	tmp = object->list.objects[2];
	if (!tmp) {
		r_asn1_free_object (object);
		free (certificate);
		return NULL;
	}
	if (tmp->klass != CLASS_UNIVERSAL || tmp->form != FORM_PRIMITIVE || tmp->tag != TAG_BITSTRING) {
		r_asn1_free_object (object);
		free (certificate);
		return NULL;
	}

	certificate->signature = r_asn1_create_binary (object->list.objects[2]->sector, object->list.objects[2]->length);

	r_x509_parse_tbscertificate (&certificate->tbsCertificate, object->list.objects[0]);

	if (!r_x509_parse_algorithmidentifier (&certificate->algorithmIdentifier, object->list.objects[1])) {
		r_asn1_free_object (object);
		free (certificate);
		return NULL;
	}
	r_asn1_free_object (object);
	return certificate;
}

RX509Certificate * r_x509_parse_certificate2 (const ut8 *buffer, ut32 length) {
	RX509Certificate *certificate;
	RASN1Object *object;
	if (!buffer || !length) {
		return NULL;
	}
	object = r_asn1_create_object (buffer, length);
	certificate = r_x509_parse_certificate (object);
	//object freed by r_x509_parse_certificate
	return certificate;
}

RX509CRLEntry *r_x509_parse_crlentry (RASN1Object *object) {
	RX509CRLEntry *entry;
	if (!object || object->list.length != 2) {
		return NULL;
	}
	entry = (RX509CRLEntry *) malloc (sizeof (RX509CRLEntry));
	if (!entry) {
		return NULL;
	}
	entry->userCertificate = r_asn1_create_binary (object->list.objects[0]->sector, object->list.objects[0]->length);
	entry->revocationDate = r_asn1_stringify_utctime (object->list.objects[1]->sector, object->list.objects[1]->length);
	return entry;
}

RX509CertificateRevocationList* r_x509_parse_crl (RASN1Object *object) {
	RX509CertificateRevocationList *crl;
	RASN1Object **elems;
	if (!object || object->list.length < 4) {
		return NULL;
	}
	crl = (RX509CertificateRevocationList *) malloc (sizeof (RX509CertificateRevocationList));
	if (!crl) {
		return NULL;
	}
	memset (crl, 0, sizeof (RX509CertificateRevocationList));
	elems = object->list.objects;
	r_x509_parse_algorithmidentifier (&crl->signature, elems[0]);
	r_x509_parse_name (&crl->issuer, elems[1]);
	crl->lastUpdate = r_asn1_stringify_utctime (elems[2]->sector, elems[2]->length);
	crl->nextUpdate = r_asn1_stringify_utctime (elems[3]->sector, elems[3]->length);
	if (object->list.length > 4) {
		ut32 i;
		crl->revokedCertificates = calloc (object->list.objects[4]->list.length, sizeof (RX509CRLEntry*));
		if (!crl->revokedCertificates) {
			free (crl);
			return NULL;
		}
		crl->length = object->list.objects[4]->list.length;
		for (i = 0; i < object->list.objects[4]->list.length; ++i) {
			crl->revokedCertificates[i] = r_x509_parse_crlentry (object->list.objects[4]->list.objects[i]);
		}
	}
	return crl;
}

void r_x509_free_algorithmidentifier (RX509AlgorithmIdentifier * ai) {
	if (!ai) {
		return;
	}
	r_asn1_free_string (ai->algorithm);
	r_asn1_free_string (ai->parameters);
	//no need to free ai, since this functions is used internally
}

void r_x509_free_validity (RX509Validity * validity) {
	if (!validity) {
		return;
	}
	r_asn1_free_string (validity->notAfter);
	r_asn1_free_string (validity->notBefore);
	// not freeing validity since it's not allocated dinamically
}

void r_x509_free_name (RX509Name * name) {
	ut32 i;
	if (!name) {
		return;
	}
	if (name->names) {
		for (i = 0; i < name->length; ++i) {
			r_asn1_free_string (name->oids[i]);
			r_asn1_free_string (name->names[i]);
		}
		R_FREE (name->names);
		R_FREE (name->oids);
	}
	// not freeing name since it's not allocated dinamically
}

void r_x509_free_extension (RX509Extension * ex) {
	if (ex) {
		r_asn1_free_string (ex->extnID);
		r_asn1_free_binary (ex->extnValue);
		//this is allocated dinamically so, i'll free
		free (ex);
	}
}

void r_x509_free_extensions (RX509Extensions * ex) {
	ut32 i;
	if (!ex) {
		return;
	}
	if (ex->extensions) {
		for (i = 0; i < ex->length; ++i) {
			r_x509_free_extension (ex->extensions[i]);
		}
		free (ex->extensions);
	}
	//no need to free ex, since this functions is used internally
}

void r_x509_free_subjectpublickeyinfo (RX509SubjectPublicKeyInfo * spki) {
	if (spki) {
		r_x509_free_algorithmidentifier (&spki->algorithm);
		r_asn1_free_binary (spki->subjectPublicKey);
		r_asn1_free_binary (spki->subjectPublicKeyExponent);
		r_asn1_free_binary (spki->subjectPublicKeyModule);
		// No need to free spki, since it's a static variable.
	}
}

void r_x509_free_tbscertificate (RX509TBSCertificate * tbsc) {
	if (tbsc) {
		//  version is ut32
		r_asn1_free_string (tbsc->serialNumber);
		r_x509_free_algorithmidentifier (&tbsc->signature);
		r_x509_free_name (&tbsc->issuer);
		r_x509_free_validity (&tbsc->validity);
		r_x509_free_name (&tbsc->subject);
		r_x509_free_subjectpublickeyinfo (&tbsc->subjectPublicKeyInfo);
		r_asn1_free_binary (tbsc->subjectUniqueID);
		r_asn1_free_binary (tbsc->issuerUniqueID);
		r_x509_free_extensions (&tbsc->extensions);
		//no need to free tbsc, since this functions is used internally
	}
}

void r_x509_free_certificate (RX509Certificate * certificate) {
	if (certificate) {
		r_asn1_free_binary (certificate->signature);
		r_x509_free_algorithmidentifier (&certificate->algorithmIdentifier);
		r_x509_free_tbscertificate (&certificate->tbsCertificate);
		free (certificate);
	}
}

void r_x509_free_crlentry (RX509CRLEntry *entry) {
	if (entry) {
		r_asn1_free_binary (entry->userCertificate);
		r_asn1_free_string (entry->revocationDate);
		free (entry);
	}
}

void r_x509_free_crl (RX509CertificateRevocationList *crl) {
	ut32 i;
	if (crl) {
		r_x509_free_algorithmidentifier (&crl->signature);
		r_x509_free_name (&crl->issuer);
		r_asn1_free_string (crl->nextUpdate);
		r_asn1_free_string (crl->lastUpdate);
		if (crl->revokedCertificates) {
			for (i = 0; i < crl->length; ++i) {
				r_x509_free_crlentry (crl->revokedCertificates[i]);
				crl->revokedCertificates[i] = NULL;
			}
			free (crl->revokedCertificates);
			crl->revokedCertificates = NULL;
		}
		free (crl);
	}
}

char* r_x509_validity_dump (RX509Validity* validity, char* buffer, ut32 length, const char* pad) {
	int p;
	if (!validity || !buffer || !length) {
		return NULL;
	}
	if (!pad)
		pad = "";
	const char* b = validity->notBefore ? validity->notBefore->string : "Missing";
	const char* a = validity->notAfter ? validity->notAfter->string : "Missing";
	p = snprintf (buffer, length, "%sNot Before: %s\n%sNot After: %s\n", pad, b, pad, a);
	return p < 0 ? NULL : buffer + (ut32) p;
}

char* r_x509_name_dump (RX509Name* name, char* buffer, ut32 length, const char* pad) {
	ut32 i, p, len;
	int r;
	char* c;
	if (!name || !buffer || !length) {
		return NULL;
	}
	if (!pad) {
		pad = "";
	}
	len = length;
	c = buffer;
	for (i = 0, p = 0; i < name->length; ++i) {
		if (!name->oids[i] || !name->names[i]) {
			continue;
		}
		if (len <= p) {
			return NULL;
		}
		r = snprintf (c + p, len - p, "%s%s: %s\n", pad, name->oids[i]->string, name->names[i]->string);
		p += r;
		if (r < 0 || len < p) {
			return NULL;
		}
	}
	return c + p;
}

char* r_x509_subjectpublickeyinfo_dump (RX509SubjectPublicKeyInfo* spki, char* buffer, ut32 length, const char* pad) {
	int r;
	const char *a;
	if (!spki || !buffer || !length) {
		return NULL;
	}
	if (!pad) {
		pad = "";
	}
	a = spki->algorithm.algorithm ? spki->algorithm.algorithm->string : "Missing";
	RASN1String* m = NULL;
	if (spki->subjectPublicKeyModule) {
		m = r_asn1_stringify_integer (spki->subjectPublicKeyModule->binary, spki->subjectPublicKeyModule->length);
	}
	//	RASN1String* e = r_asn1_stringify_bytes (spki->subjectPublicKeyExponent->sector, spki->subjectPublicKeyExponent->length);
	//	r = snprintf (buffer, length, "%sAlgorithm: %s\n%sModule: %s\n%sExponent: %u bytes\n%s\n", pad, a, pad, m->string,
	//				pad, spki->subjectPublicKeyExponent->length - 1, e->string);
	r = snprintf (buffer, length, "%sAlgorithm: %s\n%sModule: %s\n%sExponent: %u bytes\n", pad, a, pad, m ? m->string : "Missing",
				pad, spki->subjectPublicKeyExponent ? spki->subjectPublicKeyExponent->length - 1 : 0);
	r_asn1_free_string (m);
	//	r_asn1_free_string (e);
	return r < 0 ? NULL : buffer + (ut32) r;
}

char* r_x509_extensions_dump (RX509Extensions* exts, char* buffer, ut32 length, const char* pad) {
	ut32 i, p, len;
	int r;
	char* c;
	if (!exts || !buffer || !length) {
		return NULL;
	}
	if (!pad) {
		pad = "";
	}
	len = length;
	c = buffer;
	for (i = 0, p = 0, r = 0; i < exts->length; ++i) {
		//RASN1String *s;
		RX509Extension *e = exts->extensions[i];
		if (!e) continue;
		//TODO handle extensions..
		//s = r_asn1_stringify_bytes (e->extnValue->sector, e->extnValue->length);
		if (len < p) {
			return NULL;
		}
		r = snprintf (c + p, len - p, "%s%s: %s\n%s%u bytes\n", pad,
					e->extnID ? e->extnID->string : "Missing",
					e->critical ? "critical" : "",
					pad, e->extnValue ? e->extnValue->length : 0);
		p += r;
		//r_asn1_free_string (s);
		if (r < 0 || len <= p) {
			return NULL;
		}
	}
	return c + p;
}

char* r_x509_tbscertificate_dump (RX509TBSCertificate* tbsc, char* buffer, ut32 length, const char* pad) {
	RASN1String *sid = NULL, *iid = NULL;
	char *pad2, *tmp;
	ut32 p;
	int r;
	if (!tbsc || !buffer || !length) {
		return NULL;
	}
	if (!pad) {
		pad = "";
	}
	pad2 = r_str_newf ("%s  ", pad);
	if (!pad2) return NULL;
	r = snprintf (buffer, length, "%sVersion: v%u\n"
				"%sSerial Number:\n%s  %s\n"
				"%sSignature Algorithm:\n%s  %s\n"
				"%sIssuer:\n",
				pad, tbsc->version + 1,
				pad, pad, tbsc->serialNumber ? tbsc->serialNumber->string : "Missing",
				pad, pad, tbsc->signature.algorithm ? tbsc->signature.algorithm->string : "Missing",
				pad);
	p = (ut32) r;
	if (r < 0 || length <= p || !(tmp = r_x509_name_dump (&tbsc->issuer, buffer + p, length - p, pad2))) {
		free (pad2);
		return NULL;
	}
	p = tmp - buffer;
	if (length <= p) {
		free (pad2);
		return NULL;
	}
	r = snprintf (buffer + p, length - p, "%sValidity:\n", pad);
	p += r;
	if (r < 0 || length <= p || !(tmp = r_x509_validity_dump (&tbsc->validity, buffer + p, length - p, pad2))) {
		free (pad2);
		return NULL;
	}
	p = tmp - buffer;
	if (r < 0 || length <= p) {
		free (pad2);
		return NULL;
	}
	r = snprintf (buffer + p, length - p, "%sSubject:\n", pad);
	p += r;
	if (r < 0 || length <= p || !(tmp = r_x509_name_dump (&tbsc->subject, buffer + p, length - p, pad2))) {
		free (pad2);
		return NULL;
	}
	p = tmp - buffer;
	if (r < 0 || length <= p) {
		free (pad2);
		return NULL;
	}
	r = snprintf (buffer + p, length - p, "%sSubject Public Key Info:\n", pad);
	p += r;
	if (r < 0 || length <= p ||
			!(tmp = r_x509_subjectpublickeyinfo_dump (&tbsc->subjectPublicKeyInfo, buffer + p, length - p, pad2))) {
		free (pad2);
		return NULL;
	}
	p = tmp - buffer;
	if (tbsc->issuerUniqueID) {
		iid = r_asn1_stringify_integer (tbsc->issuerUniqueID->binary, tbsc->issuerUniqueID->length);
		if (iid) {
			if (length <= p) {
				r_asn1_free_string (iid);
				free (pad2);
				return NULL;
			}
			r = snprintf (buffer + p, length - p, "%sIssuer Unique ID:\n%s  %s", pad, pad, iid->string);
			p += r;
		} else {
			free (pad2);
			return NULL;
		}
		r_asn1_free_string (iid);
	}
	if (tbsc->subjectUniqueID) {
		sid = r_asn1_stringify_integer (tbsc->subjectUniqueID->binary, tbsc->subjectUniqueID->length);
		if (sid) {
			if (length <= p) {
				r_asn1_free_string (sid);
				free (pad2);
				return NULL;
			}
			r = snprintf (buffer + p, length - p, "%sSubject Unique ID:\n%s  %s", pad, pad, sid->string);
			p += r;
		} else {
			free (pad2);
			return NULL;
		}
		r_asn1_free_string (sid);
	}
	if (r < 0 || length <= p) {
		free (pad2);
		return NULL;
	}
	r = snprintf (buffer + p, length - p, "%sExtensions:\n", pad);
	p += r;
	if (r < 0 || length <= p || !(tmp = r_x509_extensions_dump (&tbsc->extensions, buffer + p, length - p, pad2))) {
		free (pad2);
		return NULL;
	}
	free (pad2);
	return buffer + p;
}

char* r_x509_certificate_dump (RX509Certificate* certificate, char* buffer, ut32 length, const char* pad) {
	//	RASN1String *signature,
	RASN1String *algo = NULL;
	ut32 p;
	int r;
	char *tbsc, *pad2;
	if (!certificate || !buffer || !length) {
		return NULL;
	}
	if (!pad) {
		pad = "";
	}
	pad2 = r_str_newf ("%s  ", pad);
	if (!pad2) {
		return NULL;
	}
	if ((r = snprintf (buffer, length, "%sTBSCertificate:\n", pad)) < 0) {
		return NULL;
	}
	p = (ut32) r;
	tbsc = r_x509_tbscertificate_dump (&certificate->tbsCertificate, buffer + p, length - p, pad2);
	p = tbsc - buffer;
	if (length <= p) {
		free (pad2);
		return NULL;
	}
	algo = certificate->algorithmIdentifier.algorithm;
	//	signature = r_asn1_stringify_bytes (certificate->signature->binary, certificate->signature->length);
	//	r = snprintf (buffer + p, length - p, "%sAlgorithm:\n%s%s\n%sSignature: %u bytes\n%s\n",
	//				pad, pad2, algo ? algo->string : "",
	//				pad, certificate->signature->length, signature ? signature->string : "");
	r = snprintf (buffer + p, length - p, "%sAlgorithm:\n%s%s\n%sSignature: %u bytes\n",
				pad, pad2, algo ? algo->string : "", pad, certificate->signature->length);
	if (r < 0) {
		free (pad2);
		return NULL;
	}
	p += (ut32) r;
	free (pad2);
	//	r_asn1_free_string (signature);
	return buffer + p;
}

char* r_x509_crlentry_dump (RX509CRLEntry *crle, char* buffer, ut32 length, const char* pad) {
	RASN1String *id = NULL, *utc = NULL;
	int r;
	if (!crle || !buffer || !length) {
		return NULL;
	}
	if (!pad) {
		pad = "";
	}
	utc = crle->revocationDate;
	if (crle->userCertificate) {
		id = r_asn1_stringify_integer (crle->userCertificate->binary, crle->userCertificate->length);
	}

	r = snprintf (buffer, length, "%sUser Certificate:\n%s  %s\n"
				"%sRevocation Date:\n%s  %s\n",
				pad, pad, id ? id->string : "Missing",
				pad, pad, utc ? utc->string : "Missing");

	r_asn1_free_string (id);
	return r < 0 ? NULL : buffer + (ut32) r;
}

char* r_x509_crl_dump (RX509CertificateRevocationList *crl, char* buffer, ut32 length, const char* pad) {
	RASN1String *algo = NULL, *last = NULL, *next = NULL;
	ut32 i, p;
	int r;
	char *tmp, *pad2, *pad3;
	if (!crl || !buffer || !length) {
		return NULL;
	}
	if (!pad) {
		pad = "";
	}
	pad3 = r_str_newf ("%s    ", pad);
	if (!pad3) return NULL;
	pad2 = pad3 + 2;
	algo = crl->signature.algorithm;
	last = crl->lastUpdate;
	next = crl->nextUpdate;
	r = snprintf (buffer, length, "%sCRL:\n%sSignature:\n%s%s\n%sIssuer\n",
				pad, pad2, pad3, algo ? algo->string : "", pad2);
	p = (ut32) r;
	if (r < 0 || !(tmp = r_x509_name_dump (&crl->issuer, buffer + p, length - p, pad3))) {
		free (pad3);
		return NULL;
	}
	p = tmp - buffer;
	if (length <= p) {
		free (pad3);
		return NULL;
	}
	r = snprintf (buffer + p, length - p, "%sLast Update: %s\n%sNext Update: %s\n%sRevoked Certificates:\n",
				pad2, last ? last->string : "Missing",
				pad2, next ? next->string : "Missing", pad2);
	p += (ut32) r;
	if (r < 0) {
		free (pad3);
		return NULL;
	}
	for (i = 0; i < crl->length; ++i) {
		if (length <= p || !(tmp = r_x509_crlentry_dump (crl->revokedCertificates[i], buffer + p, length - p, pad3))) {
			free (pad3);
			return NULL;
		}
		p = tmp - buffer;
	}

	free (pad3);
	return buffer + p;
}

RJSVar *r_x509_validity_json (RX509Validity* validity) {
	RJSVar* obj = r_json_object_new ();
	if (!validity) {
		return obj;
	}
	if (validity->notBefore) {
		r_json_object_add (obj, "NotBefore", r_json_string_new (validity->notBefore->string));
	}
	if (validity->notAfter) {
		r_json_object_add (obj, "NotAfter", r_json_string_new (validity->notAfter->string));
	}
	return obj;
}

RJSVar *r_x509_name_json (RX509Name* name) {
	ut32 i;
	RJSVar* obj = r_json_object_new ();
	if (!name) {
		return obj;
	}
	for (i = 0; i < name->length; ++i) {
		if (!name->oids[i] || !name->names[i]) {
			continue;
		}
		r_json_object_add (obj, name->oids[i]->string, r_json_string_new (name->names[i]->string));
	}
	return obj;
}

RJSVar* r_x509_subjectpublickeyinfo_json (RX509SubjectPublicKeyInfo* spki) {
	RASN1String *m = NULL;
	RJSVar *obj = r_json_object_new ();
	if (!spki) {
		return obj;
	}
	if (spki->algorithm.algorithm) {
		r_json_object_add (obj, "Algorithm", r_json_string_new (spki->algorithm.algorithm->string));
	}
	if (spki->subjectPublicKeyModule) {
		m = r_asn1_stringify_integer (spki->subjectPublicKeyModule->binary, spki->subjectPublicKeyModule->length);
		if (m) {
			r_json_object_add (obj, "Module", r_json_string_new (m->string));
		}
		r_asn1_free_string (m);
	}
	if (spki->subjectPublicKeyExponent) {
		m = r_asn1_stringify_integer (spki->subjectPublicKeyExponent->binary, spki->subjectPublicKeyExponent->length);
		if (m) {
			r_json_object_add (obj, "Exponent", r_json_string_new (m->string));
		}
		r_asn1_free_string (m);
	}
	return obj;
}

RJSVar *r_x509_extensions_json (RX509Extensions* exts) {
	ut32 i;
	RASN1String *m = NULL;
	RJSVar* array = NULL;
	if (!exts) {
		return array;
	}
	array = r_json_array_new (exts->length);
	for (i = 0; i < exts->length; ++i) {
		RX509Extension *e = exts->extensions[i];
		RJSVar* obj = r_json_object_new ();
		if (!e || !obj) {
			r_json_var_free (obj);
			continue;
		}
		if (e->extnID) {
			r_json_object_add (obj, "OID", r_json_string_new (e->extnID->string));
		}
		if (e->critical) {
			r_json_object_add (obj, "Critical", r_json_boolean_new (1));
		}
		//TODO handle extensions correctly..
		if (e->extnValue) {
			m = r_asn1_stringify_integer (e->extnValue->binary, e->extnValue->length);
			if (m) {
				r_json_object_add (obj, "Value", r_json_string_new (m->string));
			}
			r_asn1_free_string (m);
		}
		r_json_array_add (array, obj);
	}
	return array;
}

RJSVar *r_x509_crlentry_json (RX509CRLEntry *crle) {
	RASN1String *m = NULL;
	RJSVar* obj = r_json_object_new ();
	if (!crle) {
		return obj;
	}
	if (crle->userCertificate) {
		m = r_asn1_stringify_integer (crle->userCertificate->binary, crle->userCertificate->length);
		if (m) {
			r_json_object_add (obj, "UserCertificate", r_json_string_new (m->string));
		}
		r_asn1_free_string (m);
	}
	if (crle->revocationDate) {
		r_json_object_add (obj, "RevocationDate", r_json_string_new (crle->revocationDate->string));
	}
	return obj;
}

RJSVar *r_x509_crl_json (RX509CertificateRevocationList *crl) {
	ut32 i;
	RJSVar* obj = r_json_object_new ();
	RJSVar* array = NULL;
	if (!crl) {
		return obj;
	}

	if (crl->signature.algorithm) {
		r_json_object_add (obj, "Signature", r_json_string_new (crl->signature.algorithm->string));
	}
	r_json_object_add (obj, "Issuer", r_x509_name_json (&crl->issuer));
	if (crl->lastUpdate) {
		r_json_object_add (obj, "LastUpdate", r_json_string_new (crl->lastUpdate->string));
	}
	if (crl->nextUpdate) {
		r_json_object_add (obj, "NextUpdate", r_json_string_new (crl->nextUpdate->string));
	}

	array = r_json_array_new (crl->length);
	for (i = 0; i < crl->length; ++i) {
		r_json_array_add (array, r_x509_crlentry_json (crl->revokedCertificates[i]));
	}

	r_json_object_add (obj, "RevokedCertificates", array);
	return obj;
}

RJSVar *r_x509_tbscertificate_json (RX509TBSCertificate* tbsc) {
	RASN1String *m = NULL;
	RJSVar* obj = r_json_object_new ();
	if (!tbsc) {
		return obj;
	}
	r_json_object_add (obj, "Version", r_json_number_new (tbsc->version + 1));
	if (tbsc->serialNumber) {
		r_json_object_add (obj, "SerialNumber", r_json_string_new (tbsc->serialNumber->string));
	}
	if (tbsc->signature.algorithm) {
		r_json_object_add (obj, "SignatureAlgorithm", r_json_string_new (tbsc->signature.algorithm->string));
	}
	r_json_object_add (obj, "Issuer", r_x509_name_json (&tbsc->issuer));
	r_json_object_add (obj, "Validity", r_x509_validity_json (&tbsc->validity));
	r_json_object_add (obj, "Subject", r_x509_name_json (&tbsc->subject));
	r_json_object_add (obj, "SubjectPublicKeyInfo", r_x509_subjectpublickeyinfo_json (&tbsc->subjectPublicKeyInfo));
	if (tbsc->issuerUniqueID) {
		m = r_asn1_stringify_integer (tbsc->issuerUniqueID->binary, tbsc->issuerUniqueID->length);
		if (m) {
			r_json_object_add (obj, "IssuerUniqueID", r_json_string_new (m->string));
		}
		r_asn1_free_string (m);
	}
	if (tbsc->subjectUniqueID) {
		m = r_asn1_stringify_integer (tbsc->subjectUniqueID->binary, tbsc->subjectUniqueID->length);
		if (m) {
			r_json_object_add (obj, "SubjectUniqueID", r_json_string_new (m->string));
		}
		r_asn1_free_string (m);
	}
	r_json_object_add (obj, "Extensions", r_x509_extensions_json (&tbsc->extensions));
	return obj;
}

RJSVar* r_x509_certificate_json (RX509Certificate *certificate) {
	RASN1String *m = NULL;
	RJSVar* obj = r_json_object_new ();
	if (!certificate) {
		return obj;
	}
	r_json_object_add (obj, "TBSCertificate", r_x509_tbscertificate_json (&certificate->tbsCertificate));
	if (certificate->algorithmIdentifier.algorithm) {
		r_json_object_add (obj, "Algorithm", r_json_string_new (certificate->algorithmIdentifier.algorithm->string));
	}
	if (certificate->signature) {
		m = r_asn1_stringify_integer (certificate->signature->binary, certificate->signature->length);
		if (m) {
			r_json_object_add (obj, "Signature", r_json_string_new (m->string));
		}
		r_asn1_free_string (m);
	}
	return obj;
}
