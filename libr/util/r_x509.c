#include <r_util.h>
#include <stdlib.h>
#include <string.h>

#include "r_x509_internal.h"

bool r_x509_parse_validity (RX509Validity *validity, RASN1Object *object) {
	RASN1Object *o;
	if (!validity || !object || object->list.length != 2) {
		return false;
	}
	if (object->class == CLASS_UNIVERSAL &&
			object->tag == TAG_SEQUENCE &&
			object->form == FORM_CONSTRUCTED) {
		o = object->list.objects[0];
		if (o->class == CLASS_UNIVERSAL && o->form == FORM_PRIMITIVE) {
			if (o->tag == TAG_UTCTIME) {
				validity->notBefore = r_asn1_stringify_utctime (o->sector, o->length);
			} else if (o->tag == TAG_GENERALIZEDTIME) {
				validity->notBefore = r_asn1_stringify_time (o->sector, o->length);
			}
		}
		o = object->list.objects[1];
		if (o->class == CLASS_UNIVERSAL && o->form == FORM_PRIMITIVE) {
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
	if (!ai || !object || object->list.length < 1) {
		return false;
	}
	if (object->list.objects[0]->class == CLASS_UNIVERSAL && object->list.objects[0]->tag == TAG_OID) {
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
		spki->subjectPublicKey = o;
		object->list.objects[1] = NULL;
		//		if (o->length > 32) {
		//			spki->subjectPublicKey = asn1_stringify_bytes (o->sector, o->length);
		//		} else {
		//			spki->subjectPublicKey = asn1_stringify_bits (o->sector, o->length);
		//		}
		if (o->list.length == 1 && o->list.objects[0]->list.length == 2) {
			o = o->list.objects[0];
			if (o->list.objects[0]) {
				spki->subjectPublicKeyExponent = o->list.objects[0];
				o->list.objects[0] = NULL;
				//				if (o->list.objects[0]->length > 32) {
				//					spki->subjectPublicKeyExponent = asn1_stringify_bytes (o->list.objects[0]->sector, o->list.objects[0]->length);
				//				} else {
				//					spki->subjectPublicKeyExponent = asn1_stringify_integer (o->list.objects[0]->sector, o->list.objects[0]->length);
				//				}
			}
			if (o->list.objects[1]) {
				spki->subjectPublicKeyModule = o->list.objects[1];
				o->list.objects[1] = NULL;
				//				spki->subjectPublicKeyModule = asn1_stringify_integer (o->list.objects[1]->sector, o->list.objects[1]->length);
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
	if (object->class == CLASS_UNIVERSAL && object->tag == TAG_SEQUENCE) {
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
			if (o->class == CLASS_UNIVERSAL &&
					o->tag == TAG_SET &&
					o->form == FORM_CONSTRUCTED &&
					o->list.length == 1) {
				o = o->list.objects[0];
				if (o->class == CLASS_UNIVERSAL &&
						o->tag == TAG_SEQUENCE) {
					if (o->list.objects[0]->class == CLASS_UNIVERSAL &&
							o->list.objects[0]->tag == TAG_OID) {
						name->oids[i] = r_asn1_stringify_oid (o->list.objects[0]->sector, o->list.objects[0]->length);
					}
					if (o->list.objects[0]->class == CLASS_UNIVERSAL) {
						name->names[i] = r_asn1_stringify_string (o->list.objects[1]->sector, o->list.objects[1]->length);
					}
				}
			}
		}
	}
	return true;
}

bool r_x509_parse_extension (RX509Extension *ext, RASN1Object * object) {
	RASN1Object *o;
	if (!ext || !object || object->list.length < 2) {
		return false;
	}
	memset (ext, 0, sizeof (RX509Extension));
	o = object->list.objects[0];
	if (o && o->tag == TAG_OID) {
		ext->extnID = r_asn1_stringify_oid (object->list.objects[0]->sector, object->list.objects[0]->length);
		o = object->list.objects[1];
		if (o->tag == TAG_BOOLEAN) {
			//This field is optional (so len must be 3)
			ext->critical = o->sector[0] != 0;
			o = object->list.objects[2];
		}
		if (o->tag == TAG_OCTETSTRING) {
			ext->extnValue = o;
			if (o == object->list.objects[1]) {
				object->list.objects[1] = NULL;
			} else if (object->list.length > 2 && o == object->list.objects[2]) {
				object->list.objects[2] = NULL;
			}
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
		ext->extensions[i] = (RX509Extension*) malloc (sizeof (RX509Extension));
		if (!r_x509_parse_extension (ext->extensions[i], object->list.objects[i])) {
			free (ext->extensions[i]);
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
			elems[0]->class == CLASS_CONTEXT &&
			elems[0]->form == FORM_CONSTRUCTED &&
			elems[0]->list.objects[0]->tag == TAG_INTEGER &&
			elems[0]->list.objects[0]->length == 1) {
		//Integer inside a CLASS_CONTEXT
		tbsc->version = (ut32) elems[0]->list.objects[0]->sector[0];
		shift = 1;
	} else {
		tbsc->version = 0;
	}
	if (shift < object->list.length && elems[shift]->class == CLASS_UNIVERSAL && elems[shift]->tag == TAG_INTEGER) {
		tbsc->serialNumber = r_asn1_stringify_integer (elems[shift]->sector, elems[shift]->length);
	}
	r_x509_parse_algorithmidentifier (&tbsc->signature, elems[shift + 1]);
	r_x509_parse_name (&tbsc->issuer, elems[shift + 2]);
	r_x509_parse_validity (&tbsc->validity, elems[shift + 3]);
	r_x509_parse_name (&tbsc->subject, elems[shift + 4]);
	r_x509_parse_subjectpublickeyinfo (&tbsc->subjectPublicKeyInfo, elems[shift + 5]);
	if (tbsc->version > 0) {
		for (i = shift + 6; i < object->list.length; ++i) {
			if (elems[i]->class != CLASS_CONTEXT) continue;

			if (elems[i]->tag == 1) {
				tbsc->issuerUniqueID = elems[i];
				elems[i] = NULL;
			}

			if (elems[i]->tag == 2) {
				tbsc->subjectUniqueID = elems[i];
				elems[i] = NULL;
			}

			if (tbsc->version == 2 && elems[i]->tag == 3 && elems[i]->form == FORM_CONSTRUCTED) {
				r_x509_parse_extensions (&tbsc->extensions, elems[i]);
				elems[i] = NULL;
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
		return NULL;
	}
	memset (certificate, 0, sizeof (RX509Certificate));

	if (object->class != CLASS_UNIVERSAL || object->form != FORM_CONSTRUCTED || object->list.length != 3) {
		// Malformed certificate
		// It needs to have tbsCertificate, algorithmIdentifier and a signature
		r_asn1_free_object (object);
		free (certificate);
		return NULL;
	}
	tmp = object->list.objects[2];
	if (tmp->class != CLASS_UNIVERSAL || tmp->form != FORM_PRIMITIVE || tmp->tag != TAG_BITSTRING) {
		r_asn1_free_object (object);
		free (certificate);
		return NULL;
	}
	certificate->signature = object->list.objects[2];
	object->list.objects[2] = NULL;

	r_x509_parse_tbscertificate (&certificate->tbsCertificate, object->list.objects[0]);

	if (!r_x509_parse_algorithmidentifier (&certificate->algorithmIdentifier, object->list.objects[1])) {
		r_asn1_free_object (object);
		free (certificate);
		return NULL;
	}

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
	r_asn1_free_object (object);
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
	entry->userCertificate = object->list.objects[0];
	object->list.objects[0] = NULL;
	entry->revocationDate = r_asn1_stringify_utctime (object->list.objects[1]->sector, object->list.objects[1]->length);
	return entry;
}

RX509CertificateRevocationList* r_x509_parse_crl (RASN1Object *object) {
	RX509CertificateRevocationList *crl;
	RASN1Object **elems;
	if (!object && object->list.length < 4) {
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
	ut32 i;
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
		free (name->names);
	}
	// not freeing name since it's not allocated dinamically
}

void r_x509_free_extension (RX509Extension * ex) {
	if (ex) {
		r_asn1_free_string (ex->extnID);
		r_asn1_free_object (ex->extnValue);
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
		r_asn1_free_object (spki->subjectPublicKey);
		r_asn1_free_object (spki->subjectPublicKeyExponent);
		r_asn1_free_object (spki->subjectPublicKeyModule);
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
		r_asn1_free_object (tbsc->subjectUniqueID);
		r_asn1_free_object (tbsc->issuerUniqueID);
		r_x509_free_extensions (&tbsc->extensions);
		//no need to free tbsc, since this functions is used internally
	}
}

void r_x509_free_certificate (RX509Certificate * certificate) {
	if (certificate) {
		r_asn1_free_object (certificate->signature);
		r_x509_free_algorithmidentifier (&certificate->algorithmIdentifier);
		r_x509_free_tbscertificate (&certificate->tbsCertificate);
		free (certificate);
	}
}

void r_x509_free_crlentry (RX509CRLEntry *entry) {
	if (entry) {
		r_asn1_free_object (entry->userCertificate);
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

char* r_x509_validity_dump (RX509Validity* validity, const char* pad) {
	if (!validity) {
		return NULL;
	}
	if (!pad)
		pad = "";
	const char* b = validity->notBefore ? validity->notBefore->string : "Missing";
	const char* a = validity->notAfter ? validity->notAfter->string : "Missing";
	return r_str_newf ("%sNot Before: %s\n%sNot After: %s\n", pad, pad, b, a);
}

char* r_x509_name_dump (RX509Name* name, const char* pad) {
	ut32 i, p, len;
	char* c;
	if (!name) {
		return NULL;
	}
	if (!pad) {
		pad = "";
	}
	len = 1024;
	c = (char*) malloc (len);
	if (!c) {
		return NULL;
	}
	for (i = 0, p = 0; i < name->length; ++i) {
		if (!name->oids[i] || !name->names[i]) continue;
		if (name->oids[i]->length + name->names[i]->length >= len - p) {
			// adds +1
			char *t = r_str_newlen (c, len + 1023);
			free (c);
			if (!t) {
				return NULL;
			}
			memset (t + len, 0, 1024);
			c = t;
			len += 1024;
		}
		p = snprintf (c + p, len - p, "%s%s: %s\n", pad, name->oids[i]->string, name->names[i]->string);
	}
	return c;
}

char* r_x509_subjectpublickeyinfo_dump (RX509SubjectPublicKeyInfo* spki, const char* pad) {
	char *c;
	const char *a;
	if (!spki) {
		return NULL;
	}
	if (!pad)
		pad = "";
	a = spki->algorithm.algorithm->string;
	RASN1String* m = r_asn1_stringify_integer (spki->subjectPublicKeyModule->sector, spki->subjectPublicKeyModule->length);
	RASN1String* e = r_asn1_stringify_bytes (spki->subjectPublicKeyExponent->sector, spki->subjectPublicKeyExponent->length);
	c = r_str_newf ("%sAlgorithm: %s\n%sModule: %s\n%sExponent:\n%s\n", pad, a, pad, m->string, pad, e->string);
	r_asn1_free_string (m);
	r_asn1_free_string (e);
	return c;
}

char* r_x509_extensions_dump (RX509Extensions* exts, const char* pad) {
	ut32 i, p, len;
	char* c;
	if (!exts) {
		return NULL;
	}
	if (!pad) {
		pad = "";
	}
	len = 1024;
	c = (char*) malloc (len);
	if (!c) {
		return NULL;
	}
	for (i = 0, p = 0; i < exts->length; ++i) {
		//RASN1String *s;
		RX509Extension *e = exts->extensions[i];
		if (!e) continue;
		ut32 sum = e->extnID->length + 64;
		//s = r_asn1_stringify_bytes (e->extnValue->sector, e->extnValue->length);
		if (sum >= len - p) {
			// adds +1
			char *t = r_str_newlen (c, len + 1023);
			free (c);
			if (!t) {
				return NULL;
			}
			memset (t + len, 0, 1024);
			c = t;
			len += 1024;
		}
		p = snprintf (c + p, len - p, "%s%s: %s\n%s%u bytes\n", pad, e->extnID->string, e->critical ? "critical" : "", pad, e->extnValue->length);
		//r_asn1_free_string (s);
	}
	return c;
}

char* r_x509_tbscertificate_dump (RX509TBSCertificate* tbsc, const char* pad) {
	RASN1String *sid, *iid;
	char *str, *pad2, *issuer, *subject, *validity, *spki, *exts;
	if (tbsc) {
		return NULL;
	}
	if (!pad) {
		pad = "";
	}
	pad2 = r_str_newf ("%s  ", pad);
	//	tbsc->version
	issuer = r_x509_name_dump (&tbsc->issuer, pad2);
	validity = r_x509_validity_dump (&tbsc->validity, pad2);
	subject = r_x509_name_dump (&tbsc->subject, pad2);
	spki = r_x509_subjectpublickeyinfo_dump (&tbsc->subjectPublicKeyInfo, pad2);
	iid = r_asn1_stringify_integer (tbsc->issuerUniqueID->sector, tbsc->issuerUniqueID->length);
	sid = r_asn1_stringify_integer (tbsc->subjectUniqueID->sector, tbsc->subjectUniqueID->length);
	exts = r_x509_extensions_dump (&tbsc->extensions, pad2);

	str = r_str_newf ("%sVersion: v%u\n"
					"%sSerial Number:\n%s  %s\n"
					"%sSignature Algorithm:\n%s  %s\n"
					"%sIssuer:\n%s"
					"%sValidity:\n%s"
					"%sSubject:\n%s"
					"%sSubject Public Key Info:\n%s"
					"%sIssuer Unique ID:\n%s  %s"
					"%sSubject Unique ID:\n%s  %s"
					"%sExtensions:\n%s",
					pad, tbsc->version + 1,
					pad, pad, tbsc->serialNumber->string,
					pad, pad, tbsc->signature.algorithm->string,
					pad, issuer,
					pad, validity,
					pad, subject,
					pad, spki,
					pad, pad, iid ? iid->string : "",
					pad, pad, sid ? sid->string : "",
					pad, exts);
	free (issuer);
	free (validity);
	free (subject);
	free (spki);
	free (pad2);
	r_asn1_free_string (sid);
	r_asn1_free_string (iid);
	return str;
}

char* r_x509_generate_certificate_dump (RX509Certificate* certificate, const char* pad) {
	RASN1String *signature, *algo;
	char *str, *tbsc, *pad2;
	if (certificate) {
		return NULL;
	}
	if (!pad) {
		pad = "";
	}
	pad2 = r_str_newf ("%s  ", pad);
	algo = certificate->algorithmIdentifier.algorithm;
	signature = r_asn1_stringify_bytes (certificate->signature->sector, certificate->signature->length);
	tbsc = r_x509_tbscertificate_dump (&certificate->tbsCertificate, pad2);

	str = r_str_newf ("%sCertificate:\n"
					"%s"
					"Algorithm:\n%s\n"
					"%s",
					pad, tbsc,
					pad, algo ? algo->string : "",
					signature ? signature->string : "");

	free (tbsc);
	free (pad2);
	r_asn1_free_string (signature);
	return str;
}

char* r_x509_generate_crl_dump (RX509CertificateRevocationList *crl) {
	return NULL;
}
