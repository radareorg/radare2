/* radare2 - LGPL - Copyright 2017-2021 - wargio */

#include <r_util.h>
#include <r_cons.h>
#include <stdlib.h>
#include <string.h>
#include "./x509.h"

static bool r_x509_parse_validity(RX509Validity *validity, RASN1Object *object) {
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

static inline bool is_oid_object (RASN1Object *object) {
	return object->list.objects[0] &&
		object->list.objects[0]->klass == CLASS_UNIVERSAL &&
		object->list.objects[0]->tag == TAG_OID;
}

bool r_x509_parse_algorithmidentifier (RX509AlgorithmIdentifier *ai, RASN1Object *object) {
	r_return_val_if_fail (ai && object, false);

	if (object->list.length < 1 || !object->list.objects || !is_oid_object (object)) {
			return false;
	}

	ai->algorithm = r_asn1_stringify_oid (object->list.objects[0]->sector, object->list.objects[0]->length);
	ai->parameters = NULL; // TODO
	//ai->parameters = asn1_stringify_sector (object->list.objects[1]);
	return true;
}

bool r_x509_parse_subjectpublickeyinfo (RX509SubjectPublicKeyInfo *spki, RASN1Object *object) {
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

R_API bool r_x509_parse_name(RX509Name *name, RASN1Object *object) {
	ut32 i;
	if (!name || !object || !object->list.length) {
		return false;
	}
	if (object->klass == CLASS_UNIVERSAL && object->tag == TAG_SEQUENCE) {
		name->length = object->list.length;
		name->names = (RASN1String **)calloc (name->length, sizeof (RASN1String *));
		if (!name->names) {
			name->length = 0;
			return false;
		}
		name->oids = (RASN1String **)calloc (name->length, sizeof (RASN1String *));
		if (!name->oids) {
			name->length = 0;
			R_FREE (name->names);
			return false;
		}
		for (i = 0; i < object->list.length; i++) {
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

R_API bool r_x509_parse_extension(RX509Extension *ext, RASN1Object *object) {
	RASN1Object *o;
	if (!ext || !object || object->list.length != 2) {
		return false;
	}
	o = object->list.objects[0];
	if (o && o->tag == TAG_OID) {
		ext->extnID = r_asn1_stringify_oid (o->sector, o->length);
		o = object->list.objects[1];
		if (o->tag == TAG_BOOLEAN && object->list.length > 2) {
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

R_API bool r_x509_parse_extensions(RX509Extensions *ext, RASN1Object *object) {
	ut32 i;
	if (!ext || !object || object->list.length != 1 || !object->list.objects[0]->length) {
		return false;
	}
	object = object->list.objects[0];
	ext->extensions = (RX509Extension **)calloc (object->list.length, sizeof (RX509Extension *));
	if (!ext->extensions) {
		return false;
	}
	ext->length = object->list.length;
	for (i = 0; i < object->list.length; i++) {
		ext->extensions[i] = R_NEW0 (RX509Extension);
		if (!r_x509_parse_extension (ext->extensions[i], object->list.objects[i])) {
			r_x509_free_extension (ext->extensions[i]);
			ext->extensions[i] = NULL;
		}
	}
	return true;
}

R_API bool r_x509_parse_tbscertificate (RX509TBSCertificate *tbsc, RASN1Object *object) {
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
		tbsc->version = (ut32)elems[0]->list.objects[0]->sector[0];
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

R_API RX509Certificate *r_x509_parse_certificate(RASN1Object *object) {
	if (!object) {
		return NULL;
	}
	RX509Certificate *cert = R_NEW0 (RX509Certificate);
	if (!cert) {
		goto fail;
	}
	if (object->klass != CLASS_UNIVERSAL || object->form != FORM_CONSTRUCTED || object->list.length != 3) {
		R_FREE (cert);
		goto fail;
	}
	RASN1Object *tmp = object->list.objects[2];
	if (!tmp) {
		R_FREE (cert);
		goto fail;
	}
	if (tmp->klass != CLASS_UNIVERSAL || tmp->form != FORM_PRIMITIVE || tmp->tag != TAG_BITSTRING) {
		R_FREE (cert);
		goto fail;
	}
	cert->signature = r_asn1_create_binary (object->list.objects[2]->sector, object->list.objects[2]->length);
	r_x509_parse_tbscertificate (&cert->tbsCertificate, object->list.objects[0]);

	if (!r_x509_parse_algorithmidentifier (&cert->algorithmIdentifier, object->list.objects[1])) {
		R_FREE (cert);
	}
fail:
	r_asn1_free_object (object);
	return cert;
}

R_API RX509Certificate *r_x509_parse_certificate2(const ut8 *buffer, ut32 length) {
	RX509Certificate *certificate;
	RASN1Object *object;
	if (!buffer || !length) {
		return NULL;
	}
	object = r_asn1_create_object (buffer, length, buffer);
	certificate = r_x509_parse_certificate (object);
	//object freed by r_x509_parse_certificate
	return certificate;
}

R_API RX509CRLEntry *r_x509_parse_crlentry(RASN1Object *object) {
	RX509CRLEntry *entry;
	if (!object || object->list.length != 2) {
		return NULL;
	}
	entry = (RX509CRLEntry *)malloc (sizeof (RX509CRLEntry));
	if (!entry) {
		return NULL;
	}
	entry->userCertificate = r_asn1_create_binary (object->list.objects[0]->sector, object->list.objects[0]->length);
	entry->revocationDate = r_asn1_stringify_utctime (object->list.objects[1]->sector, object->list.objects[1]->length);
	return entry;
}

R_API RX509CertificateRevocationList *r_x509_parse_crl(RASN1Object *object) {
	if (!object || object->list.length < 4) {
		return NULL;
	}
	RX509CertificateRevocationList *crl = R_NEW0 (RX509CertificateRevocationList);
	if (!crl) {
		return NULL;
	}
	RASN1Object **elems = object->list.objects;
	r_x509_parse_algorithmidentifier (&crl->signature, elems[0]);
	r_x509_parse_name (&crl->issuer, elems[1]);
	crl->lastUpdate = r_asn1_stringify_utctime (elems[2]->sector, elems[2]->length);
	crl->nextUpdate = r_asn1_stringify_utctime (elems[3]->sector, elems[3]->length);
	if (object->list.length > 4 && object->list.objects[4]) {
		ut32 i;
		crl->revokedCertificates = calloc (object->list.objects[4]->list.length, sizeof (RX509CRLEntry *));
		if (!crl->revokedCertificates) {
			free (crl);
			return NULL;
		}
		crl->length = object->list.objects[4]->list.length;
		for (i = 0; i < object->list.objects[4]->list.length; i++) {
			crl->revokedCertificates[i] = r_x509_parse_crlentry (object->list.objects[4]->list.objects[i]);
		}
	}
	return crl;
}

R_API void r_x509_free_algorithmidentifier(RX509AlgorithmIdentifier *ai) {
	if (ai) {
		// no need to free ai, since this functions is used internally
		r_asn1_free_string (ai->algorithm);
		r_asn1_free_string (ai->parameters);
	}
}

static void r_x509_free_validity(RX509Validity *validity) {
	if (validity) {
		// not freeing validity since it's not allocated dinamically
		r_asn1_free_string (validity->notAfter);
		r_asn1_free_string (validity->notBefore);
	}
}

R_API void r_x509_free_name(RX509Name *name) {
	ut32 i;
	if (!name) {
		return;
	}
	if (name->names) {
		for (i = 0; i < name->length; i++) {
			r_asn1_free_string (name->oids[i]);
			r_asn1_free_string (name->names[i]);
		}
		R_FREE (name->names);
		R_FREE (name->oids);
	}
	// not freeing name since it's not allocated dinamically
}

void r_x509_free_extension(RX509Extension *ex) {
	if (ex) {
		r_asn1_free_string (ex->extnID);
		r_asn1_free_binary (ex->extnValue);
		//this is allocated dinamically so, i'll free
		free (ex);
	}
}

void r_x509_free_extensions (RX509Extensions *ex) {
	ut32 i;
	if (!ex) {
		return;
	}
	if (ex->extensions) {
		for (i = 0; i < ex->length; i++) {
			r_x509_free_extension (ex->extensions[i]);
		}
		free (ex->extensions);
	}
	//no need to free ex, since this functions is used internally
}

void r_x509_free_subjectpublickeyinfo (RX509SubjectPublicKeyInfo *spki) {
	if (spki) {
		r_x509_free_algorithmidentifier (&spki->algorithm);
		r_asn1_free_binary (spki->subjectPublicKey);
		r_asn1_free_binary (spki->subjectPublicKeyExponent);
		r_asn1_free_binary (spki->subjectPublicKeyModule);
		// No need to free spki, since it's a static variable.
	}
}

void r_x509_free_tbscertificate (RX509TBSCertificate *tbsc) {
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

void r_x509_free_certificate (RX509Certificate *certificate) {
	if (certificate) {
		r_asn1_free_binary (certificate->signature);
		r_x509_free_algorithmidentifier (&certificate->algorithmIdentifier);
		r_x509_free_tbscertificate (&certificate->tbsCertificate);
		free (certificate);
	}
}

static void r_x509_free_crlentry(RX509CRLEntry *entry) {
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
			for (i = 0; i < crl->length; i++) {
				r_x509_free_crlentry (crl->revokedCertificates[i]);
				crl->revokedCertificates[i] = NULL;
			}
			R_FREE (crl->revokedCertificates);
		}
		free (crl);
	}
}

static void r_x509_validity_dump(RX509Validity *validity, const char *pad, RStrBuf *sb) {
	if (!validity) {
		return;
	}
	if (!pad) {
		pad = "";
	}
	const char *b = validity->notBefore ? validity->notBefore->string : "Missing";
	const char *a = validity->notAfter ? validity->notAfter->string : "Missing";
	r_strbuf_appendf (sb, "%sNot Before: %s\n%sNot After: %s\n", pad, b, pad, a);
}

void r_x509_name_dump (RX509Name *name, const char *pad, RStrBuf *sb) {
	ut32 i;
	if (!name) {
		return;
	}
	if (!pad) {
		pad = "";
	}
	for (i = 0; i < name->length; i++) {
		if (!name->oids[i] || !name->names[i]) {
			continue;
		}
		r_strbuf_appendf (sb, "%s%s: %s\n", pad, name->oids[i]->string, name->names[i]->string);
	}
}

static void r_x509_subjectpublickeyinfo_dump(RX509SubjectPublicKeyInfo *spki, const char *pad, RStrBuf *sb) {
	const char *a;
	if (!spki) {
		return;
	}
	if (!pad) {
		pad = "";
	}
	a = spki->algorithm.algorithm ? spki->algorithm.algorithm->string : "Missing";
	RASN1String *m = NULL;
	if (spki->subjectPublicKeyModule) {
		m = r_asn1_stringify_integer (spki->subjectPublicKeyModule->binary, spki->subjectPublicKeyModule->length);
	}
	//	RASN1String* e = r_asn1_stringify_bytes (spki->subjectPublicKeyExponent->sector, spki->subjectPublicKeyExponent->length);
	//	r = snprintf (buffer, length, "%sAlgorithm: %s\n%sModule: %s\n%sExponent: %u bytes\n%s\n", pad, a, pad, m->string,
	//				pad, spki->subjectPublicKeyExponent->length - 1, e->string);
	r_strbuf_appendf (sb, "%sAlgorithm: %s\n%sModule: %s\n%sExponent: %u bytes\n", pad, a, pad, m ? m->string : "Missing",
		pad, spki->subjectPublicKeyExponent ? spki->subjectPublicKeyExponent->length - 1 : 0);
	r_asn1_free_string (m);
	//	r_asn1_free_string (e);
}

static void r_x509_extensions_dump(RX509Extensions *exts, const char *pad, RStrBuf *sb) {
	ut32 i;
	if (!exts) {
		return;
	}
	if (!pad) {
		pad = "";
	}
	for (i = 0; i < exts->length; i++) {
		RX509Extension *e = exts->extensions[i];
		if (!e) {
			continue;
		}
		//TODO handle extensions..
		//s = r_asn1_stringify_bytes (e->extnValue->sector, e->extnValue->length);
		r_strbuf_appendf (sb, "%s%s: %s\n%s%u bytes\n", pad,
			e->extnID ? e->extnID->string : "Missing",
			e->critical ? "critical" : "",
			pad, e->extnValue ? e->extnValue->length : 0);
		//r_asn1_free_string (s);
	}
}

static void r_x509_tbscertificate_dump(RX509TBSCertificate *tbsc, const char *pad, RStrBuf *sb) {
	RASN1String *sid = NULL, *iid = NULL;
	if (!tbsc) {
		return;
	}
	if (!pad) {
		pad = "";
	}
	char *pad2 = r_str_newf ("%s  ", pad);
	if (!pad2) {
		return;
	}
	r_strbuf_appendf (sb, "%sVersion: v%u\n"
			      "%sSerial Number:\n%s  %s\n"
			      "%sSignature Algorithm:\n%s  %s\n"
			      "%sIssuer:\n",
		pad, tbsc->version + 1,
		pad, pad, tbsc->serialNumber ? tbsc->serialNumber->string : "Missing",
		pad, pad, tbsc->signature.algorithm ? tbsc->signature.algorithm->string : "Missing",
		pad);
	r_x509_name_dump (&tbsc->issuer, pad2, sb);

	r_strbuf_appendf (sb, "%sValidity:\n", pad);
	r_x509_validity_dump (&tbsc->validity, pad2, sb);

	r_strbuf_appendf (sb, "%sSubject:\n", pad);
	r_x509_name_dump (&tbsc->subject, pad2, sb);

	r_strbuf_appendf (sb, "%sSubject Public Key Info:\n", pad);
	r_x509_subjectpublickeyinfo_dump (&tbsc->subjectPublicKeyInfo, pad2, sb);

	if (tbsc->issuerUniqueID) {
		iid = r_asn1_stringify_integer (tbsc->issuerUniqueID->binary, tbsc->issuerUniqueID->length);
		if (iid) {
			r_strbuf_appendf (sb, "%sIssuer Unique ID:\n%s  %s", pad, pad, iid->string);
			r_asn1_free_string (iid);
		}
	}
	if (tbsc->subjectUniqueID) {
		sid = r_asn1_stringify_integer (tbsc->subjectUniqueID->binary, tbsc->subjectUniqueID->length);
		if (sid) {
			r_strbuf_appendf (sb, "%sSubject Unique ID:\n%s  %s", pad, pad, sid->string);
			r_asn1_free_string (sid);
		}
	}

	r_strbuf_appendf (sb, "%sExtensions:\n", pad);
	r_x509_extensions_dump (&tbsc->extensions, pad2, sb);
	free (pad2);
}

void r_x509_certificate_dump (RX509Certificate *cert, const char *pad, RStrBuf *sb) {
	RASN1String *algo = NULL;
	char *pad2;
	if (!cert) {
		return;
	}
	if (!pad) {
		pad = "";
	}
	pad2 = r_str_newf ("%s  ", pad);
	if (!pad2) {
		return;
	}
	r_strbuf_appendf (sb, "%sTBSCertificate:\n", pad);
	r_x509_tbscertificate_dump (&cert->tbsCertificate, pad2, sb);

	algo = cert->algorithmIdentifier.algorithm;
	//	signature = r_asn1_stringify_bytes (certificate->signature->binary, certificate->signature->length);
	//	eprintf ("%sAlgorithm:\n%s%s\n%sSignature: %u bytes\n%s\n",
	//				pad, pad2, algo ? algo->string : "",
	//				pad, certificate->signature->length, signature ? signature->string : "");
	r_strbuf_appendf (sb, "%sAlgorithm:\n%s%s\n%sSignature: %u bytes\n",
		pad, pad2, algo ? algo->string : "", pad, cert->signature->length);
	free (pad2);
	//	r_asn1_free_string (signature);
}

void r_x509_crlentry_dump (RX509CRLEntry *crle, const char *pad, RStrBuf *sb) {
	RASN1String *id = NULL, *utc = NULL;
	if (!crle) {
		return;
	}
	if (!pad) {
		pad = "";
	}
	utc = crle->revocationDate;
	if (crle->userCertificate) {
		id = r_asn1_stringify_integer (crle->userCertificate->binary, crle->userCertificate->length);
	}
	r_strbuf_appendf (sb, "%sUser Certificate:\n%s  %s\n"
			      "%sRevocation Date:\n%s  %s\n",
		pad, pad, id ? id->string : "Missing",
		pad, pad, utc ? utc->string : "Missing");
	r_asn1_free_string (id);
}

R_API char *r_x509_crl_to_string(RX509CertificateRevocationList *crl, const char *pad) {
	RASN1String *algo = NULL, *last = NULL, *next = NULL;
	ut32 i;
	char *pad2, *pad3;
	if (!crl) {
		return NULL;
	}
	if (!pad) {
		pad = "";
	}
	pad3 = r_str_newf ("%s    ", pad);
	if (!pad3) {
		return NULL;
	}
	pad2 = pad3 + 2;
	algo = crl->signature.algorithm;
	last = crl->lastUpdate;
	next = crl->nextUpdate;
	RStrBuf *sb = r_strbuf_new ("");
	r_strbuf_appendf (sb, "%sCRL:\n%sSignature:\n%s%s\n%sIssuer\n", pad, pad2, pad3,
		algo ? algo->string : "", pad2);
	r_x509_name_dump (&crl->issuer, pad3, sb);

	r_strbuf_appendf (sb, "%sLast Update: %s\n%sNext Update: %s\n%sRevoked Certificates:\n",
		pad2, last ? last->string : "Missing",
		pad2, next ? next->string : "Missing", pad2);

	for (i = 0; i < crl->length; i++) {
		r_x509_crlentry_dump (crl->revokedCertificates[i], pad3, sb);
	}

	free (pad3);
	return r_strbuf_drain (sb);
}

R_API void r_x509_validity_json(PJ *pj, RX509Validity *validity) {
	if (validity) {
		if (validity->notBefore) {
			pj_ks (pj, "NotBefore", validity->notBefore->string);
		}
		if (validity->notAfter) {
			pj_ks (pj, "NotAfter", validity->notAfter->string);
		}
	}
}

R_API void r_x509_name_json(PJ *pj, RX509Name *name) {
	ut32 i;
	for (i = 0; i < name->length; i++) {
		if (!name->oids[i] || !name->names[i]) {
			continue;
		}
		pj_ks (pj, name->oids[i]->string, name->names[i]->string);
	}
}

R_API void r_x509_subjectpublickeyinfo_json(PJ *pj, RX509SubjectPublicKeyInfo *spki) {
	RASN1String *m = NULL;
	if (spki) {
		if (spki->algorithm.algorithm) {
			pj_ks (pj, "Algorithm", spki->algorithm.algorithm->string);
		}
		if (spki->subjectPublicKeyModule) {
			m = r_asn1_stringify_integer (spki->subjectPublicKeyModule->binary, spki->subjectPublicKeyModule->length);
			if (m) {
				pj_ks (pj, "Module", m->string);
			}
			r_asn1_free_string (m);
		}
		if (spki->subjectPublicKeyExponent) {
			m = r_asn1_stringify_integer (spki->subjectPublicKeyExponent->binary, spki->subjectPublicKeyExponent->length);
			if (m) {
				pj_ks (pj, "Exponent", m->string);
			}
			r_asn1_free_string (m);
		}
	}
}

R_API void r_x509_extensions_json(PJ *pj, RX509Extensions *exts) {
	if (exts) {
		RASN1String *m = NULL;
		ut32 i;
		pj_a (pj);
		for (i = 0; i < exts->length; i++) {
			RX509Extension *e = exts->extensions[i];
			if (!e) {
				continue;
			}
			pj_o (pj);
			if (e->extnID) {
				pj_ks (pj, "OID", e->extnID->string);
			}
			if (e->critical) {
				pj_kb (pj, "Critical", e->critical);
			}
			//TODO handle extensions correctly..
			if (e->extnValue) {
				m = r_asn1_stringify_integer (e->extnValue->binary, e->extnValue->length);
				if (m) {
					pj_ks (pj, "Value", m->string);
				}
				r_asn1_free_string (m);
			}
			pj_end (pj);
		}
		pj_end (pj);
		pj_end (pj);
	}
}

R_API void r_x509_crlentry_json(PJ *pj, RX509CRLEntry *crle) {
	RASN1String *m = NULL;
	if (crle) {
		if (crle->userCertificate) {
			m = r_asn1_stringify_integer (crle->userCertificate->binary, crle->userCertificate->length);
			if (m) {
				pj_ks (pj, "UserCertificate", m->string);
			}
			r_asn1_free_string (m);
		}
		if (crle->revocationDate) {
			pj_ks (pj, "RevocationDate", crle->revocationDate->string);
		}
	}
}

R_API void r_x509_crl_json(PJ *pj, RX509CertificateRevocationList *crl) {
	ut32 i;
	if (crl) {
		if (crl->signature.algorithm) {
			pj_ks (pj, "Signature", crl->signature.algorithm->string);
		}
		pj_k (pj, "Issuer");
		pj_o (pj);
		r_x509_name_json (pj, &crl->issuer);
		pj_end (pj);
		if (crl->lastUpdate) {
			pj_ks (pj, "LastUpdate", crl->lastUpdate->string);
		}
		if (crl->nextUpdate) {
			pj_ks (pj, "NextUpdate", crl->nextUpdate->string);
		}
		pj_k (pj, "RevokedCertificates");
		pj_a (pj);
		for (i = 0; i < crl->length; i++) {
			r_x509_crlentry_json (pj, crl->revokedCertificates[i]);
		}
		pj_end (pj);
	}
}

R_API void r_x509_tbscertificate_json(PJ *pj, RX509TBSCertificate *tbsc) {
	pj_o (pj);
	RASN1String *m = NULL;
	if (tbsc) {
		pj_ki (pj, "Version", tbsc->version + 1);
		if (tbsc->serialNumber) {
			pj_ks (pj, "SerialNumber", tbsc->serialNumber->string);
		}
		if (tbsc->signature.algorithm) {
			pj_ks (pj, "SignatureAlgorithm", tbsc->signature.algorithm->string);
		}
		pj_k (pj, "Issuer");
		pj_o (pj);
		r_x509_name_json (pj, &tbsc->issuer);
		pj_end (pj);
		pj_k (pj, "Validity");
		pj_o (pj);
		r_x509_validity_json (pj, &tbsc->validity);
		pj_end (pj);
		pj_k (pj, "Subject");
		pj_o (pj);
		r_x509_name_json (pj, &tbsc->subject);
		pj_end (pj);
		pj_k (pj, "SubjectPublicKeyInfo");
		pj_o (pj);
		r_x509_subjectpublickeyinfo_json (pj, &tbsc->subjectPublicKeyInfo);
		pj_end (pj);
		if (tbsc->issuerUniqueID) {
			m = r_asn1_stringify_integer (tbsc->issuerUniqueID->binary, tbsc->issuerUniqueID->length);
			if (m) {
				pj_ks (pj, "IssuerUniqueID", m->string);
			}
			r_asn1_free_string (m);
		}
		if (tbsc->subjectUniqueID) {
			m = r_asn1_stringify_integer (tbsc->subjectUniqueID->binary, tbsc->subjectUniqueID->length);
			if (m) {
				pj_ks (pj, "SubjectUniqueID", m->string);
			}
			r_asn1_free_string (m);
		}
		pj_k (pj, "Extensions");
		r_x509_extensions_json (pj, &tbsc->extensions);
	}
}

R_API void r_x509_certificate_json(PJ *pj, RX509Certificate *certificate) {
	if (!certificate) {
		return;
	}
	RASN1String *m = NULL;
	pj_o (pj);
	pj_k (pj, "TBSCertificate");
	r_x509_tbscertificate_json (pj, &certificate->tbsCertificate);
	if (certificate->algorithmIdentifier.algorithm) {
		pj_ks (pj, "Algorithm", certificate->algorithmIdentifier.algorithm->string);
	}
	if (certificate->signature) {
		m = r_asn1_stringify_integer (certificate->signature->binary, certificate->signature->length);
		if (m) {
			pj_ks (pj, "Signature", m->string);
		}
		r_asn1_free_string (m);
	}
	pj_end (pj);
}
