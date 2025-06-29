/* radare2 - LGPL - Copyright 2017-2025 - pancake, wargio */

#include <r_util.h>
#include "x509.h"

static bool parse_validity(RX509Validity *validity, RASN1Object *object) {
	R_RETURN_VAL_IF_FAIL (validity && object, false);
	if (object->list.length != 2) {
		return false;
	}
	if (object->klass == CLASS_UNIVERSAL &&
		object->tag == TAG_SEQUENCE &&
		object->form == FORM_CONSTRUCTED) {
		RASN1Object *o = object->list.objects[0];
		if (o->klass == CLASS_UNIVERSAL && o->form == FORM_PRIMITIVE) {
			if (o->tag == TAG_UTCTIME) {
				validity->notBefore = r_asn1_stringify_utctime (o->sector, o->length);
			} else if (o->tag == TAG_GENERALIZEDTIME) {
				validity->notBefore = r_asn1_stringify_time (o->sector, o->length);
			}
		}
		o = object->list.objects[1];
		if (o && o->klass == CLASS_UNIVERSAL && o->form == FORM_PRIMITIVE) {
			if (o->tag == TAG_UTCTIME) {
				validity->notAfter = r_asn1_stringify_utctime (o->sector, o->length);
			} else if (o->tag == TAG_GENERALIZEDTIME) {
				validity->notAfter = r_asn1_stringify_time (o->sector, o->length);
			}
		}
	}
	return true;
}

static inline bool is_oid_object(RASN1Object *object) {
	return object->list.objects[0] &&
		object->list.objects[0]->klass == CLASS_UNIVERSAL &&
		object->list.objects[0]->tag == TAG_OID;
}

static void fini_validity(RX509Validity *validity) {
	R_RETURN_IF_FAIL (validity);
	r_asn1_string_free (validity->notAfter);
	r_asn1_string_free (validity->notBefore);
}

static void crlentry_free(RX509CRLEntry * R_NULLABLE entry) {
	if (entry) {
		r_asn1_binary_free (entry->userCertificate);
		r_asn1_string_free (entry->revocationDate);
		free (entry);
	}
}

static void validity_dump(RX509Validity *validity, const char *pad, RStrBuf *sb) {
	R_RETURN_IF_FAIL (validity && sb);
	if (!pad) {
		pad = "";
	}
	const char *b = validity->notBefore ? validity->notBefore->string : "Missing";
	const char *a = validity->notAfter ? validity->notAfter->string : "Missing";
	r_strbuf_appendf (sb, "%sNot Before: %s\n%sNot After: %s\n", pad, b, pad, a);
}

R_IPI bool r_x509_algorithmidentifier_parse(RX509AlgorithmIdentifier *ai, RASN1Object *object) {
	R_RETURN_VAL_IF_FAIL (ai && object, false);
	if (object->list.length < 1 || !object->list.objects || !is_oid_object (object)) {
			return false;
	}

	ai->algorithm = r_asn1_stringify_oid (object->list.objects[0]->sector, object->list.objects[0]->length);
	ai->parameters = NULL; // TODO
	//ai->parameters = asn1_stringify_sector (object->list.objects[1]);
	return true;
}

R_IPI void r_x509_algorithmidentifier_fini(RX509AlgorithmIdentifier *ai) {
	R_RETURN_IF_FAIL (ai);
	r_asn1_string_free (ai->algorithm);
	r_asn1_string_free (ai->parameters);
}

static bool r_x509_subjectpublickeyinfo_parse(RX509SubjectPublicKeyInfo *spki, RASN1Object *object) {
	R_RETURN_VAL_IF_FAIL (spki && object, false);
	if (!spki || !object || object->list.length != 2) {
		return false;
	}
	r_x509_algorithmidentifier_parse (&spki->algorithm, object->list.objects[0]);
	if (object->list.objects[1]) {
		RASN1Object *o = object->list.objects[1];
		spki->subjectPublicKey = r_asn1_binary_new (o->sector, o->length);
	}
	return true;
}

static void r_x509_subjectpublickeyinfo_fini(RX509SubjectPublicKeyInfo *spki) {
	R_RETURN_IF_FAIL (spki);
	r_x509_algorithmidentifier_fini (&spki->algorithm);
	r_asn1_binary_free (spki->subjectPublicKey);
}

R_IPI bool r_x509_name_parse(RX509Name *name, RASN1Object *object) {
	R_RETURN_VAL_IF_FAIL (name && object, false);
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
		ut32 i;
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
						name->oids[i] = r_asn1_stringify_oid (o->list.objects[0]->sector,
								o->list.objects[0]->length);
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

R_IPI void r_x509_name_fini(RX509Name *name) {
	R_RETURN_IF_FAIL (name);
	if (name->names) {
		ut32 i;
		for (i = 0; i < name->length; i++) {
			r_asn1_string_free (name->oids[i]);
			r_asn1_string_free (name->names[i]);
		}
		R_FREE (name->names);
		R_FREE (name->oids);
	}
}

static bool r_x509_extension_parse(RX509Extension *ext, RASN1Object *object) {
	R_RETURN_VAL_IF_FAIL (ext && object, false);
	if (object->list.length != 2) {
		return false;
	}
	RASN1Object *o = object->list.objects[0];
	if (o && o->tag == TAG_OID) {
		ext->extnID = r_asn1_stringify_oid (o->sector, o->length);
		o = object->list.objects[1];
		if (o->tag == TAG_BOOLEAN && object->list.length > 2) {
			// This field is optional (so len must be 3)
			ext->critical = o->sector[0] != 0;
			o = object->list.objects[2];
		}
		if (o->tag == TAG_OCTETSTRING) {
			ext->extnValue = r_asn1_binary_new (o->sector, o->length);
		}
	}
	return true;
}

R_API void r_x509_extension_free(RX509Extension * R_NULLABLE ex) {
	if (ex) {
		r_asn1_string_free (ex->extnID);
		r_asn1_binary_free (ex->extnValue);
		free (ex);
	}
}

static bool r_x509_extensions_parse(RX509Extensions *ext, RASN1Object *object) {
	R_RETURN_VAL_IF_FAIL (ext && object, false);
	if (!ext || !object || object->list.length != 1 || !object->list.objects[0]->length) {
		return false;
	}
	object = object->list.objects[0];
	ext->extensions = (RX509Extension **)calloc (object->list.length, sizeof (RX509Extension *));
	if (!ext->extensions) {
		return false;
	}
	ext->length = object->list.length;
	ut32 i;
	for (i = 0; i < object->list.length; i++) {
		ext->extensions[i] = R_NEW0 (RX509Extension);
		if (!r_x509_extension_parse (ext->extensions[i], object->list.objects[i])) {
			r_x509_extension_free (ext->extensions[i]);
			ext->extensions[i] = NULL;
		}
	}
	return true;
}

static void r_x509_extensions_fini(RX509Extensions *ex) {
	R_RETURN_IF_FAIL (ex);
	if (ex->extensions) {
		ut32 i;
		for (i = 0; i < ex->length; i++) {
			r_x509_extension_free (ex->extensions[i]);
		}
		free (ex->extensions);
	}
}

static bool r_x509_tbscertificate_parse(RX509TBSCertificate *tbsc, RASN1Object *object) {
	R_RETURN_VAL_IF_FAIL (tbsc && object, false);
	if (object->list.length < 6) {
		return false;
	}
	RASN1Object **elems = object->list.objects;
	ut32 shift = 0;
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
	if (shift < object->list.length && elems[shift]->klass == CLASS_UNIVERSAL \
			&& elems[shift]->tag == TAG_INTEGER) {
		tbsc->serialNumber = r_asn1_stringify_integer (elems[shift]->sector, elems[shift]->length);
	}
	if (object->list.length < shift + 6) {
		return false;
	}
	r_x509_algorithmidentifier_parse (&tbsc->signature, elems[shift + 1]);
	r_x509_name_parse (&tbsc->issuer, elems[shift + 2]);
	parse_validity (&tbsc->validity, elems[shift + 3]);
	r_x509_name_parse (&tbsc->subject, elems[shift + 4]);
	r_x509_subjectpublickeyinfo_parse (&tbsc->subjectPublicKeyInfo, elems[shift + 5]);
	if (tbsc->version > 0) {
		ut32 i;
		for (i = shift + 6; i < object->list.length; i++) {
			if (!elems[i] || elems[i]->klass != CLASS_CONTEXT) {
				continue;
			}
			if (elems[i]->tag == 1) {
				tbsc->issuerUniqueID = r_asn1_binary_new (object->list.objects[i]->sector,
						object->list.objects[i]->length);
			}
			if (!elems[i]) {
				continue;
			}
			if (elems[i]->tag == 2) {
				tbsc->subjectUniqueID = r_asn1_binary_new (object->list.objects[i]->sector,
						object->list.objects[i]->length);
			}
			if (!elems[i]) {
				continue;
			}
			if (tbsc->version == 2 && elems[i]->tag == 3 && elems[i]->form == FORM_CONSTRUCTED) {
				r_x509_extensions_parse (&tbsc->extensions, elems[i]);
			}
		}
	}
	return true;
}

static void r_x509_tbscertificate_fini(RX509TBSCertificate *tbsc) {
	R_RETURN_IF_FAIL (tbsc);
	r_asn1_string_free (tbsc->serialNumber);
	r_x509_algorithmidentifier_fini (&tbsc->signature);
	r_x509_name_fini (&tbsc->issuer);
	fini_validity (&tbsc->validity);
	r_x509_name_fini (&tbsc->subject);
	r_x509_subjectpublickeyinfo_fini (&tbsc->subjectPublicKeyInfo);
	r_asn1_binary_free (tbsc->subjectUniqueID);
	r_asn1_binary_free (tbsc->issuerUniqueID);
	r_x509_extensions_fini (&tbsc->extensions);
}

static RX509CRLEntry *r_x509_crlentry_parse(RASN1Object *object) {
	R_RETURN_VAL_IF_FAIL (object, NULL);
	if (object->list.length != 2) {
		return NULL;
	}
	RX509CRLEntry *entry = R_NEW0 (RX509CRLEntry);
	struct r_asn1_object_t *obj0 = object->list.objects[0];
	if (!obj0) {
		free (entry);
		return NULL;
	}
	entry->userCertificate = r_asn1_binary_new (obj0->sector, obj0->length);
	struct r_asn1_object_t *obj1 = object->list.objects[1];
	if (!obj1) {
		r_asn1_binary_free (entry->userCertificate);
		free (entry);
		return NULL;
	}
	entry->revocationDate = r_asn1_stringify_utctime (obj1->sector, obj1->length);
	return entry;
}

R_IPI void r_x509_name_dump(RX509Name *name, const char *pad, RStrBuf *sb) {
	R_RETURN_IF_FAIL (name && sb);
	if (!pad) {
		pad = "";
	}
	ut32 i;
	for (i = 0; i < name->length; i++) {
		if (!name->oids[i] || !name->names[i]) {
			continue;
		}
		r_strbuf_appendf (sb, "%s%s: %s\n", pad, name->oids[i]->string, name->names[i]->string);
	}
}

R_API RX509Certificate *r_x509_certificate_parse(RASN1Object *object) {
	R_RETURN_VAL_IF_FAIL (object, NULL);
	RX509Certificate *cert = R_NEW0 (RX509Certificate);
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
	cert->signature = r_asn1_binary_new (object->list.objects[2]->sector, object->list.objects[2]->length);
	r_x509_tbscertificate_parse (&cert->tbsCertificate, object->list.objects[0]);

	if (!r_x509_algorithmidentifier_parse (&cert->algorithmIdentifier, object->list.objects[1])) {
		free (cert->signature);
		R_FREE (cert);
	}
fail:
	r_asn1_object_free (object);
	return cert;
}

R_API void r_x509_certificate_free(RX509Certificate * R_NULLABLE certificate) {
	if (certificate) {
		r_asn1_binary_free (certificate->signature);
		r_x509_algorithmidentifier_fini (&certificate->algorithmIdentifier);
		r_x509_tbscertificate_fini (&certificate->tbsCertificate);
		free (certificate);
	}
}

R_API RX509CertificateRevocationList *r_x509_crl_parse(RASN1Object *object) {
	R_RETURN_VAL_IF_FAIL (object, NULL);
	if (object->list.length < 4) {
		return NULL;
	}
	RX509CertificateRevocationList *crl = R_NEW0 (RX509CertificateRevocationList);
	RASN1Object **elems = object->list.objects;
	if (!elems) {
		free (crl);
		return NULL;
	}
	if (elems[0]) {
		r_x509_algorithmidentifier_parse (&crl->signature, elems[0]);
	}
	if (elems[1]) {
		r_x509_name_parse (&crl->issuer, elems[1]);
	}
	if (elems[2]) {
		crl->lastUpdate = r_asn1_stringify_utctime (elems[2]->sector, elems[2]->length);
	}
	if (elems[3]) {
		crl->nextUpdate = r_asn1_stringify_utctime (elems[3]->sector, elems[3]->length);
	}
	if (object->list.length > 4 && object->list.objects[4]) {
		crl->revokedCertificates = calloc (object->list.objects[4]->list.length, sizeof (RX509CRLEntry *));
		if (!crl->revokedCertificates) {
			r_asn1_string_free (crl->nextUpdate);
			free (crl);
			return NULL;
		}
		crl->length = object->list.objects[4]->list.length;
		ut32 i;
		for (i = 0; i < object->list.objects[4]->list.length; i++) {
			crl->revokedCertificates[i] = r_x509_crlentry_parse (object->list.objects[4]->list.objects[i]);
		}
	}
	return crl;
}

R_IPI void r_x509_crl_free(RX509CertificateRevocationList * R_NULLABLE crl) {
	if (crl) {
		r_x509_algorithmidentifier_fini (&crl->signature);
		r_x509_name_fini (&crl->issuer);
		r_asn1_string_free (crl->nextUpdate);
		r_asn1_string_free (crl->lastUpdate);
		if (crl->revokedCertificates) {
			ut32 i;
			for (i = 0; i < crl->length; i++) {
				crlentry_free (crl->revokedCertificates[i]);
				crl->revokedCertificates[i] = NULL;
			}
			R_FREE (crl->revokedCertificates);
		}
		free (crl);
	}
}

static void pubkey_dump(RX509SubjectPublicKeyInfo *spki, const char *pad, RStrBuf *sb) {
	R_RETURN_IF_FAIL (spki && sb);
	if (!pad) {
		pad = "";
	}
	const char *a = spki->algorithm.algorithm? spki->algorithm.algorithm->string: "Missing";
	RASN1String *pubkey = NULL;
	if (spki->subjectPublicKey) {
		pubkey = r_asn1_stringify_integer (spki->subjectPublicKey->binary, spki->subjectPublicKey->length);
	}
	r_strbuf_appendf (sb, "%sAlgorithm: %s\n%sPublic key: %u bytes\n", pad, a, pad,
			pubkey? spki->subjectPublicKey->length: 0);
	r_asn1_string_free (pubkey);
}

static void extensions_dump(RX509Extensions *exts, const char *pad, RStrBuf *sb) {
	R_RETURN_IF_FAIL (exts && sb);
	if (!pad) {
		pad = "";
	}
	ut32 i;
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
		//r_asn1_string_free (s);
	}
}

static void tbscertificate_dump(RX509TBSCertificate *tbsc, const char *pad, RStrBuf *sb) {
	R_RETURN_IF_FAIL (tbsc && sb);
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
	validity_dump (&tbsc->validity, pad2, sb);

	r_strbuf_appendf (sb, "%sSubject:\n", pad);
	r_x509_name_dump (&tbsc->subject, pad2, sb);

	r_strbuf_appendf (sb, "%sSubject Public Key Info:\n", pad);
	pubkey_dump (&tbsc->subjectPublicKeyInfo, pad2, sb);

	if (tbsc->issuerUniqueID) {
		RASN1String *iid = r_asn1_stringify_integer (tbsc->issuerUniqueID->binary, tbsc->issuerUniqueID->length);
		if (iid) {
			r_strbuf_appendf (sb, "%sIssuer Unique ID:\n%s  %s", pad, pad, iid->string);
			r_asn1_string_free (iid);
		}
	}
	if (tbsc->subjectUniqueID) {
		RASN1String *sid = r_asn1_stringify_integer (tbsc->subjectUniqueID->binary, tbsc->subjectUniqueID->length);
		if (sid) {
			r_strbuf_appendf (sb, "%sSubject Unique ID:\n%s  %s", pad, pad, sid->string);
			r_asn1_string_free (sid);
		}
	}

	r_strbuf_appendf (sb, "%sExtensions:\n", pad);
	extensions_dump (&tbsc->extensions, pad2, sb);
	free (pad2);
}

R_API void r_x509_certificate_dump(RX509Certificate *cert, const char *pad, RStrBuf *sb) {
	R_RETURN_IF_FAIL (cert && sb);
	if (!pad) {
		pad = "";
	}
	char *pad2 = r_str_newf ("%s  ", pad);
	if (!pad2) {
		return;
	}
	r_strbuf_appendf (sb, "%sTBSCertificate:\n", pad);
	tbscertificate_dump (&cert->tbsCertificate, pad2, sb);

	RASN1String *algo = cert->algorithmIdentifier.algorithm;
	//	signature = r_asn1_stringify_bytes (certificate->signature->binary, certificate->signature->length);
	//	eprintf ("%sAlgorithm:\n%s%s\n%sSignature: %u bytes\n%s\n",
	//				pad, pad2, algo ? algo->string : "",
	//				pad, certificate->signature->length, signature ? signature->string : "");
	r_strbuf_appendf (sb, "%sAlgorithm:\n%s%s\n%sSignature: %u bytes\n",
		pad, pad2, algo ? algo->string : "", pad, cert->signature->length);
	free (pad2);
	// r_asn1_string_free (signature);
}

static void r_x509_crlentry_dump(RX509CRLEntry *crle, const char *pad, RStrBuf *sb) {
	R_RETURN_IF_FAIL (crle && sb);
	if (!pad) {
		pad = "";
	}
	RASN1String *id = NULL, *utc = crle->revocationDate;
	if (crle->userCertificate) {
		id = r_asn1_stringify_integer (crle->userCertificate->binary, crle->userCertificate->length);
	}
	r_strbuf_appendf (sb, "%sUser Certificate:\n%s  %s\n"
			      "%sRevocation Date:\n%s  %s\n",
		pad, pad, id ? id->string : "Missing",
		pad, pad, utc ? utc->string : "Missing");
	r_asn1_string_free (id);
}

R_API char *r_x509_crl_tostring(RX509CertificateRevocationList *crl, const char *pad) {
	R_RETURN_VAL_IF_FAIL (crl, NULL);
	if (!pad) {
		pad = "";
	}
	char *pad3 = r_str_newf ("%s    ", pad);
	if (!pad3) {
		return NULL;
	}
	char *pad2 = pad3 + 2;
	RASN1String *algo = crl->signature.algorithm;
	RASN1String *last = crl->lastUpdate;
	RASN1String *next = crl->nextUpdate;
	RStrBuf *sb = r_strbuf_new ("");
	r_strbuf_appendf (sb, "%sCRL:\n%sSignature:\n%s%s\n%sIssuer\n", pad, pad2, pad3,
		algo ? algo->string : "", pad2);
	r_x509_name_dump (&crl->issuer, pad3, sb);

	r_strbuf_appendf (sb, "%sLast Update: %s\n%sNext Update: %s\n%sRevoked Certificates:\n",
		pad2, last ? last->string : "Missing",
		pad2, next ? next->string : "Missing", pad2);

	ut32 i;
	for (i = 0; i < crl->length; i++) {
		r_x509_crlentry_dump (crl->revokedCertificates[i], pad3, sb);
	}

	free (pad3);
	return r_strbuf_drain (sb);
}

static void r_x509_validity_json(PJ *pj, RX509Validity *validity) {
	R_RETURN_IF_FAIL (pj && validity);
	if (validity) {
		if (validity->notBefore) {
			pj_ks (pj, "NotBefore", validity->notBefore->string);
		}
		if (validity->notAfter) {
			pj_ks (pj, "NotAfter", validity->notAfter->string);
		}
	}
}

R_IPI void r_x509_name_json(PJ *pj, RX509Name *name) {
	R_RETURN_IF_FAIL (pj && name);
	ut32 i;
	for (i = 0; i < name->length; i++) {
		if (!name->oids[i] || !name->names[i]) {
			continue;
		}
		pj_ks (pj, name->oids[i]->string, name->names[i]->string);
	}
}

static void r_x509_subjectpublickeyinfo_json(PJ *pj, RX509SubjectPublicKeyInfo *spki) {
	R_RETURN_IF_FAIL (pj && spki);
	if (spki) {
		if (spki->algorithm.algorithm) {
			pj_ks (pj, "Algorithm", spki->algorithm.algorithm->string);
		}
		if (spki->subjectPublicKey) {
			RASN1String *m = r_asn1_stringify_integer (spki->subjectPublicKey->binary,
					spki->subjectPublicKey->length);
			if (m) {
				pj_ks (pj, "Public key", m->string);
			}
			r_asn1_string_free (m);
		}
	}
}

static void r_x509_extensions_json(PJ *pj, RX509Extensions *exts) {
	R_RETURN_IF_FAIL (pj && exts);
	pj_a (pj);
	ut32 i;
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
			RASN1String *m = r_asn1_stringify_integer (e->extnValue->binary, e->extnValue->length);
			if (m) {
				pj_ks (pj, "Value", m->string);
			}
			r_asn1_string_free (m);
		}
		pj_end (pj);
	}
	pj_end (pj);
}

static void r_x509_crlentry_json(PJ *pj, RX509CRLEntry *crle) {
	R_RETURN_IF_FAIL (pj && crle);
	if (crle) {
		if (crle->userCertificate) {
			RASN1String *m = r_asn1_stringify_integer (crle->userCertificate->binary,
					crle->userCertificate->length);
			if (m) {
				pj_ks (pj, "UserCertificate", m->string);
			}
			r_asn1_string_free (m);
		}
		if (crle->revocationDate) {
			pj_ks (pj, "RevocationDate", crle->revocationDate->string);
		}
	}
}

R_API void r_x509_crl_json(PJ *pj, RX509CertificateRevocationList *crl) {
	R_RETURN_IF_FAIL (pj && crl);
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
		ut32 i;
		for (i = 0; i < crl->length; i++) {
			r_x509_crlentry_json (pj, crl->revokedCertificates[i]);
		}
		pj_end (pj);
	}
}

static void r_x509_tbscertificate_json(PJ *pj, RX509TBSCertificate *tbsc) {
	R_RETURN_IF_FAIL (pj && tbsc);
	pj_o (pj);
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
		RASN1String *m = NULL;
		if (tbsc->issuerUniqueID) {
			m = r_asn1_stringify_integer (tbsc->issuerUniqueID->binary, tbsc->issuerUniqueID->length);
			if (m) {
				pj_ks (pj, "IssuerUniqueID", m->string);
			}
			r_asn1_string_free (m);
		}
		if (tbsc->subjectUniqueID) {
			m = r_asn1_stringify_integer (tbsc->subjectUniqueID->binary, tbsc->subjectUniqueID->length);
			if (m) {
				pj_ks (pj, "SubjectUniqueID", m->string);
			}
			r_asn1_string_free (m);
		}
		pj_k (pj, "Extensions");
		r_x509_extensions_json (pj, &tbsc->extensions);
	}
	pj_end (pj);
}

R_API void r_x509_certificate_json(PJ *pj, RX509Certificate *certificate) {
	R_RETURN_IF_FAIL (pj && certificate);
	pj_o (pj);
	pj_k (pj, "TBSCertificate");
	r_x509_tbscertificate_json (pj, &certificate->tbsCertificate);
	if (certificate->algorithmIdentifier.algorithm) {
		pj_ks (pj, "Algorithm", certificate->algorithmIdentifier.algorithm->string);
	}
	if (certificate->signature) {
		RASN1String *m = r_asn1_stringify_integer (certificate->signature->binary,
				certificate->signature->length);
		if (m) {
			pj_ks (pj, "Signature", m->string);
		}
		r_asn1_string_free (m);
	}
	pj_end (pj);
}
