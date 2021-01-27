/* radare2 - LGPL - Copyright 2017-2018 - wargio */

#include <stdlib.h>
#include <string.h>
#include <r_util.h>
#include "./x509.h"

extern void r_x509_name_json (PJ *pj, RX509Name *name);
extern void r_x509_free_crl (RX509CertificateRevocationList *crl);
extern void r_x509_crlentry_dump (RX509CRLEntry *crle, const char *pad, RStrBuf *sb);
static bool r_pkcs7_parse_attributes(RPKCS7Attributes *attribute, RASN1Object *object);

static bool r_pkcs7_parse_contentinfo(RPKCS7ContentInfo *ci, RASN1Object *object) {
	if (!ci || !object || object->list.length < 1 || !object->list.objects[0]) {
		return false;
	}
	ci->contentType = r_asn1_stringify_oid (object->list.objects[0]->sector, object->list.objects[0]->length);
	if (object->list.length > 1) {
		RASN1Object *obj1 = object->list.objects[1];
		if (obj1) {
			ci->content = r_asn1_create_binary (obj1->sector, obj1->length);
		}
	}
	return true;
}

static bool r_pkcs7_parse_certificaterevocationlists(RPKCS7CertificateRevocationLists *crls, RASN1Object *object) {
	ut32 i;
	if (!crls || !object) {
		return false;
	}
	if (object->list.length > 0) {
		crls->elements = (RX509CertificateRevocationList **)calloc (object->list.length, sizeof (RX509CertificateRevocationList *));
		if (!crls->elements) {
			return false;
		}
		crls->length = object->list.length;
		for (i = 0; i < crls->length; i++) {
			crls->elements[i] = r_x509_parse_crl (object->list.objects[i]);
		}
	}
	return true;
}

static void r_pkcs7_free_certificaterevocationlists(RPKCS7CertificateRevocationLists *crls) {
	ut32 i;
	if (crls) {
		for (i = 0; i < crls->length; i++) {
			r_x509_free_crl (crls->elements[i]);
			crls->elements[i] = NULL;
		}
		R_FREE (crls->elements);
		// Used internally pkcs #7, so it shouldn't free crls.
	}
}

static bool r_pkcs7_parse_extendedcertificatesandcertificates(RPKCS7ExtendedCertificatesAndCertificates *ecac, RASN1Object *object) {
	ut32 i;
	if (!ecac || !object) {
		return false;
	}
	if (object->list.length > 0) {
		ecac->elements = (RX509Certificate **)calloc (object->list.length, sizeof (RX509Certificate *));
		if (!ecac->elements) {
			return false;
		}
		ecac->length = object->list.length;
		for (i = 0; i < ecac->length; i++) {
			ecac->elements[i] = r_x509_parse_certificate (object->list.objects[i]);
			object->list.objects[i] = NULL;
		}
	}
	return true;
}

static void r_pkcs7_free_extendedcertificatesandcertificates(RPKCS7ExtendedCertificatesAndCertificates *ecac) {
	ut32 i;
	if (ecac) {
		for (i = 0; i < ecac->length; i++) {
			r_x509_free_certificate (ecac->elements[i]);
			ecac->elements[i] = NULL;
		}
		R_FREE (ecac->elements);
		// Used internally pkcs #7, so it shouldn't free ecac.
	}
}

static bool r_pkcs7_parse_digestalgorithmidentifier(RPKCS7DigestAlgorithmIdentifiers *dai, RASN1Object *object) {
	ut32 i;
	if (!dai || !object) {
		return false;
	}
	if (object->list.length > 0) {
		dai->elements = (RX509AlgorithmIdentifier **)calloc (object->list.length, sizeof (RX509AlgorithmIdentifier *));
		if (!dai->elements) {
			return false;
		}
		dai->length = object->list.length;
		for (i = 0; i < dai->length; i++) {
			// r_x509_parse_algorithmidentifier returns bool,
			// so i have to allocate before calling the function
			dai->elements[i] = (RX509AlgorithmIdentifier *)malloc (sizeof (RX509AlgorithmIdentifier));
			//should i handle invalid memory? the function checks the pointer
			//or it should return if dai->elements[i] == NULL ?
			if (dai->elements[i]) {
				//Memset is needed to initialize to 0 the structure and avoid garbage.
				memset (dai->elements[i], 0, sizeof (RX509AlgorithmIdentifier));
				r_x509_parse_algorithmidentifier (dai->elements[i], object->list.objects[i]);
			}
		}
	}
	return true;
}

static void r_pkcs7_free_digestalgorithmidentifier(RPKCS7DigestAlgorithmIdentifiers *dai) {
	ut32 i;
	if (dai) {
		for (i = 0; i < dai->length; i++) {
			if (dai->elements[i]) {
				r_x509_free_algorithmidentifier (dai->elements[i]);
				// r_x509_free_algorithmidentifier doesn't free the pointer
				// because on x509 the original use was internal.
				R_FREE (dai->elements[i]);
			}
		}
		R_FREE (dai->elements);
		// Used internally pkcs #7, so it shouldn't free dai.
	}
}

static void r_pkcs7_free_contentinfo(RPKCS7ContentInfo *ci) {
	if (ci) {
		r_asn1_free_binary (ci->content);
		r_asn1_free_string (ci->contentType);
		// Used internally pkcs #7, so it shouldn't free ci.
	}
}

static bool r_pkcs7_parse_issuerandserialnumber(RPKCS7IssuerAndSerialNumber *iasu, RASN1Object *object) {
	if (!iasu || !object || object->list.length != 2) {
		return false;
	}
	r_x509_parse_name (&iasu->issuer, object->list.objects[0]);
	RASN1Object *obj1 = object->list.objects[1];
	if (obj1) {
		iasu->serialNumber = r_asn1_create_binary (obj1->sector, obj1->length);
	}
	return true;
}

static void r_pkcs7_free_issuerandserialnumber(RPKCS7IssuerAndSerialNumber *iasu) {
	if (iasu) {
		r_x509_free_name (&iasu->issuer);
		r_asn1_free_binary (iasu->serialNumber);
		// Used internally pkcs #7, so it shouldn't free iasu.
	}
}

/*
	RX509AlgorithmIdentifier digestEncryptionAlgorithm;
	RASN1Object *encryptedDigest;
	RASN1Object *unauthenticatedAttributes; //Optional type ??
} RPKCS7SignerInfo;
 */

static bool r_pkcs7_parse_signerinfo(RPKCS7SignerInfo *si, RASN1Object *object) {
	RASN1Object **elems;
	ut32 shift = 3;
	if (!si || !object || object->list.length < 5) {
		return false;
	}
	elems = object->list.objects;
	//Following RFC
	si->version = (ut32)elems[0]->sector[0];
	r_pkcs7_parse_issuerandserialnumber (&si->issuerAndSerialNumber, elems[1]);
	r_x509_parse_algorithmidentifier (&si->digestAlgorithm, elems[2]);
	if (shift < object->list.length && elems[shift]->klass == CLASS_CONTEXT && elems[shift]->tag == 0) {
		r_pkcs7_parse_attributes (&si->authenticatedAttributes, elems[shift]);
		shift++;
	}
	if (shift < object->list.length) {
		r_x509_parse_algorithmidentifier (&si->digestEncryptionAlgorithm, elems[shift]);
		shift++;
	}
	if (shift < object->list.length) {
		RASN1Object *obj1 = object->list.objects[shift];
		if (obj1) {
			si->encryptedDigest = r_asn1_create_binary (obj1->sector, obj1->length);
			shift++;
		}
	}
	if (shift < object->list.length) {
		RASN1Object *elem = elems[shift];
		if (elem && elem->klass == CLASS_CONTEXT && elem->tag == 1) {
			r_pkcs7_parse_attributes (&si->unauthenticatedAttributes, elems[shift]);
		}
	}
	return true;
}

static void r_pkcs7_free_attribute(RPKCS7Attribute *attribute) {
	if (attribute) {
		r_asn1_free_binary (attribute->data);
		r_asn1_free_string (attribute->oid);
		free (attribute);
	}
}

static void r_pkcs7_free_attributes(RPKCS7Attributes *attributes) {
	ut32 i;
	if (attributes) {
		for (i = 0; i < attributes->length; i++) {
			r_pkcs7_free_attribute (attributes->elements[i]);
		}
		R_FREE (attributes->elements);
		// Used internally pkcs #7, so it shouldn't free attributes.
	}
}

static void r_pkcs7_free_signerinfo(RPKCS7SignerInfo *si) {
	if (si) {
		r_pkcs7_free_issuerandserialnumber (&si->issuerAndSerialNumber);
		r_x509_free_algorithmidentifier (&si->digestAlgorithm);
		r_pkcs7_free_attributes (&si->authenticatedAttributes);
		r_x509_free_algorithmidentifier (&si->digestEncryptionAlgorithm);
		r_asn1_free_binary (si->encryptedDigest);
		r_pkcs7_free_attributes (&si->unauthenticatedAttributes);
		free (si);
	}
}

static bool r_pkcs7_parse_signerinfos(RPKCS7SignerInfos *ss, RASN1Object *object) {
	ut32 i;
	if (!ss || !object) {
		return false;
	}
	if (object->list.length > 0) {
		ss->elements = (RPKCS7SignerInfo **)calloc (object->list.length, sizeof (RPKCS7SignerInfo *));
		if (!ss->elements) {
			return false;
		}
		ss->length = object->list.length;
		for (i = 0; i < ss->length; i++) {
			// r_pkcs7_parse_signerinfo returns bool,
			// so i have to allocate before calling the function
			ss->elements[i] = R_NEW0 (RPKCS7SignerInfo);
			//should i handle invalid memory? the function checks the pointer
			//or it should return if si->elements[i] == NULL ?
			r_pkcs7_parse_signerinfo (ss->elements[i], object->list.objects[i]);
		}
	}
	return true;
}

static void r_pkcs7_free_signerinfos(RPKCS7SignerInfos *ss) {
	ut32 i;
	if (ss) {
		for (i = 0; i < ss->length; i++) {
			r_pkcs7_free_signerinfo (ss->elements[i]);
			ss->elements[i] = NULL;
		}
		R_FREE (ss->elements);
		// Used internally pkcs #7, so it shouldn't free ss.
	}
}

static bool r_pkcs7_parse_signeddata(RPKCS7SignedData *sd, RASN1Object *object) {
	ut32 shift = 3;
	if (!sd || !object || object->list.length < 4) {
		return false;
	}
	memset (sd, 0, sizeof (RPKCS7SignedData));
	RASN1Object **elems = object->list.objects;
	//Following RFC
	sd->version = (ut32)elems[0]->sector[0];
	r_pkcs7_parse_digestalgorithmidentifier (&sd->digestAlgorithms, elems[1]);
	r_pkcs7_parse_contentinfo (&sd->contentInfo, elems[2]);
	//Optional
	if (object->list.length > 3 && shift < object->list.length && elems[shift] &&
		elems[shift]->klass == CLASS_CONTEXT && elems[shift]->tag == 0) {
		r_pkcs7_parse_extendedcertificatesandcertificates (&sd->certificates, elems[shift]);
		shift++;
	}
	//Optional
	if (object->list.length > 3 && shift < object->list.length && elems[shift] &&
		elems[shift]->klass == CLASS_CONTEXT && elems[shift]->tag == 1) {
		r_pkcs7_parse_certificaterevocationlists (&sd->crls, elems[shift]);
		shift++;
	}
	if (shift < object->list.length) {
		r_pkcs7_parse_signerinfos (&sd->signerinfos, elems[shift]);
	}
	return true;
}

static void r_pkcs7_free_signeddata(RPKCS7SignedData *sd) {
	if (sd) {
		r_pkcs7_free_digestalgorithmidentifier (&sd->digestAlgorithms);
		r_pkcs7_free_contentinfo (&sd->contentInfo);
		r_pkcs7_free_extendedcertificatesandcertificates (&sd->certificates);
		r_pkcs7_free_certificaterevocationlists (&sd->crls);
		r_pkcs7_free_signerinfos (&sd->signerinfos);
		// Used internally pkcs #7, so it shouldn't free sd.
	}
}

R_API RCMS *r_pkcs7_parse_cms(const ut8 *buffer, ut32 length) {
	RASN1Object *object;
	RCMS *container;
	if (!buffer || !length) {
		return NULL;
	}
	container = R_NEW0 (RCMS);
	if (!container) {
		return NULL;
	}
	object = r_asn1_create_object (buffer, length, buffer);
	if (!object || object->list.length < 2 || !object->list.objects ||
		!object->list.objects[0] || !object->list.objects[1] ||
		object->list.objects[1]->list.length < 1) {
		r_asn1_free_object (object);
		free (container);
		return NULL;
	}
	if (object->list.objects[0]) {
		container->contentType = r_asn1_stringify_oid (object->list.objects[0]->sector, object->list.objects[0]->length);
		if (!container->contentType) {
			r_asn1_free_object (object);
			free (container);
			return NULL;
		}
	}
	if (object->list.objects[1]) {
		r_pkcs7_parse_signeddata (&container->signedData, object->list.objects[1]->list.objects[0]);
	}
	r_asn1_free_object (object);
	return container;
}

R_API void r_pkcs7_free_cms(RCMS *container) {
	if (container) {
		r_asn1_free_string (container->contentType);
		r_pkcs7_free_signeddata (&container->signedData);
		free (container);
	}
}

static RPKCS7Attribute *r_pkcs7_parse_attribute(RASN1Object *object) {
	RPKCS7Attribute *attribute;
	if (!object || object->list.length < 1) {
		return NULL;
	}
	attribute = R_NEW0 (RPKCS7Attribute);
	if (!attribute) {
		return NULL;
	}
	if (object->list.objects[0]) {
		attribute->oid = r_asn1_stringify_oid (object->list.objects[0]->sector, object->list.objects[0]->length);
	}
	if (object->list.length == 2) {
		RASN1Object *obj1 = object->list.objects[1];
		if (obj1) {
			attribute->data = r_asn1_create_binary (obj1->sector, obj1->length);
		}
	}
	return attribute;
}

static bool r_pkcs7_parse_attributes(RPKCS7Attributes *attributes, RASN1Object *object) {
	ut32 i;
	if (!attributes || !object || !object->list.length) {
		return false;
	}

	attributes->length = object->list.length;
	if (attributes->length > 0) {
		attributes->elements = R_NEWS0 (RPKCS7Attribute *, attributes->length);
		if (!attributes->elements) {
			attributes->length = 0;
			return false;
		}
		for (i = 0; i < object->list.length; i++) {
			attributes->elements[i] = r_pkcs7_parse_attribute (object->list.objects[i]);
		}
	}
	return true;
}

#if 0
// XXX: unused
static void r_pkcs7_signerinfos_dump(RX509CertificateRevocationList *crl, const char* pad, RStrBuf *sb) {
	RASN1String *algo = NULL, *last = NULL, *next = NULL;
	ut32 i;
	char *pad2, *pad3;
	if (!crl) {
		return;
	}
	if (!pad) {
		pad = "";
	}
	pad3 = r_str_newf ("%s    ", pad);
	if (!pad3) return;

	pad2 = pad3 + 2;
	algo = crl->signature.algorithm;
	last = crl->lastUpdate;
	next = crl->nextUpdate;
	r_strbuf_appendf (sb, "%sCRL:\n%sSignature:\n%s%s\n%sIssuer\n", pad, pad2, pad3, algo ? algo->string : "", pad2);
	r_x509_name_dump (&crl->issuer, pad3, sb);
	r_strbuf_appendf (sb, "%sLast Update: %s\n%sNext Update: %s\n%sRevoked Certificates:\n",
				pad2, last ? last->string : "Missing",
				pad2, next ? next->string : "Missing", pad2);
	for (i = 0; i < crl->length; i++) {
		r_x509_crlentry_dump (crl->revokedCertificates[i], pad3, sb);
	}
	free (pad3);
}
#endif

static void r_x509_signedinfo_dump(RPKCS7SignerInfo *si, const char *pad, RStrBuf *sb) {
	RASN1String *s = NULL;
	RASN1Binary *o = NULL;
	ut32 i;
	char *pad2, *pad3;
	if (!si) {
		return;
	}
	if (!pad) {
		pad = "";
	}
	pad3 = r_str_newf ("%s    ", pad);
	if (!pad3) {
		return;
	}
	pad2 = pad3 + 2;

	r_strbuf_appendf (sb, "%sSignerInfo:\n%sVersion: v%u\n%sIssuer\n", pad, pad2, si->version + 1, pad2);
	r_x509_name_dump (&si->issuerAndSerialNumber.issuer, pad3, sb);
	if ((o = si->issuerAndSerialNumber.serialNumber)) {
		s = r_asn1_stringify_integer (o->binary, o->length);
	}
	r_strbuf_appendf (sb, "%sSerial Number:\n%s%s\n", pad2, pad3, s ? s->string : "Missing");
	r_asn1_free_string (s);

	s = si->digestAlgorithm.algorithm;
	r_strbuf_appendf (sb, "%sDigest Algorithm:\n%s%s\n%sAuthenticated Attributes:\n",
		pad2, pad3, s ? s->string : "Missing", pad2);

	for (i = 0; i < si->authenticatedAttributes.length; i++) {
		RPKCS7Attribute *attr = si->authenticatedAttributes.elements[i];
		if (!attr) {
			continue;
		}
		r_strbuf_appendf (sb, "%s%s: %u bytes\n", pad3, attr->oid ? attr->oid->string : "Missing",
			attr->data ? attr->data->length : 0);
	}
	s = si->digestEncryptionAlgorithm.algorithm;
	r_strbuf_appendf (sb, "%sDigest Encryption Algorithm\n%s%s\n", pad2, pad3, s ? s->string : "Missing");

	//	if ((o = si->encryptedDigest)) s = r_asn1_stringify_bytes (o->binary, o->length);
	//	else s = NULL;
	//	eprintf ("%sEncrypted Digest: %u bytes\n%s\n", pad2, o ? o->length : 0, s ? s->string : "Missing");
	//	r_asn1_free_string (s);
	r_strbuf_appendf (sb, "%sEncrypted Digest: %u bytes\n", pad2, o ? o->length : 0);
	r_strbuf_appendf (sb, "%sUnauthenticated Attributes:\n", pad2);
	for (i = 0; i < si->unauthenticatedAttributes.length; i++) {
		RPKCS7Attribute *attr = si->unauthenticatedAttributes.elements[i];
		if (!attr) {
			continue;
		}
		o = attr->data;
		eprintf ("%s%s: %u bytes\n", pad3, attr->oid ? attr->oid->string : "Missing",
			o ? o->length : 0);
	}
	free (pad3);
}

R_API char *r_pkcs7_cms_to_string(RCMS *container) {
	ut32 i;
	if (!container) {
		return NULL;
	}
	RPKCS7SignedData *sd = &container->signedData;
	RStrBuf *sb = r_strbuf_new ("");
	r_strbuf_appendf (sb, "signedData\n  Version: v%u\n  Digest Algorithms:\n", sd->version);

	if (container->signedData.digestAlgorithms.elements) {
		for (i = 0; i < container->signedData.digestAlgorithms.length; i++) {
			if (container->signedData.digestAlgorithms.elements[i]) {
				RASN1String *s = container->signedData.digestAlgorithms.elements[i]->algorithm;
				r_strbuf_appendf (sb, "    %s\n", s ? s->string : "Missing");
			}
		}
	}

	r_strbuf_appendf (sb, "  Certificates: %u\n", container->signedData.certificates.length);

	for (i = 0; i < container->signedData.certificates.length; i++) {
		r_x509_certificate_dump (container->signedData.certificates.elements[i], "    ", sb);
	}

	for (i = 0; i < container->signedData.crls.length; i++) {
		char *res = r_x509_crl_to_string (container->signedData.crls.elements[i], "    ");
		if (res) {
			r_strbuf_append (sb, res);
			free (res);
		}
	}

	r_strbuf_appendf (sb, "  SignerInfos:\n");
	if (container->signedData.signerinfos.elements) {
		for (i = 0; i < container->signedData.signerinfos.length; i++) {
			r_x509_signedinfo_dump (container->signedData.signerinfos.elements[i], "    ", sb);
		}
	}
	return r_strbuf_drain (sb);
}

R_API void r_x509_signedinfo_json(PJ *pj, RPKCS7SignerInfo *si) {
	ut32 i;
	if (si) {
		pj_o (pj);
		pj_ki (pj, "Version", si->version + 1);
		pj_k (pj, "Issuer");
		pj_o (pj);
		r_x509_name_json (pj, &si->issuerAndSerialNumber.issuer);
		pj_end (pj);
		if (si->issuerAndSerialNumber.serialNumber) {
			RASN1Binary *o = si->issuerAndSerialNumber.serialNumber;
			RASN1String *s = r_asn1_stringify_integer (o->binary, o->length);
			if (s) {
				pj_ks (pj, "SerialNumber", s->string);
			}
			r_asn1_free_string (s);
		}

		if (si->digestAlgorithm.algorithm) {
			pj_ks (pj, "DigestAlgorithm", si->digestAlgorithm.algorithm->string);
		}
		pj_k (pj, "AuthenticatedAttributes");
		pj_a (pj);
		for (i = 0; i < si->authenticatedAttributes.length; i++) {
			RPKCS7Attribute *attr = si->authenticatedAttributes.elements[i];
			if (!attr) {
				continue;
			}
			pj_o (pj);
			if (attr->oid) {
				pj_ks (pj, "oid", attr->oid->string);
			}
			if (attr->data) {
				pj_ki (pj, "length", attr->data->length);
			}
			pj_end (pj);
		}
		pj_end (pj);
		if (si->digestEncryptionAlgorithm.algorithm) {
			pj_ks (pj, "DigestEncryptionAlgorithm", si->digestEncryptionAlgorithm.algorithm->string);
		}

		if (si->encryptedDigest) {
			RASN1Binary *o = si->encryptedDigest;
			RASN1String *s = r_asn1_stringify_integer (o->binary, o->length);
			if (s) {
				pj_ks (pj, "EncryptedDigest", s->string);
			}
			r_asn1_free_string (s);
		}

		pj_k (pj, "UnauthenticatedAttributes");
		pj_a (pj);
		for (i = 0; i < si->unauthenticatedAttributes.length; i++) {
			RPKCS7Attribute *attr = si->unauthenticatedAttributes.elements[i];
			if (!attr) {
				continue;
			}
			pj_o (pj);
			if (attr->oid) {
				pj_ks (pj, "oid", attr->oid->string);
			}
			if (attr->data) {
				pj_ki (pj, "length", attr->data->length);
			}
			pj_end (pj);
		}
		pj_end (pj);
		pj_end (pj);
	}
}

R_API PJ *r_pkcs7_cms_json (RCMS *container) {
	PJ *pj = NULL;
	if (container) {
		ut32 i;

		pj = pj_new ();

		pj_o (pj);
		pj_kn (pj, "Version", container->signedData.version);

		if (container->signedData.digestAlgorithms.elements) {
			pj_k (pj, "DigestAlgorithms");
			pj_a (pj);
			for (i = 0; i < container->signedData.digestAlgorithms.length; i++) {
				if (container->signedData.digestAlgorithms.elements[i]) {
					RASN1String *s = container->signedData.digestAlgorithms.elements[i]->algorithm;
					if (s) {
						pj_s (pj, s->string);
					}
				}
			}
			pj_end (pj);
		}

		pj_k (pj, "Certificates");
		pj_a (pj);
		for (i = 0; i < container->signedData.certificates.length; i++) {
			r_x509_certificate_json (pj, container->signedData.certificates.elements[i]);
		}
		pj_end (pj);

		pj_k (pj, "CRL");
		pj_a (pj);
		for (i = 0; i < container->signedData.crls.length; i++) {
			r_x509_crl_json (pj, container->signedData.crls.elements[i]);
		}
		pj_end (pj);

		pj_k (pj, "SignerInfos");
		pj_a (pj);
		if (container->signedData.signerinfos.elements) {
			for (i = 0; i < container->signedData.signerinfos.length; i++) {
				r_x509_signedinfo_json (pj, container->signedData.signerinfos.elements[i]);
			}
		}
		pj_end (pj);
		pj_end (pj);
	}
	return pj;
}

static bool r_pkcs7_parse_spcdata(SpcAttributeTypeAndOptionalValue *data, RASN1Object *object) {
	if (!data || !object || object->list.length < 1 ||
		!object->list.objects[0]) {
		return false;
	}
	data->type = r_asn1_stringify_oid (object->list.objects[0]->sector, object->list.objects[0]->length);
	if (!data->type) {
		return false;
	}
	RASN1Object *obj1 = object->list.objects[1];
	if (object->list.length > 1) {
		if (obj1) {
			data->data = r_asn1_create_binary (obj1->sector, obj1->length);
		}
	}
	return true;
}

static bool r_pkcs7_parse_spcmessagedigest(SpcDigestInfo *messageDigest, RASN1Object *object) {
	if (!messageDigest || !object || object->list.length < 2 ||
		!object->list.objects[0] || !object->list.objects[1]) {
		return false;
	}
	if (!r_x509_parse_algorithmidentifier (&messageDigest->digestAlgorithm, object->list.objects[0])) {
		return false;
	}
	RASN1Object *obj1 = object->list.objects[1];
	messageDigest->digest = r_asn1_create_binary (obj1->sector, obj1->length);
	return true;
}

R_API SpcIndirectDataContent *r_pkcs7_parse_spcinfo(RCMS *cms) {
	r_return_val_if_fail (cms, NULL);

	RASN1String *type = cms->signedData.contentInfo.contentType;
	if (type && strcmp (type->string, "spcIndirectDataContext")) {
		return NULL;
	}

	SpcIndirectDataContent *spcinfo = R_NEW0 (SpcIndirectDataContent);
	if (!spcinfo) {
		return NULL;
	}

	RASN1Binary *content = cms->signedData.contentInfo.content;
	if (!content) {
		free (spcinfo);
		return NULL;
	}
	RASN1Object *object = r_asn1_create_object (content->binary, content->length, content->binary);
	if (!object || object->list.length < 2 || !object->list.objects ||
		!object->list.objects[0] || !object->list.objects[1]) {
		R_FREE (spcinfo);
		goto beach;
	}
	if (object->list.objects[0]) {
		if (!r_pkcs7_parse_spcdata (&spcinfo->data, object->list.objects[0])) {
			R_FREE (spcinfo);
			goto beach;
		}
	}
	if (object->list.objects[1]) {
		if (!r_pkcs7_parse_spcmessagedigest (&spcinfo->messageDigest, object->list.objects[1])) {
			R_FREE (spcinfo);
			goto beach;
		}
	}
beach:
	r_asn1_free_object (object);
	return spcinfo;
}

static void r_pkcs7_free_spcdata(SpcAttributeTypeAndOptionalValue *data) {
	if (data) {
		r_asn1_free_string (data->type);
		r_asn1_free_binary (data->data);
	}
}

static void r_pkcs7_free_spcmessagedigest(SpcDigestInfo *messageDigest) {
	if (messageDigest) {
		r_asn1_free_binary (messageDigest->digest);
		r_x509_free_algorithmidentifier (&messageDigest->digestAlgorithm);
	}
}

R_API void r_pkcs7_free_spcinfo(SpcIndirectDataContent *spcinfo) {
	if (spcinfo) {
		r_pkcs7_free_spcdata (&spcinfo->data);
		r_pkcs7_free_spcmessagedigest (&spcinfo->messageDigest);
	}
}
