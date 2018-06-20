/* radare2 - LGPL - Copyright 2017-2018 - wargio */

#include <r_util.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static RASN1Object *asn1_parse_header (const ut8 *buffer, ut32 length) {
	RASN1Object *object;
	ut8 head, length8, byte;
	ut64 length64;
	if (!buffer || length < 2) {
		return NULL;
	}

	object = R_NEW0 (RASN1Object);
	if (!object) {
		return NULL;
	}
	head = buffer[0];
	object->klass = head & ASN1_CLASS;
	object->form = head & ASN1_FORM;
	object->tag = head & ASN1_TAG;
	length8 = buffer[1];
	if (length8 & ASN1_LENLONG) {
		length64 = 0;
		length8 &= ASN1_LENSHORT;
		if (length8 && length8 < length - 2) {
			ut8 i8;
			// can overflow.
			for (i8 = 0; i8 < length8; ++i8) {
				byte = buffer[2 + i8];
				length64 <<= 8;
				length64 |= byte;
				if (length64 > length) {
					goto out_error;
				}
			}
			object->sector = buffer + 2 + length8;
		} else {
			//indefinite
			const ut8 *from = buffer + 2;
			const ut8 *end = from + (length - 2);
			do {
				byte = *from;
				length64 <<= 8;
				length64 |= byte;
				from++;
			} while (from < end && length64 <= length && byte & 0x80);
			if (length64 > length) {
				goto out_error;
			}
			object->sector = from;
		}
		object->length = (ut32) length64;
	} else {
		object->length = (ut32) length8;
		object->sector = buffer + 2;
	}
	if (object->tag == TAG_BITSTRING && object->sector[0] == 0) {
		if (object->length > 0){
			object->sector++; //real sector starts +1
			object->length--;
		}
	}
	if (object->length > length) {
		// Malformed object - overflow from data ptr
		goto out_error;
	}
	return object;
out_error:
	free (object);
	return NULL;
}

static ut32 r_asn1_count_objects (const ut8 *buffer, ut32 length) {
	ut32 counter;
	RASN1Object *object;
	const ut8 *next, *end;
	if (!buffer || !length) {
		return 0;
	}
	counter = 0;
	object = NULL;
	next = buffer;
	end = buffer + length;
	while (next >= buffer && next < end) {
		object = asn1_parse_header (next, end - next);
		if (!object || next == object->sector) {
			R_FREE (object);
			break;
		}
		next = object->sector + object->length;
		counter++;
		R_FREE (object);
	}
	R_FREE (object);
	return counter;
}

R_API RASN1Object *r_asn1_create_object (const ut8 *buffer, ut32 length) {
	RASN1Object *object = asn1_parse_header (buffer, length);
	if (object && (object->form == FORM_CONSTRUCTED || object->tag == TAG_BITSTRING || object->tag == TAG_OCTETSTRING)) {
		ut32 i, count;
		RASN1Object *inner = NULL;
		const ut8 *next = object->sector;
		const ut8 *end = next + object->length;
		if (end > buffer + length) {
			free (object);
			return NULL;
		}
		count = r_asn1_count_objects (object->sector, object->length);
		if (count > 0) {
			object->list.length = count;
			object->list.objects = R_NEWS0 (RASN1Object*, count);
			if (!object->list.objects) {
				r_asn1_free_object (object);
				return NULL;
			}
			for (i = 0; next >= buffer && next < end && i < count; ++i) {
				inner = r_asn1_create_object (next, end - next);
				if (!inner || next == inner->sector) {
					r_asn1_free_object (inner);
					break;
				}
				next = inner->sector + inner->length;
				R_PTR_MOVE (object->list.objects[i], inner);
			}
		}
	}
	return object;
}

R_API RASN1Binary *r_asn1_create_binary (const ut8 *buffer, ut32 length) {
	RASN1Binary* bin = NULL;
	ut8* buf = NULL;
	if (!buffer || !length) {
		return NULL;
	}
	buf = (ut8*) calloc (sizeof (*buf), length);
	if (!buf) {
		return NULL;
	}
	bin = R_NEW0 (RASN1Binary);
	if (!bin) {
		free (buf);
		return NULL;
	}
	memcpy (buf, buffer, length);
	bin->binary = buf;
	bin->length = length;
	return bin;
}

R_API void r_asn1_free_object (RASN1Object *object) {
	ut32 i;
	if (!object) {
		return;
	}
	//this shall not be freed. it's a pointer into the buffer.
	object->sector = 0;
	if (object->list.objects) {
		for (i = 0; i < object->list.length; ++i) {
			r_asn1_free_object (object->list.objects[i]);
		}
		R_FREE (object->list.objects);
	}
	object->list.objects = NULL;
	object->list.length = 0;
	R_FREE (object);
}

R_API void r_asn1_free_binary (RASN1Binary* bin) {
	if (bin) {
		free ((char*) bin->binary);
		free (bin);
	}
}
