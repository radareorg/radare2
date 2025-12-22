#ifndef _INCLUDE_R_BIN_DSC_C_
#define _INCLUDE_R_BIN_DSC_C_

typedef struct {
	const char * format;
	const char * name;
} RDSCField;

typedef struct {
	const RDSCField * fields;
	RBuffer * buf;
	ut8 * data;
} RDSCHeader;

static RDSCHeader * dsc_header_new(ut8 * data, ut64 data_len, const RDSCField fields[]) {
	RDSCHeader * self = R_NEW0 (RDSCHeader);
	if (!self) {
		return NULL;
	}

	RBuffer * buf = r_buf_new_with_bytes (data, data_len);
	if (!buf) {
		free (self);
		return NULL;
	}

	self->fields = fields;
	self->buf = buf;
	self->data = data;

	return self;
}

static void dsc_header_free(RDSCHeader * self) {
	if (!self) {
		return;
	}

	r_buf_free (self->buf);
	free (self->data);
	free (self);
}

static bool dsc_header_get_field(RDSCHeader *self, const char *name, ut8 *out_value, size_t size) {
	const RDSCField * field;
	ut8 tmp[32];

	ut64 data_len = r_buf_size (self->buf);
	ut64 cursor = 0;
	// Initialize out value to avoid UB
	memset (out_value, 0, size);
	for (field = self->fields; field->name != NULL && cursor < data_len; field++) {
		st64 field_size = r_buf_fread_at (self->buf, cursor, tmp, field->format, 1);
		if (field_size < 0) {
			return false;
		}
		if (!strcmp (field->name, name)) {
			if (size < field_size) {
				return false;
			}
			memcpy (out_value, tmp, field_size);
			return true;
		}
		cursor += field_size;
	}

	return false;
}

static bool dsc_header_get_u64(RDSCHeader *self, const char *name, ut64 *out_value) {
	return dsc_header_get_field (self, name, (ut8 *) out_value, sizeof (ut64));
}

static bool dsc_header_get_u32(RDSCHeader *self, const char *name, ut32 *out_value) {
	return dsc_header_get_field (self, name, (ut8 *) out_value, sizeof (ut32));
}

static const RDSCField dsc_header_fields[] = {
	{ "16c", "magic" },
	{ "i", "mappingOffset" },
	{ "i", "mappingCount" },
	{ "i", "imagesOffsetOld" },
	{ "i", "imagesCountOld" },
	{ "l", "dyldBaseAddress" },
	{ "l", "codeSignatureOffset" },
	{ "l", "codeSignatureSize" },
	{ "l", "slideInfoOffsetUnused" },
	{ "l", "slideInfoSizeUnused" },
	{ "l", "localSymbolsOffset" },
	{ "l", "localSymbolsSize" },
	{ "16c", "uuid" },
	{ "l", "cacheType" },
	{ "i", "branchPoolsOffset" },
	{ "i", "branchPoolsCount" },
	{ "l", "dyldInCacheMH" },
	{ "l", "dyldInCacheEntry" },
	{ "l", "imagesTextOffset" },
	{ "l", "imagesTextCount" },
	{ "l", "patchInfoAddr" },
	{ "l", "patchInfoSize" },
	{ "l", "otherImageGroupAddrUnused" },
	{ "l", "otherImageGroupSizeUnused" },
	{ "l", "progClosuresAddr" },
	{ "l", "progClosuresSize" },
	{ "l", "progClosuresTrieAddr" },
	{ "l", "progClosuresTrieSize" },
	{ "i", "platform" },
	{ "i", "flags" },
	{ "l", "sharedRegionStart" },
	{ "l", "sharedRegionSize" },
	{ "l", "maxSlide" },
	{ "l", "dylibsImageArrayAddr" },
	{ "l", "dylibsImageArraySize" },
	{ "l", "dylibsTrieAddr" },
	{ "l", "dylibsTrieSize" },
	{ "l", "otherImageArrayAddr" },
	{ "l", "otherImageArraySize" },
	{ "l", "otherTrieAddr" },
	{ "l", "otherTrieSize" },
	{ "i", "mappingWithSlideOffset" },
	{ "i", "mappingWithSlideCount" },
	{ "l", "dylibsPBLStateArrayAddrUnused" },
	{ "l", "dylibsPBLSetAddr" },
	{ "l", "programsPBLSetPoolAddr" },
	{ "l", "programsPBLSetPoolSize" },
	{ "l", "programTrieAddr" },
	{ "i", "programTrieSize" },
	{ "i", "osVersion" },
	{ "i", "altPlatform" },
	{ "i", "altOsVersion" },
	{ "l", "swiftOptsOffset" },
	{ "l", "swiftOptsSize" },
	{ "i", "subCacheArrayOffset" },
	{ "i", "subCacheArrayCount" },
	{ "16c", "symbolFileUUID" },
	{ "l", "rosettaReadOnlyAddr" },
	{ "l", "rosettaReadOnlySize" },
	{ "l", "rosettaReadWriteAddr" },
	{ "l", "rosettaReadWriteSize" },
	{ "i", "imagesOffset" },
	{ "i", "imagesCount" },
	{ "i", "cacheSubType" },
	{ "i", "padding" },
	{ "l", "objcOptsOffset" },
	{ "l", "objcOptsSize" },
	{ "l", "cacheAtlasOffset" },
	{ "l", "cacheAtlasSize" },
	{ "l", "dynamicDataOffset" },
	{ "l", "dynamicDataMaxSize" },
	{ "i", "maybePointsToLinkeditMapAtTheEndOfSubCachesArray" },
	{ "i", "previousPointerMakesSense" },
	{ NULL, NULL }
};

#endif
