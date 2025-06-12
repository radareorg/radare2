/* radare2 - LGPL - Copyright 2025 - Rot127 <unisono@quyllur.org> (ported from rizin2) */

/**
 * \file Loader for the Qualcomm peripheral firmware images.
 *
 * Reference: https://github.com/torvalds/linux/blob/master/drivers/soc/qcom/mdt_loader.c
 */

#ifndef R2_MDT_H
#define R2_MDT_H

#include <r_bin.h>
#include <r_types.h>
#include <r_util.h>
#include "../elf/elf.h"

#define qcom_p_flags(p_flags) (p_flags >> 24)

/**
 * \brief Mask for the segment type.
 */
#define QCOM_MDT_TYPE_MASK (7 << 24)
/**
 * \brief Bits set for the first firmware part.
 */
#define QCOM_MDT_TYPE_LAYOUT (7 << 24)
/**
 * \brief Type of the signature segment.
 */
#define QCOM_MDT_TYPE_SIGNATURE (2 << 24)
/**
 * \brief Relocatable segment.
 */
#define QCOM_MDT_RELOCATABLE (1 << 27)

/**
 * \brief The segment type/p_type as it is in the ELF.
 */
typedef ut32 RBinMdtPFlags;

typedef enum r_bin_mdt_seg_type {
	R_BIN_MDT_PART_UNIDENTIFIED = 0,
	R_BIN_MDT_PART_ELF, ///< An ELF file.
	R_BIN_MDT_PART_MBN, ///< The secure boot authentication signature segment.
	R_BIN_MDT_PART_COMPRESSED_Q6ZIP, ///< Q6ZIP compressed segment (if identified).
	R_BIN_MDT_PART_COMPRESSED_CLADE2, ///< CLADE2 compressed segment (if identified).
	R_BIN_MDT_PART_COMPRESSED_ZLIB, ///< Zlib compressed segment (if identified).
} RBinMdtSegBinFormat;

/**
 * \brief An MDT firmware part and some descriptions.
 */
typedef struct {
	char *name; ///< The name of the part. Should be equal to the base name of the file.
	bool relocatable; ///< True if the Qualcomm relocatable flag is set for the segment.
	bool is_layout; ///< True if the ELF segment is the firmware layout.
	RBinMdtSegBinFormat format; ///< The segment type.
	RBinMdtPFlags pflags; ///< The segment p_flags.
	RBinFile *vfile; ///< The virtual file for the `.bNN` file (simplified from RBinVirtualFile).
	RBuffer *vfile_buf; ///< Buffer for the virtual file
	char *vfile_name; ///< Name of the virtual file
	union {
		ELFOBJ *elf; ///< Set if this part is an ELF.
		void *mbn; ///< Set if this part is an MBN auth segment.
	} obj;
	RBinAddr *entry; ///< The entry point, if any.
	RBinMap *map; ///< The mapping of the part in memory.
	/**
	 * \brief The physical address as in the layout. This is not the same as map->paddr!
	 * Because map is used to read from the files. So it has be zero (to not mess up the reading offsets).
	 */
	ut64 paddr;
	char *patches_vfile_name; ///< Name of the vfile of patches to the binary. If NULL, no patches are supported.
	char *relocs_vfile_name; ///< Name of the vfile of relocs to the binary. If NULL, no relocs are supported.
	RList/*<RBinSymbol *>*/ *symbols; ///< Symbols in this part.
	RList/*<RBinReloc *>*/ *relocs; ///< Relocs in this part.
	RList/*<RBinSection *>*/ *sections; ///< Sections in this part.
	RList/*<RBinMap *>*/ *sub_maps; ///< Maps of the obj, if any.
} RBinMdtPart;

typedef struct {
	char *name; ///< The name of the peripheral firmware. E.g. modem, adsp, cdsp or npu.
	ELFOBJ *header; ///< The ELF header of the whole firmware. From `<peripheral>.mdt`.
	RList/*<RBinMdtPart *>*/ *parts; ///< All parts from the `<peripheral>.bNN` files.
} RBinMdtObj;

R_IPI RBinMdtPart *r_bin_mdt_part_new(const char *name, size_t p_flags);
R_IPI void r_bin_mdt_part_free(RBinMdtPart *part);
R_IPI RBinMdtObj *r_bin_mdt_obj_new(void);
R_IPI void r_bin_mdt_obj_free(RBinMdtObj *obj);
R_IPI bool r_bin_mdt_check_filename(const char *filename);
R_IPI bool r_bin_mdt_check_buffer(RBuffer *b);

#endif // R2_MDT_H