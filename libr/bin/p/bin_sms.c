#include <r_bin.h>

typedef struct gen_hdr {
    ut8 HeaderID[8];
    ut8 ReservedWord[2];
    ut16 CheckSum;
    ut8 ProductCode[2];
    ut8 Version; //Low 4 bits version, Top 4 bits ProductCode
    ut8 RegionRomSize; //Low 4 bits RomSize, Top 4 bits Region
} SMS_Header;

static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
    check_bytes (buf, sz);
    return R_NOTNULL;
}


static int check(RBinFile *arch) {
    const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
    ut64 sz = arch ? r_buf_size (arch->buf): 0;
    return check_bytes (bytes, sz);
}

static int check_bytes(const ut8 *buf, ut64 length) {
    if (length > 0x2000) {
      if (!memcmp (buf+0x1ff0, "TMR SEGA", 8) || 
        !memcmp (buf+0x3ff0, "TMR SEGA", 8) ||
        !memcmp (buf+0x7ff0, "TMR SEGA", 8) ||
        !memcmp (buf+0x8ff0, "TMR SEGA", 8) ||
        !memcmp (buf+0x7fe0, "SDSC", 4))
          return true;
    }
    return false;
}


static RBinInfo* info(RBinFile *arch) {
    RBinInfo *ret = R_NEW0 (RBinInfo);
    if (!ret) return NULL;

    if (!arch || !arch->buf) {
        free (ret);
        return NULL;
    }
    ret->file = strdup (arch->file);
    ret->type = strdup ("ROM");
    ret->machine = strdup ("SEGA MasterSystem");
    ret->os = strdup ("sms");
    ret->arch = strdup ("z80");
    ret->has_va = 1;
    ret->bits = 8;
    
    // TODO: figure out sections/symbols for this format and move this there
    //       also add SDSC headers..and find entry
    SMS_Header * hdr;
    if (!memcmp (arch->buf->buf+0x1ff0, "TMR SEGA", 8))
        hdr = (SMS_Header*)(arch->buf->buf + 0x1ff0);
    if (!memcmp (arch->buf->buf+0x3ff0, "TMR SEGA", 8))
        hdr = (SMS_Header*)(arch->buf->buf + 0x3ff0);
    if (!memcmp (arch->buf->buf+0x7ff0, "TMR SEGA", 8))
        hdr = (SMS_Header*)(arch->buf->buf + 0x7ff0);
    if (!memcmp (arch->buf->buf+0x8ff0, "TMR SEGA", 8))
        hdr = (SMS_Header*)(arch->buf->buf + 0x8ff0);

    eprintf ("Checksum: 0x%04x\n", (ut32)hdr->CheckSum);
    eprintf ("ProductCode: %02d%02X%02X\n", (hdr->Version >> 4), hdr->ProductCode[1],
      hdr->ProductCode[0]);
    switch (hdr->RegionRomSize >> 4) {
        case 3:
            eprintf ("Console: Sega Master System\n");
            eprintf ("Region: Japan\n");
            break;
        case 4:
            eprintf ("Console: Sega Master System\n");
            eprintf ("Region: Export\n");
            break;
        case 5:
            eprintf ("Console: Game Gear\n");
            eprintf ("Region: Japan\n");
            break;
        case 6:
            eprintf ("Console: Game Gear\n");
            eprintf ("Region: Export\n");
            break;
        case 7:
            eprintf ("Console: Game Gear\n");
            eprintf ("Region: International\n");
            break;
    }
    switch (hdr->RegionRomSize & 0xf) {
        case 0xa:
            eprintf ("RomSize: 8KB\n");
            break;
        case 0xb:
            eprintf ("RomSize: 16KB\n");
            break;
        case 0xc:
            eprintf ("RomSize: 32KB\n");
            break;
        case 0xd:
            eprintf ("RomSize: 48KB\n");
            break;
        case 0xe:
            eprintf ("RomSize: 64KB\n");
            break;
        case 0xf:
            eprintf ("RomSize: 128KB\n");
            break;
        case 0x0:
            eprintf ("RomSize: 256KB\n");
            break;
        case 0x1:
            eprintf ("RomSize: 512KB\n");
            break;
        case 0x2:
            eprintf ("RomSize: 1024KB\n");
            break;
    } 
    return ret;
}


struct r_bin_plugin_t r_bin_plugin_sms = {
    .name = "sms",
    .desc = "SEGA MasterSystem/GameGear",
    .license = "LGPL3",
    .init = NULL,
    .fini = NULL,
    .get_sdb = NULL,
    .load = NULL,
    .load_bytes = &load_bytes,
    .check = &check,
    .baddr = NULL,
    .check_bytes = &check_bytes,
    .entries = NULL,
    .sections = NULL,
    .info = &info,
    .minstrlen = 10,
    .strfilter = 'U'
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
    .type = R_LIB_TYPE_BIN,
    .data = &r_bin_plugin_sms,
    .version = R2_VERSION
};
#endif

