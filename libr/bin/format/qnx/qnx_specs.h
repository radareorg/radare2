#ifndef QNX_SPECS_H_
#define QNX_SPECS_H_

#define QNX_VERSION                     400
#define VERIFY_OFFSET                   36

#define QNX_MAX_REC_SIZE                (0x8000 - 512) // was 0xFFFF
#define QNX_MAX_DATA_SIZE               (QNX_MAX_REC_SIZE - sizeof(lmf_data))
#define VERIFY_END                      (VERIFY_OFFSET + sizeof(RWEndRec.verify))
#define QNX_MAX_FIXUPS                  (0x8000 - 512) 

#define QNX_MAGIC                       "\x00\x00\x38\x00\x00\x00"
#define QNX_HDR_SIZE                    sizeof (lmf_header)
#define QNX_RECORD_SIZE                 sizeof (lmf_record)
#define QNX_HEADER_ADDR                 sizeof (lmf_record)


#define _TCF_LONG_LIVED                 0x0001
#define _TCF_32BIT                      0x0002
#define _TCF_PRIV_MASK                  0x000c
#define _TCF_FLAT                       0x0010

#define SEG16_CODE_FIXUP                0x0004
#define LINEAR32_CODE_FIXUP             0x80000000
#define LINEAR32_SELF_RELATIVE_FIXUP    0x40000000

#endif