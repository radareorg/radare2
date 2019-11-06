#ifndef R_PROTOBUF_H
#define R_PROTOBUF_H

#ifdef __cplusplus
extern "C" {
#endif

R_API char *r_protobuf_decode(const ut8* buffer, const ut64 size, bool debug);

#ifdef __cplusplus
}
#endif

#endif /* R_PROTOBUF_H */
