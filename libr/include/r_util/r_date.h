#ifndef R2_DATE_H
#define R2_DATE_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef R_API

R_API char *r_time_stamp_to_str(ut32 timeStamp);
R_API ut32 r_dos_time_stamp_to_posix(ut32 timeStamp);
R_API bool r_time_stamp_is_dos_format(const ut32 certainPosixTimeStamp, const ut32 possiblePosixOrDosTimeStamp);

#endif

#ifdef __cplusplus
}
#endif

#endif
