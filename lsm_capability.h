#ifndef __LSM_H__
#define __LSM_H__

#include <stdbool.h>

extern bool has_fjsec_lsm(void);
extern bool unlock_fjsec_lsm(void);

extern bool has_miyabi_lsm(void);
extern bool unlock_miyabi_lsm(void);

#endif /* __LSM_H__ */

