#ifndef __LSM_H__
#define __LSM_H__

#include <stdbool.h>
#include "libkallsyms/kallsyms_in_memory.h"

extern bool has_fjsec_lsm(kallsyms *info);
extern bool unlock_fjsec_lsm(kallsyms *info);

extern bool has_miyabi_lsm(kallsyms *info);
extern bool unlock_miyabi_lsm(kallsyms *info);

#endif /* __LSM_H__ */

