#ifndef __MMC_PROTECT_PART_H__
#define __MMC_PROTECT_PART_H__

#include <stdbool.h>
#include "libkallsyms/kallsyms_in_memory.h"

extern bool has_mmc_protect_part(kallsyms *info);
extern bool unlock_mmc_protect_part(kallsyms *info);

#endif /* __MMC_PROTECT_PART_H__ */
