#ifndef __MMC_PROTECT_PART_H__
#define __MMC_PROTECT_PART_H__

#include <stdbool.h>

extern bool has_mmc_protect_part(void);
extern bool unlock_mmc_protect_part(void);

#endif /* __MMC_PROTECT_PART_H__ */
