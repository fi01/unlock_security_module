#ifndef __CCSECURITY_H__
#define __CCSECURITY_H__

#include <stdbool.h>
#include "libkallsyms/kallsyms_in_memory.h"

extern bool has_ccsecurity(kallsyms *info);
extern bool unlock_ccsecurity(kallsyms *info);

#endif /* __CCSECURITY_H__ */
