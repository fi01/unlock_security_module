#ifndef __RESET_SECURITY_OPS_H__
#define __RESET_SECURITY_OPS_H__

#include <stdbool.h>
#include "libkallsyms/kallsyms_in_memory.h"

extern bool has_reset_security_ops(kallsyms *info);
extern bool run_reset_security_ops(kallsyms *info);

#endif /* __RESET_SECURITY_OPS_H__ */
