#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <stdlib.h>

#include "kernel_memory.h"
#include "kallsymsprint.h"
#include "ccsecurity.h"
#include "reset_security_ops.h"
#include "lsm_capability.h"

#define CHECK_SYMBOL    "printk"

static bool
check_is_kallsymsprint_working(void)
{
  unsigned long addr;
  const char *name;

  addr = kallsyms_lookup_name(CHECK_SYMBOL);
  name = kallsyms_lookup_address(addr);

  if (strcmp(name, CHECK_SYMBOL) != 0) {
    return false;
  }

  return true;
}

static bool
do_unlock(void)
{
  bool success = false;

  printf("Checking ccsecurity...\n");
  if (has_ccsecurity()) {
    printf("Found ccsecurity.\n");

    if (unlock_ccsecurity()) {
      goto unlock_success;
    }

    goto unlock_failed;
  }

  printf("Checking reset_security_ops...\n");
  if (has_reset_security_ops()) {
    printf("Found reset_security_ops. Run it.\n");
    if (run_reset_security_ops()) {
      printf("OK.\n\n");
      success = true;
    }
    else {
      printf("Failed.\n\n");
    }
  }

  printf("Checking fjsec LSM...\n");
  if (has_fjsec_lsm()) {
    printf("Found fjsec LSM.\n");

    if (unlock_fjsec_lsm()) {
      goto unlock_success;
    }

    goto unlock_failed;
  }

  printf("Checking miyabi LSM...\n");
  if (has_miyabi_lsm()) {
    printf("Found miyabi LSM.\n");

    if (unlock_miyabi_lsm()) {
      goto unlock_success;
    }

    goto unlock_failed;
  }

  if (success) {
    goto unlock_success;
  }

  printf("\nSecurity module is not found.\n");
  return false;

unlock_failed:
  printf("Failed unlock LSM.\n");
  return false;

unlock_success:
  printf("\nUnlocked LSM.\n");
  return true;
}

int
main(int argc, char **argv)
{
  void *mapped_address;

  printf("Mapping kernel memory...\n");
  if (!map_kernel_memory()) {
    printf("Failed.\n");
    exit(EXIT_FAILURE);
  }
  printf("OK.\n\n");

  printf("Finding kallsyms address in memory...\n");
  mapped_address = convert_to_kernel_mapped_address((void *)KERNEL_BASE_ADDRESS);
  if (get_kallsyms(mapped_address, KERNEL_MEMORY_SIZE)) {
    printf("Checking kallsyms working...\n");

    if (check_is_kallsymsprint_working()) {
      printf("OK. Ready to unlock security module.\n\n");

      do_unlock();
    }
    else {
      printf("kallsymsprint doesn't work\n");
    }
  }
  else {
    printf("Failed: Lookup kallsyms in memory.\n");
  }

  unmap_kernel_memory();

  exit(EXIT_SUCCESS);
}
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
