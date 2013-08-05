#define _LARGEFILE64_SOURCE
#include <stdio.h>

#include "device_database/device_database.h"
#include "libkallsyms/kallsyms_in_memory.h"
#include "kernel_memory.h"

typedef struct _supported_device {
  device_id_t device_id;
  unsigned long int ccsecurity_ops_address;
  unsigned long int search_binary_handler_address;
} supported_device;

static supported_device supported_devices[] = {
};

static int n_supported_devices = sizeof(supported_devices) / sizeof(supported_devices[0]);

static void *ccsecurity_ops;
static void *search_binary_handler;

static bool
setup_variables(kallsyms *info)
{
  device_id_t device_id = detect_device();
  int i;

  for (i = 0; i < n_supported_devices; i++) {
    if (supported_devices[i].device_id == device_id) {
      ccsecurity_ops = (void *)supported_devices[i].ccsecurity_ops_address;
      search_binary_handler = (void *)supported_devices[i].search_binary_handler_address;
      break;
    }
  }

  if (!ccsecurity_ops) {
    ccsecurity_ops = (void *)kallsyms_in_memory_lookup_name(info, "ccsecurity_ops");
  }

  if (!search_binary_handler) {
    search_binary_handler = (void *)kallsyms_in_memory_lookup_name(info, "search_binary_handler");
  }

  return ccsecurity_ops && search_binary_handler;
}

bool
has_ccsecurity(kallsyms *info)
{
  return kallsyms_in_memory_lookup_name(info, "ccsecurity_ops") != 0;
}

#define NUM_CCSECURITY_OPS  39
#define BINARY_HANDLER_POS  35

bool
unlock_ccsecurity(kallsyms *info)
{
  void **p;
  const char *name;
  int i;

  if (!setup_variables(info)) {
    print_reason_device_not_supported();
    return false;
  }

  p = convert_to_kernel_mapped_address(ccsecurity_ops);
  name = kallsyms_in_memory_lookup_address(info, (unsigned long)p[BINARY_HANDLER_POS]);

  if (strcmp(name, "__ccs_search_binary_handler")) {
    if (p[BINARY_HANDLER_POS] == search_binary_handler) {
      printf("Already disabled??\nUnlock anyway.");
    }
    else {
      printf("check failed: ccsecurity_ops[%d] = %s\n", BINARY_HANDLER_POS, name);
      return false;
    }
  }

  for (i = 0; i < NUM_CCSECURITY_OPS; i++) {
    switch (i) {
    case BINARY_HANDLER_POS:
      p[i] = search_binary_handler;
      break;

    default:
      p[i] = 0;
    }
  }

  return true;
}
