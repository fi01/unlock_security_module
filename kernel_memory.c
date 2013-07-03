#include <stdio.h>

#include "device_database/device_database.h"
#include "ptmx.h"
#include "kernel_memory.h"

#define KERNEL_MEMORY_MAPPED_ADDRESS    0x10000000

void *
convert_to_kernel_virtual_address(void *address)
{
  return address - KERNEL_MEMORY_MAPPED_ADDRESS + KERNEL_BASE_ADDRESS;
}

void *
convert_to_kernel_mapped_address(void *address)
{
  return address - KERNEL_BASE_ADDRESS + KERNEL_MEMORY_MAPPED_ADDRESS;
}

static unsigned long int
find_kernel_text_from_iomem(void)
{
  unsigned long int kernel_ram;
  FILE *fp;

  fp = fopen("/proc/iomem", "rt");
  if (!fp) {
    return 0;
  }

  kernel_ram = 0;

  while (!feof(fp)) {
    unsigned long int start, end;
    char buf[256];
    char *p;
    int len;
    char colon[256], name1[256], name2[256];
    int n;

    p = fgets(buf, sizeof (buf) - 1, fp);
    if (p == NULL)
      break;

    if (sscanf(buf, "%lx-%lx %s %s %s", &start, &end, colon, name1, name2) != 5
        || strcmp(colon, ":")) {
      continue;
    }

    if (!strcasecmp(name1, "System") && !strcasecmp(name2, "RAM")) {
      kernel_ram = start;
      continue;
    }

    if (strcasecmp(name1, "Kernel") || (strcasecmp(name2, "text") && strcasecmp(name2, "code"))) {
      kernel_ram = 0;
      continue;
    }

    fclose(fp);

    kernel_ram += 0x00008000;

    printf("Detected kernel physical address at 0x%08x\n", kernel_ram);

    return kernel_ram;
  }

  fclose(fp);
  return 0;
}

unsigned long int kernel_physical_offset;

static bool
setup_variables(void)
{
  kernel_physical_offset = device_get_symbol_address(DEVICE_SYMBOL(kernel_physical_offset));
  if (kernel_physical_offset) {
    return true;
  }

  kernel_physical_offset = find_kernel_text_from_iomem();
  if (kernel_physical_offset) {
    return true;
  }

  print_reason_device_not_supported();
  return false;
}

bool
map_kernel_memory(void)
{
  if (!kernel_physical_offset) {
    if (!setup_variables()) {
      return false;
    }
  }

  return ptmx_map_memory(KERNEL_MEMORY_MAPPED_ADDRESS, kernel_physical_offset, KERNEL_MEMORY_SIZE);
}

bool
unmap_kernel_memory(void)
{
  if (!kernel_physical_offset) {
    return false;
  }

  return ptmx_unmap_memory(KERNEL_MEMORY_MAPPED_ADDRESS, KERNEL_MEMORY_SIZE);
}
