#include <stdio.h>

#include "device_database/device_database.h"
#include "kallsyms.h"
#include "mm.h"

void *
get_remap_pfn_range_address(void)
{
  void *ret = NULL;

  ret = (void*)device_get_symbol_address(DEVICE_SYMBOL(remap_pfn_range));
  if (!ret && kallsyms_exist()) {
    ret = kallsyms_get_symbol_address("remap_pfn_range");
    if (ret) {
#ifdef HAS_SET_SYMBOL_ADDRESS
      device_set_symbol_address(DEVICE_SYMBOL(remap_pfn_range), (unsigned long int)ret);
#endif /* HAS_SET_SYMBOL_ADDRESS */
    }
  }

  if (!ret) {
    print_reason_device_not_supported();
    return NULL;
  }

  return ret;
}
