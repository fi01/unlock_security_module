#include <stdbool.h>

typedef enum {
  FOPS_RUN_BY_EXPLOIT,
  FOPS_RUN_BY_KERNEL_MEMORY,
} fops_run_mode;

extern bool fops_run_in_kernel_mode(void *fops_address,
                                    const char *device_path,
                                    fops_run_mode mode,
                                    bool (*function)(void *),
                                    void *user_data);

extern bool fops_map_physical_memory(void *fops_address,
                                     const char *device_path,
                                     fops_run_mode mode,
                                     unsigned long int map_address,
                                     unsigned long int physical_address,
                                     unsigned long int size);

extern bool fops_unmap_physical_memory(unsigned long int map_address, unsigned long int size);
