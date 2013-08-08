#include <stdbool.h>

#define KERNEL_BASE_ADDRESS             0xc0008000
#define KERNEL_MEMORY_SIZE              0x02000000

extern void *convert_to_kernel_virtual_address(void *address);
extern void *convert_to_kernel_mapped_address(void *address);

extern bool map_kernel_memory(void);
extern bool unmap_kernel_memory(void);
