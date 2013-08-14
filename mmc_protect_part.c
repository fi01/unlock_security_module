#include "mmc_protect_part.h"
#include "kernel_memory.h"
#include "libkallsyms/kallsyms_in_memory.h"

//#define UNLOCK_MMC_BOOT_WRITE
//#define UNLOCK_MMC_RECOVERY_WRITE
#define UNLOCK_MMC_SYSTEM_WRITE

typedef enum {
  MMC_PROTECT_TYPE_UNKNOWN,
  MMC_PROTECT_TYPE_SH04E,
  MMC_PROTECT_TYPE_SHL21,
} mmc_protect_type_t;

static mmc_protect_type_t mmc_protect_type;

struct mmc_protect_inf {
  unsigned long int partition;
  unsigned long int protect;
};

#define MMC_NO_PROTECT          0x00
#define MMC_PROTECT_READ        0x01
#define MMC_PROTECT_WRITE       0x02

#define MMC_BOOT_PARTITION_SH04E      11
#define MMC_RECOVERY_PARTITION_SH04E  12
#define MMC_SYSTEM_PARTITION_SH04E    15

static const struct mmc_protect_inf mmc_protect_inf_sh04e[] = {
  { 2,                       MMC_PROTECT_WRITE    },
  { 3,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  { 4,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  { 5,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  { 6,                       MMC_PROTECT_WRITE    },
  { 7,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  { 8,                       MMC_PROTECT_WRITE    },
  { 9,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  {10,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  {11,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  {12,                       MMC_PROTECT_WRITE    },
  {13,                       MMC_PROTECT_WRITE    },
  {15,                       MMC_PROTECT_WRITE    },
};

static int n_mmc_protect_inf_sh04e = sizeof (mmc_protect_inf_sh04e) / sizeof (mmc_protect_inf_sh04e[0]);

#define MMC_BOOT_PARTITION_SHL21      10
#define MMC_RECOVERY_PARTITION_SHL21  13
#define MMC_SYSTEM_PARTITION_SHL21    12

static const struct mmc_protect_inf mmc_protect_inf_shl21[] = {
  { 1,                       MMC_PROTECT_WRITE    },
  { 2,                       MMC_PROTECT_WRITE    },
  { 3,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  { 4,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  { 5,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  { 6,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  { 8,                       MMC_PROTECT_WRITE    },
  { 9,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  {10,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  {11,                       MMC_PROTECT_WRITE    },
  {12,                       MMC_PROTECT_WRITE    },
  {13,                       MMC_PROTECT_WRITE    },
  {14,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
};

static int n_mmc_protect_inf_shl21 = sizeof (mmc_protect_inf_shl21) / sizeof (mmc_protect_inf_shl21[0]);

static unsigned long int mmc_protect_part_address;

static bool
check_type_sh04e(const struct mmc_protect_inf *protect_inf)
{
  int i;

  for (i = 0; i < n_mmc_protect_inf_sh04e; i++) {
    if (protect_inf[i].partition != mmc_protect_inf_sh04e[i].partition) {
      return false;
    }
  }

  return true;
}

static bool
check_type_shl21(const struct mmc_protect_inf *protect_inf)
{
  int i;

  for (i = 0; i < n_mmc_protect_inf_shl21; i++) {
    if (protect_inf[i].partition != mmc_protect_inf_shl21[i].partition) {
      return false;
    }
  }

  return true;
}

bool
has_mmc_protect_part(kallsyms *info)
{
  struct mmc_protect_inf *protect_inf;
  int i;

  mmc_protect_type = MMC_PROTECT_TYPE_UNKNOWN;

  mmc_protect_part_address = kallsyms_in_memory_lookup_name(info, "mmc_protect_part");
  if (!mmc_protect_part_address) {
    printf("mmc_protect_part is not found.\n");
    return false;
  }

  protect_inf = convert_to_kernel_mapped_address((void *)mmc_protect_part_address);

  if (protect_inf[0].partition == 0) {
    protect_inf++;
  }

  if (check_type_sh04e(protect_inf)) {
    printf("  type SH-04E\n");
    mmc_protect_type = MMC_PROTECT_TYPE_SH04E;
    return true;
  }

  if (check_type_shl21(protect_inf)) {
    printf("  type SHL21\n");
    mmc_protect_type = MMC_PROTECT_TYPE_SHL21;
    return true;
  }

  printf("mmc_protect_part is unknown type.\n");

  return false;
}

bool
unlock_mmc_protect_part(kallsyms *info)
{
  struct mmc_protect_inf *protect_inf;
  int count;
  int count_readable = 0;
  int count_writable = 0;
  int partition_boot;
  int partition_recovery;
  int partition_system;
  int i;

  switch (mmc_protect_type) {
  case MMC_PROTECT_TYPE_SH04E:
    partition_boot = MMC_BOOT_PARTITION_SH04E;
    partition_recovery = MMC_RECOVERY_PARTITION_SH04E;
    partition_system = MMC_SYSTEM_PARTITION_SH04E;
    count = n_mmc_protect_inf_sh04e;
    break;

  case MMC_PROTECT_TYPE_SHL21:
    partition_boot = MMC_BOOT_PARTITION_SHL21;
    partition_recovery = MMC_RECOVERY_PARTITION_SHL21;
    partition_system = MMC_SYSTEM_PARTITION_SHL21;
    count = n_mmc_protect_inf_shl21;
    break;

  default:
    return false;
  }

  protect_inf = convert_to_kernel_mapped_address((void *)mmc_protect_part_address);

  if (protect_inf[0].partition == 0) {
    protect_inf++;
  }

  for (i = 0; i < count; i++) {
    bool unlock_write;

    if (protect_inf[i].protect & MMC_PROTECT_READ) {
      protect_inf[i].protect &= ~MMC_PROTECT_READ;
      count_readable++;
    }

    unlock_write = false;

#ifdef UNLOCK_MMC_BOOT_WRITE
    if (protect_inf[i].partition == partition_boot) {
      unlock_write = true;
    }
#endif

#ifdef UNLOCK_MMC_RECOVERY_WRITE
    if (protect_inf[i].partition == partition_recovery) {
      unlock_write = true;
    }
#endif

#ifdef UNLOCK_MMC_SYSTEM_WRITE
    if (protect_inf[i].partition == partition_system) {
      unlock_write = true;
    }
#endif

    if (unlock_write) {
      if (protect_inf[i].protect & MMC_PROTECT_WRITE) {
	protect_inf[i].protect &= ~MMC_PROTECT_WRITE;
	count_writable++;
      }
    }
  }

  printf("  %d functions are fixed to readable.\n", count_readable);
  printf("  %d functions are fixed to writable.\n", count_writable);

  return true;
}
