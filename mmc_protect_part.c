#include "mmc_protect_part.h"
#include "kernel_memory.h"
#include "libkallsyms/kallsyms_in_memory.h"

//#define UNLOCK_MMC_BOOT_WRITE
//#define UNLOCK_MMC_RECOVERY_WRITE
#define UNLOCK_MMC_SYSTEM_WRITE

#if defined(UNLOCK_MMC_BOOT_WRITE) || defined(UNLOCK_MMC_RECOVERY_WRITE) || defined(UNLOCK_MMC_SYSTEM_WRITE)
#define UNLOCK_MMC_WRITE
#endif

#define MMC_BOOT_PARTITION      11
#define MMC_RECOVERY_PARTITION  12
#define MMC_SYSTEM_PARTITION    15

struct mmc_protect_inf {
  unsigned long int partition;
  unsigned long int protect;
};

#define MMC_NO_PROTECT          0x00
#define MMC_PROTECT_READ        0x01
#define MMC_PROTECT_WRITE       0x02

static const struct mmc_protect_inf check_mmc_protect_part[] = {
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

static int n_mmc_protect_part = sizeof (check_mmc_protect_part) / sizeof (check_mmc_protect_part[0]);

static unsigned long int mmc_protect_part_address;

bool
has_mmc_protect_part(void)
{
  struct mmc_protect_inf *p;
  int i;

  mmc_protect_part_address = kallsyms_in_memory_lookup_name("mmc_protect_part");
  if (!mmc_protect_part_address) {
    return false;
  }

  p = convert_to_kernel_mapped_address((void *)mmc_protect_part_address);

  for (i = 0; i < n_mmc_protect_part; i++) {
    if (p[i].partition != check_mmc_protect_part[i].partition) {
      printf("mmc_protect_part is not found.\n");
      return false;
    }
  }

  return true;
}

bool
unlock_mmc_protect_part(void)
{
  struct mmc_protect_inf *p;
  int count_readable = 0;
  int count_writable = 0;
  int i;

  p = convert_to_kernel_mapped_address((void *)mmc_protect_part_address);

  for (i = 0; i < n_mmc_protect_part; i++) {
    if (p[i].protect & ~MMC_PROTECT_READ) {
      p[i].protect &= ~MMC_PROTECT_READ;
      count_readable++;
    }

#ifdef UNLOCK_MMC_WRITE
    switch (p[i].partition) {
#ifdef UNLOCK_MMC_BOOT_WRITE
    case MMC_BOOT_PARTITION:
#endif
#ifdef UNLOCK_MMC_RECOVERY_WRITE
    case MMC_RECOVERY_PARTITION:
#endif
#ifndef UNLOCK_MMC_SYSTEM_WRITE
    case MMC_SYSTEM_PARTITION:
#endif
      if (p[i].protect & ~MMC_PROTECT_WRITE) {
	p[i].protect &= ~MMC_PROTECT_WRITE;
	count_writable++;
      }
    }
#endif
  }

  printf("  %d functions are fixed to readable.\n", count_readable);
  printf("  %d functions are fixed to writable.\n", count_writable);

  return true;
}
