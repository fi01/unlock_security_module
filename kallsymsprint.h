#ifndef __KALLSYMSPRINT_H__
#define __KALLSYMSPRINT_H__

#include <stdbool.h>

extern unsigned long kallsyms_lookup_name(const char *name);
extern const char *kallsyms_lookup_address(unsigned long address);
extern void kallsyms_print_all(void);
extern int get_kallsyms_addresses(unsigned long *mem, unsigned long length, unsigned long offset);
extern int get_kallsyms(unsigned long *mem, size_t len);

extern bool is_address_in_kallsyms_addresses(void *mapped_address);

#endif /* __KALLSYMSPRINT_H__ */

/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
