/*
 * Copyright (C) 2013 Hiroyuki Ikezoe
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#ifndef PTMX_H
#define PTMX_H

#include <stdbool.h>

extern bool ptmx_run_in_kernel_mode(bool (*function)(void *), void *user_data);

extern bool ptmx_map_memory(unsigned long int map_address, unsigned long physical_address, unsigned long int size);
extern bool ptmx_unmap_memory(unsigned long int map_address, unsigned long int size);

#endif /* PTMX_H */
