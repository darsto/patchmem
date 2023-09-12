/* SPDX-License-Identifier: MIT
 * Copyright(c) 2023 Darek Stojaczyk
 */

#include <dlfcn.h>
/* a simple way to keep those two symbols around */
static void *g_dlopen_addr = (void *)dlopen;
static void *g_dlclose_addr = (void *)dlclose;
