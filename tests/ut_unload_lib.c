/* SPDX-License-Identifier: MIT
 * Copyright(c) 2023 Darek Stojaczyk
 */

#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <dlfcn.h>
#include <libgen.h>
#include <semaphore.h>
#include <sys/types.h>

#include <patchmem.h>

#include "util.h"

extern void OVERRIDABLE_REF(main_loop)();

static _Atomic uint64_t g_hooked_calls;

static void (*org_main_loop)(void) = OVERRIDABLE_REF(main_loop);
static void
hooked_main_loop(void)
{
	org_main_loop();
	g_hooked_calls++;
}
TRAMPOLINE_FN(&org_main_loop, 5, hooked_main_loop);

static void __attribute__((constructor(200))) init(void)
{
	printf("so init\n");

	Dl_info info;
	dladdr(&init, &info);
	char *this_name = strrchr(info.dli_fname, '/') + 1;

	patch_mem_static_init((void *)this_name);
}

void
deinit(int deinit_strategy)
{
	Dl_info info;
	dladdr(&init, &info);
	char *this_name = strrchr(info.dli_fname, '/') + 1;

	patch_mem_static_deinit((void *)this_name, deinit_strategy);
}

static void __attribute__((destructor(200))) fini(void)
{
	printf("so fini\n");

	assert(g_hooked_calls > 0);
}