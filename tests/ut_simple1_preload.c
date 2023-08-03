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

extern uint64_t g_counter;
extern sem_t g_sem;
extern bool OVERRIDABLE_REF(main_loop)();

static size_t g_hooked_calls;

static bool (*org_main_loop)(void) = OVERRIDABLE_REF(main_loop);
static bool
hooked_main_loop(void)
{
	fprintf(stderr, "%s!\n", __func__);

	uint64_t prev_counter = g_counter;
	org_main_loop();
	assert(g_counter == prev_counter + 1);
	org_main_loop();
	assert(g_counter == prev_counter + 2);

	g_hooked_calls++;
	if (g_hooked_calls >= 5) {
		sem_post(&g_sem);
		return false;
	}

	return true;
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

static void __attribute__((destructor(200))) fini(void)
{
	printf("so fini\n");

	assert(g_hooked_calls == 5);
}