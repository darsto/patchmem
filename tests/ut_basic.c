/* SPDX-License-Identifier: MIT
 * Copyright(c) 2023 Darek Stojaczyk
 */

#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

#include <dlfcn.h>
#include <libgen.h>
#include <sys/types.h>

#include <patchmem.h>

#include "util.h"

void _os_safely_suspend_all_threads(void);
void _os_resume_all_threads(void);

static bool g_hooked_flag = false;

static void __attribute__((noinline)) some_fn(void)
{
	printf("%s!\n", __func__);
	g_hooked_flag = false;
}
void OVERRIDABLE_FN(some_fn);

static void (*org_some_fn)(void) = (void *)OVERRIDABLE_REF(some_fn);
static void
hooked_some_fn(void)
{
	printf("%s!\n", __func__);

	assert(g_hooked_flag == false);
	g_hooked_flag = true;

	org_some_fn();
	assert(g_hooked_flag == false);

	g_hooked_flag = true;
}
TRAMPOLINE_FN(&org_some_fn, 5, hooked_some_fn);

void *
thread_fn(void *arg)
{
	OVERRIDABLE_REF(some_fn)();
	assert(g_hooked_flag);
	usleep(100 * 1000);
	return NULL;
}

int
main(int argc, char *argv[])
{
	printf("hello\n");

	Dl_info info;
	dladdr(&main, &info);
	void *this_name = basename(argv[0]);
	assert(this_name != NULL);
	patch_mem_static_init(this_name);

	pthread_t pid;
	pthread_create(&pid, NULL, thread_fn, NULL);
	printf("thread created\n");

	usleep(10 * 1000);
	_os_safely_suspend_all_threads();
	usleep(10 * 1000);
	_os_resume_all_threads();

	pthread_join(pid, NULL);
	return 0;
}