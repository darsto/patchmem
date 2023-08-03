/* SPDX-License-Identifier: MIT
 * Copyright(c) 2023 Darek Stojaczyk
 */

#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <unistd.h>

#include <dlfcn.h>
#include <libgen.h>
#include <semaphore.h>
#include <sys/types.h>

#include <patchmem.h>

#include "util.h"

_Atomic uint64_t g_counter;
_Atomic bool g_running = true;

static void __attribute__((noinline)) main_loop(void)
{
	g_counter++;
	__asm__("sfence");
}
void OVERRIDABLE_FN(main_loop);

static void *
thread_fn(void *arg)
{
	while (g_running) {
		OVERRIDABLE_REF(main_loop)();
		usleep(25 * 1000);
	}
	return NULL;
}

int
main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s /path/to/lib.so\n", argv[0]);
		return 1;
	}

	void *pm = dlopen(argv[1], RTLD_NOW);
	if (pm == NULL) {
		fprintf(stderr, "Failed to load .so: \"%s\"\n", argv[1]);
		return 1;
	}

	printf("hello\n");

	pthread_t pid;
	pthread_create(&pid, NULL, thread_fn, NULL);
	printf("thread created\n");

	/* let the thread start */
	while (g_counter == 0) {
		usleep(25 * 1000);
	}

	for (size_t i = 0; i < 10; i++) {
		fprintf(stderr, "starting iter %zu\n", i);

		void (*deinit)(int) = dlsym(pm, "deinit");
		deinit(PATCH_MEM_DEINIT_SUSPEND_ALL);
		dlclose(pm);
		pm = NULL;

		uint64_t oldcnt = atomic_load_explicit(&g_counter, memory_order_acquire);
		/* wait a bit */
		usleep(200 * 1000);
		/* the thread should be stopped by patchmem */
		uint64_t newcnt = atomic_load_explicit(&g_counter, memory_order_acquire);
		/* wait a bit */
		usleep(200 * 1000);
		/* the thread should be stopped by patchmem */
		uint64_t newcnt2 = atomic_load_explicit(&g_counter, memory_order_acquire);
		assert(newcnt2 == newcnt);
		assert(newcnt == oldcnt);

		pm = dlopen(argv[1], RTLD_NOW);
		if (pm == NULL) {
			fprintf(stderr, "subsequent dlopen() failed!\n");
			return 1;
		}

		/* the thread should be now resumed by patchmem */
		oldcnt = g_counter;
		while (g_counter == oldcnt) {
			usleep(50 * 1000);
		}
	}

	fprintf(stderr, "iters done, closing the lib\n");

	void (*deinit)(int) = dlsym(pm, "deinit");
	deinit(PATCH_MEM_DEINIT_RESUME_ALL);
	dlclose(pm);

	g_running = false;
	pthread_join(pid, NULL);
	return 0;
}