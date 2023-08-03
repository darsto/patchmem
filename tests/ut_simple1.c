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

uint64_t g_counter;
sem_t g_sem;

static bool __attribute__((noinline)) main_loop(void)
{
	g_counter++;
	return true;
}
bool OVERRIDABLE_FN(main_loop);

void *
thread_fn(void *arg)
{
	while (true) {
		bool ret = OVERRIDABLE_REF(main_loop)();
		if (!ret) {
			break;
		}
		usleep(50 * 1000);
	}
	return NULL;
}

int
main(int argc, char *argv[])
{
	sem_init(&g_sem, 0, 0);
	printf("hello\n");

	pthread_t pid;
	pthread_create(&pid, NULL, thread_fn, NULL);
	printf("thread created\n");

	sem_wait(&g_sem);

	pthread_join(pid, NULL);
	return 0;
}