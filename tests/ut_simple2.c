/* SPDX-License-Identifier: MIT
 * Copyright(c) 2023 Darek Stojaczyk
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#include "util.h"

static bool __attribute__((noinline)) fn(void)
{
	__asm__ volatile("");
	return true;
}
bool OVERRIDABLE_FN(fn);

void *
thread_fn(void *arg)
{
	printf("calling fn()\n");
	/* wait until fn returns false */
	while (OVERRIDABLE_REF(fn)()) {
		usleep(50 * 1000);
	}

	printf("fn() returned false\n");
	printf("calling fn()\n");

	/* wait until fn returns true again */
	while (!OVERRIDABLE_REF(fn)()) {
		usleep(50 * 1000);
	}

	printf("fn() returned true, at last\n");
	return NULL;
}

int
main(int argc, char *argv[])
{
	printf("hello\n");

	pthread_t pid;
	pthread_create(&pid, NULL, thread_fn, NULL);
	printf("thread created\n");

	pthread_join(pid, NULL);
	return 0;
}