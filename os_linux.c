/* SPDX-License-Identifier: MIT
 * Copyright(c) 2019-2023 Darek Stojaczyk
 */

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dirent.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <ucontext.h>

#include "patchmem.h"
#include "patchmem_internal.h"

STATIC_ASSERT(MEM_PROT_NONE == PROT_NONE);
STATIC_ASSERT(MEM_PROT_READ == PROT_READ);
STATIC_ASSERT(MEM_PROT_WRITE == PROT_WRITE);
STATIC_ASSERT(MEM_PROT_EXEC == PROT_EXEC);

struct mem_region {
	uintptr_t addr;
	size_t size;
	unsigned prot;
};

#define MAX_MEM_PROTS 256
static struct mem_region g_org_mem_prots[MAX_MEM_PROTS];
static unsigned g_org_mem_prots_num;

static struct mem_region *
find_mem_region(uintptr_t addr)
{
	struct mem_region *reg;
	unsigned m, l, r;

	l = 0;
	r = g_org_mem_prots_num;

	while (l <= r) {
		m = l + (r - l) / 2;

		reg = &g_org_mem_prots[m];
		if (addr < reg->addr) {
			r = m - 1;
		} else if (addr >= reg->addr + reg->size) {
			l = m + 1;
		} else {
			return &g_org_mem_prots[m];
		}
	}

	return NULL;
}

static void
get_mem_regions(void)
{
	char buf[4096];
	int i, nread;
	FILE *fp;

	fp = fopen("/proc/self/maps", "r");
	assert(fp != NULL);

	nread = fread(buf, 1, sizeof(buf), fp);
	while (nread > 0) {
		char *line = buf;
		for (i = 0; i < nread; i++) {
			if (buf[i] != '\n') {
				continue;
			}

			char *endptr1 = NULL, *endptr2 = NULL;
			unsigned long start = strtoul(line, &endptr1, 16);
			assert(*endptr1 == '-');
			unsigned long end = strtoul(endptr1 + 1, &endptr2, 16);
			assert(*endptr2 == ' ');
			char *prot_str = endptr2 + 1;  // "rwxp"

			unsigned prot = MEM_PROT_NONE;
			prot |= prot_str[0] == 'r' ? MEM_PROT_READ : 0;
			prot |= prot_str[1] == 'w' ? MEM_PROT_WRITE : 0;
			prot |= prot_str[2] == 'x' ? MEM_PROT_EXEC : 0;

			assert(g_org_mem_prots_num < MAX_MEM_PROTS);
			g_org_mem_prots[g_org_mem_prots_num].addr = start;
			g_org_mem_prots[g_org_mem_prots_num].size = end - start;
			g_org_mem_prots[g_org_mem_prots_num].prot = prot;
			g_org_mem_prots_num++;

			line = &buf[i + 1];
		}

		size_t fread_off = 0;
		if (&buf[nread] > line) {
			/* incomplete line, copy it to the beginning of buf, then
			 * fread() the rest. */
			fread_off = &buf[nread] - line;
			memmove(buf, line, fread_off);
		}
		nread = fread(buf + fread_off, 1, sizeof(buf) - fread_off, fp);
		nread += fread_off;
	}

	fclose(fp);
}

void *
_os_alloc(int size)
{
	void *ret;
	int rc;

	if (size == 0) {
		return NULL;
	}

	size = (size + 0xFFF) & ~0xFFF;
	rc = posix_memalign(&ret, size, 0x1000);
	return rc == 0 ? ret : NULL;
}

void
_os_free(void *mem, int size)
{
	return free(mem);
}

int
_os_protect(void *addr_p, size_t size, unsigned flags, unsigned *prev_flags)
{
	uintptr_t addr = (uintptr_t)addr_p;
	uintptr_t addr_aligned = addr & ~0xFFF;

	size = (addr - addr_aligned + size + 0xFFF) & ~0xFFF;
	if (prev_flags) {
		struct mem_region *reg = find_mem_region(addr);

		if (reg) {
			/* verify the entire range is contained within the same region */
			assert(reg->addr + reg->size >= addr_aligned + size);
			*prev_flags = reg->prot;
		} else {
			/* not a region that was initially mapped, assume simple RW */
			*prev_flags = MEM_PROT_READ | MEM_PROT_READ;
		}
	}
	return mprotect((void *)addr_aligned, size, flags);
}

int
_os_static_init(void)
{
	get_mem_regions();
	return 0;
}

void
_os_static_persist(void)
{
	Dl_info info;
	dladdr(&_os_static_persist, &info);
	const char *so_filename = info.dli_fname;
	void *ret = dlopen(so_filename, RTLD_NOLOAD | RTLD_GLOBAL | RTLD_NODELETE);
	assert(ret != NULL);
}

static pid_t
sys_gettid(void)
{
	return syscall(SYS_gettid);
}

#define MAX_THREADS 128
#define MAX_BACKTRACE_DEPTH 32
static struct thr_ctx {
	/* thread id the signal was sent to */
	pid_t tid;
	/* thread id retrieved inside the signal
	 * (can be different if the thread was just joined) */
	pid_t realtid;
	/* the number of filled backtrace[] entries */
	size_t backtrace_depth;
	/* backtrace */
	void *backtrace[MAX_BACKTRACE_DEPTH];
	/* semaphore the thread is waiting on */
	sem_t resume_sem;
} g_thr_ctx[MAX_THREADS];

static pid_t g_mgmt_tid;
static pid_t g_suspend_tid;
static sem_t g_suspend_sem;

static struct thr_ctx *
thr_ctx_find(pid_t tid)
{
	struct thr_ctx *ctx = NULL;
	size_t i;

	for (i = 0; i < MAX_THREADS; i++) {
		ctx = &g_thr_ctx[i];
		if (ctx->tid == 0) {
			return NULL;
		}

		if (ctx->tid == tid) {
			return ctx;
		}
	}

	return NULL;
}

static void
thread_suspend_control_handler(int n, siginfo_t *siginfo, void *_sigcontext)
{
	ucontext_t *sigcontext = _sigcontext;
	/* thistid can differ from the tid this signal was sent to if there
	 * was the thread was joined inbetween - this must not be a problem */
	pid_t thistid = sys_gettid();
	struct thr_ctx *ctx = thr_ctx_find(g_suspend_tid);

	assert(ctx != NULL);

	/* step 1: setup the the shared memory */
	ctx->realtid = thistid;
	sem_init(&ctx->resume_sem, 0, 0);

	void *trace[16];
	int trace_size = backtrace(trace, sizeof(trace) / sizeof(trace[0]));

	/* eip poits to a syscall function - usually a generic syscall wrapper
	 * anything before that is signal handing that we can easily omit from
	 * the backtrace. */
	void *eip = (void *)sigcontext->uc_mcontext.gregs[REG_EIP];
	size_t final_trace_size = 0;
	bool eip_found = false;
	for (size_t i = 0; i < trace_size; i++) {
		if (!eip_found) {
			if (trace[i] == eip) {
				eip_found = true;
			}
			continue;
		}
		ctx->backtrace[final_trace_size++] = trace[i];
	}
	ctx->backtrace_depth = final_trace_size;

	/* step 2: wake the main thread */
	sem_post(&g_suspend_sem);

	/* step 3: sleep until the main threads kicks us.
	 * This can happen immediately (if the backtrace says it's not safe to
	 * hot-patch) or later when the library is unloaded and loaded again.
	 * If the thread has finished inbetween, the tid can change to its parent
	 * - in that case, if it's the thread that's suspending us, we need not
	 *   to wait or there will be an unnecessary deadlock */
	if (thistid != g_mgmt_tid) {
		while (sem_wait(&ctx->resume_sem) == -1 && errno == EINTR) {
			continue;
		}
	}
}

/** Suspend a thread in a safe-to-hot-unload state */
static void
thread_safe_suspend(struct thr_ctx *ctx)
{
	int rc;
	assert(ctx != NULL);

	struct sigaction act = {};
	struct sigaction oact = {};
	memset(&act, 0, sizeof(act));
	act.sa_sigaction = thread_suspend_control_handler;
	act.sa_flags = SA_RESTART | SA_SIGINFO | SA_ONSTACK;
	sigemptyset(&act.sa_mask);

	sem_init(&g_suspend_sem, 0, 0);
	if (sigaction(SIGURG, &act, &oact)) {
		assert(false);
	}

	while (true) {
		g_suspend_tid = ctx->tid;
		/* call our handler */
		rc = kill(ctx->tid, SIGURG);
		if (rc != 0) {
			/* the thread died */
			break;
		}

		struct timespec ts;
		rc = clock_gettime(CLOCK_REALTIME, &ts);
		assert(rc == 0);
		ts.tv_sec += 3;

		/* wait for the handler to fill the shared memory */
		while ((rc = sem_timedwait(&g_suspend_sem, &ts)) == -1 &&
		       errno == EINTR) {
			continue;
		}

		if (rc == -1) {
			/* the thread died or is deadlocked */
			break;
		}

		bool is_safe = true;
		char **trace_str =
		    backtrace_symbols(ctx->backtrace, ctx->backtrace_depth);
		assert(trace_str != NULL);

		/* unlikely, but make sure we're not in a syscall called directly in
		 * the patched asm */
		if (patch_mem_check_addr_patched((uintptr_t)ctx->backtrace[0])) {
			is_safe = false;
		}

		for (size_t i = 0; i < ctx->backtrace_depth; i++) {
			// trace_str[i] == "/lib/i386-linux-gnu/libc.so.6(+0xbf4ad)
			// [0xf7df04ad]"
			char *end_sep = strrchr(trace_str[i], '(');
			assert(end_sep != NULL);

			char *start_sep = strrchr(trace_str[i], '/');
			assert(start_sep != NULL);
			char filename[64];

			assert(end_sep > start_sep);

			snprintf(filename, sizeof(filename), "%.*s",
				 (int)((uintptr_t)end_sep - (uintptr_t)start_sep) - 1,
				 start_sep + 1);
			// fprintf(stderr, "\tbt[%zu] = %s\n", i, filename);

			if (strcmp(filename, (const char *)patch_mem_get_libhandle()) ==
			    0) {
				is_safe = false;
			}
		}

		free(trace_str);

		if (is_safe) {
			break;
		}

		if (ctx->realtid != g_mgmt_tid) {
			sem_post(&ctx->resume_sem);
		}

		usleep(1000 * 5);
	}
}

void
_os_safely_suspend_all_threads(void)
{
	DIR *proc_dir;
	char dirname[256];
	pid_t thistid = sys_gettid();
	pid_t tid;

	g_mgmt_tid = thistid;

	snprintf(dirname, sizeof(dirname), "/proc/self/task");
	proc_dir = opendir(dirname);

	assert(proc_dir != NULL);
	size_t num_entries = 0;

	struct dirent *entry;
	while ((entry = readdir(proc_dir)) != NULL) {
		if (entry->d_name[0] == '.') {
			continue;
		}

		tid = atoll(entry->d_name);
		fprintf(stderr, "found tid = %d\n", (int)tid);
		if (tid == thistid) {
			continue;
		}

		if (num_entries >= MAX_THREADS) {
			assert(false);
			break;
		}

		struct thr_ctx *ctx = &g_thr_ctx[num_entries];
		assert(ctx->tid == 0);
		ctx->tid = tid;

		thread_safe_suspend(ctx);

		num_entries++;
	}

	closedir(proc_dir);
}