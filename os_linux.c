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

#define MAX_THREADS 64
#define MAX_BACKTRACE_DEPTH 32
struct thr_ctx {
	/* thread id the signal was sent to */
	pid_t tid;
	/* the number of filled backtrace[] entries */
	size_t backtrace_depth;
	/* backtrace */
	void *backtrace[MAX_BACKTRACE_DEPTH];
	/* semaphore the thread is waiting on */
	sem_t resume_sem;
	/* anything after resume_sem is kept after patchmem deinit */
};

static struct persistent_ctx {
	/* Array of per-thread contexts */
	struct thr_ctx *threads_ctx;

	/* Preallocated, persistent code thunk for synchronizing pthreads */
	void *thread_suspend_thunk;
} * g_persistent;

void thread_resume_thunk();
void thread_resume_thunk_end();

int
_os_static_init(void)
{
	const char *ctxstr = getenv("_PATCHMEM_INTERNAL_CTX");
	if (ctxstr == NULL) {
		g_persistent = calloc(1, sizeof(*g_persistent));
		assert(g_persistent != NULL);

		g_persistent->threads_ctx =
		    calloc(1, sizeof(*g_persistent->threads_ctx) * MAX_THREADS);
		assert(g_persistent->threads_ctx != NULL);

		for (size_t i = 0; i < MAX_THREADS; i++) {
			/* We don't want to ever reinitialize it, so initialize it here,
			 * now */
			sem_init(&g_persistent->threads_ctx[i].resume_sem, 0, 0);
		}

		size_t thread_resume_thunk_size = (size_t)(
		    (uintptr_t)thread_resume_thunk_end - (uintptr_t)thread_resume_thunk);
		void *thunk_p = _os_alloc(thread_resume_thunk_size);
		assert(thunk_p != NULL);
		memcpy(thunk_p, thread_resume_thunk, thread_resume_thunk_size);
		_os_protect(thunk_p, thread_resume_thunk_size,
			    MEM_PROT_READ | MEM_PROT_EXEC, NULL);

		g_persistent->thread_suspend_thunk = thunk_p;

		char tmp[32];
		snprintf(tmp, sizeof(tmp), "0x%llx", (long long)(uintptr_t)g_persistent);
		setenv("_PATCHMEM_INTERNAL_CTX", tmp, 1);
	} else {
		char *endptr;
		g_persistent = (void *)(uintptr_t)strtoll(ctxstr, &endptr, 16);
		assert(g_persistent != NULL);
	}

	get_mem_regions();
	return 0;
}

void
_os_static_persist(void)
{
	Dl_info info;
	dladdr(&_os_static_persist, &info);
	const char *so_filename = info.dli_fname;
	void *ret = dlopen(so_filename, RTLD_NOW | RTLD_NOLOAD);
	assert(ret != NULL);
}

static pid_t
sys_gettid(void)
{
	return syscall(SYS_gettid);
}

static struct thr_ctx *
thr_ctx_find(pid_t tid)
{
	struct thr_ctx *ctx = NULL;
	size_t i;

	for (i = 0; i < MAX_THREADS; i++) {
		ctx = &g_persistent->threads_ctx[i];
		if (ctx->tid == 0) {
			return NULL;
		}

		if (ctx->tid == tid) {
			return ctx;
		}
	}

	return NULL;
}

static pid_t g_suspend_tid;
static sem_t g_suspend_sem;

static void
thread_suspend_control_handler(int n, siginfo_t *siginfo, void *_sigcontext)
{
	ucontext_t *sigcontext = _sigcontext;
	/* this thread's tid can differ from the tid this signal was sent to if
	 * the thread was joined inbetween - this must not be a problem */
	struct thr_ctx *ctx = thr_ctx_find(g_suspend_tid);
	assert(ctx != NULL);

	/* Get the backtrace. This includes the signal handler and anything
	 * below it. */
	void *trace[MAX_BACKTRACE_DEPTH + 1];
	int trace_size = backtrace(trace, sizeof(trace) / sizeof(trace[0]));

	/* we'll skip all stack frames from the signal handling
	 * (there's more than one!) */
	void **eip = (void **)&sigcontext->uc_mcontext.gregs[REG_EIP];
	bool eip_found = false;
	size_t backtrace_depth = 0;

	for (size_t i = 1; i < trace_size; i++) {
		if (!eip_found) {
			if (trace[i] == *eip) {
				eip_found = true;
			} else {
				continue;
			}
		}
		ctx->backtrace[backtrace_depth++] = trace[i];
	}
	ctx->backtrace_depth = backtrace_depth;

	/* Notify the main thread.
	 * Since this can potentially do a context switch and even stall this
	 * function execution until the library is unloaded, we have to do the
	 * notification straight from library-persistent asm code */
	void **esp = (void **)&sigcontext->uc_mcontext.gregs[REG_ESP];

#define PUSH_STACK(val) \
	*esp -= 4;      \
	*(void **)(*esp) = (val);

	/* push the original eip to jump back to (ret) */
	PUSH_STACK(*eip);
	/* push some context for the asm code to work with */
	PUSH_STACK(__errno_location);
	PUSH_STACK(sem_wait);
	PUSH_STACK(&ctx->resume_sem);
	PUSH_STACK(sem_post);
	PUSH_STACK(&g_suspend_sem);

	void *neweip = g_persistent->thread_suspend_thunk;
	*eip = neweip;
}

/* Once we send a signal and suspend given threads we need to hold them
 * suspended - potentially until after we hot-reload the library. This is
 * not really possible inside a signal handler, so patch the thread to
 * resume execution at the following chunk of code instead (before jumping
 * back to whatever it was executing).
 *
 * We need to preserve all registers, and also we need to copy this chunk
 * of code into a buffer that will persist after the library is unloaded,
 * so the code needs to be position independent.
 *
 * The following is expected on the stack:
 *   [esp + 16] __errno_location;
 *   [esp + 12] sem_wait;
 *   [esp +  8] &ctx->resume_sem;
 *   [esp +  4] sem_post;
 *   [esp +  0] &g_suspend_sem;
 */
__asm__(
    "thread_resume_thunk:\n"
    "  pushad\n" /* backup the registers first */
    "  lea esi, [esp + 32]\n" /* beginning of our stack data in esi */
    "  push [esi]\n" /* push &g_suspend_sem */
    "  call [esi + 4]\n" /* sem_post() -> wake the main thread */
    /* - the patchmem library may be already unloaded at this point - */
    "  add esp, 4\n"
    /* sleep until the main threads kicks us.
     * This can happen immediately (if the backtrace says it's not safe to
     * hot-patch) or later when the library is unloaded and loaded again. */
    "  push [esi + 8]\n" /* push &ctx->resume_sem */
    ".wait:\n"
    "  call [esi + 12]\n" /* sem_wait() */
    "  cmp eax, 0\n"
    "  jz .done\n"
    "  call [esi + 16]\n" /* __errno_location() */
    "  mov eax, [eax]\n"
    "  cmp eax, 4\n" /* EINTR */
    "  jz .wait\n"
    ".done:\n"
    "  add esp, 4\n"
    "  popad\n"
    "  add esp, 20\n"
    "  ret\n"
    "thread_resume_thunk_end:");

static void thread_safe_resume(struct thr_ctx *ctx);

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

		/* unlikely, but make sure we're not directly in the patched asm */
		if (patch_mem_check_addr_patched((uintptr_t)ctx->backtrace[0])) {
			is_safe = false;
		}

		for (size_t i = 0; i < ctx->backtrace_depth; i++) {
			// trace_str[i] == "/lib/i386-linux-gnu/libc.so.6(+0xbf4ad)
			// [0xf7df04ad]"
			const char *end_sep = strrchr(trace_str[i], '(');
			if (end_sep == NULL) {
				// trace_str[i] == "[0x57062000]"
				// - dynamically allocated memory, we can't find its owner
				// so assume this is not safe
				is_safe = false;
				break;
			}

			const char *start = strrchr(trace_str[i], '/');
			if (start == NULL) {
				// trace_str[i] ==
				// "linux-gate.so.1(__kernel_rt_sigreturn+0) [0xf7fd0580]"
				start = trace_str[i];
			} else {
				start += 1;
			}
			assert(end_sep >= start);

			char filename[64];
			snprintf(filename, sizeof(filename), "%.*s",
				 (uintptr_t)end_sep - (uintptr_t)start, start);
			if (strcmp(filename, (const char *)patch_mem_get_libhandle()) ==
			    0) {
				is_safe = false;
				break;
			}
		}

		free(trace_str);
		if (is_safe) {
			break;
		}

		thread_safe_resume(ctx);
		usleep(1000 * 5);
	}

	sem_destroy(&g_suspend_sem);
}

static void
thread_safe_resume(struct thr_ctx *ctx)
{
	sem_post(&ctx->resume_sem);
}

void
_os_safely_suspend_all_threads(void)
{
	DIR *proc_dir;
	char dirname[256];
	pid_t thistid = sys_gettid();
	pid_t tid;

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
		if (tid == thistid) {
			continue;
		}

		if (num_entries >= MAX_THREADS) {
			assert(false);
			break;
		}

		struct thr_ctx *ctx = &g_persistent->threads_ctx[num_entries];
		assert(ctx->tid == 0);
		ctx->tid = tid;

		num_entries++;
	}

	closedir(proc_dir);

	struct thr_ctx *ctx = g_persistent->threads_ctx;
	while (ctx->tid > 0) {
		thread_safe_suspend(ctx);
		ctx++;
	}
}

void
_os_resume_all_threads(void)
{
	struct thr_ctx *ctx = g_persistent->threads_ctx;

	while (ctx->tid > 0) {
		thread_safe_resume(ctx);
		memset(ctx, 0, offsetof(struct thr_ctx, resume_sem));
		ctx++;
	}
}