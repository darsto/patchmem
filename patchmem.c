/* SPDX-License-Identifier: MIT
 * Copyright(c) 2019-2023 Darek Stojaczyk
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <windows.h>

/* tlhelp32.h is broken, must come after windows.h */
#include <tlhelp32.h>

#include <keystone/keystone.h>

#define DLLEXPORT
#include "patchmem.h"
#include "patchmem_internal.h"

enum patch_mem_type {
	PATCH_MEM_T_RAW,
	PATCH_MEM_T_TRAMPOLINE,
	PATCH_MEM_T_TRAMPOLINE_FN
};

struct patch_mem_t {
	enum patch_mem_type type;
	uintptr_t addr;
	int replaced_bytes;
	union {
		struct {
			char *asm_code;
		} raw;
		struct {
			size_t len;
		} trampoline;
		struct {
			void **fn_ptr;
			void *fn;
		} trampoline_fn;
	} u;
	void *org_bytes;
	struct patch_mem_t *next;
};

static struct {
	int init_count;
	HMODULE usermodule;
	bool persist;
	struct patch_mem_t *patches;
	ks_engine *ks_engine;
	unsigned char *ks_buf;
	struct patch_mem_lib_handle *libhandle;
} g_patchmem;

static int
assemble_x86(uint32_t addr, const char *in, unsigned char **out)
{
	ks_free(g_patchmem.ks_buf);
	g_patchmem.ks_buf = NULL;
	size_t size, icount;
	ks_err rc;

	rc = ks_asm(g_patchmem.ks_engine, in, addr, &g_patchmem.ks_buf, &size, &icount);
	if (rc != KS_ERR_OK) {
		return -ks_errno(g_patchmem.ks_engine);
	}

	*out = g_patchmem.ks_buf;
	return size;
}

void
copy_mem_rawbytes(uintptr_t addr, char *buf, unsigned num_bytes)
{
	DWORD prevProt;

	VirtualProtect((void *)addr, num_bytes, PAGE_EXECUTE_READWRITE, &prevProt);
	memcpy(buf, (void *)addr, num_bytes);
	VirtualProtect((void *)addr, num_bytes, prevProt, &prevProt);
}

void
patch_mem_rawbytes(uintptr_t addr, const char *buf, unsigned num_bytes)
{
	DWORD prevProt;

	VirtualProtect((void *)addr, num_bytes, PAGE_EXECUTE_READWRITE, &prevProt);
	memcpy((void *)addr, buf, num_bytes);
	VirtualProtect((void *)addr, num_bytes, prevProt, &prevProt);
}

static void
u32_to_str(char *buf, uint32_t u32)
{
	union {
		char c[4];
		uint32_t u;
	} u;

	u.u = u32;
	buf[0] = u.c[0];
	buf[1] = u.c[1];
	buf[2] = u.c[2];
	buf[3] = u.c[3];
}

static uint32_t
str_to_u32(char *buf)
{
	union {
		char c[4];
		uint32_t u;
	} u;

	u.c[0] = buf[0];
	u.c[1] = buf[1];
	u.c[2] = buf[2];
	u.c[3] = buf[3];
	return u.u;
}

/* vasprintf is not available in mingw */
static int
vasprintf(char **s, const char *fmt, va_list args)
{
	va_list args2;
	int rc;

	va_copy(args2, args); /* this is always optimized out */
	rc = vsnprintf(0, 0, fmt, args2);
	va_end(args2);

	if (rc < 0) {
		return -1;
	}

	*s = malloc(rc + 1);
	if (*s == NULL) {
		return -1;
	}

	return vsnprintf(*s, rc + 1, fmt, args);
}

static int
assemble_trampoline(uintptr_t addr, int replaced_bytes, char *asm_buf,
		    unsigned char **out)
{
	unsigned char *code, *c;
	unsigned char *tmpcode;
	int len;
	DWORD prevprot;

	assert(replaced_bytes >= 5);
	code = c = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (code == NULL) {
		fprintf(stderr, "malloc failed\n");
		return -ENOMEM;
	}

	char *call_org_str = "call org";
	char *asm_org = strstr(asm_buf, call_org_str);
	if (asm_org != NULL && (*(asm_org + strlen(call_org_str)) == ';' ||
				*(asm_org + strlen(call_org_str)) == 0)) {
		/* First assemble everything before the org, then copy org, and finally
		 * assemble the rest  */
		asm_org[0] = 0;
		len = assemble_x86((uintptr_t)c, asm_buf, &tmpcode);
		if (len < 0) {
			VirtualFree(code, 0x1000, MEM_RELEASE);
			return len;
		}

		if (len > 0) {
			assert(len <= 0x1000 - (c - code));
			memcpy(c, tmpcode, len);
			c += len;
		}

		assert(replaced_bytes <= 0x1000 - (c - code));
		memcpy(c, (void *)addr, replaced_bytes); /* replaced instructions */
		c += replaced_bytes;

		asm_buf = asm_org + strlen(call_org_str);
	}

	len = assemble_x86((uintptr_t)c, asm_buf, &tmpcode);
	if (len < 0) {
		VirtualFree(code, 0x1000, MEM_RELEASE);
		return len;
	}

	assert(len <= 0x1000 - (c - code));
	memcpy(c, tmpcode, len);
	c += len;

	assert(5 <= 0x1000 - (c - code));
	*c++ = 0xe9; /* jmp */
	u32_to_str((char *)c, /* jump back rel addr */
		   addr + replaced_bytes - ((uintptr_t)c - 1) - 5);
	c += 4;

	VirtualProtect(code, 0x1000, PAGE_EXECUTE_READ, &prevprot);
	*out = code;
	return c - code;
}

void
_trampoline_fn_static_add(void **orig_fn, int replaced_bytes, void *fn)
{
	struct patch_mem_t *t;

	assert(replaced_bytes >= 5);
	t = calloc(1, sizeof(*t));
	if (!t) {
		fprintf(stderr, "malloc failed\n");
		assert(false);
		return;
	}

	t->type = PATCH_MEM_T_TRAMPOLINE_FN;
	t->addr = (uintptr_t)*orig_fn;
	t->replaced_bytes = replaced_bytes;
	t->u.trampoline_fn.fn_ptr = orig_fn;
	t->u.trampoline_fn.fn = fn;

	t->next = g_patchmem.patches;
	g_patchmem.patches = t;
}

void
_trampoline_static_add(uintptr_t addr, int replaced_bytes, const char *asm_fmt, ...)
{
	struct patch_mem_t *t;
	va_list args;
	char *c;
	int rc;

	assert(replaced_bytes >= 5);
	t = calloc(1, sizeof(*t));
	if (!t) {
		fprintf(stderr, "malloc failed\n");
		assert(false);
		return;
	}

	t->type = PATCH_MEM_T_TRAMPOLINE;
	t->addr = addr;
	t->replaced_bytes = replaced_bytes;

	va_start(args, asm_fmt);
	rc = vasprintf(&t->u.raw.asm_code, asm_fmt, args);
	va_end(args);

	if (rc < 0) {
		fprintf(stderr, "vasprintf failed\n");
		assert(false);
		return;
	}

	c = t->u.raw.asm_code;
	while (*c) {
		if (*c == '\t') {
			*c = ' ';
		}
		c++;
	}

	t->next = g_patchmem.patches;
	g_patchmem.patches = t;
}

void
_patch_mem_static_add(uintptr_t addr, int replaced_bytes, const char *asm_fmt, ...)
{
	struct patch_mem_t *t;
	va_list args;
	char *c;
	int rc;

	t = calloc(1, sizeof(*t));
	if (!t) {
		fprintf(stderr, "malloc failed\n");
		assert(false);
		return;
	}

	t->type = PATCH_MEM_T_RAW;
	t->addr = addr;
	t->replaced_bytes = replaced_bytes;

	va_start(args, asm_fmt);
	rc = vasprintf(&t->u.raw.asm_code, asm_fmt, args);
	va_end(args);

	if (rc < 0) {
		fprintf(stderr, "vasprintf failed\n");
		assert(false);
		return;
	}

	c = t->u.raw.asm_code;
	while (*c) {
		if (*c == '\t') {
			*c = ' ';
		}
		c++;
	}

	t->next = g_patchmem.patches;
	g_patchmem.patches = t;
}

void
_patch_jmp32_static_add(uintptr_t addr, void *fn)
{
	unsigned char op;
	char tmp[16];

	copy_mem_rawbytes(addr, (char *)&op, 1);
	if (op == 0xe8) {
		_snprintf(tmp, sizeof(tmp), "call 0x%x", (uintptr_t)fn);
	} else {
		_snprintf(tmp, sizeof(tmp), "jmp 0x%x", (uintptr_t)fn);
	}

	_patch_mem_static_add(addr, 5, tmp);
}

void
_patch_ptr_static_add(uintptr_t addr, void **org_ptr, void *new)
{
	char tmp[32];

	*org_ptr = *(void **)addr; /* mem should be readable */
	_snprintf(tmp, sizeof(tmp), ".long 0x%x", (uintptr_t) new);

	_patch_mem_static_add(addr, 4, tmp);
}

static void
_process_static_patch_mem(struct patch_mem_t *p)
{
	char tmp[512];
	unsigned char *code = NULL;
	int len = 0;

	/* backup original code first */
	p->org_bytes = malloc(p->replaced_bytes);
	if (p->org_bytes == NULL) {
		fprintf(stderr, "malloc failed\n");
		assert(false);
		return;
	}
	copy_mem_rawbytes(p->addr, p->org_bytes, p->replaced_bytes);

	switch (p->type) {
	case PATCH_MEM_T_RAW: {
		len = assemble_x86(p->addr, p->u.raw.asm_code, &code);
		if (len < 0) {
			fprintf(stderr,
				"patching %d bytes at 0x%x: can't assemble, invalid "
				"instruction\n",
				len, p->addr);
			assert(false);
			return;
		}

		if (len > p->replaced_bytes) {
			fprintf(stderr,
				"patching %d bytes at 0x%x: assembled code takes %d "
				"bytes and "
				"doesn't fit (max %d)\n",
				len, p->addr, len, p->replaced_bytes);
			assert(false);
			return;
		}

		/* prepare patched instructions in a temporary buffer */
		assert(len <= sizeof(tmp));
		memcpy(tmp, code, len);
		break;
	}
	case PATCH_MEM_T_TRAMPOLINE: {
		p->u.trampoline.len = assemble_trampoline(p->addr, p->replaced_bytes,
							  p->u.raw.asm_code, &code);

		/* jump to new code */
		tmp[0] = 0xe9;
		u32_to_str(tmp + 1, (uintptr_t)code - p->addr - 5);
		len = 5;
		break;
	}
	case PATCH_MEM_T_TRAMPOLINE_FN: {
		char orig_code[32];
		char *orig;
		DWORD oldprot;

		assert(p->replaced_bytes <= sizeof(orig_code));
		memcpy(orig_code, p->u.trampoline_fn.fn, p->replaced_bytes);

		orig = VirtualAlloc(NULL, (p->replaced_bytes + 5 + 0xFFF) & ~0xFFF,
				    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (orig == NULL) {
			fprintf(stderr, "malloc failed\n");
			return;
		}

		/* copy original code to a buffer */
		memcpy(orig, (void *)p->addr, p->replaced_bytes);
		/* follow it by a jump to the rest of original code */
		orig[p->replaced_bytes] = 0xe9;
		u32_to_str(orig + p->replaced_bytes + 1,
			   (uint32_t)(uintptr_t)p->addr + p->replaced_bytes -
			       (uintptr_t)orig - p->replaced_bytes - 5);

		VirtualProtect(orig, p->replaced_bytes + 5, PAGE_EXECUTE_READ, &oldprot);

		/* make the original fn jump to new code */
		tmp[0] = 0xe9;
		u32_to_str(tmp + 1,
			   (uint32_t)(uintptr_t)p->u.trampoline_fn.fn - p->addr - 5);
		len = 5;

		/* update the original pointer to the new function (that acts the same as
		 * original) */
		*p->u.trampoline_fn.fn_ptr = orig;
		break;
	}
	}

	/* fill the rest of temporary buffer with NOPs */
	if (len < p->replaced_bytes) {
		memset(tmp + len, 0x90, p->replaced_bytes - len);
	}

	/* TODO if EIP of any thread is within the patched range,
	 * try to handle it */

	/* finally patch the real code */
	patch_mem_rawbytes(p->addr, tmp, p->replaced_bytes);
}

static int
init_once(void)
{
	ks_err err;

	err = ks_open(KS_ARCH_X86, KS_MODE_32, &g_patchmem.ks_engine);
	if (err != KS_ERR_OK) {
		fprintf(stderr, "Failed to init ks engine\n");
		return -ks_errno(g_patchmem.ks_engine);
	}

	return 0;
}

static int
init_again(void)
{
	return 0;
}

int
patch_mem_static_init(struct patch_mem_lib_handle *libhandle)
{
	struct patch_mem_t *p;
	int rc;

	assert(g_patchmem.libhandle == NULL || g_patchmem.libhandle == libhandle);
	g_patchmem.libhandle = libhandle;

	if (g_patchmem.init_count == 0) {
		rc = init_once();
	} else {
		rc = init_again();
	}

	if (rc < 0) {
		return rc;
	}

	p = g_patchmem.patches;
	while (p) {
		_process_static_patch_mem(p);
		p = p->next;
	}

	return g_patchmem.init_count++;
}

void
patch_mem_static_persist(void)
{
	HMODULE hm;
	BOOL ok;

	if (g_patchmem.persist) {
		/* nothing more to do */
		return;
	}

	ok = GetModuleHandleEx(
	    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
	    (void *)patch_mem_static_persist, &hm);
	if (!ok) {
		assert(false);
	}

	g_patchmem.persist = true;
}

static void
_unprocess_static_patch_mem_free(struct patch_mem_t *p)
{
	char tmp[512];

	switch (p->type) {
	case PATCH_MEM_T_RAW: {
		free(p->u.raw.asm_code);
		break;
	}
	case PATCH_MEM_T_TRAMPOLINE: {
		/* retrieve the pointer that is jmp-ed to */
		copy_mem_rawbytes(p->addr + 1, tmp, 4); /* skip the 0xe9 byte */
		uint32_t addr = str_to_u32(tmp) + p->addr + 5;

		VirtualFree((void *)(uintptr_t)addr, 0x1000, MEM_RELEASE);
		break;
	}
	case PATCH_MEM_T_TRAMPOLINE_FN: {
		/* retrieve the pointer that is jmp-ed to */
		copy_mem_rawbytes(p->addr + 1, tmp, 4); /* skip the 0xe9 byte */
		uint32_t addr = str_to_u32(tmp) + p->addr + 5;

		VirtualFree((void *)(uintptr_t)addr, 0x1000, MEM_RELEASE);
		/* restore the original fn pointer */
		*p->u.trampoline_fn.fn_ptr = (void *)p->addr;
		break;
	}
	}

	/* patch the real code */
	assert(p->org_bytes != NULL);
	patch_mem_rawbytes(p->addr, p->org_bytes, p->replaced_bytes);
	free(p->org_bytes);

	free(p);
}

static bool
verify_safe_stack_strace(HANDLE thread)
{
	struct patch_mem_t *p;
	CONTEXT ctx __attribute__((aligned(16))) = { 0 };
	BOOL ok;

	ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;
	ok = GetThreadContext(thread, &ctx);
	if (!ok) {
		fprintf(stderr, "GetThreadContext() failed: %lu\n", GetLastError());
		return false;
	}

	uintptr_t eip = ctx.Eip;
	p = g_patchmem.patches;
	while (p) {
		if (eip >= p->addr && eip < p->addr + p->replaced_bytes) {
			fprintf(stderr, "eip=0x%x in use by p->addr=0x%x nbytes=%d\n",
				eip, p->addr, p->replaced_bytes);
			return false;
		}
		p = p->next;
	}

	struct stack_area stack_area = _os_stack_area_get_by_thr(thread, &ctx);
	struct stack_frame *frame = _os_stack_frame_get_by_thr(thread, &ctx, &stack_area);
	if (frame == NULL) {
		/* we most likely ended up in a context with -fomit-frame-pointer */
		return false;
	}

	while (frame != NULL) {
		HMODULE hm;

		ok = GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
					   GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
				       (void *)_os_stack_frame_retaddr(frame), &hm);
		if (!ok) {
			assert(false);
		}

		if ((struct patch_mem_lib_handle *)hm == g_patchmem.libhandle) {
			return false;
		}

		frame = _os_stack_frame_next(frame, &stack_area);
	}

	return true;
}

/**
 * Iterate through all threads, foreach:
 *  1. suspend the thread
 *  2. verify the EIP is not in the patched instruction range
 *  3. get stack trace, verify none of the functions are in the caller's library
 *  4. if any of the above failed, try to resume the thread, Sleep(1ms), go back to 1.
 */
static void
safely_suspend_all_threads(void)
{
	DWORD thisproc_id = GetCurrentProcessId();
	DWORD thisthrd_id = GetCurrentThreadId();
	HANDLE h;
	THREADENTRY32 te;

	h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h == INVALID_HANDLE_VALUE) {
		return;
	}

	te.dwSize = sizeof(te);
	if (!Thread32First(h, &te)) {
		CloseHandle(h);
		return;
	}

	do {
		if (te.dwSize < FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
				    sizeof(te.th32OwnerProcessID)) {
			continue;
		}

		if (te.th32OwnerProcessID != thisproc_id ||
		    te.th32ThreadID == thisthrd_id) {
			continue;
		}

		HANDLE thread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
		if (thread != NULL) {
			size_t i = 1, max_attempts = 30;
			while (i < max_attempts) {
				DWORD rc = SuspendThread(thread);
				/* the thread may be executing some un-suspendable
				 * critical section */
				if (rc != -1) {
					if (verify_safe_stack_strace(thread)) {
						break;
					}

					ResumeThread(thread);
				}

				Sleep(i);
				i++;
			}

			CloseHandle(thread);

			if (i == max_attempts) {
				assert(false);
				return;
			}
		}

		te.dwSize = sizeof(te);
	} while (Thread32Next(h, &te));

	CloseHandle(h);
}

void
patch_mem_static_deinit(struct patch_mem_lib_handle *libhandle)
{
	struct patch_mem_t *p_next, *p;

	assert(libhandle == g_patchmem.libhandle);
	assert(g_patchmem.init_count > 0);
	g_patchmem.init_count--;

	safely_suspend_all_threads();

	p = g_patchmem.patches;
	while (p) {
		p_next = p->next;
		_unprocess_static_patch_mem_free(p);
		p = p_next;
	}
	g_patchmem.patches = NULL;

	if (g_patchmem.init_count == 0 || g_patchmem.persist) {
		return;
	}

	if (g_patchmem.ks_buf != NULL) {
		ks_free(g_patchmem.ks_buf);
	}

	ks_close(g_patchmem.ks_engine);
}