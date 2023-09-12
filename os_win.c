/* SPDX-License-Identifier: MIT
 * Copyright(c) 2023 Darek Stojaczyk
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <windows.h>
#include <winnt.h>

#include "patchmem.h"
#include "patchmem_internal.h"

/**
 * A piece of x86_32 stack containing current EBP and the address
 * the current call instruction will return to.
 */
struct stack_frame {
	void *ebp;
	void *ret_addr;
};

/**
 * Stack memory area. Used for call stack validation.
 */
struct stack_area {
	uintptr_t end; /**< lower address */
	uintptr_t start; /**< higher address */
};

/** Check if stack area contains given address. */
static bool
stack_area_contains(struct stack_area *stack_area, uintptr_t addr)
{
	return addr > stack_area->end && addr <= stack_area->start;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
/** Get stack frame of the calling function. */
static struct stack_frame *__attribute__((naked)) stack_frame_get(void)
{
	__asm__("lea eax, [esp - 4]; ret");
}

/** Get stack memory area of the calling function. */
static struct stack_area
stack_area_get(void)
{
	NT_TIB *pTIB = (NT_TIB *)NtCurrentTeb();
	return (struct stack_area){ (uintptr_t)pTIB->StackLimit,
				    (uintptr_t)pTIB->StackBase };
}
#pragma GCC diagnostic pop

/** Get stack memory area for the provided Windows thread HANDLE and
 *  CONTEXT. */
static struct stack_area
stack_area_get_by_thr(HANDLE thread, CONTEXT *ctx)
{
	LDT_ENTRY ldt_entry = { 0 };
	BOOL ok;

	ok = GetThreadSelectorEntry(thread, ctx->SegFs, &ldt_entry);
	if (!ok) {
		return (struct stack_area){ 0, 0 };
	}

	NT_TIB *pTIB =
	    (void *)(ldt_entry.BaseLow | (ldt_entry.HighWord.Bytes.BaseMid << 0x10) |
		     (ldt_entry.HighWord.Bytes.BaseHi << 0x18));
	return (struct stack_area){ (uintptr_t)pTIB->StackLimit,
				    (uintptr_t)pTIB->StackBase };
}

static bool
is_valid_stack_frame(struct stack_frame *frame, struct stack_area *stack_area)
{
	MEMORY_BASIC_INFORMATION info;
	SIZE_T ret;

	ret = VirtualQuery(frame->ret_addr, &info, sizeof(info));
	if (ret == 0 || ret < offsetof(MEMORY_BASIC_INFORMATION, Protect)) {
		return false;
	}

	if (info.Protect != PAGE_EXECUTE && info.Protect != PAGE_EXECUTE_READ &&
	    info.Protect != PAGE_EXECUTE_READWRITE &&
	    info.Protect != PAGE_EXECUTE_WRITECOPY) {
		return false;
	}

	/* if EBP currently has a rogue value we may detect it here by checking
	 * against the stack region bounds. There can be a still a pointer to
	 * somewhere inside the stack that is not a stack frame. And if it passes
	 * the further checks, we might return it as a "valid" stack frame, which
	 * can be far off from reality. We could go through the trouble of
	 * checking if the return pointer is preceeded by a CALL instruction,
	 * which should practically give us a 100% confidence in a valid/invalid
	 * stack frame. But (subjectively) this wasn't needed so far. If some of
	 * the program doesn't keep the frame pointer we can't get the complete
	 * call stack anyway.
	 */
	if (!stack_area_contains(stack_area, (uintptr_t)frame->ebp)) {
		return false;
	}

	return true;
}

/** Get the next stack frame, deeper in the call stack. */
static struct stack_frame *
stack_frame_next(struct stack_frame *frame, struct stack_area *stack_area)
{
	struct stack_frame *next = frame->ebp;
	return is_valid_stack_frame(next, stack_area) ? next : NULL;
}

/** Get stack frame from the provided Windows thread HANDLE and CONTEXT. */
static struct stack_frame *
stack_frame_get_by_thr(HANDLE thread, CONTEXT *ctx, struct stack_area *stack_area)
{
	(void)thread;

	if (!stack_area_contains(stack_area, (uintptr_t)ctx->Ebp)) {
		return NULL;
	}

	struct stack_frame *frame = (void *)ctx->Ebp;
	return is_valid_stack_frame(frame, stack_area) ? frame : NULL;
}

#define MEM_PROT_WINSPECIFIC (1UL << 31)
static unsigned
win_flags_to_internal(DWORD flags)
{
	return flags | MEM_PROT_WINSPECIFIC;
}

static DWORD
internal_flags_to_win(unsigned flags)
{
	if (flags & MEM_PROT_WINSPECIFIC) {
		return flags & ~MEM_PROT_WINSPECIFIC;
	}

	switch (flags) {
	case MEM_PROT_READ:
		return PAGE_READONLY;
	case MEM_PROT_READ | MEM_PROT_WRITE:
		return PAGE_READWRITE;
	case MEM_PROT_READ | MEM_PROT_WRITE | MEM_PROT_EXEC:
		return PAGE_EXECUTE_READWRITE;
	case MEM_PROT_READ | MEM_PROT_EXEC:
		return PAGE_EXECUTE_READ;
	case MEM_PROT_NONE:
		return PAGE_NOACCESS;
	}

	assert(false);	// invalid flags combination
	return PAGE_NOACCESS;
}

void *
_os_alloc(int size)
{
	if (size == 0) {
		return NULL;
	}

	size = (size + 0xFFF) & ~0xFFF;
	return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

void
_os_free(void *mem, int size)
{
	VirtualFree(mem, size, MEM_RELEASE);
}

int
_os_protect(void *addr, size_t size, unsigned flags, unsigned *prev_flags)
{
	DWORD prevProt;
	DWORD prot = internal_flags_to_win(flags);
	BOOL ok;

	ok = VirtualProtect(addr, size, prot, &prevProt);
	if (!ok) {
		return -GetLastError();
	}

	if (prev_flags) {
		*prev_flags = win_flags_to_internal(prevProt);
	}

	return 0;
}

int
_os_static_init(void)
{
	/* nothing to do */
	return 0;
}

void
_os_static_persist(void)
{
	HMODULE hm;
	BOOL ok;
	ok = GetModuleHandleEx(
	    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
	    (void *)_os_static_persist, &hm);
	if (!ok) {
		assert(false);
	}
}

static bool
verify_safe_stack_strace(HANDLE thread)
{
	CONTEXT ctx __attribute__((aligned(16))) = { 0 };
	BOOL ok;

	ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;
	ok = GetThreadContext(thread, &ctx);
	if (!ok) {
		fprintf(stderr, "GetThreadContext() failed: %lu\n", GetLastError());
		return false;
	}

	uintptr_t eip = ctx.Eip;
	if (_patch_mem_check_addr_patched(eip)) {
		return false;
	}

	struct stack_area stack_area = stack_area_get_by_thr(thread, &ctx);
	struct stack_frame *frame = stack_frame_get_by_thr(thread, &ctx, &stack_area);
	if (frame == NULL) {
		/* we most likely ended up in a context with -fomit-frame-pointer */
		return false;
	}

	while (frame != NULL) {
		HMODULE hm;

		ok = GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
					   GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
				       frame->ret_addr, &hm);
		if (!ok) {
			assert(false);
		}

		if ((struct patch_mem_lib_handle *)hm == _patch_mem_get_libhandle()) {
			return false;
		}

		frame = stack_frame_next(frame, &stack_area);
	}

	return true;
}

void
_os_safely_suspend_all_threads(void)
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
_os_resume_all_threads(void)
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
			ResumeThread(thread);
			CloseHandle(thread);
		}

		te.dwSize = sizeof(te);
	} while (Thread32Next(h, &te));

	CloseHandle(h);
}