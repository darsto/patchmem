/* SPDX-License-Identifier: MIT
 * Copyright(c) 2023 Darek Stojaczyk
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <windows.h>
#include <winnt.h>

#include "patchmem_internal.h"

/**
 * A piece of x86_32 stack containing current EBP and the address
 * the current call instruction will return to.
 */
struct stack_frame {
	void *ebp;
	void *ret_addr;
};

struct stack_area
_os_stack_area_get(void)
{
	NT_TIB *pTIB = (NT_TIB *)NtCurrentTeb();
	return (struct stack_area){ (uintptr_t)pTIB->StackLimit,
				    (uintptr_t)pTIB->StackBase };
}

struct stack_area
_os_stack_area_get_by_thr(HANDLE thread, CONTEXT *context)
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

struct stack_frame *__attribute__((naked)) _os_stack_frame_get(void)
{
	__asm__("lea eax, [esp - 4]; ret");
}

static bool
stack_area_contains(struct stack_area *stack_area, uintptr_t addr)
{
	return addr > stack_area->end && addr <= stack_area->start;
}

uintptr_t
_os_stack_frame_retaddr(struct stack_frame *frame)
{
	return (uintptr_t)frame->ret_addr;
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

struct stack_frame *
_os_stack_frame_next(struct stack_frame *frame, struct stack_area *stack_area)
{
	struct stack_frame *next = frame->ebp;
	return is_valid_stack_frame(next, stack_area) ? next : NULL;
}

struct stack_frame *
_os_stack_frame_get_by_thr(HANDLE thread, CONTEXT *ctx, struct stack_area *stack_area)
{
	(void)thread;

	if (!stack_area_contains(stack_area, (uintptr_t)ctx->Ebp)) {
		return NULL;
	}

	struct stack_frame *frame = (void *)ctx->Ebp;
	return is_valid_stack_frame(frame, stack_area) ? frame : NULL;
}