/* SPDX-License-Identifier: MIT
 * Copyright(c) 2019-2023 Darek Stojaczyk
 */

/**
 * Functions needed by multiple os_XXX.c files which are not meant
 * to be a public API. */

#include "patchmem_internal.h"

struct stack_frame *__attribute__((naked)) _os_stack_frame_get(void)
{
	__asm__("lea eax, [esp - 4]; ret");
}

bool
_os_stack_area_contains(struct stack_area *stack_area, uintptr_t addr)
{
	return addr > stack_area->end && addr <= stack_area->start;
}