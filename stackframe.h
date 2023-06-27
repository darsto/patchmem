/* SPDX-License-Identifier: MIT
 * Copyright(c) 2019-2023 Darek Stojaczyk
 */

#ifndef PATCHMEM_STACKFRAME_H
#define PATCHMEM_STACKFRAME_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A singular frame in the function call stack.
 */
struct stack_frame;

/**
 * Stack memory area. Used for call stack validation.
 */
struct stack_area {
	uintptr_t end; /**< lower address */
	uintptr_t start; /**< higher address */
};

/**
 * Get stack memory area of the calling function.
 *
 * \return stack memory area of the calling function
 */
struct stack_area stack_area_get(void);

/**
 * Get stack memory area for the provided Windows thread HANDLE and
 * CONTEXT.
 *
 * \param thread Windows HANDLE casted to void*
 * \param context Windows CONTEXT*, casted to void*
 * \return stack memory area
 */
struct stack_area stack_area_get_by_thr(void *thread, void *context);

/**
 * Get stack frame from the provided Windows thread HANDLE and CONTEXT.
 * This can be used to get stack_frame of other threads.
 *
 * \param thread Windows HANDLE casted to void*
 * \param context Windows CONTEXT*, casted to void*
 * \param stack_area previously obtained stack area for given thread
 * \return stack frame
 */
struct stack_frame *stack_frame_get_by_thr(void *thread, void *context,
					   struct stack_area *stack_area);

/**
 * Get stack frame of the calling function.
 *
 * \return stack frame of the calling function
 */
struct stack_frame *stack_frame_get(void);

/**
 * Get return address from the function inside the given stack frame.
 *
 * \param frame stack frame
 * \return address to jmp to if \c frame unwinds
 */
uintptr_t stack_frame_retaddr(struct stack_frame *frame);

/**
 * Get the next stack frame, deeper in the call stack.
 *
 * \param frame stack frame
 * \param stack_area previously obtained stack area for given thread
 * \return stack frame one level deeper, or NULL if no deeper stack
 * frame could be found.
 */
struct stack_frame *stack_frame_next(struct stack_frame *frame,
				     struct stack_area *stack_area);

#ifdef __cplusplus
}
#endif

#endif /* PATCHMEM_STACKFRAME_H */