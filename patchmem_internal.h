/* SPDX-License-Identifier: MIT
 * Copyright(c) 2023 Darek Stojaczyk
 */

#ifndef PATCHMEM_INTERNAL_H
#define PATCHMEM_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>
#include <windows.h>
#include <winnt.h>

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
struct stack_area _os_stack_area_get(void);

/**
 * Get stack memory area for the provided Windows thread HANDLE and
 * CONTEXT.
 *
 * \param thread Windows HANDLE casted to void*
 * \param context Windows CONTEXT*, casted to void*
 * \return stack memory area
 */
struct stack_area _os_stack_area_get_by_thr(HANDLE thread, CONTEXT *context);

/**
 * Check if stack area contains given address.
 *
 * \param stack_area stack area
 * \param addr address to check
 */
bool _os_stack_area_contains(struct stack_area *stack_area, uintptr_t addr);

/**
 * Get stack frame from the provided Windows thread HANDLE and CONTEXT.
 * This can be used to get stack_frame of other threads.
 *
 * \param thread Windows HANDLE casted to void*
 * \param context Windows CONTEXT*, casted to void*
 * \param stack_area previously obtained stack area for given thread
 * \return stack frame
 */
struct stack_frame *_os_stack_frame_get_by_thr(HANDLE thread, CONTEXT *context,
					       struct stack_area *stack_area);

/**
 * Get stack frame of the calling function.
 *
 * \return stack frame of the calling function
 */
struct stack_frame *_os_stack_frame_get(void);

/**
 * Get return address from the function inside the given stack frame.
 *
 * \param frame stack frame
 * \return address to jmp to if \c frame unwinds
 */
uintptr_t _os_stack_frame_retaddr(struct stack_frame *frame);

/**
 * Get the next stack frame, deeper in the call stack.
 *
 * \param frame stack frame
 * \param stack_area previously obtained stack area for given thread
 * \return stack frame one level deeper, or NULL if no deeper stack
 * frame could be found.
 */
struct stack_frame *_os_stack_frame_next(struct stack_frame *frame,
					 struct stack_area *stack_area);

/**
 * OS-specific implementation of patch_mem_static_init().
 */
int _os_static_init(void);

/**
 * OS-specific implementation of patch_mem_static_persist().
 */
void _os_static_persist(void);

/**
 * Iterate through all threads, foreach:
 *  1. suspend the thread
 *  2. verify the EIP is not in the patched instruction range
 *  3. get stack trace, verify none of the functions are in the caller's library
 *  4. if any of the above failed, try to resume the thread, Sleep(1ms), go back to 1.
 */
void _os_safely_suspend_all_threads(void);

#ifdef __cplusplus
}
#endif

#endif /* PATCHMEM_INTERNAL_H */
