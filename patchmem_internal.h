/* SPDX-License-Identifier: MIT
 * Copyright(c) 2023 Darek Stojaczyk
 */

#ifndef PATCHMEM_INTERNAL_H
#define PATCHMEM_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__clang__)
#define STATIC_ASSERT(cond) _Static_assert(cond, #cond)
#elif defined(_MSC_VER) && _MSC_VER >= 1600
#define STATIC_ASSERT(cond) static_assert(cond, #cond)
#elif __STDC_VERSION__ >= 202311L
#define STATIC_ASSERT(cond) static_assert(cond)
#else /* __STDC_VERSION__ < 202311L */
#define STATIC_ASSERT(cond) _Static_assert(cond, #cond)
#endif /* __STDC_VERSION__ < 202311L */

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
 * Flags to mem_protect(). Map 1:1 to linux mprotect() flags.
 */
enum _os_mprotect_flags {
	MEM_PROT_NONE = 0x00,
	MEM_PROT_READ = 0x01,
	MEM_PROT_WRITE = 0x02,
	MEM_PROT_EXEC = 0x04,
	MEM_PROT_LAST = MEM_PROT_EXEC
};

/**
 * Allocate page-aligned memory.
 * Needs to be freed with _os_free().
 */
void *_os_alloc(int size);

/** Free memory from _os_alloc(). */
void _os_free(void *mem, int size);

/**
 * Set memory protection bits on provided memory region.
 * This will affect all memory pages in the given range.
 * \param ptr start of the memory area
 * \param size size of the memory area
 * \param flags bitwise OR of \c _os_mprotect_flags
 * \param flags pointer to be filled with previous \c _os_mprotect_flags
 * of this memory area (specifically, it's the flags of memory at \c ptr )
 */
int _os_protect(void *addr, size_t size, unsigned flags, unsigned *prev_flags);

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
