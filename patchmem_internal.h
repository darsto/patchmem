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
