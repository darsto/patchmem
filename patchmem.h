/* SPDX-License-Identifier: MIT
 * Copyright(c) 2019-2023 Darek Stojaczyk
 */

#ifndef PATCHMEM_H
#define PATCHMEM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#ifdef DLLEXPORT
#define APICALL __attribute__((dllexport))
#else /* DLLEXPORT */
#define APICALL __attribute__((dllimport))
#endif /* DLLEXPORT */
#else /* _WIN32 */
#define APICALL
#endif /* _WIN32 */

/**
 * On Windows:
 *   Generic typedef for Windows' HMODULE.
 *   HMODULE mod = (struct patchmem_lib_handle *)lib_handle;
 *
 * On Linux:
 *   Basename of the shared library / executable.
 *   const char *filename = (struct patchmem_lib_handle *)lib_handle;
 *   It has to outlive the patchmem library.
 */
struct patch_mem_lib_handle;

enum patch_mem_deinit_strategy {
	/* Deinit patchmem library and leave all threads suspended
	 * (until the library is initialized again - hotpatching) */
	PATCH_MEM_DEINIT_SUSPEND_ALL,
	/* Deinit patchmem library and leave all threads running normally */
	PATCH_MEM_DEINIT_RESUME_ALL,
};

/**
 * Copy `num_bytes` from given address into `buf`.
 * Memory read protection to affected pages will be temporarily turned off.
 */
APICALL void copy_mem_rawbytes(uintptr_t addr, char *buf, size_t num_bytes);

/**
 * Write `num_bytes` from `buf` under a given address.
 * Memory write protection to affected pages will be temporarily turned off.
 */
APICALL void patch_mem_rawbytes(uintptr_t addr, const char *buf, size_t num_bytes);

/**
 * Build ASM string with printf-like syntax, them assemble and write it under `addr_p`.
 * Up to `replaced_bytes_p` asesmbled bytes will be written. If `replaced_bytes_p` was
 * too small to fit all bytes, the function will abort. If `replaced_bytes_p` was more
 * than the number of bytes, the remainder will be filled with NOP instructions.
 * Memory write protection to affected pages will be temporarily turned off.
 *
 * \param addr_p address to patch
 * \param replaced_bytes_p maximum number of bytes to patch with assembled code.
 * If the assembled code takes less bytes, this will be filled with NOP instructions.
 * \param asm_fmt_p printf-like string containing ASM instructions
 */
#define PATCH_MEM(addr_p, replaced_bytes_p, asm_fmt_p, ...)                \
	static void __attribute__((constructor(110)))                      \
	    _PATCH_JOIN(init_patch_, __LINE__)(void)                       \
	{                                                                  \
		_patch_mem_static_add(addr_p, replaced_bytes_p, asm_fmt_p, \
				      ##__VA_ARGS__);                      \
	}

/**
 * Change target address of relative JMP or CALL instruction under given
 * address to `fn_p`. If `addr_p` doesn't point to a relative JMP or CALL instruction,
 * this will abort. Memory write protection to affected pages will be temporarily
 * turned off.
 *
 * \param addr_p address to patch, must be the beginning of the JMP/CALL instruction
 * \param fn_p the new pointer to jump to
 */
#define PATCH_JMP32(addr_p, fn_p)                              \
	static void __attribute__((constructor(110)))          \
	    _PATCH_JOIN(init_patch_, __LINE__)(void)           \
	{                                                      \
		_patch_jmp32_static_add(addr_p, (void *)fn_p); \
	}

/**
 * Set an absolute 4-byte address under `addr_p` to `new_p`. The original 4-byte
 * address is saved to `*org_ptr_p`. The memory under `addr_p` must be readable.
 *
 * \param addr_p address to patch
 * \param org_ptr_p variable to write `*(void **)addr_p` to
 * \param new_p the new pointer to write
 */
#define PATCH_PTR(addr_p, org_ptr_p, new_p)                               \
	static void __attribute__((constructor(110)))                     \
	    _PATCH_JOIN(init_patch_, __LINE__)(void)                      \
	{                                                                 \
		_patch_ptr_static_add(addr_p, (void **)org_ptr_p, new_p); \
	}

/**
 * This is a PATCH_MEM() function, with the only difference being the code is
 * not overwritten in place, but instead it's patched to make a JMP to a new code
 * region containing the assembled instructions. This means we can insert arbitrary
 * amount of new code anywhere in the middle of existing code.
 *
 * Exactly `replaced_bytes_p` will be overwritten at `addr_p`. `replaced_bytes_p`
 * must be at least 5. If it's more, the remaining bytes will be filled with NOP
 * instructions.
 *
 * A speciall "call org;" ASM instruction can be used to execute the original
 * replaced code - exactly `replaced_bytes_p` of them.
 *
 * \param addr_p address to patch with a JMP
 * \param replaced_bytes_p number of bytes to patch, must be at least 5.
 * May be more than 5, then the remainder is filled with NOP instructions.
 * \param asm_fmt_p printf-like string containing ASM instructions
 */
#define TRAMPOLINE(addr_p, replaced_bytes_p, asm_fmt_p, ...)                \
	static void __attribute__((constructor(110)))                       \
	    _PATCH_JOIN(init_patch_, __LINE__)(void)                        \
	{                                                                   \
		_trampoline_static_add(addr_p, replaced_bytes_p, asm_fmt_p, \
				       ##__VA_ARGS__);                      \
	}

/**
 * Patch given address `*fn_ptr_p` - supposedly a function entry point - to
 * jump to given address `fn`. The original contents under `*fn_ptr_p` are
 * copied to a dynamically allocated, executable buffer, which is later
 * assigned to `fn_ptr_p`.
 *
 * This is meant to replace an entire function while still being able to
 * call the original.
 *
 * Example:
 *   static void * __thiscall (*ca_login_action)(void *thisptr) = (void*)0x552ea0;
 *   static void * __thiscall hooked_login_action(void *thisptr) {
 *      // prepare something
 *      void *ret = ca_login_action(thisptr); // call the original code
 *      // do something with ret
 *      return ret;
 *   }
 *   TRAMPOLINE_FN(&ca_login_action, 7, hooked_login_action);
 *
 * The code at 0x552ea0 will be patched to make a jump to hooked_player_login(),
 * while ca_player_login (the function pointer) is set to a copy of the original
 * code.
 *
 * \param fn_ptr_p pointer to the function to replace. Will be updated with
 * a new executable buffer with the original program code. Must be initially
 * set with a valid address.
 * \param replaced_bytes_p number of bytes to patch, must be at least 5.
 * May be more than 5, then the remainder is filled with NOP instructions.
 * \param fn_p trampoline target function to jump to
 */
#define TRAMPOLINE_FN(fn_ptr_p, replaced_bytes_p, fn_p)                        \
	static void __attribute__((constructor(110)))                          \
	    _PATCH_JOIN(init_patch_, __LINE__)(void)                           \
	{                                                                      \
		_trampoline_fn_static_add((void **)fn_ptr_p, replaced_bytes_p, \
					  (void *)fn_p);                       \
	}

/**
 * Insert all trampolines/patches added by static constructors.
 *
 * \param libhandle handle of the current DLL/SO. See patchmem_library_handle
 */
APICALL int patch_mem_static_init(struct patch_mem_lib_handle *libhandle);

/**
 * Return true if the given addr was patched by patchmem.
 */
APICALL bool patch_mem_check_addr_patched(uintptr_t addr);

/**
 * Get libhandle that patchmem was initialized with.
 */
APICALL struct patch_mem_lib_handle *patch_mem_get_libhandle(void);

/**
 * If patchmem was loaded as a separate library, calling this function
 * makes sure it is never unloaded. This should speed up re-injecting the
 * main DLL for runtime code patching purposes.
 */
APICALL void patch_mem_static_persist(void);

/**
 * Undo patch_mem_static_init(), which can be called again afterwards.
 *
 * \param libhandle handle of the current DLL/SO. See patchmem_library_handle
 */
APICALL void patch_mem_static_deinit(struct patch_mem_lib_handle *libhandle,
				     enum patch_mem_deinit_strategy strategy);

/* internal functions */
APICALL void _patch_mem_static_add(uintptr_t addr, size_t replaced_bytes,
				   const char *asm_fmt, ...);
APICALL void _patch_jmp32_static_add(uintptr_t addr, void *fn);
APICALL void _patch_ptr_static_add(uintptr_t addr, void **orig_fn, void *fn);
APICALL void _trampoline_static_add(uintptr_t addr, size_t replaced_bytes,
				    const char *asm_fmt, ...);
APICALL void _trampoline_fn_static_add(void **orig_fn, size_t replaced_bytes, void *fn);
#define _PATCH_JOIN2(a, b) a##b
#define _PATCH_JOIN(a, b) _PATCH_JOIN2(a, b)

#ifdef __cplusplus
}
#endif

#endif /* PATCHMEM_H */
