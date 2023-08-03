/* SPDX-License-Identifier: MIT
 * Copyright(c) 2023 Darek Stojaczyk
 */

#ifndef UT_UTIL_H
#define UT_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

/** Generic function wrapper with a 5-byte NOP header. Can be safely detoured.
 * Note on the .text directive: without it, in -O0 this assembly gets put in
 * the .data section, which is non executable and causes an immediate segfault.
 * GCC bug? This is not happening with -O2.
 */
#define OVERRIDABLE_FN(name_p)                               \
	__attribute__((noinline)) OVERRIDABLE_REF(name_p)(); \
	void *unused_symbol_##name_p = (void *)(name_p);     \
	__asm__( \
    ".text \n" \
    ".global overridable_" STRINGIFY(name_p) "\n" \
    "overridable_" STRINGIFY(name_p) ":\n" \
    "  nop; nop; nop; nop; nop\n" \
    "  jmp " STRINGIFY(name_p))

/** Get the name of function from OVERRIDABLE_FN() */
#define OVERRIDABLE_REF(name_p) overridable_##name_p

#define _STRINGIFY(x) #x
#define STRINGIFY(x) _STRINGIFY(x)
#define _CONCAT(x, y) x #y
#define CONCAT(x, y) _CONCAT(x, y)

#ifdef __cplusplus
}
#endif

#endif /* UT_UTIL_H */