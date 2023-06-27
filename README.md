# x86 32-bit Runtime Code Patching library

A library providing pretty macros for replacing code at given address, adding detours, or adding trampolines. Keeps track of code modifications, is able to undo them. Supports hot-patching/hot-un-patching at any point in program lifecycle. Integrates nicely with [DLL Hotpach Daemon](https://github.com/darsto/dll-hotpatch-daemon).

Currently supports Windows only.

## Examples

A few samples. Descriptions can be found in the only API header file - `patchmem.h`:

```c
PATCH_MEM(0x8cea20, 2, "pop eax");
```

```c
TRAMPOLINE(0x8d456c, 5, "mov ecx, 0x%x; call org", &g_some_hooked_data);
```

```c
static void * __thiscall (*ca_login_action)(void *thisptr) = (void*)0x552ea0;
static void * __thiscall hooked_login_action(void *thisptr) {
    // prepare something
    void *ret = ca_login_action(thisptr); // call the original code
    // do something with ret
    return ret;
}
TRAMPOLINE_FN(&ca_player_login, 7, hooked_player_login);
```

All of the above macros expand to static gcc constructors, which add necessary patch information to a patchmem-internal list. The patches can be then applied with `patch_mem_static_init()` and then potentially un-applied with `patch_mem_static_deinit()`.

`patch_mem_static_deinit()` is only meant for hot-reloading the DLL. It suspends all other threads, checks if any of them are executing the patched code, un-suspends them if needed, repeats up to a few times until it succeeds, then un-patches the code. A suggested practice is to call `patch_mem_static_deinit()` from `DllMain(DLL_PROCESS_DETACH)`, but only if the process is not exiting - this can be usually checked by hooking into the regular exit code, or listening for WM_QUIT WndProc messages.

# Dependencies

Depends on [Keystone Engine](https://github.com/keystone-engine/keystone) to assemble x86 asm at runtime. This assembly could be done at build time, but then this library wouldn't allow for such a nice syntax.

# Building & Integrating

Patchmem comes with a Makefile to build it as a separate DLL.

Simply:
`$ make`

With a single function call to `patch_mem_static_persist()` it can be made to never unload itself. This comes useful for quicker hot-reloading the target DLL, since the patchmem & the keystone dependency won't need to be reloaded.

But it's also straightforward to integrate patchmem directly into the target DLL.