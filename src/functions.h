#ifndef DZ_FUNCTIONS_H
#define DZ_FUNCTIONS_H
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>
#include <ps5/kernel.h>
/* The five pad-data readers of libScePad, in the order the filter blobs know
 * them (kind 0..4): state120, lots120, state128, lots128, tracking168.
 * Kind 0 = scePadReadState (ScePadData 120), 1 = scePadRead (batches),
 * 2 = scePadReadStateExt (128), 3 = scePadReadExt (batches),
 * 4 = scePadReadForTracker (168). Resolved by name so the payload follows the
 * library wherever the firmware places its code. */
#define DZ_PAD_FUNCS 5
static const char *const pad_func_names[DZ_PAD_FUNCS] = {
    "scePadReadState", "scePadRead", "scePadReadStateExt",
    "scePadReadExt", "scePadReadForTracker"};
/* Every reader must land inside the first 2 MiB of the library, past its
 * headers, as a distinct address. */
static int dz_pad_funcs(pid_t pid, uintptr_t pad, uintptr_t funcs[DZ_PAD_FUNCS]) {
    uint32_t module = 0;
    if (kernel_dynlib_handle(pid, "libScePad.sprx", &module) || !module)
        return -1;
    for (int i = 0; i < DZ_PAD_FUNCS; ++i) {
        intptr_t found = kernel_dynlib_dlsym(pid, module, pad_func_names[i]);
        if (found <= (intptr_t)pad || (size_t)(found - (intptr_t)pad) > 0x200000)
            return -1;
        for (int j = 0; j < i; ++j) if (funcs[j] == (uintptr_t)found) return -1;
        funcs[i] = (uintptr_t)found;
    }
    return 0;
}
/* Cross-checks the five resolved addresses against the actual library code:
 * ReadState/ReadStateExt and Read/ReadExt are thin thunks whose relative
 * jumps lead to two distinct shared readers, ReadForTracker is a standalone
 * function. Any other layout means this is not the library the filter knows,
 * whatever the firmware. */
static int dz_pad_thunks(pid_t pid, uintptr_t pad, const uintptr_t funcs[DZ_PAD_FUNCS],
                         int (*read)(pid_t, uintptr_t, void *, size_t)) {
    uintptr_t common[4];
    for (int i = 0; i < 4; ++i) {
        unsigned char code[10]; /* xor r,r;jmp (7) or mov r,imm32;jmp (10) */
        if (read(pid, funcs[i], code, sizeof(code))) return -1;
        /* The thunk is a 2-byte prologue (xor r,r) or a 5-byte mov imm32,
         * then one jmp rel32. Only the opcode that follows the prologue may be
         * taken: the rel32 displacement can contain 0xe9 itself (13.60's
         * scePadReadStateExt jumps with c6 e9 ff ff), so a rule that demands
         * exactly one 0xe9 in the window rejects a valid thunk. */
        int jump = -1;
        for (int j = 2; j < 9; ++j) if (code[j] == 0xe9) { jump = j; break; }
        if (jump < 0) return -1;
        int32_t rel;
        memcpy(&rel, code + jump + 1, 4);
        common[i] = (uintptr_t)((int64_t)funcs[i] + jump + 5 + rel);
        if (common[i] <= pad || common[i] - pad > 0x200000) return -1;
    }
    if (common[0] != common[2] || common[1] != common[3] || common[0] == common[1])
        return -1;
    unsigned char code[6];
    if (read(pid, funcs[4], code, sizeof(code))) return -1;
    for (int j = 0; j < 6; ++j) if (code[j] == 0xe9) return -1;
    return 0;
}
#endif
