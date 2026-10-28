#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <ps5/kernel.h>
#include "patch.h"
#include "functions.h"
#include "filter.h"
#include "clock.h"
#include "input.h"
#include <stddef.h>
#include <time.h>


static pid_t shell_pid(struct timeval *started) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
    size_t size = 0;
    if (sysctl(mib, 4, NULL, &size, NULL, 0) || !size || size>8*1024*1024) return -1;
    size += size / 4;
    char *buf = malloc(size);
    if (!buf) return -1;
    pid_t found = -1;
    if (!sysctl(mib, 4, buf, &size, NULL, 0)) {
        for (char *p = buf; p + sizeof(struct kinfo_proc) <= buf + size;) {
            struct kinfo_proc *ki = (void *)p;
            if (ki->ki_structsize < (int)sizeof(*ki) ||
                (size_t)ki->ki_structsize > (size_t)(buf + size - p)) break;
            if (!strcmp(ki->ki_comm, "SceShellUI")) {
                if (found != -1) { found = -1; break; }
                found = ki->ki_pid;
                *started = ki->ki_start;
            }
            p += ki->ki_structsize;
        }
    }
    free(buf);
    return found;
}

int dz_read_remote(pid_t pid, uintptr_t addr, void *buf, size_t size) {
    if (!buf || size > UINTPTR_MAX - addr) return -1;
    unsigned char *out = buf;
    while (size) {
        /* The SDK fallback must never receive a read spanning a 4 KiB page. */
        size_t chunk = 4096 - (addr & 4095);
        if (chunk > size) chunk = size;
        if (kernel_proc_copyout(pid, (intptr_t)addr, out, chunk)) return -1;
        addr += chunk; out += chunk; size -= chunk;
    }
    return 0;
}

static int verify(pid_t pid, uintptr_t addr, const void *expected, size_t size) {
    unsigned char bytes[512];
    if (size > sizeof(bytes) || dz_read_remote(pid, addr, bytes, size)) return -1;
    return memcmp(bytes, expected, size) ? -1 : 0;
}

/* Execute-only pages cannot be written through the process mapping; writes go
 * through the direct map. The pmap offset inside the target's vmspace is
 * resolved by the SDK for the running firmware (KERNEL_OFFSET_VMSPACE_VM_PMAP),
 * covering every firmware the SDK itself supports. */
int dz_write_remote(pid_t pid, uintptr_t addr, const void *buf, size_t size) {
    intptr_t proc = kernel_get_proc(pid);
    if (!proc) return -1;
    uintptr_t vmspace = kernel_getlong(proc + KERNEL_OFFSET_PROC_P_VMSPACE);
    if (!vmspace) return -1;
    uint64_t paging[2];
    if (kernel_copyout(vmspace + (uintptr_t)KERNEL_OFFSET_VMSPACE_VM_PMAP + 32,
                       paging, sizeof(paging)) ||
        !paging[0] || !paging[1] || paging[0] <= paging[1]) return -1;
    uint64_t dmap = paging[0] - paging[1];
    const unsigned char *src = buf;
    while (size) {
        uint64_t table = paging[1] & 0x000ffffffffff000ull;
        uint64_t phys = 0, remaining = 0;
        for (int shift = 39; shift >= 12; shift -= 9) {
            uint64_t pte;
            if (kernel_copyout(dmap + table + ((addr >> shift) & 511) * 8,
                               &pte, sizeof(pte)) || !(pte & 1)) return -1;
            if (shift == 12 || ((shift == 30 || shift == 21) && (pte & 128))) {
                uint64_t mask = (1ull << shift) - 1;
                phys = (pte & ((1ull << 52) - (1ull << shift))) | (addr & mask);
                remaining = (1ull << shift) - (addr & mask);
                break;
            }
            table = pte & 0x000ffffffffff000ull;
        }
        if (!remaining) return -1;
        size_t chunk = size < remaining ? size : (size_t)remaining;
        if (kernel_copyin(src, dmap + phys, chunk)) return -1;
        addr += chunk; src += chunk; size -= chunk;
    }
    return 0;
}

static struct {
    pid_t pid;
    int count;
    struct timeval started;
    uintptr_t base, pad, cave, slots[6];
    int kinds[6], enabled;
    uintptr_t funcs[DZ_PAD_FUNCS];
    struct dz_config config;
} target;
static const char *error = "";
static struct dz_observation observation;

static int motion_seen(const unsigned char *data) {
    return data[4] != 128 || data[5] != 128 || data[6] != 128 || data[7] != 128;
}

const char *dz_error(void) { return error; }
static int fail(const char *message) { error = message; return -1; }

static int validate(void) {
    unsigned char code[sizeof(blob)];
    if (dz_read_remote(target.pid, target.cave, code, sizeof(code)))
        return fail("Cannot read filter");
    struct dz_config config = dz_default;
    int valid = !dz_code_config(code, target.funcs[0], target.funcs[4], &config);
    int empty = 1, originals = 0, hooks = 0;
    for (size_t i = 0; i < sizeof(code); ++i) if (code[i]) empty = 0;
    if (!valid && !empty) return fail("Another filter occupies this area");
    for (int i = 0; i < target.count; ++i) {
        uintptr_t pointer;
        if (dz_read_remote(target.pid, target.slots[i], &pointer, 8))
            return fail("Cannot read imports");
        if (pointer == target.funcs[target.kinds[i] ? 4 : 0]) ++originals;
        else if (pointer == target.cave + target.kinds[i] * 32 && valid) ++hooks;
        else return fail("Unexpected import: change refused");
    }
    if (originals != target.count && hooks != target.count) return fail("Imports incomplete: change refused");
    target.enabled = hooks == target.count;
    target.config = valid ? config : dz_default;
    return 0;
}

static int locate(pid_t pid) {
    uint32_t module = 0;
    if (kernel_dynlib_handle(pid, "libScePad.sprx", &module) || !module)
        return fail("Controller library unavailable");
    memset(&target, 0, sizeof(target));
    target.pid = pid;
    target.base = kernel_dynlib_mapbase_addr(pid, 0);
    target.pad = kernel_dynlib_mapbase_addr(pid, module);
    if (!target.base || !target.pad || (target.base & 0x3fff) || (target.pad & 0x3fff))
        return fail("Unknown memory layout");
    if (dz_pad_funcs(pid, target.pad, target.funcs) ||
        dz_pad_thunks(pid, target.pad, target.funcs, dz_read_remote))
        return fail("Controller library not recognized");
    /* Two reader layouts are known, and the library itself says which one it
     * is. On 10.20 SceShellUI's two reader families sit at fixed offsets in
     * the library (0x2960: thunk; 0x29a0: standalone), NOT at dlsym's
     * resolution of scePadReadForTracker (0x5a0 further on, with no import
     * pointing there). Those two offsets are pinned by signature.
     *
     * When the signatures are not there, the readers are simply the five
     * dlsym resolves this process has, which dz_pad_thunks has just
     * cross-checked against the library's own code: 13.60 keeps the same
     * thunk pair at +0x3080..+0x30b0 over +0x1a70/+0x1e50 and the standalone
     * tracker at +0x3840, so nothing is assumed and nothing is overridden. */
    {
        const unsigned char first[] = {0x31,0xd2,0xe9,0x69,0xec,0xff,0xff};
        const unsigned char second[] = {0x55,0x48,0x89,0xe5,0x41,0x56,0x53,0x48,0x81,0xec,0xb0,0,0,0};
        if (!verify(pid, target.pad + 0x2960, first, sizeof(first)) &&
            !verify(pid, target.pad + 0x29a0, second, sizeof(second)) &&
            target.pad + 0x29a0 != target.funcs[0]) {
            target.funcs[0] = target.pad + 0x2960;
            target.funcs[4] = target.pad + 0x29a0;
        }
    }
    /* The filter code lives in an empty gap of the home screen's own program
     * image (never inside a shared library). A previously deployed filter is
     * recognised by its signature so it is updated in place; on a fresh boot
     * the longest all-zero run of an executable mapping is claimed (code gaps
     * are int3-filled, so a zero run is always unused padding). The blob
     * entries are 32-byte aligned, so must be the gap end. */
    {
        int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_VMMAP, pid};
        size_t size = 0;
        if (sysctl(mib, 4, NULL, &size, NULL, 0) || !size || size > 16 * 1024 * 1024)
            return fail("Memory map unavailable");
        size += size / 4;
        char *maps = malloc(size);
        unsigned char *page = malloc(65536);
        if (!maps || !page) { free(maps); free(page); return fail("Out of memory"); }
        int failed = sysctl(mib, 4, maps, &size, NULL, 0);
        int signatures = 0;
        uintptr_t first_hit = 0;
        size_t need = (sizeof(blob) + 31) & ~(size_t)31;
        uintptr_t gap_end = 0, run_start = 0, best_start = 0;
        size_t best_run = 0;
        for (char *p = maps; !failed && p + sizeof(int) <= maps + size;) {
            struct kinfo_vmentry *vm = (void *)p;
            if (vm->kve_structsize < (int)offsetof(struct kinfo_vmentry, kve_path) ||
                (size_t)vm->kve_structsize > (size_t)(maps + size - p)) { failed = 1; break; }
            p += vm->kve_structsize;
            uintptr_t start = vm->kve_start, end = vm->kve_end;
            run_start = 0;
            /* Code segments are megabytes large, unlike the small read-only
             * import segments; allow whole program-image code mappings here. */
            if (!(vm->kve_protection & KVME_PROT_EXEC) || start < target.base ||
                end > target.base + 0x10000000ull || end <= start || end - start > 64 * 1024 * 1024)
                continue;
            for (uintptr_t addr = start; !failed && addr < end; addr += 65536) {
                size_t bytes = end - addr < 65536 ? end - addr : 65536;
                if (dz_read_remote(pid, addr, page, bytes)) { failed = 1; break; }
                /* A previous install is recognised by its entry code: two
                 * 32-byte-spaced entries, each "movabs rax, <reader>" (the
                 * pointer differs per boot, so only the prefix signs) followed
                 * by "mov r10d, <mode>" (240 for the first entry, 336 for the
                 * second) and a "jmp rel8". The installed pointers are
                 * re-checked against the resolved readers by dz_code_config
                 * afterwards. */
                for (size_t pos = 0; pos + 17 <= bytes; ++pos) {
                    const unsigned char *q = page + pos;
                    if (q[0] != 72 || q[1] != 184 || q[10] != 65 || q[11] != 186 ||
                        q[14] || q[15] || q[16] != 235) continue;
                    if (signatures >= 16) { failed = 1; break; }
                    if (!signatures) {
                        if (q[12] != 240 || q[13]) continue;
                        first_hit = addr + pos;
                    } else {
                        if (q[12] != 80 || q[13] != 1) continue;
                        if (addr + pos != first_hit + 32) { failed = 1; break; }
                    }
                    ++signatures;
                    pos += 31;
                }
                for (size_t pos = 0; pos < bytes; ++pos) {
                    if (page[pos]) { run_start = 0; continue; }
                    if (!run_start) run_start = addr + pos;
                    if ((size_t)(addr + pos + 1 - run_start) > best_run) {
                        best_run = (size_t)(addr + pos + 1 - run_start);
                        gap_end = addr + pos + 1;
                        best_start = run_start;
                    }
                }
            }
        }
        free(maps); free(page);
        if (failed) return fail("Program area unusable");
        if (signatures && signatures != 2) return fail("Installed filter not recognised");
        if (signatures) target.cave = first_hit;
        else {
            /* Claim the end of the longest zero run, 32-byte aligned like the
             * blob entries; the payload verifies the gap is empty (or its own
             * code) before writing anything. */
            uintptr_t end = gap_end & ~(uintptr_t)31;
            if (best_run < need + 32 || end < need || end - need < best_start)
                return fail("No free program area for the filter");
            target.cave = end - need;
        }
    }
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_VMMAP, pid};
    size_t size = 0;
    if (sysctl(mib, 4, NULL, &size, NULL, 0) || !size || size > 16 * 1024 * 1024)
        return fail("Memory map unavailable");
    size += size / 4;
    char *maps = malloc(size);
    unsigned char *page = malloc(65536);
    if (!maps || !page) { free(maps); free(page); return fail("Out of memory"); }
    int found = 0, cave_ok = 0, failed = sysctl(mib, 4, maps, &size, NULL, 0);
    size_t scanned = 0;
    for (char *p = maps; !failed && p + sizeof(int) <= maps + size;) {
        struct kinfo_vmentry *vm = (void *)p;
        if (vm->kve_structsize < (int)offsetof(struct kinfo_vmentry, kve_path) ||
            (size_t)vm->kve_structsize > (size_t)(maps + size - p)) { failed = 1; break; }
        p += vm->kve_structsize;
        uintptr_t start = vm->kve_start, end = vm->kve_end;
        if (start <= target.cave && end >= target.cave + sizeof(blob) &&
            (vm->kve_protection & KVME_PROT_EXEC)) cave_ok = 1;
        /* Imported reader pointers sit in relocation segments. Two shapes are
         * known: 10.20 keeps them in the shared-library window at 0x800000000,
         * 13.60 keeps them in the home screen's own image (relro and data
         * follow the code). Both are scanned, and any readable protection is
         * accepted, so a firmware that imports more or fewer readers is simply
         * counted. */
        if (!(vm->kve_protection & KVME_PROT_READ) || end <= start || end - start > 2 * 1024 * 1024)
            continue;
        if (!((start >= 0x800000000ull && end <= 0x900000000ull) ||
              (start >= target.base && end <= target.base + 0x1500000ull)))
            continue;
        scanned += end - start;
        if (scanned > 128 * 1024 * 1024) { failed = 1; break; }
        for (uintptr_t addr = start; !failed && addr < end; addr += 65536) {
            size_t bytes = end - addr < 65536 ? end - addr : 65536;
            if (dz_read_remote(pid, addr, page, bytes)) { failed = 1; break; }
            for (size_t pos = 0; pos + 8 <= bytes; pos += 8) {
                uintptr_t pointer;
                memcpy(&pointer, page + pos, 8);
                int kind = -1;
                if (pointer == target.funcs[0] || pointer == target.cave) kind = 0;
                if (pointer == target.funcs[4] || pointer == target.cave + 32) kind = 1;
                if (kind < 0) continue;
                /* More imported readers than we can hold: unknown layout. */
                if (found >= 6) { failed = 1; break; }
                target.slots[found] = addr + pos;
                target.kinds[found++] = kind;
            }
        }
    }
    /* The home screen also imports the two readers inside its own program
     * image (SceShellUI), in a mapping this scan cannot see; those two
     * imports feed the on-screen cursor. Their image offsets come from the
     * validated layout; validate() re-checks their actual pointers, so a
     * wrong offset fails loudly ("Unexpected import") instead of leaving
     * the home screen silently half hooked. All six imports, or nothing. */
    /* The 10.20 image imports those two readers inside its own program image,
     * in a mapping this scan cannot see, and the whole set of six is expected:
     * all six, or nothing. Firmwares whose imports are all in scanned segments
     * (13.60 has a single scePadReadState slot in relro) are accepted with any
     * count from one upwards; validate() re-checks every pointer before
     * anything is written, so a wrong slot still fails loudly. */
    if (!failed && found >= 6) {
        for (int i = 0; i < 2; ++i) {
            uintptr_t anchor = target.base + (i ? 0x101a768 : 0x1019690);
            int seen = 0;
            for (int j = 0; j < found; ++j) if (target.slots[j] == anchor) seen = 1;
            if (seen) continue;
            if (found >= 6) { failed = 1; break; }
            target.slots[found] = anchor;
            target.kinds[found++] = i;
        }
    }
    free(maps); free(page);
    if (failed || !cave_ok || found < 1)
        return fail("The controller reads are not identified");
    if (found >= 6) {
        int kind0 = 0, kind1 = 0;
        for (int i = 0; i < found; ++i) target.kinds[i] ? ++kind1 : ++kind0;
        if (!kind0 || !kind1) return fail("The controller reads are not identified");
    }
    target.count = found;
    return validate();
}

static int ensure(void) {
    struct timeval started={0};
    pid_t pid = shell_pid(&started);
    if (pid <= 0) return fail("Home screen unavailable");
    if (pid != target.pid || started.tv_sec!=target.started.tv_sec ||
        started.tv_usec!=target.started.tv_usec || !target.count) {
        memset(&observation,0,sizeof(observation));
        int result = locate(pid);
        if (result) target.pid = 0;
        else target.started=started;
        return result;
    }
    return validate();
}

/* records = 0x8ae0 bytes at pad + 0x20018: 24 handle caches of 0x5c8 bytes,
 * handle id at +0x1c, state sample at +0x4b8, tracking sample at +0x538.
 * SceShellUI keeps a second handle that is fed fresh, all-neutral samples
 * slightly ahead of the real pad: among samples within 100 ms of the newest,
 * one with an axis off neutral wins. */
const unsigned char *dz_active_sample(const unsigned char *records, uint64_t *stamp) {
    const unsigned char *samples[48];
    uint64_t stamps[48], newest = 0;
    int count = 0;
    for (int i = 0; i < 24; ++i) {
        const unsigned char *slot = records + (size_t)i * 0x5c8;
        uint32_t handle;
        memcpy(&handle, slot + 0x1c, 4);
        if (!handle) continue;
        const unsigned offsets[2] = {0x4b8, 0x538};
        for (int k = 0; k < 2; ++k) {
            const unsigned char *p = slot + offsets[k];
            if (p[76] != 1) continue;
            memcpy(&stamps[count], p + 80, 8);
            if (stamps[count] > newest) newest = stamps[count];
            samples[count++] = p;
        }
    }
    const unsigned char *sample = NULL;
    int moving = 0;
    *stamp = 0;
    for (int i = 0; i < count; ++i) {
        if (newest - stamps[i] > 100000) continue;
        int m = motion_seen(samples[i]);
        if (m > moving || (m == moving && stamps[i] > *stamp)) { sample = samples[i]; *stamp = stamps[i]; moving = m; }
    }
    return sample;
}

/* Layouts without the 0x20018 record table keep the same kind of ScePadData
 * copy in the library's rw- segment, which starts at pad + 0x24000 and is
 * 64 KB: connected flag at +76, microseconds-since-boot stamp at +80.
 *
 * One snapshot cannot identify the live copy — the window holds dozens of
 * structures with 1 at +76 and a plausible value at +80, and one carries
 * 0xffffffff, which wins any "newest" test. What separates them is that the
 * live stamp ADVANCES between two reads a few milliseconds apart, so the
 * segment is read twice and only candidates whose stamp moved forward by a
 * plausible microsecond delta are kept. Among those, a sample with an axis off
 * neutral wins: SceShellUI keeps a second handle fed all-neutral samples
 * slightly ahead of the real pad, so "take the newest" reports a centred stick
 * while the real one drifts. */
static size_t dz_pick_sample(const unsigned char *a, const unsigned char *b, uint64_t *stamp) {
    size_t best = 0;
    uint64_t best_stamp = 0;
    int best_motion = -1;
    for (size_t off = 0; off + 96 <= DZ_REC_LEN; off += 8) {
        if (a[off + 76] != 1 || b[off + 76] != 1) continue;
        uint64_t s1, s2;
        memcpy(&s1, a + off + 80, 8);
        memcpy(&s2, b + off + 80, 8);
        if (!s1 || !s2 || (s1 >> 32) || (s2 >> 32) || s2 <= s1) continue;
        if (s2 - s1 > 1000000) continue;   /* not a microsecond tick */
        int m = motion_seen(b + off);
        if (m > best_motion || (m == best_motion && s2 > best_stamp)) {
            best = off; best_stamp = s2; best_motion = m;
        }
    }
    *stamp = best_stamp;
    return best;
}

/* The live sample of a process, whichever of the two layouts it maps: the
 * 0x20018 table when it has one, the rw- window otherwise. Returns 0 with
 * *data NULL when nothing is advancing, which the server reports as
 * "controller disconnected". */
int dz_pad_sample(int pid, uintptr_t pad, const unsigned char **data, uint64_t *stamp) {
    static unsigned char records[0x8ae0];
    static unsigned char first[DZ_REC_LEN], second[DZ_REC_LEN];
    *data = NULL;
    *stamp = 0;
    if (!dz_read_remote(pid, pad + 0x20018, records, sizeof(records))) {
        const unsigned char *sample = dz_active_sample(records, stamp);
        if (sample) { *data = sample; return 0; }
    }
    *stamp = 0;
    if (dz_read_remote(pid, pad + DZ_REC_OFF, first, sizeof(first))) return -1;
    usleep(20000);
    if (dz_read_remote(pid, pad + DZ_REC_OFF, second, sizeof(second))) return -1;
    size_t off = dz_pick_sample(first, second, stamp);
    if (off) *data = second + off; else *stamp = 0;
    return 0;
}

int dz_read(struct dz_state *out) {
    if (ensure()) return -1;
    uint64_t stamp = 0;
    const unsigned char *data = NULL;
    if (dz_pad_sample(target.pid, target.pad, &data, &stamp))
        return fail("Cannot read controller");
    *out=(struct dz_state){.pid=target.pid,.enabled=target.enabled,.config=target.config,
        .started=(uint64_t)target.started.tv_sec*1000000+(uint64_t)target.started.tv_usec};
    if (dz_sample(out,&observation,data,stamp,dz_milliseconds()))
        return fail("Monotonic clock unavailable");
    error = "";
    return 0;
}

int dz_apply(const struct dz_config *settings, int enabled) {
    if (!dz_valid(settings) || (enabled != 0 && enabled != 1)) return fail("Invalid setting");
    if (ensure()) return -1;
    pid_t pid = target.pid, self = getpid();
    int result = -1, attached = 0, touched = 0;
    uint64_t auth = kernel_get_ucred_authid(self);
    unsigned char caps[16], all_caps[16], previous[sizeof(blob)], code[sizeof(blob)];
    uintptr_t before[6];
    if (!auth || kernel_get_ucred_caps(self, caps)) return fail("Privileges unavailable");
    memset(all_caps, 255, sizeof(all_caps));
    error = "Cannot apply setting";
    if (kernel_set_ucred_authid(self, 0x4800000000010003ull) ||
        kernel_set_ucred_caps(self, all_caps)) goto finish;
    if (ptrace(PT_ATTACH, pid, NULL, 0)) goto finish;
    attached = 1;
    int stopped = 0;
    for (int i = 0; i < 200; ++i) {
        int status;
        pid_t got = waitpid(pid, &status, WNOHANG);
        if (got == pid) { stopped = WIFSTOPPED(status); break; }
        if (got < 0 && errno != EINTR) break;
        usleep(10000);
    }
    if (!stopped || validate() || dz_read_remote(pid, target.cave, previous, sizeof(previous))) goto finish;
    for (int i = 0; i < target.count; ++i)
        if (dz_read_remote(pid, target.slots[i], &before[i], 8)) goto finish;
    dz_code(code, target.funcs[0], target.funcs[4], settings);
    struct dz_config config;
    int existing = !dz_code_config(previous, target.funcs[0], target.funcs[4], &config);
    if (enabled) {
        touched = 1;
        if (existing) {
            for (int i=0;i<DZ_FIELDS;i++) {
                size_t offset=home_fields[i], length=i==DZ_FIELDS-1?DZ_CONFIG_SIZE:4;
                if (dz_write_remote(pid,target.cave+offset,code+offset,length)) goto rollback;
            }
        } else if (dz_write_remote(pid,target.cave,code,sizeof(code))) goto rollback;
        if (verify(pid,target.cave,code,sizeof(code))) goto rollback;
    }
    for (int i = 0; i < target.count; ++i) {
        uintptr_t after = enabled ? target.cave + target.kinds[i] * 32 :
            target.funcs[target.kinds[i] ? 4 : 0];
        if (before[i] == after) continue;
        touched = 1;
        if (dz_write_remote(pid, target.slots[i], &after, 8) ||
            verify(pid, target.slots[i], &after, 8)) goto rollback;
    }
    result = 0;
    goto finish;
rollback:
    if (touched) {
        int failed = 0;
        if (existing) {
            for (int i=0;i<DZ_FIELDS;i++) {
                size_t offset=home_fields[i], length=i==DZ_FIELDS-1?DZ_CONFIG_SIZE:4;
                if (dz_write_remote(pid,target.cave+offset,previous+offset,length)) failed=1;
            }
            if (verify(pid,target.cave,previous,sizeof(previous))) failed=1;
        }
        for (int i = 0; i < target.count; ++i)
            if (dz_write_remote(pid, target.slots[i], &before[i], 8) ||
                verify(pid, target.slots[i], &before[i], 8)) failed = 1;
        if (!failed && !existing &&
            (dz_write_remote(pid, target.cave, previous, sizeof(previous)) ||
             verify(pid, target.cave, previous, sizeof(previous)))) failed = 1;
        if (failed) {
            kernel_set_ucred_caps(self, caps);
            kernel_set_ucred_authid(self, auth);
            puts("[deadzone] Rollback failed; reboot required");
            for (;;) sleep(60);
        }
    }
finish:
    if (attached && ptrace(PT_DETACH, pid, NULL, 0)) result = fail("Cannot resume home screen; reboot required");
    if (kernel_set_ucred_caps(self, caps)) result = fail("Cannot restore filter capabilities; reboot required");
    if (kernel_set_ucred_authid(self, auth)) result = fail("Cannot restore filter identity; reboot required");
    if (!result) result = validate();
    if (!result) error = "";
    return result;
}

