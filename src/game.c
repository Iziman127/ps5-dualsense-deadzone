#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <time.h>
#include <unistd.h>
#include <stddef.h>
#include <ps5/kernel.h>
#include "game.h"
#include "game-code.h"
#include "functions.h"
#include "clock.h"
#include "input.h"
#define MAX_IMPORTS 128
static struct {
    int pid, count, supported, enabled;
    struct dz_config config;
    struct timeval started;
    uintptr_t pad, cave, funcs[DZ_PAD_FUNCS], slots[MAX_IMPORTS];
    unsigned char kinds[MAX_IMPORTS];
    struct dz_observation observation;
    int64_t retry;
    const char *error;
} game;
static int fail(const char *s) { game.error=s;return -1; }
static int read_at(uintptr_t address,void *data,size_t size) {
    return dz_read_remote(game.pid,address,data,size);
}
static int game_read_thunk(pid_t pid,uintptr_t address,void *data,size_t size) {
    (void)pid;return read_at(address,data,size);
}
static int checked_write(uintptr_t address,const void *data,size_t size) {
    unsigned char actual[512];
    if (size>sizeof(actual) || dz_write_remote(game.pid,address,data,size) || read_at(address,actual,size)) return -1;
    return memcmp(actual,data,size)?-1:0;
}
static int current_game(struct timeval *started) {
    int mib[4]={CTL_KERN,KERN_PROC,KERN_PROC_PROC,0};size_t size=0;
    if (sysctl(mib,4,NULL,&size,NULL,0) || !size || size>8*1024*1024) return -1;
    size+=size/4;char *data=malloc(size);if (!data) return -1;
    int pid=0;
    if (sysctl(mib,4,data,&size,NULL,0)) { free(data);return -1; }
    for (char *p=data;p+sizeof(struct kinfo_proc)<=data+size;) {
        struct kinfo_proc *ki=(void*)p;
        if (ki->ki_structsize<(int)sizeof(*ki) || (size_t)ki->ki_structsize>(size_t)(data+size-p)) { pid=-1;break; }
        p+=ki->ki_structsize;
        if (strcmp(ki->ki_comm,"eboot.bin")) continue;
        if (pid) { pid=-1;break; }
        pid=ki->ki_pid;*started=ki->ki_start;
    }
    free(data);return pid;
}
static int validate(void) {
    unsigned char code[sizeof(game_blob)];
    if (read_at(game.cave,code,sizeof(code))) return fail("Cannot read game filter");
    struct dz_config config=dz_default;
    int valid=!game_code_config(code,game.cave,game.funcs,&config),empty=1,originals=0,hooks=0;
    for (size_t i=0;i<sizeof(code);i++) if (code[i]) empty=0;
    if (!valid && !empty) return fail("Another code occupies the game area");
    for (int i=0;i<game.count;i++) {
        uintptr_t pointer;
        if (read_at(game.slots[i],&pointer,8)) return fail("The game changed its pad reads");
        int kind=game.kinds[i];
        if (pointer==game.funcs[kind]) originals++;
        else if (valid && pointer==game.cave+game_entries[kind]) hooks++;
        else return fail("Game reads modified by another tool");
    }
    if (!game.count || (originals!=game.count && hooks!=game.count)) return fail("Incomplete game filter");
    game.enabled=hooks==game.count;game.config=valid?config:dz_default;
    return 0;
}
static int discover(void) {
    uint32_t module=0;
    if (kernel_dynlib_handle(game.pid,"libScePad.sprx",&module) || !module) return fail("Game library unavailable");
    game.pad=kernel_dynlib_mapbase_addr(game.pid,module);
    if (game.pad<0x400000 || (game.pad&0x3fff)) return fail("Unknown library address");
    if (dz_pad_funcs(game.pid,game.pad,game.funcs)) return fail("Game controller functions unavailable");
    if (dz_pad_thunks(game.pid,game.pad,game.funcs,game_read_thunk))
        return fail("Game controller library not recognized");
    unsigned char *buffer=malloc(65536);if (!buffer) return fail("Out of memory");
    int bad=0;
    /* The filter code lives in an empty gap of the game's own copy of the
     * controller library (execute-only mapping). A previous install is found
     * by its entry marker (five hits, 32 bytes apart); on a fresh game the
     * longest all-zero run is claimed, 32-byte aligned like the blob
     * entries. Both are verified again before anything is written. */
    {
        int mib[4]={CTL_KERN,KERN_PROC,KERN_PROC_VMMAP,game.pid};size_t size=0;
        if (sysctl(mib,4,NULL,&size,NULL,0) || !size || size>16*1024*1024) { free(buffer);return fail("Game memory map unavailable"); }
        size+=size/4;char *maps=malloc(size);
        if (!maps) { free(buffer);return fail("Out of memory"); }
        bad=sysctl(mib,4,maps,&size,NULL,0);
        int signatures=0;uintptr_t first_hit=0,gap_end=0,run_start=0,best_start=0;
        size_t best_run=0,need=(sizeof(game_blob)+31)&~(size_t)31;
        for (char *p=maps;!bad && p+sizeof(int)<=maps+size;) {
            struct kinfo_vmentry *vm=(void*)p;
            if (vm->kve_structsize<(int)offsetof(struct kinfo_vmentry,kve_path) || (size_t)vm->kve_structsize>(size_t)(maps+size-p)) { bad=1;break; }
            p+=vm->kve_structsize;uintptr_t a=vm->kve_start,b=vm->kve_end;
            run_start=0;
            /* The library text is one mapping starting exactly at the module
             * base; allow it whole. */
            if (!(vm->kve_protection&KVME_PROT_EXEC) || a!=game.pad || b>game.pad+16*1024*1024 || b<=a) continue;
            for (uintptr_t address=a;!bad && address<b;address+=65536) {
                size_t n=b-address<65536?b-address:65536;
                if (read_at(address,buffer,n)) { bad=1;break; }
                /* A previous install is recognised by its entry code: five
                 * 32-byte-spaced entries, each "lea rax, [rip+<disp>]" (the
                 * displacement differs per boot, so only the prefix signs)
                 * followed by "mov r10d, <mode>". Game modes are 240, 241,
                 * 256, 257, 336. The displacements are re-checked against the
                 * resolved readers by game_code_config afterwards. */
                for (size_t offset=0;!bad && offset+47<n;++offset) {
                    const unsigned char *q=buffer+offset;
                    /* lea rax,[rip+d] (48 8d 05) ; mov r10d,mode (41 ba m32) */
                    if (q[0]!=72 || q[1]!=141 || q[2]!=5 || q[7]!=65 || q[8]!=186) continue;
                    if (q[11] || q[12]) continue;                    /* mode fits 16 bits */
                    if (q[10]==0) { if (q[9]!=240 && q[9]!=241) continue; }
                    else if (q[10]==1) { if (q[9]!=0 && q[9]!=1 && q[9]!=0x50) continue; }
                    else continue;
                    if (signatures>=16) { bad=1;break; }
                    if (!signatures) first_hit=address+offset;
                    else if (address+offset!=first_hit+32*(uintptr_t)signatures) { bad=1;break; }
                    ++signatures;
                    offset+=31;
                }
                for (size_t offset=0;offset<n;++offset) {
                    if (buffer[offset]) { run_start=0;continue; }
                    if (!run_start) run_start=address+offset;
                    if ((size_t)(address+offset+1-run_start)>best_run) {
                        best_run=(size_t)(address+offset+1-run_start);
                        gap_end=address+offset+1;best_start=run_start;
                    }
                }
            }
        }
        free(maps);
        if (bad) { free(buffer);return fail("Game library code unreadable"); }
        if (signatures && signatures!=5) { free(buffer);return fail("Installed game filter not recognised"); }
        if (signatures) game.cave=first_hit;
        else {
            uintptr_t end=gap_end&~(uintptr_t)31;
            if (best_run<need+32 || end<need || end-need<best_start) { free(buffer);return fail("No free area in the game library"); }
            game.cave=end-need;
        }
    }
    int mib[4]={CTL_KERN,KERN_PROC,KERN_PROC_VMMAP,game.pid};size_t size=0;
    if (sysctl(mib,4,NULL,&size,NULL,0) || !size || size>16*1024*1024) { free(buffer);return fail("Game memory map unavailable"); }
    size+=size/4;char *maps=malloc(size);
    if (!maps) { free(buffer);return fail("Out of memory"); }
    bad=sysctl(mib,4,maps,&size,NULL,0);size_t scanned=0;int cave_ok=0;
    game.count=0;
    for (char *p=maps;!bad && p+sizeof(int)<=maps+size;) {
        struct kinfo_vmentry *vm=(void*)p;
        if (vm->kve_structsize<(int)offsetof(struct kinfo_vmentry,kve_path) || (size_t)vm->kve_structsize>(size_t)(maps+size-p)) { bad=1;break; }
        p+=vm->kve_structsize;uintptr_t a=vm->kve_start,b=vm->kve_end;
        if (a<=game.cave && b>=game.cave+sizeof(game_blob) && (vm->kve_protection&KVME_PROT_EXEC)) cave_ok=1;
        if (vm->kve_protection!=KVME_PROT_READ || b<=a || b-a>16*1024*1024 || a<0x400000) continue;
        scanned+=b-a;if (scanned>128*1024*1024) { bad=1;break; }
        for (uintptr_t address=a;!bad && address<b;address+=65536) {
            size_t n=b-address<65536?b-address:65536;
            if (read_at(address,buffer,n)) { bad=1;break; }
            for (size_t offset=0;offset+8<=n;offset+=8) {
                uintptr_t pointer;memcpy(&pointer,buffer+offset,8);
                for (int k=0;k<5;k++) if (pointer==game.funcs[k] || pointer==game.cave+game_entries[k]) {
                    if (game.count==MAX_IMPORTS) { bad=1;break; }
                    game.slots[game.count]=address+offset;game.kinds[game.count++]=(unsigned char)k;
                }
                if (bad) break;
            }
        }
    }
    free(buffer);free(maps);
    if (bad || !cave_ok || !game.count) return fail("Game pad reads not identified");
    if (validate()) return -1;
    game.supported=1;return 0;
}
static int ensure(void) {
    struct timeval started={0};int pid=current_game(&started);
    if (pid<0) return fail("Game identification unavailable or ambiguous");
    if (pid!=game.pid || started.tv_sec!=game.started.tv_sec || started.tv_usec!=game.started.tv_usec) {
        memset(&game,0,sizeof(game));game.pid=pid;game.started=started;
    }
    if (!pid) { game.error="";return 0; }
    if (!game.supported) {
        int64_t now=dz_milliseconds();if (now<0) return fail("Monotonic clock unavailable");
        if (now<game.retry) return -1;
        game.retry=now+5000;return discover();
    }
    return validate();
}
static int apply(const struct dz_config *settings,int enabled) {
    if (!dz_valid(settings) || (enabled!=0 && enabled!=1)) return fail("Invalid game setting");
    if (ensure()) return -1;
    if (!game.pid || (game.enabled==enabled && (!enabled || dz_equal(&game.config,settings)))) { game.error="";return 0; }
    /* The game keeps running: the cave is written and verified before any
     * import points at it, and each import swap is one aligned 8-byte store. */
    unsigned char before_code[sizeof(game_blob)],code[sizeof(game_blob)];
    uintptr_t before[MAX_IMPORTS],functions[5];
    int result=-1,touched=0,existing=0;
    game.error="Cannot apply filter to game";
    if (read_at(game.cave,before_code,sizeof(before_code))) goto finish;
    for (int i=0;i<game.count;i++) if (read_at(game.slots[i],&before[i],8)) goto finish;
    for (int i=0;i<5;i++) functions[i]=game.funcs[i];
    if (game_build(code,game.cave,functions,settings)) goto finish;
    struct dz_config config;
    existing=!game_code_config(before_code,game.cave,game.funcs,&config);
    if (enabled) {
        touched=1;
        if(existing) {
            for(int i=0;i<DZ_FIELDS;i++) {
                size_t offset=game_fields[i],n=i==DZ_FIELDS-1?DZ_CONFIG_SIZE:4;
                if(checked_write(game.cave+offset,code+offset,n))goto rollback;
            }
        } else if(checked_write(game.cave,code,sizeof(code)))goto rollback;
    }
    for (int i=0;i<game.count;i++) {
        int kind=game.kinds[i];uintptr_t pointer=enabled?game.cave+game_entries[kind]:functions[kind];
        if (before[i]==pointer) continue;
        touched=1;if (checked_write(game.slots[i],&pointer,8)) goto rollback;
    }
    result=0;goto finish;
rollback:
    if (touched) {
        int bad=0;
        if(existing)for(int i=0;i<DZ_FIELDS;i++) {
            size_t offset=game_fields[i],n=i==DZ_FIELDS-1?DZ_CONFIG_SIZE:4;
            if(checked_write(game.cave+offset,before_code+offset,n))bad=1;
        }
        for (int i=0;i<game.count;i++) if (checked_write(game.slots[i],&before[i],8)) bad=1;
        if (!bad && !existing && checked_write(game.cave,before_code,sizeof(before_code))) bad=1;
        if (bad) {
            puts("[deadzone-game] Restore failed; reboot required");
            for (;;) sleep(60);
        }
    }
finish:
    if (!result) result=validate();
    if (!result) game.error="";
    return result;
}
int game_sync(const struct dz_config *config,int enabled) { return apply(config,enabled); }
void game_refresh(void) { (void)ensure(); }
void game_tick(const struct dz_config *config,int enabled) {
    static int64_t retry;
    int64_t now=dz_milliseconds();
    if (now<0) { fail("Monotonic clock unavailable");return; }
    if (now<retry) return;
    if (apply(config,enabled)) retry=now+5000;
    else retry=0;
}
void game_read(struct game_status *out) {
    memset(out,0,sizeof(*out));
    out->pid=game.pid;out->supported=game.supported;out->enabled=game.enabled;out->config=game.config;out->imports=game.count;out->error=game.error?game.error:"";
    if (!game.pid || !game.supported) return;
    uint64_t best=0;const unsigned char *sample=NULL;
    if (dz_pad_sample(game.pid,game.pad,&sample,&best)) { out->error="Cannot read game controller";return; }
    out->input=(struct dz_state){.pid=game.pid,.enabled=game.enabled,.config=game.config};
    if (dz_sample(&out->input,&game.observation,sample,best,dz_milliseconds()))
        out->error="Monotonic clock unavailable";
}
