# Firmware 13.60 port

This branch makes the payload work on a retail PS5 on firmware **13.60**
(kstuff + etaHEN chain). Upstream was written and validated against 10.20 only,
and refuses to patch any layout it does not recognise — which is what happens on
13.60: every request answers `Controller library not recognized`.

Everything below was measured on one console (CFI-1216, FW 13.60, kstuff-lite,
etaHEN 13.60 port) and then verified end to end: the filter applies on the home
screen and inside a running game, and the live read-out works in both.

## What did not work, and why

Four firmware-specific assumptions, all in `src/patch.c` / `src/functions.h`:

| Assumption | 10.20 | 13.60 |
|---|---|---|
| reader addresses | pinned `pad+0x2960`, `pad+0x29a0` + byte check | resolved by name only: `+0x3080/+0x3090/+0x30a0/+0x30b0/+0x3840` |
| import-slot scan window | `0x800000000..0x900000000`, `r--` only | the home image's own segments, e.g. slot at `base+0x11f9630` |
| slot count | exactly 6, plus anchors `base+0x1019690` / `+0x101a768` | **one** slot (`scePadReadState`); the anchors do not exist |
| live read-out | `pad+0x20018`, 24 × 0x5c8 handle records | zeros; the samples live in the library's `rw-` segment |

The one that actually breaks first is subtler: `dz_pad_thunks` demanded exactly
ONE `0xe9` byte in the first 9 bytes of each thunk. On 13.60
`scePadReadStateExt` is `ba 01 00 00 00 e9 c6 e9 ff ff` — the rel32 displacement
contains a second `0xe9`, so a perfectly good thunk was rejected and nothing
else was ever attempted.

## Measurements (13.60)

```
libScePad image          0x810198000, 114_688 B
scePadReadState        +0x3080   31 d2 e9 ..       -> +0x1a70   (state120)
scePadRead             +0x3090   31 c9 e9 ..       -> +0x1e50   (batch)
scePadReadStateExt     +0x30a0   ba 01 00 00 00 e9 -> +0x1a70   (same target)
scePadReadExt          +0x30b0   b9 01 00 00 00 e9 -> +0x1e50
scePadReadForTracker   +0x3840   standalone, no jmp

SceShellUI base        0x0eaf8000
  --x  base+0x0000000..+0x0d30000   code
  r--  ..+0x0f34000 / ..+0x10db000  rodata / relro
  rw-  base+0x10db000..+0x1374000   data - import slots live here

libScePad mappings:
  --x  pad+0x00000..+0x1c000        code
  r--  pad+0x1c000..+0x20000
  r--  pad+0x20000..+0x24000
  rw-  pad+0x24000..+0x34000        handle caches
```

A state sample inside that `rw-` segment is a `ScePadData` copy: buttons at `+0`,
`lx/ly/rx/ry` at `+4..+7`, connected flag at `+76` (`1`), microsecond timestamp
at `+80`. Measured at `pad+0x24550` on this console; the segment also holds a
second handle fed all-neutral samples slightly ahead of the real pad (that one is
what the home screen reads for its own cursor), so the sample has to be chosen,
not taken.

Cave space, both verified present: home exec 9_940 zero bytes at `0x0f828000`
(the home blob needs 416), library image 4_594 zero bytes at its end (the game
blob needs 512).

## What this branch changes

1. `src/functions.h` — take the first `0xe9` at index >= 2 and stop, instead of
   demanding a single one in the window. Works on both firmwares.
2. `src/patch.c` — reader addresses come from `dlsym` (the thunks are already
   cross-checked); import slots are scanned in the home image's own readable
   mappings; any count from one upwards is accepted; the two 10.20 image anchors
   are gone.
3. `src/patch.c` — new read-out: read the library's `rw-` segment twice, ~20 ms
   apart, and keep only candidates whose timestamp advanced, preferring a sample
   with an axis off neutral. One snapshot is not enough: dozens of structures in
   there have `1` at `+76` and a plausible value at `+80`, and one carries
   `0xffffffff`, which wins any "newest" test.
4. `src/game.c` — the game path uses the same sample discovery (it needs no
   other change; it already resolves and scans generically and accepts >= 1 slot).
5. `ui/index.html` — `Apply` no longer requires a live read-out, so a firmware
   whose record layout is not recognised can still be filtered.

## Build

```sh
curl -sL -o ps5-payload-sdk.zip https://github.com/ps5-payload-dev/sdk/releases/latest/download/ps5-payload-sdk.zip
unzip -d "$HOME/sdk-dist/extract" ps5-payload-sdk.zip
export PS5_PAYLOAD_SDK="$HOME/sdk-dist/extract/ps5-payload-sdk"
export LLVM_CONFIG=/usr/bin/llvm-config      # clang 23 works; upstream says 18
make                                          # -> ps5-dualsense-deadzone.elf (~205 KB)
```

## Install on the console

There is no ELF loader on 9021 in a 13.60 autoloader chain, so:

1. FTP (port **1337**, etaHEN; 2121/ftpsrv is flaky) `STOR` the ELF into
   `/data/etaHEN/payloads/`.
2. Start it once from **Settings → etaHEN Toolbox → Payloads**.
3. For boot-time start, write an empty `<name>.elf.auto_start` next to it.

The payload serves its UI on **8089**; the setting lives in
`/data/ps5-dualsense-deadzone.conf` and is re-applied when the payload loads.

## Verified on hardware

- home screen: locate, apply, disable, restore, live read-out
- in game: `gameSupported true`, `gameImports 1`, filter applied, live read-out
  from the game's own library copy, drift gone on the left stick (3.2 % at rest)

## Not done here

These paths are 13.60-specific and would regress 10.20 if merged as they are.
A mergeable version should try the old layout first and fall back to these
(new record walk, then the `rw-` discovery; pinned 10.20 reader pair when its
signatures verify, else `dlsym`; old scan window **and** the image-local one).
`make test` also needs two Linux fixes: `-arch x86_64` is macOS-only and
`tests/test_dual.c` needs `-lm`.
