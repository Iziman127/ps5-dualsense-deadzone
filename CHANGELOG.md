# ps5-dualsense-deadzone

## Changelog

### Unreleased

- Support firmware 13.60 without changing the 10.20 path. The reader set, the
  import-slot window and the slot count are taken from the library when the
  10.20 layout is not recognised, and the live read-out falls back to the
  library's rw- segment when the 0x20018 record table is absent.
- Accept a reader thunk whose `jmp rel32` displacement itself contains `0xe9`
  (13.60's `scePadReadStateExt` is `ba 01 00 00 00 e9 c6 e9 ff ff`). The old
  rule demanded exactly one `e9` in the first nine bytes and rejected it.

### v0.1

First public release.

- Cone deadzone (angle, width, range) per stick, or circle mode, aimed at
  one-direction stick drift. Movements inside the cone snap back to center;
  everything else passes through untouched.
- Hooks the controller library of the home screen and of the running game,
  calibrated from a self-contained web UI on the phone or computer, with a
  live view of the raw stick position.
- Remembers the setting on the console and reapplies it when the payload is
  loaded again, including into games.
- Refuses to patch anything it does not recognize: reader functions resolved
  by name and pinned by their instruction bytes, imports found by scanning
  memory, all-or-nothing hooking, verified writes, full rollback.
- Host test suite: the generated assembly against a C model over every
  byte-coordinate pair, the web UI preview against the same model, injected
  write failures with rollback checks, HTTP and input-sampling checks.

**Known issues:** one setting for all controllers; the filter hides the drift,
it does not repair the worn potentiometer; the web UI has no authentication;
some games need the filter disabled while they launch (see the README).

**Compatibilité:** tested on firmware 10.20. Other firmwares are not tested;
an unrecognized layout is refused cleanly (the UI says why) instead of being
patched blindly.

**Disclaimer:** hobbyist homebrew for a jailbroken console, provided as is,
without warranty of any kind. Not affiliated with or endorsed by Sony
Interactive Entertainment.
