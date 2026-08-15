# REG-082 — Chromium DevTools Port Ownership

Status: **LOCKED**

## Defect

The executable Chromium gates previously asked the OS for a free TCP port, closed that reservation, then launched Chromium later with that released port number. This created a time-of-check/time-of-use race: another process or the OS could reclaim the port before Chromium bound it. The browser could remain alive while the expected DevTools endpoint never appeared, producing a platform-dependent false gate failure.

## Root repair

Both Chromium engineering smokes now launch the isolated browser profile with `--remote-debugging-port=0`. Chromium owns port allocation and publishes the authoritative selected port in its profile-local `DevToolsActivePort` file. The gate validates that published port before connecting to `/json/version` and CDP.

The Email Shield local test server still uses an isolated free-port allocation because the Node listener is the direct owner of that server bind; the removed race applies specifically to the separately spawned Chromium debug listener.

## Permanent protection

`tests/unit/engineeringAutomation.test.ts` requires both browser smokes to:

- use `--remote-debugging-port=0`;
- read `DevToolsActivePort` from the isolated profile;
- call the authoritative-port wait helper; and
- never return to interpolating an OS-released `debugPort` into Chromium arguments.

This regression is part of the full Windows/macOS/Ubuntu Engineering Gate.